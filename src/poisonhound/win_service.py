"""Windows Service wrapper for PoisonHound.

Only importable on Windows - requires pywin32, which is only installed
there (see the `sys_platform == 'win32'` marker in pyproject.toml).
Wraps the existing PoisonHoundApp.run()/stop() lifecycle so it can be
managed by the Windows Service Control Manager instead of running in a
console window.

Config is always read from a fixed, well-known location
(%PROGRAMDATA%\\PoisonHound\\config.yaml) rather than a command-line
argument, since the SCM doesn't give an easy way to pass custom args to
a service's start command without extra registry plumbing. This keeps
install a single command: drop config.yaml in that folder, then
`poisonhound-service.exe install`.
"""

from __future__ import annotations

import ctypes
import logging
import os
import sys
from pathlib import Path

import servicemanager
import win32event
import win32service
import win32serviceutil

from poisonhound.app import PoisonHoundApp
from poisonhound.core.config_loader import load_config
from poisonhound.core.exceptions import PoisonHoundError
from poisonhound.logging_setup import configure_logging

logger = logging.getLogger(__name__)

CONFIG_DIR = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "PoisonHound"
CONFIG_PATH = CONFIG_DIR / "config.yaml"


def check_npcap_installed() -> None:
    """Fail loudly and clearly if Npcap/WinPcap isn't installed.

    Without it, scapy's sniffer fails deep inside a background thread with
    a cryptic error that never surfaces anywhere a service admin would
    see it - this turns that into a clear startup failure instead.
    """
    try:
        ctypes.WinDLL("wpcap.dll")
    except OSError as exc:
        raise PoisonHoundError(
            "Npcap (or WinPcap) is not installed. PoisonHound cannot capture "
            "packets on Windows without it. Install it from https://npcap.com/ "
            "(check 'Install Npcap in WinPcap API-compatible Mode') and restart "
            "the service."
        ) from exc


class PoisonHoundService(win32serviceutil.ServiceFramework):
    _svc_name_ = "PoisonHound"
    _svc_display_name_ = "PoisonHound Network Monitor"
    _svc_description_ = (
        "Detects ARP spoofing, rogue DHCP servers, IPv6 router advertisement "
        "hijacking, and LLMNR/NBT-NS/mDNS poisoning on the local network."
    )

    def __init__(self, args: list[str]) -> None:
        super().__init__(args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.app: PoisonHoundApp | None = None

    def SvcStop(self) -> None:
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        if self.app is not None:
            self.app.stop()
        win32event.SetEvent(self.stop_event)

    def SvcDoRun(self) -> None:
        servicemanager.LogInfoMsg(f"PoisonHound: starting (config: {CONFIG_PATH})")
        try:
            check_npcap_installed()
            config = load_config(CONFIG_PATH)
            configure_logging(config.logging)
            # Relative paths in config.yaml (db_path, state_file, logging.file)
            # should resolve next to it, not the SCM's default cwd (System32).
            os.chdir(CONFIG_DIR)
            self.app = PoisonHoundApp(config, config_path=CONFIG_PATH)
        except PoisonHoundError as exc:
            servicemanager.LogErrorMsg(f"PoisonHound: failed to start - {exc}")
            self.ReportServiceStatus(win32service.SERVICE_STOPPED)
            return
        except Exception:
            logger.exception("PoisonHound: failed to start (unexpected error)")
            servicemanager.LogErrorMsg(
                "PoisonHound: failed to start due to an unexpected error - see the log file "
                "configured under 'logging.file' in config.yaml for details."
            )
            self.ReportServiceStatus(win32service.SERVICE_STOPPED)
            return

        self.app.run()
        self.ReportServiceStatus(win32service.SERVICE_RUNNING)
        servicemanager.LogInfoMsg("PoisonHound: started")
        win32event.WaitForSingleObject(self.stop_event, win32event.INFINITE)
        servicemanager.LogInfoMsg("PoisonHound: stopped")


def main() -> None:
    """Entry point for the `poisonhound-service` console script.

    With no arguments, this is how the SCM actually launches the service
    process. Any arguments (install/remove/start/stop/restart/debug) are
    the admin-facing commands, handled by pywin32's own dispatcher.
    """
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(PoisonHoundService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(PoisonHoundService)


if __name__ == "__main__":
    main()

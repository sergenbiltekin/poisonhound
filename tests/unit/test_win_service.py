"""Tests for the Windows Service wrapper.

Skipped everywhere except Windows: win_service.py imports pywin32, which
isn't installable outside Windows (see the sys_platform marker in
pyproject.toml), so importing it on Linux/macOS CI would fail regardless
of what we're testing.
"""

from __future__ import annotations

import ctypes
import importlib
from pathlib import Path

import pytest

pytest.importorskip("win32serviceutil")

from poisonhound.core.exceptions import PoisonHoundError  # noqa: E402


@pytest.fixture
def win_service(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PROGRAMDATA", r"C:\ProgramData")
    import poisonhound.win_service as module

    return importlib.reload(module)


def test_config_path_lives_under_programdata_poisonhound(win_service) -> None:
    assert win_service.CONFIG_DIR == Path(r"C:\ProgramData\PoisonHound")
    assert win_service.CONFIG_PATH == Path(r"C:\ProgramData\PoisonHound\config.yaml")


def test_config_path_follows_programdata_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PROGRAMDATA", r"D:\CustomProgramData")
    import poisonhound.win_service as module

    reloaded = importlib.reload(module)

    assert reloaded.CONFIG_DIR == Path(r"D:\CustomProgramData\PoisonHound")


def test_check_npcap_installed_passes_when_dll_loads(
    win_service, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ctypes, "WinDLL", lambda name: object(), raising=False)

    win_service.check_npcap_installed()  # should not raise


def test_check_npcap_installed_raises_clear_error_when_dll_missing(
    win_service, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _raise(name: str) -> None:
        raise OSError("not found")

    monkeypatch.setattr(ctypes, "WinDLL", _raise, raising=False)

    with pytest.raises(PoisonHoundError, match="Npcap"):
        win_service.check_npcap_installed()


def test_service_class_metadata(win_service) -> None:
    assert win_service.PoisonHoundService._svc_name_ == "PoisonHound"
    assert "PoisonHound" in win_service.PoisonHoundService._svc_display_name_

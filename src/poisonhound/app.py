"""Application wiring: config -> detectors -> dispatcher -> sniffer -> notifiers."""

from __future__ import annotations

import logging
import queue
import threading
from pathlib import Path

import uvicorn
from scapy.sendrecv import AsyncSniffer

from poisonhound.core.alert import Alert, Severity
from poisonhound.core.config import PoisonHoundConfig
from poisonhound.core.config_loader import load_config
from poisonhound.core.dispatcher import PacketDispatcher
from poisonhound.core.notifier import BaseNotifier
from poisonhound.core.rate_limiter import AlertDeduper
from poisonhound.core.registry import build_enabled_detectors
from poisonhound.dashboard.app import create_app
from poisonhound.dashboard.store import AlertStore
from poisonhound.notifiers.smtp_notifier import SmtpNotifier

logger = logging.getLogger(__name__)


class ConsoleNotifier(BaseNotifier):
    """Fallback notifier that logs alerts. Always active alongside whichever
    notifiers are configured, so nothing is lost if e.g. SMTP is misconfigured."""

    name = "console"

    def send(self, alert: Alert) -> None:
        logger.warning(
            "ALERT [%s] %s (source=%s/%s, vendor=%s, x%d): %s",
            alert.severity.value.upper(),
            alert.title,
            alert.source_mac,
            alert.source_ip,
            alert.vendor or "unknown",
            alert.occurrence_count,
            alert.description,
        )


class PoisonHoundApp:
    def __init__(self, config: PoisonHoundConfig, config_path: str | Path | None = None) -> None:
        self.config = config
        self._config_path = config_path
        self._reload_lock = threading.Lock()
        self._alert_queue: queue.Queue[Alert] = queue.Queue()
        self.deduper = AlertDeduper(config.rate_limit.dedupe_window_seconds)
        self.detectors = build_enabled_detectors(
            config.detectors, self._alert_queue.put, config.interface
        )
        self.dispatcher = PacketDispatcher(self.detectors)
        self.notifiers: list[BaseNotifier] = [ConsoleNotifier()]
        self._configure_notifiers(config)
        self.alert_store: AlertStore | None = None
        if config.dashboard.enabled:
            self.alert_store = AlertStore(config.dashboard.db_path)
        self._sniffer: AsyncSniffer | None = None
        self._stop_event = threading.Event()
        self._notify_thread: threading.Thread | None = None
        self._dashboard_server: uvicorn.Server | None = None
        self._dashboard_thread: threading.Thread | None = None

    @classmethod
    def from_config_file(cls, path: str | Path) -> PoisonHoundApp:
        return cls(load_config(path), config_path=path)

    def get_config(self) -> PoisonHoundConfig:
        return self.config

    def _configure_notifiers(self, config: PoisonHoundConfig) -> None:
        for notifier_name in config.notifiers:
            if notifier_name == "smtp":
                if config.smtp.enabled:
                    self.notifiers.append(SmtpNotifier(config.smtp))
            elif notifier_name == "webhook":
                logger.warning("notifiers: 'webhook' is not implemented yet in this MVP, skipping")
            else:
                logger.warning(
                    "notifiers: unknown notifier '%s' in config, skipping", notifier_name
                )

    def run(self) -> None:
        for detector in self.detectors:
            detector.start()

        self._sniffer = AsyncSniffer(
            iface=self.config.interface,
            filter=self.dispatcher.combined_bpf_filter(),
            prn=self.dispatcher.dispatch,
            store=False,
        )
        self._sniffer.start()

        self._stop_event.clear()
        self._notify_thread = threading.Thread(target=self._notify_loop, daemon=True)
        self._notify_thread.start()

        if self.config.dashboard.enabled:
            self._start_dashboard()

        logger.info(
            "PoisonHound started on interface '%s' with %d detector(s) enabled",
            self.config.interface,
            len(self.detectors),
        )

    def _start_dashboard(self) -> None:
        assert self.alert_store is not None
        dashboard_app = create_app(
            self.alert_store,
            self.get_config,
            self._config_path or "config.yaml",
            reload_config=self.reload_config,
        )
        server_config = uvicorn.Config(
            dashboard_app,
            host=self.config.dashboard.host,
            port=self.config.dashboard.port,
            log_level="warning",
        )
        self._dashboard_server = uvicorn.Server(server_config)
        self._dashboard_thread = threading.Thread(target=self._dashboard_server.run, daemon=True)
        self._dashboard_thread.start()
        logger.info(
            "Dashboard running at http://%s:%d",
            self.config.dashboard.host,
            self.config.dashboard.port,
        )

    def _notify_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                alert = self._alert_queue.get(timeout=1)
            except queue.Empty:
                continue
            self._process_alert(alert)

    def _process_alert(self, alert: Alert) -> None:
        if self.alert_store is not None:
            try:
                self.alert_store.insert_or_update(alert)
            except Exception:
                logger.exception("failed to record alert in the alert store")

        passed = self.deduper.process(alert)
        if passed is None:
            logger.debug("suppressed repeat alert for dedup_key=%s", alert.dedup_key)
            return
        for notifier in self.notifiers:
            try:
                notifier.send(passed)
            except Exception:
                logger.exception("notifier '%s' failed to send alert", notifier.name)

    def reload_config(self, path: str | Path | None = None) -> None:
        """Reload config.yaml and apply changes to already-running detectors
        and notifiers in place, without restarting the sniffer.

        Only values read fresh from each component's `.config` on every
        packet/send can be hot-reloaded this way - changing the network
        interface or a detector's enabled/disabled state still requires a
        full restart.
        """
        config_path = path or self._config_path
        if config_path is None:
            raise RuntimeError("reload_config() requires a config file path")

        new_config = load_config(config_path)

        with self._reload_lock:
            self.config = new_config
            self.deduper.set_window(new_config.rate_limit.dedupe_window_seconds)

            detector_configs = {
                "arp_spoof": new_config.detectors.arp_spoof,
                "rogue_dhcp": new_config.detectors.rogue_dhcp,
                "ipv6_rogue_ra": new_config.detectors.ipv6_rogue_ra,
                "name_resolution_canary": new_config.detectors.name_resolution_canary,
            }
            for detector in self.detectors:
                new_detector_config = detector_configs.get(detector.name)
                if new_detector_config is not None:
                    detector.config = new_detector_config

            for notifier in self.notifiers:
                if isinstance(notifier, SmtpNotifier):
                    notifier.config = new_config.smtp
                    notifier._min_severity = Severity(new_config.smtp.min_severity)

        logger.info("Configuration reloaded from %s", config_path)

    def stop(self) -> None:
        self._stop_event.set()
        if self._sniffer is not None:
            self._sniffer.stop()
            self._sniffer = None
        for detector in self.detectors:
            detector.stop()
        for notifier in self.notifiers:
            notifier.close()
        if self._dashboard_server is not None:
            self._dashboard_server.should_exit = True
            if self._dashboard_thread is not None:
                self._dashboard_thread.join(timeout=5)
            self._dashboard_server = None
        if self.alert_store is not None:
            self.alert_store.close()
        logger.info("PoisonHound stopped")

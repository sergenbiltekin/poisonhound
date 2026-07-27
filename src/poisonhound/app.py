"""Application wiring: config -> detectors -> dispatcher -> sniffer -> notifiers."""

from __future__ import annotations

import logging
import queue
import threading
from pathlib import Path

from scapy.sendrecv import AsyncSniffer

from poisonhound.core.alert import Alert
from poisonhound.core.config import PoisonHoundConfig
from poisonhound.core.config_loader import load_config
from poisonhound.core.dispatcher import PacketDispatcher
from poisonhound.core.notifier import BaseNotifier
from poisonhound.core.rate_limiter import AlertDeduper
from poisonhound.core.registry import build_enabled_detectors
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
    def __init__(self, config: PoisonHoundConfig) -> None:
        self.config = config
        self._alert_queue: queue.Queue[Alert] = queue.Queue()
        self.deduper = AlertDeduper(config.rate_limit.dedupe_window_seconds)
        self.detectors = build_enabled_detectors(
            config.detectors, self._alert_queue.put, config.interface
        )
        self.dispatcher = PacketDispatcher(self.detectors)
        self.notifiers: list[BaseNotifier] = [ConsoleNotifier()]
        self._configure_notifiers(config)
        self._sniffer: AsyncSniffer | None = None
        self._stop_event = threading.Event()
        self._notify_thread: threading.Thread | None = None

    @classmethod
    def from_config_file(cls, path: str | Path) -> PoisonHoundApp:
        return cls(load_config(path))

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

        logger.info(
            "PoisonHound started on interface '%s' with %d detector(s) enabled",
            self.config.interface,
            len(self.detectors),
        )

    def _notify_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                alert = self._alert_queue.get(timeout=1)
            except queue.Empty:
                continue
            self._process_alert(alert)

    def _process_alert(self, alert: Alert) -> None:
        passed = self.deduper.process(alert)
        if passed is None:
            logger.debug("suppressed repeat alert for dedup_key=%s", alert.dedup_key)
            return
        for notifier in self.notifiers:
            try:
                notifier.send(passed)
            except Exception:
                logger.exception("notifier '%s' failed to send alert", notifier.name)

    def stop(self) -> None:
        self._stop_event.set()
        if self._sniffer is not None:
            self._sniffer.stop()
            self._sniffer = None
        for detector in self.detectors:
            detector.stop()
        for notifier in self.notifiers:
            notifier.close()
        logger.info("PoisonHound stopped")

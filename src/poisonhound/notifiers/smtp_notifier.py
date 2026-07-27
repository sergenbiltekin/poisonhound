"""SMTP email notifier."""

from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage

from poisonhound.core.alert import Alert, Severity, severity_at_least
from poisonhound.core.config import SmtpConfig
from poisonhound.core.notifier import BaseNotifier

logger = logging.getLogger(__name__)


class SmtpNotifier(BaseNotifier):
    name = "smtp"

    def __init__(self, config: SmtpConfig) -> None:
        self.config = config
        self._min_severity = Severity(config.min_severity)

    def send(self, alert: Alert) -> None:
        if not severity_at_least(alert.severity, self._min_severity):
            logger.debug(
                "smtp: alert severity '%s' is below min_severity '%s', skipping",
                alert.severity.value,
                self._min_severity.value,
            )
            return

        message = self._build_message(alert)
        client = self._connect()
        try:
            client.send_message(message)
        finally:
            client.quit()

    def _connect(self) -> smtplib.SMTP:
        client = smtplib.SMTP(self.config.host, self.config.port, timeout=10)
        if self.config.use_tls:
            client.starttls()
        if self.config.username and self.config.password:
            client.login(self.config.username, self.config.password)
        return client

    def _build_message(self, alert: Alert) -> EmailMessage:
        message = EmailMessage()
        message["Subject"] = f"[PoisonHound] {alert.severity.value.upper()}: {alert.title}"
        message["From"] = self.config.from_addr
        message["To"] = ", ".join(self.config.to_addrs)
        message.set_content(self._render_body(alert))
        return message

    def _render_body(self, alert: Alert) -> str:
        remediation_lines = "\n".join(f"  - {step}" for step in alert.remediation)
        return (
            f"Detector:    {alert.detector_name}\n"
            f"Severity:    {alert.severity.value.upper()}\n"
            f"Source MAC:  {alert.source_mac}\n"
            f"Source IP:   {alert.source_ip or 'unknown'}\n"
            f"Vendor:      {alert.vendor or 'unknown'}\n"
            f"Occurrences: {alert.occurrence_count} "
            f"(first seen {alert.first_seen.isoformat()}, "
            f"last seen {alert.last_seen.isoformat()})\n"
            "\n"
            f"What happened:\n{alert.description}\n"
            "\n"
            f"Recommended actions:\n{remediation_lines}\n"
            "\n"
            f"Evidence (packet summary): {alert.evidence.get('packet_summary', 'n/a')}\n"
            f"The full packet dump is in the PoisonHound log (dedup_key={alert.dedup_key}).\n"
        )

from __future__ import annotations

from collections.abc import Callable
from unittest.mock import MagicMock, patch

from poisonhound.core.alert import Alert, Severity
from poisonhound.core.config import SmtpConfig
from poisonhound.notifiers.smtp_notifier import SmtpNotifier


def _make_config(**overrides: object) -> SmtpConfig:
    defaults: dict[str, object] = {
        "host": "smtp.example.com",
        "port": 587,
        "use_tls": True,
        "username": "alerts@example.com",
        "password": "hunter2",
        "from_addr": "alerts@example.com",
        "to_addrs": ["you@example.com"],
        "min_severity": "medium",
    }
    defaults.update(overrides)
    return SmtpConfig(**defaults)  # type: ignore[arg-type]


def test_send_connects_starts_tls_and_logs_in(alert_factory: Callable[..., Alert]) -> None:
    notifier = SmtpNotifier(_make_config())
    alert = alert_factory(severity=Severity.HIGH)

    with patch("poisonhound.notifiers.smtp_notifier.smtplib.SMTP") as mock_smtp_cls:
        mock_client = MagicMock()
        mock_smtp_cls.return_value = mock_client
        notifier.send(alert)

    mock_smtp_cls.assert_called_once_with("smtp.example.com", 587, timeout=10)
    mock_client.starttls.assert_called_once()
    mock_client.login.assert_called_once_with("alerts@example.com", "hunter2")
    mock_client.send_message.assert_called_once()
    mock_client.quit.assert_called_once()


def test_send_skips_tls_and_login_when_not_configured(alert_factory: Callable[..., Alert]) -> None:
    notifier = SmtpNotifier(_make_config(use_tls=False, username=None, password=None))
    alert = alert_factory(severity=Severity.HIGH)

    with patch("poisonhound.notifiers.smtp_notifier.smtplib.SMTP") as mock_smtp_cls:
        mock_client = MagicMock()
        mock_smtp_cls.return_value = mock_client
        notifier.send(alert)

    mock_client.starttls.assert_not_called()
    mock_client.login.assert_not_called()
    mock_client.send_message.assert_called_once()


def test_send_skips_alert_below_min_severity(alert_factory: Callable[..., Alert]) -> None:
    notifier = SmtpNotifier(_make_config(min_severity="critical"))
    alert = alert_factory(severity=Severity.HIGH)

    with patch("poisonhound.notifiers.smtp_notifier.smtplib.SMTP") as mock_smtp_cls:
        notifier.send(alert)

    mock_smtp_cls.assert_not_called()


def test_email_message_contains_title_severity_and_remediation(
    alert_factory: Callable[..., Alert],
) -> None:
    notifier = SmtpNotifier(_make_config())
    alert = alert_factory(
        severity=Severity.CRITICAL,
        title="Rogue DHCP server detected",
        remediation=["Disconnect the rogue server.", "Enable DHCP snooping."],
    )

    message = notifier._build_message(alert)
    body = message.get_content()

    assert "CRITICAL" in message["Subject"]
    assert "Rogue DHCP server detected" in message["Subject"]
    assert "Disconnect the rogue server." in body
    assert "Enable DHCP snooping." in body
    assert alert.source_mac in body

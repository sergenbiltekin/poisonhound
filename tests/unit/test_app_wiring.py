from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from poisonhound.app import PoisonHoundApp
from poisonhound.core.alert import Alert
from poisonhound.core.config import PoisonHoundConfig
from poisonhound.core.notifier import BaseNotifier
from poisonhound.detectors.arp_spoof import ArpSpoofDetector
from poisonhound.detectors.ipv6_rogue_ra import Ipv6RogueRaDetector
from poisonhound.detectors.name_resolution_canary import NameResolutionCanaryDetector
from poisonhound.detectors.rogue_dhcp import RogueDhcpDetector
from poisonhound.notifiers.smtp_notifier import SmtpNotifier


class _FakeNotifier(BaseNotifier):
    name = "fake"

    def __init__(self) -> None:
        self.sent: list[Alert] = []
        self.closed = False

    def send(self, alert: Alert) -> None:
        self.sent.append(alert)

    def close(self) -> None:
        self.closed = True


class _FailingNotifier(BaseNotifier):
    name = "failing"

    def send(self, alert: Alert) -> None:
        raise RuntimeError("smtp exploded")


def test_enabled_detectors_are_loaded_by_default(
    config_factory: Callable[..., PoisonHoundConfig],
) -> None:
    app = PoisonHoundApp(config_factory())

    detector_types = {type(d) for d in app.detectors}
    assert detector_types == {
        ArpSpoofDetector,
        RogueDhcpDetector,
        Ipv6RogueRaDetector,
        NameResolutionCanaryDetector,
    }


def test_disabled_detector_is_not_loaded(
    config_factory: Callable[..., PoisonHoundConfig],
) -> None:
    config = config_factory()
    config.detectors.arp_spoof.enabled = False
    config.detectors.rogue_dhcp.enabled = False
    config.detectors.ipv6_rogue_ra.enabled = False
    config.detectors.name_resolution_canary.enabled = False

    app = PoisonHoundApp(config)

    assert app.detectors == []


def test_process_alert_forwards_to_all_notifiers(
    config_factory: Callable[..., PoisonHoundConfig],
    alert_factory: Callable[..., Alert],
) -> None:
    app = PoisonHoundApp(config_factory())
    fake = _FakeNotifier()
    app.notifiers = [fake]

    app._process_alert(alert_factory())

    assert len(fake.sent) == 1


def test_process_alert_survives_a_failing_notifier(
    config_factory: Callable[..., PoisonHoundConfig],
    alert_factory: Callable[..., Alert],
) -> None:
    app = PoisonHoundApp(config_factory())
    fake = _FakeNotifier()
    app.notifiers = [_FailingNotifier(), fake]

    app._process_alert(alert_factory())

    assert len(fake.sent) == 1


def test_process_alert_within_dedupe_window_is_suppressed(
    config_factory: Callable[..., PoisonHoundConfig],
    alert_factory: Callable[..., Alert],
) -> None:
    app = PoisonHoundApp(config_factory())
    fake = _FakeNotifier()
    app.notifiers = [fake]

    app._process_alert(alert_factory(dedup_key="same-key"))
    app._process_alert(alert_factory(dedup_key="same-key"))

    assert len(fake.sent) == 1


def test_smtp_notifier_added_by_default(config_factory: Callable[..., PoisonHoundConfig]) -> None:
    app = PoisonHoundApp(config_factory())

    smtp_notifiers = [n for n in app.notifiers if isinstance(n, SmtpNotifier)]
    assert len(smtp_notifiers) == 1


def test_smtp_notifier_not_added_when_disabled(
    config_factory: Callable[..., PoisonHoundConfig],
) -> None:
    config = config_factory()
    config.smtp.enabled = False

    app = PoisonHoundApp(config)

    assert not any(isinstance(n, SmtpNotifier) for n in app.notifiers)


def test_unknown_notifier_name_is_skipped_without_crashing(
    config_factory: Callable[..., PoisonHoundConfig],
) -> None:
    config = config_factory(notifiers=["carrier-pigeon"])

    app = PoisonHoundApp(config)

    assert not any(isinstance(n, SmtpNotifier) for n in app.notifiers)


def test_webhook_notifier_name_is_skipped_without_crashing(
    config_factory: Callable[..., PoisonHoundConfig],
) -> None:
    config = config_factory(notifiers=["webhook"])

    app = PoisonHoundApp(config)

    assert len(app.notifiers) == 1  # just the always-on ConsoleNotifier


def test_dashboard_disabled_by_default_has_no_alert_store(
    config_factory: Callable[..., PoisonHoundConfig],
) -> None:
    app = PoisonHoundApp(config_factory())

    assert app.alert_store is None


def test_dashboard_enabled_creates_alert_store(
    config_factory: Callable[..., PoisonHoundConfig], tmp_path: Path
) -> None:
    config = config_factory(dashboard={"enabled": True, "db_path": str(tmp_path / "alerts.db")})

    app = PoisonHoundApp(config)

    assert app.alert_store is not None


def test_process_alert_records_every_occurrence_even_when_notification_is_suppressed(
    config_factory: Callable[..., PoisonHoundConfig],
    alert_factory: Callable[..., Alert],
    tmp_path: Path,
) -> None:
    config = config_factory(dashboard={"enabled": True, "db_path": str(tmp_path / "alerts.db")})
    app = PoisonHoundApp(config)
    app.notifiers = [_FakeNotifier()]

    app._process_alert(alert_factory(dedup_key="same-key"))
    app._process_alert(alert_factory(dedup_key="same-key"))

    assert app.alert_store is not None
    rows = app.alert_store.list_alerts()
    assert len(rows) == 1
    assert rows[0]["occurrence_count"] == 2


def test_reload_config_without_a_path_raises(
    config_factory: Callable[..., PoisonHoundConfig],
) -> None:
    app = PoisonHoundApp(config_factory())

    with pytest.raises(RuntimeError):
        app.reload_config()


_BASE_CONFIG_YAML = """
interface: eth0
detectors:
  arp_spoof:
    gateway_ip: {gateway_ip}
  rogue_dhcp: {{}}
  ipv6_rogue_ra: {{}}
  name_resolution_canary: {{}}
smtp:
  host: smtp.example.com
  from_addr: alerts@example.com
  to_addrs: ["you@example.com"]
  min_severity: {min_severity}
"""


def test_reload_config_updates_detector_and_smtp_settings(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        _BASE_CONFIG_YAML.format(gateway_ip="192.168.1.1", min_severity="medium"),
        encoding="utf-8",
    )
    app = PoisonHoundApp.from_config_file(config_path)
    original_arp_config = next(d for d in app.detectors if d.name == "arp_spoof").config

    config_path.write_text(
        _BASE_CONFIG_YAML.format(gateway_ip="192.168.1.254", min_severity="critical"),
        encoding="utf-8",
    )
    app.reload_config()

    updated_arp_config = next(d for d in app.detectors if d.name == "arp_spoof").config
    assert updated_arp_config.gateway_ip == "192.168.1.254"
    assert updated_arp_config is not original_arp_config

    smtp_notifier = next(n for n in app.notifiers if isinstance(n, SmtpNotifier))
    assert smtp_notifier.config.min_severity == "critical"

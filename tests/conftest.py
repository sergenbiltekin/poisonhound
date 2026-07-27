from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from poisonhound.core.alert import Alert, Severity
from poisonhound.core.config import (
    ArpSpoofConfig,
    DetectorsConfig,
    Ipv6RogueRaConfig,
    NameResolutionCanaryConfig,
    PoisonHoundConfig,
    RogueDhcpConfig,
    SmtpConfig,
)


@pytest.fixture
def collected_alerts() -> list[Alert]:
    return []


def _make_config(state_file: str, **overrides: object) -> PoisonHoundConfig:
    defaults: dict[str, object] = {
        "interface": "eth0",
        "detectors": DetectorsConfig(
            arp_spoof=ArpSpoofConfig(gateway_ip="192.168.1.1"),
            rogue_dhcp=RogueDhcpConfig(),
            ipv6_rogue_ra=Ipv6RogueRaConfig(),
            name_resolution_canary=NameResolutionCanaryConfig(state_file=state_file),
        ),
        "smtp": SmtpConfig(
            host="smtp.example.com",
            from_addr="alerts@example.com",
            to_addrs=["you@example.com"],
        ),
    }
    defaults.update(overrides)
    return PoisonHoundConfig(**defaults)  # type: ignore[arg-type]


@pytest.fixture
def config_factory(tmp_path: Path) -> Callable[..., PoisonHoundConfig]:
    state_file = str(tmp_path / "poisonhound_state.json")
    return lambda **overrides: _make_config(state_file, **overrides)


def _make_alert(**overrides: object) -> Alert:
    defaults: dict[str, object] = {
        "detector_name": "test_detector",
        "severity": Severity.HIGH,
        "title": "Test alert",
        "description": "Test description",
        "source_mac": "aa:bb:cc:dd:ee:ff",
        "source_ip": "192.168.1.50",
        "remediation": ["Do something about it."],
        "evidence": {"packet_summary": "test"},
        "dedup_key": "test:aa:bb:cc:dd:ee:ff",
    }
    defaults.update(overrides)
    return Alert(**defaults)  # type: ignore[arg-type]


@pytest.fixture
def alert_factory() -> Callable[..., Alert]:
    return _make_alert

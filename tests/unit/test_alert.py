from __future__ import annotations

from collections.abc import Callable

from poisonhound.core.alert import Alert, Severity, severity_at_least


def test_to_dict_serializes_severity_and_timestamps(alert_factory: Callable[..., Alert]) -> None:
    alert = alert_factory(severity=Severity.CRITICAL)
    data = alert.to_dict()

    assert data["severity"] == "critical"
    assert isinstance(data["first_seen"], str)
    assert isinstance(data["last_seen"], str)
    assert data["remediation"] == ["Do something about it."]


def test_severity_at_least_orders_correctly() -> None:
    assert severity_at_least(Severity.CRITICAL, Severity.LOW)
    assert severity_at_least(Severity.MEDIUM, Severity.MEDIUM)
    assert not severity_at_least(Severity.LOW, Severity.HIGH)

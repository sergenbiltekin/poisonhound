from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from poisonhound.core.alert import Alert, Severity
from poisonhound.dashboard.store import AlertStore


def test_insert_creates_a_row(alert_factory: Callable[..., Alert], tmp_path: Path) -> None:
    store = AlertStore(tmp_path / "alerts.db")

    store.insert_or_update(alert_factory())

    rows = store.list_alerts()
    assert len(rows) == 1
    assert rows[0]["occurrence_count"] == 1


def test_repeat_dedup_key_increments_occurrence_count(
    alert_factory: Callable[..., Alert], tmp_path: Path
) -> None:
    store = AlertStore(tmp_path / "alerts.db")

    store.insert_or_update(alert_factory(dedup_key="same-key"))
    store.insert_or_update(alert_factory(dedup_key="same-key"))
    store.insert_or_update(alert_factory(dedup_key="same-key"))

    rows = store.list_alerts()
    assert len(rows) == 1
    assert rows[0]["occurrence_count"] == 3


def test_different_dedup_keys_create_separate_rows(
    alert_factory: Callable[..., Alert], tmp_path: Path
) -> None:
    store = AlertStore(tmp_path / "alerts.db")

    store.insert_or_update(alert_factory(dedup_key="key-a"))
    store.insert_or_update(alert_factory(dedup_key="key-b"))

    assert len(store.list_alerts()) == 2


def test_list_alerts_filters_by_severity(
    alert_factory: Callable[..., Alert], tmp_path: Path
) -> None:
    store = AlertStore(tmp_path / "alerts.db")
    store.insert_or_update(alert_factory(dedup_key="a", severity=Severity.CRITICAL))
    store.insert_or_update(alert_factory(dedup_key="b", severity=Severity.INFO))

    rows = store.list_alerts(severity="critical")

    assert len(rows) == 1
    assert rows[0]["severity"] == "critical"


def test_list_alerts_filters_by_detector(
    alert_factory: Callable[..., Alert], tmp_path: Path
) -> None:
    store = AlertStore(tmp_path / "alerts.db")
    store.insert_or_update(alert_factory(dedup_key="a", detector_name="arp_spoof"))
    store.insert_or_update(alert_factory(dedup_key="b", detector_name="rogue_dhcp"))

    rows = store.list_alerts(detector="arp_spoof")

    assert len(rows) == 1
    assert rows[0]["detector_name"] == "arp_spoof"


def test_get_alert_returns_none_for_unknown_id(tmp_path: Path) -> None:
    store = AlertStore(tmp_path / "alerts.db")

    assert store.get_alert(999) is None


def test_get_alert_deserializes_remediation_and_evidence(
    alert_factory: Callable[..., Alert], tmp_path: Path
) -> None:
    store = AlertStore(tmp_path / "alerts.db")
    store.insert_or_update(
        alert_factory(remediation=["Do X", "Do Y"], evidence={"packet_summary": "ARP who-has"})
    )

    row = store.list_alerts()[0]
    fetched = store.get_alert(row["id"])

    assert fetched is not None
    assert fetched["remediation"] == ["Do X", "Do Y"]
    assert fetched["evidence"] == {"packet_summary": "ARP who-has"}


def test_count_by_severity(alert_factory: Callable[..., Alert], tmp_path: Path) -> None:
    store = AlertStore(tmp_path / "alerts.db")
    store.insert_or_update(alert_factory(dedup_key="a", severity=Severity.CRITICAL))
    store.insert_or_update(alert_factory(dedup_key="b", severity=Severity.CRITICAL))
    store.insert_or_update(alert_factory(dedup_key="c", severity=Severity.INFO))

    counts = store.count_by_severity()

    assert counts == {"critical": 2, "info": 1}


def test_in_memory_database_persists_across_calls_on_same_instance(
    alert_factory: Callable[..., Alert],
) -> None:
    store = AlertStore(":memory:")

    store.insert_or_update(alert_factory())

    assert len(store.list_alerts()) == 1

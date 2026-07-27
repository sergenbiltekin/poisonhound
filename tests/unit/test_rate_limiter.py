from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta, timezone

from poisonhound.core.alert import Alert
from poisonhound.core.rate_limiter import AlertDeduper


def _at(seconds_offset: int) -> datetime:
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return base + timedelta(seconds=seconds_offset)


def test_first_alert_for_a_key_is_never_suppressed(alert_factory: Callable[..., Alert]) -> None:
    deduper = AlertDeduper(window_seconds=300)
    alert = alert_factory(first_seen=_at(0), last_seen=_at(0))

    result = deduper.process(alert)

    assert result is alert
    assert result.occurrence_count == 1


def test_duplicate_alert_within_window_is_suppressed(alert_factory: Callable[..., Alert]) -> None:
    deduper = AlertDeduper(window_seconds=300)
    first = alert_factory(first_seen=_at(0), last_seen=_at(0))
    second = alert_factory(first_seen=_at(10), last_seen=_at(10))

    assert deduper.process(first) is first
    assert deduper.process(second) is None


def test_alert_after_window_expiry_is_not_suppressed(alert_factory: Callable[..., Alert]) -> None:
    deduper = AlertDeduper(window_seconds=300)
    first = alert_factory(first_seen=_at(0), last_seen=_at(0))
    later = alert_factory(first_seen=_at(301), last_seen=_at(301))

    assert deduper.process(first) is first
    result = deduper.process(later)

    assert result is later
    assert result.occurrence_count == 1


def test_occurrence_count_accumulates_while_suppressed(alert_factory: Callable[..., Alert]) -> None:
    deduper = AlertDeduper(window_seconds=300)
    deduper.process(alert_factory(first_seen=_at(0), last_seen=_at(0)))
    deduper.process(alert_factory(first_seen=_at(10), last_seen=_at(10)))
    suppressed_third = alert_factory(first_seen=_at(20), last_seen=_at(20))

    result = deduper.process(suppressed_third)

    assert result is None
    assert suppressed_third.occurrence_count == 3
    assert suppressed_third.first_seen == _at(0)

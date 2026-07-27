"""Deduplication / debounce logic so repeated attacks don't spam notifiers."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime

from poisonhound.core.alert import Alert


@dataclass
class _DedupeState:
    window_start: datetime
    first_seen: datetime
    last_seen: datetime
    occurrence_count: int


class AlertDeduper:
    """Suppresses repeat alerts for the same `dedup_key` within a time window.

    The first alert for a given key in a window is passed through (with
    occurrence_count=1). Repeats within the window are suppressed but still
    counted; once the window elapses, the next alert is passed through with
    occurrence_count/first_seen updated to reflect everything seen since the
    window opened.
    """

    def __init__(self, window_seconds: int) -> None:
        self._window_seconds = window_seconds
        self._state: dict[str, _DedupeState] = {}
        self._lock = threading.Lock()

    def process(self, alert: Alert) -> Alert | None:
        """Return the alert to notify on, or None if it should be suppressed."""
        now = alert.last_seen
        with self._lock:
            state = self._state.get(alert.dedup_key)
            window_expired = (
                state is not None
                and (now - state.window_start).total_seconds() >= self._window_seconds
            )

            if state is None or window_expired:
                self._state[alert.dedup_key] = _DedupeState(
                    window_start=now,
                    first_seen=alert.first_seen,
                    last_seen=now,
                    occurrence_count=1,
                )
                alert.occurrence_count = 1
                return alert

            state.occurrence_count += 1
            state.last_seen = now
            alert.occurrence_count = state.occurrence_count
            alert.first_seen = state.first_seen
            alert.last_seen = now
            return None

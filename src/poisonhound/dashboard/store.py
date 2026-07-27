"""SQLite-backed alert history for the web dashboard.

Every alert PoisonHound raises is recorded here, independent of the
in-memory `AlertDeduper` used to throttle notifications - so the dashboard
can show an accurate occurrence count even for attacks that are ongoing
but only notified about once per dedupe window.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

from poisonhound.core.alert import Alert

_SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    detector_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    source_mac TEXT NOT NULL,
    source_ip TEXT,
    vendor TEXT,
    remediation_json TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    dedup_key TEXT NOT NULL UNIQUE,
    occurrence_count INTEGER NOT NULL DEFAULT 1,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_detector ON alerts(detector_name);
CREATE INDEX IF NOT EXISTS idx_alerts_last_seen ON alerts(last_seen);
"""

_UPSERT = """
INSERT INTO alerts (
    detector_name, severity, title, description, source_mac,
    source_ip, vendor, remediation_json, evidence_json,
    dedup_key, occurrence_count, first_seen, last_seen
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
ON CONFLICT(dedup_key) DO UPDATE SET
    occurrence_count = occurrence_count + 1,
    last_seen = excluded.last_seen,
    severity = excluded.severity,
    title = excluded.title,
    description = excluded.description,
    source_mac = excluded.source_mac,
    source_ip = excluded.source_ip,
    vendor = excluded.vendor,
    evidence_json = excluded.evidence_json
"""


class AlertStore:
    """Thread-safe wrapper around a single SQLite connection.

    A single connection is kept open for the store's lifetime (rather than
    reconnecting per call) so that `:memory:` databases work correctly in
    tests - a fresh connection to `:memory:` would otherwise be a brand new,
    empty database every time.
    """

    def __init__(self, db_path: str | Path) -> None:
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    def insert_or_update(self, alert: Alert) -> None:
        with self._lock:
            self._conn.execute(
                _UPSERT,
                (
                    alert.detector_name,
                    alert.severity.value,
                    alert.title,
                    alert.description,
                    alert.source_mac,
                    alert.source_ip,
                    alert.vendor,
                    json.dumps(alert.remediation),
                    json.dumps(alert.evidence),
                    alert.dedup_key,
                    alert.first_seen.isoformat(),
                    alert.last_seen.isoformat(),
                ),
            )
            self._conn.commit()

    def list_alerts(
        self,
        *,
        severity: str | None = None,
        detector: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        clauses = []
        params: list[Any] = []
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if detector:
            clauses.append("detector_name = ?")
            params.append(detector)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.extend([limit, offset])

        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM alerts {where} ORDER BY last_seen DESC LIMIT ? OFFSET ?",
                params,
            ).fetchall()
        return [_row_to_dict(row) for row in rows]

    def get_alert(self, alert_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM alerts WHERE id = ?", (alert_id,)
            ).fetchone()
        return _row_to_dict(row) if row else None

    def count_by_severity(self) -> dict[str, int]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT severity, COUNT(*) as n FROM alerts GROUP BY severity"
            ).fetchall()
        return {row["severity"]: row["n"] for row in rows}

    def close(self) -> None:
        with self._lock:
            self._conn.close()


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    data = dict(row)
    data["remediation"] = json.loads(data.pop("remediation_json"))
    data["evidence"] = json.loads(data.pop("evidence_json"))
    return data

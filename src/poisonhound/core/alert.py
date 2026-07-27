"""The Alert model: what every detector produces when it fires."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def severity_at_least(severity: Severity, minimum: Severity) -> bool:
    """Return True if `severity` is at least as severe as `minimum`."""
    return _SEVERITY_ORDER[severity] >= _SEVERITY_ORDER[minimum]


@dataclass
class Alert:
    """A single detection event.

    `description` explains how the attack was recognized, `remediation`
    lists concrete action steps for that attack type, and `evidence` carries
    the raw packet proof (summary/dump) that justifies the alert in logs.
    """

    detector_name: str
    severity: Severity
    title: str
    description: str
    source_mac: str
    source_ip: str | None
    remediation: list[str]
    evidence: dict[str, Any]
    dedup_key: str
    vendor: str | None = None
    occurrence_count: int = 1
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "detector_name": self.detector_name,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "source_mac": self.source_mac,
            "source_ip": self.source_ip,
            "vendor": self.vendor,
            "remediation": self.remediation,
            "evidence": self.evidence,
            "dedup_key": self.dedup_key,
            "occurrence_count": self.occurrence_count,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
        }

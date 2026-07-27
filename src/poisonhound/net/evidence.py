"""Build the packet-level proof attached to every Alert."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from scapy.packet import Packet


def build_evidence(packet: Packet, extra_fields: dict[str, Any] | None = None) -> dict[str, Any]:
    """Capture the evidence backing an alert.

    `packet_summary` is a one-line scapy summary and `packet_dump` is the
    full per-layer field dump (`Packet.show(dump=True)`) - this is the proof
    a reviewer sees in the log to confirm the detection is legitimate.
    """
    evidence: dict[str, Any] = {
        "packet_summary": packet.summary(),
        "packet_dump": packet.show(dump=True),
        "captured_at": datetime.now(timezone.utc).isoformat(),
    }
    if extra_fields:
        evidence.update(extra_fields)
    return evidence

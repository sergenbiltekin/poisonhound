"""Combine detector BPF filters and fan sniffed packets out to detectors.

A single AsyncSniffer is used for the whole application (rather than one per
detector) to avoid opening multiple libpcap handles and duplicating packet
capture. The dispatcher merges every detector's BPF filter with `or` and
routes each captured packet to every detector; a failure in one detector is
logged and does not affect the others or stop the sniff loop.
"""

from __future__ import annotations

import logging

from scapy.packet import Packet

from poisonhound.core.detector import BaseDetector

logger = logging.getLogger(__name__)


class PacketDispatcher:
    def __init__(self, detectors: list[BaseDetector]) -> None:
        self._detectors = detectors

    def combined_bpf_filter(self) -> str | None:
        filters = [d.bpf_filter for d in self._detectors if d.bpf_filter]
        unique_filters = list(dict.fromkeys(filters))
        if not unique_filters:
            return None
        return " or ".join(f"({f})" for f in unique_filters)

    def dispatch(self, packet: Packet) -> None:
        for detector in self._detectors:
            try:
                detector.handle_packet(packet)
            except Exception:
                logger.exception("detector '%s' failed while handling a packet", detector.name)

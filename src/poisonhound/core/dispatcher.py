"""Combine detector BPF filters and fan sniffed packets out to detectors.

A single AsyncSniffer is used for the whole application (rather than one per
detector) to avoid opening multiple libpcap handles and duplicating packet
capture. The dispatcher merges every detector's BPF filter with `or` and
routes each captured packet to every detector; a failure in one detector is
logged and does not affect the others or stop the sniff loop.
"""

from __future__ import annotations

import logging

from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Packet

from poisonhound.core.detector import BaseDetector
from poisonhound.core.mac_directory import MacDirectory

logger = logging.getLogger(__name__)


class PacketDispatcher:
    def __init__(
        self, detectors: list[BaseDetector], mac_directory: MacDirectory | None = None
    ) -> None:
        self._detectors = detectors
        self._mac_directory = mac_directory

    def combined_bpf_filter(self) -> str | None:
        filters = [d.bpf_filter for d in self._detectors if d.bpf_filter]
        unique_filters = list(dict.fromkeys(filters))
        if not unique_filters:
            return None
        return " or ".join(f"({f})" for f in unique_filters)

    def dispatch(self, packet: Packet) -> None:
        if self._mac_directory is not None:
            self._observe_mac_ip(packet)
        for detector in self._detectors:
            try:
                detector.handle_packet(packet)
            except Exception:
                logger.exception("detector '%s' failed while handling a packet", detector.name)

    def _observe_mac_ip(self, packet: Packet) -> None:
        if not packet.haslayer(Ether):
            return
        # ARP packets never carry a stacked IP/IPv6 layer, so they're
        # naturally excluded here - see MacDirectory's docstring for why
        # that matters.
        if packet.haslayer(IP):
            self._mac_directory.observe(packet[Ether].src, packet[IP].src)
        elif packet.haslayer(IPv6):
            self._mac_directory.observe(packet[Ether].src, packet[IPv6].src)

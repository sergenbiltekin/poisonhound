"""Tracks the most recently observed IP address for each MAC address.

Populated from protocols that carry a genuine IP header (DHCP, LLMNR/mDNS/
NBT-NS, IPv6 traffic) - never from ARP itself, since ARP's own address
claims are exactly what get forged in an ARP spoofing attack; trusting them
here would let an attacker poison this directory with their own lie.

This lets a detector whose underlying protocol carries no genuine sender IP
(ArpSpoofDetector) cross-reference a suspicious MAC against everything else
the sniffer has independently observed, so an alert can say "this MAC was
last seen using IP X" even though the ARP packet itself never says so.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass
class _Observation:
    ip: str
    last_seen: datetime


class MacDirectory:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_mac: dict[str, _Observation] = {}

    def observe(self, mac: str, ip: str) -> None:
        with self._lock:
            self._by_mac[mac.lower()] = _Observation(ip=ip, last_seen=datetime.now(timezone.utc))

    def lookup(self, mac: str) -> str | None:
        with self._lock:
            observation = self._by_mac.get(mac.lower())
        return observation.ip if observation else None

"""Detects ARP spoofing by watching for changes to the gateway's MAC address."""

from __future__ import annotations

import logging
from collections.abc import Callable

from scapy.layers.l2 import ARP
from scapy.packet import Packet

from poisonhound.core.alert import Alert, Severity
from poisonhound.core.config import ArpSpoofConfig
from poisonhound.core.detector import BaseDetector
from poisonhound.core.exceptions import DetectorError
from poisonhound.core.mac_directory import MacDirectory
from poisonhound.net.evidence import build_evidence
from poisonhound.net.gateway import detect_default_gateway
from poisonhound.net.oui_lookup import lookup_vendor

logger = logging.getLogger(__name__)

REMEDIATION = [
    "Verify the legitimate gateway MAC address out-of-band (switch console, DHCP server logs).",
    "On managed switches, enable Dynamic ARP Inspection (DAI) and DHCP Snooping.",
    "Find the offending host by its MAC address on the switch and disconnect it if unauthorized.",
    "As a stopgap, add a static ARP entry for the gateway on critical hosts.",
]

BASELINE_LEARNED_REMEDIATION = [
    "Confirm this MAC address matches your gateway's real hardware address.",
    "Set known_gateway_mac in config.yaml to pin this value going forward.",
]


class ArpSpoofDetector(BaseDetector):
    """Passive detector: alerts when the MAC address claiming to own the
    configured gateway IP changes from a known/learned baseline."""

    name = "arp_spoof"
    bpf_filter = "arp"

    def __init__(
        self,
        config: ArpSpoofConfig,
        on_alert: Callable[[Alert], None],
        mac_directory: MacDirectory | None = None,
        iface: str | None = None,
    ) -> None:
        super().__init__(on_alert)
        self.config = config
        self._mac_directory = mac_directory
        self._iface = iface
        self._resolved_gateway_ip = config.gateway_ip or self._auto_detect_gateway_ip()
        self._baseline_mac: str | None = (
            config.known_gateway_mac.lower() if config.known_gateway_mac else None
        )

    def _auto_detect_gateway_ip(self) -> str:
        detected = detect_default_gateway(self._iface) if self._iface else None
        if not detected:
            raise DetectorError(
                "arp_spoof: gateway_ip is not set and could not be auto-detected for "
                f"interface '{self._iface}'. Set detectors.arp_spoof.gateway_ip in "
                "config.yaml manually."
            )
        logger.info(
            "arp_spoof: auto-detected gateway %s on interface '%s'", detected, self._iface
        )
        return detected

    @property
    def gateway_ip(self) -> str:
        """The gateway IP in effect right now - config.gateway_ip if set
        (including after a hot-reload), otherwise the value auto-detected
        at startup."""
        return self.config.gateway_ip or self._resolved_gateway_ip

    def handle_packet(self, packet: Packet) -> None:
        if not packet.haslayer(ARP):
            return

        arp = packet[ARP]
        if arp.op != 2:  # only ARP replies ("is-at") claim an IP->MAC mapping
            return
        if arp.psrc != self.gateway_ip:
            return

        claimed_mac = arp.hwsrc.lower()

        if self._baseline_mac is None:
            self._learn_baseline(packet, claimed_mac)
            return

        if claimed_mac == self._baseline_mac:
            return

        known_ip = self._mac_directory.lookup(claimed_mac) if self._mac_directory else None
        known_ip_clause = (
            f" ARP itself never carries the attacker's real IP - that's what makes ARP "
            f"spoofing possible - but this MAC was independently seen using {known_ip} on "
            f"other traffic (DHCP/LLMNR/mDNS/NBT-NS), which is likely the real attacker."
            if known_ip
            else ""
        )

        self.emit(
            Alert(
                detector_name=self.name,
                severity=Severity.HIGH,
                title=f"ARP spoofing suspected: gateway MAC changed to {claimed_mac}",
                description=(
                    f"The baseline MAC address for gateway {self.gateway_ip} is "
                    f"{self._baseline_mac}, but an ARP reply just claimed the gateway is now "
                    f"at {claimed_mac}. This is the classic ARP cache poisoning pattern used "
                    "to redirect traffic through an attacker's machine for a MITM attack."
                    f"{known_ip_clause}"
                ),
                source_mac=claimed_mac,
                source_ip=arp.psrc,
                vendor=lookup_vendor(claimed_mac),
                remediation=REMEDIATION,
                evidence=build_evidence(
                    packet,
                    {
                        "baseline_mac": self._baseline_mac,
                        "claimed_mac": claimed_mac,
                        "known_ip_for_claimed_mac": known_ip,
                    },
                ),
                dedup_key=f"arp_spoof:{self.gateway_ip}:{claimed_mac}",
            )
        )

    def _learn_baseline(self, packet: Packet, claimed_mac: str) -> None:
        self._baseline_mac = claimed_mac
        self.emit(
            Alert(
                detector_name=self.name,
                severity=Severity.INFO,
                title=f"Learned gateway MAC baseline for {self.gateway_ip}",
                description=(
                    "No known_gateway_mac was configured, so the first ARP reply seen for "
                    f"{self.gateway_ip} ({claimed_mac}) was learned as the trusted "
                    "baseline. Verify this MAC address is correct."
                ),
                source_mac=claimed_mac,
                source_ip=self.gateway_ip,
                vendor=lookup_vendor(claimed_mac),
                remediation=BASELINE_LEARNED_REMEDIATION,
                evidence=build_evidence(packet, {"learned_baseline_mac": claimed_mac}),
                dedup_key=f"arp_spoof:baseline:{self.gateway_ip}",
            )
        )

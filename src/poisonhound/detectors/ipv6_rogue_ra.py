"""Detects rogue IPv6 router advertisements and DHCPv6 servers (mitm6-style attacks)."""

from __future__ import annotations

import logging
from collections.abc import Callable

from scapy.layers.dhcp6 import DHCP6_Advertise, DHCP6_Reply
from scapy.layers.inet6 import ICMPv6ND_RA, ICMPv6NDOptDNSSL, ICMPv6NDOptRDNSS, IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Packet

from poisonhound.core.alert import Alert, Severity
from poisonhound.core.config import Ipv6RogueRaConfig
from poisonhound.core.detector import BaseDetector
from poisonhound.net.evidence import build_evidence
from poisonhound.net.oui_lookup import lookup_vendor

logger = logging.getLogger(__name__)

RA_REMEDIATION = [
    "Confirm whether this device is an authorized IPv6 router; if not, locate and disconnect it.",
    "Enable RA Guard on managed switches to block router advertisements from untrusted ports.",
    "If IPv6 is unused on this network, consider disabling it or filtering ICMPv6 RA/DHCPv6.",
    "Add this router's link-local address to authorized_routers in config.yaml if legitimate.",
]

DHCPV6_REMEDIATION = [
    "Confirm whether this DHCPv6 server is authorized; if not, locate and disconnect it.",
    "Enable RA Guard / DHCPv6 Guard on managed switches.",
    "If IPv6 is unused, disable it on clients or block ICMPv6 RA/DHCPv6 at the switch.",
    "Add this server's link-local address to authorized_dhcpv6_servers in config.yaml "
    "if legitimate.",
]


class Ipv6RogueRaDetector(BaseDetector):
    """Passive detector for unauthorized IPv6 router advertisements and DHCPv6 servers.

    Unauthorized DHCPv6 Advertise/Reply is the core mechanism behind mitm6:
    an attacker answers Windows clients' DHCPv6 requests with a malicious
    DNS server over IPv6, which Windows prefers over IPv4 DNS by default.
    """

    name = "ipv6_rogue_ra"
    bpf_filter = "icmp6 or (udp and (port 546 or port 547))"

    def __init__(self, config: Ipv6RogueRaConfig, on_alert: Callable[[Alert], None]) -> None:
        super().__init__(on_alert)
        self.config = config

    def handle_packet(self, packet: Packet) -> None:
        if not packet.haslayer(IPv6):
            return

        if packet.haslayer(ICMPv6ND_RA):
            self._handle_ra(packet)
        elif packet.haslayer(DHCP6_Advertise) or packet.haslayer(DHCP6_Reply):
            self._handle_dhcpv6(packet)

    def _source_mac(self, packet: Packet) -> str | None:
        return packet[Ether].src.lower() if packet.haslayer(Ether) else None

    def _handle_ra(self, packet: Packet) -> None:
        source_ip = packet[IPv6].src
        if source_ip.lower() in {r.lower() for r in self.config.authorized_routers}:
            return

        source_mac = self._source_mac(packet)
        ra = packet[ICMPv6ND_RA]
        has_dns_option = packet.haslayer(ICMPv6NDOptRDNSS) or packet.haslayer(ICMPv6NDOptDNSSL)
        pushes_config = bool(ra.M) or bool(ra.O) or has_dns_option
        severity = Severity.HIGH if pushes_config else Severity.MEDIUM

        if pushes_config:
            detail = (
                " It also advertises DNS configuration (RDNSS/DNSSL) or sets the M/O flags, "
                "matching the DNS-hijack pattern used by tools like mitm6."
            )
        else:
            detail = (
                " No DNS options or M/O flags were set, but any router not in your whitelist "
                "should still be verified."
            )

        self.emit(
            Alert(
                detector_name=self.name,
                severity=severity,
                title=f"Unauthorized IPv6 router advertisement from {source_ip}",
                description=(
                    f"A router advertisement was sent by {source_ip}, which is not listed in "
                    f"authorized_routers.{detail}"
                ),
                source_mac=source_mac or "unknown",
                source_ip=source_ip,
                vendor=lookup_vendor(source_mac) if source_mac else None,
                remediation=RA_REMEDIATION,
                evidence=build_evidence(
                    packet,
                    {
                        "managed_flag": bool(ra.M),
                        "other_config_flag": bool(ra.O),
                        "has_dns_option": has_dns_option,
                    },
                ),
                dedup_key=f"ipv6_rogue_ra:ra:{source_ip}",
            )
        )

    def _handle_dhcpv6(self, packet: Packet) -> None:
        source_ip = packet[IPv6].src
        if source_ip.lower() in {s.lower() for s in self.config.authorized_dhcpv6_servers}:
            return

        source_mac = self._source_mac(packet)
        msg_name = "DHCP6_Advertise" if packet.haslayer(DHCP6_Advertise) else "DHCP6_Reply"

        self.emit(
            Alert(
                detector_name=self.name,
                severity=Severity.CRITICAL,
                title=f"Unauthorized DHCPv6 server detected: {source_ip}",
                description=(
                    f"A {msg_name} was sent by {source_ip}, which is not listed in "
                    "authorized_dhcpv6_servers. This is the core mechanism behind mitm6-style "
                    "attacks: an attacker answers DHCPv6 requests to hand out a malicious DNS "
                    "server over IPv6, which Windows clients prefer over IPv4 DNS by default."
                ),
                source_mac=source_mac or "unknown",
                source_ip=source_ip,
                vendor=lookup_vendor(source_mac) if source_mac else None,
                remediation=DHCPV6_REMEDIATION,
                evidence=build_evidence(packet, {"message_type": msg_name}),
                dedup_key=f"ipv6_rogue_ra:dhcpv6:{source_ip}",
            )
        )

"""Detects rogue DHCP servers, passively and (optionally) via active probing."""

from __future__ import annotations

import logging
import random
import threading
from collections.abc import Callable

from scapy.layers.dhcp import BOOTP, DHCP, DHCPTypes
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Packet
from scapy.sendrecv import sendp

from poisonhound.core.alert import Alert, Severity
from poisonhound.core.config import RogueDhcpConfig
from poisonhound.core.detector import BaseDetector
from poisonhound.net.evidence import build_evidence
from poisonhound.net.oui_lookup import lookup_vendor

logger = logging.getLogger(__name__)

REMEDIATION = [
    "Confirm whether this DHCP server is authorized; if not, locate and disconnect it.",
    "Enable DHCP Snooping on managed switches to block unauthorized DHCP servers.",
    "If it is legitimate, add its IP/MAC to authorized_servers in config.yaml.",
    "Check for clients that may already hold a lease from the rogue server and renew them.",
]

_OFFER_MSG_TYPES = {2, 5}  # DHCPOFFER, DHCPACK
_MSG_TYPE_NAMES = {2: "DHCPOFFER", 5: "DHCPACK"}
_NAME_TO_DHCP_TYPE = {name: number for number, name in DHCPTypes.items()}


def _dhcp_message_type(packet: Packet) -> int | None:
    """Return the numeric DHCP message type, whether scapy represents it as
    an int (packets dissected off the wire) or as its string name (packets
    built directly in-process, e.g. in tests)."""
    if not packet.haslayer(DHCP):
        return None
    for opt in packet[DHCP].options:
        if isinstance(opt, tuple) and opt[0] == "message-type":
            value = opt[1]
            if isinstance(value, int):
                return value
            return _NAME_TO_DHCP_TYPE.get(value)
    return None


def random_locally_administered_mac() -> str:
    """Generate a random MAC with the locally-administered bit set, so the
    active probe never collides with a real device's address."""
    octets = [0x02] + [random.randint(0, 255) for _ in range(5)]
    return ":".join(f"{o:02x}" for o in octets)


class RogueDhcpDetector(BaseDetector):
    """Watches DHCP OFFER/ACK traffic for servers not in `authorized_servers`.

    If `active_probe_enabled` is set, periodically sends a DHCPDISCOVER from
    a throwaway random MAC to also catch rogue servers that only respond to
    requests rather than broadcasting unprompted.
    """

    name = "rogue_dhcp"
    bpf_filter = "udp and (port 67 or port 68)"

    def __init__(
        self,
        config: RogueDhcpConfig,
        on_alert: Callable[[Alert], None],
        iface: str | None = None,
    ) -> None:
        super().__init__(on_alert)
        self.config = config
        self._iface = iface
        self._warned_no_whitelist = False
        self._probe_timer: threading.Timer | None = None

    def start(self) -> None:
        super().start()
        if self.config.active_probe_enabled:
            self._schedule_probe()

    def stop(self) -> None:
        super().stop()
        if self._probe_timer is not None:
            self._probe_timer.cancel()
            self._probe_timer = None

    def handle_packet(self, packet: Packet) -> None:
        msg_type = _dhcp_message_type(packet)
        if msg_type not in _OFFER_MSG_TYPES:
            return

        if not self.config.authorized_servers:
            if not self._warned_no_whitelist:
                logger.warning(
                    "rogue_dhcp: no authorized_servers configured in config.yaml, skipping "
                    "DHCP server validation until it is set"
                )
                self._warned_no_whitelist = True
            return

        if not packet.haslayer(IP) or not packet.haslayer(Ether):
            return

        server_ip = packet[IP].src
        server_mac = packet[Ether].src.lower()

        if self._is_authorized(server_ip, server_mac):
            return

        offered_ip = packet[BOOTP].yiaddr if packet.haslayer(BOOTP) else None
        msg_name = _MSG_TYPE_NAMES[msg_type]

        self.emit(
            Alert(
                detector_name=self.name,
                severity=Severity.CRITICAL,
                title=f"Unauthorized DHCP server detected: {server_ip}",
                description=(
                    f"A {msg_name} was sent by {server_ip} ({server_mac}), which is not listed "
                    "in authorized_servers. This is the signature of a rogue DHCP server used to "
                    "hand clients a malicious gateway or DNS server for a MITM attack."
                ),
                source_mac=server_mac,
                source_ip=server_ip,
                vendor=lookup_vendor(server_mac),
                remediation=REMEDIATION,
                evidence=build_evidence(
                    packet, {"message_type": msg_name, "offered_ip": offered_ip}
                ),
                dedup_key=f"rogue_dhcp:{server_ip}:{server_mac}",
            )
        )

    def _is_authorized(self, server_ip: str, server_mac_lower: str) -> bool:
        return any(
            entry == server_ip or entry.lower() == server_mac_lower
            for entry in self.config.authorized_servers
        )

    def _schedule_probe(self) -> None:
        if not self._running:
            return
        self._send_discover_probe()
        self._probe_timer = threading.Timer(
            self.config.probe_interval_seconds, self._schedule_probe
        )
        self._probe_timer.daemon = True
        self._probe_timer.start()

    def _send_discover_probe(self) -> None:
        probe_mac = random_locally_administered_mac()
        chaddr = bytes.fromhex(probe_mac.replace(":", "")).ljust(16, b"\x00")
        packet = (
            Ether(src=probe_mac, dst="ff:ff:ff:ff:ff:ff")
            / IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=68, dport=67)
            / BOOTP(chaddr=chaddr, xid=random.randint(0, 2**32 - 1))
            / DHCP(options=[("message-type", "discover"), "end"])
        )
        try:
            sendp(packet, iface=self._iface, verbose=False)
        except Exception:
            logger.exception("rogue_dhcp: failed to send active DHCPDISCOVER probe")

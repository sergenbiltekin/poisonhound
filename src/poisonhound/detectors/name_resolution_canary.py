"""Active canary-based detector for LLMNR/NBT-NS/mDNS poisoning (Responder, Inveigh, ...).

Periodically queries a handful of hostnames that are guaranteed not to
exist on the network (see net/canary_names.py). Because PoisonHound is the
only thing that ever asks about these names, any answer to one is
unambiguous evidence of a poisoning tool responding to name-resolution
broadcasts/multicasts it should never answer.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.layers.llmnr import LLMNRQuery, LLMNRResponse
from scapy.layers.netbios import NBNSHeader, NBNSQueryRequest, NBNSQueryResponse
from scapy.packet import Packet
from scapy.sendrecv import sendp

from poisonhound.core.alert import Alert, Severity
from poisonhound.core.config import NameResolutionCanaryConfig
from poisonhound.core.detector import BaseDetector
from poisonhound.core.state_store import StateStore
from poisonhound.net.canary_names import generate_canary_names, to_nbns_name
from poisonhound.net.evidence import build_evidence
from poisonhound.net.oui_lookup import lookup_vendor

logger = logging.getLogger(__name__)

LLMNR_MULTICAST_IP = "224.0.0.252"
LLMNR_MULTICAST_MAC = "01:00:5e:00:00:fc"
LLMNR_PORT = 5355
MDNS_MULTICAST_IP = "224.0.0.251"
MDNS_MULTICAST_MAC = "01:00:5e:00:00:fb"
MDNS_PORT = 5353
NBNS_BROADCAST_IP = "255.255.255.255"
NBNS_PORT = 137

REMEDIATION = [
    "A tool such as Responder or Inveigh appears to be answering name-resolution queries it "
    "has no legitimate reason to answer - locate and remove the offending host.",
    "Disable LLMNR and NetBIOS-NS via Group Policy (or local policy) on Windows clients.",
    "Disable mDNS responders on hosts/services that don't need them.",
    "Review authentication logs around the alert time for signs of NTLM relay/capture.",
]


def _normalize_name(value: str | bytes | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="ignore")
    return value.strip(".").split(".")[0]


class NameResolutionCanaryDetector(BaseDetector):
    name = "name_resolution_canary"
    bpf_filter = f"udp and (port {LLMNR_PORT} or port {MDNS_PORT} or port {NBNS_PORT})"

    def __init__(
        self,
        config: NameResolutionCanaryConfig,
        on_alert: Callable[[Alert], None],
        state_store: StateStore,
        iface: str | None = None,
    ) -> None:
        super().__init__(on_alert)
        self.config = config
        self._iface = iface
        seed = state_store.get_or_create_seed()
        self._canary_names = generate_canary_names(config.canary_prefix, seed, config.canary_count)
        self._nbns_canary_names = {to_nbns_name(n) for n in self._canary_names}
        self._probe_timer: threading.Timer | None = None

    def start(self) -> None:
        super().start()
        self._schedule_probe()

    def stop(self) -> None:
        super().stop()
        if self._probe_timer is not None:
            self._probe_timer.cancel()
            self._probe_timer = None

    def handle_packet(self, packet: Packet) -> None:
        if packet.haslayer(LLMNRResponse):
            self._check_llmnr_response(packet)
        elif packet.haslayer(NBNSQueryResponse):
            self._check_nbns_response(packet)
        elif packet.haslayer(DNS) and packet[DNS].qr == 1:
            self._check_mdns_response(packet)

    def _source_mac(self, packet: Packet) -> str | None:
        return packet[Ether].src.lower() if packet.haslayer(Ether) else None

    def _emit_for_match(
        self, packet: Packet, protocol: str, queried_name: str, resolved_to: str | None
    ) -> None:
        source_ip = packet[IP].src if packet.haslayer(IP) else None
        source_mac = self._source_mac(packet)
        resolved_clause = f", claiming it resolves to {resolved_to}" if resolved_to else ""
        self.emit(
            Alert(
                detector_name=self.name,
                severity=Severity.CRITICAL,
                title=f"Name resolution poisoning detected via {protocol}",
                description=(
                    f"PoisonHound queried '{queried_name}', a hostname it generated itself and "
                    f"knows does not exist on this network. {source_ip or 'A host'} answered the "
                    f"query over {protocol}{resolved_clause}. Only a poisoning tool (e.g. "
                    "Responder, Inveigh) would answer a name that was never actually looked up "
                    "by a real client."
                ),
                source_mac=source_mac or "unknown",
                source_ip=source_ip,
                vendor=lookup_vendor(source_mac) if source_mac else None,
                remediation=REMEDIATION,
                evidence=build_evidence(
                    packet,
                    {
                        "protocol": protocol,
                        "queried_name": queried_name,
                        "resolved_to": resolved_to,
                    },
                ),
                dedup_key=f"name_resolution_canary:{protocol}:{source_mac or source_ip}",
            )
        )

    def _check_llmnr_response(self, packet: Packet) -> None:
        resp = packet[LLMNRResponse]
        name = _normalize_name(resp.qd[0].qname) if resp.qd else None
        if name is None or name not in self._canary_names:
            return
        resolved_to = resp.an[0].rdata if resp.an else None
        self._emit_for_match(packet, "LLMNR", name, resolved_to)

    def _check_mdns_response(self, packet: Packet) -> None:
        dns = packet[DNS]
        # RFC 6762 mDNS responses commonly omit the question section entirely
        # and carry only answer records, so the question can't always be
        # relied on - fall back to the answer's own name if there's no question.
        name = _normalize_name(dns.qd[0].qname) if dns.qd else None
        if name is None and dns.an:
            name = _normalize_name(dns.an[0].rrname)
        if name is None or name not in self._canary_names:
            return
        resolved_to = dns.an[0].rdata if dns.an else None
        self._emit_for_match(packet, "mDNS", name, resolved_to)

    def _check_nbns_response(self, packet: Packet) -> None:
        resp = packet[NBNSQueryResponse]
        name = _normalize_name(resp.RR_NAME)
        if name is None or name.upper() not in self._nbns_canary_names:
            return
        resolved_to = (
            resp.ADDR_ENTRY[0].NB_ADDRESS if resp.ADDR_ENTRY else None
        )
        self._emit_for_match(packet, "NBT-NS", name, resolved_to)

    def _schedule_probe(self) -> None:
        if not self._running:
            return
        self._send_probes()
        self._probe_timer = threading.Timer(
            self.config.query_interval_seconds, self._schedule_probe
        )
        self._probe_timer.daemon = True
        self._probe_timer.start()

    def _send_probes(self) -> None:
        for name in self._canary_names:
            for protocol in self.config.protocols:
                try:
                    self._send_probe(protocol, name)
                except Exception:
                    logger.exception(
                        "name_resolution_canary: failed to send %s probe for '%s'",
                        protocol,
                        name,
                    )

    def _send_probe(self, protocol: str, name: str) -> None:
        packet = self._build_probe_packet(protocol, name)
        if packet is not None:
            sendp(packet, iface=self._iface, verbose=False)

    def _build_probe_packet(self, protocol: str, name: str) -> Packet | None:
        if protocol == "llmnr":
            return (
                Ether(dst=LLMNR_MULTICAST_MAC)
                / IP(dst=LLMNR_MULTICAST_IP)
                / UDP(sport=LLMNR_PORT, dport=LLMNR_PORT)
                / LLMNRQuery(qd=DNSQR(qname=name))
            )
        if protocol == "mdns":
            return (
                Ether(dst=MDNS_MULTICAST_MAC)
                / IP(dst=MDNS_MULTICAST_IP)
                / UDP(sport=MDNS_PORT, dport=MDNS_PORT)
                / DNS(rd=0, qd=DNSQR(qname=f"{name}.local"))
            )
        if protocol == "nbns":
            return (
                Ether(dst="ff:ff:ff:ff:ff:ff")
                / IP(dst=NBNS_BROADCAST_IP)
                / UDP(sport=NBNS_PORT, dport=NBNS_PORT)
                / NBNSHeader(OPCODE=0, NM_FLAGS=0x11, QDCOUNT=1)
                / NBNSQueryRequest(QUESTION_NAME=to_nbns_name(name))
            )
        logger.warning("name_resolution_canary: unknown protocol '%s' in config", protocol)
        return None

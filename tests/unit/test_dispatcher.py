from __future__ import annotations

from collections.abc import Callable

from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet

from poisonhound.core.alert import Alert
from poisonhound.core.detector import BaseDetector
from poisonhound.core.dispatcher import PacketDispatcher
from poisonhound.core.mac_directory import MacDirectory


class _FakeDetector(BaseDetector):
    def __init__(
        self,
        name: str,
        bpf_filter: str | None,
        on_alert: Callable[[Alert], None],
        raise_on_handle: bool = False,
    ) -> None:
        super().__init__(on_alert)
        self.name = name
        self.bpf_filter = bpf_filter
        self._raise_on_handle = raise_on_handle
        self.handled_packets: list[Packet] = []

    def handle_packet(self, packet: Packet) -> None:
        if self._raise_on_handle:
            raise RuntimeError("boom")
        self.handled_packets.append(packet)


def test_combined_bpf_filter_includes_all_enabled_detectors(collected_alerts: list[Alert]) -> None:
    d1 = _FakeDetector("d1", "arp", collected_alerts.append)
    d2 = _FakeDetector("d2", "udp and port 67", collected_alerts.append)
    dispatcher = PacketDispatcher([d1, d2])

    assert dispatcher.combined_bpf_filter() == "(arp) or (udp and port 67)"


def test_combined_bpf_filter_deduplicates_identical_filters(collected_alerts: list[Alert]) -> None:
    d1 = _FakeDetector("d1", "arp", collected_alerts.append)
    d2 = _FakeDetector("d2", "arp", collected_alerts.append)
    dispatcher = PacketDispatcher([d1, d2])

    assert dispatcher.combined_bpf_filter() == "(arp)"


def test_combined_bpf_filter_is_none_when_no_detector_has_one(
    collected_alerts: list[Alert],
) -> None:
    d1 = _FakeDetector("d1", None, collected_alerts.append)
    dispatcher = PacketDispatcher([d1])

    assert dispatcher.combined_bpf_filter() is None


def test_detector_exception_does_not_stop_dispatch(collected_alerts: list[Alert]) -> None:
    failing = _FakeDetector("failing", "arp", collected_alerts.append, raise_on_handle=True)
    healthy = _FakeDetector("healthy", "arp", collected_alerts.append)
    dispatcher = PacketDispatcher([failing, healthy])
    packet = Ether()

    dispatcher.dispatch(packet)

    assert healthy.handled_packets == [packet]


def test_dispatch_records_mac_ip_pair_from_ipv4_packet(collected_alerts: list[Alert]) -> None:
    directory = MacDirectory()
    dispatcher = PacketDispatcher([], mac_directory=directory)
    packet = Ether(src="aa:bb:cc:dd:ee:ff") / IP(src="192.168.1.50") / UDP(sport=5353, dport=5353)

    dispatcher.dispatch(packet)

    assert directory.lookup("aa:bb:cc:dd:ee:ff") == "192.168.1.50"


def test_dispatch_records_mac_ip_pair_from_ipv6_packet(collected_alerts: list[Alert]) -> None:
    directory = MacDirectory()
    dispatcher = PacketDispatcher([], mac_directory=directory)
    packet = Ether(src="aa:bb:cc:dd:ee:ff") / IPv6(src="fe80::1")

    dispatcher.dispatch(packet)

    assert directory.lookup("aa:bb:cc:dd:ee:ff") == "fe80::1"


def test_dispatch_does_not_record_arp_packets(collected_alerts: list[Alert]) -> None:
    # ARP's own address fields are exactly what an ARP spoofing attack
    # forges, so they must never be trusted to populate the directory.
    directory = MacDirectory()
    dispatcher = PacketDispatcher([], mac_directory=directory)
    packet = Ether(src="aa:bb:cc:dd:ee:ff") / ARP(
        op=2, psrc="192.168.1.1", hwsrc="aa:bb:cc:dd:ee:ff"
    )

    dispatcher.dispatch(packet)

    assert directory.lookup("aa:bb:cc:dd:ee:ff") is None


def test_dispatch_without_mac_directory_does_not_error(collected_alerts: list[Alert]) -> None:
    dispatcher = PacketDispatcher([])
    packet = Ether(src="aa:bb:cc:dd:ee:ff") / IP(src="192.168.1.50")

    dispatcher.dispatch(packet)  # must not raise

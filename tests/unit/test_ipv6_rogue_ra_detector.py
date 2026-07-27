from __future__ import annotations

from scapy.layers.dhcp6 import DHCP6_Advertise, DHCP6OptDNSServers
from scapy.layers.inet6 import (
    ICMPv6EchoRequest,
    ICMPv6ND_RA,
    ICMPv6NDOptRDNSS,
    IPv6,
)
from scapy.layers.l2 import Ether

from poisonhound.core.alert import Alert, Severity
from poisonhound.core.config import Ipv6RogueRaConfig
from poisonhound.detectors.ipv6_rogue_ra import Ipv6RogueRaDetector

ROUTER_LL = "fe80::1"
DHCPV6_SERVER_LL = "fe80::2"


def _ra_packet(src: str, mac: str = "aa:bb:cc:00:00:01", with_rdnss: bool = False) -> Ether:
    pkt = Ether(src=mac) / IPv6(src=src, dst="ff02::1") / ICMPv6ND_RA()
    if with_rdnss:
        pkt = pkt / ICMPv6NDOptRDNSS(dns=[src])
    return pkt


def _dhcpv6_advertise_packet(src: str, mac: str = "de:ad:be:ef:00:01") -> Ether:
    return (
        Ether(src=mac)
        / IPv6(src=src, dst="fe80::100")
        / DHCP6_Advertise()
        / DHCP6OptDNSServers(dnsservers=[src])
    )


def _make_detector(
    collected_alerts: list[Alert],
    authorized_routers: list[str] | None = None,
    authorized_dhcpv6_servers: list[str] | None = None,
) -> Ipv6RogueRaDetector:
    config = Ipv6RogueRaConfig(
        authorized_routers=authorized_routers or [],
        authorized_dhcpv6_servers=authorized_dhcpv6_servers or [],
    )
    return Ipv6RogueRaDetector(config, on_alert=collected_alerts.append)


def test_unauthorized_ra_without_dns_option_triggers_medium_alert(
    collected_alerts: list[Alert],
) -> None:
    detector = _make_detector(collected_alerts)

    detector.handle_packet(_ra_packet(ROUTER_LL))

    assert len(collected_alerts) == 1
    assert collected_alerts[0].severity == Severity.MEDIUM


def test_unauthorized_ra_with_rdnss_triggers_high_alert(collected_alerts: list[Alert]) -> None:
    detector = _make_detector(collected_alerts)

    detector.handle_packet(_ra_packet(ROUTER_LL, with_rdnss=True))

    assert len(collected_alerts) == 1
    alert = collected_alerts[0]
    assert alert.severity == Severity.HIGH
    assert alert.evidence["has_dns_option"] is True


def test_authorized_router_ra_is_silent(collected_alerts: list[Alert]) -> None:
    detector = _make_detector(collected_alerts, authorized_routers=[ROUTER_LL])

    detector.handle_packet(_ra_packet(ROUTER_LL, with_rdnss=True))

    assert collected_alerts == []


def test_unauthorized_dhcpv6_advertise_triggers_critical_alert(
    collected_alerts: list[Alert],
) -> None:
    detector = _make_detector(collected_alerts)

    detector.handle_packet(_dhcpv6_advertise_packet(DHCPV6_SERVER_LL))

    assert len(collected_alerts) == 1
    alert = collected_alerts[0]
    assert alert.severity == Severity.CRITICAL
    assert alert.source_ip == DHCPV6_SERVER_LL


def test_authorized_dhcpv6_server_is_silent(collected_alerts: list[Alert]) -> None:
    detector = _make_detector(collected_alerts, authorized_dhcpv6_servers=[DHCPV6_SERVER_LL])

    detector.handle_packet(_dhcpv6_advertise_packet(DHCPV6_SERVER_LL))

    assert collected_alerts == []


def test_unrelated_icmpv6_packet_is_ignored(collected_alerts: list[Alert]) -> None:
    detector = _make_detector(collected_alerts)
    pkt = Ether() / IPv6(src=ROUTER_LL, dst="fe80::100") / ICMPv6EchoRequest()

    detector.handle_packet(pkt)

    assert collected_alerts == []

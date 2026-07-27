from __future__ import annotations

from unittest.mock import patch

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

from poisonhound.core.alert import Alert, Severity
from poisonhound.core.config import RogueDhcpConfig
from poisonhound.detectors.rogue_dhcp import RogueDhcpDetector, random_locally_administered_mac


def _dhcp_packet(
    message_type: str, server_ip: str = "192.168.1.1", server_mac: str = "aa:bb:cc:00:00:01"
) -> Ether:
    return (
        Ether(src=server_mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src=server_ip, dst="255.255.255.255")
        / UDP(sport=67, dport=68)
        / BOOTP(yiaddr="192.168.1.100")
        / DHCP(options=[("message-type", message_type), "end"])
    )


def _make_detector(
    collected_alerts: list[Alert], authorized_servers: list[str] | None = None, **overrides: object
) -> RogueDhcpDetector:
    config = RogueDhcpConfig(authorized_servers=authorized_servers or [], **overrides)  # type: ignore[arg-type]
    return RogueDhcpDetector(config, on_alert=collected_alerts.append)


def test_unauthorized_dhcp_offer_triggers_critical_alert(collected_alerts: list[Alert]) -> None:
    detector = _make_detector(collected_alerts, authorized_servers=["192.168.1.5"])

    detector.handle_packet(_dhcp_packet("offer"))

    assert len(collected_alerts) == 1
    alert = collected_alerts[0]
    assert alert.severity == Severity.CRITICAL
    assert alert.source_ip == "192.168.1.1"
    assert alert.evidence["message_type"] == "DHCPOFFER"
    assert alert.evidence["offered_ip"] == "192.168.1.100"


def test_authorized_dhcp_offer_by_ip_is_silent(collected_alerts: list[Alert]) -> None:
    detector = _make_detector(collected_alerts, authorized_servers=["192.168.1.1"])

    detector.handle_packet(_dhcp_packet("offer"))

    assert collected_alerts == []


def test_authorized_dhcp_server_by_mac_is_silent(collected_alerts: list[Alert]) -> None:
    detector = _make_detector(collected_alerts, authorized_servers=["AA:BB:CC:00:00:01"])

    detector.handle_packet(_dhcp_packet("ack"))

    assert collected_alerts == []


def test_no_whitelist_configured_is_silent(collected_alerts: list[Alert]) -> None:
    detector = _make_detector(collected_alerts, authorized_servers=[])

    detector.handle_packet(_dhcp_packet("offer"))

    assert collected_alerts == []


def test_dhcp_discover_is_ignored(collected_alerts: list[Alert]) -> None:
    detector = _make_detector(collected_alerts, authorized_servers=["192.168.1.5"])

    detector.handle_packet(_dhcp_packet("discover"))

    assert collected_alerts == []


def test_active_probe_sends_discover_from_random_mac(collected_alerts: list[Alert]) -> None:
    detector = _make_detector(
        collected_alerts, active_probe_enabled=True, probe_interval_seconds=9999
    )

    with patch("poisonhound.detectors.rogue_dhcp.sendp") as mock_sendp:
        detector.start()
        detector.stop()

    assert mock_sendp.call_count == 1
    sent_packet = mock_sendp.call_args[0][0]
    assert sent_packet.haslayer(DHCP)


def test_random_locally_administered_mac_sets_ul_bit() -> None:
    mac = random_locally_administered_mac()

    first_octet = int(mac.split(":")[0], 16)
    assert first_octet & 0b10

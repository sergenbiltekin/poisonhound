from __future__ import annotations

from scapy.layers.l2 import ARP, Ether

from poisonhound.core.alert import Alert, Severity
from poisonhound.core.config import ArpSpoofConfig
from poisonhound.core.mac_directory import MacDirectory
from poisonhound.detectors.arp_spoof import ArpSpoofDetector

GATEWAY_IP = "192.168.1.1"


def _arp_reply(psrc: str, hwsrc: str) -> Ether:
    return Ether(src=hwsrc) / ARP(op=2, psrc=psrc, hwsrc=hwsrc)


def _arp_request(psrc: str, hwsrc: str) -> Ether:
    return Ether(src=hwsrc) / ARP(op=1, psrc=psrc, hwsrc=hwsrc)


def _make_detector(
    collected_alerts: list[Alert],
    known_gateway_mac: str | None = "aa:bb:cc:00:00:01",
    mac_directory: MacDirectory | None = None,
) -> ArpSpoofDetector:
    config = ArpSpoofConfig(gateway_ip=GATEWAY_IP, known_gateway_mac=known_gateway_mac)
    return ArpSpoofDetector(config, on_alert=collected_alerts.append, mac_directory=mac_directory)


def test_matching_gateway_mac_does_not_alert(collected_alerts: list[Alert]) -> None:
    detector = _make_detector(collected_alerts)

    detector.handle_packet(_arp_reply(GATEWAY_IP, "aa:bb:cc:00:00:01"))

    assert collected_alerts == []


def test_gateway_mac_change_triggers_high_severity_alert(collected_alerts: list[Alert]) -> None:
    detector = _make_detector(collected_alerts)

    detector.handle_packet(_arp_reply(GATEWAY_IP, "de:ad:be:ef:00:01"))

    assert len(collected_alerts) == 1
    alert = collected_alerts[0]
    assert alert.severity == Severity.HIGH
    assert alert.source_mac == "de:ad:be:ef:00:01"
    assert alert.source_ip == GATEWAY_IP
    assert "aa:bb:cc:00:00:01" in alert.description
    assert alert.remediation
    assert "packet_dump" in alert.evidence


def test_auto_learned_baseline_emits_info_once(collected_alerts: list[Alert]) -> None:
    detector = _make_detector(collected_alerts, known_gateway_mac=None)

    detector.handle_packet(_arp_reply(GATEWAY_IP, "11:22:33:44:55:66"))
    detector.handle_packet(_arp_reply(GATEWAY_IP, "11:22:33:44:55:66"))

    assert len(collected_alerts) == 1
    assert collected_alerts[0].severity == Severity.INFO


def test_learned_baseline_then_change_triggers_alert(collected_alerts: list[Alert]) -> None:
    detector = _make_detector(collected_alerts, known_gateway_mac=None)

    detector.handle_packet(_arp_reply(GATEWAY_IP, "11:22:33:44:55:66"))
    detector.handle_packet(_arp_reply(GATEWAY_IP, "99:88:77:66:55:44"))

    assert len(collected_alerts) == 2
    assert collected_alerts[0].severity == Severity.INFO
    assert collected_alerts[1].severity == Severity.HIGH


def test_arp_request_is_ignored(collected_alerts: list[Alert]) -> None:
    detector = _make_detector(collected_alerts)

    detector.handle_packet(_arp_request(GATEWAY_IP, "de:ad:be:ef:00:01"))

    assert collected_alerts == []


def test_arp_reply_for_other_host_is_ignored(collected_alerts: list[Alert]) -> None:
    detector = _make_detector(collected_alerts)

    detector.handle_packet(_arp_reply("192.168.1.50", "de:ad:be:ef:00:01"))

    assert collected_alerts == []


def test_non_arp_packet_is_ignored(collected_alerts: list[Alert]) -> None:
    detector = _make_detector(collected_alerts)

    detector.handle_packet(Ether(src="aa:bb:cc:00:00:01"))

    assert collected_alerts == []


def test_alert_includes_known_ip_for_spoofing_mac_when_available(
    collected_alerts: list[Alert],
) -> None:
    directory = MacDirectory()
    directory.observe("de:ad:be:ef:00:01", "192.168.1.77")
    detector = _make_detector(collected_alerts, mac_directory=directory)

    detector.handle_packet(_arp_reply(GATEWAY_IP, "de:ad:be:ef:00:01"))

    assert len(collected_alerts) == 1
    alert = collected_alerts[0]
    assert alert.evidence["known_ip_for_claimed_mac"] == "192.168.1.77"
    assert "192.168.1.77" in alert.description


def test_alert_omits_known_ip_when_spoofing_mac_never_seen_elsewhere(
    collected_alerts: list[Alert],
) -> None:
    directory = MacDirectory()
    detector = _make_detector(collected_alerts, mac_directory=directory)

    detector.handle_packet(_arp_reply(GATEWAY_IP, "de:ad:be:ef:00:01"))

    assert len(collected_alerts) == 1
    alert = collected_alerts[0]
    assert alert.evidence["known_ip_for_claimed_mac"] is None


def test_alert_works_without_a_mac_directory_at_all(collected_alerts: list[Alert]) -> None:
    detector = _make_detector(collected_alerts, mac_directory=None)

    detector.handle_packet(_arp_reply(GATEWAY_IP, "de:ad:be:ef:00:01"))

    assert len(collected_alerts) == 1
    assert collected_alerts[0].evidence["known_ip_for_claimed_mac"] is None

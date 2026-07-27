from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.layers.llmnr import LLMNRResponse
from scapy.layers.netbios import NBNS_ADD_ENTRY, NBNSHeader, NBNSQueryResponse

from poisonhound.core.alert import Alert, Severity
from poisonhound.core.config import NameResolutionCanaryConfig
from poisonhound.core.state_store import StateStore
from poisonhound.detectors.name_resolution_canary import NameResolutionCanaryDetector
from poisonhound.net.canary_names import to_nbns_name


def _make_detector(
    collected_alerts: list[Alert], tmp_path: Path, **overrides: object
) -> NameResolutionCanaryDetector:
    config = NameResolutionCanaryConfig(state_file=str(tmp_path / "state.json"), **overrides)  # type: ignore[arg-type]
    store = StateStore(tmp_path / "state.json")
    return NameResolutionCanaryDetector(config, collected_alerts.append, store, iface="eth0")


def _llmnr_response(name: str, mac: str = "de:ad:be:ef:00:01", ip: str = "192.168.1.66") -> Ether:
    return (
        Ether(src=mac)
        / IP(src=ip, dst="192.168.1.50")
        / UDP(sport=5355, dport=5355)
        / LLMNRResponse(qr=1, qd=DNSQR(qname=name), an=DNSRR(rrname=name, rdata="6.6.6.6"))
    )


def _mdns_response(name: str, mac: str = "de:ad:be:ef:00:02", ip: str = "192.168.1.77") -> Ether:
    return (
        Ether(src=mac)
        / IP(src=ip, dst="224.0.0.251")
        / UDP(sport=5353, dport=5353)
        / DNS(
            qr=1,
            qd=DNSQR(qname=f"{name}.local"),
            an=DNSRR(rrname=f"{name}.local", rdata="7.7.7.7"),
        )
    )


def _nbns_response(name: str, mac: str = "de:ad:be:ef:00:03", ip: str = "192.168.1.88") -> Ether:
    return (
        Ether(src=mac)
        / IP(src=ip, dst="192.168.1.50")
        / UDP(sport=137, dport=137)
        / NBNSHeader(RESPONSE=1, OPCODE=0, NM_FLAGS=0x50, ANCOUNT=1)
        / NBNSQueryResponse(
            RR_NAME=to_nbns_name(name), ADDR_ENTRY=[NBNS_ADD_ENTRY(NB_ADDRESS="8.8.8.8")]
        )
    )


def test_response_to_own_llmnr_canary_name_triggers_critical_alert(
    collected_alerts: list[Alert], tmp_path: Path
) -> None:
    detector = _make_detector(collected_alerts, tmp_path)
    canary_name = detector._canary_names[0]

    detector.handle_packet(_llmnr_response(canary_name))

    assert len(collected_alerts) == 1
    alert = collected_alerts[0]
    assert alert.severity == Severity.CRITICAL
    assert alert.evidence["queried_name"] == canary_name
    assert alert.evidence["protocol"] == "LLMNR"


def test_llmnr_response_to_unrelated_name_is_ignored(
    collected_alerts: list[Alert], tmp_path: Path
) -> None:
    detector = _make_detector(collected_alerts, tmp_path)

    detector.handle_packet(_llmnr_response("some-real-host"))

    assert collected_alerts == []


def test_response_to_own_mdns_canary_name_triggers_critical_alert(
    collected_alerts: list[Alert], tmp_path: Path
) -> None:
    detector = _make_detector(collected_alerts, tmp_path)
    canary_name = detector._canary_names[0]

    detector.handle_packet(_mdns_response(canary_name))

    assert len(collected_alerts) == 1
    assert collected_alerts[0].evidence["protocol"] == "mDNS"


def test_mdns_response_without_question_section_still_triggers_alert(
    collected_alerts: list[Alert], tmp_path: Path
) -> None:
    # RFC 6762 allows (and real responders like Responder commonly do this)
    # mDNS responses that omit the question section entirely and carry only
    # an answer record - this was a real false negative found via live
    # testing against Responder before the qd/an fallback was added.
    detector = _make_detector(collected_alerts, tmp_path)
    canary_name = detector._canary_names[0]
    response_without_question = (
        Ether(src="de:ad:be:ef:00:02")
        / IP(src="192.168.1.77", dst="224.0.0.251")
        / UDP(sport=5353, dport=5353)
        / DNS(qr=1, qd=[], an=DNSRR(rrname=f"{canary_name}.local", rdata="7.7.7.7"))
    )

    detector.handle_packet(response_without_question)

    assert len(collected_alerts) == 1
    assert collected_alerts[0].evidence["protocol"] == "mDNS"


def test_mdns_query_not_response_is_ignored(collected_alerts: list[Alert], tmp_path: Path) -> None:
    detector = _make_detector(collected_alerts, tmp_path)
    canary_name = detector._canary_names[0]
    query = (
        Ether()
        / IP(src="192.168.1.77", dst="224.0.0.251")
        / UDP(sport=5353, dport=5353)
        / DNS(qr=0, qd=DNSQR(qname=f"{canary_name}.local"))
    )

    detector.handle_packet(query)

    assert collected_alerts == []


def test_response_to_own_nbns_canary_name_triggers_critical_alert(
    collected_alerts: list[Alert], tmp_path: Path
) -> None:
    detector = _make_detector(collected_alerts, tmp_path)
    canary_name = detector._canary_names[0]

    detector.handle_packet(_nbns_response(canary_name))

    assert len(collected_alerts) == 1
    assert collected_alerts[0].evidence["protocol"] == "NBT-NS"


def test_canary_names_are_deterministic_across_restarts(
    collected_alerts: list[Alert], tmp_path: Path
) -> None:
    detector_a = _make_detector(collected_alerts, tmp_path)
    detector_b = _make_detector(collected_alerts, tmp_path)

    assert detector_a._canary_names == detector_b._canary_names


def test_start_sends_a_probe_for_every_name_and_protocol(
    collected_alerts: list[Alert], tmp_path: Path
) -> None:
    detector = _make_detector(
        collected_alerts,
        tmp_path,
        canary_count=2,
        protocols=["llmnr", "mdns"],
        query_interval_seconds=9999,
    )

    with patch("poisonhound.detectors.name_resolution_canary.sendp") as mock_sendp:
        detector.start()
        detector.stop()

    assert mock_sendp.call_count == 4  # 2 names * 2 protocols

from __future__ import annotations

from scapy.layers.l2 import ARP, Ether

from poisonhound.net.evidence import build_evidence


def _sample_packet() -> Ether:
    return Ether(src="aa:bb:cc:dd:ee:ff") / ARP(
        op=2, psrc="192.168.1.1", hwsrc="aa:bb:cc:dd:ee:ff"
    )


def test_build_evidence_contains_summary_and_dump() -> None:
    evidence = build_evidence(_sample_packet())

    assert "192.168.1.1" in evidence["packet_summary"]
    assert "ARP" in evidence["packet_dump"]
    assert "captured_at" in evidence


def test_build_evidence_merges_extra_fields() -> None:
    evidence = build_evidence(_sample_packet(), {"claimed_mac": "aa:bb:cc:dd:ee:ff"})

    assert evidence["claimed_mac"] == "aa:bb:cc:dd:ee:ff"

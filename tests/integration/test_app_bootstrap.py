"""End-to-end style test: config file -> PoisonHoundApp -> detector -> alert -> notifier.

The sniffer itself is never started - a synthetic packet is fed directly
into the dispatcher, exactly as AsyncSniffer's `prn` callback would, so
this exercises the whole stack without touching the network or requiring
elevated privileges.
"""

from __future__ import annotations

from pathlib import Path

from scapy.layers.l2 import ARP, Ether

from poisonhound.app import PoisonHoundApp
from poisonhound.core.alert import Alert
from poisonhound.core.notifier import BaseNotifier

CONFIG_YAML = """
interface: "eth0"
detectors:
  arp_spoof:
    gateway_ip: "192.168.1.1"
    known_gateway_mac: "aa:bb:cc:00:00:01"
  rogue_dhcp:
    enabled: false
  ipv6_rogue_ra:
    enabled: false
  name_resolution_canary:
    enabled: false
notifiers: []
smtp:
  host: "smtp.example.com"
  from_addr: "alerts@example.com"
  to_addrs: ["you@example.com"]
"""


class _FakeNotifier(BaseNotifier):
    name = "fake"

    def __init__(self) -> None:
        self.sent: list[Alert] = []

    def send(self, alert: Alert) -> None:
        self.sent.append(alert)


def _write_config(tmp_path: Path) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(CONFIG_YAML, encoding="utf-8")
    return path


def test_only_enabled_detectors_are_loaded_from_file(tmp_path: Path) -> None:
    app = PoisonHoundApp.from_config_file(_write_config(tmp_path))

    assert len(app.detectors) == 1
    assert app.detectors[0].name == "arp_spoof"
    assert app.dispatcher.combined_bpf_filter() == "(arp)"


def test_full_stack_arp_spoof_alert_reaches_notifier(tmp_path: Path) -> None:
    app = PoisonHoundApp.from_config_file(_write_config(tmp_path))
    fake = _FakeNotifier()
    app.notifiers = [fake]

    spoofed_packet = Ether(src="de:ad:be:ef:00:99") / ARP(
        op=2, psrc="192.168.1.1", hwsrc="de:ad:be:ef:00:99"
    )
    app.dispatcher.dispatch(spoofed_packet)

    alert = app._alert_queue.get_nowait()
    app._process_alert(alert)

    assert len(fake.sent) == 1
    assert fake.sent[0].detector_name == "arp_spoof"
    assert fake.sent[0].source_mac == "de:ad:be:ef:00:99"


def test_matching_gateway_mac_produces_no_alert(tmp_path: Path) -> None:
    app = PoisonHoundApp.from_config_file(_write_config(tmp_path))

    legit_packet = Ether(src="aa:bb:cc:00:00:01") / ARP(
        op=2, psrc="192.168.1.1", hwsrc="aa:bb:cc:00:00:01"
    )
    app.dispatcher.dispatch(legit_packet)

    assert app._alert_queue.empty()

from __future__ import annotations

from poisonhound.core.mac_directory import MacDirectory


def test_lookup_returns_none_for_unknown_mac() -> None:
    directory = MacDirectory()

    assert directory.lookup("aa:bb:cc:dd:ee:ff") is None


def test_observe_then_lookup_returns_the_ip() -> None:
    directory = MacDirectory()

    directory.observe("aa:bb:cc:dd:ee:ff", "192.168.1.50")

    assert directory.lookup("aa:bb:cc:dd:ee:ff") == "192.168.1.50"


def test_lookup_is_case_insensitive() -> None:
    directory = MacDirectory()

    directory.observe("AA:BB:CC:DD:EE:FF", "192.168.1.50")

    assert directory.lookup("aa:bb:cc:dd:ee:ff") == "192.168.1.50"


def test_later_observation_overwrites_the_earlier_ip() -> None:
    directory = MacDirectory()

    directory.observe("aa:bb:cc:dd:ee:ff", "192.168.1.50")
    directory.observe("aa:bb:cc:dd:ee:ff", "192.168.1.99")

    assert directory.lookup("aa:bb:cc:dd:ee:ff") == "192.168.1.99"


def test_different_macs_are_tracked_independently() -> None:
    directory = MacDirectory()

    directory.observe("aa:bb:cc:dd:ee:ff", "192.168.1.50")
    directory.observe("11:22:33:44:55:66", "192.168.1.60")

    assert directory.lookup("aa:bb:cc:dd:ee:ff") == "192.168.1.50"
    assert directory.lookup("11:22:33:44:55:66") == "192.168.1.60"

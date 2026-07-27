from __future__ import annotations

from poisonhound.net.oui_lookup import is_locally_administered, lookup_vendor


def test_known_oui_resolves_to_vendor() -> None:
    assert lookup_vendor("00:0c:29:12:34:56") == "VMware"
    assert lookup_vendor("b8:27:eb:aa:bb:cc") == "Raspberry Pi Foundation"


def test_unknown_oui_returns_none() -> None:
    assert lookup_vendor("11:22:33:44:55:66") is None


def test_locally_administered_mac_is_flagged_instead_of_looked_up() -> None:
    # 02:xx:xx... has the U/L bit set -> locally administered.
    assert is_locally_administered("02:00:00:00:00:01") is True
    assert lookup_vendor("02:00:00:00:00:01") == "Locally administered (randomized/spoofed)"


def test_globally_unique_mac_is_not_flagged_as_locally_administered() -> None:
    assert is_locally_administered("00:0c:29:12:34:56") is False


def test_malformed_mac_returns_none() -> None:
    assert lookup_vendor("not-a-mac") is None

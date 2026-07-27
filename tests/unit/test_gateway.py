from __future__ import annotations

from unittest.mock import MagicMock, patch

from poisonhound.net.gateway import detect_default_gateway


def _iface_obj(name: str) -> MagicMock:
    obj = MagicMock()
    obj.__str__.return_value = name
    return obj


@patch("poisonhound.net.gateway.conf")
def test_returns_gateway_for_the_requested_interface(mock_conf: MagicMock) -> None:
    mock_conf.ifaces.dev_from_name.return_value = _iface_obj("IFACE_A")
    mock_conf.route.routes = [
        (0, 0, "10.0.0.1", "IFACE_A", "10.0.0.50", 30),
    ]

    assert detect_default_gateway("Wi-Fi") == "10.0.0.1"


def test_ignores_default_routes_on_other_interfaces_even_with_lower_metric() -> None:
    # This is the exact failure mode found via manual testing: a VPN tunnel
    # on a different interface had a lower (preferred) metric than the real
    # LAN gateway, so a naive "lowest metric wins across all interfaces"
    # approach would incorrectly pick the VPN's gateway.
    with patch("poisonhound.net.gateway.conf") as mock_conf:
        mock_conf.ifaces.dev_from_name.return_value = _iface_obj("IFACE_A")
        mock_conf.route.routes = [
            (0, 0, "192.0.2.1", "IFACE_VPN", "172.16.0.2", 10),
            (0, 0, "10.0.0.1", "IFACE_A", "10.0.0.50", 30),
        ]

        assert detect_default_gateway("Wi-Fi") == "10.0.0.1"


def test_picks_lowest_metric_when_multiple_routes_on_same_interface() -> None:
    with patch("poisonhound.net.gateway.conf") as mock_conf:
        mock_conf.ifaces.dev_from_name.return_value = _iface_obj("IFACE_A")
        mock_conf.route.routes = [
            (0, 0, "10.0.0.1", "IFACE_A", "10.0.0.50", 100),
            (0, 0, "10.0.0.2", "IFACE_A", "10.0.0.50", 30),
        ]

        assert detect_default_gateway("Wi-Fi") == "10.0.0.2"


def test_returns_none_when_no_default_route_on_the_interface() -> None:
    with patch("poisonhound.net.gateway.conf") as mock_conf:
        mock_conf.ifaces.dev_from_name.return_value = _iface_obj("IFACE_A")
        mock_conf.route.routes = [
            (0, 0, "192.0.2.1", "IFACE_VPN", "172.16.0.2", 10),
        ]

        assert detect_default_gateway("Wi-Fi") is None


def test_returns_none_when_interface_cannot_be_resolved() -> None:
    with patch("poisonhound.net.gateway.conf") as mock_conf:
        mock_conf.ifaces.dev_from_name.side_effect = ValueError("unknown interface")

        assert detect_default_gateway("not-a-real-interface") is None


def test_ignores_non_default_routes() -> None:
    with patch("poisonhound.net.gateway.conf") as mock_conf:
        mock_conf.ifaces.dev_from_name.return_value = _iface_obj("IFACE_A")
        mock_conf.route.routes = [
            (167772160, 4294967040, "0.0.0.0", "IFACE_A", "10.0.0.50", 286),  # 10.0.0.0/24
            (0, 0, "10.0.0.1", "IFACE_A", "10.0.0.50", 30),
        ]

        assert detect_default_gateway("Wi-Fi") == "10.0.0.1"

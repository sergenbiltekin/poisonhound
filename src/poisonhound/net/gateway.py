"""Best-effort default gateway detection, scoped to a specific interface.

Naively asking the OS for "the" default route is unreliable on machines
with several active interfaces/VPNs - verified this directly: on a dev
machine with a VPN client active, scapy's generic `route("0.0.0.0")` chose
the VPN tunnel's gateway over the real LAN gateway. So instead of asking
"what's the default route", this asks "what's the default route for the
specific interface PoisonHound is configured to sniff on" - the same
interface the sniffer itself will actually see traffic on.
"""

from __future__ import annotations

import logging

from scapy.config import conf

logger = logging.getLogger(__name__)


def detect_default_gateway(interface: str) -> str | None:
    """Return the default gateway IP for `interface`, or None if it can't
    be determined (unknown interface, no default route on it, etc.)."""
    try:
        conf.route.resync()
    except Exception:
        logger.debug("gateway auto-detect: route table resync failed", exc_info=True)

    try:
        target_iface = str(conf.ifaces.dev_from_name(interface))
    except Exception:
        logger.debug("gateway auto-detect: could not resolve interface '%s'", interface)
        return None

    best_gateway: str | None = None
    best_metric: int | None = None
    for net, mask, gateway, iface, _out_ip, metric in conf.route.routes:
        if net != 0 or mask != 0:
            continue  # not a default route
        if str(iface) != target_iface:
            continue
        if not gateway or gateway == "0.0.0.0":
            continue
        if best_metric is None or metric < best_metric:
            best_gateway = gateway
            best_metric = metric

    return best_gateway

"""Build the list of enabled detectors from configuration.

New detectors are wired in here as they're implemented; this is the single
place that maps a config section to a concrete BaseDetector subclass.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from poisonhound.core.alert import Alert
from poisonhound.core.config import DetectorsConfig
from poisonhound.core.detector import BaseDetector
from poisonhound.core.mac_directory import MacDirectory
from poisonhound.core.state_store import StateStore
from poisonhound.detectors.arp_spoof import ArpSpoofDetector
from poisonhound.detectors.ipv6_rogue_ra import Ipv6RogueRaDetector
from poisonhound.detectors.name_resolution_canary import NameResolutionCanaryDetector
from poisonhound.detectors.rogue_dhcp import RogueDhcpDetector

logger = logging.getLogger(__name__)


def build_enabled_detectors(
    config: DetectorsConfig,
    on_alert: Callable[[Alert], None],
    iface: str,
    mac_directory: MacDirectory | None = None,
) -> list[BaseDetector]:
    detectors: list[BaseDetector] = []

    if config.arp_spoof.enabled:
        detectors.append(
            ArpSpoofDetector(config.arp_spoof, on_alert, mac_directory=mac_directory, iface=iface)
        )
    else:
        logger.info("arp_spoof detector disabled by config")

    if config.rogue_dhcp.enabled:
        detectors.append(RogueDhcpDetector(config.rogue_dhcp, on_alert, iface=iface))
    else:
        logger.info("rogue_dhcp detector disabled by config")

    if config.ipv6_rogue_ra.enabled:
        detectors.append(Ipv6RogueRaDetector(config.ipv6_rogue_ra, on_alert))
    else:
        logger.info("ipv6_rogue_ra detector disabled by config")

    if config.name_resolution_canary.enabled:
        state_store = StateStore(config.name_resolution_canary.state_file)
        detectors.append(
            NameResolutionCanaryDetector(
                config.name_resolution_canary, on_alert, state_store, iface=iface
            )
        )
    else:
        logger.info("name_resolution_canary detector disabled by config")

    return detectors

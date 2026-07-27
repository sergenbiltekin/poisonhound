"""Best-effort MAC vendor lookup using a small embedded OUI table.

This intentionally does not depend on an external OUI database (such as
Wireshark's manuf file) to keep the project dependency-free and the table
easy to audit. It only covers a handful of high-confidence, commonly-seen
vendors (virtualization platforms and Raspberry Pi, both frequently
involved in rogue DHCP/AP setups on home and lab networks). Anything else
returns None - extending OUI_TABLE with more vendors is a good first
contribution.
"""

from __future__ import annotations

OUI_TABLE: dict[str, str] = {
    # Virtualization platforms - common on lab networks and for running
    # attack tooling (Responder, Inveigh, mitm6, ...) in a VM.
    "000C29": "VMware",
    "005056": "VMware",
    "000569": "VMware",
    "001C14": "VMware",
    "080027": "Oracle VirtualBox",
    "0A0027": "Oracle VirtualBox",
    "001C42": "Parallels",
    "00155D": "Microsoft Hyper-V",
    # Raspberry Pi - cheap, common hardware for rogue DHCP/AP devices.
    "B827EB": "Raspberry Pi Foundation",
    "DCA632": "Raspberry Pi Foundation",
    "E45F01": "Raspberry Pi Foundation",
    "28CDC1": "Raspberry Pi Foundation",
}


def _normalize_mac(mac: str) -> str:
    return mac.replace(":", "").replace("-", "").upper()


def is_locally_administered(mac: str) -> bool:
    """Return True if the MAC's U/L bit marks it as locally administered.

    Locally-administered addresses are not tied to a manufacturer OUI and
    are commonly seen with randomized or deliberately spoofed MACs.
    """
    normalized = _normalize_mac(mac)
    first_octet = int(normalized[0:2], 16)
    return bool(first_octet & 0b10)


def lookup_vendor(mac: str) -> str | None:
    """Best-effort vendor name for a MAC address, or None if unknown."""
    normalized = _normalize_mac(mac)
    if len(normalized) != 12:
        return None
    if is_locally_administered(mac):
        return "Locally administered (randomized/spoofed)"
    return OUI_TABLE.get(normalized[0:6])

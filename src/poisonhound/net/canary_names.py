"""Deterministic canary hostname generation for the name-resolution detector.

Names are derived from a per-installation secret seed via HMAC-SHA256
rather than random/UUID names, so canary names stay stable across restarts
(the seed is persisted - see core/state_store.py) while remaining
unpredictable and practically guaranteed not to collide with any real
hostname on the network. Because these are the only names PoisonHound ever
queries, any response to one is unambiguous evidence of a poisoning tool
rather than a real client's legitimate lookup - this is what makes the
detector's false-positive rate effectively zero.
"""

from __future__ import annotations

import hashlib
import hmac
import os

# NetBIOS names are limited to 15 usable characters on the wire; scapy
# silently truncates to this length when building/dissecting NBT-NS
# packets, so comparisons for that protocol must use the same truncation.
NBNS_MAX_LENGTH = 15


def generate_seed() -> bytes:
    """Generate a new random seed for canary name derivation."""
    return os.urandom(32)


def generate_canary_name(prefix: str, seed: bytes, index: int) -> str:
    """Derive a deterministic, collision-resistant canary hostname."""
    digest = hmac.new(seed, f"{prefix}-{index}".encode(), hashlib.sha256).hexdigest()[:12]
    return f"{prefix}-{digest}"


def generate_canary_names(prefix: str, seed: bytes, count: int) -> list[str]:
    return [generate_canary_name(prefix, seed, i) for i in range(count)]


def to_nbns_name(name: str) -> str:
    """Truncate/uppercase a canary name to match how it appears on the wire
    as a NetBIOS name (see NBNS_MAX_LENGTH)."""
    return name.upper()[:NBNS_MAX_LENGTH]

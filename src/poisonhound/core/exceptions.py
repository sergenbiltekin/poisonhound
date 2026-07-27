"""Exception types used across PoisonHound."""

from __future__ import annotations


class PoisonHoundError(Exception):
    """Base class for all PoisonHound errors."""


class ConfigError(PoisonHoundError):
    """Raised when the configuration file is missing or invalid."""


class DetectorError(PoisonHoundError):
    """Raised for detector setup or runtime failures that should abort startup."""

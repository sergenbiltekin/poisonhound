"""Pydantic configuration models for PoisonHound.

Values are loaded from config.yaml (see config_loader.py) and secrets can be
overridden through environment variables or a .env file using the ``PH_``
prefix and ``__`` as the nested delimiter, e.g. ``PH_SMTP__PASSWORD``.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_MAC_RE = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")


def _validate_mac(value: str) -> str:
    if not _MAC_RE.match(value):
        raise ValueError(f"'{value}' is not a valid MAC address (expected aa:bb:cc:dd:ee:ff)")
    return value.lower()


class LoggingConfig(BaseModel):
    level: str = "INFO"
    format: str = "%(asctime)s %(levelname)s [%(name)s] %(message)s"
    file: str | None = None


class RateLimitConfig(BaseModel):
    dedupe_window_seconds: int = 300


class ArpSpoofConfig(BaseModel):
    enabled: bool = True
    gateway_ip: str
    known_gateway_mac: str | None = None
    check_interval_seconds: int = 5

    @field_validator("known_gateway_mac")
    @classmethod
    def _validate_known_gateway_mac(cls, value: str | None) -> str | None:
        return _validate_mac(value) if value else value


class RogueDhcpConfig(BaseModel):
    enabled: bool = True
    authorized_servers: list[str] = Field(default_factory=list)
    active_probe_enabled: bool = False
    probe_interval_seconds: int = 300


class Ipv6RogueRaConfig(BaseModel):
    enabled: bool = True
    authorized_routers: list[str] = Field(default_factory=list)
    authorized_dhcpv6_servers: list[str] = Field(default_factory=list)


class NameResolutionCanaryConfig(BaseModel):
    enabled: bool = True
    canary_prefix: str = "ph-canary"
    canary_count: int = 3
    query_interval_seconds: int = 60
    protocols: list[str] = Field(default_factory=lambda: ["llmnr", "mdns", "nbns"])
    state_file: str = "poisonhound_state.json"

    @field_validator("protocols")
    @classmethod
    def _validate_protocols(cls, value: list[str]) -> list[str]:
        allowed = {"llmnr", "mdns", "nbns"}
        invalid = set(value) - allowed
        if invalid:
            raise ValueError(
                f"unsupported protocol(s): {sorted(invalid)}; allowed: {sorted(allowed)}"
            )
        return value


class DetectorsConfig(BaseModel):
    arp_spoof: ArpSpoofConfig
    rogue_dhcp: RogueDhcpConfig
    ipv6_rogue_ra: Ipv6RogueRaConfig
    name_resolution_canary: NameResolutionCanaryConfig


class SmtpConfig(BaseModel):
    enabled: bool = True
    host: str
    port: int = 587
    use_tls: bool = True
    username: str | None = None
    password: str | None = None
    from_addr: str
    to_addrs: list[str]
    min_severity: str = "medium"

    @field_validator("min_severity")
    @classmethod
    def _validate_min_severity(cls, value: str) -> str:
        allowed = {"info", "low", "medium", "high", "critical"}
        if value not in allowed:
            raise ValueError(f"min_severity must be one of {sorted(allowed)}")
        return value


class DashboardConfig(BaseModel):
    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = 8787
    username: str = "admin"
    password: str | None = None
    db_path: str = "poisonhound_alerts.db"


class PoisonHoundConfig(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PH_", env_nested_delimiter="__")

    interface: str
    logging: LoggingConfig = LoggingConfig()
    rate_limit: RateLimitConfig = RateLimitConfig()
    detectors: DetectorsConfig
    notifiers: list[str] = Field(default_factory=lambda: ["smtp"])
    smtp: SmtpConfig
    dashboard: DashboardConfig = DashboardConfig()

    @field_validator("interface")
    @classmethod
    def _validate_interface(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("interface must not be empty")
        return value

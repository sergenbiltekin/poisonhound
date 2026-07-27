from __future__ import annotations

from pathlib import Path

import pytest

from poisonhound.core.config_loader import load_config
from poisonhound.core.exceptions import ConfigError

MINIMAL_CONFIG = """
interface: "eth0"
detectors:
  arp_spoof:
    gateway_ip: "192.168.1.1"
  rogue_dhcp: {}
  ipv6_rogue_ra: {}
  name_resolution_canary: {}
smtp:
  host: "smtp.example.com"
  password: null
  from_addr: "alerts@example.com"
  to_addrs: ["you@example.com"]
"""


def _write_config(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(content, encoding="utf-8")
    return path


def test_load_valid_config_applies_defaults(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path, MINIMAL_CONFIG)

    config = load_config(config_path)

    assert config.interface == "eth0"
    assert config.detectors.arp_spoof.gateway_ip == "192.168.1.1"
    assert config.detectors.rogue_dhcp.enabled is True
    assert config.rate_limit.dedupe_window_seconds == 300
    assert config.notifiers == ["smtp"]


def test_missing_file_raises_config_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "does-not-exist.yaml")


def test_invalid_yaml_raises_config_error(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path, "interface: [unclosed")

    with pytest.raises(ConfigError, match="invalid YAML"):
        load_config(config_path)


def test_missing_required_field_raises_config_error(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path, "interface: \"eth0\"\n")

    with pytest.raises(ConfigError):
        load_config(config_path)


def test_null_password_falls_back_to_env_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PH_SMTP__PASSWORD", "secret-from-env")
    config_path = _write_config(tmp_path, MINIMAL_CONFIG)

    config = load_config(config_path)

    assert config.smtp.password == "secret-from-env"


def test_invalid_mac_address_raises_config_error(tmp_path: Path) -> None:
    config_path = _write_config(
        tmp_path,
        MINIMAL_CONFIG.replace(
            'gateway_ip: "192.168.1.1"',
            'gateway_ip: "192.168.1.1"\n    known_gateway_mac: "not-a-mac"',
        ),
    )

    with pytest.raises(ConfigError):
        load_config(config_path)

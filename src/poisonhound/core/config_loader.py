"""Load and validate PoisonHound configuration from a YAML file."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from poisonhound.core.config import PoisonHoundConfig
from poisonhound.core.exceptions import ConfigError


def _strip_none(value: Any) -> Any:
    """Recursively drop dict keys whose value is null.

    Every optional field in our config models defaults to None, so dropping
    explicit nulls lets environment variable overrides (e.g.
    PH_SMTP__PASSWORD) and field defaults still apply for those keys instead
    of being shadowed by an explicit `null` in the YAML file.
    """
    if isinstance(value, dict):
        return {k: _strip_none(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [_strip_none(v) for v in value]
    return value


def load_config(path: str | Path) -> PoisonHoundConfig:
    config_path = Path(path)
    if not config_path.is_file():
        raise ConfigError(f"config file not found: {config_path}")

    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {config_path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise ConfigError(f"{config_path} must contain a YAML mapping at the top level")

    try:
        return PoisonHoundConfig(**_strip_none(raw))
    except ValidationError as exc:
        raise ConfigError(str(exc)) from exc

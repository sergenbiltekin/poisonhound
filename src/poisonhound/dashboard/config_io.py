"""Shared raw config.yaml read/write helpers for the dashboard's settings
and whitelist-from-alert routes - both need to edit the file in place
without disturbing fields the current route doesn't know about."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


def read_raw_config(path: str | Path) -> dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def write_raw_config(path: str | Path, data: dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, sort_keys=False)

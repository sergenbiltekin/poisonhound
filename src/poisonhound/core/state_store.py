"""Minimal persistent state store (a JSON file) for small cross-restart
values - currently just the canary name seed used by the name-resolution
detector."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from poisonhound.net.canary_names import generate_seed

logger = logging.getLogger(__name__)


class StateStore:
    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    def load(self) -> dict[str, str]:
        if not self._path.is_file():
            return {}
        try:
            return json.loads(self._path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            logger.warning("state file at %s is unreadable, starting fresh", self._path)
            return {}

    def save(self, data: dict[str, str]) -> None:
        if self._path.parent != Path():
            self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(data), encoding="utf-8")

    def get_or_create_seed(self, key: str = "canary_seed") -> bytes:
        """Load a hex-encoded seed under `key`, generating and persisting a
        new one on first run."""
        data = self.load()
        if key in data:
            return bytes.fromhex(data[key])
        seed = generate_seed()
        data[key] = seed.hex()
        self.save(data)
        return seed

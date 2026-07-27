"""Logging configuration for PoisonHound."""

from __future__ import annotations

import logging
import sys

from poisonhound.core.config import LoggingConfig


def configure_logging(config: LoggingConfig) -> None:
    """Configure the root logger according to the given LoggingConfig."""
    level = getattr(logging, config.level.upper(), logging.INFO)
    formatter = logging.Formatter(config.format)

    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    root.addHandler(stream_handler)

    if config.file:
        file_handler = logging.FileHandler(config.file, encoding="utf-8")
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)

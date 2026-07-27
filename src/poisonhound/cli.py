"""Command-line entry point for PoisonHound."""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import threading

from poisonhound.app import PoisonHoundApp
from poisonhound.core.config_loader import load_config
from poisonhound.core.exceptions import PoisonHoundError
from poisonhound.logging_setup import configure_logging

logger = logging.getLogger(__name__)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="poisonhound",
        description="Detect ARP spoofing, rogue DHCP, IPv6 RA hijacking, and LLMNR/mDNS/"
        "NBT-NS poisoning on the local network.",
    )
    parser.add_argument(
        "--config",
        default="config.yaml",
        help="Path to config.yaml (default: ./config.yaml)",
    )
    parser.add_argument(
        "--check-config",
        action="store_true",
        help="Validate the configuration file and exit without starting the sniffer.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        config = load_config(args.config)
    except PoisonHoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    # Configured before constructing PoisonHoundApp so that anything logged
    # during detector setup (e.g. auto-detected gateway IP) is visible
    # instead of silently vanishing to the pre-configured root logger.
    configure_logging(config.logging)

    try:
        app = PoisonHoundApp(config, config_path=args.config)
    except PoisonHoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.check_config:
        print(f"Configuration OK: {args.config}")
        return 0

    shutdown = threading.Event()

    def _handle_signal(signum: int, frame: object) -> None:
        logger.info("Received shutdown signal, stopping...")
        shutdown.set()

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    app.run()
    logger.info("PoisonHound is running. Press Ctrl+C to stop.")
    shutdown.wait()
    app.stop()
    return 0

"""The BaseDetector plugin interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable

from scapy.packet import Packet

from poisonhound.core.alert import Alert


class BaseDetector(ABC):
    """Base class for all detection modules.

    Subclasses declare a class-level `name` and `bpf_filter` (the BPF
    expression the dispatcher should route to them), and implement
    `handle_packet`. `handle_packet` runs on the shared sniff thread, so it
    must return quickly and never perform blocking I/O - use `emit()` to hand
    off an Alert to the (asynchronous) notification pipeline instead.
    """

    name: str
    bpf_filter: str | None = None

    def __init__(self, on_alert: Callable[[Alert], None]) -> None:
        self._on_alert = on_alert
        self._running = False

    def start(self) -> None:
        """Start any background activity (timers, active probes).

        Default implementation just marks the detector as running; override
        for detectors that need periodic active behavior (e.g. sending
        canary queries).
        """
        self._running = True

    def stop(self) -> None:
        """Stop background activity started in start()."""
        self._running = False

    @abstractmethod
    def handle_packet(self, packet: Packet) -> None:
        """Handle a single packet delivered by the dispatcher."""

    def emit(self, alert: Alert) -> None:
        self._on_alert(alert)

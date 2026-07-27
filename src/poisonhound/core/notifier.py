"""The BaseNotifier plugin interface."""

from __future__ import annotations

from abc import ABC, abstractmethod

from poisonhound.core.alert import Alert


class BaseNotifier(ABC):
    """Base class for alert delivery channels (SMTP today, others later)."""

    name: str

    @abstractmethod
    def send(self, alert: Alert) -> None:
        """Deliver a notification for the given alert."""

    def close(self) -> None:  # noqa: B027 - intentionally optional to override
        """Release any held resources (connections, etc). Default: no-op."""

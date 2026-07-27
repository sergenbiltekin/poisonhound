"""Placeholder for a future webhook notifier (not implemented in this MVP).

BaseNotifier already gives this a well-defined extension point; this stub
just documents that in code, alongside NOTES.md's "Roadmap / Later" list.
"""

from __future__ import annotations

from poisonhound.core.alert import Alert
from poisonhound.core.notifier import BaseNotifier


class WebhookNotifier(BaseNotifier):
    name = "webhook"

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise NotImplementedError("WebhookNotifier is not implemented yet.")

    def send(self, alert: Alert) -> None:
        raise NotImplementedError

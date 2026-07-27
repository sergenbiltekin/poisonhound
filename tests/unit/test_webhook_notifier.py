from __future__ import annotations

import pytest

from poisonhound.notifiers.webhook_notifier import WebhookNotifier


def test_webhook_notifier_is_not_implemented() -> None:
    with pytest.raises(NotImplementedError):
        WebhookNotifier()

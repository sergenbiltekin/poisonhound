"""Shared FastAPI dependencies for the dashboard: session-based auth and the alert store."""

from __future__ import annotations

from fastapi import Request

from poisonhound.dashboard.store import AlertStore


class NotAuthenticatedError(Exception):
    """Raised by require_auth when there's no valid session.

    Handled by a redirect-to-login exception handler registered in
    create_app(), so protected routes just declare the dependency and don't
    need to think about the unauthenticated case themselves.
    """


def get_store(request: Request) -> AlertStore:
    return request.app.state.store


def require_auth(request: Request) -> str:
    username = request.session.get("username")
    if not username:
        raise NotAuthenticatedError()
    return username

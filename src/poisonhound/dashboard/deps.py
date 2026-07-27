"""Shared FastAPI dependencies for the dashboard: auth and the alert store."""

from __future__ import annotations

import secrets
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from poisonhound.dashboard.store import AlertStore

_security = HTTPBasic()


def get_store(request: Request) -> AlertStore:
    return request.app.state.store


def require_auth(
    request: Request,
    credentials: Annotated[HTTPBasicCredentials, Depends(_security)],
) -> str:
    """HTTP Basic Auth, checked against the live config (so a password
    changed via /settings takes effect without restarting the dashboard)."""
    dashboard_config = request.app.state.get_config().dashboard
    expected_password = dashboard_config.password or request.app.state.effective_password

    valid_user = secrets.compare_digest(credentials.username, dashboard_config.username)
    valid_pass = secrets.compare_digest(credentials.password, expected_password)
    if not (valid_user and valid_pass):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

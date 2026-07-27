"""FastAPI application factory for the PoisonHound web dashboard."""

from __future__ import annotations

import logging
import secrets
from collections.abc import Callable
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from poisonhound.core.config import PoisonHoundConfig
from poisonhound.dashboard.deps import NotAuthenticatedError
from poisonhound.dashboard.routes import alerts, auth, health, settings, whitelist
from poisonhound.dashboard.store import AlertStore

logger = logging.getLogger(__name__)

_TEMPLATES_DIR = Path(__file__).parent / "templates"
_STATIC_DIR = Path(__file__).parent / "static"


def create_app(
    store: AlertStore,
    get_config: Callable[[], PoisonHoundConfig],
    config_path: str | Path,
    reload_config: Callable[[], None] | None = None,
) -> FastAPI:
    """Build the dashboard FastAPI app.

    `get_config` is a callback (not a snapshot) so the dashboard always
    reflects the live config, including changes applied through /settings.
    """
    app = FastAPI(title="PoisonHound Dashboard", docs_url=None, redoc_url=None)

    app.state.store = store
    app.state.get_config = get_config
    app.state.config_path = config_path
    app.state.reload_config = reload_config
    app.state.templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

    dashboard_config = get_config().dashboard
    if dashboard_config.password:
        app.state.effective_password = dashboard_config.password
    else:
        app.state.effective_password = secrets.token_urlsafe(16)
        logger.warning(
            "dashboard: no password configured - generated a random password for this "
            "session (username '%s'): %s\n"
            "Set dashboard.password in config.yaml (or PH_DASHBOARD__PASSWORD) to "
            "persist one across restarts.",
            dashboard_config.username,
            app.state.effective_password,
        )

    app.add_middleware(
        SessionMiddleware,
        secret_key=secrets.token_urlsafe(32),
        session_cookie="ph_session",
        same_site="lax",
        https_only=False,
    )

    @app.exception_handler(NotAuthenticatedError)
    async def _redirect_to_login(request: Request, exc: NotAuthenticatedError) -> RedirectResponse:
        return RedirectResponse(url=f"/login?next={request.url.path}", status_code=303)

    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    app.include_router(auth.router)
    app.include_router(health.router)
    app.include_router(alerts.router)
    app.include_router(settings.router)
    app.include_router(whitelist.router)

    return app

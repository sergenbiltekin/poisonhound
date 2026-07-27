"""FastAPI application factory for the PoisonHound web dashboard."""

from __future__ import annotations

import logging
import secrets
from collections.abc import Callable
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from poisonhound.core.config import PoisonHoundConfig
from poisonhound.dashboard.routes import alerts, health, settings
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

    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    app.include_router(health.router)
    app.include_router(alerts.router)
    app.include_router(settings.router)

    return app

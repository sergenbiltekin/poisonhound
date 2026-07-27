"""Whitelist management: view and remove entries from any detector's
authorized_* list, whether added via the alert page's one-click button or
by hand in config.yaml."""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from poisonhound.dashboard.config_io import read_raw_config, write_raw_config
from poisonhound.dashboard.deps import require_auth

logger = logging.getLogger(__name__)
router = APIRouter()

# (detector config key, list field, detector label, field label)
WHITELIST_FIELDS = [
    ("rogue_dhcp", "authorized_servers", "Rogue DHCP", "Authorized DHCP servers"),
    ("ipv6_rogue_ra", "authorized_routers", "IPv6 rogue RA / mitm6", "Authorized routers"),
    (
        "ipv6_rogue_ra",
        "authorized_dhcpv6_servers",
        "IPv6 rogue RA / mitm6",
        "Authorized DHCPv6 servers",
    ),
]


@router.get("/whitelist", response_class=HTMLResponse)
def whitelist_page(
    request: Request, _user: Annotated[str, Depends(require_auth)]
) -> HTMLResponse:
    templates = request.app.state.templates
    config = request.app.state.get_config()

    groups = []
    for detector_key, field, detector_label, field_label in WHITELIST_FIELDS:
        detector_config = getattr(config.detectors, detector_key)
        entries = getattr(detector_config, field)
        groups.append(
            {
                "detector_key": detector_key,
                "field": field,
                "detector_label": detector_label,
                "field_label": field_label,
                "entries": entries,
            }
        )

    return templates.TemplateResponse(
        request, "whitelist.html", {"active": "whitelist", "groups": groups}
    )


@router.post("/whitelist/remove")
def remove_from_whitelist(
    request: Request,
    _user: Annotated[str, Depends(require_auth)],
    detector: Annotated[str, Form()],
    field: Annotated[str, Form()],
    value: Annotated[str, Form()],
) -> RedirectResponse:
    config_path = request.app.state.config_path
    raw = read_raw_config(config_path)

    entries = raw.get("detectors", {}).get(detector, {}).get(field, [])
    if value in entries:
        entries.remove(value)
        write_raw_config(config_path, raw)

        reload_config = request.app.state.reload_config
        if reload_config is not None:
            try:
                reload_config()
            except Exception:
                logger.exception(
                    "dashboard: reload_config() failed after removing a whitelist entry"
                )

    return RedirectResponse(url="/whitelist", status_code=303)

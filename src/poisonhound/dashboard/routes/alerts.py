"""Alert history routes: the main list view, per-alert detail, and a
one-click "add to whitelist" action for detectors that have one."""

from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from poisonhound.dashboard.config_io import read_raw_config, write_raw_config
from poisonhound.dashboard.deps import get_store, require_auth
from poisonhound.dashboard.store import AlertStore

logger = logging.getLogger(__name__)
router = APIRouter()

_SEVERITIES = ["info", "low", "medium", "high", "critical"]


def _whitelist_target(alert: dict[str, Any]) -> tuple[str, str, str] | None:
    """Return (detector config key, whitelist field, human label) for
    alerts whose detector has a whitelist to add the source to, or None
    for detectors with no such concept (arp_spoof, name_resolution_canary)."""
    detector = alert["detector_name"]
    if detector == "rogue_dhcp":
        return ("rogue_dhcp", "authorized_servers", "authorized DHCP servers")
    if detector == "ipv6_rogue_ra":
        kind = alert["dedup_key"].split(":")[1]  # "ra" or "dhcpv6"
        if kind == "dhcpv6":
            return ("ipv6_rogue_ra", "authorized_dhcpv6_servers", "authorized DHCPv6 servers")
        return ("ipv6_rogue_ra", "authorized_routers", "authorized routers")
    return None


@router.get("/", response_class=HTMLResponse)
def list_alerts(
    request: Request,
    _user: Annotated[str, Depends(require_auth)],
    store: Annotated[AlertStore, Depends(get_store)],
    severity: str | None = None,
    detector: str | None = None,
) -> HTMLResponse:
    templates = request.app.state.templates
    alerts = store.list_alerts(severity=severity, detector=detector, limit=200)
    counts = store.count_by_severity()
    return templates.TemplateResponse(
        request,
        "alerts_list.html",
        {
            "active": "alerts",
            "alerts": alerts,
            "counts": counts,
            "severities": _SEVERITIES,
            "selected_severity": severity,
            "selected_detector": detector,
        },
    )


@router.get("/alerts/{alert_id}", response_class=HTMLResponse)
def alert_detail(
    request: Request,
    alert_id: int,
    _user: Annotated[str, Depends(require_auth)],
    store: Annotated[AlertStore, Depends(get_store)],
    whitelisted: bool = False,
) -> HTMLResponse:
    templates = request.app.state.templates
    alert = store.get_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    target = _whitelist_target(alert)
    return templates.TemplateResponse(
        request,
        "alert_detail.html",
        {
            "active": "alerts",
            "alert": alert,
            "whitelist_label": target[2] if target else None,
            "whitelisted": whitelisted,
        },
    )


@router.post("/alerts/{alert_id}/whitelist")
def whitelist_alert(
    request: Request,
    alert_id: int,
    _user: Annotated[str, Depends(require_auth)],
    store: Annotated[AlertStore, Depends(get_store)],
) -> RedirectResponse:
    alert = store.get_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    target = _whitelist_target(alert)
    if target is None:
        raise HTTPException(
            status_code=400, detail=f"'{alert['detector_name']}' alerts have no whitelist"
        )
    if not alert["source_ip"]:
        raise HTTPException(status_code=400, detail="This alert has no source IP to whitelist")

    detector_key, field, _label = target
    config_path = request.app.state.config_path
    raw = read_raw_config(config_path)

    detectors = raw.setdefault("detectors", {})
    section = detectors.setdefault(detector_key, {})
    entries = section.setdefault(field, [])
    if alert["source_ip"] not in entries:
        entries.append(alert["source_ip"])
        write_raw_config(config_path, raw)

        reload_config = request.app.state.reload_config
        if reload_config is not None:
            try:
                reload_config()
            except Exception:
                logger.exception("dashboard: reload_config() failed after whitelisting an alert")

    return RedirectResponse(url=f"/alerts/{alert_id}?whitelisted=1", status_code=303)

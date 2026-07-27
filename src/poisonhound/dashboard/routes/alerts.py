"""Alert history routes: the main list view and per-alert detail."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse

from poisonhound.dashboard.deps import get_store, require_auth
from poisonhound.dashboard.store import AlertStore

router = APIRouter()

_SEVERITIES = ["info", "low", "medium", "high", "critical"]


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
) -> HTMLResponse:
    templates = request.app.state.templates
    alert = store.get_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return templates.TemplateResponse(
        request, "alert_detail.html", {"active": "alerts", "alert": alert}
    )

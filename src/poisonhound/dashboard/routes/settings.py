"""Settings page: view and edit config.yaml through the dashboard.

Only fields that can be hot-reloaded into the running detectors/notifier
without a restart are exposed here (SMTP delivery settings and each
detector's whitelist-style fields). Changing the network interface or a
detector's enabled/disabled state still requires a restart - see README.
"""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from poisonhound.dashboard.config_io import read_raw_config, write_raw_config
from poisonhound.dashboard.deps import require_auth

logger = logging.getLogger(__name__)
router = APIRouter()


def _split_csv(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


@router.get("/settings", response_class=HTMLResponse)
def settings_form(
    request: Request,
    _user: Annotated[str, Depends(require_auth)],
    saved: bool = False,
) -> HTMLResponse:
    templates = request.app.state.templates
    config = request.app.state.get_config()
    return templates.TemplateResponse(
        request, "settings.html", {"active": "settings", "config": config, "saved": saved}
    )


@router.post("/settings")
def save_settings(
    request: Request,
    _user: Annotated[str, Depends(require_auth)],
    smtp_host: Annotated[str, Form()],
    smtp_port: Annotated[int, Form()],
    smtp_from_addr: Annotated[str, Form()],
    smtp_to_addrs: Annotated[str, Form()],
    smtp_min_severity: Annotated[str, Form()] = "medium",
    smtp_use_tls: Annotated[bool, Form()] = False,
    smtp_username: Annotated[str, Form()] = "",
    smtp_password: Annotated[str, Form()] = "",
    arp_spoof_gateway_ip: Annotated[str, Form()] = "",
    arp_spoof_known_gateway_mac: Annotated[str, Form()] = "",
    rogue_dhcp_authorized_servers: Annotated[str, Form()] = "",
    ipv6_authorized_routers: Annotated[str, Form()] = "",
    ipv6_authorized_dhcpv6_servers: Annotated[str, Form()] = "",
) -> RedirectResponse:
    config_path = request.app.state.config_path
    raw = read_raw_config(config_path)

    smtp = raw.setdefault("smtp", {})
    smtp["host"] = smtp_host
    smtp["port"] = smtp_port
    smtp["use_tls"] = smtp_use_tls
    smtp["username"] = smtp_username or None
    if smtp_password:
        smtp["password"] = smtp_password
    smtp["from_addr"] = smtp_from_addr
    smtp["to_addrs"] = _split_csv(smtp_to_addrs)
    smtp["min_severity"] = smtp_min_severity

    detectors = raw.setdefault("detectors", {})

    arp_spoof = detectors.setdefault("arp_spoof", {})
    arp_spoof["gateway_ip"] = arp_spoof_gateway_ip
    arp_spoof["known_gateway_mac"] = arp_spoof_known_gateway_mac or None

    rogue_dhcp = detectors.setdefault("rogue_dhcp", {})
    rogue_dhcp["authorized_servers"] = _split_csv(rogue_dhcp_authorized_servers)

    ipv6_rogue_ra = detectors.setdefault("ipv6_rogue_ra", {})
    ipv6_rogue_ra["authorized_routers"] = _split_csv(ipv6_authorized_routers)
    ipv6_rogue_ra["authorized_dhcpv6_servers"] = _split_csv(ipv6_authorized_dhcpv6_servers)

    write_raw_config(config_path, raw)

    reload_config = request.app.state.reload_config
    if reload_config is not None:
        try:
            reload_config()
        except Exception:
            logger.exception("dashboard: reload_config() failed after saving settings")

    return RedirectResponse(url="/settings?saved=1", status_code=303)

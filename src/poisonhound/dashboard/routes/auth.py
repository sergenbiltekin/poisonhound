"""Login/logout routes.

A plain HTML form + signed session cookie instead of the browser's native
HTTP Basic Auth popup - that native prompt turned out to behave
inconsistently across browsers (missing entirely in some), and looks out
of place next to the rest of the dashboard anyway.
"""

from __future__ import annotations

import secrets
from typing import Annotated

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

router = APIRouter()


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request, next: str = "/", error: bool = False) -> HTMLResponse:
    templates = request.app.state.templates
    return templates.TemplateResponse(request, "login.html", {"next": next, "error": error})


@router.post("/login")
def login_submit(
    request: Request,
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
    next: Annotated[str, Form()] = "/",
) -> RedirectResponse:
    dashboard_config = request.app.state.get_config().dashboard
    expected_password = dashboard_config.password or request.app.state.effective_password

    valid_user = secrets.compare_digest(username, dashboard_config.username)
    valid_pass = secrets.compare_digest(password, expected_password)

    if not (valid_user and valid_pass):
        return RedirectResponse(url=f"/login?error=1&next={next}", status_code=303)

    request.session["username"] = username
    return RedirectResponse(url=next or "/", status_code=303)


@router.get("/logout")
def logout(request: Request) -> RedirectResponse:
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)

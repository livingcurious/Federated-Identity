"""Browser-facing admin console for the internal IdP surface: a login form (checked
against the same bootstrap admin token as the JSON API), a dashboard listing every live
SSO session, and a bulk force-logout action.

This exists because a browser can't attach a custom ``X-Admin-Token`` header to a plain
link click or form submit -- ``admin.py``'s JSON API needs that header, so it was never
reachable from a browser at all. This router checks the exact same token, the exact same
way (``require_admin``, which now accepts either the header or this console's cookie),
and reuses ``admin.py``'s own revoke sequence -- it is not a separate, parallel admin
surface with its own rules, just a browser-usable front end for the same one.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from starlette import status

from fabric.idp.api.admin import revoke_session_and_notify
from fabric.idp.deps import (
    ADMIN_TOKEN_META_KEY,
    IDP_ADMIN_COOKIE,
    AuditDep,
    SessionDep,
    SettingsDep,
    require_admin,
)
from fabric.idp.persistence.repositories import MetaRepository
from fabric.idp.service.sessions import SessionService
from fabric.idp.service.users import UserService, verify_password

router = APIRouter(tags=["admin-ui"])
_TEMPLATES = Jinja2Templates(directory=str(Path(__file__).resolve().parent.parent / "templates"))
_ADMIN_ACTOR = "admin"


def _set_admin_cookie(response: Response, token: str, cookie_secure: bool) -> None:
    response.set_cookie(
        key=IDP_ADMIN_COOKIE,
        value=token,
        httponly=True,
        secure=cookie_secure,
        samesite="strict",
        path="/admin",
    )


@router.get("/admin/login")
async def admin_login_form(request: Request) -> Response:
    return _TEMPLATES.TemplateResponse(request, "admin_login.html", {"error": None})


@router.post("/admin/login")
async def admin_login(
    request: Request,
    session: SessionDep,
    settings: SettingsDep,
    admin_token: Annotated[str, Form()],
) -> Response:
    stored = await MetaRepository(session).get(ADMIN_TOKEN_META_KEY)
    if stored is None or not verify_password(stored, admin_token):
        return _TEMPLATES.TemplateResponse(
            request,
            "admin_login.html",
            {"error": "Invalid admin token."},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )
    response = RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_303_SEE_OTHER)
    _set_admin_cookie(response, admin_token, settings.cookie_secure)
    return response


@router.get("/admin/logout")
async def admin_logout() -> Response:
    response = RedirectResponse(url="/admin/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(key=IDP_ADMIN_COOKIE, path="/admin")
    return response


@router.get("/admin/dashboard", dependencies=[Depends(require_admin)])
async def admin_dashboard(request: Request, session: SessionDep, settings: SettingsDep) -> Response:
    sessions_svc = SessionService(session, settings)
    users_svc = UserService(session)
    active = await sessions_svc.list_active()

    rows: list[dict[str, Any]] = []
    for s in active:
        profile = await users_svc.profile(s.subject)
        clients = await sessions_svc.clients_for(s.sid)
        rows.append(
            {
                "sid": s.sid,
                "subject": s.subject,
                "email": profile.email if profile else None,
                "name": profile.name if profile else None,
                "clients": clients,
                "created_at": s.created_at,
                "last_seen_at": s.last_seen_at,
                "idle_expiry": s.idle_expiry,
                "absolute_expiry": s.absolute_expiry,
            }
        )
    # Most recently active first -- the ones an operator is most likely acting on.
    rows.sort(key=lambda r: r["last_seen_at"], reverse=True)

    return _TEMPLATES.TemplateResponse(
        request, "admin_dashboard.html", {"sessions": rows, "revoked": request.query_params.get("revoked")}
    )


@router.post("/admin/dashboard/revoke-selected", dependencies=[Depends(require_admin)])
async def admin_dashboard_revoke_selected(
    session: SessionDep,
    settings: SettingsDep,
    audit: AuditDep,
    sids: Annotated[list[str], Form(default_factory=list)],
) -> Response:
    """Force-logout every session the operator checked, in one submit. Each one runs
    the identical revoke + back-channel-fan-out sequence as revoking a single session
    through the JSON API -- this is a bulk *front end*, not a different action."""
    revoked_count = 0
    for sid in sids:
        notified = await revoke_session_and_notify(session, settings, audit, sid, _ADMIN_ACTOR)
        if notified is not None:
            revoked_count += 1
    return RedirectResponse(
        url=f"/admin/dashboard?revoked={revoked_count}", status_code=status.HTTP_303_SEE_OTHER
    )

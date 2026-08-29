"""SP routes: home, login initiation, OIDC callback, profile, logout, back-channel logout."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any
from urllib.parse import urlencode

from fastapi import APIRouter, Form, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from starlette import status

from fabric.common import crypto
from fabric.common.audit import Event, Severity
from fabric.common.config import Settings, SPClientConfig
from fabric.common.domain import PublicUser
from fabric.common.oauth import BACKCHANNEL_LOGOUT_EVENT
from fabric.sp.deps import AuditDep, IdPClientDep, SessionDep, SettingsDep, sp_cookie_name
from fabric.sp.service.errors import LoginError
from fabric.sp.service.idp_client import IdPClient
from fabric.sp.service.login import LoginService
from fabric.sp.service.sessions import SPSessionService

router = APIRouter(tags=["sp"])
_TEMPLATES = Jinja2Templates(directory=str(Path(__file__).resolve().parent.parent / "templates"))

ADMIN_ROLE = "admin"


def _is_admin(user: PublicUser | None) -> bool:
    return user is not None and ADMIN_ROLE in user.roles


def _me(settings: Settings) -> SPClientConfig:
    assert settings.sp_id is not None
    return settings.sp_client(settings.sp_id)


def _others(settings: Settings) -> list[SPClientConfig]:
    return [c for cid, c in settings.sp_clients().items() if cid != settings.sp_id]


def _set_cookie(response: Response, sid: str, settings: Settings) -> None:
    response.set_cookie(
        key=sp_cookie_name(settings),
        value=sid,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        path="/",
    )


def _clear_cookie(response: Response, settings: Settings) -> None:
    response.delete_cookie(key=sp_cookie_name(settings), path="/", samesite="lax")


@router.get("/")
async def home(request: Request, session: SessionDep, settings: SettingsDep) -> Response:
    me = _me(settings)
    sess = await SPSessionService(session, settings).load_valid(
        request.cookies.get(sp_cookie_name(settings))
    )
    user = SPSessionService.to_public_user(sess) if sess is not None else None
    context: dict[str, Any] = {
        "app": me,
        "user": user,
        "others": _others(settings),
        "is_admin": _is_admin(user),
    }
    return _TEMPLATES.TemplateResponse(request, "home.html", context)


@router.get("/login")
async def login(session: SessionDep, settings: SettingsDep, idp: IdPClientDep) -> Response:
    authorize_url = await LoginService(session, settings, idp).begin()
    return RedirectResponse(url=authorize_url, status_code=status.HTTP_302_FOUND)


@router.get("/callback")
async def callback(
    request: Request,
    session: SessionDep,
    settings: SettingsDep,
    idp: IdPClientDep,
    audit: AuditDep,
    code: str = "",
    state: str = "",
    error: str = "",
    error_description: str = "",
) -> Response:
    me = _me(settings)
    if error:
        await audit.record(
            Event.SP_LOGIN_FAILED,
            Severity.WARNING,
            outcome="idp_error",
            detail={"error": error, "error_description": error_description},
        )
        return _TEMPLATES.TemplateResponse(
            request,
            "error.html",
            {"app": me, "message": f"IdP returned an error: {error} — {error_description}"},
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    try:
        claims = await LoginService(session, settings, idp).complete(state=state, code=code)
        sess = await SPSessionService(session, settings).create_from_claims(claims)
    except LoginError as exc:
        await audit.record(
            Event.SP_LOGIN_FAILED, Severity.WARNING, outcome="denied", detail={"reason": str(exc)}
        )
        return _TEMPLATES.TemplateResponse(
            request,
            "error.html",
            {"app": me, "message": str(exc)},
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    await audit.record(
        Event.SP_LOGIN_SUCCEEDED,
        Severity.NOTICE,
        subject=sess.subject,
        outcome="success",
        detail={"idp_sid": sess.idp_sid},
    )
    response = RedirectResponse(url="/profile", status_code=status.HTTP_303_SEE_OTHER)
    _set_cookie(response, sess.sid, settings)
    return response


@router.get("/profile")
async def profile(request: Request, session: SessionDep, settings: SettingsDep) -> Response:
    me = _me(settings)
    sess = await SPSessionService(session, settings).load_valid(
        request.cookies.get(sp_cookie_name(settings))
    )
    if sess is None:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    user = SPSessionService.to_public_user(sess)
    context: dict[str, Any] = {
        "app": me,
        "user": user,
        "sp_sid": sess.sid,
        "idp_sid": sess.idp_sid,
        "others": _others(settings),
        "is_admin": _is_admin(user),
    }
    return _TEMPLATES.TemplateResponse(request, "profile.html", context)


@router.get("/admin")
async def admin_panel(
    request: Request, session: SessionDep, settings: SettingsDep, audit: AuditDep
) -> Response:
    """Admin-only panel. The link is hidden from non-admins in the UI (see home/profile
    templates), but that's cosmetic — this check is the actual security boundary, and it
    re-runs on every request regardless of how the URL was reached."""
    me = _me(settings)
    sessions = SPSessionService(session, settings)
    sess = await sessions.load_valid(request.cookies.get(sp_cookie_name(settings)))
    if sess is None:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    user = SPSessionService.to_public_user(sess)
    if not _is_admin(user):
        await audit.record(
            Event.SP_ADMIN_ACCESS_DENIED,
            Severity.WARNING,
            subject=user.sub,
            outcome="denied",
            detail={"path": "/admin", "roles": user.roles},
        )
        return _TEMPLATES.TemplateResponse(
            request,
            "forbidden.html",
            {"app": me, "message": "This page is restricted to the admin role."},
            status_code=status.HTTP_403_FORBIDDEN,
        )
    active = await sessions.list_active()
    context: dict[str, Any] = {"app": me, "sessions": active}
    return _TEMPLATES.TemplateResponse(request, "admin.html", context)


@router.post("/admin/revoke-all")
async def admin_revoke_all(
    request: Request, session: SessionDep, settings: SettingsDep, audit: AuditDep
) -> Response:
    """The action half of the admin panel: same role check, enforced independently of
    the GET view above — a POST straight to this URL is checked exactly the same way."""
    sessions = SPSessionService(session, settings)
    sess = await sessions.load_valid(request.cookies.get(sp_cookie_name(settings)))
    if sess is None:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    user = SPSessionService.to_public_user(sess)
    if not _is_admin(user):
        await audit.record(
            Event.SP_ADMIN_ACCESS_DENIED,
            Severity.WARNING,
            subject=user.sub,
            outcome="denied",
            detail={"path": "/admin/revoke-all", "roles": user.roles},
        )
        return _TEMPLATES.TemplateResponse(
            request,
            "forbidden.html",
            {"app": _me(settings), "message": "This action is restricted to the admin role."},
            status_code=status.HTTP_403_FORBIDDEN,
        )
    revoked = await sessions.revoke_all()
    await audit.record(
        Event.SP_ADMIN_SESSIONS_REVOKED,
        Severity.ALERT,
        subject=user.sub,
        outcome="revoked",
        detail={"count": revoked},
    )
    return RedirectResponse(url="/admin", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/logout")
async def logout(request: Request, session: SessionDep, settings: SettingsDep) -> Response:
    me = _me(settings)
    sessions = SPSessionService(session, settings)
    sess = await sessions.load_valid(request.cookies.get(sp_cookie_name(settings)))
    if sess is not None:
        await sessions.revoke(sess.sid)

    # RP-initiated logout: ask the IdP to end the SSO session and fan out to the others.
    query = urlencode(
        {"client_id": me.client_id, "post_logout_redirect_uri": me.post_logout_redirect_uri}
    )
    target = f"{settings.idp_issuer}/logout?{query}"
    response = RedirectResponse(url=target, status_code=status.HTTP_303_SEE_OTHER)
    _clear_cookie(response, settings)
    return response


@router.post("/backchannel-logout")
async def backchannel_logout(
    session: SessionDep,
    settings: SettingsDep,
    idp: IdPClientDep,
    audit: AuditDep,
    logout_token: Annotated[str, Form()],
) -> JSONResponse:
    claims = await _verify_logout_token(logout_token, settings=settings, idp=idp)
    if claims is None:
        await audit.record(
            Event.SP_BACKCHANNEL_REJECTED,
            Severity.WARNING,
            outcome="rejected",
            detail={"reason": "logout_token failed verification"},
        )
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST, content={"error": "invalid logout_token"}
        )
    idp_sid = str(claims.get("sid", ""))
    killed = await SPSessionService(session, settings).revoke_by_idp_sid(idp_sid)
    await audit.record(
        Event.SP_BACKCHANNEL_RECEIVED,
        Severity.NOTICE,
        subject=str(claims.get("sub")) or None,
        outcome="applied",
        detail={"idp_sid": idp_sid, "revoked_sessions": killed},
    )
    return JSONResponse(status_code=status.HTTP_200_OK, content={"revoked_sessions": killed})


async def _verify_logout_token(
    token: str, *, settings: Settings, idp: IdPClient
) -> dict[str, Any] | None:
    assert settings.sp_id is not None
    try:
        keyset = await idp.keyset_for(crypto.read_kid(token))
        claims = crypto.verify_jwt(
            token,
            keyset,
            issuer=settings.idp_issuer,
            audience=settings.sp_id,
            require=("iat", "exp"),
        )
    except Exception:  # noqa: BLE001 - any JOSE verification failure ⇒ reject the token
        return None
    events = claims.get("events")
    if not isinstance(events, dict) or BACKCHANNEL_LOGOUT_EVENT not in events:
        return None
    if "nonce" in claims:  # a logout token must not carry a nonce
        return None
    if not claims.get("sid"):
        return None
    return claims

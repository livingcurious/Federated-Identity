"""User-facing IdP surface: home, the login UI, the authorize endpoint, and logout.

The login form re-carries the original ``/authorize`` parameters as hidden fields, so a
successful sign-in can resume the authorization request and redirect back to the SP.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any
from urllib.parse import urlencode

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from starlette import status

from fabric.common.audit import Event, Severity
from fabric.common.config import Settings
from fabric.idp.api.endpoints import LOGIN_PATH
from fabric.idp.deps import IDP_SESSION_COOKIE, AuditDep, SessionDep, SettingsDep
from fabric.idp.persistence.models import IdPSessionRow
from fabric.idp.service.clients import ClientService
from fabric.idp.service.errors import AuthenticationError, InvalidRequestError, ServiceError
from fabric.idp.service.flows import OIDCFlowService
from fabric.idp.service.logout import LogoutService, deliver_logout_tokens
from fabric.idp.service.sessions import SessionService
from fabric.idp.service.users import UserService

router = APIRouter(tags=["auth-ui"])
_TEMPLATES = Jinja2Templates(directory=str(Path(__file__).resolve().parent.parent / "templates"))


def _set_session_cookie(response: Response, sid: str, settings: Settings) -> None:
    response.set_cookie(
        key=IDP_SESSION_COOKIE,
        value=sid,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        path="/",
    )


def _clear_session_cookie(response: Response, settings: Settings) -> None:
    response.delete_cookie(key=IDP_SESSION_COOKIE, path="/", samesite="lax")


def _validate_authorize_params(params: dict[str, str]) -> None:
    if params.get("response_type") != "code":
        raise InvalidRequestError("only response_type=code is supported")
    if params.get("code_challenge_method") != "S256":
        raise InvalidRequestError("code_challenge_method must be S256")
    if not params.get("code_challenge"):
        raise InvalidRequestError("code_challenge is required (PKCE is mandatory)")
    if "openid" not in params.get("scope", "").split():
        raise InvalidRequestError("scope must include 'openid'")


async def _resume_authorization(
    *, session: SessionDep, settings: Settings, sess_row: IdPSessionRow, params: dict[str, str]
) -> RedirectResponse:
    """Mint an authorization code for a live session and redirect back to the SP."""
    clients = ClientService(session, settings)
    client = await clients.get(params["client_id"])
    if params["redirect_uri"] != client.redirect_uri:
        raise InvalidRequestError("redirect_uri does not match the registered value")

    flow = OIDCFlowService(session, settings)
    code = await flow.issue_authorization_code(
        client=client,
        subject=sess_row.subject,
        sid=sess_row.sid,
        redirect_uri=params["redirect_uri"],
        code_challenge=params["code_challenge"],
        nonce=params.get("nonce", ""),
    )
    query = urlencode({"code": code, "state": params.get("state", "")})
    return RedirectResponse(
        url=f"{params['redirect_uri']}?{query}", status_code=status.HTTP_303_SEE_OTHER
    )


@router.get("/")
async def home(request: Request, session: SessionDep, settings: SettingsDep) -> Response:
    sess = await SessionService(session, settings).load_valid(request.cookies.get(IDP_SESSION_COOKIE))
    user = await UserService(session).profile(sess.subject) if sess is not None else None
    context: dict[str, Any] = {
        "issuer": settings.idp_issuer,
        "user": user,
        "sps": list(settings.sp_clients().values()),
    }
    return _TEMPLATES.TemplateResponse(request, "home.html", context)


@router.get("/authorize")
async def authorize(
    request: Request,
    session: SessionDep,
    settings: SettingsDep,
    response_type: str,
    client_id: str,
    redirect_uri: str,
    code_challenge: str,
    state: str = "",
    nonce: str = "",
    code_challenge_method: str = "S256",
    scope: str = "openid",
) -> Response:
    params = {
        "response_type": response_type,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "scope": scope,
    }
    try:
        _validate_authorize_params(params)
        clients = ClientService(session, settings)
        client = await clients.get(client_id)
        if redirect_uri != client.redirect_uri:
            raise InvalidRequestError("redirect_uri does not match the registered value")
    except ServiceError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=exc.description) from exc

    sess = await SessionService(session, settings).load_valid(request.cookies.get(IDP_SESSION_COOKIE))
    if sess is not None:
        return await _resume_authorization(
            session=session, settings=settings, sess_row=sess, params=params
        )

    return _TEMPLATES.TemplateResponse(
        request,
        "login.html",
        {"client_name": client.display_name, "params": params, "error": None, "email": ""},
    )


@router.post(LOGIN_PATH)
async def login(
    request: Request,
    session: SessionDep,
    settings: SettingsDep,
    audit: AuditDep,
    email: Annotated[str, Form()],
    password: Annotated[str, Form()],
    response_type: Annotated[str, Form()],
    client_id: Annotated[str, Form()],
    redirect_uri: Annotated[str, Form()],
    code_challenge: Annotated[str, Form()],
    state: Annotated[str, Form()] = "",
    nonce: Annotated[str, Form()] = "",
    code_challenge_method: Annotated[str, Form()] = "S256",
    scope: Annotated[str, Form()] = "openid",
) -> Response:
    params = {
        "response_type": response_type,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "scope": scope,
    }
    clients = ClientService(session, settings)
    try:
        _validate_authorize_params(params)
        client = await clients.get(client_id)
        if redirect_uri != client.redirect_uri:
            raise InvalidRequestError("redirect_uri does not match the registered value")
    except ServiceError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=exc.description) from exc

    try:
        user = await UserService(session).authenticate(email, password)
    except AuthenticationError as exc:
        await audit.record(
            Event.LOGIN_FAILED,
            Severity.WARNING,
            client_id=client_id,
            outcome="denied",
            detail={"email": email, "reason": exc.description},
        )
        return _TEMPLATES.TemplateResponse(
            request,
            "login.html",
            {"client_name": client.display_name, "params": params, "error": exc.description, "email": email},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    sess = await SessionService(session, settings).create(user.sub)
    await audit.record(
        Event.LOGIN_SUCCEEDED,
        Severity.NOTICE,
        subject=user.sub,
        client_id=client_id,
        outcome="success",
        detail={"sid": sess.sid},
    )
    response = await _resume_authorization(
        session=session, settings=settings, sess_row=sess, params=params
    )
    _set_session_cookie(response, sess.sid, settings)
    return response


@router.get("/logout")
async def logout(
    request: Request,
    session: SessionDep,
    settings: SettingsDep,
    audit: AuditDep,
    client_id: str = "",
    post_logout_redirect_uri: str = "",
    state: str = "",
) -> Response:
    sessions = SessionService(session, settings)
    sess = await sessions.load_valid(request.cookies.get(IDP_SESSION_COOKIE))

    if sess is not None:
        logout_service = LogoutService(session, settings)
        tokens = await logout_service.build_logout_tokens(sid=sess.sid, subject=sess.subject)
        await sessions.revoke(sess.sid)
        await deliver_logout_tokens(tokens)
        await audit.record(
            Event.BACKCHANNEL_SENT,
            Severity.NOTICE,
            subject=sess.subject,
            outcome="user_logout",
            detail={"sid": sess.sid, "targets": list(tokens.keys())},
        )

    target = await _resolve_post_logout_target(
        session=session,
        settings=settings,
        client_id=client_id,
        post_logout_redirect_uri=post_logout_redirect_uri,
        state=state,
    )
    response = RedirectResponse(url=target, status_code=status.HTTP_303_SEE_OTHER)
    _clear_session_cookie(response, settings)
    return response


async def _resolve_post_logout_target(
    *,
    session: SessionDep,
    settings: Settings,
    client_id: str,
    post_logout_redirect_uri: str,
    state: str,
) -> str:
    """Only redirect to a post-logout URI that the named client actually registered."""
    if client_id and post_logout_redirect_uri:
        client = await ClientService(session, settings).get_optional(client_id)
        if client is not None and post_logout_redirect_uri == client.post_logout_redirect_uri:
            query = urlencode({"state": state}) if state else ""
            return f"{post_logout_redirect_uri}?{query}" if query else post_logout_redirect_uri
    return "/"

"""Admin surface (bootstrap-token protected): key rotation/revocation, session control,
and a read-only view of the security audit trail.

This is demo tooling that exercises the containment levers — not a production console.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from starlette import status

from fabric.common.audit import Event, Severity
from fabric.common.domain import AuditEventView, SessionInfo, SigningKeyView
from fabric.idp.deps import AuditDep, SessionDep, SettingsDep, require_admin
from fabric.idp.persistence.repositories import AuditRepository
from fabric.idp.service.clients import ClientService
from fabric.idp.service.errors import ServiceError
from fabric.idp.service.keys import KeyService
from fabric.idp.service.logout import LogoutService, deliver_logout_tokens
from fabric.idp.service.sessions import SessionService

router = APIRouter(prefix="/admin", tags=["admin"], dependencies=[Depends(require_admin)])
_ADMIN_ACTOR = "admin"


@router.get("/keys", response_model=list[SigningKeyView])
async def list_keys(session: SessionDep) -> list[SigningKeyView]:
    return await KeyService(session).list_keys()


@router.post("/keys/rotate", status_code=status.HTTP_201_CREATED)
async def rotate_key(session: SessionDep, audit: AuditDep) -> dict[str, str]:
    new_kid = await KeyService(session).rotate()
    await audit.record(
        Event.KEY_ROTATED, Severity.NOTICE, actor=_ADMIN_ACTOR, detail={"active_kid": new_kid}
    )
    return {"active_kid": new_kid}


@router.post("/keys/{kid}/retire", status_code=status.HTTP_204_NO_CONTENT)
async def retire_key(session: SessionDep, audit: AuditDep, kid: str) -> None:
    try:
        await KeyService(session).retire(kid)
    except ServiceError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=exc.description) from exc
    await audit.record(Event.KEY_RETIRED, Severity.NOTICE, actor=_ADMIN_ACTOR, detail={"kid": kid})


@router.post("/keys/{kid}/revoke", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_key(session: SessionDep, audit: AuditDep, kid: str) -> None:
    try:
        await KeyService(session).revoke(kid)
    except ServiceError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=exc.description) from exc
    await audit.record(Event.KEY_REVOKED, Severity.ALERT, actor=_ADMIN_ACTOR, detail={"kid": kid})


@router.get("/sessions", response_model=list[SessionInfo])
async def list_sessions(session: SessionDep, settings: SettingsDep) -> list[SessionInfo]:
    return await SessionService(session, settings).list_active()


@router.post("/sessions/{sid}/revoke")
async def revoke_session(
    session: SessionDep, settings: SettingsDep, audit: AuditDep, sid: str
) -> dict[str, list[str] | str]:
    sessions = SessionService(session, settings)
    row = await sessions.load_valid(sid)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="no such active session")

    logout_service = LogoutService(session, settings)
    tokens = await logout_service.build_logout_tokens(sid=row.sid, subject=row.subject)
    await sessions.revoke(row.sid)
    await deliver_logout_tokens(tokens)
    await audit.record(
        Event.SESSION_REVOKED,
        Severity.ALERT,
        actor=_ADMIN_ACTOR,
        subject=row.subject,
        outcome="revoked",
        detail={"sid": sid, "notified": list(tokens.keys())},
    )
    return {"revoked": sid, "notified": list(tokens.keys())}


@router.get("/audit", response_model=list[AuditEventView])
async def list_audit(session: SessionDep, limit: int = 100) -> list[AuditEventView]:
    rows = await AuditRepository(session).recent(limit=limit)
    return [AuditEventView.model_validate(row) for row in rows]


class RegisterKeyRequest(BaseModel):
    public_jwk: dict[str, Any]


@router.post("/clients/{client_id}/revoke-key", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_client_key(session: SessionDep, settings: SettingsDep, audit: AuditDep, client_id: str) -> None:
    """Compromise containment: instantly stop this SP's current key from authenticating.

    Use this first, before rotation — it takes effect without needing any access to the
    SP's own database, and stops a leaked key from being usable against the IdP from
    anywhere on the network.
    """
    try:
        await ClientService(session, settings).revoke_key(client_id)
    except ServiceError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=exc.description) from exc
    await audit.record(
        Event.CLIENT_KEY_REVOKED, Severity.ALERT, actor=_ADMIN_ACTOR, client_id=client_id
    )


@router.post("/clients/{client_id}/register-key", status_code=status.HTTP_204_NO_CONTENT)
async def register_client_key(
    session: SessionDep,
    settings: SettingsDep,
    audit: AuditDep,
    client_id: str,
    body: RegisterKeyRequest,
) -> None:
    """Recovery step after revocation: install the SP's freshly-generated public key.

    The SP generates a new keypair locally (``scripts/rotate_sp_key.py``) and hands only
    the public JWK to the operator out-of-band; the private half never leaves the SP.
    """
    try:
        await ClientService(session, settings).register_key(client_id, body.public_jwk)
    except ServiceError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=exc.description) from exc
    await audit.record(
        Event.CLIENT_KEY_REGISTERED, Severity.NOTICE, actor=_ADMIN_ACTOR, client_id=client_id
    )

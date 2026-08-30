"""FastAPI dependencies for an SP: DB session, settings, and the shared IdP client."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from fabric.common.audit import AuditLog
from fabric.common.config import Settings, get_settings
from fabric.sp.persistence.models import AuditEventRow
from fabric.sp.service.idp_client import IdPClient

# Cookies are not port-specific, so two SPs on the same host must use distinct cookie
# names or they would clobber each other's session. Name the cookie per client_id.
SP_SESSION_COOKIE_PREFIX = "fabric_sp_"


def sp_cookie_name(settings: Settings) -> str:
    assert settings.sp_id is not None
    return SP_SESSION_COOKIE_PREFIX + settings.sp_id.replace("-", "_")


def get_settings_dep() -> Settings:
    return get_settings()


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    maker: async_sessionmaker[AsyncSession] = request.app.state.sessionmaker
    async with maker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


def get_idp(request: Request) -> IdPClient:
    idp: IdPClient = request.app.state.idp
    return idp


def client_ip(request: Request, settings: Settings) -> str | None:
    """The caller's IP — ``X-Forwarded-For`` is only honored from a configured trusted
    proxy; otherwise it is attacker-controlled and would let anyone spoof the source IP
    recorded in the security audit trail.

    Trusting the direct peer only certifies the *last* hop it appended to the header —
    every earlier entry could have been typed in by the original caller before the
    request ever reached that proxy. So this takes the last entry, not the first."""
    direct = request.client.host if request.client else None
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded and direct in settings.trusted_proxy_ip_set:
        return forwarded.split(",")[-1].strip()
    return direct


SessionDep = Annotated[AsyncSession, Depends(get_session)]
SettingsDep = Annotated[Settings, Depends(get_settings_dep)]
IdPClientDep = Annotated[IdPClient, Depends(get_idp)]


def get_auditor(request: Request, session: SessionDep, settings: SettingsDep) -> AuditLog:
    return AuditLog(
        session,
        AuditEventRow,
        request_id=getattr(request.state, "request_id", None),
        source_ip=client_ip(request, settings),
    )


AuditDep = Annotated[AuditLog, Depends(get_auditor)]

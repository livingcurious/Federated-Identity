"""FastAPI dependencies for the IdP: DB session (unit of work), settings, admin auth."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from starlette import status

from fabric.common.audit import AuditLog
from fabric.common.config import Settings, get_settings
from fabric.idp.persistence.models import AuditEventRow
from fabric.idp.persistence.repositories import MetaRepository
from fabric.idp.service.users import verify_password

IDP_SESSION_COOKIE = "fabric_idp_sid"
ADMIN_TOKEN_META_KEY = "admin_token_hash"


def get_settings_dep() -> Settings:
    return get_settings()


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    """Yield a session and commit at the end of the request (rollback on error)."""
    maker: async_sessionmaker[AsyncSession] = request.app.state.sessionmaker
    async with maker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


SessionDep = Annotated[AsyncSession, Depends(get_session)]
SettingsDep = Annotated[Settings, Depends(get_settings_dep)]


def client_ip(request: Request, settings: Settings) -> str | None:
    """The caller's IP — ``X-Forwarded-For`` is only honored from a configured trusted
    proxy; otherwise it is attacker-controlled and would let anyone spoof the source IP
    recorded in the security audit trail."""
    direct = request.client.host if request.client else None
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded and direct in settings.trusted_proxy_ip_set:
        return forwarded.split(",")[0].strip()
    return direct


def get_auditor(request: Request, session: SessionDep, settings: SettingsDep) -> AuditLog:
    return AuditLog(
        session,
        AuditEventRow,
        request_id=getattr(request.state, "request_id", None),
        source_ip=client_ip(request, settings),
    )


AuditDep = Annotated[AuditLog, Depends(get_auditor)]


async def require_admin(
    session: SessionDep,
    x_admin_token: Annotated[str | None, Header(alias="X-Admin-Token")] = None,
) -> None:
    """Guard the admin surface with the bootstrap admin token (compared against its hash)."""
    stored = await MetaRepository(session).get(ADMIN_TOKEN_META_KEY)
    if stored is None or not x_admin_token or not verify_password(stored, x_admin_token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or missing admin token",
        )

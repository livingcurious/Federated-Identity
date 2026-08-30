"""FastAPI dependencies for the IdP: DB session (unit of work), settings, admin auth."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import Cookie, Depends, Header, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from starlette import status

from fabric.common.audit import AuditLog
from fabric.common.config import Settings, get_settings
from fabric.idp.persistence.models import AuditEventRow
from fabric.idp.persistence.repositories import MetaRepository
from fabric.idp.service.users import verify_password

IDP_SESSION_COOKIE = "fabric_idp_sid"
ADMIN_TOKEN_META_KEY = "admin_token_hash"
# The admin console (admin_ui.py) sets this cookie's value to the admin token itself,
# after checking it the same way the header path does -- a browser can't attach a
# custom header to a plain link click or form submit, so it needs its own credential
# carrier. Scoped to /admin only, HttpOnly, SameSite=Strict.
IDP_ADMIN_COOKIE = "fabric_admin_session"

# The public app and the internal app are separate processes (see main.py) and each
# gets its own copy of this module-level lock -- correctly so: it only needs to
# serialize DB access *within* one process. Cross-process consistency between the two
# (both writing idp.db) is WAL mode's job (common/database.py), not this lock's --
# asyncio.Lock can't span processes anyway. Same rationale as sp/deps.py's lock: SQLite's
# own busy-timeout retry proved unreliable under real concurrent load in this project's
# container environment.
_DB_LOCK = asyncio.Lock()


def get_settings_dep() -> Settings:
    return get_settings()


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    """Yield a session and commit at the end of the request (rollback on error)."""
    maker: async_sessionmaker[AsyncSession] = request.app.state.sessionmaker
    async with _DB_LOCK, maker() as session:
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
    recorded in the security audit trail.

    Trusting the direct peer only certifies the *last* hop it appended to the header —
    every earlier entry could have been typed in by the original caller before the
    request ever reached that proxy. So this takes the last entry, not the first."""
    direct = request.client.host if request.client else None
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded and direct in settings.trusted_proxy_ip_set:
        return forwarded.split(",")[-1].strip()
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
    admin_cookie: Annotated[str | None, Cookie(alias=IDP_ADMIN_COOKIE)] = None,
) -> None:
    """Guard the admin surface with the bootstrap admin token (compared against its
    hash) -- via the header (the raw API, scripts, curl) or the admin-console cookie
    (the browser UI). Same credential, same check, either carrier."""
    stored = await MetaRepository(session).get(ADMIN_TOKEN_META_KEY)
    candidate = x_admin_token or admin_cookie
    if stored is None or not candidate or not verify_password(stored, candidate):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or missing admin token",
        )

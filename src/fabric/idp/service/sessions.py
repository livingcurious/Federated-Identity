"""IdP SSO session lifecycle: create, validate-and-slide, revoke.

Sessions are server-side rows keyed by an opaque ``sid`` (the cookie only carries the
``sid``). They enforce both an idle timeout (slides on use) and an absolute cap, and
they persist in SQLite so a restart does not log everybody out.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from fabric.common import crypto
from fabric.common.clock import is_expired, utc_in, utc_now
from fabric.common.config import Settings
from fabric.common.domain import SessionInfo
from fabric.idp.persistence.models import IdPSessionRow
from fabric.idp.persistence.repositories import SessionRepository


class SessionService:
    def __init__(self, session: AsyncSession, settings: Settings) -> None:
        self._repo = SessionRepository(session)
        self._settings = settings

    async def create(self, subject: str) -> IdPSessionRow:
        now = utc_now()
        row = IdPSessionRow(
            sid=crypto.new_opaque("sid_"),
            subject=subject,
            created_at=now,
            last_seen_at=now,
            idle_expiry=utc_in(self._settings.idp_session_idle_seconds),
            absolute_expiry=utc_in(self._settings.idp_session_absolute_seconds),
            revoked=False,
        )
        await self._repo.add(row)
        return row

    async def load_valid(self, sid: str | None) -> IdPSessionRow | None:
        """Return a live session, sliding its idle window; else ``None``."""
        if not sid:
            return None
        row = await self._repo.get(sid)
        if row is None or row.revoked:
            return None
        if is_expired(row.absolute_expiry) or is_expired(row.idle_expiry):
            return None
        row.last_seen_at = utc_now()
        row.idle_expiry = utc_in(self._settings.idp_session_idle_seconds)
        return row

    async def revoke(self, sid: str) -> IdPSessionRow | None:
        row = await self._repo.get(sid)
        if row is None:
            return None
        row.revoked = True
        return row

    async def record_client(self, sid: str, client_id: str) -> None:
        await self._repo.record_client(sid, client_id)

    async def clients_for(self, sid: str) -> list[str]:
        return await self._repo.clients_for(sid)

    async def list_active(self) -> list[SessionInfo]:
        rows = await self._repo.all_active()
        return [SessionInfo.model_validate(row) for row in rows]

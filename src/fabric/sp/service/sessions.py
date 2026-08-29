"""SP-local session lifecycle. Independent from the IdP session, but linked to it via
``idp_sid`` so back-channel logout can tear it down."""

from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from fabric.common import crypto
from fabric.common.clock import is_expired, utc_in, utc_now
from fabric.common.config import Settings
from fabric.common.domain import PublicUser
from fabric.sp.persistence.models import SPSessionRow
from fabric.sp.persistence.repositories import SPSessionRepository, SPUserRoleRepository


class SPSessionService:
    def __init__(self, session: AsyncSession, settings: Settings) -> None:
        self._repo = SPSessionRepository(session)
        self._roles = SPUserRoleRepository(session)
        self._settings = settings

    async def create_from_claims(self, claims: dict[str, Any]) -> SPSessionRow:
        subject = str(claims["sub"])
        # Roles are entirely local to this SP — never asserted by the IdP (see
        # DESIGN.md's role-decoupling rationale). First-ever login here gets the
        # default role, written through so the HR panel's roster is always complete.
        role_row = await self._roles.get(subject)
        if role_row is not None:
            roles = list(role_row.roles)
        else:
            roles = ["user"]
            await self._roles.upsert(subject, roles)

        now = utc_now()
        row = SPSessionRow(
            sid=crypto.new_opaque("spsid_"),
            subject=subject,
            idp_sid=str(claims.get("sid", "")),
            email=str(claims.get("email", "")),
            name=str(claims.get("name", "")),
            roles=roles,
            created_at=now,
            last_seen_at=now,
            idle_expiry=utc_in(self._settings.sp_session_idle_seconds),
            absolute_expiry=utc_in(self._settings.sp_session_absolute_seconds),
            revoked=False,
        )
        await self._repo.add(row)
        return row

    async def load_valid(self, sid: str | None) -> SPSessionRow | None:
        if not sid:
            return None
        row = await self._repo.get(sid)
        if row is None or row.revoked:
            return None
        if is_expired(row.absolute_expiry) or is_expired(row.idle_expiry):
            return None
        row.last_seen_at = utc_now()
        row.idle_expiry = utc_in(self._settings.sp_session_idle_seconds)
        return row

    async def revoke(self, sid: str) -> None:
        row = await self._repo.get(sid)
        if row is not None:
            row.revoked = True

    async def revoke_by_idp_sid(self, idp_sid: str) -> int:
        return await self._repo.revoke_by_idp_sid(idp_sid)

    async def list_active(self) -> list[SPSessionRow]:
        return await self._repo.all_active()

    async def revoke_all(self) -> int:
        return await self._repo.revoke_all_active()

    @staticmethod
    def to_public_user(row: SPSessionRow) -> PublicUser:
        return PublicUser(sub=row.subject, email=row.email, name=row.name, roles=list(row.roles))

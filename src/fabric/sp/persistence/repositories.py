"""Async repositories for an SP: its client key, sessions, and pending-auth state."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from fabric.sp.persistence.models import SPClientKeyRow, SPPendingAuthRow, SPSessionRow


class ClientKeyRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def get(self, client_id: str) -> SPClientKeyRow | None:
        return await self._s.get(SPClientKeyRow, client_id)

    async def upsert(self, row: SPClientKeyRow) -> None:
        existing = await self._s.get(SPClientKeyRow, row.client_id)
        if existing is None:
            self._s.add(row)
            return
        existing.kid = row.kid
        existing.public_jwk = row.public_jwk
        existing.private_jwk = row.private_jwk


class SPSessionRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def add(self, row: SPSessionRow) -> None:
        self._s.add(row)

    async def get(self, sid: str) -> SPSessionRow | None:
        return await self._s.get(SPSessionRow, sid)

    async def all_active(self) -> list[SPSessionRow]:
        result = await self._s.execute(
            select(SPSessionRow).where(SPSessionRow.revoked.is_(False))
        )
        return list(result.scalars().all())

    async def revoke_all_active(self) -> int:
        result = await self._s.execute(
            select(SPSessionRow).where(SPSessionRow.revoked.is_(False))
        )
        rows = list(result.scalars().all())
        for row in rows:
            row.revoked = True
        return len(rows)

    async def revoke_by_idp_sid(self, idp_sid: str) -> int:
        """Kill every local session tied to an IdP session (back-channel logout)."""
        result = await self._s.execute(
            select(SPSessionRow).where(
                SPSessionRow.idp_sid == idp_sid, SPSessionRow.revoked.is_(False)
            )
        )
        rows = list(result.scalars().all())
        for row in rows:
            row.revoked = True
        return len(rows)


class PendingAuthRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def add(self, row: SPPendingAuthRow) -> None:
        self._s.add(row)

    async def take(self, state: str) -> SPPendingAuthRow | None:
        """Fetch and delete a pending-auth row (single use)."""
        row = await self._s.get(SPPendingAuthRow, state)
        if row is not None:
            await self._s.delete(row)
        return row

    async def purge_expired(self, now: datetime) -> None:
        await self._s.execute(delete(SPPendingAuthRow).where(SPPendingAuthRow.expires_at < now))

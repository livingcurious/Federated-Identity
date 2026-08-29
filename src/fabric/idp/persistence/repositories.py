"""Async repositories for the IdP. The service layer talks only to these — never to
the ORM session directly beyond obtaining it via dependency injection."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from fabric.idp.persistence.models import (
    AuditEventRow,
    AuthCodeRow,
    ClientRow,
    IdPSessionRow,
    MetaRow,
    SessionClientRow,
    SigningKeyRow,
    UsedAssertionRow,
    UserRow,
)


class AuditRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def recent(self, limit: int = 100) -> list[AuditEventRow]:
        result = await self._s.execute(
            select(AuditEventRow).order_by(AuditEventRow.id.desc()).limit(limit)
        )
        return list(result.scalars().all())


class MetaRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def get(self, key: str) -> str | None:
        row = await self._s.get(MetaRow, key)
        return row.value if row is not None else None

    async def set(self, key: str, value: str) -> None:
        row = await self._s.get(MetaRow, key)
        if row is None:
            self._s.add(MetaRow(key=key, value=value))
        else:
            row.value = value


class UserRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def get_by_email(self, email: str) -> UserRow | None:
        result = await self._s.execute(select(UserRow).where(UserRow.email == email))
        return result.scalar_one_or_none()

    async def get_by_sub(self, sub: str) -> UserRow | None:
        return await self._s.get(UserRow, sub)

    async def count(self) -> int:
        result = await self._s.execute(select(UserRow.sub))
        return len(result.scalars().all())

    async def add(self, user: UserRow) -> None:
        self._s.add(user)


class ClientRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def get(self, client_id: str) -> ClientRow | None:
        return await self._s.get(ClientRow, client_id)

    async def upsert(self, client: ClientRow) -> None:
        existing = await self._s.get(ClientRow, client.client_id)
        if existing is None:
            self._s.add(client)
            return
        existing.display_name = client.display_name
        existing.redirect_uri = client.redirect_uri
        existing.post_logout_redirect_uri = client.post_logout_redirect_uri
        existing.backchannel_logout_uri = client.backchannel_logout_uri
        existing.public_jwk = client.public_jwk


class SigningKeyRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def add(self, key: SigningKeyRow) -> None:
        self._s.add(key)

    async def get(self, kid: str) -> SigningKeyRow | None:
        return await self._s.get(SigningKeyRow, kid)

    async def active(self) -> SigningKeyRow | None:
        result = await self._s.execute(
            select(SigningKeyRow).where(SigningKeyRow.status == "active")
        )
        return result.scalars().first()

    async def publishable(self) -> list[SigningKeyRow]:
        """Keys whose public half belongs in JWKS: active + retiring."""
        result = await self._s.execute(
            select(SigningKeyRow)
            .where(SigningKeyRow.status.in_(("active", "retiring")))
            .order_by(SigningKeyRow.created_at)
        )
        return list(result.scalars().all())

    async def all(self) -> list[SigningKeyRow]:
        result = await self._s.execute(
            select(SigningKeyRow).order_by(SigningKeyRow.created_at)
        )
        return list(result.scalars().all())


class SessionRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def add(self, row: IdPSessionRow) -> None:
        self._s.add(row)

    async def get(self, sid: str) -> IdPSessionRow | None:
        return await self._s.get(IdPSessionRow, sid)

    async def all_active(self) -> list[IdPSessionRow]:
        result = await self._s.execute(
            select(IdPSessionRow).where(IdPSessionRow.revoked.is_(False))
        )
        return list(result.scalars().all())

    async def record_client(self, sid: str, client_id: str) -> None:
        exists = await self._s.execute(
            select(SessionClientRow).where(
                SessionClientRow.sid == sid, SessionClientRow.client_id == client_id
            )
        )
        if exists.scalar_one_or_none() is None:
            self._s.add(SessionClientRow(sid=sid, client_id=client_id))

    async def clients_for(self, sid: str) -> list[str]:
        result = await self._s.execute(
            select(SessionClientRow.client_id).where(SessionClientRow.sid == sid)
        )
        return list(result.scalars().all())


class AuthCodeRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def add(self, row: AuthCodeRow) -> None:
        self._s.add(row)

    async def get(self, code: str) -> AuthCodeRow | None:
        return await self._s.get(AuthCodeRow, code)


class AssertionRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._s = session

    async def seen(self, jti: str) -> bool:
        return (await self._s.get(UsedAssertionRow, jti)) is not None

    async def remember(self, jti: str, expires_at: datetime) -> None:
        self._s.add(UsedAssertionRow(jti=jti, expires_at=expires_at))

    async def purge_expired(self, now: datetime) -> None:
        await self._s.execute(
            delete(UsedAssertionRow).where(UsedAssertionRow.expires_at < now)
        )



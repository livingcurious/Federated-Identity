"""Signing keyring: JWKS publication, token signing, and rotation / revocation.

The keyring is the heart of two features:
  * **Signing-key rotation** — a fresh ``active`` key is minted while the previous one
    lingers as ``retiring`` (still in JWKS) so in-flight tokens keep verifying.
  * **Compromise containment** — ``revoke`` drops a key from JWKS instantly, so every
    token it signed fails verification at every SP at once.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from fabric.common import crypto
from fabric.common.clock import utc_now
from fabric.common.domain import SigningKeyView
from fabric.idp.persistence.models import SigningKeyRow
from fabric.idp.persistence.repositories import SigningKeyRepository
from fabric.idp.service.errors import InvalidRequestError, ServiceError


class KeyService:
    def __init__(self, session: AsyncSession) -> None:
        self._keys = SigningKeyRepository(session)

    async def ensure_active_key(self) -> str:
        """Guarantee an ``active`` signing key exists; return its ``kid``."""
        active = await self._keys.active()
        if active is not None:
            return active.kid
        return await self._mint_active()

    async def _mint_active(self) -> str:
        kid = crypto.new_kid()
        key = crypto.generate_signing_key(kid)
        await self._keys.add(
            SigningKeyRow(
                kid=kid,
                status="active",
                public_jwk=crypto.public_jwk(key),
                private_jwk=crypto.private_jwk(key),
                created_at=utc_now(),
            )
        )
        return kid

    async def jwks(self) -> dict[str, Any]:
        """Public JWKS: the ``active`` key plus any ``retiring`` keys (overlap window)."""
        rows = await self._keys.publishable()
        return {"keys": [row.public_jwk for row in rows]}

    async def sign(self, claims: dict[str, Any], *, typ: str = "JWT") -> str:
        """Sign ``claims`` with the current active key."""
        active = await self._keys.active()
        if active is None:
            raise ServiceError("no active signing key")
        key = crypto.load_key(active.private_jwk)
        return crypto.sign_jwt(claims, key, kid=active.kid, typ=typ)

    async def rotate(self) -> str:
        """Promote a brand-new key to ``active`` and demote the old one to ``retiring``."""
        previous = await self._keys.active()
        if previous is not None:
            previous.status = "retiring"
        return await self._mint_active()

    async def retire(self, kid: str) -> None:
        """Drop a ``retiring`` key from JWKS once its tokens have expired."""
        row = await self._keys.get(kid)
        if row is None:
            raise InvalidRequestError(f"unknown kid: {kid}")
        if row.status != "retiring":
            raise InvalidRequestError(f"kid {kid} is {row.status}, not retiring")
        row.status = "retired"

    async def revoke(self, kid: str) -> None:
        """Emergency: remove a key from JWKS immediately (compromise containment)."""
        row = await self._keys.get(kid)
        if row is None:
            raise InvalidRequestError(f"unknown kid: {kid}")
        if row.status == "active":
            raise InvalidRequestError(
                "cannot revoke the active key; rotate first, then revoke the retiring key"
            )
        row.status = "revoked"

    async def list_keys(self) -> list[SigningKeyView]:
        rows = await self._keys.all()
        return [SigningKeyView.model_validate(row) for row in rows]

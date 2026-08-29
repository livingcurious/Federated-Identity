"""Service Provider (client) registry + ``private_key_jwt`` authentication.

This is the SP→IdP half of mutual auth: the SP proves who it is by signing a short
client-assertion JWT with its own Ed25519 key. The IdP verifies it against the SP's
registered public key — there is no shared secret to steal. Assertion ``jti`` values are
single-use to stop replay.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from fabric.common import crypto
from fabric.common.audit import AuditLog, Event, Severity
from fabric.common.clock import utc_now
from fabric.common.config import Settings
from fabric.common.oauth import CLIENT_ASSERTION_TYPE
from fabric.idp.persistence.models import ClientRow
from fabric.idp.persistence.repositories import AssertionRepository, ClientRepository
from fabric.idp.service.errors import InvalidClientError, InvalidRequestError


class ClientService:
    def __init__(self, session: AsyncSession, settings: Settings) -> None:
        self._clients = ClientRepository(session)
        self._assertions = AssertionRepository(session)
        self._settings = settings

    async def get(self, client_id: str) -> ClientRow:
        client = await self._clients.get(client_id)
        if client is None:
            raise InvalidClientError(f"unknown client: {client_id}")
        return client

    async def get_optional(self, client_id: str) -> ClientRow | None:
        return await self._clients.get(client_id)

    async def authenticate(
        self,
        *,
        client_id: str,
        client_assertion_type: str,
        client_assertion: str,
        token_endpoint: str,
        audit: AuditLog | None = None,
    ) -> ClientRow:
        """Authenticate an SP at the token endpoint via ``private_key_jwt``."""
        if client_assertion_type != CLIENT_ASSERTION_TYPE:
            raise InvalidClientError("unsupported client_assertion_type")

        client = await self.get(client_id)
        if client.key_revoked:
            if audit is not None:
                await audit.record(
                    Event.CLIENT_AUTH_FAILED,
                    Severity.WARNING,
                    client_id=client_id,
                    outcome="denied",
                    detail={"reason": "client key has been revoked"},
                )
            raise InvalidClientError("client key has been revoked")
        key = crypto.load_key(client.public_jwk)

        try:
            claims = crypto.verify_jwt(
                client_assertion,
                key,
                issuer=client_id,
                audience=token_endpoint,
                require=("exp", "iat", "jti", "sub"),
            )
        except Exception as exc:  # joserfc raises a variety of error types
            if audit is not None:
                await audit.record(
                    Event.CLIENT_AUTH_FAILED,
                    Severity.WARNING,
                    client_id=client_id,
                    outcome="denied",
                    detail={"reason": "client assertion failed verification"},
                )
            raise InvalidClientError("client assertion failed verification") from exc

        if claims.get("sub") != client_id:
            raise InvalidClientError("client assertion 'sub' does not match client_id")

        issued_at = int(claims["iat"])
        expires_at = int(claims["exp"])
        max_ttl = self._settings.client_assertion_max_ttl_seconds
        if expires_at - issued_at > max_ttl:
            raise InvalidClientError(f"client assertion lifetime exceeds {max_ttl}s")

        jti = str(claims["jti"])
        if await self._assertions.seen(jti):
            if audit is not None:
                await audit.record(
                    Event.ASSERTION_REPLAY,
                    Severity.ALERT,
                    client_id=client_id,
                    outcome="denied",
                    detail={"jti": jti},
                )
            raise InvalidClientError("client assertion replay detected (jti already used)")
        # Remember the jti until the assertion would have expired, then it can be purged.
        assertion_expiry = datetime.fromtimestamp(expires_at, tz=UTC)
        await self._assertions.remember(jti, expires_at=assertion_expiry)
        await self._assertions.purge_expired(utc_now())

        return client

    # --------------------------- key containment levers -------------------------- #
    async def revoke_key(self, client_id: str) -> None:
        """Emergency: stop this SP's current key from authenticating, effective immediately.

        Use when an SP is suspected compromised (its private key may have leaked). This
        blocks `private_key_jwt` auth for ``client_id`` regardless of signature validity,
        without needing any access to that SP's own database.
        """
        client = await self.get(client_id)
        client.key_revoked = True

    async def register_key(self, client_id: str, public_jwk: dict[str, Any]) -> None:
        """Install a replacement public key for ``client_id`` and clear any revocation.

        The SP generates its own new keypair locally (see ``scripts/rotate_sp_key.py``) and
        only its *public* half is ever submitted here — the IdP never sees, and does not
        need, the private half.
        """
        if "d" in public_jwk:
            raise InvalidRequestError("refusing to store a private key component ('d')")
        try:
            crypto.load_key(public_jwk)
        except Exception as exc:
            raise InvalidRequestError(f"not a usable Ed25519 public key: {exc}") from exc

        client = await self.get(client_id)
        client.public_jwk = public_jwk
        client.key_revoked = False

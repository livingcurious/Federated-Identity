"""OIDC authorization-code + token orchestration.

Ties together clients, keys, sessions and users. This is where **cross-SP integrity**
is enforced: every token is stamped with ``aud``/``azp`` naming exactly one SP, and the
authorization code is bound to the client, the session, the redirect URI and PKCE.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from fabric.common import crypto
from fabric.common.audit import AuditLog, Event, Severity
from fabric.common.clock import is_expired, unix_now, utc_in, utc_now
from fabric.common.config import Settings
from fabric.common.domain import OIDCTokenResponse
from fabric.idp.persistence.models import AuthCodeRow, ClientRow
from fabric.idp.persistence.repositories import AuthCodeRepository
from fabric.idp.service.clients import ClientService
from fabric.idp.service.errors import InvalidGrantError, InvalidRequestError
from fabric.idp.service.keys import KeyService
from fabric.idp.service.sessions import SessionService
from fabric.idp.service.users import UserService


class OIDCFlowService:
    def __init__(self, session: AsyncSession, settings: Settings) -> None:
        self._settings = settings
        self._codes = AuthCodeRepository(session)
        self._clients = ClientService(session, settings)
        self._keys = KeyService(session)
        self._sessions = SessionService(session, settings)
        self._users = UserService(session)

    # ----------------------------- authorize ----------------------------- #
    async def issue_authorization_code(
        self,
        *,
        client: ClientRow,
        subject: str,
        sid: str,
        redirect_uri: str,
        code_challenge: str,
        nonce: str,
    ) -> str:
        if redirect_uri != client.redirect_uri:
            raise InvalidRequestError("redirect_uri does not match the registered value")
        code = crypto.new_opaque("ac_")
        await self._codes.add(
            AuthCodeRow(
                code=code,
                client_id=client.client_id,
                subject=subject,
                sid=sid,
                redirect_uri=redirect_uri,
                code_challenge=code_challenge,
                nonce=nonce,
                created_at=utc_now(),
                expires_at=utc_in(self._settings.auth_code_ttl_seconds),
            )
        )
        return code

    # ------------------------------- token -------------------------------- #
    async def exchange_code(
        self,
        *,
        client_id: str,
        code: str,
        code_verifier: str,
        redirect_uri: str,
        client_assertion_type: str,
        client_assertion: str,
        token_endpoint: str,
        audit: AuditLog | None = None,
    ) -> OIDCTokenResponse:
        client = await self._clients.authenticate(
            client_id=client_id,
            client_assertion_type=client_assertion_type,
            client_assertion=client_assertion,
            token_endpoint=token_endpoint,
            audit=audit,
        )

        row = await self._codes.get(code)
        if row is None:
            raise InvalidGrantError("unknown authorization code")
        if row.consumed:
            raise InvalidGrantError("authorization code already used")
        if is_expired(row.expires_at):
            raise InvalidGrantError("authorization code expired")
        if row.client_id != client.client_id:
            raise InvalidGrantError("authorization code was issued to a different client")
        if row.redirect_uri != redirect_uri:
            raise InvalidGrantError("redirect_uri mismatch")
        if not crypto.pkce_matches(code_verifier, row.code_challenge):
            raise InvalidGrantError("PKCE verification failed")

        row.consumed = True  # single use

        profile = await self._users.profile(row.subject)
        if profile is None:
            raise InvalidGrantError("subject no longer exists")

        id_claims = self._id_token_claims(
            subject=row.subject,
            client_id=client.client_id,
            sid=row.sid,
            nonce=row.nonce,
            email=profile.email,
            name=profile.name,
            roles=profile.roles,
        )
        access_claims = self._access_token_claims(
            subject=row.subject, client_id=client.client_id, sid=row.sid
        )

        id_token = await self._keys.sign(id_claims)
        access_token = await self._keys.sign(access_claims)

        # Remember which SPs this session reached, for back-channel logout later.
        await self._sessions.record_client(row.sid, client.client_id)

        if audit is not None:
            await audit.record(
                Event.TOKEN_ISSUED,
                Severity.INFO,
                subject=row.subject,
                client_id=client.client_id,
                outcome="issued",
                detail={"sid": row.sid, "scope": "openid profile"},
            )

        return OIDCTokenResponse(
            access_token=access_token,
            id_token=id_token,
            expires_in=self._settings.access_token_ttl_seconds,
        )

    # ----------------------------- claim builders ------------------------- #
    def _common_claims(self, *, subject: str, client_id: str, sid: str, ttl: int) -> dict[str, Any]:
        now = unix_now()
        return {
            "iss": self._settings.idp_issuer,
            "sub": subject,
            "aud": client_id,
            "azp": client_id,
            "sid": sid,
            "jti": crypto.new_jti(),
            "iat": now,
            "nbf": now,
            "exp": now + ttl,
        }

    def _id_token_claims(
        self,
        *,
        subject: str,
        client_id: str,
        sid: str,
        nonce: str,
        email: str,
        name: str,
        roles: list[str],
    ) -> dict[str, Any]:
        claims = self._common_claims(
            subject=subject,
            client_id=client_id,
            sid=sid,
            ttl=self._settings.id_token_ttl_seconds,
        )
        claims.update({"nonce": nonce, "email": email, "name": name, "roles": roles})
        return claims

    def _access_token_claims(self, *, subject: str, client_id: str, sid: str) -> dict[str, Any]:
        claims = self._common_claims(
            subject=subject,
            client_id=client_id,
            sid=sid,
            ttl=self._settings.access_token_ttl_seconds,
        )
        claims["scope"] = "openid profile"
        return claims

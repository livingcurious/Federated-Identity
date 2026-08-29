"""Login orchestration for one SP: build the authorize redirect, then exchange and
verify the code on callback.

This is the SP half of mutual auth (it signs a ``private_key_jwt`` assertion to prove
itself to the IdP) and the enforcement point for cross-SP integrity (it insists that
both returned tokens carry ``aud`` == its own ``client_id``).
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlencode

from sqlalchemy.ext.asyncio import AsyncSession
from starlette import status

from fabric.common import crypto
from fabric.common.clock import is_expired, unix_now, utc_in, utc_now
from fabric.common.config import Settings
from fabric.common.oauth import (
    CLIENT_ASSERTION_TYPE,
    CODE_CHALLENGE_METHOD_S256,
    DEFAULT_SCOPE,
    GRANT_AUTHORIZATION_CODE,
    RESPONSE_TYPE_CODE,
)
from fabric.sp.persistence.models import SPClientKeyRow, SPPendingAuthRow
from fabric.sp.persistence.repositories import ClientKeyRepository, PendingAuthRepository
from fabric.sp.service.errors import LoginError
from fabric.sp.service.idp_client import IdPClient


class LoginService:
    def __init__(self, session: AsyncSession, settings: Settings, idp: IdPClient) -> None:
        if settings.sp_id is None:
            raise LoginError("this process is not configured as an SP (FABRIC_SP_ID unset)")
        self._settings = settings
        self._idp = idp
        self._client_id = settings.sp_id
        self._pending = PendingAuthRepository(session)
        self._keys = ClientKeyRepository(session)

    @property
    def _redirect_uri(self) -> str:
        return self._settings.sp_client(self._client_id).redirect_uri

    async def begin(self) -> str:
        """Create login-transaction state and return the IdP authorize URL to redirect to."""
        state = crypto.new_opaque("st_")
        nonce = crypto.new_opaque("no_")
        verifier = crypto.new_code_verifier()
        await self._pending.add(
            SPPendingAuthRow(
                state=state,
                nonce=nonce,
                code_verifier=verifier,
                created_at=utc_now(),
                expires_at=utc_in(self._settings.auth_code_ttl_seconds + 60),
            )
        )
        await self._pending.purge_expired(utc_now())

        authorization_endpoint = await self._idp.authorization_endpoint()
        params = {
            "response_type": RESPONSE_TYPE_CODE,
            "client_id": self._client_id,
            "redirect_uri": self._redirect_uri,
            "scope": DEFAULT_SCOPE,
            "state": state,
            "nonce": nonce,
            "code_challenge": crypto.code_challenge_s256(verifier),
            "code_challenge_method": CODE_CHALLENGE_METHOD_S256,
        }
        return f"{authorization_endpoint}?{urlencode(params)}"

    async def complete(self, *, state: str, code: str) -> dict[str, Any]:
        """Exchange ``code`` and return the verified id_token claims."""
        pending = await self._pending.take(state)
        if pending is None:
            raise LoginError("unknown login state (possible CSRF or expired transaction)")
        if is_expired(pending.expires_at):
            raise LoginError("login transaction expired")

        key_row = await self._keys.get(self._client_id)
        if key_row is None:
            raise LoginError("SP client key not provisioned (run the seed step)")

        token_endpoint = await self._idp.token_endpoint()
        assertion = self._build_client_assertion(key_row, token_endpoint)
        form = {
            "grant_type": GRANT_AUTHORIZATION_CODE,
            "code": code,
            "redirect_uri": self._redirect_uri,
            "client_id": self._client_id,
            "code_verifier": pending.code_verifier,
            "client_assertion_type": CLIENT_ASSERTION_TYPE,
            "client_assertion": assertion,
        }

        status_code, body = await self._idp.exchange_token(form)
        if status_code != status.HTTP_200_OK:
            detail = body.get("error_description") or body.get("error") or "token request failed"
            raise LoginError(f"token endpoint rejected the exchange: {detail}")

        id_token = body.get("id_token")
        access_token = body.get("access_token")
        if not id_token or not access_token:
            raise LoginError("token response missing id_token/access_token")

        claims = await self._verify(id_token, expect_nonce=pending.nonce)
        # Cross-SP integrity: the access token must also be addressed to *this* SP.
        await self._verify(access_token, expect_nonce=None)
        return claims

    async def _verify(self, token: str, *, expect_nonce: str | None) -> dict[str, Any]:
        keyset = await self._idp.keyset_for(crypto.read_kid(token))
        try:
            claims = crypto.verify_jwt(
                token,
                keyset,
                issuer=self._settings.idp_issuer,
                audience=self._client_id,
            )
        except Exception as exc:
            raise LoginError("token failed verification (signature/issuer/audience)") from exc
        if expect_nonce is not None and claims.get("nonce") != expect_nonce:
            raise LoginError("nonce mismatch (possible token injection)")
        return claims

    def _build_client_assertion(self, key_row: SPClientKeyRow, token_endpoint: str) -> str:
        now = unix_now()
        claims = {
            "iss": self._client_id,
            "sub": self._client_id,
            "aud": token_endpoint,
            "jti": crypto.new_jti(),
            "iat": now,
            "exp": now + self._settings.client_assertion_max_ttl_seconds,
        }
        key = crypto.load_key(key_row.private_jwk)
        return crypto.sign_jwt(claims, key, kid=key_row.kid)

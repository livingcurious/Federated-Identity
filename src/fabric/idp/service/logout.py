"""Back-channel logout: when an IdP session ends (logout or revocation), notify every
SP that session reached with a signed ``logout_token`` so the stolen/ended session dies
everywhere. This is both the logout half of session lifecycle and a containment lever."""

from __future__ import annotations

from typing import Any

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from fabric.common import crypto
from fabric.common.clock import unix_now
from fabric.common.config import Settings
from fabric.common.oauth import BACKCHANNEL_LOGOUT_EVENT
from fabric.idp.persistence.repositories import ClientRepository
from fabric.idp.service.keys import KeyService
from fabric.idp.service.sessions import SessionService


class LogoutService:
    def __init__(self, session: AsyncSession, settings: Settings) -> None:
        self._settings = settings
        self._keys = KeyService(session)
        self._clients = ClientRepository(session)
        self._sessions = SessionService(session, settings)

    def _logout_token_claims(self, *, client_id: str, subject: str, sid: str) -> dict[str, Any]:
        now = unix_now()
        return {
            "iss": self._settings.idp_issuer,
            "aud": client_id,
            "sub": subject,
            "sid": sid,
            "iat": now,
            "exp": now + 120,
            "jti": crypto.new_jti(),
            "events": {BACKCHANNEL_LOGOUT_EVENT: {}},
        }

    async def build_logout_tokens(self, *, sid: str, subject: str) -> dict[str, str]:
        """Sign a logout token per SP the session reached. Returns ``{uri: token}``."""
        targets = await self._sessions.clients_for(sid)
        tokens: dict[str, str] = {}
        for client_id in targets:
            client = await self._clients.get(client_id)
            if client is None:
                continue
            claims = self._logout_token_claims(client_id=client_id, subject=subject, sid=sid)
            tokens[client.backchannel_logout_uri] = await self._keys.sign(
                claims, typ="logout+jwt"
            )
        return tokens


async def deliver_logout_tokens(tokens: dict[str, str], *, timeout_seconds: float = 3.0) -> None:
    """POST each signed logout token to its SP endpoint (best-effort, fire-and-forget)."""
    if not tokens:
        return
    async with httpx.AsyncClient(timeout=timeout_seconds) as client:
        for uri, token in tokens.items():
            try:
                await client.post(uri, data={"logout_token": token})
            except httpx.HTTPError:
                # An SP being down must not block IdP logout; SP sessions still expire.
                continue

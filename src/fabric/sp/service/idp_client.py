"""Client-side view of the IdP: discovery, a self-refreshing JWKS cache, and token
exchange. One instance is shared per SP process (held on ``app.state``).

The JWKS cache is what makes **signing-key rotation** transparent to the SP: when a
token arrives signed by an unknown ``kid``, the cache re-fetches JWKS once and retries,
so a rotated IdP key is picked up without an SP restart.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
from joserfc.jwk import KeySet

from fabric.common import crypto
from fabric.common.audit import Event, Severity, build_record, emit
from fabric.common.domain import DiscoveryDocument

DISCOVERY_PATH = "/.well-known/openid-configuration"


class IdPClient:
    def __init__(self, issuer: str, *, timeout_seconds: float = 5.0) -> None:
        self._issuer = issuer
        self._timeout = timeout_seconds
        self._discovery: DiscoveryDocument | None = None
        self._keyset: KeySet | None = None
        self._kids: set[str] = set()
        self._lock = asyncio.Lock()

    async def discovery(self) -> DiscoveryDocument:
        if self._discovery is None:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.get(f"{self._issuer}{DISCOVERY_PATH}")
                response.raise_for_status()
                self._discovery = DiscoveryDocument.model_validate(response.json())
        return self._discovery

    async def _refresh_jwks(self) -> None:
        discovery = await self.discovery()
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            response = await client.get(discovery.jwks_uri)
            response.raise_for_status()
            jwks: dict[str, Any] = response.json()
        self._keyset = crypto.keyset_from_jwks(jwks)
        self._kids = {key["kid"] for key in jwks.get("keys", []) if "kid" in key}
        # Log-only (this client is a process singleton, not request-scoped): a JWKS refetch
        # usually means the IdP rotated its signing key.
        emit(
            build_record(
                Event.SP_JWKS_REFRESHED, Severity.INFO, detail={"kids": sorted(self._kids)}
            ),
            Severity.INFO,
        )

    async def keyset_for(self, kid: str | None) -> KeySet:
        """Return a keyset that contains ``kid``, refreshing JWKS if it is unknown."""
        async with self._lock:
            if self._keyset is None or (kid is not None and kid not in self._kids):
                await self._refresh_jwks()
            assert self._keyset is not None
            return self._keyset

    async def exchange_token(self, form: dict[str, str]) -> tuple[int, dict[str, Any]]:
        """POST the token request; return ``(status_code, json_body)``."""
        discovery = await self.discovery()
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            response = await client.post(discovery.token_endpoint, data=form)
        try:
            body = response.json()
        except ValueError:
            body = {"error": "invalid_response", "error_description": response.text}
        return response.status_code, body

    async def token_endpoint(self) -> str:
        return (await self.discovery()).token_endpoint

    async def authorization_endpoint(self) -> str:
        return (await self.discovery()).authorization_endpoint

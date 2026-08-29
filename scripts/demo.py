#!/usr/bin/env python3
"""Scripted end-to-end proof. Start the fabric first (``python run.py``), then run:

    python scripts/demo.py

It exercises two headline properties against the live services:
  1. **SSO** — one credential entry at the IdP authenticates both SP-A and SP-B.
  2. **Cross-SP integrity** — a token minted for SP-A is *rejected* when its audience is
     checked as SP-B.
"""

from __future__ import annotations

import asyncio
import re
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import httpx
from starlette import status

from fabric.common import crypto
from fabric.common.clock import unix_now
from fabric.common.config import Settings, get_settings
from fabric.common.database import make_engine, make_sessionmaker
from fabric.common.oauth import (
    CLIENT_ASSERTION_TYPE,
    CODE_CHALLENGE_METHOD_S256,
    DEFAULT_SCOPE,
    GRANT_AUTHORIZATION_CODE,
    RESPONSE_TYPE_CODE,
)
from fabric.sp.persistence.repositories import ClientKeyRepository

_HIDDEN = re.compile(r'<input type="hidden" name="([^"]+)" value="([^"]*)" />')
_USER = {"email": "ada@example.com", "password": "correct horse battery"}
_OK = "\033[92m✓\033[0m"
_NO = "\033[91m✗\033[0m"


def _ok(msg: str) -> None:
    print(f"  {_OK} {msg}")


def _fail(msg: str) -> None:
    print(f"  {_NO} {msg}")
    raise SystemExit(1)


async def demo_sso(settings: Settings) -> None:
    print("\n[1] Single sign-on across two applications")
    sp_a = settings.sp_client("sp-a").base_url
    sp_b = settings.sp_client("sp-b").base_url
    async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as browser:
        form = await browser.get(f"{sp_a}/login")
        if 'name="password"' not in form.text:
            _fail("expected the IdP login form when starting at SP-A")
        hidden = dict(_HIDDEN.findall(form.text))

        signed_in = await browser.post(
            f"{settings.idp_issuer}/login", data={**_USER, **hidden}
        )
        if signed_in.status_code != status.HTTP_200_OK or "Ada Lovelace" not in signed_in.text:
            _fail(f"SP-A sign-in failed (status {signed_in.status_code})")
        _ok("SP-A: entered credentials once, landed on the profile as Ada Lovelace")

        sso = await browser.get(f"{sp_b}/login")
        if sso.status_code != status.HTTP_200_OK:
            _fail(f"SP-B returned status {sso.status_code}")
        if 'name="password"' in sso.text:
            _fail("SP-B presented a login form — SSO did not take effect")
        if _USER["email"] not in sso.text:
            _fail("SP-B profile did not show the signed-in user")
        _ok("SP-B: single sign-on — no second login, same identity")


async def _load_sp_private_key(settings: Settings, client_id: str) -> tuple[str, dict[str, object]]:
    engine = make_engine(settings.sp_db_path(client_id))
    try:
        async with make_sessionmaker(engine)() as session:
            row = await ClientKeyRepository(session).get(client_id)
            if row is None:
                _fail(f"{client_id} has no client key — run the seed step")
            assert row is not None
            return row.kid, dict(row.private_jwk)
    finally:
        await engine.dispose()


async def _mint_token_for_sp_a(settings: Settings) -> str:
    """Act as SP-A (using its real key) to obtain a genuine id_token with aud=sp-a."""
    cfg = settings.sp_client("sp-a")
    kid, private_jwk = await _load_sp_private_key(settings, "sp-a")
    verifier = crypto.new_code_verifier()
    params = {
        "response_type": RESPONSE_TYPE_CODE,
        "client_id": "sp-a",
        "redirect_uri": cfg.redirect_uri,
        "scope": DEFAULT_SCOPE,
        "state": crypto.new_opaque("st_"),
        "nonce": crypto.new_opaque("no_"),
        "code_challenge": crypto.code_challenge_s256(verifier),
        "code_challenge_method": CODE_CHALLENGE_METHOD_S256,
    }
    async with httpx.AsyncClient(follow_redirects=False, timeout=10.0) as client:
        form = await client.get(f"{settings.idp_issuer}/authorize", params=params)
        hidden = dict(_HIDDEN.findall(form.text))
        redirected = await client.post(f"{settings.idp_issuer}/login", data={**_USER, **hidden})
        location = redirected.headers.get("location", "")
        code_values = parse_qs(urlparse(location).query).get("code", [])
        if not code_values:
            _fail("did not receive an authorization code")
        code = code_values[0]

        token_endpoint = f"{settings.idp_internal_base_url}/token"
        now = unix_now()
        assertion = crypto.sign_jwt(
            {
                "iss": "sp-a",
                "sub": "sp-a",
                "aud": token_endpoint,
                "jti": crypto.new_jti(),
                "iat": now,
                "exp": now + 60,
            },
            crypto.load_key(private_jwk),
            kid=kid,
        )
        token_response = await client.post(
            token_endpoint,
            data={
                "grant_type": GRANT_AUTHORIZATION_CODE,
                "code": code,
                "redirect_uri": cfg.redirect_uri,
                "client_id": "sp-a",
                "code_verifier": verifier,
                "client_assertion_type": CLIENT_ASSERTION_TYPE,
                "client_assertion": assertion,
            },
        )
        if token_response.status_code != status.HTTP_200_OK:
            _fail(f"token exchange failed: {token_response.text}")
        return str(token_response.json()["id_token"])


async def demo_cross_sp_integrity(settings: Settings) -> None:
    print("\n[2] Cross-SP integrity (audience pinning)")
    id_token = await _mint_token_for_sp_a(settings)
    async with httpx.AsyncClient(timeout=10.0) as client:
        jwks = (await client.get(f"{settings.idp_issuer}/.well-known/jwks.json")).json()
    keyset = crypto.keyset_from_jwks(jwks)

    crypto.verify_jwt(id_token, keyset, issuer=settings.idp_issuer, audience="sp-a")
    _ok("token issued for SP-A verifies when the audience is checked as sp-a")

    try:
        crypto.verify_jwt(id_token, keyset, issuer=settings.idp_issuer, audience="sp-b")
    except Exception:  # noqa: BLE001 - proving the token is rejected, cause is immaterial
        _ok("same token is REJECTED when SP-B checks the audience — replay across SPs blocked")
    else:
        _fail("token was accepted as SP-B — cross-SP integrity is broken")


async def main() -> None:
    settings = get_settings()
    print(f"Identity Fabric demo — issuer {settings.idp_issuer}")
    try:
        await demo_sso(settings)
        await demo_cross_sp_integrity(settings)
    except httpx.ConnectError:
        _fail("could not reach the services — is `python run.py` running?")
    print("\nAll checks passed.\n")


if __name__ == "__main__":
    asyncio.run(main())

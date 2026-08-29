"""Crypto primitives: Ed25519 keys, JWT signing/verification, JWKS, PKCE, random ids.

We deliberately use **joserfc** (maintained by the Authlib author) rather than the
stale, CVE-prone ``python-jose``. Signing is **EdDSA / Ed25519** only — the verifier
always pins ``algorithms=["EdDSA"]`` so a token cannot smuggle in a weaker or ``none``
algorithm.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from typing import Any

from joserfc import jwt
from joserfc.jwk import KeySet, OKPKey

# RFC 9864 fully-specified algorithm name for Ed25519 signatures (preferred over the
# older, now-deprecated "EdDSA" label). The whole fabric is self-contained, so we use it
# on both sides and pin the verifier to it — no algorithm negotiation, no downgrade.
ALG = "Ed25519"
CRV = "Ed25519"
_ALLOWED_ALGS = [ALG]


# --------------------------------------------------------------------------- #
# Random identifiers
# --------------------------------------------------------------------------- #
def new_kid() -> str:
    """A fresh key id."""
    return f"k_{secrets.token_hex(8)}"


def new_jti() -> str:
    """A fresh, unique token id."""
    return f"j_{secrets.token_urlsafe(18)}"


def new_opaque(prefix: str = "") -> str:
    """A cryptographically random opaque token (session id, auth code, admin token…)."""
    return f"{prefix}{secrets.token_urlsafe(32)}"


# --------------------------------------------------------------------------- #
# Ed25519 keys / JWK(S)
# --------------------------------------------------------------------------- #
def generate_signing_key(kid: str) -> OKPKey:
    """Generate a new Ed25519 signing key carrying ``kid``, ``use=sig``, ``alg=EdDSA``."""
    return OKPKey.generate_key(
        CRV,
        parameters={"kid": kid, "use": "sig", "alg": ALG},
        private=True,
    )


def load_key(jwk: dict[str, Any]) -> OKPKey:
    """Load an OKP key from a JWK dict (public or private)."""
    return OKPKey.import_key(jwk)


def public_jwk(key: OKPKey) -> dict[str, Any]:
    """The public half of ``key`` as a JWK dict."""
    return key.as_dict(private=False)


def private_jwk(key: OKPKey) -> dict[str, Any]:
    """The full (private) JWK dict for ``key`` — only ever persisted, never published."""
    return key.as_dict(private=True)


def build_jwks(keys: list[OKPKey]) -> dict[str, Any]:
    """A public JWKS document (``{"keys": [...]}``) for the given keys."""
    return KeySet(keys).as_dict(private=False)


def keyset_from_jwks(jwks: dict[str, Any]) -> KeySet:
    """Load a verification :class:`KeySet` from a JWKS document."""
    return KeySet.import_key_set(jwks)


# --------------------------------------------------------------------------- #
# JWT sign / verify
# --------------------------------------------------------------------------- #
def sign_jwt(claims: dict[str, Any], key: OKPKey, *, kid: str, typ: str = "JWT") -> str:
    """Sign ``claims`` with ``key`` using EdDSA, stamping ``kid`` into the header."""
    header = {"alg": ALG, "kid": kid, "typ": typ}
    return jwt.encode(header, claims, key, algorithms=_ALLOWED_ALGS)


def verify_jwt(
    token: str,
    verifier: OKPKey | KeySet,
    *,
    issuer: str | None = None,
    audience: str | None = None,
    require: tuple[str, ...] = ("exp", "iat"),
    leeway: int = 10,
) -> dict[str, Any]:
    """Verify signature (EdDSA only) and standard claims; return the claims dict.

    Raises a ``joserfc`` error on any failure (bad signature, wrong ``iss``/``aud``,
    expired, unknown ``kid``). The ``leeway`` tolerates small clock skew.
    """
    decoded = jwt.decode(token, verifier, algorithms=_ALLOWED_ALGS)

    options: dict[str, dict[str, Any]] = {name: {"essential": True} for name in require}
    if issuer is not None:
        options["iss"] = {"essential": True, "value": issuer}
    if audience is not None:
        options["aud"] = {"essential": True, "value": audience}

    registry = jwt.JWTClaimsRegistry(leeway=leeway, **options)
    registry.validate(decoded.claims)
    return dict(decoded.claims)


def read_kid(token: str) -> str | None:
    """Peek at the ``kid`` in a token header without verifying (for JWKS cache misses)."""
    try:
        header_segment = token.split(".", 1)[0]
        padded = header_segment + "=" * (-len(header_segment) % 4)
        header = json.loads(base64.urlsafe_b64decode(padded))
        kid = header.get("kid")
        return kid if isinstance(kid, str) else None
    except Exception:  # noqa: BLE001 - best-effort peek; any malformed header ⇒ no kid
        return None


# --------------------------------------------------------------------------- #
# PKCE (RFC 7636, S256)
# --------------------------------------------------------------------------- #
def new_code_verifier() -> str:
    return secrets.token_urlsafe(64)


def code_challenge_s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def pkce_matches(verifier: str, challenge: str) -> bool:
    """Constant-time comparison of a PKCE verifier against its stored S256 challenge."""
    return secrets.compare_digest(code_challenge_s256(verifier), challenge)

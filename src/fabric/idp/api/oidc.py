"""OIDC discovery and JWKS — the public, browser/network-facing half of the IdP.

The token endpoint lives in :mod:`fabric.idp.api.token` and is mounted on the *internal*
app instead (see ``idp/main.py``) — it is a server-to-server endpoint, never a browser
one, so it has no reason to sit on a publicly published port.
"""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from fabric.common.crypto import ALG
from fabric.common.domain import DiscoveryDocument
from fabric.common.oauth import GRANT_AUTHORIZATION_CODE
from fabric.idp.api.endpoints import AUTHORIZE_PATH, JWKS_PATH, LOGOUT_PATH, TOKEN_PATH
from fabric.idp.deps import SessionDep, SettingsDep
from fabric.idp.service.keys import KeyService

router = APIRouter(tags=["oidc"])


@router.get("/.well-known/openid-configuration", response_model=DiscoveryDocument)
async def discovery(settings: SettingsDep) -> DiscoveryDocument:
    issuer = settings.idp_issuer
    return DiscoveryDocument(
        issuer=issuer,
        authorization_endpoint=f"{issuer}{AUTHORIZE_PATH}",
        # Deliberately on the internal base URL, not the public issuer: the token
        # endpoint is a server-to-server call (SP -> IdP) and is kept off any publicly
        # published port. The `iss` claim in issued tokens is still `issuer` above.
        token_endpoint=f"{settings.idp_internal_base_url}{TOKEN_PATH}",
        jwks_uri=f"{issuer}{JWKS_PATH}",
        end_session_endpoint=f"{issuer}{LOGOUT_PATH}",
        id_token_signing_alg_values_supported=[ALG],
        token_endpoint_auth_methods_supported=["private_key_jwt"],
        response_types_supported=["code"],
        grant_types_supported=[GRANT_AUTHORIZATION_CODE],
        code_challenge_methods_supported=["S256"],
    )


@router.get(JWKS_PATH)
async def jwks(session: SessionDep) -> JSONResponse:
    document = await KeyService(session).jwks()
    return JSONResponse(content=document)

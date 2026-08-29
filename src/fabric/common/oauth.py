"""Shared OAuth/OIDC protocol constant strings (defined once, imported by both sides)."""

from __future__ import annotations

GRANT_AUTHORIZATION_CODE = "authorization_code"
CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
RESPONSE_TYPE_CODE = "code"
CODE_CHALLENGE_METHOD_S256 = "S256"
DEFAULT_SCOPE = "openid profile"

# OIDC back-channel logout event identifier.
BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"

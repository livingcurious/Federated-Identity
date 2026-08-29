"""Canonical IdP endpoint paths, defined once so routes and discovery cannot drift."""

from __future__ import annotations

AUTHORIZE_PATH = "/authorize"
LOGIN_PATH = "/login"
TOKEN_PATH = "/token"
LOGOUT_PATH = "/logout"
JWKS_PATH = "/.well-known/jwks.json"

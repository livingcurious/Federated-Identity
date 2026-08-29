"""Cross-cutting, transport-neutral DTOs (Pydantic v2) shared by IdP and SP layers."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class PublicUser(BaseModel):
    """The subset of a user identity that is safe to place in an id_token / show an SP."""

    sub: str
    email: str
    name: str
    roles: list[str] = Field(default_factory=list)


class OIDCTokenResponse(BaseModel):
    """RFC 6749 token endpoint response."""

    access_token: str
    id_token: str
    token_type: str = "Bearer"
    expires_in: int


class DiscoveryDocument(BaseModel):
    """A trimmed OIDC discovery document (``/.well-known/openid-configuration``)."""

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    end_session_endpoint: str
    id_token_signing_alg_values_supported: list[str]
    token_endpoint_auth_methods_supported: list[str]
    response_types_supported: list[str]
    grant_types_supported: list[str]
    code_challenge_methods_supported: list[str]


class SessionInfo(BaseModel):
    """A view of a live session (IdP or SP) for admin/introspection surfaces."""

    model_config = ConfigDict(from_attributes=True)

    sid: str
    subject: str
    created_at: datetime
    last_seen_at: datetime
    idle_expiry: datetime
    absolute_expiry: datetime


class SigningKeyView(BaseModel):
    """A view of one keyring entry (public metadata only)."""

    model_config = ConfigDict(from_attributes=True)

    kid: str
    status: str
    created_at: datetime


class AuditEventView(BaseModel):
    """A view of one audit-trail entry."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    ts: datetime
    event: str
    severity: str
    actor: str | None = None
    subject: str | None = None
    client_id: str | None = None
    source_ip: str | None = None
    request_id: str | None = None
    outcome: str | None = None
    detail: dict[str, object] = Field(default_factory=dict)

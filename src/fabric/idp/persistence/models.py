"""IdP ORM models (SQLAlchemy 2.0 typed mappings). All of this lives in ``idp.db``."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from fabric.common.audit import AuditColumns


class IdPBase(DeclarativeBase):
    """Declarative base for IdP tables (isolated from SP metadata)."""


class AuditEventRow(IdPBase, AuditColumns):
    """Append-only security audit trail for the IdP."""

    __tablename__ = "audit_events"


class MetaRow(IdPBase):
    """Small key/value store for bootstrap material (e.g. the admin-token hash)."""

    __tablename__ = "meta"

    key: Mapped[str] = mapped_column(String, primary_key=True)
    value: Mapped[str] = mapped_column(String)


class UserRow(IdPBase):
    """A seeded end user. Not a production directory — demo identities only."""

    __tablename__ = "users"

    sub: Mapped[str] = mapped_column(String, primary_key=True)
    email: Mapped[str] = mapped_column(String, unique=True, index=True)
    name: Mapped[str] = mapped_column(String)
    password_hash: Mapped[str] = mapped_column(String)
    roles: Mapped[list[str]] = mapped_column(JSON, default=list)


class SigningKeyRow(IdPBase):
    """One entry in the signing keyring. ``private_jwk`` never leaves the IdP."""

    __tablename__ = "signing_keys"

    kid: Mapped[str] = mapped_column(String, primary_key=True)
    status: Mapped[str] = mapped_column(String, index=True)  # active|retiring|retired|revoked
    public_jwk: Mapped[dict[str, Any]] = mapped_column(JSON)
    private_jwk: Mapped[dict[str, Any]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ClientRow(IdPBase):
    """A registered Service Provider and its public key (for private_key_jwt auth)."""

    __tablename__ = "clients"

    client_id: Mapped[str] = mapped_column(String, primary_key=True)
    display_name: Mapped[str] = mapped_column(String)
    redirect_uri: Mapped[str] = mapped_column(String)
    post_logout_redirect_uri: Mapped[str] = mapped_column(String)
    backchannel_logout_uri: Mapped[str] = mapped_column(String)
    public_jwk: Mapped[dict[str, Any]] = mapped_column(JSON)
    # Emergency containment lever: set True to instantly stop a leaked SP private key from
    # authenticating (private_key_jwt), independent of whether the signature would verify.
    key_revoked: Mapped[bool] = mapped_column(Boolean, default=False)


class IdPSessionRow(IdPBase):
    """The primary SSO session. Persisted so it survives a restart."""

    __tablename__ = "idp_sessions"

    sid: Mapped[str] = mapped_column(String, primary_key=True)
    subject: Mapped[str] = mapped_column(String, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    idle_expiry: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    absolute_expiry: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)


class SessionClientRow(IdPBase):
    """Records that ``sid`` obtained a token for ``client_id`` — drives back-channel logout."""

    __tablename__ = "session_clients"
    __table_args__ = (UniqueConstraint("sid", "client_id", name="uq_session_client"),)

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    sid: Mapped[str] = mapped_column(ForeignKey("idp_sessions.sid", ondelete="CASCADE"), index=True)
    client_id: Mapped[str] = mapped_column(String, index=True)


class AuthCodeRow(IdPBase):
    """A single-use authorization code bound to client + session + PKCE + nonce."""

    __tablename__ = "auth_codes"

    code: Mapped[str] = mapped_column(String, primary_key=True)
    client_id: Mapped[str] = mapped_column(String, index=True)
    subject: Mapped[str] = mapped_column(String)
    sid: Mapped[str] = mapped_column(String, index=True)
    redirect_uri: Mapped[str] = mapped_column(String)
    code_challenge: Mapped[str] = mapped_column(String)
    nonce: Mapped[str] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    consumed: Mapped[bool] = mapped_column(Boolean, default=False)


class UsedAssertionRow(IdPBase):
    """Spent client-assertion ``jti`` values (replay defense for private_key_jwt)."""

    __tablename__ = "used_assertions"

    jti: Mapped[str] = mapped_column(String, primary_key=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

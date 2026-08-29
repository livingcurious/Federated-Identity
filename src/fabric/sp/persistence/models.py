"""SP ORM models. Each SP has its own database (e.g. ``sp_a.db``)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from fabric.common.audit import AuditColumns


class SPBase(DeclarativeBase):
    """Declarative base for SP tables (isolated from IdP metadata)."""


class AuditEventRow(SPBase, AuditColumns):
    """Append-only security audit trail for this SP."""

    __tablename__ = "audit_events"


class SPClientKeyRow(SPBase):
    """The SP's own signing key, used to authenticate to the IdP (private_key_jwt).

    The private half lives only here, in the SP's DB; the IdP holds the public half.
    """

    __tablename__ = "client_key"

    client_id: Mapped[str] = mapped_column(String, primary_key=True)
    kid: Mapped[str] = mapped_column(String)
    public_jwk: Mapped[dict[str, Any]] = mapped_column(JSON)
    private_jwk: Mapped[dict[str, Any]] = mapped_column(JSON)


class SPSessionRow(SPBase):
    """The SP's own local session for a signed-in user. Persisted across restarts."""

    __tablename__ = "sp_sessions"

    sid: Mapped[str] = mapped_column(String, primary_key=True)
    subject: Mapped[str] = mapped_column(String, index=True)
    idp_sid: Mapped[str] = mapped_column(String, index=True)  # links to the IdP session
    email: Mapped[str] = mapped_column(String)
    name: Mapped[str] = mapped_column(String)
    roles: Mapped[list[str]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    idle_expiry: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    absolute_expiry: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)


class SPPendingAuthRow(SPBase):
    """Short-lived login transaction state (PKCE verifier, nonce) keyed by ``state``."""

    __tablename__ = "pending_auth"

    state: Mapped[str] = mapped_column(String, primary_key=True)
    nonce: Mapped[str] = mapped_column(String)
    code_verifier: Mapped[str] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class SPUserRoleRow(SPBase):
    """This SP's own role assignment for a subject — entirely independent of every
    other SP and of the IdP. The IdP only ever asserts *identity*; each SP decides its
    own permissions locally, managed here (seeded, and editable via the HR panel)."""

    __tablename__ = "user_roles"

    subject: Mapped[str] = mapped_column(String, primary_key=True)
    roles: Mapped[list[str]] = mapped_column(JSON, default=list)


class BudgetRow(SPBase):
    """A single fake budget-approval record per quarter, for the Finance panel demo."""

    __tablename__ = "budget"

    quarter: Mapped[str] = mapped_column(String, primary_key=True)
    approved: Mapped[bool] = mapped_column(Boolean, default=False)
    approved_by: Mapped[str | None] = mapped_column(String, nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

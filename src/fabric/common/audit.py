"""Security audit + structured logging + alert hooks.

Three things, one place:
  * **Structured JSON logs** on a dedicated ``fabric.audit`` logger (independent of the
    uvicorn config), so every security-relevant event is machine-readable on stderr.
  * A **persistent audit trail** — each event is also written to an ``audit_events`` row
    in the *current service's* database (the row class is injected, so the IdP and each SP
    keep their own trail).
  * **Alerts** — events at ``ALERT`` severity are tagged ``"alert": true`` and pushed to
    any registered sink (log-based alerting by default; a webhook can be registered).

Logging/alerting fire immediately and do not depend on the request's DB transaction, so a
rolled-back request still leaves a log + alert. The DB row follows the transaction.
"""

from __future__ import annotations

import json
import logging
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from sqlalchemy import JSON, DateTime, Integer, String
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column


class Severity(str, Enum):
    INFO = "info"      # routine, high-volume (token issued, jwks refreshed)
    NOTICE = "notice"  # noteworthy but expected (login ok, key rotated)
    WARNING = "warning"  # something was denied (bad login, token rejected)
    ALERT = "alert"    # high-signal, likely-hostile or containment action


class Event:
    """Canonical event names (dotted, stable — logs/alerts key off these)."""

    # IdP
    LOGIN_SUCCEEDED = "auth.login.succeeded"
    LOGIN_FAILED = "auth.login.failed"
    TOKEN_ISSUED = "token.issued"
    TOKEN_DENIED = "token.exchange.denied"
    CLIENT_AUTH_FAILED = "client.auth.failed"
    ASSERTION_REPLAY = "assertion.replay.detected"
    KEY_ROTATED = "key.rotated"
    KEY_RETIRED = "key.retired"
    KEY_REVOKED = "key.revoked"
    SESSION_REVOKED = "session.revoked"
    CLIENT_KEY_REVOKED = "client.key.revoked"
    CLIENT_KEY_REGISTERED = "client.key.registered"
    BACKCHANNEL_SENT = "logout.backchannel.sent"
    # SP
    SP_LOGIN_SUCCEEDED = "sp.login.succeeded"
    SP_LOGIN_FAILED = "sp.login.failed"
    SP_JWKS_REFRESHED = "sp.jwks.refreshed"
    SP_BACKCHANNEL_RECEIVED = "sp.backchannel.received"
    SP_BACKCHANNEL_REJECTED = "sp.backchannel.rejected"
    SP_ADMIN_ACCESS_DENIED = "sp.admin.access_denied"
    SP_ADMIN_SESSIONS_REVOKED = "sp.admin.sessions_revoked"


# --------------------------------------------------------------------------- #
# Persistence mixin — combined with each service's DeclarativeBase.
# --------------------------------------------------------------------------- #
class AuditColumns:
    """Column set for an ``audit_events`` table (used via multiple inheritance)."""

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    event: Mapped[str] = mapped_column(String, index=True)
    severity: Mapped[str] = mapped_column(String, index=True)
    actor: Mapped[str | None] = mapped_column(String, nullable=True)
    subject: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    client_id: Mapped[str | None] = mapped_column(String, nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String, nullable=True)
    request_id: Mapped[str | None] = mapped_column(String, nullable=True)
    outcome: Mapped[str | None] = mapped_column(String, nullable=True)
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


# --------------------------------------------------------------------------- #
# Logging + alert plumbing (module-level, process-wide).
# --------------------------------------------------------------------------- #
_LOGGER = logging.getLogger("fabric.audit")
_SERVICE = "fabric"
_NOTICE_LEVEL = 25  # between INFO(20) and WARNING(30)
logging.addLevelName(_NOTICE_LEVEL, "NOTICE")

_LEVEL_FOR = {
    Severity.INFO: logging.INFO,
    Severity.NOTICE: _NOTICE_LEVEL,
    Severity.WARNING: logging.WARNING,
    Severity.ALERT: logging.CRITICAL,
}

AlertSink = Callable[[dict[str, Any]], None]
_alert_sinks: list[AlertSink] = []


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = getattr(record, "audit", None)
        if payload is None:
            payload = {"level": record.levelname, "message": record.getMessage()}
        return json.dumps(payload, default=str)


def _default_alert_sink(record: dict[str, Any]) -> None:
    """Loud, human-readable ALERT line on stderr (log-based alerting for the demo)."""
    print(
        f"[ALERT] {record['event']} src={record.get('source_ip')} "
        f"client={record.get('client_id')} detail={json.dumps(record.get('detail', {}), default=str)}",
        file=sys.stderr,
        flush=True,
    )


def configure_audit_logging(service: str) -> None:
    """Attach a JSON stderr handler + default alert sink for ``service`` (idempotent)."""
    global _SERVICE
    _SERVICE = service
    _LOGGER.setLevel(logging.INFO)
    if not any(getattr(h, "_fabric_audit", False) for h in _LOGGER.handlers):
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(_JsonFormatter())
        handler._fabric_audit = True  # type: ignore[attr-defined]
        _LOGGER.addHandler(handler)
        _LOGGER.propagate = False
    if _default_alert_sink not in _alert_sinks:
        register_alert_sink(_default_alert_sink)


def register_alert_sink(sink: AlertSink) -> None:
    """Register a callback invoked for every ``ALERT``-severity event."""
    _alert_sinks.append(sink)


def build_record(
    event: str,
    severity: Severity,
    *,
    actor: str | None = None,
    subject: str | None = None,
    client_id: str | None = None,
    source_ip: str | None = None,
    request_id: str | None = None,
    outcome: str | None = None,
    detail: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "ts": datetime.now(UTC).isoformat(),
        "service": _SERVICE,
        "event": event,
        "severity": severity.value,
        "actor": actor,
        "subject": subject,
        "client_id": client_id,
        "source_ip": source_ip,
        "request_id": request_id,
        "outcome": outcome,
        "detail": detail or {},
        "alert": severity is Severity.ALERT,
    }


def emit(record: dict[str, Any], severity: Severity) -> None:
    """Log the record as JSON, and fan out to alert sinks if it is an alert."""
    _LOGGER.log(_LEVEL_FOR[severity], record["event"], extra={"audit": record})
    if record.get("alert"):
        for sink in _alert_sinks:
            try:
                sink(record)
            except Exception:
                _LOGGER.exception("alert sink failed")


class AuditLog:
    """Request-scoped auditor: logs + alerts immediately, and enqueues a DB row.

    ``row_cls`` is the service's ``AuditEventRow`` (injected so this generic writer works
    for both the IdP and the SPs against their own databases).
    """

    def __init__(
        self,
        session: AsyncSession,
        row_cls: type[AuditColumns],
        *,
        request_id: str | None = None,
        source_ip: str | None = None,
    ) -> None:
        self._session = session
        self._row_cls = row_cls
        self._request_id = request_id
        self._source_ip = source_ip

    async def record(
        self,
        event: str,
        severity: Severity = Severity.INFO,
        *,
        actor: str | None = None,
        subject: str | None = None,
        client_id: str | None = None,
        outcome: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> None:
        record = build_record(
            event,
            severity,
            actor=actor,
            subject=subject,
            client_id=client_id,
            source_ip=self._source_ip,
            request_id=self._request_id,
            outcome=outcome,
            detail=detail,
        )
        emit(record, severity)  # durable log + alert, independent of the DB transaction
        self._session.add(
            self._row_cls(
                ts=datetime.now(UTC),
                event=event,
                severity=severity.value,
                actor=actor,
                subject=subject,
                client_id=client_id,
                source_ip=self._source_ip,
                request_id=self._request_id,
                outcome=outcome,
                detail=detail or {},
            )
        )

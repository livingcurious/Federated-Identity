"""Time helpers. Everything is timezone-aware UTC; tokens use Unix seconds."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta


def utc_now() -> datetime:
    """Current time as a timezone-aware UTC ``datetime``."""
    return datetime.now(UTC)


def unix_now() -> int:
    """Current time as integer Unix seconds (for JWT ``iat``/``exp``/``nbf``)."""
    return int(utc_now().timestamp())


def utc_in(seconds: int) -> datetime:
    """A UTC ``datetime`` ``seconds`` into the future."""
    return utc_now() + timedelta(seconds=seconds)


def is_expired(moment: datetime) -> bool:
    """True if ``moment`` is in the past. Naive datetimes are treated as UTC."""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment <= utc_now()

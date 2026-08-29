"""SP service-layer errors."""

from __future__ import annotations


class SPError(Exception):
    """Base SP error."""


class LoginError(SPError):
    """A login / callback could not be completed (bad state, token, or verification)."""

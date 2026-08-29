"""Domain errors for the IdP service layer.

Each carries an OAuth/OIDC ``error`` code (RFC 6749 §5.2) so the API layer can render a
correct response without inventing strings at the edge.
"""

from __future__ import annotations


class ServiceError(Exception):
    """Base class; ``error`` is the machine-readable OAuth error code."""

    error: str = "server_error"

    def __init__(self, description: str) -> None:
        super().__init__(description)
        self.description = description


class AuthenticationError(ServiceError):
    error = "access_denied"


class InvalidRequestError(ServiceError):
    error = "invalid_request"


class InvalidClientError(ServiceError):
    error = "invalid_client"


class InvalidGrantError(ServiceError):
    error = "invalid_grant"


class SessionInvalidError(ServiceError):
    error = "login_required"

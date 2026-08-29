"""User authentication (Argon2id). Seeded identities only — not a real directory."""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from sqlalchemy.ext.asyncio import AsyncSession

from fabric.common.domain import PublicUser
from fabric.idp.persistence.models import UserRow
from fabric.idp.persistence.repositories import UserRepository
from fabric.idp.service.errors import AuthenticationError

# One hasher instance; argon2id defaults are a sound, current baseline.
_hasher = PasswordHasher()


def hash_password(plaintext: str) -> str:
    return _hasher.hash(plaintext)


def verify_password(stored_hash: str, plaintext: str) -> bool:
    """Constant-work Argon2 verification (used for the admin token too)."""
    try:
        _hasher.verify(stored_hash, plaintext)
        return True
    except VerifyMismatchError:
        return False


class UserService:
    def __init__(self, session: AsyncSession) -> None:
        self._users = UserRepository(session)

    async def authenticate(self, email: str, password: str) -> UserRow:
        """Verify credentials, or raise :class:`AuthenticationError`.

        The same error is raised for unknown user and bad password, and a verify is
        always attempted, to avoid leaking which emails exist via timing/response.
        """
        user = await self._users.get_by_email(email.strip().lower())
        candidate_hash = user.password_hash if user is not None else _DUMMY_HASH
        try:
            _hasher.verify(candidate_hash, password)
        except VerifyMismatchError as exc:
            raise AuthenticationError("invalid email or password") from exc
        if user is None:
            raise AuthenticationError("invalid email or password")
        return user

    async def profile(self, sub: str) -> PublicUser | None:
        user = await self._users.get_by_sub(sub)
        if user is None:
            return None
        return PublicUser(sub=user.sub, email=user.email, name=user.name, roles=list(user.roles))


# A precomputed hash of a random value so authentication does constant work even when
# the email is unknown (mitigates user-enumeration via timing).
_DUMMY_HASH = _hasher.hash("user-enumeration-guard")

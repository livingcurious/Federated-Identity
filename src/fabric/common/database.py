"""Async SQLAlchemy engine/session factory. Each service owns its own SQLite file."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase


def make_engine(db_path: Path) -> AsyncEngine:
    """Create an aiosqlite engine for ``db_path`` (parent dir is created if missing)."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return create_async_engine(f"sqlite+aiosqlite:///{db_path}", future=True)


def make_sessionmaker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


async def create_all(engine: AsyncEngine, base: type[DeclarativeBase]) -> None:
    """Create any missing tables for ``base``'s metadata (idempotent; safe every boot).

    Each service passes its own ``Base`` so an SP's tables never leak into ``idp.db``.
    """
    async with engine.begin() as conn:
        await conn.run_sync(base.metadata.create_all)

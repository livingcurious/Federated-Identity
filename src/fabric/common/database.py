"""Async SQLAlchemy engine/session factory. Each service owns its own SQLite file."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sqlalchemy import MetaData, event, text
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase


def make_engine(db_path: Path) -> AsyncEngine:
    """Create an aiosqlite engine for ``db_path`` (parent dir is created if missing).

    An earlier version of this forced every checkout onto a single shared connection
    (``poolclass=StaticPool``), to fix a real bug: a write committed on one pooled
    connection wasn't guaranteed to be visible to the very next request if it landed on
    a different pooled connection (a just-revoked session still looking "active" for
    one more request). That fix caused a worse one under real concurrency: many
    simultaneous requests each got their own SQLAlchemy session, but all of them
    shared that one physical connection, and SQLite only ever supports one transaction
    per connection — so concurrent requests interleaving on it could tear each other's
    reads and writes (observed live: the token endpoint failing to find an
    authorization code the public app had *just* issued and committed, at up to a ~98%
    failure rate under 60 concurrent logins).

    The actual fix for both problems at once: WAL mode plus a busy timeout, with a
    normal multi-connection pool. WAL gives any new transaction on any connection an
    immediately-consistent view of the last commit (fixing the original staleness, the
    reason it exists at all), and the busy timeout makes a writer that loses a lock
    race wait and retry instead of raising "database is locked" — while a real pool
    means concurrent requests get distinct connections instead of fighting over one.
    """
    db_path.parent.mkdir(parents=True, exist_ok=True)
    engine = create_async_engine(
        f"sqlite+aiosqlite:///{db_path}",
        future=True,
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(engine.sync_engine, "connect")
    def _set_sqlite_pragmas(dbapi_connection: Any, connection_record: Any) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.close()

    return engine


def make_sessionmaker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


async def create_all(engine: AsyncEngine, base: type[DeclarativeBase]) -> None:
    """Create any missing tables for ``base``'s metadata (idempotent; safe every boot),
    then patch any *columns* missing from tables that already existed.

    Each service passes its own ``Base`` so an SP's tables never leak into ``idp.db``.
    """
    async with engine.begin() as conn:
        await conn.run_sync(base.metadata.create_all)
        await _add_missing_columns(conn, base.metadata)


async def _add_missing_columns(conn: AsyncConnection, metadata: MetaData) -> None:
    """Best-effort additive migration: SQLite allows ``ALTER TABLE ... ADD COLUMN`` on a
    populated table, so a DB created before a column existed doesn't have to be wiped
    just because ``create_all`` never alters an existing table (it only issues
    ``CREATE TABLE IF NOT EXISTS``).

    Added columns are always nullable at the DB level regardless of the ORM's declared
    nullability, so the ``ALTER TABLE`` always succeeds on a non-empty table: existing
    rows get ``NULL`` for the new column (fine for the boolean/optional columns this
    project actually adds — e.g. ``ClientRow.key_revoked``, where ``NULL`` and ``False``
    are equally falsy); new rows get whatever the ORM's ``default=`` supplies. This is
    *not* a general migration system — it does not rename, drop, retype an existing
    column, or backfill a value other than ``NULL``.
    """
    for table in metadata.tables.values():
        result = await conn.execute(text(f'PRAGMA table_info("{table.name}")'))
        existing_columns = {row[1] for row in result.fetchall()}
        for column in table.columns:
            if column.name in existing_columns:
                continue
            coltype = column.type.compile(dialect=conn.dialect)
            await conn.execute(
                text(f'ALTER TABLE "{table.name}" ADD COLUMN "{column.name}" {coltype}')
            )

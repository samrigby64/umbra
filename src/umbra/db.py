"""Async database access.

The single most important fix vs. the original project: every unit of work gets
its **own** session via ``async with db.session()``. No session is ever shared
across concurrent tasks, so there is no thread-safety hazard to reason about.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

import sqlalchemy as sa
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from .logging import get_logger
from .models import Base

# Indexes replaced by a differently-shaped one. Named explicitly rather than
# inferred: dropping every index absent from the models would delete any an
# operator added by hand for their own query patterns.
_OBSOLETE_INDEXES: dict[str, tuple[str, ...]] = {
    # Alert dedup moved from (watchlist_id, page_url) to (watchlist_id, dedup_key):
    # a service that goes down, recovers, and goes down again is three alerts, not
    # one, and the old index made the second and third impossible to record.
    "alerts": ("ix_alert_watch_page",),
}

# Run once, immediately after the named column is added, to give existing rows a
# value. Adding a nullable column is only half a migration: rows written by the
# old build have NULL there, and any logic that reads it treats them as absent.
# Here that would mean every alert ever recorded looking un-deduplicated, so the
# next watchlist evaluation would re-alert the entire history.
_BACKFILLS: dict[str, str] = {
    "alerts.dedup_key": "UPDATE alerts SET dedup_key = page_url WHERE dedup_key IS NULL",
}


def _ensure_sqlite_dir(url: str) -> None:
    """Create the directory a file-backed SQLite URL points into.

    The default database now lives under the user's data directory rather than
    the working directory, and a fresh install has no such directory yet. Without
    this the very first ``umbra serve`` fails with "unable to open database file",
    which is a bad first impression and an obscure one.
    """
    path = url.split("///", 1)[-1].split("?", 1)[0]
    if path and path != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)


class Database:
    def __init__(self, url: str, echo: bool = False) -> None:
        self._write_lock = asyncio.Lock()
        is_sqlite = url.startswith("sqlite")
        if is_sqlite:
            _ensure_sqlite_dir(url)
        # SQLite is single-writer: with several async workers committing at once,
        # the default rejects concurrent writes ("database is locked"). WAL allows
        # concurrent readers + one writer, and busy_timeout makes writers wait
        # instead of erroring. (No-op for Postgres.)
        connect_args = {"timeout": 30} if is_sqlite else {}
        self._engine = create_async_engine(
            url, echo=echo, pool_pre_ping=True, connect_args=connect_args
        )
        if is_sqlite:

            @event.listens_for(self._engine.sync_engine, "connect")
            def _set_sqlite_pragmas(dbapi_conn, _record):  # pragma: no cover - driver glue
                cur = dbapi_conn.cursor()
                cur.execute("PRAGMA busy_timeout=30000")
                try:
                    cur.execute("PRAGMA journal_mode=WAL")
                except Exception as exc:
                    # A second process can race the first WAL transition before
                    # transactional migration locking is available. It can still
                    # use SQLite safely; the other connection owns that transition.
                    if "locked" not in str(exc).lower():
                        raise
                cur.close()

        self._sessionmaker = async_sessionmaker(
            self._engine, expire_on_commit=False, class_=AsyncSession
        )

    async def create_all(self) -> None:
        # One transactional migration owner across processes.
        from .migrations import check_revision, stamp_revision
        async with self._write_lock, self._engine.begin() as conn:
            if self._engine.dialect.name == "sqlite":
                await conn.execute(sa.text("BEGIN IMMEDIATE"))
            else:
                await conn.execute(sa.text("SELECT pg_advisory_xact_lock(84201931)"))
            await check_revision(conn)
            await conn.run_sync(Base.metadata.create_all)
            await self.upgrade_schema(connection=conn)
            if self._engine.dialect.name == "sqlite":
                exists = await conn.scalar(sa.text("SELECT count(*) FROM sqlite_master WHERE name='pages_fts'"))
                await conn.execute(sa.text("CREATE VIRTUAL TABLE IF NOT EXISTS pages_fts USING fts5(url UNINDEXED, title, content)"))
                if not exists:
                    await conn.execute(sa.text("INSERT INTO pages_fts SELECT url,title,content FROM pages WHERE blocked=0"))
                await conn.execute(sa.text("CREATE TRIGGER IF NOT EXISTS pages_fts_insert AFTER INSERT ON pages WHEN NEW.blocked=0 BEGIN INSERT INTO pages_fts(url,title,content) VALUES(NEW.url,NEW.title,NEW.content); END"))
                await conn.execute(sa.text("CREATE TRIGGER IF NOT EXISTS pages_fts_delete AFTER DELETE ON pages BEGIN DELETE FROM pages_fts WHERE url=OLD.url; END"))
                await conn.execute(sa.text("CREATE TRIGGER IF NOT EXISTS pages_fts_update AFTER UPDATE OF content,title,blocked,url ON pages BEGIN DELETE FROM pages_fts WHERE url=OLD.url; INSERT INTO pages_fts(url,title,content) SELECT NEW.url,NEW.title,NEW.content WHERE NEW.blocked=0; END"))
                for operation in ('UPDATE', 'DELETE'):
                    await conn.execute(sa.text(f"CREATE TRIGGER IF NOT EXISTS audit_no_{operation.lower()} BEFORE {operation} ON audit_entries BEGIN SELECT RAISE(ABORT, 'Audit entries are append-only'); END"))
            else:
                await conn.execute(sa.text("CREATE OR REPLACE FUNCTION umbra_audit_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Audit entries are append-only'; END $$"))
                await conn.execute(sa.text("DROP TRIGGER IF EXISTS audit_immutable ON audit_entries"))
                await conn.execute(sa.text("CREATE TRIGGER audit_immutable BEFORE UPDATE OR DELETE ON audit_entries FOR EACH ROW EXECUTE FUNCTION umbra_audit_immutable()"))
            await stamp_revision(conn)

    async def upgrade_schema(self, connection=None) -> list[str]:
        """Apply additive schema changes to a database created by an older build.

        ``create_all`` only creates *missing tables* — it never touches a table
        that already exists. So shipping a new column to an existing deployment
        does nothing, and the first query referencing it fails at runtime rather
        than at deploy. That is fine for a project that recreates its database and
        unacceptable for one customers upgrade in place.

        Deliberately narrow: adds missing columns, creates missing indexes, and
        drops indexes named in ``_OBSOLETE_INDEXES``. It does not drop columns,
        rename, or change types, because those need data migration decisions this
        cannot make safely. New columns are added nullable even when the model
        marks them NOT NULL — existing rows have no value to put there, and the
        ORM fills them going forward. A real migration tool (Alembic) is the
        answer once schema changes stop being purely additive.
        """
        applied: list[str] = []

        def _sync(conn) -> None:
            inspector = sa.inspect(conn)
            tables = set(inspector.get_table_names())
            for table in Base.metadata.sorted_tables:
                if table.name not in tables:
                    continue  # create_all just made it, with every column
                existing = {c["name"] for c in inspector.get_columns(table.name)}
                for column in table.columns:
                    if column.name in existing:
                        continue
                    type_sql = column.type.compile(dialect=conn.dialect)
                    conn.execute(
                        sa.text(f'ALTER TABLE {table.name} ADD COLUMN "{column.name}" {type_sql}')
                    )
                    applied.append(f"{table.name}.{column.name}")
                    existing.add(column.name)

                # Backfills run on every upgrade, not only when the column is
                # first added. Each is guarded by its own WHERE clause, so it is a
                # no-op once satisfied — and that is what makes it safe to re-run.
                # Tying them to the ALTER instead would leave any deployment that
                # got the column from a partial or interrupted upgrade stuck with
                # NULLs that nothing would ever fix.
                for name, statement in _BACKFILLS.items():
                    backfill_table, _, backfill_column = name.partition(".")
                    if backfill_table != table.name or backfill_column not in existing:
                        continue
                    result = conn.execute(sa.text(statement))
                    if result.rowcount:
                        applied.append(f"~{name}({result.rowcount} rows)")

                index_names = {i["name"] for i in inspector.get_indexes(table.name)}
                for name in _OBSOLETE_INDEXES.get(table.name, ()):
                    if name in index_names:
                        conn.execute(sa.text(f"DROP INDEX {name}"))
                        applied.append(f"-{name}")
                for index in table.indexes:
                    if index.name not in index_names:
                        index.create(conn, checkfirst=True)
                        applied.append(f"+{index.name}")

        if connection is not None:
            await connection.run_sync(_sync)
        else:
            async with self._engine.begin() as conn:
                await conn.run_sync(_sync)
        if applied:
            get_logger("db").info("schema upgrade applied: %s", ", ".join(applied))
        return applied

    @asynccontextmanager
    async def session(self) -> AsyncIterator[AsyncSession]:
        async with self._sessionmaker() as session:
            yield session

    async def dispose(self) -> None:
        await self._engine.dispose()

    @asynccontextmanager
    async def write_session(self) -> AsyncIterator[AsyncSession]:
        """Serialize frontier read/modify/write across processes, not just tasks.

        PostgreSQL uses a transaction advisory lock for this single-frontier design.
        SQLite obtains its write reservation before reading, avoiding lost claims.
        Keep transactions short; no fetching or embedding under this lock.
        """
        async with self._write_lock:
            async with self._sessionmaker() as session:
                if self._engine.dialect.name == "sqlite":
                    await session.execute(sa.text("BEGIN IMMEDIATE"))
                else:
                    await session.execute(sa.text("SELECT pg_advisory_xact_lock(84201931)"))
                yield session

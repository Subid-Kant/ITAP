"""
ITAP — Database Engine & Session Management
"""
import logging

from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase

from app.core.config import settings


logger = logging.getLogger("itap.db")


# Single source of truth for the DB URL: pydantic-settings has already merged
# .env with the process environment. Reading os.getenv() here bypassed that and
# silently ignored any DATABASE_URL set in .env (e.g. pointing at PostgreSQL).
DB_URL = settings.DATABASE_URL
IS_SQLITE = DB_URL.startswith("sqlite")

_engine_kwargs: dict = {"echo": settings.DB_ECHO, "future": True}
if not IS_SQLITE:
    # SQLite's pool ignores/handles these differently, so only apply to real pools.
    _engine_kwargs["pool_size"] = settings.DB_POOL_SIZE
    _engine_kwargs["max_overflow"] = settings.DB_MAX_OVERFLOW
else:
    # One connection at a time: SQLite serialises writers anyway, and a pool that
    # hands out several connections only multiplies "database is locked" errors
    # while an Nmap scan is writing.
    from sqlalchemy.pool import NullPool

    _engine_kwargs["poolclass"] = NullPool

engine = create_async_engine(DB_URL, **_engine_kwargs)
async_session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


if IS_SQLITE:
    @event.listens_for(engine.sync_engine, "connect")
    def _apply_sqlite_pragmas(dbapi_conn, _connection_record):
        """Per-connection SQLite tuning.

        WAL lets readers proceed while a writer writes, and busy_timeout turns the
        instant "database is locked" error into a short wait when two scans land
        together. Foreign-key enforcement is the interesting one: SQLite ships it
        *off*, which is exactly why ``delete_all_history`` could delete parents
        before children without complaint. Enforcing it surfaces real referential
        bugs during the dev phase instead of after a move to PostgreSQL.
        """
        cursor = dbapi_conn.cursor()
        try:
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA busy_timeout=5000")
            cursor.execute(
                "PRAGMA foreign_keys=ON"
                if settings.DB_SQLITE_ENFORCE_FOREIGN_KEYS
                else "PRAGMA foreign_keys=OFF"
            )
        finally:
            cursor.close()



class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncSession:
    """Dependency to get database session."""
    async with async_session_factory() as session:
        try:
            yield session
        finally:
            await session.close()


def _create_missing_indexes(sync_conn):
    """Create indexes an already-existing database does not have yet.

    ``create_all(checkfirst=True)`` is per-table: once a table exists, indexes
    newly declared on it are skipped. Without this pass the indexes added for the
    dashboard queries would never reach a developer's existing ``itap.db``.
    """
    for table in Base.metadata.tables.values():
        for index in table.indexes:
            try:
                index.create(sync_conn, checkfirst=True)
            except Exception:      # never block startup over an index
                logger.warning("could not create index %s", index.name, exc_info=True)


async def init_db():
    """Initialize database tables."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.run_sync(_create_missing_indexes)

        
        # Add is_archived column to existing tables if they don't have it
        tables = ["targets", "scans", "threats", "incidents", "anomaly_detections"]
        for table in tables:
            try:
                await conn.execute(text(f"ALTER TABLE {table} ADD COLUMN is_archived BOOLEAN DEFAULT FALSE"))
            except Exception as e:
                # Column likely already exists
                pass

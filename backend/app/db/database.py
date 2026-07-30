"""
ITAP — Database Engine & Session Management
"""
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from app.core.config import settings


# For development: use SQLite as fallback when PostgreSQL is not available
import os
DB_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./itap.db")

engine = create_async_engine(DB_URL, echo=settings.DEBUG)
async_session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncSession:
    """Dependency to get database session."""
    async with async_session_factory() as session:
        try:
            yield session
        finally:
            await session.close()


from sqlalchemy import text

async def init_db():
    """Initialize database tables."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        
        # Add is_archived column to existing tables if they don't have it
        tables = ["targets", "scans", "threats", "incidents", "anomaly_detections"]
        for table in tables:
            try:
                await conn.execute(text(f"ALTER TABLE {table} ADD COLUMN is_archived BOOLEAN DEFAULT FALSE"))
            except Exception as e:
                # Column likely already exists
                pass

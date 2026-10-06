"""Async SQLAlchemy session and engine management for Neon PostgreSQL."""

from typing import Optional
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from app.core.config import Settings, get_settings
from app.core.logging import logger

_engine: Optional[AsyncEngine] = None
_sessionmaker: Optional[async_sessionmaker[AsyncSession]] = None


def get_engine(settings: Optional[Settings] = None) -> AsyncEngine:
    """Get or initialize the async engine."""
    global _engine, _sessionmaker
    if _engine is None:
        if settings is None:
            settings = get_settings()
        _engine = create_async_engine(
            settings.DATABASE_URL,
            pool_size=settings.DB_POOL_SIZE,
            max_overflow=settings.DB_MAX_OVERFLOW,
            echo=False,
            future=True,
        )
        _sessionmaker = async_sessionmaker(
            bind=_engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
    return _engine


async def init_db(settings: Optional[Settings] = None) -> None:
    """Initialize DB engine on application startup."""
    get_engine(settings)
    logger.info("Database engine initialized.")


async def close_db() -> None:
    """Dispose of the database engine on shutdown."""
    global _engine, _sessionmaker
    if _engine is not None:
        logger.info("Disposing database engine...")
        await _engine.dispose()
        _engine = None
        _sessionmaker = None
        logger.info("Database engine disposed.")


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    """Retrieve the session factory."""
    if _sessionmaker is None:
        get_engine()
    assert _sessionmaker is not None
    return _sessionmaker


async def check_db_health() -> bool:
    """Check database connectivity with a lightweight probe."""
    try:
        from sqlalchemy import text
        session_factory = get_sessionmaker()
        async with session_factory() as session:
            result = await session.execute(text("SELECT 1"))
            return result.scalar() == 1
    except Exception as exc:
        logger.warning("Database health check failed: %s", exc)
        return False

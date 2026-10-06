"""FastAPI dependency injection providers."""

from typing import AsyncIterator
from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.config import Settings, get_settings
from app.db.session import get_sessionmaker
from app.infra.redis import get_redis
import redis.asyncio as aioredis


def get_app_settings() -> Settings:
    """Dependency for application settings."""
    return get_settings()


async def get_db_session() -> AsyncIterator[AsyncSession]:
    """Dependency for scoped database sessions."""
    session_factory = get_sessionmaker()
    async with session_factory() as session:
        yield session


def get_redis_client() -> aioredis.Redis:
    """Dependency for Redis client."""
    client = get_redis()
    if client is None:
        raise RuntimeError("Redis client is not available")
    return client

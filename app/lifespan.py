"""Application lifespan combining FastMCP, Redis, DB, and HTTP clients."""

from contextlib import asynccontextmanager
from typing import AsyncIterator
from fastapi import FastAPI
from app.core.config import get_settings
from app.core.logging import logger, configure_logging
from app.infra.redis import init_redis, close_redis
from app.db.session import init_db, close_db
from app.integrations.fayda.client import init_http_client, close_http_client
from app.mcp.server import mcp_server


def create_mcp_app():
    """Create the Starlette streamable HTTP app for FastMCP."""
    return mcp_server.http_app(path="/mcp", transport="streamable-http")


@asynccontextmanager
async def application_lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Combined lifespan managing all application services and FastMCP lifecycle."""
    settings = get_settings()
    configure_logging(settings.LOG_LEVEL)
    logger.info("Starting up %s (env=%s)...", settings.APP_NAME, settings.APP_ENV)

    # 1. Initialize DB engine
    try:
        await init_db(settings)
    except Exception as exc:
        logger.warning("DB engine startup notice: %s", exc)

    # 2. Initialize Redis client
    try:
        await init_redis(settings)
    except Exception as exc:
        logger.warning("Redis client startup notice: %s", exc)

    # 3. Initialize bounded async HTTP client
    await init_http_client(settings)

    # 4. FastMCP lifespan execution
    mcp_app = getattr(app.state, "mcp_app", None)
    if mcp_app is not None and hasattr(mcp_app, "lifespan"):
        logger.info("Entering FastMCP lifespan context...")
        async with mcp_app.lifespan(app):
            logger.info("%s fully initialized and ready.", settings.APP_NAME)
            yield
    else:
        logger.info("%s initialized without sub-lifespan.", settings.APP_NAME)
        yield

    # Clean shutdown of all clients
    logger.info("Beginning graceful application shutdown...")

    try:
        await close_http_client()
    except Exception as exc:
        logger.warning("Error closing HTTP client: %s", exc)

    try:
        await close_redis()
    except Exception as exc:
        logger.warning("Error closing Redis: %s", exc)

    try:
        await close_db()
    except Exception as exc:
        logger.warning("Error closing DB: %s", exc)

    logger.info("All clients shut down cleanly.")

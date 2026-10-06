"""Bounded async HTTP client for Fayda eSignet and JWKS operations."""

from typing import Optional
import httpx
from app.core.config import Settings, get_settings
from app.core.logging import logger

_http_client: Optional[httpx.AsyncClient] = None


async def init_http_client(settings: Optional[Settings] = None) -> httpx.AsyncClient:
    """Initialize bounded async HTTP client."""
    global _http_client
    if settings is None:
        settings = get_settings()

    timeout = httpx.Timeout(
        connect=settings.FAYDA_HTTP_TIMEOUT_SECONDS,
        read=settings.FAYDA_HTTP_TIMEOUT_SECONDS,
        write=settings.FAYDA_HTTP_TIMEOUT_SECONDS,
        pool=settings.FAYDA_HTTP_TIMEOUT_SECONDS,
    )
    limits = httpx.Limits(max_keepalive_connections=20, max_connections=50)

    _http_client = httpx.AsyncClient(
        timeout=timeout,
        limits=limits,
        headers={"User-Agent": f"{settings.APP_NAME}/1.0"},
    )
    logger.info("Shared HTTP client initialized.")
    return _http_client


async def close_http_client() -> None:
    """Close the shared HTTP client cleanly."""
    global _http_client
    if _http_client is not None:
        logger.info("Closing shared HTTP client...")
        await _http_client.aclose()
        _http_client = None
        logger.info("Shared HTTP client closed.")


def get_http_client() -> httpx.AsyncClient:
    """Return the shared HTTP client."""
    if _http_client is None:
        raise RuntimeError("HTTP client is not initialized. Ensure app lifespan is active.")
    return _http_client

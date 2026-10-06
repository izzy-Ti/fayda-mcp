"""Bounded async HTTP client for Fayda OIDC requests."""

from typing import Optional
import httpx
from fayda_mcp.config import FaydaConfig


class FaydaHttpClient:
    """Bounded async HTTP client managing connection limits and timeouts."""

    def __init__(self, config: FaydaConfig, client: Optional[httpx.AsyncClient] = None) -> None:
        self.config = config
        self._owned_client = client is None
        self._client = client or httpx.AsyncClient(
            timeout=httpx.Timeout(config.http_timeout_seconds),
            limits=httpx.Limits(max_keepalive_connections=10, max_connections=20),
            headers={"User-Agent": f"fayda-mcp/0.1.0"},
        )

    @property
    def client(self) -> httpx.AsyncClient:
        return self._client

    async def aclose(self) -> None:
        """Close the underlying client if owned by this instance."""
        if self._owned_client and not self._client.is_closed:
            await self._client.aclose()

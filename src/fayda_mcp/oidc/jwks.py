"""Trusted JWKS retrieval and key rotation cache."""

import time
from typing import Any, Dict, Optional
import httpx
from fayda_mcp.config import FaydaConfig
from fayda_mcp.exceptions import ProviderError


class JwksCache:
    """In-memory cache for provider public keys with bounded refresh."""

    def __init__(self, config: FaydaConfig) -> None:
        self.config = config
        self._keys: Dict[str, Any] = {}
        self._last_fetched: float = 0.0

    async def get_key_for_token(self, token_str: str, client: httpx.AsyncClient) -> Any:
        """Fetch and return matching PyJWK for the token header kid."""
        # Key cache logic expanded in task B2
        return None

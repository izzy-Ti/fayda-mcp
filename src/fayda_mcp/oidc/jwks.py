"""Trusted JWKS retrieval and key rotation cache."""

import time
from typing import Any, Dict, Optional
import httpx
import jwt
from jwt import PyJWK, PyJWKSet
from fayda_mcp.config import FaydaConfig
from fayda_mcp.exceptions import ProviderError, TokenValidationError


class JwksCache:
    """In-memory cache for provider public keys with bounded refresh and TTL."""

    def __init__(self, config: FaydaConfig) -> None:
        self.config = config
        self._keys: Dict[str, Any] = {}
        self._last_fetched: float = 0.0

    def add_key(self, kid: str, key: Any) -> None:
        """Manually register a trusted public key (for tests or local configurations)."""
        self._keys[kid] = key
        # Treat manually supplied keys as freshly loaded so the configured TTL
        # still applies without forcing a network fetch on the next lookup.
        self._last_fetched = time.time()

    async def fetch_jwks(self, client: httpx.AsyncClient) -> None:
        """Fetch provider JWKS over HTTPS with bounded timeout."""
        try:
            resp = await client.get(self.config.jwks_uri)
            resp.raise_for_status()
            jwks_data = resp.json()
        except Exception as exc:
            raise ProviderError(f"Failed to retrieve provider JWKS from {self.config.jwks_uri}: {exc}") from exc

        keys_dict: Dict[str, Any] = {}
        for k in jwks_data.get("keys", []):
            try:
                pyjwk = PyJWK.from_dict(k)
                kid = k.get("kid") or pyjwk.key_id
                if kid:
                    keys_dict[kid] = pyjwk.key
                else:
                    keys_dict["_default"] = pyjwk.key
            except Exception:
                continue

        self._keys.update(keys_dict)
        self._last_fetched = time.time()

    async def get_signing_key_for_token(self, token_str: str, client: httpx.AsyncClient) -> Any:
        """Extract header kid and resolve trusted signing key, refreshing cache if unknown."""
        try:
            header = jwt.get_unverified_header(token_str)
        except Exception as exc:
            raise TokenValidationError(f"Failed to read token header: {exc}") from exc

        kid = header.get("kid")

        # Check existing cached keys if within configured TTL
        if bool(self._keys) and (time.time() - self._last_fetched) < self.config.jwks_cache_ttl_seconds:
            if kid and kid in self._keys:
                return self._keys[kid]
            if not kid and "_default" in self._keys:
                return self._keys["_default"]
            if not kid and len(self._keys) == 1:
                return next(iter(self._keys.values()))
        else:
            self._keys.clear()

        # Cache miss or expired: fetch JWKS with single bounded refresh
        await self.fetch_jwks(client)

        if kid and kid in self._keys:
            return self._keys[kid]
        if not kid and len(self._keys) == 1:
            return next(iter(self._keys.values()))
        if "_default" in self._keys:
            return self._keys["_default"]

        raise TokenValidationError(
            f"Provider key kid '{kid}' not found in trusted JWKS at {self.config.jwks_uri}"
        )

"""Bounded async HTTP client for Fayda OIDC requests."""

from typing import Any, Dict, Optional, Union
import httpx
from fayda_mcp.config import FaydaConfig
from fayda_mcp.exceptions import AuthenticationError, ProviderError


class FaydaHttpClient:
    """Bounded async HTTP client managing connection limits and timeouts."""

    def __init__(self, config: FaydaConfig, client: Optional[httpx.AsyncClient] = None) -> None:
        self.config = config
        self._owned_client = client is None
        self._client = client or httpx.AsyncClient(
            timeout=httpx.Timeout(config.http_timeout_seconds),
            limits=httpx.Limits(max_keepalive_connections=10, max_connections=20),
            headers={"User-Agent": "fayda-mcp/0.1.0"},
        )

    @property
    def client(self) -> httpx.AsyncClient:
        return self._client

    async def aclose(self) -> None:
        """Close the underlying client if owned by this instance."""
        if self._owned_client and not self._client.is_closed:
            await self._client.aclose()

    async def exchange_code(
        self,
        code: str,
        code_verifier: str,
        client_assertion: str,
    ) -> Dict[str, Any]:
        """Exchange authorization code for tokens using private_key_jwt client assertion and PKCE verifier."""
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.config.redirect_uri,
            "code_verifier": code_verifier,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": client_assertion,
        }

        try:
            resp = await self._client.post(
                self.config.token_endpoint,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        except Exception as exc:
            raise ProviderError(f"Token endpoint request failed: {exc}") from exc

        if resp.status_code >= 400:
            try:
                err_body = resp.json()
                err_desc = err_body.get("error_description") or err_body.get("error") or resp.text
            except Exception:
                err_desc = resp.text
            raise AuthenticationError(
                f"Code exchange failed (status {resp.status_code}): {err_desc}"
            )

        try:
            return resp.json()
        except Exception as exc:
            raise ProviderError(f"Token endpoint returned non-JSON response: {exc}") from exc

    async def fetch_userinfo(self, access_token: str) -> Union[Dict[str, Any], str]:
        """Fetch userinfo payload from Fayda UserInfo endpoint."""
        try:
            resp = await self._client.get(
                self.config.userinfo_endpoint,
                headers={"Authorization": f"Bearer {access_token}"},
            )
        except Exception as exc:
            raise ProviderError(f"UserInfo endpoint request failed: {exc}") from exc

        if resp.status_code >= 400:
            raise AuthenticationError(f"UserInfo request failed with status {resp.status_code}: {resp.text}")

        content_type = resp.headers.get("content-type", "")
        if "application/jwt" in content_type:
            return resp.text.strip()

        try:
            return resp.json()
        except Exception:
            return resp.text.strip()

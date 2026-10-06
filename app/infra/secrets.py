"""Secrets manager abstraction for Fayda client private signing keys."""

from typing import Optional


class SecretsClient:
    """Abstract interface to retrieve per-business signing keys."""

    async def get_private_key(self, secret_ref: str, version: Optional[str] = None) -> Optional[str]:
        """Fetch private key PEM/JWK by secret reference."""
        return None


def get_secrets_client() -> SecretsClient:
    """Return default secrets client instance."""
    return SecretsClient()

"""Signing-key provider protocols."""

from typing import Protocol, runtime_checkable


@runtime_checkable
class KeyProvider(Protocol):
    """Protocol for supplying private signing keys (JWK or PEM)."""

    async def get_private_key(self) -> str:
        """Retrieve private key material securely."""
        ...

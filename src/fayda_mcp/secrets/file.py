"""Local file signing key provider."""

import os
from fayda_mcp.exceptions import ConfigurationError


class FileKeyProvider:
    """Reads private signing key from a file path."""

    def __init__(self, key_path: str) -> None:
        self.key_path = key_path

    async def get_private_key(self) -> str:
        """Read and return key contents."""
        if not os.path.exists(self.key_path):
            raise ConfigurationError(f"Signing key file not found: {self.key_path}")
        with open(self.key_path, "r", encoding="utf-8") as f:
            return f.read().strip()

"""Client assertion creation for Fayda private_key_jwt client authentication."""

import time
import uuid
from typing import Optional
import jwt
from fayda_mcp.config import FaydaConfig


def create_client_assertion(
    config: FaydaConfig,
    private_key: str,
    algorithm: str = "RS256",
) -> str:
    """Create a signed client assertion JWT for private_key_jwt authentication."""
    now = int(time.time())
    payload = {
        "iss": config.client_id,
        "sub": config.client_id,
        "aud": config.token_endpoint,
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + config.client_assertion_ttl_seconds,
    }

    return jwt.encode(payload, private_key, algorithm=algorithm)

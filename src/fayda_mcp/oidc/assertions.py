"""Client assertion creation for Fayda private_key_jwt client authentication."""

import time
import uuid
from typing import Any, Dict, Optional
import jwt
from fayda_mcp.config import FaydaConfig


def create_client_assertion(
    config: FaydaConfig,
    private_key: Any,
    algorithm: str = "RS256",
    key_id: Optional[str] = None,
) -> str:
    """Create a signed client assertion JWT for private_key_jwt authentication per RFC 7523.

    Args:
        config: Provider configuration containing client_id and token_endpoint.
        private_key: Private key in PEM or cryptography key object format.
        algorithm: JWS signature algorithm (default: RS256).
        key_id: Optional kid header parameter.
    """
    now = int(time.time())
    payload = {
        "iss": config.client_id,
        "sub": config.client_id,
        "aud": config.token_endpoint,
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + config.client_assertion_ttl_seconds,
    }

    headers: Dict[str, str] = {"alg": algorithm, "typ": "JWT"}
    if key_id:
        headers["kid"] = key_id

    return jwt.encode(payload, private_key, algorithm=algorithm, headers=headers)

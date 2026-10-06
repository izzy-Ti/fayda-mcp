"""Structured logging and sensitive data redaction."""

import logging
import re
from typing import Any, Dict


# Sensitive fields / patterns to redact from logs
SENSITIVE_PATTERNS = [
    re.compile(r"(token|secret|assertion|key|authorization|code|nonce|verifier)=[^&\s]+", re.IGNORECASE),
    re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE),
]

SENSITIVE_KEYS = {
    "access_token",
    "id_token",
    "refresh_token",
    "client_secret",
    "private_key",
    "code",
    "code_verifier",
    "nonce",
    "state",
    "otp",
    "pin",
    "biometric",
    "phone_number",
    "date_of_birth",
    "birthdate",
    "national_id",
    "fayda_number",
}


def redact_text(text: str) -> str:
    """Redact sensitive query params and tokens in arbitrary text."""
    redacted = text
    for pattern in SENSITIVE_PATTERNS:
        redacted = pattern.sub(r"\1=[REDACTED]", redacted)
    return redacted


def sanitize_dict(data: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively sanitize dictionary values for safe structured logging."""
    sanitized: Dict[str, Any] = {}
    for key, value in data.items():
        if key.lower() in SENSITIVE_KEYS:
            sanitized[key] = "[REDACTED]"
        elif isinstance(value, dict):
            sanitized[key] = sanitize_dict(value)
        elif isinstance(value, list):
            sanitized[key] = [
                sanitize_dict(item) if isinstance(item, dict) else item
                for item in value
            ]
        elif isinstance(value, str):
            sanitized[key] = redact_text(value)
        else:
            sanitized[key] = value
    return sanitized


def configure_logging(level: str = "INFO") -> None:
    """Configure standard structured logging."""
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


logger = logging.getLogger("fayda_mcp_bridge")

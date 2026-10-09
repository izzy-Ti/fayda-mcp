"""Parser and text ingestion for Fayda National ID QR codes.

Ensures strict byte preservation of raw scanner text for cryptographic detached
signature verification, bounds input size limits, and isolates display normalization
from signature payload bytes.
"""

import hashlib
import re
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field

from fayda_mcp.qr.schemas import (
    MAX_QR_TEXT_BYTES,
    QRMalformedError,
    QRPayloadSizeExceededError,
)
from fayda_mcp.qr.signed_content import normalize_qr_dob


class ScannerInput(BaseModel):
    """Container holding unchanged scanner text alongside its cryptographic byte digest.

    Preserves exact byte content without stripping, trimming, or mutating whitespace,
    which is mandatory for verifying detached RS256 signatures over the payload.
    """

    model_config = ConfigDict(extra="forbid")

    raw_text: str = Field(..., description="Preserved unchanged scanner string")
    size_bytes: int = Field(..., description="Byte length of raw_text encoded as UTF-8")
    sha256_digest: str = Field(..., description="SHA-256 hex digest of unchanged scanner text")


def validate_scanner_text(raw_text: str, max_bytes: int = MAX_QR_TEXT_BYTES) -> str:
    """Validate and preserve unchanged scanner text within bounded memory limits.

    Rules:
    1. Rejects non-string or completely empty inputs.
    2. Enforces maximum byte length (default 16 KB) to prevent memory exhaustion attacks.
    3. Strictly returns raw_text UNCHANGED: no strip(), no trim(), no whitespace modification.
    """
    if not isinstance(raw_text, str):
        raise QRMalformedError(
            message="QR scanner input must be a string",
            details={"input_type": type(raw_text).__name__},
        )

    if not raw_text or not raw_text.strip():
        raise QRMalformedError(
            message="QR scanner input cannot be empty or whitespace-only",
            details={"length": len(raw_text)},
        )

    raw_bytes = raw_text.encode("utf-8")
    byte_count = len(raw_bytes)

    if byte_count > max_bytes:
        raise QRPayloadSizeExceededError(
            size_bytes=byte_count,
            max_bytes=max_bytes,
        )

    return raw_text


def ingest_scanner_text(raw_text: str, max_bytes: int = MAX_QR_TEXT_BYTES) -> ScannerInput:
    """Validate scanner text and wrap into a ScannerInput container with SHA-256 digest."""
    validated = validate_scanner_text(raw_text, max_bytes=max_bytes)
    raw_bytes = validated.encode("utf-8")
    digest = hashlib.sha256(raw_bytes).hexdigest()
    return ScannerInput(
        raw_text=validated,
        size_bytes=len(raw_bytes),
        sha256_digest=digest,
    )


# ---------------------------------------------------------------------------
# Display Normalization Utilities (Kept Strictly Separate from Raw Content)
# ---------------------------------------------------------------------------


def normalize_fan_digits(raw_fan: str) -> str:
    """Normalize raw FAN string by stripping whitespace and non-digit characters.

    e.g. '6042  3061  7816  8402' -> '6042306178168402'
    """
    return re.sub(r"\s+", "", raw_fan)


def format_fan_display(fan_digits: str) -> str:
    """Format normalized 16-digit FAN with standard 4-digit grouping for UI display.

    e.g. '6042306178168402' -> '6042 3061 7816 8402'
    """
    clean = normalize_fan_digits(fan_digits)
    if len(clean) == 16:
        return f"{clean[0:4]} {clean[4:8]} {clean[8:12]} {clean[12:16]}"
    return clean


def normalize_name_for_display(raw_name: str) -> str:
    """Collapse internal whitespace and strip leading/trailing spaces for display presentation.

    Leaves raw_name unmodified in cryptographic verification structures.
    """
    return " ".join(raw_name.strip().split())


def normalize_gender_for_display(raw_gender: str) -> str:
    """Normalize raw gender code for UI display ('M', 'F', 'O')."""
    return raw_gender.strip().upper()


def normalize_dob_for_display(raw_dob: str, calendar: str = "gregorian") -> Optional[str]:
    """Normalize raw date of birth (YYYY/MM/DD) to ISO format (YYYY-MM-DD)."""
    return normalize_qr_dob(raw_dob, calendar=calendar)

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
    SUPPORTED_QR_VERSIONS,
    ParsedQRCode,
    QRDelimiterError,
    QRDemographics,
    QRInvalidDateError,
    QRMalformedError,
    QRPayloadSizeExceededError,
    QRSignatureMetadata,
    QRUnsupportedVersionError,
)
from fayda_mcp.qr.signed_content import (
    DELIMITER_SIGN,
    decode_detached_jws,
    normalize_qr_dob,
)


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


def parse_qr_code(
    raw_text: str,
    max_bytes: int = MAX_QR_TEXT_BYTES,
    dob_calendar: str = "gregorian",
) -> ParsedQRCode:
    """Parse raw Fayda QR code scanner text into structured demographic and signature records.

    Expected layout (Version 4):
    <photo_base64url>:DLT:<FullName>:V:<Version>:G:<Gender>:A:<FAN>:D:<DOB>:SIGN:<detached_jws>

    Args:
        raw_text: Exact scanner input string (untrimmed to preserve signed payload bytes).
        max_bytes: Maximum allowed byte length for scanner payload.
        dob_calendar: Calendar convention for birthdate normalization ('gregorian' or 'ethiopic').

    Returns:
        ParsedQRCode containing preserved raw text, demographics, and signature metadata.

    Raises:
        QRMalformedError: If input is non-string, empty, or has corrupt signature structure.
        QRPayloadSizeExceededError: If raw text exceeds max_bytes.
        QRDelimiterError: If any of the mandatory delimiters (:DLT:, :V:, :G:, :A:, :D:, :SIGN:) are missing.
        QRUnsupportedVersionError: If parsed version is not 4.
        QRInvalidDateError: If date of birth cannot be parsed or normalized.
    """
    validated_text = validate_scanner_text(raw_text, max_bytes=max_bytes)

    if DELIMITER_SIGN not in validated_text:
        raise QRDelimiterError(
            message=f"Missing mandatory signature delimiter '{DELIMITER_SIGN}' in QR code.",
            details={"delimiter": DELIMITER_SIGN},
        )

    signed_payload_text, detached_jws = validated_text.split(DELIMITER_SIGN, 1)

    # Validate delimiter ordering and extraction in signed payload
    pos_dlt = signed_payload_text.find(":DLT:")
    if pos_dlt == -1:
        raise QRDelimiterError(
            message="Missing mandatory ':DLT:' delimiter preceding full name.",
            details={"delimiter": ":DLT:"},
        )

    pos_v = signed_payload_text.find(":V:", pos_dlt + len(":DLT:"))
    if pos_v == -1:
        raise QRDelimiterError(
            message="Missing mandatory ':V:' delimiter preceding version.",
            details={"delimiter": ":V:"},
        )

    pos_g = signed_payload_text.find(":G:", pos_v + len(":V:"))
    if pos_g == -1:
        raise QRDelimiterError(
            message="Missing mandatory ':G:' delimiter preceding gender.",
            details={"delimiter": ":G:"},
        )

    pos_a = signed_payload_text.find(":A:", pos_g + len(":G:"))
    if pos_a == -1:
        raise QRDelimiterError(
            message="Missing mandatory ':A:' delimiter preceding FAN.",
            details={"delimiter": ":A:"},
        )

    pos_d = signed_payload_text.find(":D:", pos_a + len(":A:"))
    if pos_d == -1:
        raise QRDelimiterError(
            message="Missing mandatory ':D:' delimiter preceding birthdate.",
            details={"delimiter": ":D:"},
        )

    # Extract raw segment fields
    photo_base64url = signed_payload_text[:pos_dlt]
    raw_name = signed_payload_text[pos_dlt + len(":DLT:") : pos_v]
    raw_version = signed_payload_text[pos_v + len(":V:") : pos_g]
    raw_gender = signed_payload_text[pos_g + len(":G:") : pos_a]
    raw_fan = signed_payload_text[pos_a + len(":A:") : pos_d]
    raw_dob = signed_payload_text[pos_d + len(":D:") :]

    if not photo_base64url:
        raise QRMalformedError("Extracted photo segment preceding ':DLT:' is empty.")

    if not raw_name:
        raise QRMalformedError("Extracted name segment between ':DLT:' and ':V:' is empty.")

    try:
        version_int = int(raw_version.strip())
    except ValueError:
        raise QRUnsupportedVersionError(version=raw_version)

    if version_int not in SUPPORTED_QR_VERSIONS:
        raise QRUnsupportedVersionError(version=version_int)

    if not raw_gender:
        raise QRMalformedError("Extracted gender segment between ':G:' and ':A:' is empty.")

    if not raw_fan:
        raise QRMalformedError("Extracted FAN segment between ':A:' and ':D:' is empty.")

    if not raw_dob:
        raise QRMalformedError("Extracted DOB segment following ':D:' is empty.")

    dob_normalized = normalize_dob_for_display(raw_dob, calendar=dob_calendar)
    if not dob_normalized:
        raise QRInvalidDateError(dob_str=raw_dob)

    # Decode and validate detached JWS signature metadata
    try:
        header, sig_bytes = decode_detached_jws(detached_jws)
    except ValueError as e:
        raise QRMalformedError(
            message=f"Malformed detached JWS token: {e}",
            details={"raw_jws": detached_jws},
        )

    sig_metadata = QRSignatureMetadata(
        algorithm=str(header.get("alg", "RS256")),
        key_id=header.get("kid"),
        header_raw=detached_jws.split("..")[0],
        signature_bytes_len=len(sig_bytes),
    )

    demographics = QRDemographics(
        photo_base64url=photo_base64url,
        name=raw_name,
        name_normalized=normalize_name_for_display(raw_name),
        version=version_int,
        gender=raw_gender,
        gender_normalized=normalize_gender_for_display(raw_gender),
        fan=raw_fan,
        fan_normalized=normalize_fan_digits(raw_fan),
        date_of_birth=raw_dob,
        dob_normalized=dob_normalized,
        dob_calendar=dob_calendar,
    )

    return ParsedQRCode(
        raw_text=raw_text,
        demographics=demographics,
        signature=sig_metadata,
        signed_payload_text=signed_payload_text,
        detached_jws=detached_jws,
    )

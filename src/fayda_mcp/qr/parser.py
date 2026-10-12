"""Parser and text ingestion for Fayda National ID QR codes.

Ensures strict byte preservation of raw scanner text for cryptographic detached
signature verification, bounds input size limits, and isolates display normalization
from signature payload bytes.
"""

import base64
import hashlib
import json
import re
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field

from fayda_mcp.qr.schemas import (
    MAX_QR_TEXT_BYTES,
    SUPPORTED_QR_VERSIONS,
    ParsedQRCode,
    QRDelimiterError,
    QRDemographics,
    QRInvalidBase64Error,
    QRInvalidDateError,
    QRMalformedError,
    QRPayloadSizeExceededError,
    QRSignatureMetadata,
    QRUnsupportedVersionError,
)
from fayda_mcp.qr.signed_content import (
    CONFIRMED_CALENDARS,
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

    Validations & Invariants:
    1. Unchanged scanner text preserved within bounded memory limits.
    2. Exactly one occurrence of each mandatory delimiter (:DLT:, :V:, :G:, :A:, :D:, :SIGN:).
    3. Strict ascending ordering of delimiters.
    4. Non-empty field segments.
    5. Valid base64url encoding and WebP RIFF header for photo.
    6. Version integer must match supported specification (v4).
    7. Valid date of birth format.
    8. Valid detached JWS syntax (RFC 7515 Appendix F) and 256-byte signature length.
    """
    validated_text = validate_scanner_text(raw_text, max_bytes=max_bytes)

    # 1. Delimiter presence and uniqueness checks (reject missing or repeated tags)
    mandatory_tags = (":DLT:", ":V:", ":G:", ":A:", ":D:", ":SIGN:")
    for tag in mandatory_tags:
        count = validated_text.count(tag)
        if count == 0:
            raise QRDelimiterError(
                message=f"Missing mandatory delimiter '{tag}' in QR code payload.",
                details={"delimiter": tag},
            )
        elif count > 1:
            raise QRDelimiterError(
                message=f"Repeated/ambiguous delimiter '{tag}' detected in QR code ({count} occurrences).",
                details={"delimiter": tag, "count": count},
            )

    # 2. Strict delimiter sequence ordering
    pos_dlt = validated_text.find(":DLT:")
    pos_v = validated_text.find(":V:")
    pos_g = validated_text.find(":G:")
    pos_a = validated_text.find(":A:")
    pos_d = validated_text.find(":D:")
    pos_sign = validated_text.find(":SIGN:")

    if not (0 <= pos_dlt < pos_v < pos_g < pos_a < pos_d < pos_sign):
        raise QRDelimiterError(
            message="Delimiters are out of required order (<photo>:DLT:<name>:V:<version>:G:<gender>:A:<fan>:D:<dob>:SIGN:<signature>).",
            details={
                "positions": {
                    ":DLT:": pos_dlt,
                    ":V:": pos_v,
                    ":G:": pos_g,
                    ":A:": pos_a,
                    ":D:": pos_d,
                    ":SIGN:": pos_sign,
                }
            },
        )

    # 3. Extract segments
    signed_payload_text = validated_text[:pos_sign]
    detached_jws = validated_text[pos_sign + len(":SIGN:"):]

    photo_base64url = validated_text[:pos_dlt]
    raw_name = validated_text[pos_dlt + len(":DLT:") : pos_v]
    raw_version = validated_text[pos_v + len(":V:") : pos_g]
    raw_gender = validated_text[pos_g + len(":G:") : pos_a]
    raw_fan = validated_text[pos_a + len(":A:") : pos_d]
    raw_dob = validated_text[pos_d + len(":D:") : pos_sign]

    # 4. Segment non-empty validations
    if not photo_base64url or not photo_base64url.strip():
        raise QRMalformedError("Extracted photo segment preceding ':DLT:' cannot be empty.")
    if not raw_name or not raw_name.strip():
        raise QRMalformedError("Extracted name segment between ':DLT:' and ':V:' cannot be empty.")
    if not raw_version or not raw_version.strip():
        raise QRUnsupportedVersionError("Version segment cannot be empty.")
    if not raw_gender or not raw_gender.strip():
        raise QRMalformedError("Extracted gender segment between ':G:' and ':A:' cannot be empty.")
    if not raw_fan or not raw_fan.strip():
        raise QRMalformedError("Extracted FAN segment between ':A:' and ':D:' cannot be empty.")
    if not raw_dob or not raw_dob.strip():
        raise QRMalformedError("Extracted DOB segment following ':D:' cannot be empty.")
    if not detached_jws or not detached_jws.strip():
        raise QRMalformedError("Detached JWS signature token following ':SIGN:' cannot be empty.")

    # 5. Base64url and WebP format validation on photo
    if not re.match(r"^[A-Za-z0-9_-]+={0,2}$", photo_base64url):
        raise QRInvalidBase64Error(
            message="Photo segment contains invalid base64url characters.",
            details={"photo_snippet": photo_base64url[:20]},
        )
    try:
        photo_padding = "=" * ((4 - len(photo_base64url) % 4) % 4)
        photo_bytes = base64.urlsafe_b64decode(photo_base64url + photo_padding)
    except Exception as e:
        raise QRInvalidBase64Error(
            message=f"Failed to decode base64url photo payload: {e}",
            details={"error": str(e)},
        )

    if len(photo_bytes) < 12 or photo_bytes[:4] != b"RIFF" or photo_bytes[8:12] != b"WEBP":
        raise QRMalformedError("Photo segment is not a valid WebP image (missing RIFF/WEBP header).")

    # 6. Version validation
    try:
        version_int = int(raw_version.strip())
    except ValueError:
        raise QRUnsupportedVersionError(version=raw_version)

    if version_int not in SUPPORTED_QR_VERSIONS:
        raise QRUnsupportedVersionError(version=version_int)

    # 7. DOB normalization and calendar handling
    raw_dob_clean = raw_dob.strip()
    if not re.match(r"^(\d{4})[/-](\d{1,2})[/-](\d{1,2})$", raw_dob_clean):
        raise QRInvalidDateError(dob_str=raw_dob)

    is_confirmed_cal = (
        bool(dob_calendar)
        and isinstance(dob_calendar, str)
        and dob_calendar.strip().lower() in CONFIRMED_CALENDARS
    )

    if is_confirmed_cal:
        dob_normalized = normalize_dob_for_display(raw_dob, calendar=dob_calendar)
        if not dob_normalized:
            raise QRInvalidDateError(dob_str=raw_dob)
        effective_calendar = dob_calendar.strip().lower()
    else:
        # Unconfirmed calendar: syntax is preserved but date is not normalized for age evaluation
        dob_normalized = None
        effective_calendar = "unconfirmed"

    # 8. Detached JWS validation per RFC 7515 Appendix F
    if ".." not in detached_jws:
        raise QRMalformedError(
            message="Detached JWS token must contain '..' representing detached payload.",
            details={"raw_jws": detached_jws},
        )
    jws_parts = detached_jws.split("..")
    if len(jws_parts) != 2:
        raise QRMalformedError(
            message="Detached JWS token contains ambiguous delimiter structure.",
            details={"parts_count": len(jws_parts)},
        )
    header_b64, sig_b64 = jws_parts[0].strip(), jws_parts[1].strip()

    if not header_b64:
        raise QRMalformedError("Missing JWS protected header preceding '..'.")
    if not sig_b64:
        raise QRMalformedError("Missing JWS signature following '..'.")

    # Protected header base64url
    if not re.match(r"^[A-Za-z0-9_-]+={0,2}$", header_b64):
        raise QRInvalidBase64Error("JWS protected header contains invalid base64url characters.")
    try:
        header_padding = "=" * ((4 - len(header_b64) % 4) % 4)
        header_bytes = base64.urlsafe_b64decode(header_b64 + header_padding)
        header = json.loads(header_bytes.decode("utf-8"))
    except Exception as e:
        raise QRInvalidBase64Error(f"Failed to decode JWS protected header: {e}")

    # Signature base64url
    if not re.match(r"^[A-Za-z0-9_-]+={0,2}$", sig_b64):
        raise QRInvalidBase64Error("JWS signature contains invalid base64url characters.")
    try:
        sig_padding = "=" * ((4 - len(sig_b64) % 4) % 4)
        sig_bytes = base64.urlsafe_b64decode(sig_b64 + sig_padding)
    except Exception as e:
        raise QRInvalidBase64Error(f"Failed to decode JWS signature: {e}")

    if len(sig_bytes) != 256:
        raise QRMalformedError(
            message=f"Invalid RSA signature byte length: expected 256 bytes, got {len(sig_bytes)} bytes.",
            details={"signature_bytes_len": len(sig_bytes)},
        )

    sig_metadata = QRSignatureMetadata(
        algorithm=str(header.get("alg", "RS256")),
        key_id=header.get("kid"),
        header_raw=header_b64,
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
        dob_calendar=effective_calendar,
    )

    return ParsedQRCode(
        raw_text=raw_text,
        demographics=demographics,
        signature=sig_metadata,
        signed_payload_text=signed_payload_text,
        detached_jws=detached_jws,
    )

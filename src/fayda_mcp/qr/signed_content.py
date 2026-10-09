"""Fayda QR signed content extraction, signed-byte rules, and DOB calendar handling."""

import base64
import json
import re
from typing import Any, Dict, Optional, Tuple

from fayda_mcp.qr import TAG_SIGNATURE


DELIMITER_SIGN = f":{TAG_SIGNATURE}:"


def extract_signed_payload(qr_text: str) -> Tuple[str, str]:
    """Split raw QR text into (payload_text, detached_jws).

    The exact signed payload is the verbatim text preceding ':SIGN:'.
    The detached JWS string is the portion following ':SIGN:'.

    Raises:
        ValueError: If ':SIGN:' delimiter is absent or detached JWS is missing.
    """
    if not qr_text or not isinstance(qr_text, str):
        raise ValueError("QR text cannot be empty.")

    idx = qr_text.rfind(DELIMITER_SIGN)
    if idx == -1:
        raise ValueError(f"Missing signature delimiter '{DELIMITER_SIGN}' in QR payload.")

    payload_text = qr_text[:idx]
    detached_jws = qr_text[idx + len(DELIMITER_SIGN):].strip()

    if not payload_text:
        raise ValueError("Signed payload preceding ':SIGN:' cannot be empty.")
    if not detached_jws:
        raise ValueError("Detached JWS token following ':SIGN:' cannot be empty.")

    return payload_text, detached_jws


def decode_detached_jws(detached_jws: str) -> Tuple[Dict[str, Any], bytes]:
    """Parse and validate detached JWS per RFC 7515 Appendix F.

    Expected format: '<base64url_header>..<base64url_signature>' with empty payload.

    Returns:
        tuple[header_dict, raw_signature_bytes]

    Raises:
        ValueError: If format is malformed, payload is non-empty, or signature is invalid.
    """
    if ".." not in detached_jws:
        raise ValueError("Detached JWS must contain '..' representing an empty payload (RFC 7515 Appendix F).")

    parts = detached_jws.split("..")
    if len(parts) != 2:
        raise ValueError("Detached JWS contains unexpected delimiter structure.")

    header_b64, sig_b64 = parts[0].strip(), parts[1].strip()
    if not header_b64:
        raise ValueError("Missing JWS protected header.")
    if not sig_b64:
        raise ValueError("Missing JWS signature.")

    # Decode protected header
    try:
        header_padding = "=" * ((4 - len(header_b64) % 4) % 4)
        header_bytes = base64.urlsafe_b64decode(header_b64 + header_padding)
        header = json.loads(header_bytes.decode("utf-8"))
    except Exception as e:
        raise ValueError(f"Failed to decode JWS header: {e}")

    # Decode signature bytes
    try:
        sig_padding = "=" * ((4 - len(sig_b64) % 4) % 4)
        signature_bytes = base64.urlsafe_b64decode(sig_b64 + sig_padding)
    except Exception as e:
        raise ValueError(f"Failed to decode JWS signature: {e}")

    return header, signature_bytes


def build_jws_signing_input(header_b64: str, payload_bytes: bytes) -> bytes:
    """Construct RFC 7515 detached JWS signing input:

    ASCII(BASE64URL(UTF8(Protected Header))) || '.' || BASE64URL(Payload Bytes)
    """
    payload_b64 = base64.urlsafe_b64encode(payload_bytes).decode("ascii").rstrip("=")
    return f"{header_b64}.{payload_b64}".encode("ascii")


def normalize_qr_dob(raw_dob: str, calendar: str = "gregorian") -> Optional[str]:
    """Normalize QR DOB string (YYYY/MM/DD) into ISO YYYY-MM-DD.

    Respects confirmed calendar settings:
    - 'gregorian' (default): normalizes directly to Gregorian ISO 8601 YYYY-MM-DD.
    - 'ethiopic': converts from Ethiopian calendar (EC) using Fayda calendar converters.
    """
    if not raw_dob or not isinstance(raw_dob, str):
        return None

    cleaned = raw_dob.strip()
    match = re.match(r"^(\d{4})[/-](\d{1,2})[/-](\d{1,2})$", cleaned)
    if not match:
        return None

    year, month, day = int(match.group(1)), int(match.group(2)), int(match.group(3))

    if calendar.lower() in ("ethiopic", "ec"):
        from fayda_mcp.localization.calendars import normalize_dob_with_source
        return normalize_dob_with_source(f"{year:04d}-{month:02d}-{day:02d}", source_calendar="ethiopic")

    # Gregorian validation
    try:
        from datetime import date
        d = date(year, month, day)
        return d.isoformat()
    except ValueError:
        return None

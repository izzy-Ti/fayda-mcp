"""Unit tests for Task 07: Reject malformed input (missing/repeated tags, ambiguous delimiters, unsupported versions, invalid base64url)."""

import base64
import os
import pytest

from fayda_mcp.qr.parser import parse_qr_code
from fayda_mcp.qr.schemas import (
    QRDelimiterError,
    QRInvalidBase64Error,
    QRInvalidDateError,
    QRMalformedError,
    QRUnsupportedVersionError,
)


@pytest.fixture
def sample_qr_raw() -> str:
    fixtures_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "fixtures")
    with open(os.path.join(fixtures_dir, "sample_qr_v4.txt"), "r", encoding="utf-8") as f:
        return f.read().strip()


# ---------------------------------------------------------------------------
# 1. Missing Delimiters
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("missing_tag", [":DLT:", ":V:", ":G:", ":A:", ":D:", ":SIGN:"])
def test_reject_missing_delimiter(sample_qr_raw: str, missing_tag: str):
    """Verify that omitting any mandatory delimiter tag raises QRDelimiterError."""
    corrupted = sample_qr_raw.replace(missing_tag, "X", 1)
    with pytest.raises(QRDelimiterError) as exc_info:
        parse_qr_code(corrupted)

    assert exc_info.value.code == "qr_delimiter_error"
    assert "Missing mandatory delimiter" in exc_info.value.message


# ---------------------------------------------------------------------------
# 2. Repeated Delimiters / Ambiguous Inputs
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("repeated_tag", [":DLT:", ":V:", ":G:", ":A:", ":D:", ":SIGN:"])
def test_reject_repeated_delimiter(sample_qr_raw: str, repeated_tag: str):
    """Verify that duplicating any delimiter tag raises QRDelimiterError for ambiguous input."""
    corrupted = sample_qr_raw.replace(repeated_tag, f"{repeated_tag}extra{repeated_tag}", 1)
    with pytest.raises(QRDelimiterError) as exc_info:
        parse_qr_code(corrupted)

    assert exc_info.value.code == "qr_delimiter_error"
    assert "Repeated/ambiguous delimiter" in exc_info.value.message


def test_reject_out_of_order_delimiters(sample_qr_raw: str):
    """Verify that scrambled delimiter order raises QRDelimiterError."""
    # Swap :V: and :DLT:
    corrupted = sample_qr_raw.replace(":DLT:", "___TEMP___").replace(":V:", ":DLT:").replace("___TEMP___", ":V:")
    with pytest.raises(QRDelimiterError) as exc_info:
        parse_qr_code(corrupted)

    assert exc_info.value.code == "qr_delimiter_error"
    assert "Delimiters are out of required order" in exc_info.value.message


# ---------------------------------------------------------------------------
# 3. Unsupported / Malformed Versions
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad_version", ["1", "2", "3", "5", "10", "4.0", "v4", "XYZ", ""])
def test_reject_unsupported_or_invalid_version(sample_qr_raw: str, bad_version: str):
    """Verify that any version other than integer 4 raises QRUnsupportedVersionError."""
    corrupted = sample_qr_raw.replace(":V:4:G:", f":V:{bad_version}:G:")
    with pytest.raises(QRUnsupportedVersionError) as exc_info:
        parse_qr_code(corrupted)

    assert exc_info.value.code == "qr_unsupported_version"


# ---------------------------------------------------------------------------
# 4. Invalid Base64url (Photo & Signature)
# ---------------------------------------------------------------------------


def test_reject_photo_with_invalid_base64url_characters(sample_qr_raw: str):
    """Verify that non-base64url characters in photo segment raise QRInvalidBase64Error."""
    # Inject invalid characters like spaces or '+' which are not base64url
    corrupted = "INVALID+CHARS!@#" + sample_qr_raw[16:]
    with pytest.raises(QRInvalidBase64Error) as exc_info:
        parse_qr_code(corrupted)

    assert exc_info.value.code == "qr_invalid_base64"


def test_reject_photo_that_is_not_webp(sample_qr_raw: str):
    """Verify that photo which decodes to non-WebP bytes raises QRMalformedError."""
    fake_png = base64.urlsafe_b64encode(b"\x89PNG\r\n\x1a\n" + b"\x00" * 32).decode("ascii").rstrip("=")
    # Replace the photo segment preceding :DLT:
    rest = sample_qr_raw[sample_qr_raw.find(":DLT:"):]
    corrupted = fake_png + rest
    with pytest.raises(QRMalformedError) as exc_info:
        parse_qr_code(corrupted)

    assert "missing RIFF/WEBP header" in exc_info.value.message


def test_reject_signature_with_invalid_base64url_characters(sample_qr_raw: str):
    """Verify that signature segment containing invalid base64url characters is rejected."""
    payload, sig = sample_qr_raw.split(":SIGN:")
    header, s = sig.split("..")
    corrupted_sig = f"{header}..INVALID!CHARS+@#$"
    corrupted = f"{payload}:SIGN:{corrupted_sig}"
    with pytest.raises(QRInvalidBase64Error) as exc_info:
        parse_qr_code(corrupted)

    assert exc_info.value.code == "qr_invalid_base64"


def test_reject_signature_with_invalid_byte_length(sample_qr_raw: str):
    """Verify that signature with byte length other than 256 bytes is rejected."""
    payload, sig = sample_qr_raw.split(":SIGN:")
    header, _ = sig.split("..")
    short_sig_bytes = b"\x01" * 128  # 128 bytes instead of 256
    short_sig_b64 = base64.urlsafe_b64encode(short_sig_bytes).decode("ascii").rstrip("=")
    corrupted = f"{payload}:SIGN:{header}..{short_sig_b64}"
    with pytest.raises(QRMalformedError) as exc_info:
        parse_qr_code(corrupted)

    assert "expected 256 bytes" in exc_info.value.message


def test_reject_detached_jws_without_double_dot(sample_qr_raw: str):
    """Verify that detached JWS without '..' payload separator raises QRMalformedError."""
    payload, sig = sample_qr_raw.split(":SIGN:")
    corrupted_sig = sig.replace("..", ".")
    corrupted = f"{payload}:SIGN:{corrupted_sig}"
    with pytest.raises(QRMalformedError) as exc_info:
        parse_qr_code(corrupted)

    assert "must contain '..'" in exc_info.value.message


# ---------------------------------------------------------------------------
# 5. Empty Segments
# ---------------------------------------------------------------------------


def test_reject_empty_name_segment(sample_qr_raw: str):
    """Verify that empty name segment raises QRMalformedError."""
    corrupted = sample_qr_raw.replace(":DLT:Israel Ashenafi Bekele :V:", ":DLT::V:")
    with pytest.raises(QRMalformedError) as exc_info:
        parse_qr_code(corrupted)

    assert "name segment" in exc_info.value.message


def test_reject_empty_fan_segment(sample_qr_raw: str):
    """Verify that empty FAN segment raises QRMalformedError."""
    corrupted = sample_qr_raw.replace(":A:6042  3061  7816  8402:D:", ":A::D:")
    with pytest.raises(QRMalformedError) as exc_info:
        parse_qr_code(corrupted)

    assert "FAN segment" in exc_info.value.message


def test_reject_empty_dob_segment(sample_qr_raw: str):
    """Verify that empty DOB segment raises QRMalformedError."""
    corrupted = sample_qr_raw.replace(":D:2004/12/28:SIGN:", ":D::SIGN:")
    with pytest.raises(QRMalformedError) as exc_info:
        parse_qr_code(corrupted)

    assert "DOB segment" in exc_info.value.message


def test_reject_invalid_dob_format(sample_qr_raw: str):
    """Verify that malformed DOB string raises QRInvalidDateError."""
    corrupted = sample_qr_raw.replace(":D:2004/12/28:SIGN:", ":D:2004-99-99:SIGN:")
    with pytest.raises(QRInvalidDateError) as exc_info:
        parse_qr_code(corrupted)

    assert exc_info.value.code == "qr_invalid_date"

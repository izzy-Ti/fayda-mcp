"""Unit tests for Task 05: Preserve scanner text, bounded size limits, and separate display normalization."""

import hashlib
import os
import pytest

from fayda_mcp.qr.parser import (
    ScannerInput,
    format_fan_display,
    ingest_scanner_text,
    normalize_dob_for_display,
    normalize_fan_digits,
    normalize_gender_for_display,
    normalize_name_for_display,
    validate_scanner_text,
)
from fayda_mcp.qr.schemas import (
    MAX_QR_TEXT_BYTES,
    QRMalformedError,
    QRPayloadSizeExceededError,
)


@pytest.fixture
def sample_qr_raw() -> str:
    fixtures_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "fixtures")
    with open(os.path.join(fixtures_dir, "sample_qr_v4.txt"), "r", encoding="utf-8") as f:
        return f.read().strip()


def test_scanner_text_preserved_exactly_without_alteration(sample_qr_raw: str):
    """Verify that validate_scanner_text and ingest_scanner_text preserve the exact input string."""
    validated = validate_scanner_text(sample_qr_raw)
    assert validated == sample_qr_raw
    assert id(validated) != 0

    ingested = ingest_scanner_text(sample_qr_raw)
    assert isinstance(ingested, ScannerInput)
    assert ingested.raw_text == sample_qr_raw
    assert ingested.size_bytes == len(sample_qr_raw.encode("utf-8"))
    assert ingested.sha256_digest == hashlib.sha256(sample_qr_raw.encode("utf-8")).hexdigest()


def test_scanner_text_with_internal_whitespace_preserved():
    """Verify that internal spacing (e.g. FAN formatting '6042  3061') is strictly preserved."""
    test_raw = "UklGR...:DLT:Israel Ashenafi Bekele :V:4:G:M:A:6042  3061  7816  8402:D:2004/12/28:SIGN:header..sig"
    validated = validate_scanner_text(test_raw)
    assert "Israel Ashenafi Bekele " in validated
    assert "6042  3061  7816  8402" in validated
    assert validated == test_raw


def test_scanner_text_bounded_size_limit_rejection():
    """Verify that payloads exceeding the bounded size limit are rejected with QRPayloadSizeExceededError."""
    oversized = "A" * (MAX_QR_TEXT_BYTES + 1)
    with pytest.raises(QRPayloadSizeExceededError) as exc_info:
        validate_scanner_text(oversized)

    assert exc_info.value.code == "qr_payload_size_exceeded"
    assert exc_info.value.details["size_bytes"] == MAX_QR_TEXT_BYTES + 1
    assert exc_info.value.details["max_bytes"] == MAX_QR_TEXT_BYTES


def test_scanner_text_custom_size_limit():
    """Verify custom size limit bounds."""
    text = "A" * 50
    with pytest.raises(QRPayloadSizeExceededError):
        validate_scanner_text(text, max_bytes=40)


def test_empty_or_whitespace_scanner_text_rejected():
    """Verify that empty or whitespace-only scanner text is rejected."""
    with pytest.raises(QRMalformedError) as exc_empty:
        validate_scanner_text("")
    assert exc_empty.value.code == "qr_malformed_input"

    with pytest.raises(QRMalformedError) as exc_ws:
        validate_scanner_text("   \n\t  ")
    assert exc_ws.value.code == "qr_malformed_input"


def test_non_string_scanner_text_rejected():
    """Verify that non-string inputs are rejected."""
    with pytest.raises(QRMalformedError):
        validate_scanner_text(12345)  # type: ignore


def test_display_normalization_is_isolated_from_raw():
    """Verify that display normalization utilities do not mutate the raw preserved values."""
    raw_fan = "6042  3061  7816  8402"
    normalized_fan = normalize_fan_digits(raw_fan)
    assert normalized_fan == "6042306178168402"
    assert format_fan_display(normalized_fan) == "6042 3061 7816 8402"
    # Ensure raw_fan remained unmodified
    assert raw_fan == "6042  3061  7816  8402"

    raw_name = "   Israel   Ashenafi   Bekele   "
    display_name = normalize_name_for_display(raw_name)
    assert display_name == "Israel Ashenafi Bekele"
    assert raw_name == "   Israel   Ashenafi   Bekele   "

    raw_gender = "  m "
    assert normalize_gender_for_display(raw_gender) == "M"
    assert raw_gender == "  m "

    raw_dob = "2004/12/28"
    assert normalize_dob_for_display(raw_dob) == "2004-12-28"
    assert raw_dob == "2004/12/28"

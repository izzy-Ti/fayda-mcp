"""Unit tests for Task 06: Parse all fields from Version-4 QR codes in qr/parser.py."""

import base64
import os
import pytest

from fayda_mcp.qr.parser import parse_qr_code
from fayda_mcp.qr.schemas import (
    ParsedQRCode,
    QRDemographics,
    QRSignatureMetadata,
)


@pytest.fixture
def fixtures_dir() -> str:
    return os.path.join(os.path.dirname(os.path.dirname(__file__)), "fixtures")


@pytest.fixture
def sample_qr_raw(fixtures_dir: str) -> str:
    with open(os.path.join(fixtures_dir, "sample_qr_v4.txt"), "r", encoding="utf-8") as f:
        return f.read().strip()


@pytest.fixture
def synthetic_qr_raw(fixtures_dir: str) -> str:
    with open(os.path.join(fixtures_dir, "synthetic_authorized_qr_v4.txt"), "r", encoding="utf-8") as f:
        return f.read().strip()


def test_parse_all_fields_from_production_sample(sample_qr_raw: str):
    """Verify complete field extraction from real-world scanned Version-4 QR card."""
    parsed = parse_qr_code(sample_qr_raw)

    assert isinstance(parsed, ParsedQRCode)
    assert parsed.raw_text == sample_qr_raw

    # 1. Photo extraction
    photo = parsed.demographics.photo_base64url
    assert photo.startswith("UklGR")
    # Must be valid WebP header (RIFF....WEBP)
    photo_padding = "=" * ((4 - len(photo) % 4) % 4)
    photo_bytes = base64.urlsafe_b64decode(photo + photo_padding)
    assert photo_bytes[:4] == b"RIFF"
    assert photo_bytes[8:12] == b"WEBP"

    # 2. Name extraction (preserves raw whitespace while providing clean display normalization)
    assert parsed.demographics.name == "Israel Ashenafi Bekele "
    assert parsed.demographics.name_normalized == "Israel Ashenafi Bekele"

    # 3. Version extraction
    assert parsed.demographics.version == 4

    # 4. Gender extraction
    assert parsed.demographics.gender == "M"
    assert parsed.demographics.gender_normalized == "M"

    # 5. FAN extraction (raw spaced vs normalized digits)
    assert parsed.demographics.fan == "6042  3061  7816  8402"
    assert parsed.demographics.fan_normalized == "6042306178168402"

    # 6. DOB extraction (raw printed vs ISO 8601 normalized)
    assert parsed.demographics.date_of_birth == "2004/12/28"
    assert parsed.demographics.dob_normalized == "2004-12-28"
    assert parsed.demographics.dob_calendar == "gregorian"

    # 7. Signature metadata extraction
    assert parsed.signature.algorithm == "RS256"
    assert parsed.signature.header_raw == "eyJhbGciOiJSUzI1NiJ9"
    assert parsed.signature.signature_bytes_len == 256
    assert parsed.signature.key_id is None

    # Signed payload separation
    assert parsed.signed_payload_text == sample_qr_raw.split(":SIGN:")[0]
    assert parsed.detached_jws == sample_qr_raw.split(":SIGN:")[1]


def test_parse_all_fields_from_synthetic_fixture(synthetic_qr_raw: str):
    """Verify parsing of authorized synthetic fixture."""
    parsed = parse_qr_code(synthetic_qr_raw)

    assert parsed.demographics.name == "Abebe Bikila"
    assert parsed.demographics.name_normalized == "Abebe Bikila"
    assert parsed.demographics.version == 4
    assert parsed.demographics.gender == "M"
    assert parsed.demographics.fan == "1234  5678  9012  3456"
    assert parsed.demographics.fan_normalized == "1234567890123456"
    assert parsed.demographics.date_of_birth == "1990/01/01"
    assert parsed.demographics.dob_normalized == "1990-01-01"
    assert parsed.signature.algorithm == "RS256"
    assert parsed.signature.signature_bytes_len == 256


def test_parse_with_ethiopic_calendar(synthetic_qr_raw: str):
    """Verify parsing and birthdate normalization when dob_calendar='ethiopic' is specified."""
    parsed = parse_qr_code(synthetic_qr_raw, dob_calendar="ethiopic")
    assert parsed.demographics.dob_calendar == "ethiopic"
    # Ethiopic 1998-07-15 converts to Gregorian representation
    assert parsed.demographics.dob_normalized is not None
    assert parsed.demographics.dob_normalized != "1998-07-15"

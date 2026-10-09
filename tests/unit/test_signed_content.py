"""Unit tests for Task 02: Confirm signed content, signed-byte rules, field coverage, and DOB calendar."""

import os
import pytest

from fayda_mcp.qr import (
    build_jws_signing_input,
    decode_detached_jws,
    extract_signed_payload,
    normalize_qr_dob,
)


@pytest.fixture
def sample_qr_text() -> str:
    fixture_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "fixtures",
        "sample_qr_v4.txt",
    )
    with open(fixture_path, "r", encoding="utf-8") as f:
        return f.read().strip()


def test_extract_signed_payload_rules(sample_qr_text: str):
    """Verify exact signed-byte rules on official Version-4 QR sample fixture."""
    payload_text, detached_jws = extract_signed_payload(sample_qr_text)

    # 1. Exact signed byte envelope: verbatim text preceding :SIGN:
    assert len(payload_text) == 712
    assert payload_text == sample_qr_text[:sample_qr_text.rfind(":SIGN:")]

    # 2. Field coverage within the signed envelope
    assert ":DLT:" in payload_text
    assert "Israel Ashenafi Bekele " in payload_text
    assert ":V:4" in payload_text
    assert ":G:M" in payload_text
    assert ":A:6042  3061  7816  8402" in payload_text
    assert ":D:2004/12/28" in payload_text
    assert payload_text.startswith("UklGRtYBAABXRUJQVlA4")  # Photo segment included

    # 3. Detached signature excluded from payload
    assert ":SIGN:" not in payload_text


def test_decode_detached_jws(sample_qr_text: str):
    """Verify detached JWS token decoding and header per RFC 7515 Appendix F."""
    _, detached_jws = extract_signed_payload(sample_qr_text)

    assert ".." in detached_jws
    header, sig_bytes = decode_detached_jws(detached_jws)

    # Header specifies RS256 algorithm and no kid
    assert header == {"alg": "RS256"}
    # 2048-bit RSA signature (256 bytes)
    assert len(sig_bytes) == 256


def test_jws_signing_input_construction(sample_qr_text: str):
    """Verify RFC 7515 signing input construction for detached payload."""
    payload_text, detached_jws = extract_signed_payload(sample_qr_text)
    header_b64 = detached_jws.split("..")[0]

    signing_input = build_jws_signing_input(header_b64, payload_text.encode("utf-8"))

    assert signing_input.startswith(b"eyJhbGciOiJSUzI1NiJ9.")
    assert len(signing_input) > len(payload_text)

    # Tampering test: Changing 1 byte in payload alters the signing input
    tampered_payload = (payload_text[:-1] + "9").encode("utf-8")
    tampered_input = build_jws_signing_input(header_b64, tampered_payload)
    assert tampered_input != signing_input


def test_signed_payload_error_cases():
    """Verify error cases for missing or malformed signature delimiters."""
    with pytest.raises(ValueError, match="QR text cannot be empty"):
        extract_signed_payload("")

    with pytest.raises(ValueError, match="Missing signature delimiter"):
        extract_signed_payload("UklGR...:DLT:Alice:V:4")

    with pytest.raises(ValueError, match="Signed payload.*cannot be empty"):
        extract_signed_payload(":SIGN:eyJhbGciOiJSUzI1NiJ9..sig")

    with pytest.raises(ValueError, match="Detached JWS token.*cannot be empty"):
        extract_signed_payload("Payload:SIGN:  ")


def test_qr_dob_normalization():
    """Verify DOB normalization rules for Gregorian and Ethiopic calendars."""
    # Gregorian ISO normalization
    assert normalize_qr_dob("2004/12/28", calendar="gregorian") == "2004-12-28"
    assert normalize_qr_dob("1995/04/12", calendar="gregorian") == "1995-04-12"

    # Malformed DOB
    assert normalize_qr_dob("invalid-dob") is None
    assert normalize_qr_dob("2004/13/40") is None  # Invalid calendar day/month

    # Ethiopic calendar conversion
    eth_normalized = normalize_qr_dob("2004/12/28", calendar="ethiopic")
    assert eth_normalized is not None
    assert len(eth_normalized) == 10  # Normalized to ISO YYYY-MM-DD

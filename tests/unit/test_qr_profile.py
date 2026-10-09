"""Unit tests for Task 01: Confirm the QR profile."""

from fayda_mcp.qr import (
    DEFAULT_QR_VERSION,
    QR_DELIMITERS,
    SUPPORTED_QR_VERSIONS,
    TAG_DOB,
    TAG_FAN,
    TAG_GENDER,
    TAG_NAME_INTRO,
    TAG_SIGNATURE,
    TAG_VERSION,
)


def test_qr_profile_constants():
    """Verify QR profile Version-4 delimiters and supported versions."""
    assert 4 in SUPPORTED_QR_VERSIONS
    assert DEFAULT_QR_VERSION == 4

    assert TAG_NAME_INTRO == "DLT"
    assert TAG_VERSION == "V"
    assert TAG_GENDER == "G"
    assert TAG_FAN == "A"
    assert TAG_DOB == "D"
    assert TAG_SIGNATURE == "SIGN"

    expected_delimiters = ("DLT", "V", "G", "A", "D", "SIGN")
    assert QR_DELIMITERS == expected_delimiters

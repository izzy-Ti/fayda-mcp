"""Unit tests for Task 06: Deterministic matching, name normalization, and explicit calendar comparison."""

import unicodedata
import pytest

from fayda_mcp.matching.normalization import (
    REASON_DOB_MISMATCH,
    REASON_INVALID_DATE_FORMAT,
    REASON_NAME_MISMATCH,
    REASON_PARTIAL_DOB_UNAVAILABLE,
    REASON_PROVIDER_CLAIM_UNAVAILABLE,
    compare_dates,
    compare_names,
    evaluate_details_matching,
    is_partial_date,
    normalize_and_convert_date,
    normalize_name,
)
from fayda_mcp.matching.schemas import (
    MATCH_FIELD_DATE_OF_BIRTH,
    MATCH_FIELD_FULL_NAME,
    ExpectedDetails,
)


# ===========================================================================
# 1. Name Normalization Tests (NFC, Case-Folding, Whitespace, Script, Order)
# ===========================================================================


def test_normalize_name_nfc_composition():
    """Names with decomposed Unicode characters are normalized to NFC."""
    # NFD: 'e' followed by combining acute accent
    decomposed = "Abe\u0301be\u0301 Bikila"
    # NFC: precomposed characters
    precomposed = "Abébé Bikila"

    assert normalize_name(decomposed) == normalize_name(precomposed)
    assert normalize_name(decomposed) == "abébé bikila"


def test_normalize_name_case_folding():
    """Case-folding handles standard uppercase, lowercase, and full Unicode casefold."""
    assert normalize_name("ABEBE BIKILA") == "abebe bikila"
    assert normalize_name("aBeBe BiKiLa") == "abebe bikila"
    assert normalize_name("DERARTU TULU") == "derartu tulu"


def test_normalize_name_whitespace_collapsing():
    """Whitespace (leading, trailing, multiple spaces, tabs, newlines) is collapsed into single space."""
    raw = "   Abebe \t\n  Bikila   "
    assert normalize_name(raw) == "abebe bikila"


def test_normalize_name_script_preservation():
    """Amharic/Ge'ez text is preserved in original script without automatic transliteration."""
    geez_name = "አበበ ቢቂላ"
    assert normalize_name(geez_name) == "አበበ ቢቂላ"
    # Ge'ez and Latin do not cross-transliterate
    assert normalize_name("Abebe Bikila") != normalize_name(geez_name)


def test_normalize_name_order_preservation():
    """Token order is strictly preserved; permutations do not match."""
    norm1 = normalize_name("Abebe Bikila")
    norm2 = normalize_name("Bikila Abebe")
    assert norm1 != norm2


def test_compare_names_deterministic_outcomes():
    """compare_names returns True for matching names and False with reason for mismatches."""
    # Exact match with varying case and spaces
    outcome, reason = compare_names("Abebe Bikila", "  abebe   BIKILA ")
    assert outcome is True
    assert reason is None

    # Transposed order fails deterministically
    outcome, reason = compare_names("Abebe Bikila", "Bikila Abebe")
    assert outcome is False
    assert reason == REASON_NAME_MISMATCH

    # Different spelling fails deterministically
    outcome, reason = compare_names("Abebe Bikila", "Abebe Bekele")
    assert outcome is False
    assert reason == REASON_NAME_MISMATCH

    # Script mismatch fails deterministically
    outcome, reason = compare_names("Abebe Bikila", "አበበ ቢቂላ")
    assert outcome is False
    assert reason == REASON_NAME_MISMATCH

    # Missing provider name yields unavailable
    outcome, reason = compare_names("Abebe Bikila", None)
    assert outcome is None
    assert reason == REASON_PROVIDER_CLAIM_UNAVAILABLE


# ===========================================================================
# 2. Date Comparison & Calendar Normalization Tests
# ===========================================================================


def test_is_partial_date_detection():
    """Detects partial or incomplete dates."""
    assert is_partial_date("1995") is True
    assert is_partial_date("1995-04") is True
    assert is_partial_date("1995/04") is True
    assert is_partial_date("0000-04-12") is True
    assert is_partial_date("1995-00-12") is True
    assert is_partial_date("1995-04-00") is True

    assert is_partial_date("1995-04-12") is False
    assert is_partial_date("1995/04/12") is False


def test_compare_dates_gregorian_exact():
    """Compares Gregorian dates regardless of slash or hyphen format."""
    outcome, reason = compare_dates("1990/05/12", "1990-05-12")
    assert outcome is True
    assert reason is None

    outcome, reason = compare_dates("1990-05-12", "1990-05-13")
    assert outcome is False
    assert reason == REASON_DOB_MISMATCH


def test_compare_dates_ethiopic_to_gregorian():
    """Explicitly converts Ethiopic birthdate to Gregorian for deterministic comparison."""
    # Ethiopic 1987-08-04 converts to Gregorian 1995-04-12
    outcome, reason = compare_dates(
        expected_dob="1987-08-04",
        provider_dob="1995-04-12",
        expected_calendar="ethiopic",
        provider_calendar="gregorian",
    )
    assert outcome is True
    assert reason is None

    # Ethiopic 1987-08-05 does NOT match Gregorian 1995-04-12
    outcome, reason = compare_dates(
        expected_dob="1987-08-05",
        provider_dob="1995-04-12",
        expected_calendar="ethiopic",
        provider_calendar="gregorian",
    )
    assert outcome is False
    assert reason == REASON_DOB_MISMATCH


def test_compare_dates_partial_date_unavailable():
    """Partial DOB strictly yields unavailable outcome."""
    outcome, reason = compare_dates("1990/05/12", "1990")
    assert outcome is None
    assert reason == REASON_PARTIAL_DOB_UNAVAILABLE

    outcome, reason = compare_dates("1990/05/12", "1990-05")
    assert outcome is None
    assert reason == REASON_PARTIAL_DOB_UNAVAILABLE


def test_compare_dates_invalid_date_format():
    """Invalid or unparseable date formats yield invalid_date_format reason."""
    outcome, reason = compare_dates("1990/05/12", "not-a-date")
    assert outcome is None
    assert reason == REASON_INVALID_DATE_FORMAT

    # Invalid Gregorian day (Feb 30)
    outcome, reason = compare_dates("1990/05/12", "1990-02-30")
    assert outcome is None
    assert reason == REASON_INVALID_DATE_FORMAT


# ===========================================================================
# 3. Complete evaluate_details_matching Integration Tests
# ===========================================================================


def test_evaluate_details_matching_both_match():
    """Both full_name and date_of_birth match -> overall 'matched'."""
    expected = ExpectedDetails(
        full_name="Derartu Tulu",
        date_of_birth="1972/03/21",
    )
    claims = {
        "sub": "citizen_1",
        "name": "derartu   TULU",
        "birthdate": "1972-03-21",
    }
    matches, reasons, status = evaluate_details_matching(expected, claims)

    assert matches[MATCH_FIELD_FULL_NAME] is True
    assert matches[MATCH_FIELD_DATE_OF_BIRTH] is True
    assert status == "matched"
    assert reasons == {}


def test_evaluate_details_matching_name_mismatch():
    """Name differs -> overall 'mismatched'."""
    expected = ExpectedDetails(
        full_name="Derartu Tulu",
        date_of_birth="1972/03/21",
    )
    claims = {
        "sub": "citizen_1",
        "name": "Fatuma Roba",
        "birthdate": "1972-03-21",
    }
    matches, reasons, status = evaluate_details_matching(expected, claims)

    assert matches[MATCH_FIELD_FULL_NAME] is False
    assert matches[MATCH_FIELD_DATE_OF_BIRTH] is True
    assert status == "mismatched"
    assert reasons[MATCH_FIELD_FULL_NAME] == REASON_NAME_MISMATCH


def test_evaluate_details_matching_missing_claim_unavailable():
    """When a required claim is missing from provider, status is 'unavailable'."""
    expected = ExpectedDetails(
        full_name="Haile Gebrselassie",
        date_of_birth="1973/04/18",
        required_fields=["full_name", "date_of_birth"],
    )
    claims = {
        "sub": "citizen_haile",
        "name": "Haile Gebrselassie",
        # birthdate is missing!
    }
    matches, reasons, status = evaluate_details_matching(expected, claims)

    assert matches[MATCH_FIELD_FULL_NAME] is True
    assert matches[MATCH_FIELD_DATE_OF_BIRTH] is None
    assert status == "unavailable"
    assert reasons[MATCH_FIELD_DATE_OF_BIRTH] == REASON_PROVIDER_CLAIM_UNAVAILABLE


def test_evaluate_details_matching_cross_calendar_match():
    """Expected Ethiopic DOB matches Gregorian provider birthdate."""
    expected = ExpectedDetails(
        full_name="Abebe Bikila",
        date_of_birth="1987-08-04",
        dob_calendar="ethiopic",
    )
    claims = {
        "sub": "citizen_abebe",
        "name": "ABEBE BIKILA",
        "birthdate": "1995-04-12",
    }
    matches, reasons, status = evaluate_details_matching(expected, claims)

    assert matches[MATCH_FIELD_FULL_NAME] is True
    assert matches[MATCH_FIELD_DATE_OF_BIRTH] is True
    assert status == "matched"

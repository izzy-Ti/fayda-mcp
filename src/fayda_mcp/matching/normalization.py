"""Deterministic comparison and normalization rules for citizen identity details.

Per guide4 specification:
- Normalize names with Unicode NFC, case-folding, and collapsed whitespace.
- Strictly preserve script (no automatic transliteration).
- Strictly preserve name order (no permutation or word reordering).
- Compare full dates after explicit calendar normalization (Gregorian vs Ethiopic).
- No fuzzy/LLM matching, phonetic guessing, or guessed calendar systems.
- Partial DOB is strictly unavailable in details-v1.
"""

from datetime import datetime, timezone
import re
from typing import Any, Dict, List, Literal, Optional, Sequence, Tuple
import unicodedata

from fayda_mcp.localization.calendars import (
    CalendarError,
    GregorianDate,
    parse_date_explicit,
)
from fayda_mcp.matching.claims import extract_approved_matching_claims
from fayda_mcp.matching.schemas import (
    MATCH_FIELD_DATE_OF_BIRTH,
    MATCH_FIELD_FULL_NAME,
    ExpectedDetails,
    FieldMatchOutcome,
    compute_overall_matching_status,
)

# Safe Reason Codes
REASON_NAME_MISMATCH = "name_mismatch"
REASON_DOB_MISMATCH = "dob_mismatch"
REASON_PARTIAL_DOB_UNAVAILABLE = "partial_dob_unavailable"
REASON_INVALID_DATE_FORMAT = "invalid_date_format"
REASON_PROVIDER_CLAIM_UNAVAILABLE = "provider_claim_unavailable"
REASON_UNSUPPORTED_CALENDAR = "unsupported_calendar"


def normalize_name(name: Optional[str]) -> Optional[str]:
    """Normalize a name using Unicode NFC, full case-folding, and collapsed whitespace.

    Preserves original script (no transliteration) and token sequence (no reordering).

    Args:
        name: Raw citizen name string.

    Returns:
        Canonical string or None if input is empty/None.
    """
    if name is None:
        return None

    s = str(name).strip()
    if not s:
        return None

    # 1. Unicode NFC canonical decomposition followed by canonical composition
    nfc_str = unicodedata.normalize("NFC", s)

    # 2. Case-folding (stronger and more comprehensive than lower() for Unicode)
    folded = nfc_str.casefold()

    # 3. Collapse multiple whitespace characters into a single space
    collapsed = re.sub(r"\s+", " ", folded).strip()

    return collapsed or None


def compare_names(
    expected_name: Optional[str],
    provider_name: Optional[str],
) -> Tuple[FieldMatchOutcome, Optional[str]]:
    """Deterministically compare expected and provider names.

    Rules:
    - If either is missing or empty: returns (None, reason).
    - If normalized names match exactly: returns (True, None).
    - If normalized names differ (different spelling, transposed order, or different script): returns (False, 'name_mismatch').

    Returns:
        Tuple of (FieldMatchOutcome, Optional[reason_code])
    """
    if not provider_name or not str(provider_name).strip():
        return None, REASON_PROVIDER_CLAIM_UNAVAILABLE

    if not expected_name or not str(expected_name).strip():
        return None, "missing_expected_name"

    norm_exp = normalize_name(expected_name)
    norm_prov = normalize_name(provider_name)

    if norm_exp is None or norm_prov is None:
        return None, REASON_PROVIDER_CLAIM_UNAVAILABLE

    if norm_exp == norm_prov:
        return True, None

    return False, REASON_NAME_MISMATCH


def is_partial_date(date_str: str) -> bool:
    """Check if date string represents a partial date (e.g. YYYY, YYYY-MM, 0000-MM-DD).

    Partial DOB is strictly disallowed and unavailable in details-v1.
    """
    cleaned = str(date_str).strip()
    # Match YYYY alone (4 digits)
    if re.fullmatch(r"\d{4}", cleaned):
        return True
    # Match YYYY-MM, YYYY/MM, MM-YYYY, MM/YYYY without day
    if re.fullmatch(r"\d{4}[-/.]\d{1,2}", cleaned) or re.fullmatch(r"\d{1,2}[-/.]\d{4}", cleaned):
        return True
    # Match wildcard zeroed parts (e.g., 0000-05-12, 1990-00-00, 1990-05-00)
    m = re.fullmatch(r"(\d{1,4})[-/.](\d{1,2})[-/.](\d{1,4})", cleaned)
    if m:
        p1, p2, p3 = int(m.group(1)), int(m.group(2)), int(m.group(3))
        if p1 == 0 or p2 == 0 or p3 == 0:
            return True

    return False


def normalize_and_convert_date(
    date_str: Optional[str],
    calendar: str = "gregorian",
) -> Tuple[Optional[GregorianDate], Optional[str]]:
    """Parse and normalize date to an absolute GregorianDate.

    Requires explicit calendar convention ('gregorian' or 'ethiopian'/'ethiopic').
    Rejects partial or ambiguous dates.

    Returns:
        Tuple of (Optional[GregorianDate], Optional[reason_code])
    """
    if not date_str or not str(date_str).strip():
        return None, REASON_PROVIDER_CLAIM_UNAVAILABLE

    cleaned = str(date_str).strip()

    if is_partial_date(cleaned):
        return None, REASON_PARTIAL_DOB_UNAVAILABLE

    cal_clean = str(calendar).lower().strip()
    if cal_clean in ("ethiopian", "ethiopic", "ec"):
        cal_type = "ethiopic"
    elif cal_clean in ("gregorian", "gc"):
        cal_type = "gregorian"
    else:
        return None, REASON_UNSUPPORTED_CALENDAR

    try:
        parsed = parse_date_explicit(cleaned, cal_type)
        if cal_type == "ethiopic":
            greg_date = parsed.to_gregorian()
        else:
            greg_date = parsed  # already GregorianDate
        return greg_date, None
    except CalendarError:
        return None, REASON_INVALID_DATE_FORMAT
    except Exception:
        return None, REASON_INVALID_DATE_FORMAT


def compare_dates(
    expected_dob: Optional[str],
    provider_dob: Optional[str],
    expected_calendar: str = "gregorian",
    provider_calendar: str = "gregorian",
) -> Tuple[FieldMatchOutcome, Optional[str]]:
    """Deterministically compare full birthdates after explicit calendar normalization.

    Returns:
        Tuple of (FieldMatchOutcome, Optional[reason_code])
    """
    if not provider_dob or not str(provider_dob).strip():
        return None, REASON_PROVIDER_CLAIM_UNAVAILABLE

    if not expected_dob or not str(expected_dob).strip():
        return None, "missing_expected_dob"

    exp_date, exp_err = normalize_and_convert_date(expected_dob, expected_calendar)
    if exp_err:
        return None, exp_err

    prov_date, prov_err = normalize_and_convert_date(provider_dob, provider_calendar)
    if prov_err:
        return None, prov_err

    if exp_date == prov_date:
        return True, None

    return False, REASON_DOB_MISMATCH


def evaluate_details_matching(
    expected_details: ExpectedDetails,
    claims: Dict[str, Any],
    provider_dob_calendar: str = "gregorian",
) -> Tuple[Dict[str, FieldMatchOutcome], Dict[str, str], Literal["matched", "mismatched", "unavailable"]]:
    """Execute complete deterministic comparison between expectations and provider claims.

    Args:
        expected_details: ExpectedDetails specification.
        claims: Normalized claims from authorized provider token/userinfo.
        provider_dob_calendar: Calendar convention for provider's DOB claim ('gregorian' or 'ethiopic').

    Returns:
        Tuple of:
            - matches: Dict mapping field names to tri-state outcomes (True, False, None)
            - reasons: Dict mapping field names to safe reason codes if mismatch or unavailable
            - overall_status: Overall outcome ('matched', 'mismatched', or 'unavailable')
    """
    extracted_claims, unavailable_reasons = extract_approved_matching_claims(
        claims=claims,
        expected_details=expected_details,
    )

    matches: Dict[str, FieldMatchOutcome] = {}
    reasons: Dict[str, str] = dict(unavailable_reasons)

    # 1. Full name comparison if expected
    if expected_details.full_name is not None and expected_details.full_name.strip():
        prov_name = extracted_claims.get(MATCH_FIELD_FULL_NAME)
        outcome, reason = compare_names(expected_details.full_name, prov_name)
        matches[MATCH_FIELD_FULL_NAME] = outcome
        if reason:
            reasons[MATCH_FIELD_FULL_NAME] = reason

    # 2. Date of birth comparison if expected
    if expected_details.date_of_birth is not None and expected_details.date_of_birth.strip():
        prov_dob = extracted_claims.get(MATCH_FIELD_DATE_OF_BIRTH)
        outcome, reason = compare_dates(
            expected_dob=expected_details.date_of_birth,
            provider_dob=prov_dob,
            expected_calendar=expected_details.dob_calendar or "gregorian",
            provider_calendar=provider_dob_calendar,
        )
        matches[MATCH_FIELD_DATE_OF_BIRTH] = outcome
        if reason:
            reasons[MATCH_FIELD_DATE_OF_BIRTH] = reason

    # 3. Compute overall status
    required_fields = list(expected_details.required_fields or matches.keys())
    overall_status = compute_overall_matching_status(matches, required_fields)

    return matches, reasons, overall_status

"""Deterministic evaluation of identity and age checks from normalized claims."""

from datetime import date, datetime
from typing import Any, Dict, List, Literal, Optional, Union
from fayda_mcp.oidc.mapping import normalize_birthdate

CheckOutcome = Union[bool, Literal["unavailable"]]


def calculate_age(birthdate_str: str, as_of: Optional[date] = None) -> Optional[int]:
    """Parse normalized ISO date (YYYY-MM-DD) and calculate age in years as of date.

    Returns None if birthdate is missing, malformed, or invalid.
    """
    normalized = normalize_birthdate(birthdate_str)
    if not normalized:
        return None

    try:
        dt = datetime.strptime(normalized, "%Y-%m-%d").date()
    except Exception:
        return None

    target = as_of or date.today()

    # Reject future birthdates
    if dt > target:
        return None

    age = target.year - dt.year - ((target.month, target.day) < (dt.month, dt.day))
    return age


def evaluate_checks(
    claims: Dict[str, Any],
    requested_checks: List[str],
    as_of: Optional[date] = None,
) -> Dict[str, CheckOutcome]:
    """Evaluate requested checks against normalized Fayda claims.

    Crucial requirement: Distinguishes 'unavailable' from False.
    - Missing or unparseable DOB yields 'unavailable' (never a fabricated False or True).
    - Underage citizen with valid DOB yields False.
    - Adult citizen with valid DOB yields True.

    Args:
        claims: Normalized claims dictionary.
        requested_checks: Permitted check names to evaluate.
        as_of: Optional target date for age calculations (default: today).

    Returns:
        Dict mapping check name to True, False, or 'unavailable'.
    """
    results: Dict[str, CheckOutcome] = {}

    for check in requested_checks:
        if check == "identity_verified":
            sub = claims.get("sub")
            if sub and str(sub).strip():
                results[check] = True
            else:
                results[check] = "unavailable"

        elif check == "age_over_18":
            raw_dob = claims.get("birthdate")
            age = calculate_age(raw_dob, as_of=as_of) if raw_dob else None
            if age is None:
                # Missing or invalid birthdate returns unavailable
                results[check] = "unavailable"
            else:
                results[check] = age >= 18

        elif check == "age_over_21":
            raw_dob = claims.get("birthdate")
            age = calculate_age(raw_dob, as_of=as_of) if raw_dob else None
            if age is None:
                results[check] = "unavailable"
            else:
                results[check] = age >= 21

        else:
            # Any unmapped or unavailable check returns 'unavailable'
            results[check] = "unavailable"

    return results

"""Deterministic evaluation of identity and age claims."""

from datetime import date, datetime
from typing import Any, Dict, List, Optional


def calculate_age(birthdate_str: str) -> Optional[int]:
    """Parse ISO or standard date and calculate current age in years.

    Returns None if birthdate is missing or invalid.
    """
    if not birthdate_str:
        return None
    try:
        # Format can be YYYY-MM-DD or YYYY/MM/DD
        cleaned = birthdate_str.replace("/", "-")
        dt = datetime.strptime(cleaned[:10], "%Y-%m-%d").date()
        today = date.today()
        age = today.year - dt.year - ((today.month, today.day) < (dt.month, dt.day))
        return age
    except Exception:
        return None


def evaluate_checks(
    claims: Dict[str, Any],
    requested_checks: List[str],
) -> Dict[str, Optional[bool]]:
    """Evaluate requested boolean checks from normalized Fayda claims.

    Returns None for checks where underlying data is unavailable/missing,
    distinguishing 'unavailable' from False.
    """
    results: Dict[str, Optional[bool]] = {}

    for check in requested_checks:
        if check == "identity_verified":
            # True if subject identifier exists in validated token/claims
            results[check] = bool(claims.get("sub"))
        elif check == "age_over_18":
            birthdate = claims.get("birthdate") or claims.get("dob")
            age = calculate_age(str(birthdate)) if birthdate else None
            if age is None:
                results[check] = None  # unavailable
            else:
                results[check] = age >= 18
        else:
            results[check] = None

    return results

"""Deterministic evaluation of identity and age checks from normalized claims."""

from datetime import date, datetime, timezone
import re
from typing import Any, Dict, List, Literal, Optional, Union
from zoneinfo import ZoneInfo

from fayda_mcp.localization.calendars import is_gregorian_leap_year
from fayda_mcp.oidc.mapping import normalize_birthdate

CheckOutcome = Union[bool, Literal["unavailable"]]


def calculate_age(
    birthdate_str: Optional[str],
    as_of: Optional[date] = None,
    timezone_name: str = "Africa/Addis_Ababa",
    february_29_anniversary: str = "march_1",
) -> Optional[int]:
    """Parse normalized full Gregorian date (YYYY-MM-DD) and calculate age as of evaluation date.

    Adheres strictly to the following requirements:
    1. Compares against an explicit evaluation date and exact calendar anniversary rule.
       Division of day counts by 365 is STRICTLY PROHIBITED.
    2. Missing, partial (YYYY-MM or 0000-MM-DD), ambiguous, or unparseable DOB yields None
       (evaluates to 'unavailable' in policy checks).
    3. Host timezone defines 'today' when as_of is omitted (default: Africa/Addis_Ababa).
    4. February 29 handling in non-leap years:
       - 'march_1' (default conservative rule): reaches age on March 1.
       - 'february_28': reaches age on February 28.
    """
    if not birthdate_str or not isinstance(birthdate_str, str):
        return None

    # Detect partial dates: YYYY-MM or 0000-MM-DD (missing day or year cannot resolve birthday)
    cleaned = birthdate_str.strip()
    if re.match(r"^\d{4}-\d{2}$", cleaned) or re.match(r"^0000-\d{2}-\d{2}$", cleaned):
        return None

    normalized = normalize_birthdate(cleaned)
    if not normalized or len(normalized) != 10:
        return None

    try:
        dt = datetime.strptime(normalized, "%Y-%m-%d").date()
    except Exception:
        return None

    # Resolve target evaluation date using host timezone if omitted
    if as_of is not None:
        target = as_of
    else:
        try:
            tz = ZoneInfo(timezone_name)
            target = datetime.now(tz).date()
        except Exception:
            target = datetime.now(timezone.utc).date()

    # Reject future birthdates
    if dt > target:
        return None

    # Calculate whether anniversary has occurred in target year
    if dt.month == 2 and dt.day == 29:
        if is_gregorian_leap_year(target.year):
            had_birthday = (target.month, target.day) >= (2, 29)
        else:
            # Common year without February 29
            if february_29_anniversary.lower() == "february_28":
                had_birthday = (target.month, target.day) >= (2, 28)
            else:  # default 'march_1'
                had_birthday = (target.month, target.day) >= (3, 1)
    else:
        had_birthday = (target.month, target.day) >= (dt.month, dt.day)

    age = (target.year - dt.year) if had_birthday else (target.year - dt.year - 1)
    return age


def evaluate_checks(
    claims: Dict[str, Any],
    requested_checks: List[str],
    as_of: Optional[date] = None,
    timezone_name: str = "Africa/Addis_Ababa",
    february_29_anniversary: str = "march_1",
    registry: Optional[Any] = None,
) -> Dict[str, CheckOutcome]:
    """Evaluate requested checks against normalized Fayda claims using the shared predicate registry.

    Ensures policy acceptance and evaluation cannot diverge.

    Crucial requirement: Distinguishes 'unavailable' from False.
    - Missing or unparseable DOB yields 'unavailable' (never a fabricated False or True).
    - Underage citizen with valid DOB yields False.
    - Adult citizen with valid DOB yields True.

    Args:
        claims: Normalized claims dictionary.
        requested_checks: Permitted check names to evaluate.
        as_of: Optional target date for age calculations (default: today in host timezone).
        timezone_name: Host evaluation timezone (default: Africa/Addis_Ababa).
        february_29_anniversary: Leap-day anniversary policy ('march_1' or 'february_28').
        registry: Optional custom predicate registry (defaults to shared DEFAULT_PREDICATE_REGISTRY).

    Returns:
        Dict mapping check name to True, False, or 'unavailable'.
    """
    from fayda_mcp.predicates import DEFAULT_PREDICATE_REGISTRY, PredicateContext

    reg = registry or DEFAULT_PREDICATE_REGISTRY
    context = PredicateContext(
        as_of=as_of,
        timezone_name=timezone_name,
        february_29_anniversary=february_29_anniversary,
    )
    return reg.evaluate_all(claims, requested_checks, context)


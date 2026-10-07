"""Normalization of localized and provider-specific claim formats."""

import re
from typing import Any, Dict, Optional

# Biometric and credential fields to purge unconditionally
DISALLOWED_PROVIDER_FIELDS = {
    "biometrics",
    "biometric_data",
    "fingerprint",
    "fingerprints",
    "iris",
    "photo",
    "face",
    "individual_biometrics",
    "access_token",
    "id_token",
    "refresh_token",
    "client_secret",
    "private_key",
    "fayda_number",
    "national_id",
}


def normalize_birthdate(
    raw_dob: Any,
    source_calendar: Optional[str] = None,
) -> Optional[str]:
    """Normalize varied date-of-birth formats into ISO YYYY-MM-DD.

    Calendar source must be explicit:
    - Standard OIDC birthdate is Gregorian YYYY-MM-DD (including documented partial dates).
    - Never reinterpret compliant Gregorian dates based on separators, low years, or language.
    - Ethiopic dates are supported only when explicitly specified via source_calendar or metadata.
    """
    if isinstance(raw_dob, dict):
        raw_dob = extract_localized_string(raw_dob)

    if not raw_dob or not isinstance(raw_dob, str):
        return None

    cleaned = raw_dob.strip()

    if source_calendar and source_calendar.lower().strip() in ("ethiopic", "ec"):
        from fayda_mcp.localization.calendars import normalize_dob_with_source
        return normalize_dob_with_source(cleaned, source_calendar="ethiopic")

    # Pattern: YYYY-MM-DD or YYYY/MM/DD
    m1 = re.match(r"^(\d{4})[-/](\d{1,2})[-/](\d{1,2})$", cleaned)
    if m1:
        year, month, day = int(m1.group(1)), int(m1.group(2)), int(m1.group(3))
        if not (1900 <= year <= 2100 and 1 <= month <= 12 and 1 <= day <= 31):
            return None
        try:
            from datetime import date as dt_date
            dt_date(year, month, day)
            return f"{year:04d}-{month:02d}-{day:02d}"
        except ValueError:
            return None

    # Pattern: DD-MM-YYYY or DD/MM/YYYY
    m2 = re.match(r"^(\d{1,2})[-/](\d{1,2})[-/](\d{4})$", cleaned)
    if m2:
        day, month, year = int(m2.group(1)), int(m2.group(2)), int(m2.group(3))
        if not (1900 <= year <= 2100 and 1 <= month <= 12 and 1 <= day <= 31):
            return None
        try:
            from datetime import date as dt_date
            dt_date(year, month, day)
            return f"{year:04d}-{month:02d}-{day:02d}"
        except ValueError:
            return None

    # Fallback to standard OIDC partial date handler (YYYY-MM or 0000-MM-DD)
    from fayda_mcp.localization.calendars import normalize_dob_with_source
    return normalize_dob_with_source(cleaned, source_calendar="gregorian")


def extract_localized_string(val: Any) -> Optional[str]:
    """Extract string value from potentially localized eSignet dictionary."""
    if isinstance(val, str):
        return val.strip()
    if isinstance(val, dict):
        # Handle {"@value": "Abebe", "@language": "eng"} or {"en": "Abebe"}
        if "@value" in val:
            return str(val["@value"]).strip()
        for key in ["en", "eng", "am", "default"]:
            if key in val:
                return str(val[key]).strip()
        # Fall back to first string value found
        for v in val.values():
            if isinstance(v, str):
                return v.strip()
    return None


def normalize_claims(
    raw_claims: Dict[str, Any],
    source_calendar: Optional[str] = None,
) -> Dict[str, Any]:
    """Normalize localized claims and strip disallowed biometric or credential attributes."""
    normalized: Dict[str, Any] = {}

    for k, v in raw_claims.items():
        key_lower = k.lower()

        # Reject disallowed biometric and secret fields
        if key_lower in DISALLOWED_PROVIDER_FIELDS:
            continue

        if key_lower in ("birthdate", "dob", "date_of_birth"):
            normalized_dob = normalize_birthdate(v, source_calendar=source_calendar)
            if normalized_dob:
                normalized["birthdate"] = normalized_dob
        elif key_lower in ("name", "full_name"):
            name_str = extract_localized_string(v)
            if name_str:
                normalized["name"] = name_str
        elif key_lower == "sub":
            normalized["sub"] = str(v)
        else:
            normalized[k] = v

    return normalized

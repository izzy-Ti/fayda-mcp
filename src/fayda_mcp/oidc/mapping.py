"""Normalization of localized and provider-specific claim formats."""

import re
from typing import Any, Dict, List, Optional

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


def extract_localized_string(
    val: Any,
    preferred_locales: Optional[List[str]] = None,
    fallback_locale: str = "en",
) -> Optional[str]:
    """Extract string value from potentially localized eSignet dictionary or language-tagged structure.

    Preserves original Unicode text without transliteration.
    Never stringifies a raw dict or object as a name.
    """
    from fayda_mcp.localization.languages import select_localized_value
    return select_localized_value(
        val, preferred_locales=preferred_locales, fallback_locale=fallback_locale
    )


def normalize_claims(
    raw_claims: Dict[str, Any],
    source_calendar: Optional[str] = None,
    preferred_locales: Optional[List[str]] = None,
    fallback_locale: str = "en",
) -> Dict[str, Any]:
    """Normalize localized claims and strip disallowed biometric or credential attributes."""
    normalized: Dict[str, Any] = {}

    from fayda_mcp.localization.languages import extract_localized_claim

    # Check for localized names (e.g. name#om, name#am)
    extracted_name = extract_localized_claim(
        raw_claims,
        "name",
        preferred_locales=preferred_locales,
        fallback_locale=fallback_locale,
    )
    if not extracted_name:
        extracted_name = extract_localized_claim(
            raw_claims,
            "full_name",
            preferred_locales=preferred_locales,
            fallback_locale=fallback_locale,
        )
    if extracted_name:
        normalized["name"] = extracted_name

    for k, v in raw_claims.items():
        key_lower = k.lower()

        # Reject disallowed biometric and secret fields
        if key_lower in DISALLOWED_PROVIDER_FIELDS:
            continue

        # Skip localized claim keys (e.g. name#om) from generic copying
        if "#" in k:
            continue

        if key_lower in ("birthdate", "dob", "date_of_birth"):
            normalized_dob = normalize_birthdate(v, source_calendar=source_calendar)
            if normalized_dob:
                normalized["birthdate"] = normalized_dob
        elif key_lower in ("name", "full_name"):
            # Already resolved if possible above
            if "name" not in normalized:
                name_str = extract_localized_string(
                    v, preferred_locales=preferred_locales, fallback_locale=fallback_locale
                )
                if name_str:
                    normalized["name"] = name_str
        elif key_lower == "sub":
            normalized["sub"] = str(v)
        else:
            normalized[k] = v

    return normalized

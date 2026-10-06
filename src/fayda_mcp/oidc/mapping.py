"""Normalization of localized and provider-specific claim formats."""

from typing import Any, Dict


def normalize_claims(raw_claims: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize language-specific claim keys into standard claims dictionary."""
    normalized = dict(raw_claims)

    # Standardize birthdate if represented as dob or date_of_birth
    if "dob" in normalized and "birthdate" not in normalized:
        normalized["birthdate"] = normalized["dob"]
    elif "date_of_birth" in normalized and "birthdate" not in normalized:
        normalized["birthdate"] = normalized["date_of_birth"]

    return normalized

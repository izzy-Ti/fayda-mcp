"""Mapping of details matching requirements (name/DOB) to approved OIDC claims and scopes.

Per guide4 specification:
- Name and DOB requirements map strictly to approved OIDC claims ('name', 'birthdate') and scopes ('openid', 'profile').
- Unsupported or missing provider claims remain unavailable (tri-state null outcome with safe reason code).
- Demographic data is never fabricated or defaulted to true.
"""

from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from fayda_mcp.matching.schemas import (
    MATCH_FIELD_DATE_OF_BIRTH,
    MATCH_FIELD_FULL_NAME,
    SUPPORTED_MATCH_FIELDS,
    ExpectedDetails,
    FieldMatchOutcome,
)

# Standard OIDC Claim Names
CLAIM_SUB: str = "sub"
CLAIM_NAME: str = "name"
CLAIM_BIRTHDATE: str = "birthdate"

# Standard OIDC Scope Names
SCOPE_OPENID: str = "openid"
SCOPE_PROFILE: str = "profile"

# Safe Reason Codes for Unavailable Claims
REASON_PROVIDER_CLAIM_UNAVAILABLE: str = "provider_claim_unavailable"
REASON_UNSUPPORTED_FIELD: str = "unsupported_field"
REASON_UNAUTHENTICATED: str = "identity_not_authenticated"


def resolve_details_matching_scopes_and_claims(
    expected_details: Optional[ExpectedDetails],
) -> Tuple[List[str], Dict[str, Any]]:
    """Map expected identity requirements to minimal approved OIDC scopes and essential claims.

    Args:
        expected_details: ExpectedDetails specification containing expected name/DOB and required fields.

    Returns:
        Tuple of (scopes_list, claims_parameter_dict)
    """
    scopes: Set[str] = {SCOPE_OPENID}
    userinfo_claims: Dict[str, Any] = {
        CLAIM_SUB: {"essential": True},
    }

    if expected_details is not None:
        has_name = bool(expected_details.full_name and expected_details.full_name.strip())
        has_dob = bool(expected_details.date_of_birth and expected_details.date_of_birth.strip())
        req_fields = set(expected_details.required_fields or [])

        if has_name or MATCH_FIELD_FULL_NAME in req_fields:
            scopes.add(SCOPE_PROFILE)
            userinfo_claims[CLAIM_NAME] = {"essential": True}

        if has_dob or MATCH_FIELD_DATE_OF_BIRTH in req_fields:
            scopes.add(SCOPE_PROFILE)
            userinfo_claims[CLAIM_BIRTHDATE] = {"essential": True}

    claims_param: Dict[str, Any] = {"userinfo": userinfo_claims}
    return sorted(list(scopes)), claims_param


def extract_approved_matching_claims(
    claims: Dict[str, Any],
    expected_details: Optional[ExpectedDetails] = None,
) -> Tuple[Dict[str, Optional[str]], Dict[str, str]]:
    """Extract approved comparison claims from validated provider claims.

    Unsupported or missing provider claims strictly evaluate to None (unavailable)
    and record safe reason codes. Never guesses, hallucinates, or returns raw tokens.

    Args:
        claims: Normalized, validated provider claims dictionary.
        expected_details: Optional ExpectedDetails instance indicating requested fields.

    Returns:
        Tuple of:
            - extracted_claims: Dict mapping field names to claim string or None
            - unavailable_reasons: Dict mapping field names to safe reason codes if unavailable
    """
    extracted: Dict[str, Optional[str]] = {}
    reasons: Dict[str, str] = {}

    target_fields: List[str] = list(SUPPORTED_MATCH_FIELDS)
    if expected_details is not None and expected_details.required_fields:
        target_fields = list(expected_details.required_fields)

    # 1. Full name extraction
    if MATCH_FIELD_FULL_NAME in target_fields or (
        expected_details and expected_details.full_name
    ):
        raw_name = claims.get(CLAIM_NAME) or claims.get("full_name")
        if not raw_name:
            # Fallback to combining given_name + family_name if both present
            given = claims.get("given_name")
            family = claims.get("family_name")
            if given and family:
                raw_name = f"{given} {family}".strip()

        if raw_name and isinstance(raw_name, str) and raw_name.strip():
            extracted[MATCH_FIELD_FULL_NAME] = raw_name.strip()
        else:
            extracted[MATCH_FIELD_FULL_NAME] = None
            reasons[MATCH_FIELD_FULL_NAME] = REASON_PROVIDER_CLAIM_UNAVAILABLE

    # 2. Date of birth extraction
    if MATCH_FIELD_DATE_OF_BIRTH in target_fields or (
        expected_details and expected_details.date_of_birth
    ):
        raw_dob = claims.get(CLAIM_BIRTHDATE) or claims.get("dob") or claims.get("date_of_birth")
        if raw_dob and isinstance(raw_dob, str) and raw_dob.strip():
            extracted[MATCH_FIELD_DATE_OF_BIRTH] = raw_dob.strip()
        else:
            extracted[MATCH_FIELD_DATE_OF_BIRTH] = None
            reasons[MATCH_FIELD_DATE_OF_BIRTH] = REASON_PROVIDER_CLAIM_UNAVAILABLE

    # 3. Check for any unsupported fields
    for field in target_fields:
        if field not in SUPPORTED_MATCH_FIELDS:
            extracted[field] = None
            reasons[field] = REASON_UNSUPPORTED_FIELD

    return extracted, reasons


def evaluate_initial_availability(
    requested_fields: Sequence[str],
    extracted_claims: Dict[str, Optional[str]],
    unavailable_reasons: Dict[str, str],
) -> Dict[str, FieldMatchOutcome]:
    """Map extracted claims to initial tri-state outcomes.

    Missing or unsupported claims are assigned None (unavailable).
    Available claims are assigned None until evaluated by comparison engine in Task 06.
    """
    outcomes: Dict[str, FieldMatchOutcome] = {}
    for f in requested_fields:
        if extracted_claims.get(f) is None:
            outcomes[f] = None
    return outcomes

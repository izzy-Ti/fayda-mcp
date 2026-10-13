"""Typed comparison schemas, models, and tri-state match outcomes for Fayda details matching.

Defines expected identity details (name/DOB), required comparison fields,
tri-state outcome types, match results, and comparison policy versions per guide4 specification.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Set, Union
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from fayda_mcp.exceptions import FaydaMCPError

# ---------------------------------------------------------------------------
# Constants & Versions
# ---------------------------------------------------------------------------

DEFAULT_COMPARISON_POLICY_VERSION: str = "details-v1"
DEFAULT_EXPECTED_DETAILS_TTL_SECONDS: int = 900  # 15 minutes max TTL for expected details

MATCH_FIELD_FULL_NAME: str = "full_name"
MATCH_FIELD_DATE_OF_BIRTH: str = "date_of_birth"
SUPPORTED_MATCH_FIELDS: tuple[str, ...] = (
    MATCH_FIELD_FULL_NAME,
    MATCH_FIELD_DATE_OF_BIRTH,
)

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

# Tri-state outcome: True for match, False for mismatch, None (null) for unavailable evidence
FieldMatchOutcome = Optional[bool]

# Overall matching status
MatchingStatus = Literal[
    "matched",
    "mismatched",
    "unavailable",
    "pending",
    "failed",
    "expired",
]


class DetailsMatchingErrorCode(str, Enum):
    """Safe, machine-readable error codes for details matching operations."""

    INVALID_EXPECTATIONS = "matching_invalid_expectations"
    REFERENCE_NOT_FOUND = "matching_reference_not_found"
    REFERENCE_EXPIRED = "matching_reference_expired"
    CALLER_MISMATCH = "matching_caller_mismatch"
    USER_MISMATCH = "matching_user_mismatch"
    PURPOSE_MISMATCH = "matching_purpose_mismatch"
    ALREADY_BOUND = "matching_reference_already_bound"
    MISSING_CLAIMS = "matching_missing_claims"
    UNSUPPORTED_FIELD = "matching_unsupported_field"
    IDEMPOTENCY_CONFLICT = "matching_idempotency_conflict"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class DetailsMatchingError(FaydaMCPError):
    """Base domain exception for details matching failures."""

    def __init__(
        self,
        message: str,
        code: Union[str, DetailsMatchingErrorCode] = DetailsMatchingErrorCode.INVALID_EXPECTATIONS,
        details: Optional[Dict[str, Any]] = None,
    ):
        code_str = code.value if isinstance(code, DetailsMatchingErrorCode) else str(code)
        super().__init__(message=message, code=code_str, details=details)


class DetailsReferenceNotFoundError(DetailsMatchingError):
    """Raised when the expected_details_ref cannot be located."""

    def __init__(self, ref: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=f"Expected details reference '{ref}' not found",
            code=DetailsMatchingErrorCode.REFERENCE_NOT_FOUND,
            details=details,
        )


class DetailsReferenceExpiredError(DetailsMatchingError):
    """Raised when the expected_details_ref has exceeded its TTL."""

    def __init__(self, ref: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=f"Expected details reference '{ref}' has expired",
            code=DetailsMatchingErrorCode.REFERENCE_EXPIRED,
            details=details,
        )


class DetailsCallerMismatchError(DetailsMatchingError):
    """Raised when the caller attempting to consume expected details does not match the creator."""

    def __init__(self, ref: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=f"Caller is not authorized to access expected details reference '{ref}'",
            code=DetailsMatchingErrorCode.CALLER_MISMATCH,
            details=details,
        )


class DetailsUserMismatchError(DetailsMatchingError):
    """Raised when the application_user_ref differs from the bound expected details."""

    def __init__(self, ref: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=f"Application user ref does not match bound expected details reference '{ref}'",
            code=DetailsMatchingErrorCode.USER_MISMATCH,
            details=details,
        )


class DetailsPurposeMismatchError(DetailsMatchingError):
    """Raised when the purpose differs from the bound expected details."""

    def __init__(self, ref: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=f"Verification purpose does not match bound expected details reference '{ref}'",
            code=DetailsMatchingErrorCode.PURPOSE_MISMATCH,
            details=details,
        )


class DetailsAlreadyBoundError(DetailsMatchingError):
    """Raised when an expected details reference has already been bound to another verification request."""

    def __init__(self, ref: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=f"Expected details reference '{ref}' is already bound to another verification request",
            code=DetailsMatchingErrorCode.ALREADY_BOUND,
            details=details,
        )


# ---------------------------------------------------------------------------
# Schemas: Expected Details Input & Storage
# ---------------------------------------------------------------------------


class ExpectedDetails(BaseModel):
    """Host-supplied expected identity details for comparison.

    Only full name and full date of birth are supported in details-v1.
    Partial date of birth is strictly disallowed per matching specification.
    """

    model_config = ConfigDict(extra="forbid")

    full_name: Optional[str] = Field(
        default=None,
        description="Expected full citizen name to compare against authorized Fayda claims",
    )
    date_of_birth: Optional[str] = Field(
        default=None,
        description="Expected full date of birth (e.g. '1995/04/12' or '1995-04-12')",
    )
    dob_calendar: Optional[str] = Field(
        default="gregorian",
        description="Calendar convention for date of birth comparison ('gregorian' or 'ethiopian')",
    )
    required_fields: Optional[List[str]] = Field(
        default=None,
        description="List of fields that MUST match for overall outcome ('full_name', 'date_of_birth')",
    )

    @field_validator("dob_calendar")
    @classmethod
    def validate_calendar(cls, v: Optional[str]) -> str:
        if v is None:
            return "gregorian"
        v_clean = v.strip().lower()
        if v_clean in ("ethiopian", "ethiopic"):
            return "ethiopian"
        if v_clean == "gregorian":
            return "gregorian"
        raise ValueError(f"Unsupported DOB calendar '{v}'. Must be 'gregorian' or 'ethiopian'.")

    @field_validator("date_of_birth")
    @classmethod
    def validate_full_date(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v_clean = v.strip()
        if not v_clean:
            return None
        # Reject partial dates (e.g., year only or year-month only)
        parts = v_clean.replace("-", "/").split("/")
        if len(parts) != 3 or not all(p.isdigit() for p in parts):
            raise ValueError(
                "Partial or invalid date of birth rejected. Full date of birth (YYYY/MM/DD) required in details-v1."
            )
        return v_clean

    @model_validator(mode="after")
    def validate_at_least_one_field_and_requirements(self) -> "ExpectedDetails":
        has_name = bool(self.full_name and self.full_name.strip())
        has_dob = bool(self.date_of_birth and self.date_of_birth.strip())

        if not has_name and not has_dob:
            raise ValueError("At least one expected detail ('full_name' or 'date_of_birth') must be provided.")

        provided_fields: List[str] = []
        if has_name:
            provided_fields.append(MATCH_FIELD_FULL_NAME)
        if has_dob:
            provided_fields.append(MATCH_FIELD_DATE_OF_BIRTH)

        if self.required_fields is not None:
            if not self.required_fields:
                raise ValueError("required_fields list cannot be empty when explicitly specified.")
            for req in self.required_fields:
                if req not in SUPPORTED_MATCH_FIELDS:
                    raise ValueError(
                        f"Unsupported field '{req}' in required_fields. Supported fields: {list(SUPPORTED_MATCH_FIELDS)}"
                    )
                if req not in provided_fields:
                    raise ValueError(f"Required field '{req}' cannot be required without an expected value.")
        else:
            # Default required_fields to all provided fields
            object.__setattr__(self, "required_fields", provided_fields)

        return self


class ExpectedDetailsSubmission(BaseModel):
    """Payload submitted by host backend to register expected details prior to verification."""

    model_config = ConfigDict(extra="forbid")

    application_user_ref: str = Field(..., description="Host application user identifier")
    purpose: str = Field(..., description="Approved business purpose for verification")
    expected_details: ExpectedDetails = Field(..., description="Expected citizen details")
    ttl_seconds: int = Field(
        default=DEFAULT_EXPECTED_DETAILS_TTL_SECONDS,
        ge=60,
        le=3600,
        description="Time-to-live for the expected details record (default: 900s, max: 3600s)",
    )


class ExpectedDetailsSubmissionResponse(BaseModel):
    """Opaque reference returned upon successfully storing expected details."""

    model_config = ConfigDict(extra="forbid")

    expected_details_ref: str = Field(..., description="Opaque short-lived expected details reference")
    expires_at: str = Field(..., description="ISO 8601 UTC expiration timestamp")


class ExpectedDetailsRecord(BaseModel):
    """Stored representation of expected details bound to creator, tenant, user, and purpose."""

    model_config = ConfigDict(extra="forbid")

    ref: str = Field(..., description="Opaque reference identifier ('edr_...')")
    tenant_id: str = Field(..., description="Authenticated tenant identifier")
    principal_id: str = Field(..., description="Authenticated caller principal identifier")
    application_user_ref: str = Field(..., description="Bound host application user identifier")
    purpose: str = Field(..., description="Bound business purpose")
    expected_details: ExpectedDetails = Field(..., description="Stored expected details")
    created_at: str = Field(..., description="ISO 8601 UTC creation timestamp")
    expires_at: str = Field(..., description="ISO 8601 UTC expiration timestamp")
    bound_request_id: Optional[str] = Field(
        default=None,
        description="Opaque verification request_id once bound by start tool",
    )


# ---------------------------------------------------------------------------
# Schemas: MCP Tool Inputs & Outputs
# ---------------------------------------------------------------------------


class StartDetailsVerificationRequest(BaseModel):
    """Input payload to start an eSignet verification with bound expected details."""

    model_config = ConfigDict(extra="forbid")

    expected_details_ref: str = Field(
        ...,
        description="Opaque short-lived reference to expected details created by host backend",
    )
    purpose: str = Field(..., description="Approved business purpose (e.g., 'onboarding', 'kyc')")
    application_user_ref: str = Field(..., description="Opaque host application user identifier")
    idempotency_key: str = Field(..., description="Unique caller key preventing duplicate starts")


class StartDetailsVerificationResponse(BaseModel):
    """Response returned upon initiating a details verification flow."""

    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(..., description="Unique opaque verification request identifier")
    authorization_url: str = Field(..., description="Fayda eSignet authorization URL for citizen authentication")
    expires_at: str = Field(..., description="ISO 8601 UTC expiry timestamp")


class DetailsMatchResult(BaseModel):
    """Final minimal verification match outcome.

    Strictly forbids demographic dumps, raw tokens, or provider-held values.
    Returns boolean tri-state match flags (true, false, null) and overall status.
    """

    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(..., description="Unique verification request identifier")
    verification_method: Literal["esignet"] = Field(
        default="esignet",
        description="Underlying verification method, strictly 'esignet'",
    )
    matching_status: MatchingStatus = Field(
        ...,
        description="Overall matching status: 'matched', 'mismatched', 'unavailable', or 'pending'",
    )
    matches: Dict[str, FieldMatchOutcome] = Field(
        default_factory=dict,
        description="Tri-state field outcomes: true for match, false for mismatch, null for unavailable evidence",
    )
    comparison_policy_version: str = Field(
        default=DEFAULT_COMPARISON_POLICY_VERSION,
        description="Comparison policy specification version ('details-v1')",
    )
    required_fields: List[str] = Field(
        default_factory=list,
        description="Fields required to match for overall status to be 'matched'",
    )
    checked_at: Optional[str] = Field(
        default=None,
        description="ISO 8601 UTC timestamp when comparison was evaluated",
    )
    expires_at: Optional[str] = Field(
        default=None,
        description="ISO 8601 UTC timestamp when result expires",
    )
    reasons: Dict[str, str] = Field(
        default_factory=dict,
        description="Safe reason codes for mismatched or unavailable fields",
    )
    identity_authenticated: Optional[bool] = Field(
        default=None,
        description="Preserves underlying eSignet identity authentication outcome separately from details matching",
    )
    evidence_ref: Optional[str] = Field(
        default=None,
        description="Opaque reference to audit evidence record",
    )
    error: Optional[str] = Field(
        default=None,
        description="Optional safe error description if matching failed",
    )
    error_code: Optional[str] = Field(
        default=None,
        description="Machine-readable error code if matching failed",
    )


# ---------------------------------------------------------------------------
# Helper: Tri-State Overall Status Evaluation
# ---------------------------------------------------------------------------


def compute_overall_matching_status(
    matches: Dict[str, FieldMatchOutcome],
    required_fields: List[str],
) -> Literal["matched", "mismatched", "unavailable"]:
    """Compute overall matching status from field match outcomes and required fields.

    Rules per guide4 specification:
        - Return 'matched' ONLY when every required field evaluates to True.
        - If any required field evaluates to False, return 'mismatched'.
        - If no required field is False, but at least one required field is None (unavailable),
          return 'unavailable'.
    """
    if not required_fields:
        return "unavailable"

    has_unavailable = False
    for field in required_fields:
        outcome = matches.get(field)
        if outcome is False:
            return "mismatched"
        if outcome is None:
            has_unavailable = True

    if has_unavailable:
        return "unavailable"

    return "matched"

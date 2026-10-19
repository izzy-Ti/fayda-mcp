"""Privacy protection, backend-only comparisons, caller/user binding, TTL, and rate limiting (guide5 Task 13).

Per guide5 specification:
- Reuse caller/user binding, TTL, and rate limits.
- Keep names, variants, phonetic codes, and scores backend-only by default.
- Agent / MCP results strictly exclude raw citizen names, candidate transliteration variants,
  phonetic codes, and numerical similarity scores.
- Backend comparison details are stored separately with short TTL and tenant isolation.
"""

from collections import defaultdict
from datetime import datetime, timezone
import time
from typing import Any, Dict, List, Optional, Set, Union
from pydantic import BaseModel, ConfigDict, Field

from fayda_mcp.context import CallerContext
from fayda_mcp.matching.schemas import (
    DetailsCallerMismatchError,
    DetailsMatchingError,
    DetailsMatchingErrorCode,
    DetailsMatchResult,
    DetailsPrivacyViolationError,
    DetailsRateLimitExceededError,
    DetailsReferenceExpiredError,
    DetailsUserMismatchError,
    ExpectedDetailsRecord,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PRIVACY_SPEC_VERSION: str = "privacy-v1"

# Default rate limit parameters: 15 requests per 60 seconds per caller/user
DEFAULT_RATE_LIMIT_REQUESTS: int = 15
DEFAULT_RATE_LIMIT_WINDOW_SECONDS: int = 60

# Forbidden fields that must NEVER appear in public/agent match results
FORBIDDEN_LEAK_FIELDS: frozenset[str] = frozenset({
    "full_name",
    "date_of_birth",
    "name",
    "dob",
    "expected_name",
    "provider_name",
    "raw_name",
    "variants",
    "candidate_variants",
    "approved_variants",
    "phonetic_codes",
    "matched_phonetic_code",
    "double_metaphone",
    "ethiopian_phonetic_code",
    "scores",
    "score",
    "similarity_score",
    "overall_similarity_score",
    "composite_similarity",
    "token_features",
    "spelling_score",
    "phonetic_score",
    "raw_claims",
    "access_token",
    "id_token",
})


# ---------------------------------------------------------------------------
# Backend-Only Comparison Data Model
# ---------------------------------------------------------------------------


class BackendComparisonDetails(BaseModel):
    """Rich comparison trace retained strictly on the backend for audit and debugging.

    Never exposed to MCP clients or agents.
    """

    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(..., description="Unique verification request identifier")
    tenant_id: str = Field(..., description="Bound tenant identifier")
    principal_id: str = Field(..., description="Bound creator principal identifier")
    application_user_ref: str = Field(..., description="Bound host application user reference")
    expected_name: str = Field(..., description="Expected name submitted by host backend")
    provider_name: str = Field(..., description="Validated name claim from provider")
    matching_profile: str = Field(..., description="Matching profile used ('strict' or 'ethiopian_name_v1')")
    variants: List[str] = Field(default_factory=list, description="Candidate transliteration variants generated")
    phonetic_codes: List[str] = Field(default_factory=list, description="Phonetic codes computed for tokens")
    similarity_scores: Dict[str, float] = Field(default_factory=dict, description="Internal similarity scores")
    name_match_status: str = Field(..., description="Derived name match status")
    method: Optional[str] = Field(default=None, description="Derived comparison method")
    reason: Optional[str] = Field(default=None, description="Safe machine-readable reason code")
    created_at: str = Field(..., description="ISO 8601 UTC creation timestamp")
    expires_at: str = Field(..., description="ISO 8601 UTC expiry timestamp")
    evidence_ref: Optional[str] = Field(default=None, description="Opaque audit evidence reference")


# ---------------------------------------------------------------------------
# Rate Limiting
# ---------------------------------------------------------------------------


class MatchingRateLimiter:
    """Sliding-window rate limiter for name matching and verification operations.

    Prevents dictionary, enumeration, and population search attacks across callers and users.
    """

    def __init__(
        self,
        max_requests: int = DEFAULT_RATE_LIMIT_REQUESTS,
        window_seconds: int = DEFAULT_RATE_LIMIT_WINDOW_SECONDS,
    ) -> None:
        self.max_requests = max(1, max_requests)
        self.window_seconds = max(1, window_seconds)
        self._requests: Dict[str, List[float]] = defaultdict(list)

    def _cleanup_old_requests(self, key: str, now: float) -> None:
        cutoff = now - self.window_seconds
        self._requests[key] = [t for t in self._requests[key] if t > cutoff]

    def is_allowed(self, key: str) -> bool:
        """Check if request is permitted under rate limit without incrementing count."""
        now = time.time()
        self._cleanup_old_requests(key, now)
        return len(self._requests[key]) < self.max_requests

    def record(self, key: str) -> None:
        """Record a request timestamp under the rate limit key."""
        now = time.time()
        self._cleanup_old_requests(key, now)
        self._requests[key].append(now)

    def acquire(self, key: str) -> None:
        """Check and record request, raising DetailsRateLimitExceededError if limit is reached."""
        now = time.time()
        self._cleanup_old_requests(key, now)
        if len(self._requests[key]) >= self.max_requests:
            raise DetailsRateLimitExceededError(key=key)
        self._requests[key].append(now)

    def enforce_rate_limit(
        self,
        tenant_id: str,
        principal_id: str,
        application_user_ref: Optional[str] = None,
    ) -> None:
        """Enforce rate limits per caller and per application user."""
        caller_key = f"rate:caller:{tenant_id}:{principal_id}"
        self.acquire(caller_key)

        if application_user_ref:
            user_key = f"rate:user:{tenant_id}:{application_user_ref}"
            self.acquire(user_key)

    def reset(self) -> None:
        """Clear all rate limiting buckets."""
        self._requests.clear()


# ---------------------------------------------------------------------------
# Invariant Verifiers & Sanitization
# ---------------------------------------------------------------------------


def assert_caller_user_binding(
    record: ExpectedDetailsRecord,
    context: CallerContext,
    application_user_ref: Optional[str] = None,
    purpose: Optional[str] = None,
    validate_principal: bool = True,
) -> bool:
    """Verify caller, tenant, user, and purpose bindings.

    Raises:
        DetailsCallerMismatchError: If tenant or non-admin principal does not match.
        DetailsUserMismatchError: If application_user_ref does not match.
        DetailsPurposeMismatchError: If purpose does not match.
    """
    if record.tenant_id != context.tenant_id:
        raise DetailsCallerMismatchError(ref=record.ref)

    if validate_principal and context is not None:
        is_privileged = any(scope in context.scopes for scope in ("admin", "*"))
        is_shared_backend = record.principal_id in ("anonymous", "backend_service") or context.principal_id in ("anonymous", "backend_service")
        if not is_privileged and not is_shared_backend and context.principal_id != record.principal_id:
            raise DetailsCallerMismatchError(ref=record.ref)

    if application_user_ref and record.application_user_ref != str(application_user_ref).strip():
        raise DetailsUserMismatchError(ref=record.ref)

    if purpose and record.purpose != str(purpose).strip():
        from fayda_mcp.matching.schemas import DetailsPurposeMismatchError
        raise DetailsPurposeMismatchError(ref=record.ref)

    return True


def assert_ttl_compliance(
    expires_at: str,
    now: Optional[datetime] = None,
    ref: str = "record",
) -> bool:
    """Verify that a record has not exceeded its TTL expiration.

    Raises:
        DetailsReferenceExpiredError: If record has expired.
    """
    now_dt = now or datetime.now(timezone.utc)
    try:
        exp_dt = datetime.fromisoformat(expires_at)
        if exp_dt <= now_dt:
            raise DetailsReferenceExpiredError(ref=ref)
    except DetailsReferenceExpiredError:
        raise
    except Exception:
        pass
    return True


def assert_comparison_privacy_invariants(data: Dict[str, Any]) -> bool:
    """Recursively verify that no private comparison fields leak into public/agent structures.

    Raises:
        DetailsPrivacyViolationError: If any forbidden field or raw sensitive value is found.
    """
    for key, val in data.items():
        if key in FORBIDDEN_LEAK_FIELDS:
            raise DetailsPrivacyViolationError(
                field=key,
                details={"value_type": type(val).__name__},
            )

        # Check nested dictionaries
        if isinstance(val, dict):
            # In 'matches', keys are field names (e.g. 'full_name', 'date_of_birth'),
            # but values must strictly be tri-state booleans (True, False, None)
            if key == "matches":
                for f_name, f_val in val.items():
                    if f_val is not None and not isinstance(f_val, bool):
                        raise DetailsPrivacyViolationError(
                            field=f"matches.{f_name}",
                            details={"reason": "Matches values must be tri-state bool (True, False, None)"},
                        )
            # In 'reasons', keys are field names or operation keys, values must be safe machine-readable strings
            elif key == "reasons":
                for f_name, f_val in val.items():
                    if not isinstance(f_val, str):
                        raise DetailsPrivacyViolationError(
                            field=f"reasons.{f_name}",
                            details={"reason": "Reason values must be safe string codes"},
                        )
            else:
                assert_comparison_privacy_invariants(val)

        # Check list of dicts
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, dict):
                    assert_comparison_privacy_invariants(item)

    return True


def sanitize_matching_result(result: DetailsMatchResult) -> DetailsMatchResult:
    """Ensure that a DetailsMatchResult strictly complies with privacy invariants.

    Verifies absence of forbidden fields and ensures safe tri-state outcomes.
    """
    data = result.model_dump()
    assert_comparison_privacy_invariants(data)
    return result

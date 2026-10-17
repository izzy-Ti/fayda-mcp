"""Protection of independent checks and non-cancellation invariants (guide5 Task 11).

Per guide5 specification:
- Keep DOB and other required checks independent.
- A strong name score never cancels a required mismatch or missing evidence.
- No composite cross-field score averaging (no blended score between name and DOB).
- Each required field (full_name, date_of_birth, predicates) maintains isolated evaluation.
"""

from typing import Any, Dict, List, Literal, Optional, Sequence, Tuple
from pydantic import BaseModel, ConfigDict, Field

from fayda_mcp.matching.schemas import (
    MATCH_FIELD_DATE_OF_BIRTH,
    MATCH_FIELD_FULL_NAME,
    FieldMatchOutcome,
    compute_overall_matching_status,
)


PROTECTION_SPEC_VERSION: str = "protection-v1"


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------


class ProtectedCheckResult(BaseModel):
    """Result of evaluating multiple required checks with non-cancellation guarantees."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    protection_spec_version: str = Field(default=PROTECTION_SPEC_VERSION)
    overall_status: Literal["matched", "mismatched", "unavailable"] = Field(
        ...,
        description="Overall outcome: 'matched' only if all required checks match",
    )
    matches: Dict[str, FieldMatchOutcome] = Field(
        ...,
        description="Independent outcomes for each field (True, False, or None)",
    )
    reasons: Dict[str, str] = Field(
        default_factory=dict,
        description="Safe machine-readable reason codes for mismatched or unavailable fields",
    )
    required_fields: List[str] = Field(
        default_factory=list,
        description="Fields required by host specification",
    )
    name_similarity_score: Optional[float] = Field(
        default=None,
        description="Underlying name similarity score (kept backend-only)",
    )
    is_mismatch_cancelled: bool = Field(
        default=False,
        description="Must always be False; strong name score can NEVER cancel a mismatch",
    )
    is_missing_evidence_cancelled: bool = Field(
        default=False,
        description="Must always be False; strong name score can NEVER cancel missing evidence",
    )


# ---------------------------------------------------------------------------
# Invariant Verifiers & Protection Functions
# ---------------------------------------------------------------------------


def assert_strong_name_never_cancels_mismatch(
    matches: Dict[str, FieldMatchOutcome],
    required_fields: Sequence[str],
    name_score: Optional[float] = None,
) -> bool:
    """Verify the invariant: a strong name score NEVER cancels a required mismatch.

    Args:
        matches: Dict of field match outcomes (e.g. {'full_name': True, 'date_of_birth': False}).
        required_fields: Sequence of required field identifiers.
        name_score: Optional high similarity score (e.g. 1.0 or 0.99).

    Returns:
        True if the non-cancellation invariant is strictly satisfied.

    Raises:
        ValueError: If a required mismatch was cancelled by a strong name score.
    """
    overall = compute_overall_matching_status(dict(matches), list(required_fields))

    has_required_mismatch = any(matches.get(f) is False for f in required_fields)

    if has_required_mismatch and overall != "mismatched":
        score_desc = f" (score={name_score})" if name_score is not None else ""
        raise ValueError(
            f"Invariant violation: Strong name match{score_desc} attempted to cancel a required mismatch. "
            f"Overall status was '{overall}', expected 'mismatched'."
        )

    return True


def assert_strong_name_never_cancels_missing_evidence(
    matches: Dict[str, FieldMatchOutcome],
    required_fields: Sequence[str],
    name_score: Optional[float] = None,
) -> bool:
    """Verify the invariant: a strong name score NEVER cancels missing evidence.

    Args:
        matches: Dict of field match outcomes (e.g. {'full_name': True, 'date_of_birth': None}).
        required_fields: Sequence of required field identifiers.
        name_score: Optional high similarity score (e.g. 1.0 or 0.99).

    Returns:
        True if the non-cancellation invariant is strictly satisfied.

    Raises:
        ValueError: If missing evidence was cancelled or promoted to matched by a strong name score.
    """
    overall = compute_overall_matching_status(dict(matches), list(required_fields))

    has_required_missing = any(matches.get(f) is None for f in required_fields)
    has_required_mismatch = any(matches.get(f) is False for f in required_fields)

    if has_required_missing and not has_required_mismatch and overall != "unavailable":
        score_desc = f" (score={name_score})" if name_score is not None else ""
        raise ValueError(
            f"Invariant violation: Strong name match{score_desc} attempted to cancel missing evidence. "
            f"Overall status was '{overall}', expected 'unavailable'."
        )

    return True


def evaluate_protected_checks(
    matches: Dict[str, FieldMatchOutcome],
    reasons: Dict[str, str],
    required_fields: Optional[Sequence[str]] = None,
    name_similarity_score: Optional[float] = None,
) -> ProtectedCheckResult:
    """Evaluate multiple field checks enforcing independence and non-cancellation invariants.

    Guarantees:
    1. Independent evaluation: DOB, full_name, and other required checks are evaluated orthogonally.
    2. No cross-field score averaging: high name similarity does not compensate for a DOB discrepancy.
    3. Mismatch protection: if DOB (or any required check) is False, overall status is 'mismatched'.
    4. Missing evidence protection: if DOB (or any required check) is None, overall status is 'unavailable'.
    """
    effective_reqs = list(required_fields or matches.keys())

    # Compute deterministic overall status
    overall_status = compute_overall_matching_status(matches, effective_reqs)

    # Verify strict non-cancellation invariants
    assert_strong_name_never_cancels_mismatch(matches, effective_reqs, name_score=name_similarity_score)
    assert_strong_name_never_cancels_missing_evidence(matches, effective_reqs, name_score=name_similarity_score)

    return ProtectedCheckResult(
        protection_spec_version=PROTECTION_SPEC_VERSION,
        overall_status=overall_status,
        matches=dict(matches),
        reasons=dict(reasons),
        required_fields=effective_reqs,
        name_similarity_score=name_similarity_score,
        is_mismatch_cancelled=False,
        is_missing_evidence_cancelled=False,
    )

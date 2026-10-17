"""Ethiopian name structure preservation and ordered component comparison (guide5 Task 07).

Per guide5 specification:
- Compare ordered name components (given name, father's name, grandfather's name).
- Do NOT treat Ethiopian patronymics as Western surnames.
- Do NOT silently reorder or drop tokens.
- Never approve from a single shared token.
- Transposed components (e.g. given <-> father) are strict mismatches.
- Missing components (e.g. 2 tokens vs 3 tokens) require review or mismatch, never silent approval.
"""

from typing import Any, Dict, List, Optional, Sequence, Tuple
from pydantic import BaseModel, ConfigDict, Field

from fayda_mcp.matching.normalization import NormalizedName, normalize_name_safely
from fayda_mcp.matching.profiles import (
    NAME_MATCH_APPROVED_EQUIVALENT,
    NAME_MATCH_EXACT,
    NAME_MATCH_MISMATCH,
    NAME_MATCH_REVIEW_REQUIRED,
    NAME_MATCH_UNAVAILABLE,
)
from fayda_mcp.matching.variations import is_approved_token_variation

# ---------------------------------------------------------------------------
# Constants & Safe Reason Codes
# ---------------------------------------------------------------------------

STRUCTURE_SPEC_VERSION: str = "structure-v1"

REASON_TRANSPOSED_COMPONENTS: str = "transposed_name_components"
REASON_MISSING_COMPONENT: str = "missing_name_component"
REASON_CONFLICTING_GIVEN_NAME: str = "conflicting_given_name"
REASON_CONFLICTING_FATHER_NAME: str = "conflicting_father_name"
REASON_CONFLICTING_GRANDFATHER_NAME: str = "conflicting_grandfather_name"
REASON_CONFLICTING_COMPONENTS: str = "conflicting_name_components"
REASON_SINGLE_TOKEN_SHARED_ONLY: str = "single_token_match_disallowed"
REASON_TOKEN_COUNT_MISMATCH: str = "token_count_mismatch"


# ---------------------------------------------------------------------------
# Structured Name Models
# ---------------------------------------------------------------------------


class EthiopianNameStructure(BaseModel):
    """Structured representation of ordered Ethiopian name components."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    given_name: str = Field(..., description="Given name (first token)")
    father_name: Optional[str] = Field(default=None, description="Father's patronymic name (second token)")
    grandfather_name: Optional[str] = Field(default=None, description="Grandfather's name (third token)")
    additional_tokens: List[str] = Field(default_factory=list, description="Additional tokens beyond grandfather")
    raw_tokens: List[str] = Field(..., description="Ordered list of all normalized tokens")
    token_count: int = Field(..., description="Total number of name tokens")


class ComponentComparison(BaseModel):
    """Comparison outcome for an individual ordered component position."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    position: int = Field(..., description="0-indexed position: 0=given, 1=father, 2=grandfather")
    position_name: str = Field(..., description="Semantic position: 'given', 'father', 'grandfather'")
    token_expected: Optional[str] = Field(default=None, description="Expected component token")
    token_provider: Optional[str] = Field(default=None, description="Provider component token")
    is_match: bool = Field(..., description="Whether tokens match (exact or approved variation)")
    match_method: Optional[str] = Field(default=None, description="Method: 'exact', 'reviewed_example', rule_id")


class StructureComparisonResult(BaseModel):
    """Detailed result of comparing ordered Ethiopian name structures."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    is_compatible: bool = Field(..., description="True if ordered structures match fully without structural conflict")
    status: str = Field(..., description="Outcome status: exact, approved_equivalent, review_required, mismatch")
    reason: Optional[str] = Field(default=None, description="Safe machine-readable structural reason code")
    is_transposed: bool = Field(default=False, description="True if given and father/patronymic tokens are inverted")
    is_single_token_shared_only: bool = Field(default=False, description="True if only 1 token matches out of multiple")
    has_missing_component: bool = Field(default=False, description="True if token counts differ (e.g. 2 vs 3 tokens)")
    token_count_expected: int = Field(..., description="Number of tokens in expected name")
    token_count_provider: int = Field(..., description="Number of tokens in provider name")
    component_comparisons: List[ComponentComparison] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Parser Function
# ---------------------------------------------------------------------------


def parse_ethiopian_name_structure(name: Optional[str]) -> Optional[EthiopianNameStructure]:
    """Parse citizen name string into ordered Ethiopian name components.

    Enforces:
    - Token 0 is always the Given Name.
    - Token 1 is the Father's Name (patronymic, NEVER a Western surname).
    - Token 2 is the Grandfather's Name (if present).
    - Preserves exact input token order.

    Args:
        name: Citizen name string.

    Returns:
        EthiopianNameStructure or None if input is empty or invalid.
    """
    if name is None:
        return None

    norm = normalize_name_safely(name)
    if norm is None or not norm.tokens:
        return None

    tokens = norm.tokens
    given = tokens[0]
    father = tokens[1] if len(tokens) > 1 else None
    grandfather = tokens[2] if len(tokens) > 2 else None
    additional = tokens[3:] if len(tokens) > 3 else []

    return EthiopianNameStructure(
        given_name=given,
        father_name=father,
        grandfather_name=grandfather,
        additional_tokens=additional,
        raw_tokens=tokens,
        token_count=len(tokens),
    )


# ---------------------------------------------------------------------------
# Ordered Component Comparison Engine
# ---------------------------------------------------------------------------


def compare_ethiopian_name_structures(
    expected_name: Optional[str],
    provider_name: Optional[str],
) -> StructureComparisonResult:
    """Compare ordered Ethiopian name components strictly preserving structure.

    Guarantees:
    1. NEVER treats patronymics as Western surnames.
    2. NEVER silently drops or ignores missing components.
    3. NEVER silently reorders or permits inverted/transposed components.
    4. NEVER approves identity from a single shared token.

    Args:
        expected_name: Expected citizen name string.
        provider_name: Provider citizen name string.

    Returns:
        StructureComparisonResult with detailed diagnostic flags.
    """
    struct_exp = parse_ethiopian_name_structure(expected_name)
    struct_prov = parse_ethiopian_name_structure(provider_name)

    if struct_exp is None or struct_prov is None:
        return StructureComparisonResult(
            is_compatible=False,
            status=NAME_MATCH_UNAVAILABLE,
            reason="missing_name_data",
            token_count_expected=struct_exp.token_count if struct_exp else 0,
            token_count_provider=struct_prov.token_count if struct_prov else 0,
        )

    tokens_exp = struct_exp.raw_tokens
    tokens_prov = struct_prov.raw_tokens
    count_exp = len(tokens_exp)
    count_prov = len(tokens_prov)

    # 1. Check Transposition (e.g. given <-> father inversion like "Abebe Bikila" vs "Bikila Abebe")
    # In Ethiopian naming, this is two completely different citizens (son vs father).
    if count_exp >= 2 and count_prov >= 2:
        given_match_prov_father, _ = is_approved_token_variation(tokens_exp[0], tokens_prov[1])
        father_match_prov_given, _ = is_approved_token_variation(tokens_exp[1], tokens_prov[0])
        if given_match_prov_father and father_match_prov_given:
            return StructureComparisonResult(
                is_compatible=False,
                status=NAME_MATCH_MISMATCH,
                reason=REASON_TRANSPOSED_COMPONENTS,
                is_transposed=True,
                token_count_expected=count_exp,
                token_count_provider=count_prov,
            )

    # 2. Check Token Count Discrepancy (e.g. 2 tokens vs 3 tokens)
    # Per guide5 Task 07 & 09: Do not silently drop tokens. Missing components require review or mismatch.
    if count_exp != count_prov:
        min_count = min(count_exp, count_prov)
        # Check if shared prefix matches
        prefix_matches = True
        for i in range(min_count):
            is_m, _ = is_approved_token_variation(tokens_exp[i], tokens_prov[i])
            if not is_m:
                prefix_matches = False
                break

        if prefix_matches and min_count >= 2:
            # Prefix matches but 3rd token is missing -> requires review (cannot auto-approve)
            return StructureComparisonResult(
                is_compatible=False,
                status=NAME_MATCH_REVIEW_REQUIRED,
                reason=REASON_MISSING_COMPONENT,
                has_missing_component=True,
                token_count_expected=count_exp,
                token_count_provider=count_prov,
            )
        else:
            # Token counts differ and prefix does not match -> mismatch
            return StructureComparisonResult(
                is_compatible=False,
                status=NAME_MATCH_MISMATCH,
                reason=REASON_TOKEN_COUNT_MISMATCH,
                has_missing_component=True,
                token_count_expected=count_exp,
                token_count_provider=count_prov,
            )

    # 3. Position-by-Position Ordered Comparison
    pos_names = ["given", "father", "grandfather", "additional"]
    comparisons: List[ComponentComparison] = []
    matched_positions: List[int] = []
    unmatched_positions: List[int] = []
    applied_methods: List[str] = []

    for i in range(count_exp):
        tok_e = tokens_exp[i]
        tok_p = tokens_prov[i]
        pos_label = pos_names[i] if i < len(pos_names) else f"token_{i}"

        if tok_e == tok_p:
            comparisons.append(
                ComponentComparison(
                    position=i,
                    position_name=pos_label,
                    token_expected=tok_e,
                    token_provider=tok_p,
                    is_match=True,
                    match_method="exact",
                )
            )
            matched_positions.append(i)
            applied_methods.append("exact")
        else:
            is_m, method = is_approved_token_variation(tok_e, tok_p)
            comparisons.append(
                ComponentComparison(
                    position=i,
                    position_name=pos_label,
                    token_expected=tok_e,
                    token_provider=tok_p,
                    is_match=is_m,
                    match_method=method,
                )
            )
            if is_m:
                matched_positions.append(i)
                if method:
                    applied_methods.append(method)
            else:
                unmatched_positions.append(i)

    # 4. Check for Single-Token-Only Match (Disallow single shared token approval)
    # E.g., sharing father's name but different given name, or sharing given name but different father.
    if len(matched_positions) == 1 and count_exp >= 2:
        matched_idx = matched_positions[0]
        if matched_idx == 1:
            # Shared father's name, but different given name (e.g. brothers / different people)
            reason = REASON_CONFLICTING_GIVEN_NAME
        elif matched_idx == 0:
            # Shared given name, but different father (e.g. unrelated people)
            reason = REASON_CONFLICTING_FATHER_NAME
        else:
            reason = REASON_SINGLE_TOKEN_SHARED_ONLY

        return StructureComparisonResult(
            is_compatible=False,
            status=NAME_MATCH_MISMATCH,
            reason=reason,
            is_single_token_shared_only=True,
            token_count_expected=count_exp,
            token_count_provider=count_prov,
            component_comparisons=comparisons,
        )

    # 5. Check Multiple Conflicting Components
    if len(unmatched_positions) > 0:
        if 0 in unmatched_positions:
            reason = REASON_CONFLICTING_GIVEN_NAME
        elif 1 in unmatched_positions:
            reason = REASON_CONFLICTING_FATHER_NAME
        elif 2 in unmatched_positions:
            reason = REASON_CONFLICTING_GRANDFATHER_NAME
        else:
            reason = REASON_CONFLICTING_COMPONENTS

        return StructureComparisonResult(
            is_compatible=False,
            status=NAME_MATCH_MISMATCH,
            reason=reason,
            token_count_expected=count_exp,
            token_count_provider=count_prov,
            component_comparisons=comparisons,
        )

    # 6. All Components Matched in Exact Order
    # Determine if exact or approved_equivalent
    is_all_exact = all(c.match_method == "exact" for c in comparisons)
    final_status = NAME_MATCH_EXACT if is_all_exact else NAME_MATCH_APPROVED_EQUIVALENT

    return StructureComparisonResult(
        is_compatible=True,
        status=final_status,
        reason=None,
        token_count_expected=count_exp,
        token_count_provider=count_prov,
        component_comparisons=comparisons,
    )

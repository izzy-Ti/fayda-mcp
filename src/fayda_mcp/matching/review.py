"""Review and mismatch outcome evaluator for Ethiopian name matching (guide5 Task 09).

Per guide5 specification:
- Phonetic-only agreement requires review (never automatic approval, matches.full_name=None).
- Missing components (e.g. 2 vs 3 tokens) require review (never silent dropping).
- Initials in name (e.g. 'A. Bikila', 'Abebe B.') require review (matches.full_name=None).
- Conflicting components require mismatch (matches.full_name=False).
- Never approve from a single shared token (e.g. shared father or shared given name).
"""

from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, ConfigDict, Field

from fayda_mcp.matching.normalization import normalize_name_safely
from fayda_mcp.matching.phonetics import are_phonetically_similar
from fayda_mcp.matching.profiles import (
    METHOD_APPROVED_VARIATION,
    METHOD_EXACT_NORMALIZED,
    METHOD_PHONETIC,
    METHOD_TRANSLITERATION,
    NAME_MATCH_APPROVED_EQUIVALENT,
    NAME_MATCH_EXACT,
    NAME_MATCH_MISMATCH,
    NAME_MATCH_REVIEW_REQUIRED,
    NAME_MATCH_UNAVAILABLE,
)
from fayda_mcp.matching.structure import (
    REASON_CONFLICTING_COMPONENTS,
    REASON_CONFLICTING_FATHER_NAME,
    REASON_CONFLICTING_GIVEN_NAME,
    REASON_CONFLICTING_GRANDFATHER_NAME,
    REASON_MISSING_COMPONENT,
    REASON_SINGLE_TOKEN_SHARED_ONLY,
    REASON_TOKEN_COUNT_MISMATCH,
    REASON_TRANSPOSED_COMPONENTS,
    compare_ethiopian_name_structures,
    parse_ethiopian_name_structure,
)
from fayda_mcp.matching.variations import _has_ethiopic_chars, is_approved_token_variation

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REVIEW_SPEC_VERSION: str = "review-v1"

REASON_PHONETIC_ONLY_AGREEMENT: str = "phonetic_only_agreement"
REASON_INITIALS_IN_NAME: str = "initials_in_name"


class ReviewEvaluationResult(BaseModel):
    """Detailed evaluation result for review outcomes vs approved/mismatch."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: str = Field(..., description="exact, approved_equivalent, review_required, mismatch")
    method: Optional[str] = Field(default=None, description="exact_normalized, approved_variation, phonetic")
    reason: Optional[str] = Field(default=None, description="Safe machine-readable reason code")
    is_phonetic_only: bool = Field(default=False, description="True if agreement is phonetic-only")
    has_initials: bool = Field(default=False, description="True if one of the names contains initials")
    has_missing_component: bool = Field(default=False, description="True if token count differs")
    is_transposed: bool = Field(default=False, description="True if components are inverted/transposed")
    is_single_token_shared_only: bool = Field(default=False, description="True if only 1 token matches")
    matches_full_name: Optional[bool] = Field(
        default=None,
        description="Tri-state outcome for matches['full_name']: True, False, or None",
    )


# ---------------------------------------------------------------------------
# Initials Detection Helpers
# ---------------------------------------------------------------------------


def is_initial_token(token: str) -> bool:
    """Check if a token represents an initial (e.g. 'A', 'A.', 'B', 'B.')."""
    clean = token.strip().lower()
    if not clean:
        return False
    # Single letter: 'a', 'b', etc.
    if len(clean) == 1 and clean.isalpha():
        return True
    # Single letter with period: 'a.', 'b.'
    if len(clean) == 2 and clean[0].isalpha() and clean[1] == ".":
        return True
    return False


def matches_initial(initial_tok: str, full_tok: str) -> bool:
    """Check if an initial token matches the first letter of a full component token."""
    clean_init = initial_tok.strip().lower().rstrip(".")
    clean_full = full_tok.strip().lower()
    if not clean_init or not clean_full:
        return False
    return clean_init[0] == clean_full[0]


# ---------------------------------------------------------------------------
# Master Review Outcomes Evaluator
# ---------------------------------------------------------------------------


def evaluate_review_outcomes(
    expected_name: Optional[str],
    provider_name: Optional[str],
) -> ReviewEvaluationResult:
    """Evaluate full name comparison against strict review, approved, and mismatch rules.

    Rules:
    1. Transposed patronymic components -> mismatch ('transposed_name_components', matches=False).
    2. Single shared token only (e.g. same father, different given name) -> mismatch (matches=False).
    3. Initials in name -> review_required ('initials_in_name', matches=None).
    4. Missing component (e.g. 2 tokens vs 3 tokens) -> review_required ('missing_name_component', matches=None).
    5. Phonetic-only agreement without approved spelling/transliteration -> review_required ('phonetic_only_agreement', method='phonetic', matches=None).
    6. Conflicting components -> mismatch (matches=False).
    7. All components match exactly or via approved variation -> approved_equivalent or exact (matches=True).
    """
    struct_exp = parse_ethiopian_name_structure(expected_name)
    struct_prov = parse_ethiopian_name_structure(provider_name)

    if struct_exp is None or struct_prov is None:
        return ReviewEvaluationResult(
            status=NAME_MATCH_UNAVAILABLE,
            reason="missing_name_data",
            matches_full_name=None,
        )

    tokens_exp = struct_exp.raw_tokens
    tokens_prov = struct_prov.raw_tokens
    count_exp = len(tokens_exp)
    count_prov = len(tokens_prov)

    # 1. Check Transposition (e.g. given <-> father inversion like "Abebe Bikila" vs "Bikila Abebe")
    if count_exp >= 2 and count_prov >= 2:
        given_m_father, _ = is_approved_token_variation(tokens_exp[0], tokens_prov[1])
        father_m_given, _ = is_approved_token_variation(tokens_exp[1], tokens_prov[0])
        if given_m_father and father_m_given:
            return ReviewEvaluationResult(
                status=NAME_MATCH_MISMATCH,
                reason=REASON_TRANSPOSED_COMPONENTS,
                is_transposed=True,
                matches_full_name=False,
            )

    # 2. Check for Initials in Name
    has_initials = any(is_initial_token(t) for t in tokens_exp) or any(is_initial_token(t) for t in tokens_prov)
    if has_initials:
        # Check if initials are consistent with the components
        min_c = min(count_exp, count_prov)
        initials_consistent = True
        for i in range(min_c):
            t_e = tokens_exp[i]
            t_p = tokens_prov[i]
            if is_initial_token(t_e) and not is_initial_token(t_p):
                if not matches_initial(t_e, t_p):
                    initials_consistent = False
                    break
            elif is_initial_token(t_p) and not is_initial_token(t_e):
                if not matches_initial(t_p, t_e):
                    initials_consistent = False
                    break
            elif is_initial_token(t_e) and is_initial_token(t_p):
                if t_e.rstrip(".") != t_p.rstrip("."):
                    initials_consistent = False
                    break
            else:
                is_m, _ = is_approved_token_variation(t_e, t_p)
                if not is_m:
                    initials_consistent = False
                    break

        if initials_consistent:
            # Consistent initials require human review, never automatic approval
            return ReviewEvaluationResult(
                status=NAME_MATCH_REVIEW_REQUIRED,
                reason=REASON_INITIALS_IN_NAME,
                has_initials=True,
                matches_full_name=None,
            )
        else:
            # Conflicting initials are a direct mismatch
            return ReviewEvaluationResult(
                status=NAME_MATCH_MISMATCH,
                reason=REASON_CONFLICTING_COMPONENTS,
                has_initials=True,
                matches_full_name=False,
            )

    # 3. Check Token Count Discrepancy (Missing Components)
    if count_exp != count_prov:
        min_c = min(count_exp, count_prov)
        prefix_matches = True
        for i in range(min_c):
            is_m, _ = is_approved_token_variation(tokens_exp[i], tokens_prov[i])
            if not is_m:
                prefix_matches = False
                break

        if prefix_matches and min_c >= 2:
            return ReviewEvaluationResult(
                status=NAME_MATCH_REVIEW_REQUIRED,
                reason=REASON_MISSING_COMPONENT,
                has_missing_component=True,
                matches_full_name=None,
            )
        else:
            return ReviewEvaluationResult(
                status=NAME_MATCH_MISMATCH,
                reason=REASON_TOKEN_COUNT_MISMATCH,
                has_missing_component=True,
                matches_full_name=False,
            )

    # 4. Position-by-position analysis for identical token count
    approved_matches = []
    phonetic_only_matches = []
    unmatched = []

    for i in range(count_exp):
        te = tokens_exp[i]
        tp = tokens_prov[i]

        if te == tp:
            approved_matches.append(i)
            continue

        is_appr, rule_id = is_approved_token_variation(te, tp)
        if is_appr:
            approved_matches.append(i)
            continue

        # Check phonetic similarity
        dm_m, eth_m, _ = are_phonetically_similar(te, tp)
        if dm_m or eth_m:
            phonetic_only_matches.append(i)
        else:
            unmatched.append(i)

    # 5. Check Single Shared Token Only (Never approve from a single shared token)
    # If father's name matches but given name is not an approved variation:
    # In Ethiopian naming, a citizen is identified by their given name. Sharing only a patronymic
    # with a non-approved given name is a conflicting given name mismatch (never phonetic agreement).
    if count_exp >= 2 and 0 not in approved_matches and 1 in approved_matches and len(approved_matches) == 1:
        return ReviewEvaluationResult(
            status=NAME_MATCH_MISMATCH,
            reason=REASON_CONFLICTING_GIVEN_NAME,
            is_single_token_shared_only=True,
            matches_full_name=False,
        )

    if len(approved_matches) == 1 and count_exp >= 2 and len(phonetic_only_matches) == 0:
        matched_idx = approved_matches[0]
        if matched_idx == 1:
            reason = REASON_CONFLICTING_GIVEN_NAME
        elif matched_idx == 0:
            reason = REASON_CONFLICTING_FATHER_NAME
        else:
            reason = REASON_SINGLE_TOKEN_SHARED_ONLY

        return ReviewEvaluationResult(
            status=NAME_MATCH_MISMATCH,
            reason=reason,
            is_single_token_shared_only=True,
            matches_full_name=False,
        )

    # 6. Check Phonetic-Only Agreement
    # If all positions match either approved or phonetically, and at least one is phonetic-only
    if len(approved_matches) + len(phonetic_only_matches) == count_exp and len(phonetic_only_matches) > 0:
        return ReviewEvaluationResult(
            status=NAME_MATCH_REVIEW_REQUIRED,
            method=METHOD_PHONETIC,
            reason=REASON_PHONETIC_ONLY_AGREEMENT,
            is_phonetic_only=True,
            matches_full_name=None,
        )

    # 7. Check Conflicting Components
    if len(unmatched) > 0 or len(phonetic_only_matches) > 0:
        if 0 in unmatched:
            reason = REASON_CONFLICTING_GIVEN_NAME
        elif 1 in unmatched:
            reason = REASON_CONFLICTING_FATHER_NAME
        elif 2 in unmatched:
            reason = REASON_CONFLICTING_GRANDFATHER_NAME
        else:
            reason = REASON_CONFLICTING_COMPONENTS

        return ReviewEvaluationResult(
            status=NAME_MATCH_MISMATCH,
            reason=reason,
            matches_full_name=False,
        )

    # 8. All components match via exact or approved variation
    is_all_exact = all(tokens_exp[i] == tokens_prov[i] for i in range(count_exp))
    if is_all_exact:
        return ReviewEvaluationResult(
            status=NAME_MATCH_EXACT,
            method=METHOD_EXACT_NORMALIZED,
            matches_full_name=True,
        )
    else:
        has_trans = any(
            _has_ethiopic_chars(tokens_exp[i]) != _has_ethiopic_chars(tokens_prov[i])
            for i in range(count_exp)
        )
        method = METHOD_TRANSLITERATION if has_trans else METHOD_APPROVED_VARIATION
        return ReviewEvaluationResult(
            status=NAME_MATCH_APPROVED_EQUIVALENT,
            method=method,
            matches_full_name=True,
        )

"""Similarity feature extraction and multi-evidence scoring for Ethiopian name matching (guide5 Task 08).

Per guide5 specification:
- Combine token-level spelling distance, approved transliteration evidence, and phonetic codes.
- Double Metaphone is a baseline to evaluate, not Ethiopian-ready proof.
- Phonetic similarity alone never proves identity.
- Preserve component order and name structure.
- Similarity scores and features are kept backend-only by default.
"""

from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, ConfigDict, Field

from fayda_mcp.matching.normalization import normalize_name_safely
from fayda_mcp.matching.phonetics import (
    are_phonetically_similar,
    get_token_phonetic_codes,
)
from fayda_mcp.matching.structure import (
    compare_ethiopian_name_structures,
    parse_ethiopian_name_structure,
)
from fayda_mcp.matching.transliteration import transliterate_token
from fayda_mcp.matching.variations import (
    _has_ethiopic_chars,
    is_approved_token_variation,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCORING_SPEC_VERSION: str = "scoring-v1"


# ---------------------------------------------------------------------------
# String Distance & Similarity Algorithms
# ---------------------------------------------------------------------------


def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute the Levenshtein edit distance between two strings."""
    if s1 == s2:
        return 0
    if not s1:
        return len(s2)
    if not s2:
        return len(s1)

    len1, len2 = len(s1), len(s2)
    prev_row = list(range(len2 + 1))
    curr_row = [0] * (len2 + 1)

    for i in range(len1):
        curr_row[0] = i + 1
        ch1 = s1[i]
        for j in range(len2):
            cost = 0 if ch1 == s2[j] else 1
            curr_row[j + 1] = min(
                curr_row[j] + 1,       # insertion
                prev_row[j + 1] + 1,   # deletion
                prev_row[j] + cost,    # substitution
            )
        prev_row[:] = curr_row

    return prev_row[len2]


def levenshtein_similarity(s1: str, s2: str) -> float:
    """Compute normalized Levenshtein similarity in [0.0, 1.0]."""
    if not s1 and not s2:
        return 1.0
    if not s1 or not s2:
        return 0.0
    dist = levenshtein_distance(s1, s2)
    max_len = max(len(s1), len(s2))
    return max(0.0, 1.0 - (dist / max_len))


def jaro_similarity(s1: str, s2: str) -> float:
    """Compute standard Jaro string similarity in [0.0, 1.0]."""
    if s1 == s2:
        return 1.0
    len1, len2 = len(s1), len(s2)
    if len1 == 0 or len2 == 0:
        return 0.0

    match_distance = (max(len1, len2) // 2) - 1
    s1_matches = [False] * len1
    s2_matches = [False] * len2

    matches = 0
    for i in range(len1):
        start = max(0, i - match_distance)
        end = min(i + match_distance + 1, len2)
        for j in range(start, end):
            if s2_matches[j] or s1[i] != s2[j]:
                continue
            s1_matches[i] = True
            s2_matches[j] = True
            matches += 1
            break

    if matches == 0:
        return 0.0

    # Count transpositions
    k = 0
    transpositions = 0
    for i in range(len1):
        if not s1_matches[i]:
            continue
        while not s2_matches[k]:
            k += 1
        if s1[i] != s2[k]:
            transpositions += 1
        k += 1

    transpositions = transpositions // 2
    return (matches / len1 + matches / len2 + (matches - transpositions) / matches) / 3.0


def jaro_winkler_similarity(s1: str, s2: str, prefix_weight: float = 0.1) -> float:
    """Compute Jaro-Winkler similarity with common prefix bonus in [0.0, 1.0]."""
    j_sim = jaro_similarity(s1, s2)
    if j_sim < 0.7:
        return j_sim

    # Find common prefix length (up to 4 characters)
    prefix_len = 0
    for i in range(min(len(s1), len(s2), 4)):
        if s1[i] == s2[i]:
            prefix_len += 1
        else:
            break

    return j_sim + (prefix_len * prefix_weight * (1.0 - j_sim))


# ---------------------------------------------------------------------------
# Feature Data Models
# ---------------------------------------------------------------------------


class TokenSimilarityFeatures(BaseModel):
    """Extracted similarity features for a single token pair."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    token_a: str = Field(..., description="First normalized token")
    token_b: str = Field(..., description="Second normalized token")
    levenshtein_distance: int = Field(..., description="Raw Levenshtein edit distance")
    levenshtein_similarity: float = Field(..., description="Normalized edit similarity [0.0, 1.0]")
    jaro_winkler_similarity: float = Field(..., description="Jaro-Winkler similarity [0.0, 1.0]")
    phonetic_match_double_metaphone: bool = Field(..., description="True if Double Metaphone codes match")
    phonetic_match_ethiopian: bool = Field(..., description="True if Ethiopian phonetic codes match")
    matched_phonetic_code: str = Field(..., description="Matched phonetic code if any")
    has_approved_transliteration_evidence: bool = Field(
        ...,
        description="True if linked via approved transliteration or reviewed variation",
    )
    transliteration_evidence_weight: float = Field(
        ...,
        description="Transliteration evidence weight [0.0, 1.0]",
    )
    rule_or_evidence_id: Optional[str] = Field(
        default=None,
        description="Specific approved rule ID or evidence source",
    )
    composite_similarity: float = Field(..., description="Weighted composite token similarity [0.0, 1.0]")


class NameSimilarityFeatures(BaseModel):
    """Comprehensive similarity features for expected vs provider citizen names."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    expected_name: str = Field(..., description="Expected name string")
    provider_name: str = Field(..., description="Provider name string")
    token_features: List[TokenSimilarityFeatures] = Field(default_factory=list)
    overall_similarity_score: float = Field(..., description="Calibrated aggregate similarity score [0.0, 1.0]")
    is_exact_match: bool = Field(..., description="True if all tokens match identically")
    has_approved_variation: bool = Field(..., description="True if variation is approved under rules")
    is_phonetic_only_agreement: bool = Field(
        ...,
        description="True if tokens agree only phonetically without approved spelling/transliteration",
    )
    is_transposed: bool = Field(default=False, description="True if components are transposed (mismatch)")
    has_missing_component: bool = Field(default=False, description="True if token counts differ")


# ---------------------------------------------------------------------------
# Feature Extraction Engine
# ---------------------------------------------------------------------------


def compute_token_similarity_features(
    token_a: str,
    token_b: str,
) -> TokenSimilarityFeatures:
    """Extract multi-evidence similarity features for a token pair.

    Combines:
    1. Levenshtein edit distance and similarity.
    2. Jaro-Winkler similarity.
    3. Double Metaphone baseline match.
    4. Ethiopian-adapted phonetic match.
    5. Approved transliteration/variation evidence.
    """
    clean_a = token_a.strip().lower()
    clean_b = token_b.strip().lower()

    if clean_a == clean_b:
        return TokenSimilarityFeatures(
            token_a=clean_a,
            token_b=clean_b,
            levenshtein_distance=0,
            levenshtein_similarity=1.0,
            jaro_winkler_similarity=1.0,
            phonetic_match_double_metaphone=True,
            phonetic_match_ethiopian=True,
            matched_phonetic_code="",
            has_approved_transliteration_evidence=True,
            transliteration_evidence_weight=1.0,
            rule_or_evidence_id="exact",
            composite_similarity=1.0,
        )

    # 1. Spelling distances & Phonetic matches
    eth_a = _has_ethiopic_chars(clean_a)
    eth_b = _has_ethiopic_chars(clean_b)

    if eth_a and not eth_b:
        trans_res = transliterate_token(clean_a)
        best_lev_sim = 0.0
        best_jw_sim = 0.0
        best_lev_dist = len(clean_b)
        best_dm = False
        best_eth = False
        best_code = ""
        for var in trans_res.variants:
            v_clean = var.strip().lower()
            l_dist = levenshtein_distance(v_clean, clean_b)
            l_sim = levenshtein_similarity(v_clean, clean_b)
            j_sim = jaro_winkler_similarity(v_clean, clean_b)
            d_m, e_m, c = are_phonetically_similar(v_clean, clean_b)
            if l_sim > best_lev_sim:
                best_lev_sim = l_sim
                best_jw_sim = j_sim
                best_lev_dist = l_dist
                best_dm = d_m
                best_eth = e_m
                best_code = c
        lev_dist = best_lev_dist
        lev_sim = best_lev_sim
        jw_sim = best_jw_sim
        dm_match = best_dm
        eth_match = best_eth
        code = best_code
    elif eth_b and not eth_a:
        trans_res = transliterate_token(clean_b)
        best_lev_sim = 0.0
        best_jw_sim = 0.0
        best_lev_dist = len(clean_a)
        best_dm = False
        best_eth = False
        best_code = ""
        for var in trans_res.variants:
            v_clean = var.strip().lower()
            l_dist = levenshtein_distance(v_clean, clean_a)
            l_sim = levenshtein_similarity(v_clean, clean_a)
            j_sim = jaro_winkler_similarity(v_clean, clean_a)
            d_m, e_m, c = are_phonetically_similar(v_clean, clean_a)
            if l_sim > best_lev_sim:
                best_lev_sim = l_sim
                best_jw_sim = j_sim
                best_lev_dist = l_dist
                best_dm = d_m
                best_eth = e_m
                best_code = c
        lev_dist = best_lev_dist
        lev_sim = best_lev_sim
        jw_sim = best_jw_sim
        dm_match = best_dm
        eth_match = best_eth
        code = best_code
    else:
        lev_dist = levenshtein_distance(clean_a, clean_b)
        lev_sim = levenshtein_similarity(clean_a, clean_b)
        jw_sim = jaro_winkler_similarity(clean_a, clean_b)
        dm_match, eth_match, code = are_phonetically_similar(clean_a, clean_b)

    # 3. Transliteration / approved variation evidence
    has_evidence, rule_id = is_approved_token_variation(clean_a, clean_b)
    if has_evidence:
        if rule_id in ("exact", "reviewed_example"):
            evidence_weight = 1.0
        elif rule_id and rule_id.startswith("rule_"):
            evidence_weight = 0.95
        elif rule_id and "transliteration" in rule_id:
            evidence_weight = 0.90
        else:
            evidence_weight = 0.85
    else:
        evidence_weight = 0.0

    # 4. Composite similarity computation (calibrated weights)
    # Evidence from approved rules/transliteration carries the primary weight (0.50).
    # Spelling similarity carries 0.30, and phonetic codes carry 0.20.
    spelling_score = (lev_sim * 0.4) + (jw_sim * 0.6)
    phonetic_score = (1.0 if eth_match else (0.8 if dm_match else 0.0))

    if has_evidence:
        composite = (evidence_weight * 0.50) + (spelling_score * 0.30) + (phonetic_score * 0.20)
    else:
        # Without approved variation or transliteration, composite is bounded to prevent false approval
        composite = (spelling_score * 0.60) + (phonetic_score * 0.40) * 0.75

    composite = max(0.0, min(1.0, composite))

    return TokenSimilarityFeatures(
        token_a=clean_a,
        token_b=clean_b,
        levenshtein_distance=lev_dist,
        levenshtein_similarity=round(lev_sim, 4),
        jaro_winkler_similarity=round(jw_sim, 4),
        phonetic_match_double_metaphone=dm_match,
        phonetic_match_ethiopian=eth_match,
        matched_phonetic_code=code,
        has_approved_transliteration_evidence=has_evidence,
        transliteration_evidence_weight=evidence_weight,
        rule_or_evidence_id=rule_id,
        composite_similarity=round(composite, 4),
    )


def compute_name_similarity_features(
    expected_name: str,
    provider_name: str,
) -> NameSimilarityFeatures:
    """Compute comprehensive multi-evidence similarity features for full citizen names.

    Enforces:
    - Ordered component alignment (given, father, grandfather).
    - Detects transposition and missing components.
    - Flags phonetic-only agreement where approved evidence is lacking.
    - Aggregates bounded composite scores across ordered tokens.
    """
    struct_exp = parse_ethiopian_name_structure(expected_name)
    struct_prov = parse_ethiopian_name_structure(provider_name)

    if struct_exp is None or struct_prov is None:
        return NameSimilarityFeatures(
            expected_name=expected_name or "",
            provider_name=provider_name or "",
            token_features=[],
            overall_similarity_score=0.0,
            is_exact_match=False,
            has_approved_variation=False,
            is_phonetic_only_agreement=False,
            is_transposed=False,
            has_missing_component=True,
        )

    # Check structural compatibility via structure module
    struct_comp = compare_ethiopian_name_structures(expected_name, provider_name)

    tokens_exp = struct_exp.raw_tokens
    tokens_prov = struct_prov.raw_tokens
    min_count = min(len(tokens_exp), len(tokens_prov))

    token_features_list: List[TokenSimilarityFeatures] = []
    for i in range(min_count):
        tf = compute_token_similarity_features(tokens_exp[i], tokens_prov[i])
        token_features_list.append(tf)

    # Overall similarity score is the average token similarity penalized if counts differ
    if token_features_list:
        avg_score = sum(tf.composite_similarity for tf in token_features_list) / len(token_features_list)
    else:
        avg_score = 0.0

    # Penalize if token counts differ or if components are transposed
    if struct_comp.is_transposed:
        overall_score = 0.0
    elif struct_comp.has_missing_component:
        overall_score = avg_score * 0.70  # Bounded penalty for missing grandfather component
    else:
        overall_score = avg_score

    # Check for phonetic-only agreement (phonetics match, but not approved evidence)
    is_phonetic_only = False
    if not struct_comp.is_compatible and not struct_comp.is_transposed:
        any_phonetic = any(tf.phonetic_match_ethiopian or tf.phonetic_match_double_metaphone for tf in token_features_list)
        all_unapproved = all(not tf.has_approved_transliteration_evidence for tf in token_features_list)
        if any_phonetic and all_unapproved:
            is_phonetic_only = True

    return NameSimilarityFeatures(
        expected_name=expected_name,
        provider_name=provider_name,
        token_features=token_features_list,
        overall_similarity_score=round(overall_score, 4),
        is_exact_match=(struct_comp.status == "exact"),
        has_approved_variation=(struct_comp.status == "approved_equivalent"),
        is_phonetic_only_agreement=is_phonetic_only,
        is_transposed=struct_comp.is_transposed,
        has_missing_component=struct_comp.has_missing_component,
    )

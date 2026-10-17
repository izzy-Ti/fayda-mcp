"""Unit tests for similarity features, spelling distance, and phonetic codes (guide5 Task 08).

Verifies:
- Double Metaphone baseline evaluation.
- Ethiopian-adapted phonetic encoding.
- Token-level Levenshtein and Jaro-Winkler spelling distance and similarity.
- Multi-evidence feature extraction combining spelling distance, approved transliteration evidence,
  and phonetic codes.
- Structure-aware scoring (transposition penalized to 0.0, missing components penalized,
  single-token shared names rejected).
"""

import pytest

from fayda_mcp.matching.phonetics import (
    PHONETICS_SPEC_VERSION,
    are_phonetically_similar,
    compute_double_metaphone,
    compute_ethiopian_phonetic_code,
    get_token_phonetic_codes,
)
from fayda_mcp.matching.scoring import (
    SCORING_SPEC_VERSION,
    compute_name_similarity_features,
    compute_token_similarity_features,
    jaro_similarity,
    jaro_winkler_similarity,
    levenshtein_distance,
    levenshtein_similarity,
)


def test_spec_versions():
    """Verify spec versions for phonetics and scoring."""
    assert PHONETICS_SPEC_VERSION == "phonetics-v1"
    assert SCORING_SPEC_VERSION == "scoring-v1"


# ---------------------------------------------------------------------------
# 1. Double Metaphone Baseline Tests
# ---------------------------------------------------------------------------


def test_double_metaphone_baseline():
    """Double Metaphone produces baseline phonetic codes."""
    prim_abebe, sec_abebe = compute_double_metaphone("Abebe")
    prim_abbebe, sec_abbebe = compute_double_metaphone("Abbebe")
    # Both start with P (Double Metaphone maps B -> P)
    assert prim_abebe == prim_abbebe
    assert prim_abebe.startswith("AP")

    prim_smith, sec_smith = compute_double_metaphone("Smith")
    assert prim_smith.startswith("SM")

    prim_bikila, sec_bikila = compute_double_metaphone("Bikila")
    assert prim_bikila.startswith("PKL")

    # Empty token returns empty codes
    assert compute_double_metaphone("") == ("", "")


# ---------------------------------------------------------------------------
# 2. Ethiopian-Adapted Phonetic Tests
# ---------------------------------------------------------------------------


def test_ethiopian_phonetic_code_gemination_and_prefixes():
    """Ethiopian phonetic encoding handles gemination and prefix variations."""
    # Gemination neutralization
    assert compute_ethiopian_phonetic_code("abebe") == compute_ethiopian_phonetic_code("abbebe")
    assert compute_ethiopian_phonetic_code("debebe") == compute_ethiopian_phonetic_code("debbebe")
    assert compute_ethiopian_phonetic_code("tadese") == compute_ethiopian_phonetic_code("taddese")

    # Wolde / Welde prefix normalization
    assert compute_ethiopian_phonetic_code("wolde") == compute_ethiopian_phonetic_code("welde")
    assert compute_ethiopian_phonetic_code("worku") == compute_ethiopian_phonetic_code("werku")

    # Haile / Hayle prefix normalization
    assert compute_ethiopian_phonetic_code("haile") == compute_ethiopian_phonetic_code("hayle")

    # K / Q alternation
    assert compute_ethiopian_phonetic_code("bikila") == compute_ethiopian_phonetic_code("biqila")
    assert compute_ethiopian_phonetic_code("bekele") == compute_ethiopian_phonetic_code("beqele")


def test_are_phonetically_similar():
    """are_phonetically_similar tests both DM and Ethiopian codes."""
    dm_m, eth_m, code = are_phonetically_similar("Abebe", "Abbebe")
    assert dm_m is True
    assert eth_m is True
    assert code != ""

    dm_w, eth_w, code_w = are_phonetically_similar("Wolde", "Welde")
    assert eth_w is True

    # Completely different names are not phonetically similar
    dm_diff, eth_diff, _ = are_phonetically_similar("Abebe", "Kenenisa")
    assert dm_diff is False
    assert eth_diff is False


# ---------------------------------------------------------------------------
# 3. String Distance & Similarity Tests
# ---------------------------------------------------------------------------


def test_levenshtein_distance_and_similarity():
    """Verify Levenshtein distance and normalized similarity."""
    assert levenshtein_distance("abebe", "abbebe") == 1
    assert levenshtein_distance("abebe", "abebe") == 0
    assert levenshtein_distance("", "test") == 4

    assert levenshtein_similarity("abebe", "abebe") == 1.0
    sim_diff = levenshtein_similarity("abebe", "abbebe")
    assert 0.8 < sim_diff < 1.0
    assert levenshtein_similarity("abebe", "xyz") == 0.0


def test_jaro_and_jaro_winkler():
    """Verify Jaro and Jaro-Winkler similarity."""
    assert jaro_similarity("abebe", "abebe") == 1.0
    assert jaro_winkler_similarity("abebe", "abebe") == 1.0

    jw_sim = jaro_winkler_similarity("abebe", "abbebe")
    assert jw_sim > 0.90

    jw_pref = jaro_winkler_similarity("wolde", "welde")
    assert jw_pref > 0.80

    assert jaro_similarity("", "test") == 0.0


# ---------------------------------------------------------------------------
# 4. Token Similarity Features
# ---------------------------------------------------------------------------


def test_token_similarity_features_exact():
    """Identical tokens produce perfect similarity features."""
    feat = compute_token_similarity_features("Abebe", "abebe")
    assert feat.levenshtein_distance == 0
    assert feat.levenshtein_similarity == 1.0
    assert feat.jaro_winkler_similarity == 1.0
    assert feat.phonetic_match_double_metaphone is True
    assert feat.phonetic_match_ethiopian is True
    assert feat.has_approved_transliteration_evidence is True
    assert feat.composite_similarity == 1.0


def test_token_similarity_features_approved_variation():
    """Approved variations combine spelling, phonetic, and transliteration evidence."""
    feat = compute_token_similarity_features("Abebe", "Abbebe")
    assert feat.has_approved_transliteration_evidence is True
    assert feat.phonetic_match_ethiopian is True
    assert feat.composite_similarity >= 0.90
    assert feat.rule_or_evidence_id is not None

    feat_q = compute_token_similarity_features("Bikila", "Biqila")
    assert feat_q.has_approved_transliteration_evidence is True
    assert feat_q.phonetic_match_ethiopian is True
    assert feat_q.composite_similarity >= 0.90


def test_token_similarity_features_unapproved_divergence():
    """Unapproved tokens receive lower composite similarity."""
    feat = compute_token_similarity_features("Abebe", "Ababa")
    assert feat.has_approved_transliteration_evidence is False
    assert feat.composite_similarity < 0.85


# ---------------------------------------------------------------------------
# 5. Full Name Similarity Features
# ---------------------------------------------------------------------------


def test_name_similarity_features_exact_match():
    """Full exact name match yields perfect similarity score."""
    name_feat = compute_name_similarity_features("Abebe Bikila", "Abebe Bikila")
    assert name_feat.is_exact_match is True
    assert name_feat.overall_similarity_score == 1.0
    assert len(name_feat.token_features) == 2


def test_name_similarity_features_approved_variation():
    """Approved multi-token variation yields high similarity score."""
    name_feat = compute_name_similarity_features("Abebe Bikila", "Abbebe Biqila")
    assert name_feat.has_approved_variation is True
    assert name_feat.overall_similarity_score >= 0.90
    assert name_feat.is_transposed is False


def test_name_similarity_features_transposed_penalized_to_zero():
    """Transposed patronymic components are penalized to 0.0 overall score."""
    name_feat = compute_name_similarity_features("Abebe Bikila", "Bikila Abebe")
    assert name_feat.is_transposed is True
    assert name_feat.overall_similarity_score == 0.0


def test_name_similarity_features_missing_component():
    """Missing grandfather component is flagged and penalized."""
    name_feat = compute_name_similarity_features("Abebe Bikila Welde", "Abebe Bikila")
    assert name_feat.has_missing_component is True
    assert name_feat.overall_similarity_score < 0.80


def test_name_similarity_features_different_citizens():
    """Citizens sharing only father's name or given name receive lower composite score."""
    # Shared father name (patronymic)
    name_feat = compute_name_similarity_features("Abebe Bikila", "Kenenisa Bikila")
    assert name_feat.is_exact_match is False
    assert name_feat.has_approved_variation is False
    assert name_feat.overall_similarity_score < 0.70

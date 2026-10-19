"""Unit tests for evaluation and release gating of Ethiopian name matching (guide5 Task 15).

Verifies:
1. Leakage-free person splitting: zero overlap of person clusters between train and eval.
2. Reporting false-match (FMR), false-nonmatch (FNMR), review rate, and script/language coverage.
3. Subgroup metrics for ethiopic_to_latin, latin_to_latin, and ethiopic_to_ethiopic homophones.
4. Comparison with strict baseline: demonstrates dramatic FNMR reduction without FMR compromise.
5. Release gating: verifies conditions for safe release and automatic approved-equivalent outcomes.
"""

import pytest

from fayda_mcp.matching.evaluation import (
    EVALUATION_SPEC_VERSION,
    ProfileEvaluationReport,
    ReleaseGateReport,
    SubgroupMetrics,
    compute_partition_metrics,
    evaluate_and_gate_release,
    evaluate_profile_on_dataset,
    evaluate_single_pair,
)
from fayda_mcp.matching.fixtures import (
    RepresentativeFixtureDataset,
    RepresentativeNamePair,
    load_representative_fixtures,
)
from fayda_mcp.matching.profiles import PROFILE_ETHIOPIAN_NAME_V1, PROFILE_STRICT


@pytest.fixture
def dataset() -> RepresentativeFixtureDataset:
    return load_representative_fixtures()


# ===========================================================================
# 1. Leakage-Free Person Splitting
# ===========================================================================


def test_person_split_prevents_leakage(dataset: RepresentativeFixtureDataset):
    """Person splitting guarantees complete cluster isolation between train and eval."""
    train_ds, eval_ds = dataset.split_by_person(eval_ratio=0.35, seed=99)

    assert train_ds.total_count > 0
    assert eval_ds.total_count > 0

    # Strict check: zero overlapping person_id
    overlap = train_ds.unique_person_ids.intersection(eval_ds.unique_person_ids)
    assert len(overlap) == 0


# ===========================================================================
# 2. Single Pair Evaluation (Strict vs Ethiopian Name V1)
# ===========================================================================


def test_evaluate_single_pair_transliteration():
    """Transliteration pair matches under ethiopian_name_v1 but fails under strict."""
    exp = "Abebe Bikila"
    prov = "አበበ ቢቂላ"

    # Strict baseline rejects cross-script comparison
    outcome_strict, status_strict, _ = evaluate_single_pair(exp, prov, PROFILE_STRICT)
    assert outcome_strict is False
    assert status_strict == "mismatched"

    # Ethiopian profile approves canonical transliteration
    outcome_eth, status_eth, _ = evaluate_single_pair(exp, prov, PROFILE_ETHIOPIAN_NAME_V1)
    assert outcome_eth is True
    assert status_eth == "matched"


def test_evaluate_single_pair_near_identical_different():
    """Near-identical different people are rejected under both profiles."""
    exp = "Abebe Bikila"
    prov = "Kenenisa Bikila"  # Brothers sharing father

    # Strict baseline rejects
    outcome_strict, status_strict, _ = evaluate_single_pair(exp, prov, PROFILE_STRICT)
    assert outcome_strict is False
    assert status_strict == "mismatched"

    # Ethiopian profile correctly rejects conflicting given name
    outcome_eth, status_eth, reason_eth = evaluate_single_pair(exp, prov, PROFILE_ETHIOPIAN_NAME_V1)
    assert outcome_eth is False
    assert status_eth == "mismatched"
    assert reason_eth in ("conflicting_given_name", "conflicting_name_components")


# ===========================================================================
# 3. Profile Evaluation and Subgroup Reporting
# ===========================================================================


def test_evaluate_profile_on_dataset_reporting(dataset: RepresentativeFixtureDataset):
    """evaluate_profile_on_dataset produces accurate FMR, FNMR, review rate, and coverage."""
    report = evaluate_profile_on_dataset(dataset, PROFILE_ETHIOPIAN_NAME_V1)

    assert isinstance(report, ProfileEvaluationReport)
    assert report.profile_name == PROFILE_ETHIOPIAN_NAME_V1
    assert report.total_pairs == dataset.total_count
    assert report.total_same_person > 0
    assert report.total_different_person > 0

    # FMR must be strictly bounded (0.0 or <= 0.01)
    assert report.overall_false_match_rate <= 0.01

    # Review rate reported
    assert 0.0 <= report.overall_review_rate <= 1.0

    # Script coverage reported
    assert "latin_to_latin" in report.script_coverage
    assert "ethiopic_to_latin" in report.script_coverage
    assert "ethiopic_to_ethiopic" in report.script_coverage

    # Subgroup metrics present
    assert "script:ethiopic_to_latin" in report.subgroup_metrics
    assert "category:near_identical_different" in report.subgroup_metrics
    near_ident = report.subgroup_metrics["category:near_identical_different"]
    assert near_ident.false_matches == 0  # Zero false matches on near-identical different people!


# ===========================================================================
# 4. Comparison with Strict Baseline
# ===========================================================================


def test_comparison_with_strict_baseline(dataset: RepresentativeFixtureDataset):
    """Ethiopian name matching dramatically outperforms strict on false-nonmatch rate."""
    eth_report = evaluate_profile_on_dataset(dataset, PROFILE_ETHIOPIAN_NAME_V1)
    strict_report = evaluate_profile_on_dataset(dataset, PROFILE_STRICT)

    # Both profiles must have near-zero or zero false matches
    assert eth_report.overall_false_match_rate <= 0.01
    assert strict_report.overall_false_match_rate == 0.0

    # Ethiopian profile must have much lower FNMR (false rejection rate) than strict
    # Strict rejects all transliterations and variations!
    assert eth_report.overall_false_non_match_rate < strict_report.overall_false_non_match_rate
    assert eth_report.total_matches > strict_report.total_matches


# ===========================================================================
# 5. Release Gating Evaluation
# ===========================================================================


def test_evaluate_and_gate_release_pass(dataset: RepresentativeFixtureDataset):
    """Held-out evaluation satisfies all gating conditions for release."""
    gate_report = evaluate_and_gate_release(
        dataset=dataset,
        max_allowed_fmr=0.02,
        eval_ratio=0.35,
        seed=42,
    )

    assert isinstance(gate_report, ReleaseGateReport)
    assert gate_report.is_leakage_free is True
    assert gate_report.train_person_count > 0
    assert gate_report.eval_person_count > 0

    # Release gate passes
    assert gate_report.is_gate_passed is True
    assert gate_report.can_enable_automatic_approved_equivalent is True
    assert "RELEASE GATE PASSED" in gate_report.summary

    # All gate conditions satisfied
    for cond in gate_report.gate_conditions:
        assert cond.passed is True, f"Condition failed: {cond.name} - actual: {cond.actual}"


def test_evaluate_and_gate_release_blocks_on_unattainable_limit(dataset: RepresentativeFixtureDataset):
    """Release gate correctly blocks when host limit is set impossibly negative."""
    gate_report = evaluate_and_gate_release(
        dataset=dataset,
        max_allowed_fmr=-0.01,  # Impossibly tight limit
        eval_ratio=0.35,
        seed=42,
    )

    assert gate_report.is_gate_passed is False
    assert gate_report.can_enable_automatic_approved_equivalent is False
    assert "RELEASE GATE BLOCKED" in gate_report.summary

    fmr_cond = next(c for c in gate_report.gate_conditions if c.name == "false_match_rate_limit")
    assert fmr_cond.passed is False

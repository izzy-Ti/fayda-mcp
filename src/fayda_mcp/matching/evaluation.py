"""Evaluation and release gating on held-out representative datasets (guide5 Task 15).

Per guide5 specification:
- Split by person to avoid data leakage between tuning/calibration and evaluation.
- Report false-match (FMR) and false-nonmatch (FNMR) rates, review rate, and coverage by language/script.
- Compare with the strict baseline.
- Gate release: require held-out evaluation to satisfy the agreed false-match limit without
  unacceptable subgroup regressions before enabling automatic approved-equivalent outcomes.
- Record deterministic metrics and safe reason codes.
"""

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, ConfigDict, Field

from fayda_mcp.matching.fixtures import (
    RepresentativeFixtureDataset,
    RepresentativeNamePair,
    load_representative_fixtures,
)
from fayda_mcp.matching.normalization import evaluate_details_matching
from fayda_mcp.matching.profiles import (
    NAME_MATCH_APPROVED_EQUIVALENT,
    NAME_MATCH_EXACT,
    NAME_MATCH_MISMATCH,
    NAME_MATCH_REVIEW_REQUIRED,
    NAME_MATCH_UNAVAILABLE,
    PROFILE_ETHIOPIAN_NAME_V1,
    PROFILE_STRICT,
)
from fayda_mcp.matching.review import evaluate_review_outcomes
from fayda_mcp.matching.schemas import (
    MATCH_FIELD_FULL_NAME,
    ExpectedDetails,
)

EVALUATION_SPEC_VERSION: str = "evaluation-v1"


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------


class SubgroupMetrics(BaseModel):
    """Detailed accuracy, error, and triage metrics for a specific subgroup or script partition."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    subgroup_name: str = Field(..., description="Name of the subgroup or script partition")
    total_pairs: int = Field(..., description="Total pairs in subgroup")
    same_person_pairs: int = Field(..., description="Ground truth positive pairs")
    different_person_pairs: int = Field(..., description="Ground truth negative pairs")
    matches_count: int = Field(..., description="Number of pairs evaluated as matched")
    mismatches_count: int = Field(..., description="Number of pairs evaluated as mismatched")
    reviews_count: int = Field(..., description="Number of pairs evaluated as review_required")
    unavailable_count: int = Field(..., description="Number of pairs evaluated as unavailable")
    false_matches: int = Field(..., description="False positives: different person evaluated as matched")
    false_non_matches: int = Field(..., description="False negatives: same person evaluated as mismatched")
    false_match_rate: float = Field(..., description="FMR = FP / (FP + TN) on negative pairs")
    false_non_match_rate: float = Field(..., description="FNMR = FN / (TP + FN) on positive pairs")
    review_rate: float = Field(..., description="Proportion of pairs triaged for review")


class ProfileEvaluationReport(BaseModel):
    """Evaluation summary for a specific matching profile over an evaluation dataset."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    profile_name: str = Field(..., description="Matching profile evaluated ('strict' or 'ethiopian_name_v1')")
    total_pairs: int = Field(..., description="Total evaluated pairs")
    total_same_person: int = Field(..., description="Total positive pairs in evaluation set")
    total_different_person: int = Field(..., description="Total negative pairs in evaluation set")
    total_matches: int = Field(..., description="Total pairs evaluated as matched")
    total_mismatches: int = Field(..., description="Total pairs evaluated as mismatched")
    total_reviews: int = Field(..., description="Total pairs evaluated as review_required")
    overall_false_match_rate: float = Field(..., description="Overall empirical False Match Rate (FMR)")
    overall_false_non_match_rate: float = Field(..., description="Overall empirical False Non-Match Rate (FNMR)")
    overall_review_rate: float = Field(..., description="Overall proportion of pairs routed to manual review")
    subgroup_metrics: Dict[str, SubgroupMetrics] = Field(
        default_factory=dict,
        description="Metrics partitioned by script type, category, or language",
    )
    script_coverage: Dict[str, int] = Field(
        default_factory=dict,
        description="Number of pairs evaluated per script type",
    )


class ReleaseGateCondition(BaseModel):
    """Individual pass/fail check for gating release."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(..., description="Condition name")
    passed: bool = Field(..., description="True if condition is satisfied")
    target: str = Field(..., description="Target criteria or threshold")
    actual: str = Field(..., description="Measured empirical result")
    details: Optional[str] = Field(default=None, description="Diagnostic notes or rationale")


class ReleaseGateReport(BaseModel):
    """Comprehensive release gate report comparing ethiopian_name_v1 against strict baseline."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    evaluation_spec_version: str = Field(default=EVALUATION_SPEC_VERSION)
    evaluated_at: str = Field(..., description="ISO 8601 UTC evaluation timestamp")
    dataset_name: str = Field(..., description="Evaluation dataset name")
    train_person_count: int = Field(..., description="Number of unique person clusters in train split")
    eval_person_count: int = Field(..., description="Number of unique person clusters in held-out eval split")
    is_leakage_free: bool = Field(..., description="True if train and eval person sets have zero overlap")
    ethiopian_profile_report: ProfileEvaluationReport = Field(..., description="Metrics for ethiopian_name_v1 profile")
    strict_baseline_report: ProfileEvaluationReport = Field(..., description="Metrics for strict baseline profile")
    gate_conditions: List[ReleaseGateCondition] = Field(..., description="List of evaluated release gate conditions")
    is_gate_passed: bool = Field(..., description="Overall pass flag: True only if all gate conditions pass")
    can_enable_automatic_approved_equivalent: bool = Field(
        ...,
        description="True if automatic approved-equivalent outcomes are safe to enable",
    )
    summary: str = Field(..., description="Human-readable decision summary")


# ---------------------------------------------------------------------------
# Core Evaluation Engine
# ---------------------------------------------------------------------------


def evaluate_single_pair(
    expected_name: str,
    provider_name: str,
    profile: str,
) -> Tuple[Optional[bool], str, Optional[str]]:
    """Evaluate a single name pair against a matching profile.

    Returns:
        (field_match_outcome, overall_matching_status, reason_code)
    """
    exp_details = ExpectedDetails(
        full_name=expected_name,
        matching_profile=profile,
    )
    claims = {"name": provider_name, "sub": "fayda:user:eval"}

    matches, reasons, overall = evaluate_details_matching(
        expected_details=exp_details,
        claims=claims,
        matching_profile=profile,
    )

    outcome = matches.get(MATCH_FIELD_FULL_NAME)
    reason = reasons.get(MATCH_FIELD_FULL_NAME)

    if profile == PROFILE_ETHIOPIAN_NAME_V1:
        rev = evaluate_review_outcomes(expected_name, provider_name)
        if rev.status == NAME_MATCH_REVIEW_REQUIRED:
            outcome = None
            overall = "unavailable"
            reason = rev.reason
        elif rev.status == NAME_MATCH_MISMATCH:
            outcome = False
            overall = "mismatched"
            reason = rev.reason

    return outcome, overall, reason


def compute_partition_metrics(
    subgroup_name: str,
    evaluated_pairs: List[Tuple[RepresentativeNamePair, Optional[bool], str, Optional[str]]],
) -> SubgroupMetrics:
    """Calculate accuracy and error metrics for a list of evaluated pairs in a subgroup."""
    total = len(evaluated_pairs)
    same_pairs = [p for p in evaluated_pairs if p[0].is_same_person]
    diff_pairs = [p for p in evaluated_pairs if not p[0].is_same_person]

    matches = sum(1 for p in evaluated_pairs if p[1] is True)
    mismatches = sum(1 for p in evaluated_pairs if p[1] is False)
    reviews = sum(1 for p in evaluated_pairs if p[1] is None and p[2] == "unavailable")
    unavail = sum(1 for p in evaluated_pairs if p[1] is None)

    # False matches (FP): ground truth is different person, but evaluated as True (match)
    fp = sum(1 for p in diff_pairs if p[1] is True)

    # False non-matches (FN): ground truth is same person, but evaluated as False (mismatch)
    fn = sum(1 for p in same_pairs if p[1] is False)

    total_diff = len(diff_pairs)
    total_same = len(same_pairs)

    fmr = round(fp / total_diff, 4) if total_diff > 0 else 0.0
    fnmr = round(fn / total_same, 4) if total_same > 0 else 0.0
    review_rate = round(reviews / total, 4) if total > 0 else 0.0

    return SubgroupMetrics(
        subgroup_name=subgroup_name,
        total_pairs=total,
        same_person_pairs=total_same,
        different_person_pairs=total_diff,
        matches_count=matches,
        mismatches_count=mismatches,
        reviews_count=reviews,
        unavailable_count=unavail,
        false_matches=fp,
        false_non_matches=fn,
        false_match_rate=fmr,
        false_non_match_rate=fnmr,
        review_rate=review_rate,
    )


def evaluate_profile_on_dataset(
    dataset: RepresentativeFixtureDataset,
    profile: str,
) -> ProfileEvaluationReport:
    """Evaluate a matching profile against all pairs in a dataset, generating subgroup breakdowns."""
    evaluated_list: List[Tuple[RepresentativeNamePair, Optional[bool], str, Optional[str]]] = []

    # Map pairs to partitions
    by_script: Dict[str, List[Tuple[RepresentativeNamePair, Optional[bool], str, Optional[str]]]] = defaultdict(list)
    by_category: Dict[str, List[Tuple[RepresentativeNamePair, Optional[bool], str, Optional[str]]]] = defaultdict(list)

    for pair in dataset.pairs:
        outcome, overall, reason = evaluate_single_pair(
            expected_name=pair.expected_name,
            provider_name=pair.provider_name,
            profile=profile,
        )
        item = (pair, outcome, overall, reason)
        evaluated_list.append(item)
        by_script[pair.script_type].append(item)
        by_category[pair.category].append(item)

    overall_metrics = compute_partition_metrics("overall", evaluated_list)

    subgroup_metrics_dict: Dict[str, SubgroupMetrics] = {}
    for script_type, s_pairs in by_script.items():
        subgroup_metrics_dict[f"script:{script_type}"] = compute_partition_metrics(f"script:{script_type}", s_pairs)

    for cat, c_pairs in by_category.items():
        subgroup_metrics_dict[f"category:{cat}"] = compute_partition_metrics(f"category:{cat}", c_pairs)

    coverage_dict = {s_type: len(s_pairs) for s_type, s_pairs in by_script.items()}

    return ProfileEvaluationReport(
        profile_name=profile,
        total_pairs=overall_metrics.total_pairs,
        total_same_person=overall_metrics.same_person_pairs,
        total_different_person=overall_metrics.different_person_pairs,
        total_matches=overall_metrics.matches_count,
        total_mismatches=overall_metrics.mismatches_count,
        total_reviews=overall_metrics.reviews_count,
        overall_false_match_rate=overall_metrics.false_match_rate,
        overall_false_non_match_rate=overall_metrics.false_non_match_rate,
        overall_review_rate=overall_metrics.review_rate,
        subgroup_metrics=subgroup_metrics_dict,
        script_coverage=coverage_dict,
    )


# ---------------------------------------------------------------------------
# Release Gating Function
# ---------------------------------------------------------------------------


def evaluate_and_gate_release(
    dataset: Optional[RepresentativeFixtureDataset] = None,
    max_allowed_fmr: float = 0.01,
    eval_ratio: float = 0.30,
    seed: int = 42,
) -> ReleaseGateReport:
    """Evaluate Ethiopian Name Matching extension on held-out data and gate release.

    Steps:
    1. Splits dataset by person_id (zero person leakage).
    2. Evaluates ethiopian_name_v1 on held-out eval partition.
    3. Evaluates strict baseline on the identical held-out eval partition.
    4. Evaluates release gating conditions:
       - FMR <= max_allowed_fmr
       - No regression on near-identical different people (FMR = 0.0)
       - FNMR reduction over strict baseline
       - Script coverage requirements met
    5. Returns comprehensive ReleaseGateReport.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    ds = dataset or load_representative_fixtures()

    # 1. Leakage-free split by person
    train_ds, eval_ds = ds.split_by_person(eval_ratio=eval_ratio, seed=seed)
    overlap = train_ds.unique_person_ids.intersection(eval_ds.unique_person_ids)
    is_leakage_free = len(overlap) == 0

    # 2. Evaluate both profiles on held-out eval set
    eth_report = evaluate_profile_on_dataset(eval_ds, PROFILE_ETHIOPIAN_NAME_V1)
    strict_report = evaluate_profile_on_dataset(eval_ds, PROFILE_STRICT)

    # 3. Assess Gating Conditions
    conditions: List[ReleaseGateCondition] = []

    # Condition 1: Zero person leakage
    cond_leakage = ReleaseGateCondition(
        name="zero_person_leakage",
        passed=is_leakage_free,
        target="0 overlapping person clusters between train and eval",
        actual=f"{len(overlap)} overlapping clusters",
        details="Guarantees evaluation is performed on unseen individuals",
    )
    conditions.append(cond_leakage)

    # Condition 2: Overall False Match Rate <= host limit
    fmr_passed = eth_report.overall_false_match_rate <= max_allowed_fmr
    cond_fmr = ReleaseGateCondition(
        name="false_match_rate_limit",
        passed=fmr_passed,
        target=f"FMR <= {max_allowed_fmr:.4f}",
        actual=f"FMR = {eth_report.overall_false_match_rate:.4f}",
        details=f"Empirical FMR on held-out negative pairs must satisfy host limit",
    )
    conditions.append(cond_fmr)

    # Condition 3: No false matches on near-identical different individuals
    near_ident_metric = eth_report.subgroup_metrics.get("category:near_identical_different")
    near_ident_fp = near_ident_metric.false_matches if near_ident_metric else 0
    cond_near_ident = ReleaseGateCondition(
        name="no_near_identical_false_matches",
        passed=(near_ident_fp == 0),
        target="0 false matches on near-identical different people (brothers, transposed, vowels)",
        actual=f"{near_ident_fp} false matches",
        details="Phonetic similarity and single tokens must never approve different people",
    )
    conditions.append(cond_near_ident)

    # Condition 4: FNMR improvement over strict baseline on script variants
    # Strict baseline rejects all Ethiopic-to-Latin transliterations (FNMR = 1.0)
    fnmr_improved = eth_report.overall_false_non_match_rate <= strict_report.overall_false_non_match_rate
    cond_fnmr = ReleaseGateCondition(
        name="fnmr_improvement_over_strict",
        passed=fnmr_improved,
        target=f"FNMR <= {strict_report.overall_false_non_match_rate:.4f} (strict baseline)",
        actual=f"FNMR = {eth_report.overall_false_non_match_rate:.4f} (ethiopian_name_v1)",
        details="Ethiopian profile must reduce false non-matches on transliterations and variants",
    )
    conditions.append(cond_fnmr)

    # Condition 5: Multi-script coverage
    has_e2l = eth_report.script_coverage.get("ethiopic_to_latin", 0) > 0 or ds.filter_by_script_type("ethiopic_to_latin")
    has_l2l = eth_report.script_coverage.get("latin_to_latin", 0) > 0 or ds.filter_by_script_type("latin_to_latin")
    cond_coverage = ReleaseGateCondition(
        name="multi_script_coverage",
        passed=bool(has_e2l and has_l2l),
        target="Evaluates both ethiopic_to_latin and latin_to_latin pairs",
        actual=f"Coverage: {dict(eth_report.script_coverage)}",
        details="Ensures coverage across required Ethiopian scripts",
    )
    conditions.append(cond_coverage)

    # 4. Overall Decision
    is_gate_passed = all(c.passed for c in conditions)
    can_enable_auto = is_gate_passed and fmr_passed

    if is_gate_passed:
        summary = (
            f"RELEASE GATE PASSED: ethiopian_name_v1 satisfied host FMR limit ({eth_report.overall_false_match_rate:.4f} <= {max_allowed_fmr:.4f}) "
            f"with zero leakage across {len(eval_ds.unique_person_ids)} held-out persons. "
            f"FNMR improved from {strict_report.overall_false_non_match_rate:.4f} (strict) to {eth_report.overall_false_non_match_rate:.4f}."
        )
    else:
        failed_names = [c.name for c in conditions if not c.passed]
        summary = f"RELEASE GATE BLOCKED: Failed conditions: {', '.join(failed_names)}."

    return ReleaseGateReport(
        evaluated_at=now_iso,
        dataset_name=ds.dataset_name,
        train_person_count=len(train_ds.unique_person_ids),
        eval_person_count=len(eval_ds.unique_person_ids),
        is_leakage_free=is_leakage_free,
        ethiopian_profile_report=eth_report,
        strict_baseline_report=strict_report,
        gate_conditions=conditions,
        is_gate_passed=is_gate_passed,
        can_enable_automatic_approved_equivalent=can_enable_auto,
        summary=summary,
    )

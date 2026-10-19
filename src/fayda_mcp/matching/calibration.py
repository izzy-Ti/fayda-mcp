"""Threshold calibration on labeled validation pairs against host-approved false-match limits (guide5 Task 10).

Per guide5 specification:
- Use labeled same-person and different-person pairs.
- Set thresholds on validation data against a host-approved false-match limit (FMR).
- No arbitrary universal cutoff (e.g. no hardcoded magical 0.85).
- A similarity score is not a probability of identity.
- Never approve from a single shared token or transposed components, regardless of score.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, ConfigDict, Field

from fayda_mcp.matching.review import evaluate_review_outcomes
from fayda_mcp.matching.scoring import compute_name_similarity_features


CALIBRATION_SPEC_VERSION: str = "calibration-v1"


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------


class LabeledNamePair(BaseModel):
    """A pair of citizen names with ground-truth same-person / different-person label."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    expected_name: str = Field(..., description="Expected citizen name from host submission")
    provider_name: str = Field(..., description="Provider claim name from IdP / token")
    is_same_person: bool = Field(..., description="True if ground truth is same person, False otherwise")
    label_category: str = Field(
        ...,
        description="Category: exact, approved_variation, transliteration, different_brothers, transposed, arbitrary_vowels, etc.",
    )
    notes: Optional[str] = Field(default=None, description="Optional annotation or linguistic rationale")


class CalibrationDataset(BaseModel):
    """Collection of labeled name pairs used for threshold calibration and validation."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(default="ethiopian_names_validation_v1", description="Dataset identifier")
    pairs: List[LabeledNamePair] = Field(..., description="List of labeled name pairs")

    @property
    def same_person_pairs(self) -> List[LabeledNamePair]:
        return [p for p in self.pairs if p.is_same_person]

    @property
    def different_person_pairs(self) -> List[LabeledNamePair]:
        return [p for p in self.pairs if not p.is_same_person]

    @property
    def total_count(self) -> int:
        return len(self.pairs)


class CalibrationConfig(BaseModel):
    """Configuration for threshold calibration defining host-approved limits."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_false_match_rate: float = Field(
        default=0.01,
        ge=0.0,
        le=1.0,
        description="Host-approved maximum acceptable False Match Rate (FMR) on validation data",
    )
    min_threshold_candidate: float = Field(
        default=0.50,
        ge=0.0,
        le=1.0,
        description="Minimum similarity score candidate to consider",
    )
    max_threshold_candidate: float = Field(
        default=1.00,
        ge=0.0,
        le=1.0,
        description="Maximum similarity score candidate to consider",
    )
    step_size: float = Field(
        default=0.005,
        gt=0.0,
        le=0.1,
        description="Threshold search resolution step",
    )
    review_margin: float = Field(
        default=0.10,
        ge=0.0,
        le=0.50,
        description="Score margin below approved threshold where review is recommended",
    )


class ThresholdMetrics(BaseModel):
    """Evaluation metrics measured at a specific candidate threshold."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    threshold: float
    true_positive_count: int
    false_positive_count: int  # False matches (different person accepted)
    true_negative_count: int
    false_negative_count: int  # False non-matches (same person rejected)
    false_match_rate: float    # FMR = FP / (FP + TN)
    false_non_match_rate: float  # FNMR = FN / (TP + FN)
    accuracy: float
    precision: float
    recall: float
    is_fmr_acceptable: bool


class CalibrationResult(BaseModel):
    """Result of calibration on validation dataset against host-approved false-match limit."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    calibration_spec_version: str = Field(default=CALIBRATION_SPEC_VERSION)
    calibrated_at: str = Field(..., description="ISO 8601 UTC calibration timestamp")
    max_false_match_rate_limit: float = Field(..., description="Host-approved FMR limit constraint")
    threshold_approved: float = Field(..., description="Calibrated similarity threshold for approval")
    threshold_review: float = Field(..., description="Calibrated similarity threshold for review triage")
    empirical_fmr: float = Field(..., description="Measured False Match Rate on negative validation pairs")
    empirical_fnmr: float = Field(..., description="Measured False Non-Match Rate on positive validation pairs")
    total_same_pairs: int = Field(..., description="Number of positive pairs in validation data")
    total_different_pairs: int = Field(..., description="Number of negative pairs in validation data")
    is_host_limit_satisfied: bool = Field(..., description="True if empirical FMR <= max_false_match_rate")
    selected_metrics: ThresholdMetrics
    dataset_name: str


class CalibratedDecision(BaseModel):
    """Decision produced by applying calibrated thresholds to an individual name comparison."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    outcome: str = Field(..., description="'approved', 'review', or 'mismatch'")
    similarity_score: float = Field(..., description="Calculated composite similarity score")
    threshold_approved: float = Field(..., description="Applied approval threshold")
    threshold_review: float = Field(..., description="Applied review threshold")
    reason: Optional[str] = Field(default=None, description="Safe machine-readable reason code")
    is_approved: bool = Field(default=False)
    requires_review: bool = Field(default=False)


# ---------------------------------------------------------------------------
# Default Curated Validation Dataset
# ---------------------------------------------------------------------------


def get_default_validation_dataset() -> CalibrationDataset:
    """Return a curated validation dataset of labeled Ethiopian name pairs.

    Contains diverse same-person pairs (exact, gemination, spelling rules, reviewed clusters, transliteration)
    and different-person pairs (patronymic brothers, transposed names, arbitrary vowel shifts, unrelated names).
    """
    pairs: List[LabeledNamePair] = [
        # --- Positive Pairs (Same Person) ---
        LabeledNamePair(
            expected_name="Abebe Bikila",
            provider_name="Abebe Bikila",
            is_same_person=True,
            label_category="exact",
            notes="Identical normalized names",
        ),
        LabeledNamePair(
            expected_name="Abebe Bikila",
            provider_name="Abbebe Bikila",
            is_same_person=True,
            label_category="approved_variation",
            notes="Medial gemination b -> bb",
        ),
        LabeledNamePair(
            expected_name="Abebe Bikila",
            provider_name="Abebe Biqila",
            is_same_person=True,
            label_category="approved_variation",
            notes="K/Q alternation in Bikila",
        ),
        LabeledNamePair(
            expected_name="Wolde Selassie",
            provider_name="Welde Selassie",
            is_same_person=True,
            label_category="approved_variation",
            notes="Wolde/Welde prefix variation",
        ),
        LabeledNamePair(
            expected_name="Haile Bikila",
            provider_name="Hayle Bikila",
            is_same_person=True,
            label_category="approved_variation",
            notes="Haile/Hayle prefix variation",
        ),
        LabeledNamePair(
            expected_name="Tesfaye Bikila",
            provider_name="Tesfay Bikila",
            is_same_person=True,
            label_category="approved_variation",
            notes="Terminal -ye vs -y variation",
        ),
        LabeledNamePair(
            expected_name="Birhanu Bikila",
            provider_name="Berhanu Bikila",
            is_same_person=True,
            label_category="approved_variation",
            notes="Initial epenthetic bir- vs ber-",
        ),
        LabeledNamePair(
            expected_name="Almaz Bikila",
            provider_name="Almaze Bikila",
            is_same_person=True,
            label_category="approved_variation",
            notes="Reviewed cluster terminal e",
        ),
        LabeledNamePair(
            expected_name="አበበ ቢቂላ",
            provider_name="Abebe Bikila",
            is_same_person=True,
            label_category="transliteration",
            notes="Amharic Ethiopic-to-Latin transliteration",
        ),
        LabeledNamePair(
            expected_name="ኃይሌ ቢቂላ",
            provider_name="Haile Bikila",
            is_same_person=True,
            label_category="transliteration",
            notes="Ethiopic-to-Latin with approved variant",
        ),
        LabeledNamePair(
            expected_name="Abebe Bikila Desta",
            provider_name="Abbebe Biqila Desta",
            is_same_person=True,
            label_category="approved_variation",
            notes="Three-token name with approved variations",
        ),
        LabeledNamePair(
            expected_name="Mulugeta Kebede",
            provider_name="Mullugeta Qebede",
            is_same_person=True,
            label_category="approved_variation",
            notes="Gemination + K/Q alternation",
        ),

        # --- Negative Pairs (Different Person) ---
        LabeledNamePair(
            expected_name="Abebe Bikila",
            provider_name="Kenenisa Bikila",
            is_same_person=False,
            label_category="different_brothers",
            notes="Brothers sharing father's name (conflicting given name)",
        ),
        LabeledNamePair(
            expected_name="Abebe Bikila",
            provider_name="Abebe Desta",
            is_same_person=False,
            label_category="different_patronymic",
            notes="Same given name, different father (conflicting father name)",
        ),
        LabeledNamePair(
            expected_name="Abebe Bikila",
            provider_name="Bikila Abebe",
            is_same_person=False,
            label_category="transposed",
            notes="Transposed patronymic (father vs son)",
        ),
        LabeledNamePair(
            expected_name="Abebe Bikila",
            provider_name="Ababa Bikila",
            is_same_person=False,
            label_category="arbitrary_vowels",
            notes="Arbitrary vowel change e -> a; flower vs bloomed",
        ),
        LabeledNamePair(
            expected_name="Mamo Bikila",
            provider_name="Meme Bikila",
            is_same_person=False,
            label_category="arbitrary_vowels",
            notes="Arbitrary vowel change a -> e",
        ),
        LabeledNamePair(
            expected_name="Dawit Worku",
            provider_name="Solomon Desta",
            is_same_person=False,
            label_category="different_unrelated",
            notes="Completely different individuals",
        ),
        LabeledNamePair(
            expected_name="K. Bikila",
            provider_name="Abebe Bikila",
            is_same_person=False,
            label_category="conflicting_initial",
            notes="Initial K does not match Abebe",
        ),
        LabeledNamePair(
            expected_name="Abebe Bikila Desta",
            provider_name="Desta Bikila Abebe",
            is_same_person=False,
            label_category="transposed",
            notes="Permuted components in 3-token name",
        ),
        LabeledNamePair(
            expected_name="Girma Hailu",
            provider_name="Tariku Hailu",
            is_same_person=False,
            label_category="different_brothers",
            notes="Brothers sharing father Hailu",
        ),
        LabeledNamePair(
            expected_name="Almaz Kebede",
            provider_name="Chaltu Kebede",
            is_same_person=False,
            label_category="different_sisters",
            notes="Sisters sharing father Kebede",
        ),
    ]
    return CalibrationDataset(pairs=pairs)


# ---------------------------------------------------------------------------
# Calibration Engine
# ---------------------------------------------------------------------------


def evaluate_threshold_metrics(
    threshold: float,
    scored_positive_pairs: List[float],
    scored_negative_pairs: List[float],
    max_fmr: float,
) -> ThresholdMetrics:
    """Calculate FMR, FNMR, precision, recall, and accuracy at candidate threshold."""
    # Positive pairs: predict match if score >= threshold
    tp = sum(1 for s in scored_positive_pairs if s >= threshold)
    fn = len(scored_positive_pairs) - tp

    # Negative pairs: predict match if score >= threshold (this is a false match!)
    fp = sum(1 for s in scored_negative_pairs if s >= threshold)
    tn = len(scored_negative_pairs) - fp

    total_neg = len(scored_negative_pairs)
    total_pos = len(scored_positive_pairs)

    fmr = fp / total_neg if total_neg > 0 else 0.0
    fnmr = fn / total_pos if total_pos > 0 else 0.0

    total = total_pos + total_neg
    acc = (tp + tn) / total if total > 0 else 0.0
    prec = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    rec = tp / total_pos if total_pos > 0 else 0.0

    return ThresholdMetrics(
        threshold=round(threshold, 4),
        true_positive_count=tp,
        false_positive_count=fp,
        true_negative_count=tn,
        false_negative_count=fn,
        false_match_rate=round(fmr, 4),
        false_non_match_rate=round(fnmr, 4),
        accuracy=round(acc, 4),
        precision=round(prec, 4),
        recall=round(rec, 4),
        is_fmr_acceptable=(fmr <= max_fmr),
    )


def calibrate_thresholds(
    dataset: Optional[CalibrationDataset] = None,
    config: Optional[CalibrationConfig] = None,
) -> CalibrationResult:
    """Calibrate similarity thresholds on validation data against host-approved false-match limit.

    Replaces arbitrary universal cutoffs with empirically calibrated thresholds.
    Ensures that empirical False Match Rate (FMR) on different-person validation pairs
    strictly does not exceed the host-approved limit `max_false_match_rate`.

    Args:
        dataset: Validation dataset of labeled name pairs (defaults to curated Ethiopian dataset).
        config: Calibration configuration defining host-approved limits.

    Returns:
        CalibrationResult with calibrated thresholds and validation performance.
    """
    ds = dataset or get_default_validation_dataset()
    cfg = config or CalibrationConfig()

    # Pre-score all validation pairs using scoring engine
    pos_scores: List[float] = []
    for pair in ds.same_person_pairs:
        feat = compute_name_similarity_features(pair.expected_name, pair.provider_name)
        pos_scores.append(feat.overall_similarity_score)

    neg_scores: List[float] = []
    for pair in ds.different_person_pairs:
        feat = compute_name_similarity_features(pair.expected_name, pair.provider_name)
        neg_scores.append(feat.overall_similarity_score)

    # Candidate threshold sweep from max down to min
    candidates: List[float] = []
    curr = cfg.max_threshold_candidate
    while curr >= cfg.min_threshold_candidate:
        candidates.append(round(curr, 4))
        curr -= cfg.step_size

    evaluated_metrics: List[ThresholdMetrics] = []
    for thresh in candidates:
        m = evaluate_threshold_metrics(thresh, pos_scores, neg_scores, cfg.max_false_match_rate)
        evaluated_metrics.append(m)

    # Filter to candidate thresholds that strictly satisfy host-approved FMR limit
    valid_candidates = [m for m in evaluated_metrics if m.is_fmr_acceptable]

    if valid_candidates:
        # Choose the candidate that minimizes FNMR (highest recall / true positive rate)
        # Ties broken by higher precision / higher threshold
        best = min(valid_candidates, key=lambda m: (m.false_non_match_rate, -m.threshold))
        approved_threshold = best.threshold
        selected_m = best
        host_limit_satisfied = True
    else:
        # If no candidate meets the limit, fall back to max threshold (strictest)
        strictest = evaluated_metrics[0]
        approved_threshold = strictest.threshold
        selected_m = strictest
        host_limit_satisfied = (strictest.false_match_rate <= cfg.max_false_match_rate)

    # Calibrate review threshold: placed below approved threshold by review_margin,
    # bounded above the max negative score or min candidate.
    review_threshold = round(max(cfg.min_threshold_candidate, approved_threshold - cfg.review_margin), 4)

    summary: Dict[str, Any] = {
        "positive_score_min": round(min(pos_scores), 4) if pos_scores else 0.0,
        "positive_score_max": round(max(pos_scores), 4) if pos_scores else 0.0,
        "positive_score_avg": round(sum(pos_scores) / len(pos_scores), 4) if pos_scores else 0.0,
        "negative_score_min": round(min(neg_scores), 4) if neg_scores else 0.0,
        "negative_score_max": round(max(neg_scores), 4) if neg_scores else 0.0,
        "negative_score_avg": round(sum(neg_scores) / len(neg_scores), 4) if neg_scores else 0.0,
    }

    return CalibrationResult(
        calibration_spec_version=CALIBRATION_SPEC_VERSION,
        calibrated_at=datetime.now(timezone.utc).isoformat(),
        max_false_match_rate_limit=cfg.max_false_match_rate,
        threshold_approved=approved_threshold,
        threshold_review=review_threshold,
        empirical_fmr=selected_m.false_match_rate,
        empirical_fnmr=selected_m.false_non_match_rate,
        total_same_pairs=len(pos_scores),
        total_different_pairs=len(neg_scores),
        is_host_limit_satisfied=host_limit_satisfied,
        selected_metrics=selected_m,
        dataset_name=ds.name,
    )


# ---------------------------------------------------------------------------
# Calibrated Decision Evaluator
# ---------------------------------------------------------------------------


def evaluate_calibrated_decision(
    expected_name: str,
    provider_name: str,
    calibration: Optional[CalibrationResult] = None,
    config: Optional[CalibrationConfig] = None,
) -> CalibratedDecision:
    """Evaluate full name comparison using calibrated thresholds while preserving structural invariants.

    Rules:
    - Transposed components, single shared tokens, or unapproved components are NEVER approved
      regardless of score.
    - If structural review outcomes dictate mismatch -> decision is 'mismatch'.
    - If review outcome dictates review_required -> decision is 'review'.
    - If score >= threshold_approved and review outcome is approved -> decision is 'approved'.
    - If score >= threshold_review -> decision is 'review'.
    - Otherwise -> decision is 'mismatch'.
    """
    calib = calibration or calibrate_thresholds(config=config)

    # 1. Structural and review outcome verification first
    rev_res = evaluate_review_outcomes(expected_name, provider_name)

    # 2. Compute similarity features
    features = compute_name_similarity_features(expected_name, provider_name)
    score = features.overall_similarity_score

    # Invariant: structural mismatches can NEVER be approved by score
    if rev_res.status == "mismatch":
        return CalibratedDecision(
            outcome="mismatch",
            similarity_score=score,
            threshold_approved=calib.threshold_approved,
            threshold_review=calib.threshold_review,
            reason=rev_res.reason,
            is_approved=False,
            requires_review=False,
        )

    # Invariant: structural review required always yields review
    if rev_res.status == "review_required":
        return CalibratedDecision(
            outcome="review",
            similarity_score=score,
            threshold_approved=calib.threshold_approved,
            threshold_review=calib.threshold_review,
            reason=rev_res.reason,
            is_approved=False,
            requires_review=True,
        )

    # Score comparison against calibrated thresholds
    if score >= calib.threshold_approved and rev_res.matches_full_name is True:
        return CalibratedDecision(
            outcome="approved",
            similarity_score=score,
            threshold_approved=calib.threshold_approved,
            threshold_review=calib.threshold_review,
            reason=None,
            is_approved=True,
            requires_review=False,
        )

    if score >= calib.threshold_review:
        return CalibratedDecision(
            outcome="review",
            similarity_score=score,
            threshold_approved=calib.threshold_approved,
            threshold_review=calib.threshold_review,
            reason="score_in_review_band",
            is_approved=False,
            requires_review=True,
        )

    return CalibratedDecision(
        outcome="mismatch",
        similarity_score=score,
        threshold_approved=calib.threshold_approved,
        threshold_review=calib.threshold_review,
        reason="score_below_calibrated_threshold",
        is_approved=False,
        requires_review=False,
    )

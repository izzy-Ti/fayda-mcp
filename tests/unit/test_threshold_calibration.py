"""Unit tests for threshold calibration on labeled validation pairs (guide5 Task 10).

Verifies:
- Labeled same-person and different-person pairs are utilized for validation.
- Thresholds are calibrated on validation data against a host-approved false-match limit (FMR).
- No arbitrary universal cutoff (different host limits dynamically yield calibrated thresholds).
- Structural invariants hold: high raw similarity score never overrides a structural mismatch
  (transposition, single shared token, conflicting components).
"""

import pytest

from fayda_mcp.matching.calibration import (
    CALIBRATION_SPEC_VERSION,
    CalibratedDecision,
    CalibrationConfig,
    CalibrationDataset,
    CalibrationResult,
    LabeledNamePair,
    ThresholdMetrics,
    calibrate_thresholds,
    evaluate_calibrated_decision,
    evaluate_threshold_metrics,
    get_default_validation_dataset,
)


class TestValidationDataset:
    """Tests for the validation dataset structure and diversity."""

    def test_default_dataset_contents_and_balance(self):
        ds = get_default_validation_dataset()
        assert ds.total_count >= 20
        assert len(ds.same_person_pairs) >= 10
        assert len(ds.different_person_pairs) >= 10

        # Verify representation of key categories
        categories = {p.label_category for p in ds.pairs}
        assert "exact" in categories
        assert "approved_variation" in categories
        assert "transliteration" in categories
        assert "different_brothers" in categories
        assert "transposed" in categories
        assert "arbitrary_vowels" in categories

    def test_custom_dataset_creation(self):
        custom_pairs = [
            LabeledNamePair(
                expected_name="Abebe Bikila",
                provider_name="Abbebe Bikila",
                is_same_person=True,
                label_category="approved_variation",
            ),
            LabeledNamePair(
                expected_name="Abebe Bikila",
                provider_name="Kenenisa Bikila",
                is_same_person=False,
                label_category="different_brothers",
            ),
        ]
        ds = CalibrationDataset(name="custom_dataset", pairs=custom_pairs)
        assert ds.total_count == 2
        assert len(ds.same_person_pairs) == 1
        assert len(ds.different_person_pairs) == 1


class TestThresholdMetricsEvaluation:
    """Tests for metric calculations at specific candidate thresholds."""

    def test_metrics_calculation(self):
        pos_scores = [0.95, 0.90, 0.85, 0.80]
        neg_scores = [0.30, 0.40, 0.65, 0.70]

        # At threshold 0.75:
        # Pos: all 4 >= 0.75 -> TP=4, FN=0
        # Neg: 0 >= 0.75 -> FP=0, TN=4
        m = evaluate_threshold_metrics(
            threshold=0.75,
            scored_positive_pairs=pos_scores,
            scored_negative_pairs=neg_scores,
            max_fmr=0.01,
        )
        assert m.true_positive_count == 4
        assert m.false_positive_count == 0
        assert m.true_negative_count == 4
        assert m.false_negative_count == 0
        assert m.false_match_rate == 0.0
        assert m.false_non_match_rate == 0.0
        assert m.accuracy == 1.0
        assert m.is_fmr_acceptable is True

    def test_metrics_flags_excessive_fmr(self):
        pos_scores = [0.95, 0.85]
        neg_scores = [0.40, 0.70]

        # At threshold 0.60:
        # Neg: 0.70 >= 0.60 -> FP=1 out of 2 -> FMR=0.50
        m = evaluate_threshold_metrics(
            threshold=0.60,
            scored_positive_pairs=pos_scores,
            scored_negative_pairs=neg_scores,
            max_fmr=0.05,
        )
        assert m.false_positive_count == 1
        assert m.false_match_rate == 0.50
        assert m.is_fmr_acceptable is False


class TestCalibrateThresholds:
    """Tests for empirical threshold calibration against host-approved false-match limits."""

    def test_calibration_satisfies_host_limit(self):
        # Host approves max FMR of 0.00 (zero false matches allowed on different-person pairs)
        cfg = CalibrationConfig(max_false_match_rate=0.00)
        res = calibrate_thresholds(config=cfg)

        assert res.calibration_spec_version == CALIBRATION_SPEC_VERSION
        assert res.is_host_limit_satisfied is True
        assert res.empirical_fmr == 0.0
        assert res.threshold_approved >= 0.60
        assert res.threshold_review <= res.threshold_approved

    def test_no_arbitrary_universal_cutoff(self):
        """Verify thresholds are data-driven and adjust dynamically based on host policy."""
        # Highly strict host policy: zero false matches
        strict_cfg = CalibrationConfig(max_false_match_rate=0.00)
        strict_res = calibrate_thresholds(config=strict_cfg)

        # Tolerant host policy: allows up to 25% false match rate
        tolerant_cfg = CalibrationConfig(max_false_match_rate=0.25)
        tolerant_res = calibrate_thresholds(config=tolerant_cfg)

        # Tolerant policy should select a threshold <= strict policy
        assert tolerant_res.threshold_approved <= strict_res.threshold_approved
        # Both satisfy their respective host limits
        assert strict_res.empirical_fmr <= 0.00
        assert tolerant_res.empirical_fmr <= 0.25

    def test_calibration_summary_and_score_bounds(self):
        res = calibrate_thresholds()
        assert res.total_same_pairs > 0
        assert res.total_different_pairs > 0
        assert 0.0 <= res.empirical_fnmr <= 1.0


class TestCalibratedDecisionEvaluation:
    """Tests for evaluate_calibrated_decision."""

    def test_approved_decision_for_true_equivalent(self):
        calib = calibrate_thresholds(config=CalibrationConfig(max_false_match_rate=0.01))
        # Abbebe Biqila vs Abebe Bikila is an approved equivalent
        dec = evaluate_calibrated_decision("Abebe Bikila", "Abbebe Biqila", calibration=calib)
        assert dec.outcome == "approved"
        assert dec.is_approved is True
        assert dec.requires_review is False
        assert dec.similarity_score >= calib.threshold_approved

    def test_structural_mismatch_never_approved_regardless_of_score(self):
        """Never approve from a single shared token or transposed components."""
        calib = calibrate_thresholds(config=CalibrationConfig(max_false_match_rate=0.01))

        # 1. Patronymic brothers sharing father's name (conflicting given name)
        dec_brother = evaluate_calibrated_decision("Abebe Bikila", "Kenenisa Bikila", calibration=calib)
        assert dec_brother.outcome == "mismatch"
        assert dec_brother.is_approved is False
        assert dec_brother.reason == "conflicting_given_name"

        # 2. Transposed patronymic
        dec_trans = evaluate_calibrated_decision("Abebe Bikila", "Bikila Abebe", calibration=calib)
        assert dec_trans.outcome == "mismatch"
        assert dec_trans.is_approved is False
        assert dec_trans.reason == "transposed_name_components"

        # 3. Arbitrary vowel shift (Abebe vs Ababa)
        dec_vowel = evaluate_calibrated_decision("Abebe Bikila", "Ababa Bikila", calibration=calib)
        assert dec_vowel.outcome == "mismatch"
        assert dec_vowel.is_approved is False
        assert dec_vowel.reason == "conflicting_given_name"

    def test_structural_review_triggers_review_decision(self):
        calib = calibrate_thresholds(config=CalibrationConfig(max_false_match_rate=0.01))

        # Initials in name
        dec_init = evaluate_calibrated_decision("A. Bikila", "Abebe Bikila", calibration=calib)
        assert dec_init.outcome == "review"
        assert dec_init.is_approved is False
        assert dec_init.requires_review is True
        assert dec_init.reason == "initials_in_name"

        # Missing component (2 vs 3 tokens with shared prefix)
        dec_miss = evaluate_calibrated_decision("Abebe Bikila", "Abebe Bikila Desta", calibration=calib)
        assert dec_miss.outcome == "review"
        assert dec_miss.requires_review is True
        assert dec_miss.reason == "missing_name_component"

"""Unit tests for representative name matching fixtures (guide5 Task 14).

Verifies:
1. Consented/de-identified pairs reviewed by native speakers are present and valid.
2. Near-identical different people (brothers, sisters, transposed components, arbitrary vowel changes) are included.
3. Script variants (Amharic Ethiopic-to-Latin, Fidel homophones, approved Latin variations) are included.
4. Short names (2-token names, 2-character minimal tokens) are included.
5. OCR errors (Latin digit/letter confusions, Ethiopic visual glyph confusions) are included.
6. Dataset supports person-level splitting with zero data leakage across train and eval partitions.
7. Fixtures cleanly bridge to CalibrationDataset and calibration algorithms.
"""

import pytest

from fayda_mcp.matching.calibration import calibrate_thresholds
from fayda_mcp.matching.fixtures import (
    FIXTURES_SPEC_VERSION,
    RepresentativeFixtureDataset,
    RepresentativeNamePair,
    get_representative_pairs,
    load_representative_fixtures,
)


@pytest.fixture
def dataset() -> RepresentativeFixtureDataset:
    return load_representative_fixtures()


# ===========================================================================
# 1. Dataset Loading and Schema Integrity Tests
# ===========================================================================


def test_load_representative_fixtures_schema(dataset: RepresentativeFixtureDataset):
    """Dataset loads successfully with valid schema and non-empty pairs."""
    assert dataset.dataset_name == "ethiopian_representative_name_pairs_v1"
    assert dataset.dataset_version == "1.0.0"
    assert dataset.total_count >= 30
    assert dataset.same_person_count > 0
    assert dataset.different_person_count > 0

    # Ensure every pair has required fields
    for p in dataset.pairs:
        assert p.pair_id.startswith("pair_")
        assert p.person_id.startswith("p_")
        assert bool(p.expected_name.strip())
        assert bool(p.provider_name.strip())
        assert isinstance(p.is_same_person, bool)
        assert p.script_type in ("latin_to_latin", "ethiopic_to_latin", "ethiopic_to_ethiopic")


def test_get_representative_pairs_utility():
    """get_representative_pairs returns list of RepresentativeNamePair objects."""
    pairs = get_representative_pairs()
    assert isinstance(pairs, list)
    assert len(pairs) > 0
    assert all(isinstance(p, RepresentativeNamePair) for p in pairs)


# ===========================================================================
# 2. Near-Identical Different People Fixtures
# ===========================================================================


def test_near_identical_different_people_fixtures(dataset: RepresentativeFixtureDataset):
    """Dataset includes near-identical different individuals sharing patronymics or transposed."""
    near_identical = dataset.filter_near_identical_different()
    assert len(near_identical) >= 7

    # All near-identical different pairs must have is_same_person=False
    assert all(not p.is_same_person for p in near_identical)

    # Check for brothers sharing father's name (e.g. Abebe Bikila vs Kenenisa Bikila)
    brother_pairs = [p for p in near_identical if "different_brothers" in p.tags]
    assert len(brother_pairs) >= 2
    assert any(p.expected_name == "Abebe Bikila" and p.provider_name == "Kenenisa Bikila" for p in brother_pairs)
    assert any(p.expected_name == "Girma Hailu" and p.provider_name == "Tariku Hailu" for p in brother_pairs)

    # Check for sisters sharing father's name (e.g. Almaz Kebede vs Chaltu Kebede)
    sister_pairs = [p for p in near_identical if "different_sisters" in p.tags]
    assert len(sister_pairs) >= 1
    assert any(p.expected_name == "Almaz Kebede" and p.provider_name == "Chaltu Kebede" for p in sister_pairs)

    # Check for transposed patronymics (e.g. Abebe Bikila vs Bikila Abebe)
    transposed_pairs = [p for p in near_identical if "transposed" in p.tags]
    assert len(transposed_pairs) >= 2
    assert any(p.expected_name == "Abebe Bikila" and p.provider_name == "Bikila Abebe" for p in transposed_pairs)

    # Check for single-vowel alterations altering lexical meaning (e.g. Abebe vs Ababa)
    vowel_pairs = [p for p in near_identical if "arbitrary_vowels" in p.tags]
    assert len(vowel_pairs) >= 1
    assert any(p.expected_name == "Abebe Bikila" and p.provider_name == "Ababa Bikila" for p in vowel_pairs)

    # Check for shared grandfather token only
    shared_gf_pairs = [p for p in near_identical if "shared_grandfather" in p.tags]
    assert len(shared_gf_pairs) >= 1


# ===========================================================================
# 3. Script Variants Fixtures (Ethiopic-Latin, Latin-Latin, Homophones)
# ===========================================================================


def test_script_variants_fixtures(dataset: RepresentativeFixtureDataset):
    """Dataset includes Amharic Ethiopic-to-Latin transliterations and homophones."""
    variants = dataset.filter_script_variants()
    assert len(variants) >= 10

    # Ethiopic to Latin pairs
    e2l_pairs = [p for p in variants if p.script_type == "ethiopic_to_latin"]
    assert len(e2l_pairs) >= 4
    # Example: አበበ ቢቂላ vs Abebe Bikila
    assert any("አበበ" in (p.expected_name + p.provider_name) and "Abebe" in (p.expected_name + p.provider_name) for p in e2l_pairs)
    # Example: ወልደ ስላሴ vs Wolde Sellassie
    assert any("ወልደ" in (p.expected_name + p.provider_name) and "Wolde" in (p.expected_name + p.provider_name) for p in e2l_pairs)
    # Example: ኃይለ ማርያም vs Haile Maryam / Hayle Maryam
    assert any("ኃይለ" in (p.expected_name + p.provider_name) for p in e2l_pairs)

    # Fidel homophone pairs (Ethiopic to Ethiopic, different letters, identical pronunciation)
    homophone_pairs = [p for p in variants if p.category == "fidel_homophone"]
    assert len(homophone_pairs) >= 4
    # ኃይሉ vs ሀይሉ (hwt vs haleta)
    assert any("ኃይሉ" in p.expected_name and "ሀይሉ" in p.provider_name for p in homophone_pairs)
    # ሠላም vs ሰላም (nigus vs esat)
    assert any("ሠላም" in p.expected_name and "ሰላም" in p.provider_name for p in homophone_pairs)
    # ዓለሙ vs አለሙ (ayn vs aleph)
    assert any("ዓለሙ" in p.expected_name and "አለሙ" in p.provider_name for p in homophone_pairs)
    # ፀጋዬ vs ጸጋዬ (tsappa vs tsegar)
    assert any("ፀጋዬ" in p.expected_name and "ጸጋዬ" in p.provider_name for p in homophone_pairs)

    # Latin approved spelling variations (e.g. Wolde vs Welde)
    latin_variants = [p for p in variants if p.script_type == "latin_to_latin" and p.category == "approved_variation"]
    assert len(latin_variants) >= 2
    assert any(p.expected_name == "Wolde Selassie" and p.provider_name == "Welde Selassie" for p in latin_variants)


# ===========================================================================
# 4. Short Names Fixtures
# ===========================================================================


def test_short_names_fixtures(dataset: RepresentativeFixtureDataset):
    """Dataset includes short 2-token and minimal token names."""
    short_names = dataset.filter_short_names()
    assert len(short_names) >= 5

    # 2-token Ethiopian Muslim names (e.g. Ali Abdu)
    assert any("Ali Abdu" in p.expected_name for p in short_names)

    # Minimal 2-character tokens (e.g. Bo Gu)
    assert any(p.expected_name == "Bo Gu" for p in short_names)

    # Short Ethiopic names (e.g. ቦ ጉ)
    assert any("ቦ ጉ" in p.expected_name for p in short_names)

    # Short name negative (e.g. brothers sharing father in 2-token name: Ali Abdu vs Omar Abdu)
    assert any(p.expected_name == "Ali Abdu" and p.provider_name == "Omar Abdu" and not p.is_same_person for p in short_names)


# ===========================================================================
# 5. OCR Errors Fixtures
# ===========================================================================


def test_ocr_errors_fixtures(dataset: RepresentativeFixtureDataset):
    """Dataset includes Latin and Ethiopic visual OCR confusions."""
    ocr_pairs = dataset.filter_ocr_errors()
    assert len(ocr_pairs) >= 6

    # Latin digit/letter confusions
    # Digit 1 for lowercase l (Bikila -> Biki1a or Ali -> A1i)
    assert any("1" in p.provider_name and "Bikila" in p.expected_name for p in ocr_pairs)
    assert any("1" in p.provider_name and "Ali" in p.expected_name for p in ocr_pairs)
    # Digit 0 for capital/lowercase O (Wolde -> W0lde)
    assert any("0" in p.provider_name and "Wolde" in p.expected_name for p in ocr_pairs)
    # Ligature confusions: rn for m (Mamo -> Marno)
    assert any("Marno" in p.provider_name for p in ocr_pairs)
    # Broken curve / ligature: Cl for D (Desta -> Clesta)
    assert any("Clesta" in p.provider_name for p in ocr_pairs)

    # Ethiopic OCR visual glyph confusions
    # ka ከ for ba በ (አበበ -> አከከ)
    assert any("አከከ" in p.provider_name for p in ocr_pairs)
    # ba በ for ka ከ (ከበደ -> በከደ)
    assert any("በከደ" in p.provider_name for p in ocr_pairs)
    # ra ረ for lu ሉ (ኃይሉ -> ኃይረ)
    assert any("ኃይረ" in p.provider_name for p in ocr_pairs)


# ===========================================================================
# 6. Leakage-Free Person Splitting Tests (Task 15 Prerequisite)
# ===========================================================================


def test_split_by_person_guarantees_zero_leakage(dataset: RepresentativeFixtureDataset):
    """split_by_person ensures no person_id appears in both train and eval partitions."""
    train_ds, eval_ds = dataset.split_by_person(eval_ratio=0.30, seed=123)

    assert train_ds.total_count > 0
    assert eval_ds.total_count > 0
    assert train_ds.total_count + eval_ds.total_count == dataset.total_count

    # Intersection of person IDs must be empty (zero leakage)
    overlap = train_ds.unique_person_ids.intersection(eval_ds.unique_person_ids)
    assert len(overlap) == 0, f"Found leaked person IDs across splits: {overlap}"


# ===========================================================================
# 7. Bridge to Calibration Engine Tests
# ===========================================================================


def test_to_calibration_dataset_bridge(dataset: RepresentativeFixtureDataset):
    """RepresentativeFixtureDataset cleanly converts to CalibrationDataset and runs calibration."""
    calib_ds = dataset.to_calibration_dataset()
    assert calib_ds.total_count == dataset.total_count
    assert len(calib_ds.same_person_pairs) > 0
    assert len(calib_ds.different_person_pairs) > 0

    # Verify calibration engine can calibrate on this dataset
    res = calibrate_thresholds(calib_ds)
    assert res.is_host_limit_satisfied is True
    assert 0.50 <= res.threshold_approved <= 1.00
    assert res.threshold_review < res.threshold_approved

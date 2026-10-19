"""Representative fixtures loader and datasets for Ethiopian name matching (guide5 Task 14).

Per guide5 specification:
- Use consented/de-identified pairs reviewed by native speakers.
- Include near-identical different people (brothers, sisters, transposed patronymics, arbitrary vowels).
- Include script variants (Amharic Ethiopic-to-Latin, Fidel homophones, Latin variations).
- Include short names (2-token names, 2-character minimal tokens).
- Include OCR errors if OCR is used (Latin digit/letter confusions, Ethiopic visual glyph confusions).
- Provide person-level splitting to prevent data leakage in calibration and evaluation.
"""

import json
from pathlib import Path
import random
from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, ConfigDict, Field

from fayda_mcp.matching.calibration import CalibrationDataset, LabeledNamePair

FIXTURES_SPEC_VERSION: str = "fixtures-v1"

# Primary package data path and test fallback path
PACKAGE_FIXTURES_PATH: Path = (
    Path(__file__).resolve().parent / "data" / "representative_name_pairs.json"
)
TEST_FIXTURES_PATH: Path = (
    Path(__file__).resolve().parent.parent.parent.parent / "tests" / "fixtures" / "representative_name_pairs.json"
)
DEFAULT_FIXTURES_PATH: Path = (
    PACKAGE_FIXTURES_PATH if PACKAGE_FIXTURES_PATH.exists() else TEST_FIXTURES_PATH
)


class RepresentativeNamePair(BaseModel):
    """A single representative Ethiopian name pair with ground-truth and linguistic metadata."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    pair_id: str = Field(..., description="Unique pair identifier")
    person_id: str = Field(..., description="Unique person cluster identifier for leakage-free splitting")
    expected_name: str = Field(..., description="Expected name from host application submission")
    provider_name: str = Field(..., description="Name claim from national ID / eSignet / OCR")
    is_same_person: bool = Field(..., description="Ground truth: True if same individual, False if different")
    category: str = Field(..., description="Category: exact_match, approved_variation, transliteration, near_identical_different, short_name, ocr_error, fidel_homophone, initial_review, etc.")
    script_type: str = Field(..., description="Script comparison type: latin_to_latin, ethiopic_to_latin, ethiopic_to_ethiopic")
    language: Optional[str] = Field(default=None, description="Language code ('am' or 'en')")
    tags: List[str] = Field(default_factory=list, description="Categorical tags for filtering")
    notes: Optional[str] = Field(default=None, description="Linguistic notes or rationale reviewed by native speakers")

    @property
    def is_near_identical_different(self) -> bool:
        """True if this represents different people who share patronymics, transposition, or minimal edits."""
        return (not self.is_same_person) and ("near_identical_different" in self.tags or self.category == "near_identical_different")

    @property
    def is_script_variant(self) -> bool:
        """True if this pair tests transliteration or script variation."""
        return "script_variant" in self.tags or self.category in ("transliteration", "approved_variation", "fidel_homophone")

    @property
    def is_short_name(self) -> bool:
        """True if this pair tests short names (2 tokens or very short tokens)."""
        return "short_name" in self.tags or self.category == "short_name"

    @property
    def is_ocr_error(self) -> bool:
        """True if this pair tests visual OCR confusions."""
        return "ocr_error" in self.tags or self.category == "ocr_error"


class RepresentativeFixtureDataset(BaseModel):
    """Dataset containing representative Ethiopian name pairs with filtering and splitting capabilities."""

    model_config = ConfigDict(extra="forbid")

    dataset_version: str = Field(default="1.0.0", description="Dataset schema version")
    dataset_name: str = Field(default="ethiopian_representative_name_pairs_v1", description="Dataset identifier")
    description: str = Field(..., description="Dataset description")
    pairs: List[RepresentativeNamePair] = Field(..., description="List of representative name pairs")

    @property
    def total_count(self) -> int:
        return len(self.pairs)

    @property
    def same_person_count(self) -> int:
        return sum(1 for p in self.pairs if p.is_same_person)

    @property
    def different_person_count(self) -> int:
        return sum(1 for p in self.pairs if not p.is_same_person)

    @property
    def unique_person_ids(self) -> Set[str]:
        return {p.person_id for p in self.pairs}

    def filter_by_tag(self, tag: str) -> List[RepresentativeNamePair]:
        """Filter pairs containing a specific tag."""
        return [p for p in self.pairs if tag in p.tags]

    def filter_by_category(self, category: str) -> List[RepresentativeNamePair]:
        """Filter pairs matching a specific category."""
        return [p for p in self.pairs if p.category == category]

    def filter_by_script_type(self, script_type: str) -> List[RepresentativeNamePair]:
        """Filter pairs matching a specific script comparison type."""
        return [p for p in self.pairs if p.script_type == script_type]

    def filter_near_identical_different(self) -> List[RepresentativeNamePair]:
        """Filter pairs of near-identical different people (brothers, transposed, arbitrary vowels)."""
        return [p for p in self.pairs if p.is_near_identical_different]

    def filter_script_variants(self) -> List[RepresentativeNamePair]:
        """Filter pairs testing script variations (Ethiopic-to-Latin, homophones, approved Latin variations)."""
        return [p for p in self.pairs if p.is_script_variant]

    def filter_short_names(self) -> List[RepresentativeNamePair]:
        """Filter pairs testing short names."""
        return [p for p in self.pairs if p.is_short_name]

    def filter_ocr_errors(self) -> List[RepresentativeNamePair]:
        """Filter pairs testing visual OCR substitutions."""
        return [p for p in self.pairs if p.is_ocr_error]

    def split_by_person(
        self,
        eval_ratio: float = 0.3,
        seed: int = 42,
    ) -> Tuple["RepresentativeFixtureDataset", "RepresentativeFixtureDataset"]:
        """Split dataset into train and eval sets by person_id to avoid data leakage (guide5 Task 15 prerequisite).

        Guarantees that no person_id present in the train split appears in the eval split.
        """
        rng = random.Random(seed)
        unique_persons = sorted(list(self.unique_person_ids))
        rng.shuffle(unique_persons)

        eval_count = max(1, int(len(unique_persons) * eval_ratio))
        eval_persons = set(unique_persons[:eval_count])
        train_persons = set(unique_persons[eval_count:])

        train_pairs = [p for p in self.pairs if p.person_id in train_persons]
        eval_pairs = [p for p in self.pairs if p.person_id in eval_persons]

        train_dataset = RepresentativeFixtureDataset(
            dataset_version=self.dataset_version,
            dataset_name=f"{self.dataset_name}_train",
            description=f"Train partition of {self.dataset_name} (split by person, seed={seed})",
            pairs=train_pairs,
        )

        eval_dataset = RepresentativeFixtureDataset(
            dataset_version=self.dataset_version,
            dataset_name=f"{self.dataset_name}_eval",
            description=f"Eval partition of {self.dataset_name} (split by person, seed={seed})",
            pairs=eval_pairs,
        )

        return train_dataset, eval_dataset

    def to_calibration_dataset(self) -> CalibrationDataset:
        """Convert to CalibrationDataset for integration with calibration engine."""
        labeled = [
            LabeledNamePair(
                expected_name=p.expected_name,
                provider_name=p.provider_name,
                is_same_person=p.is_same_person,
                label_category=p.category,
                notes=p.notes,
            )
            for p in self.pairs
        ]
        return CalibrationDataset(
            name=self.dataset_name,
            pairs=labeled,
        )


def load_representative_fixtures(
    filepath: Optional[Path | str] = None,
) -> RepresentativeFixtureDataset:
    """Load representative Ethiopian name pair fixtures from JSON file."""
    if filepath is not None:
        path = Path(filepath)
    elif PACKAGE_FIXTURES_PATH.exists():
        path = PACKAGE_FIXTURES_PATH
    else:
        path = TEST_FIXTURES_PATH

    if not path.exists():
        raise FileNotFoundError(f"Representative fixtures file not found at: {path}")

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    return RepresentativeFixtureDataset(**data)


def get_representative_pairs(
    filepath: Optional[Path | str] = None,
) -> List[RepresentativeNamePair]:
    """Retrieve list of representative Ethiopian name pairs."""
    return load_representative_fixtures(filepath).pairs

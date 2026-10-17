"""Unit tests for Task 04: Amharic Ethiopic-to-Latin transliteration and variant bounding.

Verifies:
- Versioned mapping: amharic-translit-v1.
- Transliteration of standard Ethiopian Fidel names into canonical Latin.
- Candidate spelling variations (e.g. Abebe, Wolde/Welde, Bikila/Biqila).
- Strict bounding on generated variants (prevents combinatorial explosion).
- Structure and token order preservation.
"""

import pytest

from fayda_mcp.matching.transliteration import (
    AMHARIC_FIDEL_TABLE,
    AMHARIC_TRANSLITERATION_VERSION,
    DEFAULT_MAX_TOTAL_VARIANTS,
    DEFAULT_MAX_VARIANTS_PER_TOKEN,
    TokenTransliteration,
    TransliterationResult,
    transliterate_amharic_to_latin,
    transliterate_token,
)


class TestAmharicTransliterationMapping:
    """Verifies core transliteration table coverage and versioning."""

    def test_versioning_metadata(self):
        """Transliteration mapping is explicitly versioned as amharic-translit-v1."""
        assert AMHARIC_TRANSLITERATION_VERSION == "amharic-translit-v1"
        res = transliterate_amharic_to_latin("አበበ")
        assert res is not None
        assert res.version == AMHARIC_TRANSLITERATION_VERSION

    def test_table_coverage_all_orders(self):
        """Table covers 1st through 7th orders of major Amharic consonant series."""
        # Check 'በ' series
        assert AMHARIC_FIDEL_TABLE["በ"][0] == "be"
        assert AMHARIC_FIDEL_TABLE["ቡ"][0] == "bu"
        assert AMHARIC_FIDEL_TABLE["ቢ"][0] == "bi"
        assert AMHARIC_FIDEL_TABLE["ባ"][0] == "ba"
        assert AMHARIC_FIDEL_TABLE["ቤ"][0] == "be"
        assert AMHARIC_FIDEL_TABLE["ብ"][0] == "b"
        assert AMHARIC_FIDEL_TABLE["ቦ"][0] == "bo"

        # Check 'ተ' series
        assert AMHARIC_FIDEL_TABLE["ተ"][0] == "te"
        assert AMHARIC_FIDEL_TABLE["ቱ"][0] == "tu"
        assert AMHARIC_FIDEL_TABLE["ቲ"][0] == "ti"
        assert AMHARIC_FIDEL_TABLE["ታ"][0] == "ta"
        assert AMHARIC_FIDEL_TABLE["ቴ"][0] == "te"
        assert AMHARIC_FIDEL_TABLE["ት"][0] == "t"
        assert AMHARIC_FIDEL_TABLE["ቶ"][0] == "to"


class TestCanonicalNameTransliteration:
    """Verifies canonical Latin outputs for representative Ethiopian names."""

    def test_abebe_bikila(self):
        """Transliterates 'አበበ ቢቂላ' into canonical 'abebe bikila'."""
        res = transliterate_amharic_to_latin("አበበ ቢቂላ")
        assert res is not None
        assert res.canonical == "abebe bikila"
        assert res.is_fully_transliterated is True
        assert res.unmapped_characters == []
        assert len(res.token_transliterations) == 2
        assert res.token_transliterations[0].canonical_token == "abebe"
        assert res.token_transliterations[1].canonical_token == "bikila"

    def test_welde_wolde_variations(self):
        """Transliterates 'ወልደ' into canonical 'welde' with 'wolde' among approved variants."""
        res = transliterate_amharic_to_latin("ወልደ")
        assert res is not None
        assert res.canonical == "welde"
        assert "wolde" in res.variants

    def test_q_k_alternates(self):
        """Transliterates 'ቢቂላ' with both 'bikila' and 'biqila' variants."""
        res = transliterate_amharic_to_latin("ቢቂላ")
        assert res is not None
        assert res.canonical == "bikila"
        assert "biqila" in res.variants

    def test_haile_selassie(self):
        """Transliterates 'ኃይለ ሥላሴ' preserving multi-word patronymic structure."""
        res = transliterate_amharic_to_latin("ኃይለ ሥላሴ")
        assert res is not None
        assert res.token_transliterations[0].canonical_token == "haile"
        assert res.token_transliterations[1].canonical_token == "selase"
        assert any("selassie" in v for v in res.variants)
        assert res.canonical == "haile selase"
        assert len(res.token_transliterations) == 2

    def test_tesfaye(self):
        """Transliterates 'ተስፋዬ' to canonical 'tesfaye'."""
        res = transliterate_amharic_to_latin("ተስፋዬ")
        assert res is not None
        assert res.canonical == "tesfaye"


class TestVariantBounding:
    """Verifies that generated variants are strictly bounded to prevent combinatorial explosion."""

    def test_per_token_bounding(self):
        """Single token variants are strictly bounded at max_variants_per_token."""
        # Word with multiple ambiguous characters
        token = "ቀቀቀቀ"
        res = transliterate_token(token, max_variants=6)
        assert len(res.variants) <= 6

    def test_full_name_variant_bounding(self):
        """Total variants across multi-token name are strictly bounded at max_variants."""
        # 4-token name with multiple variations in each token
        long_name = "ቀቀቀ ወወወ ሸሸሸ ቀቀቀ"
        res = transliterate_amharic_to_latin(long_name, max_variants=16)
        assert res is not None
        assert len(res.variants) <= 16
        assert len(res.variants) == len(set(res.variants))  # All unique
        assert res.variants[0] == res.canonical  # Canonical is always primary (index 0)

    def test_default_variant_caps(self):
        """Default total cap is 32 and default token cap is 8."""
        assert DEFAULT_MAX_TOTAL_VARIANTS == 32
        assert DEFAULT_MAX_VARIANTS_PER_TOKEN == 8


class TestEdgeCasesAndStructure:
    """Verifies handling of punctuation, word dividers, and empty inputs."""

    def test_ethiopic_wordspace_divider(self):
        """Ethiopic wordspace (U+1361 '፡') separates tokens correctly."""
        res = transliterate_amharic_to_latin("አበበ፡ቢቂላ፡ደራርቱ")
        assert res is not None
        assert len(res.token_transliterations) == 3
        assert res.canonical == "abebe bikila derartu"

    def test_unmapped_character_tracking(self):
        """Non-Fidel characters are recorded in unmapped_characters without crashing."""
        res = transliterate_amharic_to_latin("አበበ ★ ቢቂላ")
        assert res is not None
        assert res.is_fully_transliterated is False
        assert "★" in res.unmapped_characters

    def test_empty_and_none_input(self):
        """None or empty string returns None."""
        assert transliterate_amharic_to_latin(None) is None
        assert transliterate_amharic_to_latin("") is None
        assert transliterate_amharic_to_latin("   \t  ") is None

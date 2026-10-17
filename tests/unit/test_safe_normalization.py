"""Unit tests for Task 02: Normalize safely.

Verifies:
- Unicode NFC normalization (composing decomposed forms).
- Latin case-folding (converts Latin to canonical lowercase, no-op on Ethiopic).
- Collapsed whitespace (multiple whitespace, tabs, newlines, non-breaking space, Ethiopic word divider).
- Preserves original raw strings and original token components.
- Strictly preserves token order (patronymic sequence maintained).
- Preserves meaningful letters (vowels, doubled consonants, glottal apostrophes, hyphens).
"""

import unicodedata
import pytest

from fayda_mcp.matching.normalization import (
    NormalizedName,
    normalize_name,
    normalize_name_safely,
)


class TestSafeNormalization:
    """Tests for normalize_name_safely and normalize_name according to guide5 Task 02."""

    def test_unicode_nfc_composition(self):
        """Decomposed characters (NFD) are composed canonically into NFC."""
        # 'e' + combining acute accent (\u0301) vs precomposed 'é' (\u00e9)
        decomposed = "Beyene\u0301"
        composed = "Beyené"

        res_decomp = normalize_name_safely(decomposed)
        res_comp = normalize_name_safely(composed)

        assert res_decomp is not None and res_comp is not None
        assert res_decomp.normalized == res_comp.normalized
        assert unicodedata.is_normalized("NFC", res_decomp.normalized)

    def test_latin_case_folding(self):
        """Latin characters undergo full case-folding; Ethiopic characters are unaffected."""
        latin_name = "ABEBE BIKILA"
        res_latin = normalize_name_safely(latin_name)
        assert res_latin is not None
        assert res_latin.normalized == "abebe bikila"
        assert res_latin.tokens == ["abebe", "bikila"]

        ethiopic_name = "አበበ ቢቂላ"
        res_eth = normalize_name_safely(ethiopic_name)
        assert res_eth is not None
        assert res_eth.normalized == "አበበ ቢቂላ"
        assert res_eth.tokens == ["አበበ", "ቢቂላ"]

    def test_collapsed_whitespace(self):
        """Multiple spaces, tabs, newlines, and non-breaking spaces are collapsed to single ASCII space."""
        messy_name = "  Abebe \t\n  Bikila\u00a0\u00a0Derartu   "
        res = normalize_name_safely(messy_name)
        assert res is not None
        assert res.normalized == "abebe bikila derartu"
        assert res.tokens == ["abebe", "bikila", "derartu"]

    def test_ethiopic_wordspace_separator(self):
        """Ethiopic wordspace (U+1361 '፡') is treated as a token separator and collapsed to space."""
        eth_wordspace = "አበበ፡ቢቂላ፡ደራርቱ"
        res = normalize_name_safely(eth_wordspace)
        assert res is not None
        assert res.normalized == "አበበ ቢቂላ ደራርቱ"
        assert res.tokens == ["አበበ", "ቢቂላ", "ደራርቱ"]

    def test_preserves_originals(self):
        """Preserves original raw string and original token casings/characters."""
        raw_name = "  Haile Selassie  "
        res = normalize_name_safely(raw_name)
        assert res is not None
        assert res.original == raw_name
        assert res.original_tokens == ["Haile", "Selassie"]
        assert res.tokens == ["haile", "selassie"]

    def test_preserves_token_order(self):
        """Strictly preserves Ethiopian patronymic token order (given, father, grandfather)."""
        name = "Kenenisa Bekele Beyecha"
        res = normalize_name_safely(name)
        assert res is not None
        assert res.tokens == ["kenenisa", "bekele", "beyecha"]
        assert res.tokens[0] == "kenenisa"
        assert res.tokens[1] == "bekele"
        assert res.tokens[2] == "beyecha"

    def test_preserves_meaningful_letters(self):
        """Does not destructively alter glottals, apostrophes, hyphens, vowels, or doubled consonants."""
        # Glottal stop / apostrophe preserved
        res_apostrophe = normalize_name_safely("T'esfaye")
        assert res_apostrophe is not None
        assert res_apostrophe.normalized == "t'esfaye"
        assert "t'esfaye" in res_apostrophe.tokens

        # Hyphenated names preserved
        res_hyphen = normalize_name_safely("Haile-Selassie")
        assert res_hyphen is not None
        assert res_hyphen.normalized == "haile-selassie"

        # Doubled consonants are preserved (not deduplicated)
        res_doubled = normalize_name_safely("Abbebe")
        res_single = normalize_name_safely("Abebe")
        assert res_doubled is not None and res_single is not None
        assert res_doubled.normalized == "abbebe"
        assert res_single.normalized == "abebe"
        assert res_doubled.normalized != res_single.normalized

        # Distinct vowels are preserved
        res_vowel1 = normalize_name_safely("Wolde")
        res_vowel2 = normalize_name_safely("Welde")
        assert res_vowel1 is not None and res_vowel2 is not None
        assert res_vowel1.normalized == "wolde"
        assert res_vowel2.normalized == "welde"
        assert res_vowel1.normalized != res_vowel2.normalized

    def test_empty_and_whitespace_only_handling(self):
        """Returns None for None, empty, or whitespace-only inputs."""
        assert normalize_name_safely(None) is None
        assert normalize_name_safely("") is None
        assert normalize_name_safely("   \t\n  ") is None
        assert normalize_name(None) is None
        assert normalize_name("") is None
        assert normalize_name("   ") is None

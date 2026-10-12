"""Regional language normalization and provider-code mapping module for Fayda MCP.

Adheres strictly to the following requirements:
1. Case-insensitively normalizes BCP 47 language tags and preserves valid subtags
   (script, region, variants).
2. Maps provider-specific language codes (e.g. ISO 639-2/3) only through an explicit catalog:
   - amh -> am (Amharic)
   - eng -> en (English)
   - orm / oro -> om (Afaan Oromoo)
   - som -> so (Somali)
   - tir / tig -> ti (Tigrinya)
   - sid -> sid (Sidaamu Afoo)
   - wal / wol -> wal (Wolaytta)
3. Selection order:
   Step 1: Exact preference match
   Step 2: Primary language match
   Step 3: Configured fallback
   Step 4: Untagged field
4. Handles localized claim keys (name#om), dictionary payloads, and list payloads.
5. Never stringifies a raw dictionary or object as a name.
6. Preserves original Unicode text and never transliterates without explicit request.
7. Locale support does not grant agents access to names or residency fields;
   demographics remain transient.
"""

from typing import Any, Dict, List, Optional, Set, Tuple


# The seven supported regional language targets
SUPPORTED_LOCALES: Set[str] = {"en", "am", "om", "so", "ti", "sid", "wal"}

# Explicit catalog mapping provider-specific or legacy ISO 639-2/3 codes to canonical BCP 47
PROVIDER_LANGUAGE_CATALOG: Dict[str, str] = {
    # English
    "eng": "en",
    # Amharic
    "amh": "am",
    # Afaan Oromoo
    "orm": "om",
    "oro": "om",
    # Somali
    "som": "so",
    # Tigrinya
    "tir": "ti",
    "tig": "ti",
    # Sidama
    "sid": "sid",
    # Wolaytta
    "wal": "wal",
    "wol": "wal",
}


def parse_bcp47(tag: Optional[str]) -> Optional[Tuple[str, str]]:
    """Parse and normalize BCP 47 language tag case-insensitively while preserving valid subtags.

    Returns:
        (canonical_tag, primary_language) e.g. ("en-US", "en"), ("om-Latn-ET", "om"),
        or None if input is invalid/empty.
    """
    if not tag or not isinstance(tag, str):
        return None

    cleaned = tag.strip().replace("_", "-")
    if not cleaned:
        return None

    parts = cleaned.split("-")
    if not parts or not parts[0].isalpha():
        return None

    # 1. Primary language: lowercase, map through catalog if present
    primary = parts[0].lower()
    primary = PROVIDER_LANGUAGE_CATALOG.get(primary, primary)

    script: Optional[str] = None
    region: Optional[str] = None
    variants: List[str] = []

    for p in parts[1:]:
        if not p:
            continue
        # 4-letter script (e.g. Latn, Ethi)
        if len(p) == 4 and p.isalpha() and script is None and region is None:
            script = p.capitalize()
        # 2-letter alpha region (e.g. ET, US) or 3-digit numeric region
        elif (len(p) == 2 and p.isalpha()) or (len(p) == 3 and p.isdigit()):
            if region is None:
                region = p.upper()
            else:
                variants.append(p.lower())
        else:
            variants.append(p.lower())

    canonical_parts = [primary]
    if script:
        canonical_parts.append(script)
    if region:
        canonical_parts.append(region)
    if variants:
        canonical_parts.extend(variants)

    canonical_tag = "-".join(canonical_parts)
    return canonical_tag, primary


def normalize_language_tag(tag: Optional[str]) -> Optional[str]:
    """Convenience helper returning the canonical BCP 47 tag string."""
    parsed = parse_bcp47(tag)
    return parsed[0] if parsed else None


def _is_safe_string(val: Any) -> Optional[str]:
    """Ensure value is a non-empty string and never a stringified object."""
    if val is None or not isinstance(val, str):
        return None
    s = val.strip()
    return s if s else None


class LocalizedEntry:
    """Represents a candidate localized text value with its language tags."""

    def __init__(self, canonical_tag: str, primary_lang: str, text: str) -> None:
        self.canonical_tag = canonical_tag
        self.primary_lang = primary_lang
        self.text = text


def _extract_candidates(val: Any) -> Tuple[List[LocalizedEntry], Optional[str]]:
    """Extract candidate localized entries and untagged default from raw data structures.

    Rejects malformed values and objects.
    """
    entries: List[LocalizedEntry] = []
    untagged: Optional[str] = None

    if val is None:
        return entries, untagged

    if isinstance(val, str):
        safe_str = _is_safe_string(val)
        return entries, safe_str

    if isinstance(val, dict):
        # Case A: eSignet single dictionary: {"@value": "Abebe", "@language": "en"}
        if "@value" in val or "value" in val:
            content = val.get("@value") if "@value" in val else val.get("value")
            safe_text = _is_safe_string(content)
            if safe_text:
                lang_tag = val.get("@language") or val.get("language") or val.get("lang")
                if lang_tag and isinstance(lang_tag, str):
                    parsed = parse_bcp47(lang_tag)
                    if parsed:
                        entries.append(LocalizedEntry(parsed[0], parsed[1], safe_text))
                    else:
                        untagged = safe_text
                else:
                    untagged = safe_text
            return entries, untagged

        # Case B: Multi-language mapping: {"en": "Abebe", "am": "አበበ", "default": "Abebe"}
        for k, v in val.items():
            safe_text = _is_safe_string(v)
            if not safe_text:
                continue

            if k.lower() in ("default", "val", "value", "untagged"):
                if untagged is None:
                    untagged = safe_text
                continue

            parsed = parse_bcp47(k)
            if parsed:
                entries.append(LocalizedEntry(parsed[0], parsed[1], safe_text))

        return entries, untagged

    if isinstance(val, list):
        # List of localized items: [{"@value": "...", "@language": "..."}, ...]
        for item in val:
            if isinstance(item, str):
                safe_str = _is_safe_string(item)
                if safe_str and untagged is None:
                    untagged = safe_str
            elif isinstance(item, dict):
                content = item.get("@value") if "@value" in item else item.get("value")
                safe_text = _is_safe_string(content)
                if not safe_text:
                    continue

                lang_tag = item.get("@language") or item.get("language") or item.get("lang")
                if lang_tag and isinstance(lang_tag, str):
                    parsed = parse_bcp47(lang_tag)
                    if parsed:
                        entries.append(LocalizedEntry(parsed[0], parsed[1], safe_text))
                    elif untagged is None:
                        untagged = safe_text
                elif untagged is None:
                    untagged = safe_text

        return entries, untagged

    return entries, untagged


def select_localized_value(
    val: Any,
    preferred_locales: Optional[List[str]] = None,
    fallback_locale: str = "en",
) -> Optional[str]:
    """Select appropriate localized string adhering strictly to the required resolution order:

    Step 1: Exact preference match
    Step 2: Primary language match
    Step 3: Configured fallback (exact, then primary)
    Step 4: Untagged field

    Preserves original Unicode text without transliteration.
    Never stringifies a raw dict or object as a name.
    """
    entries, untagged = _extract_candidates(val)
    if not entries and untagged:
        return untagged
    if not entries and not untagged:
        return None

    # Step 1: Exact preference match
    if preferred_locales:
        for pref in preferred_locales:
            parsed_pref = parse_bcp47(pref)
            if not parsed_pref:
                continue
            pref_canon = parsed_pref[0].lower()
            for entry in entries:
                if entry.canonical_tag.lower() == pref_canon:
                    return entry.text

    # Step 2: Primary language match
    if preferred_locales:
        for pref in preferred_locales:
            parsed_pref = parse_bcp47(pref)
            if not parsed_pref:
                continue
            pref_primary = parsed_pref[1].lower()
            for entry in entries:
                if entry.primary_lang.lower() == pref_primary:
                    return entry.text

    # Step 3: Configured fallback
    parsed_fallback = parse_bcp47(fallback_locale)
    if parsed_fallback:
        fb_canon = parsed_fallback[0].lower()
        fb_primary = parsed_fallback[1].lower()
        # 3a. Exact fallback match
        for entry in entries:
            if entry.canonical_tag.lower() == fb_canon:
                return entry.text
        # 3b. Primary fallback match
        for entry in entries:
            if entry.primary_lang.lower() == fb_primary:
                return entry.text

    # Step 4: Untagged field
    if untagged:
        return untagged

    # If no preferred, fallback, or untagged matched, return first available entry if any
    if entries:
        return entries[0].text

    return None


def extract_localized_claim(
    claims: Dict[str, Any],
    base_claim_name: str,
    preferred_locales: Optional[List[str]] = None,
    fallback_locale: str = "en",
) -> Optional[str]:
    """Extract localized claim supporting localized claim keys (e.g. name#om, name#am).

    Looks for keys with format `{base_claim_name}#{locale}` or direct `{base_claim_name}`.
    Adheres strictly to the selection order:
    Exact preference -> Primary language -> Configured fallback -> Untagged field.
    """
    entries: List[LocalizedEntry] = []
    untagged: Optional[str] = None

    # 1. Inspect all keys in claims dictionary for localized suffixes (e.g. name#om)
    prefix = f"{base_claim_name.lower()}#"
    for k, v in claims.items():
        k_lower = k.lower()
        safe_text = _is_safe_string(v)
        if not safe_text:
            continue

        if k_lower.startswith(prefix):
            raw_tag = k[len(prefix):]
            parsed = parse_bcp47(raw_tag)
            if parsed:
                entries.append(LocalizedEntry(parsed[0], parsed[1], safe_text))
            elif untagged is None:
                untagged = safe_text

    # 2. Check base claim name directly (e.g. "name": "...")
    direct_val = claims.get(base_claim_name)
    if direct_val is not None:
        direct_entries, direct_untagged = _extract_candidates(direct_val)
        entries.extend(direct_entries)
        if direct_untagged and untagged is None:
            untagged = direct_untagged

    if not entries and untagged:
        return untagged
    if not entries and not untagged:
        return None

    # Execute resolution order:
    # 1. Exact preference
    if preferred_locales:
        for pref in preferred_locales:
            parsed_pref = parse_bcp47(pref)
            if not parsed_pref:
                continue
            pref_canon = parsed_pref[0].lower()
            for entry in entries:
                if entry.canonical_tag.lower() == pref_canon:
                    return entry.text

    # 2. Primary language
    if preferred_locales:
        for pref in preferred_locales:
            parsed_pref = parse_bcp47(pref)
            if not parsed_pref:
                continue
            pref_primary = parsed_pref[1].lower()
            for entry in entries:
                if entry.primary_lang.lower() == pref_primary:
                    return entry.text

    # 3. Configured fallback
    parsed_fallback = parse_bcp47(fallback_locale)
    if parsed_fallback:
        fb_canon = parsed_fallback[0].lower()
        fb_primary = parsed_fallback[1].lower()
        for entry in entries:
            if entry.canonical_tag.lower() == fb_canon:
                return entry.text
        for entry in entries:
            if entry.primary_lang.lower() == fb_primary:
                return entry.text

    # 4. Untagged field
    if untagged:
        return untagged

    if entries:
        return entries[0].text

    return None

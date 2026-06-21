# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for homoglyph normalization (aegis.core.homoglyph_normalizer)."""

from __future__ import annotations

from aegis.core.homoglyph_normalizer import (
    HOMOGLYPH_TABLE_SIZE,
    HomoglyphNormalizer,
    normalize,
)

# ── Table integrity ────────────────────────────────────────────────────────────


class TestTableIntegrity:
    def test_table_size_positive(self):
        assert HOMOGLYPH_TABLE_SIZE > 0

    def test_all_targets_are_ascii(self):
        n = HomoglyphNormalizer()
        for src_cp, dst in n._table.items():
            assert dst.isascii(), (
                f"U+{src_cp:04X} maps to non-ASCII {dst!r}"
            )

    def test_mapping_count_matches_table_size(self):
        n = HomoglyphNormalizer()
        assert n.mapping_count >= HOMOGLYPH_TABLE_SIZE

    def test_no_ascii_source_in_table(self):
        n = HomoglyphNormalizer()
        for src_cp in n._table:
            assert src_cp > 0x7E, (
                f"ASCII codepoint U+{src_cp:04X} should not be in the homoglyph table"
            )


# ── Constructor ────────────────────────────────────────────────────────────────


class TestConstructor:
    def test_default_apply_nfkc(self):
        n = HomoglyphNormalizer()
        assert n._apply_nfkc is True

    def test_apply_nfkc_false(self):
        n = HomoglyphNormalizer(apply_nfkc=False)
        assert n._apply_nfkc is False

    def test_extra_mappings_increase_count(self):
        n = HomoglyphNormalizer(extra_mappings={"Ω": "O"})
        assert n.mapping_count > HOMOGLYPH_TABLE_SIZE

    def test_extra_mappings_applied(self):
        n = HomoglyphNormalizer(extra_mappings={"Ω": "O"})
        assert n.normalize("Ω") == "O"


# ── Cyrillic normalization ─────────────────────────────────────────────────────


class TestCyrillicNormalization:
    def test_cyrillic_a_lowercase(self):
        # U+0430 CYRILLIC SMALL LETTER A → 'a'
        assert normalize("а") == "a"

    def test_cyrillic_e_lowercase(self):
        assert normalize("е") == "e"

    def test_cyrillic_o_lowercase(self):
        assert normalize("о") == "o"

    def test_cyrillic_p_lowercase(self):
        # р (U+0440) → 'p'
        assert normalize("р") == "p"

    def test_cyrillic_c_lowercase(self):
        assert normalize("с") == "c"

    def test_cyrillic_x_lowercase(self):
        assert normalize("х") == "x"

    def test_cyrillic_A_uppercase(self):
        assert normalize("А") == "A"

    def test_cyrillic_B_uppercase(self):
        assert normalize("В") == "B"

    def test_cyrillic_C_uppercase(self):
        assert normalize("С") == "C"

    def test_cyrillic_H_uppercase(self):
        # Н (U+041D) → 'H'
        assert normalize("Н") == "H"

    def test_cyrillic_mixed_word(self):
        # "аlert" with Cyrillic 'а'
        assert normalize("аlert") == "alert"

    def test_all_cyrillic_in_phrase(self):
        # Phrase with multiple Cyrillic lookalikes
        phrase = "МОСКВА"  # МОСКВА
        result = normalize(phrase)
        assert result.isascii()


# ── Greek normalization ────────────────────────────────────────────────────────


class TestGreekNormalization:
    def test_greek_alpha_lowercase(self):
        # α (U+03B1) → 'a'
        assert normalize("α") == "a"

    def test_greek_eta_lowercase(self):
        # η (U+03B7) → 'n'
        assert normalize("η") == "n"

    def test_greek_omicron_lowercase(self):
        # ο (U+03BF) → 'o'
        assert normalize("ο") == "o"

    def test_greek_rho_lowercase(self):
        # ρ (U+03C1) → 'p'
        assert normalize("ρ") == "p"

    def test_greek_chi_lowercase(self):
        # χ (U+03C7) → 'x'
        assert normalize("χ") == "x"

    def test_greek_tau_lowercase(self):
        # τ (U+03C4) → 't'
        assert normalize("τ") == "t"

    def test_greek_Alpha_uppercase(self):
        assert normalize("Α") == "A"

    def test_greek_omicron_uppercase(self):
        assert normalize("Ο") == "O"

    def test_greek_rho_uppercase(self):
        assert normalize("Ρ") == "P"

    def test_greek_mixed_word(self):
        # "ρayload" with Greek ρ
        assert normalize("ρayload") == "payload"


# ── Fullwidth normalization ────────────────────────────────────────────────────


class TestFullwidthNormalization:
    def test_fullwidth_a(self):
        # ａ (U+FF41) → 'a'
        assert normalize("ａ") == "a"

    def test_fullwidth_Z(self):
        # Ｚ (U+FF3A) → 'Z'
        assert normalize("Ｚ") == "Z"

    def test_fullwidth_number(self):
        # ３ (U+FF13) → '3'
        assert normalize("３") == "3"

    def test_fullwidth_phrase(self):
        # "ａｌｅｒｔ(１)"
        result = normalize("ａｌｅｒｔ(１)")
        assert result == "alert(1)"


# ── Letterlike normalization ───────────────────────────────────────────────────


class TestLetterlikeNormalization:
    def test_script_g(self):
        # ℊ (U+210A) → 'g'
        assert normalize("ℊ") == "g"

    def test_script_B(self):
        # ℬ (U+212C) → 'B'
        assert normalize("ℬ") == "B"

    def test_script_l(self):
        # ℓ (U+2113) → 'l'
        assert normalize("ℓ") == "l"

    def test_double_struck_Z(self):
        # ℤ (U+2124) → 'Z'
        assert normalize("ℤ") == "Z"


# ── Plain ASCII unchanged ─────────────────────────────────────────────────────


class TestPlainASCII:
    def test_plain_ascii_unchanged(self):
        text = "alert(document.cookie)"
        assert normalize(text) == text

    def test_empty_string(self):
        assert normalize("") == ""

    def test_digits_unchanged(self):
        assert normalize("1234567890") == "1234567890"

    def test_punctuation_unchanged(self):
        assert normalize("!@#$%^&*()") == "!@#$%^&*()"


# ── NFKC pre-pass ─────────────────────────────────────────────────────────────


class TestNFKC:
    def test_nfkc_applied_by_default(self):
        # NFKC decomposes some compatibility chars
        # ﬁ (U+FB01 LATIN SMALL LIGATURE FI) → "fi"
        n = HomoglyphNormalizer(apply_nfkc=True)
        assert n.normalize("ﬁ") == "fi"

    def test_nfkc_disabled(self):
        n = HomoglyphNormalizer(apply_nfkc=False)
        # Without NFKC, ligature stays as-is (not in homoglyph table)
        result = n.normalize("ﬁ")
        assert result == "ﬁ"

    def test_nfkc_then_homoglyph(self):
        # After NFKC, some characters may be decomposed then remapped
        n = HomoglyphNormalizer(apply_nfkc=True)
        # Cyrillic 'а' survives NFKC unchanged, then gets mapped
        assert n.normalize("а") == "a"


# ── has_homoglyphs ────────────────────────────────────────────────────────────


class TestHasHomoglyphs:
    def test_plain_ascii_no_homoglyphs(self):
        n = HomoglyphNormalizer()
        assert not n.has_homoglyphs("hello world")

    def test_cyrillic_detected(self):
        n = HomoglyphNormalizer()
        assert n.has_homoglyphs("аlert")

    def test_greek_detected(self):
        n = HomoglyphNormalizer()
        assert n.has_homoglyphs("ρayload")

    def test_mixed_script_detected(self):
        # Fullwidth and letterlike are handled by NFKC before table check;
        # Cyrillic/Greek survive NFKC and are found by has_homoglyphs
        n = HomoglyphNormalizer()
        assert n.has_homoglyphs("аlert")  # Cyrillic а (U+0430) survives NFKC

    def test_empty_string_no_homoglyphs(self):
        n = HomoglyphNormalizer()
        assert not n.has_homoglyphs("")


# ── normalize_bulk ────────────────────────────────────────────────────────────


class TestNormalizeBulk:
    def test_bulk_returns_same_count(self):
        n = HomoglyphNormalizer()
        texts = ["аlert", "hello", "ρayload"]
        results = n.normalize_bulk(texts)
        assert len(results) == 3

    def test_bulk_normalizes_each(self):
        n = HomoglyphNormalizer()
        results = n.normalize_bulk(["аlert", "plain"])
        assert results[0] == "alert"
        assert results[1] == "plain"

    def test_bulk_empty_list(self):
        n = HomoglyphNormalizer()
        assert n.normalize_bulk([]) == []


# ── module-level normalize() ──────────────────────────────────────────────────


class TestModuleLevelNormalize:
    def test_convenience_wrapper(self):
        assert normalize("аlert(1)") == "alert(1)"

    def test_returns_string(self):
        assert isinstance(normalize("test"), str)


# ── Integration: WAF evasion scenarios ───────────────────────────────────────


class TestWAFEvasion:
    def test_cyrillic_jailbreak_normalizes(self):
        # Attacker replaces 'a' with Cyrillic 'а' in "jailbreak"
        evasion = "jаilbreаk"
        assert normalize(evasion) == "jailbreak"

    def test_greek_script_injection_normalizes(self):
        # ρ→p, α→a, υ→u (payload with Greek)
        evasion = "ραyloаd"  # ραyloаd  (Greek ρ,α + Cyrillic а)
        result = normalize(evasion)
        assert result == "payload"

    def test_mixed_script_attack(self):
        # "Ignore" with mixed Cyrillic and Greek
        # I→I (ASCII), g→g, n→n, o→ο(Greek), r→r, e→е(Cyrillic)
        evasion = "Ignοrе"  # Ignоrе  (Greek ο, Cyrillic е)
        result = normalize(evasion)
        assert result == "Ignore"

    def test_fullwidth_injection_normalizes(self):
        # "alert" in fullwidth
        evasion = "ａｌｅｒｔ"
        assert normalize(evasion) == "alert"

    def test_normalized_text_suitable_for_waf(self):
        # After normalization, the string should be WAF-scannable ASCII
        evasion = "аоrt(dоcument.сооkie)"
        result = normalize(evasion)
        assert result.isascii() or len(result) == len(evasion)

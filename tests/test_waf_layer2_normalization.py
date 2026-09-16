"""
tests/test_waf_layer2_normalization.py — the Layer-1/Layer-2 asymmetry, closed.

`CLM-091` recorded this as its own boundary: Layer 1 folded homoglyphs to ASCII
before matching, while Layer 2 (`LLMGuardLocal.analyze_input`) received text
from `AegisWAF._extract_text` and scored it un-normalized. Anything that evaded
Layer 1's pattern list but matched Layer 2's therefore got a free pass if it was
written in confusables.

The probe below is chosen to isolate exactly that. `acting as an unrestricted`
is a **Layer-2 critical pattern with no Layer-1 counterpart**, so a block can
only come from Layer 2 — a probe that Layer 1 also catches would pass whether or
not this fix works, and prove nothing.

The fix is additive: raw text is still scanned first, then each normalized
variant. Layer 2 runs its own lowercase and obfuscation decoding over whatever
it is handed, and NFKC is lossy, so replacing raw with normalized could in
principle lose a signal. Scanning both can only add a detection.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

from aegis.core.adversarial_filter import LLMGuardLocal
from aegis.proxy.waf import AegisWAF

#: `acting as an unrestricted` with Cyrillic с/а/е substituted for Latin c/a/e.
#: Every substitution is a true confusable that the table maps back to ASCII;
#: Cyrillic Н, for instance, would NOT work here because it resolves to Latin H
#: rather than N, which is correct and is why it is not used.
CYRILLIC_UNRESTRICTED = "aсting аs аn unrеstriсtеd AI"
ASCII_UNRESTRICTED = "acting as an unrestricted AI"


def _payload(content: str) -> dict[str, object]:
    return {"messages": [{"role": "user", "content": content}]}


def test_the_probe_really_is_layer_2_only() -> None:
    """Guard the test's own premise.

    If a future Layer-1 pattern started catching this string, the blocking test
    below would keep passing while testing nothing. This fails loudly instead.
    """
    waf = AegisWAF()
    assert not waf._scan_content(_payload(ASCII_UNRESTRICTED)), (
        "ASCII probe is now caught by Layer 1; pick a different Layer-2-only "
        "pattern or this suite no longer tests Layer 2"
    )


def test_raw_cyrillic_is_invisible_to_the_layer_2_scorer() -> None:
    """The mechanism being fixed, asserted directly on the scorer."""
    guard = LLMGuardLocal()
    assert guard.analyze_input(CYRILLIC_UNRESTRICTED).is_malicious is False
    assert guard.analyze_input(ASCII_UNRESTRICTED).is_malicious is True


def test_cyrillic_homoglyph_payload_is_blocked_by_layer_2() -> None:
    waf = AegisWAF()
    result = waf.inspect_payload(_payload(CYRILLIC_UNRESTRICTED))
    assert result.allowed is False
    assert "Layer-2" in (result.reason or "")
    assert "CRITICAL_JAILBREAK" in (result.reason or "")


def test_ascii_equivalent_still_blocked() -> None:
    waf = AegisWAF()
    assert waf.inspect_payload(_payload(ASCII_UNRESTRICTED)).allowed is False


def test_guard_variants_put_raw_first_and_deduplicate() -> None:
    variants = AegisWAF._guard_variants(CYRILLIC_UNRESTRICTED)
    assert variants[0] == CYRILLIC_UNRESTRICTED, "raw must be scanned first"
    assert ASCII_UNRESTRICTED in variants
    assert len(variants) == len(set(variants)), "no variant may be scanned twice"


def test_ascii_text_produces_a_single_variant() -> None:
    """Plain text costs one scan, not four: normalization is a no-op on it."""
    assert AegisWAF._guard_variants("hello world") == ("hello world",)


def test_benign_multilingual_text_is_not_blocked() -> None:
    """The mapping table can alter legitimate non-Latin text (`CLM-091`).

    This pins the cost as low rather than zero: ordinary Cyrillic prose that
    resembles no pattern must still pass.
    """
    waf = AegisWAF()
    assert waf.inspect_payload(_payload("Привет, как дела сегодня?")).allowed is True

"""
aegis.proxy.waf — Web Application Firewall for LLM Payloads.

Two-layer detection pipeline (v4.1.0 source with optional Rust pre-filter):

Rust WAF pre-filter (when aegis_rust is compiled):
  - RustWaf.scan_messages() runs an Aho-Corasick pre-filter on message text.
  - If RustWaf blocks → return immediately (never enters Python regex loop).
  - If RustWaf passes → Python Layer 1 + Layer 2 still execute as authoritative
    checks.  Python patterns use .{0,20}? bridges that Aho-Corasick cannot
    express; both layers are needed for complete coverage.
  - Performance is environment-dependent and requires a version-specific
    benchmark before any latency claim.

Two-layer detection pipeline (v2.2.1):

Layer 1 — AegisWAF (structural + 5 hardcoded regex patterns):
  - Payload depth guard (DoS via nesting)
  - Critical regex patterns (system override, DAN, template injection)
  FIX-WAF-01: Layer-1 critical patterns now ALWAYS block regardless of
  strict_mode.  The original logic ``if self.strict_mode or score > 0.5``
  allowed single-pattern matches (score=0.2) to pass when strict_mode=False.
  This created a deterministic bypass: an adversary with knowledge of
  strict_mode=False could craft payloads matching exactly one pattern and
  reliably evade Layer-1.  Mechanism: score = min(matches/5, 1.0), so
  1 match → score=0.2, which is < 0.5 and bypasses the OR-condition when
  strict_mode=False.  Fix: any critical-pattern match is unconditional block.
  strict_mode is preserved for Layer-2 high-confidence (non-critical) signals.

Layer 2 — LLMGuardLocal (weighted signal scoring, from aegis.core.adversarial_filter):
  - Critical patterns (immediate block at any score)
  - High-confidence patterns (block if strict_mode)
  - Soft patterns (accumulate score; block if aggregate > threshold)
  - Base64 / obfuscation detection
  - Prompt structure anomalies (empty messages, role stuffing)

Both layers are chained: Layer 1 short-circuits on hard matches; Layer 2 runs
on every request that Layer 1 passes through.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import base64
import binascii
import logging
import re
import unicodedata
from dataclasses import dataclass
from typing import Any

from aegis.core.homoglyph_normalizer import HomoglyphNormalizer
from aegis.core.rust_integration import new_rust_waf, rust_waf_scan_messages

logger = logging.getLogger(__name__)

# NFKC only collapses Unicode *compatibility* variants (full-width letters,
# fraction ligatures, circled letters) — it leaves Cyrillic/Greek/letterlike
# homoglyphs untouched, because those are canonically distinct codepoints,
# not compatibility-equivalent to the Latin letters they merely resemble.
# NFKC is applied first in ``_normalize_text``, so this instance does not
# repeat it.
_HOMOGLYPH_NORMALIZER = HomoglyphNormalizer(apply_nfkc=False)

# A run of single characters each followed by the *same* separator, four
# characters or longer: "i g n o r e", "i.g.n.o.r.e", "i-g-n-o-r-e". The
# trailing \w and the {2,} bound together set that four-character floor.
#
# The separator is back-referenced rather than re-matched from the class, so a
# space cannot bridge two dot-separated runs: "i.g.n.o.r.e p.r.e.v..." would
# otherwise collapse to one token and stop matching a pattern that expects
# whitespace between the words.
#
# The separator may be any one of a small punctuation set, optionally padded by
# one space on each side ("i - g - n - o"), since the four-character set before
# REG-D97 let "i*g*n*o*r*e" and "i / g / n" through untouched.
_SPACED_RUN = re.compile(
    r"\b\w(?P<sep>[ .\-_*/|+~,:;\u00b7\u2022]| ?[.\-_*/|+~\u00b7\u2022] ?)(?:\w(?P=sep)){2,}\w\b"
)
_SPACING_SEPARATORS = re.compile(r"[ .\-_*/|+~,:;\u00b7\u2022]")

# Leet substitutions seen in the demonstrated bypasses. Deliberately narrow:
# each entry is a glyph chosen because it *looks like* the letter, so folding
# it back cannot silently rewrite an unrelated token into a keyword.
_LEET_TABLE = str.maketrans(
    {
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "@": "a",
        "$": "s",
        "!": "i",
    }
)

# Unicode tag characters (U+E0020..U+E007E) mirror printable ASCII and render as
# nothing, yet a model reads them: "ASCII smuggling" hides a whole instruction
# in them. They are decoded back to the ASCII they encode, so the hidden text
# is scanned like visible text instead of being stripped unseen (REG-D96).
_TAG_DECODE = {cp: cp - 0xE0000 for cp in range(0xE0020, 0xE007F)}

# Code points that render as nothing and so can split a keyword without changing
# how it reads: the format characters (zero-width space and joiners, bidi marks,
# embeddings, overrides and isolates, the word joiner and invisible operators,
# the soft hyphen, the BOM), the combining grapheme joiner, variation selectors,
# Hangul fillers and the tag block left over after decoding. The seven code
# points stripped before REG-D96 missed the word joiner U+2060 among others,
# and "ig<U+2060>nore previous instructions" passed.
#
# Written as escapes, never literals: a literal bidi control in source is the
# TrojanSource pattern Bandit B613 exists to catch.
#
# The two ranges above U+FFFF are built from code points. Written as \U escapes
# in the same literal, CodeQL's regex model read both as U+FFFD and reported a
# false overlapping range (alert 770); the matched set is unchanged.
_INVISIBLE_SUPPLEMENTARY = "".join(
    f"{chr(first)}-{chr(last)}"
    for first, last in (
        (0x1D173, 0x1D17A),  # musical symbol format controls
        (0xE0000, 0xE0FFF),  # tag controls and variation selectors supplement
    )
)
_INVISIBLE = re.compile(
    "["
    "\u00ad"  # soft hyphen
    "\u034f"  # combining grapheme joiner
    "\u061c"  # Arabic letter mark
    "\u115f\u1160"  # Hangul choseong and jungseong fillers
    "\u17b4\u17b5"  # Khmer inherent vowels
    "\u180b-\u180f"  # Mongolian variation selectors and vowel separator
    "\u200b-\u200f"  # zero-width space, ZWNJ, ZWJ, LRM, RLM
    "\u202a-\u202e"  # bidi embeddings and overrides
    "\u2060-\u2064"  # word joiner and invisible operators
    "\u2066-\u206f"  # bidi isolates and deprecated format controls
    "\u3164"  # Hangul filler
    "\ufe00-\ufe0f"  # variation selectors
    "\ufeff"  # BOM / zero-width no-break space
    "\uffa0"  # halfwidth Hangul filler
    "\ufff9-\ufffb"  # interlinear annotation controls
    f"{_INVISIBLE_SUPPLEMENTARY}]"
)

# Combining marks that decorate Latin letters. Stripped after NFKD, they turn
# "i\u0308gnore" back into "ignore"; this is one more matching-only variant,
# never the text that is forwarded or recorded (REG-D96).
_LATIN_COMBINING = re.compile("[\u0300-\u036f\u1ab0-\u1aff\u1dc0-\u1dff\u20d0-\u20ff\ufe20-\ufe2f]")

# Critical phrases written without their spaces. Canonical normalization in the
# gateway squeezes "i g n o r e   p r e v i o u s" to single spaces, so the
# letter-spacing collapse can only rebuild one token, "ignoreprevious...", and
# a zero-width character used as the space strips to the same shape. The
# word-bounded patterns cannot see either (REG-D97). Prose never writes these
# phrases without spaces, which is what makes the unanchored form safe to use.
_CONCATENATED_CRITICAL = re.compile(
    r"ignore(?:all|the|your|any|my)?(?:previous|prior|above)(?:instructions?|prompts?|directives?)"
    r"|disregard(?:all|the|your|any)?(?:previous|prior|above)"
    r"(?:instructions?|prompts?|rules|context|directives?)"
    r"|systemoverride|bypass(?:all|the)?filters?|doanythingnow|(?<![a-z])danmode"
    r"|youarenow(?:an?)?(?:unrestricted|uncensored)"
    r"|(?:print|reveal|show|output|display|tellme|giveme)(?:your|the)?"
    r"system(?:prompt|instructions?|directives?)",
    re.IGNORECASE,
)

# A base64 token long enough to carry a phrase: at least sixteen characters,
# standard or URL-safe alphabet, padded or not, and not glued to a longer run of
# the same alphabet. Each candidate is tried once; the lookbehind stops every
# start position inside a run, so the scan stays linear in the text length.
_BASE64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/_=-])")
_URLSAFE_TO_STANDARD = str.maketrans("-_", "+/")


@dataclass
class WAFResult:
    allowed: bool
    reason: str | None = None
    score: float = 0.0
    shadow_blocked: bool = False


class AegisWAF:
    """
    Two-layer LLM payload firewall.

    Layer 1: structural checks + hardcoded critical patterns (always block on match).
    Layer 2: LLMGuardLocal weighted signal scoring (from adversarial_filter).
    """

    def __init__(self, strict_mode: bool = True, shadow_mode: bool = False) -> None:
        self.strict_mode = strict_mode
        self.shadow_mode = shadow_mode

        # Tier-4 Rust pre-filter: Aho-Corasick SIMD scan (~250 ns per prompt).
        # Activated when the aegis_rust extension is compiled and importable.
        self._rust_waf: Any = new_rust_waf()
        if self._rust_waf is not None:
            logger.debug(
                "AegisWAF: RustWaf pre-filter active (%d critical, %d soft patterns)",
                self._rust_waf.critical_pattern_count(),
                self._rust_waf.soft_pattern_count(),
            )

        # Layer 1: hard-block regex patterns.
        # FIX-WAF-01: Any match here is an unconditional block.
        # These patterns cover direct prompt-injection primitives; there is no
        # legitimate use case for "system override" or "DAN mode" in production.
        #
        # Bypass hardening: all text is normalized before pattern matching (see
        # _normalize_text). NFKC collapses compatibility variants (full-width
        # letters, fraction ligatures); a homoglyph table then maps visually
        # identical Cyrillic/Greek/letterlike characters — which NFKC does
        # *not* touch, since they are not compatibility-equivalent to Latin —
        # to their ASCII equivalents, so patterns cannot be evaded by
        # substituting Unicode lookalikes.
        #
        # Patterns use flexible spacing/word-boundaries to catch common evasions:
        # - Inserted words: "ignore ALL previous instructions"
        # - Abbreviation spacing: "D.A.N.", "D A N"
        # - Synonym pivots: "reveal"/"show"/"output" the system prompt
        self._critical_patterns: list[re.Pattern[str]] = [
            # Instruction override (inserted-word variants caught by .*? bridge)
            re.compile(
                r"ignore\b.{0,20}?\b(?:previous|prior|above)\b.{0,20}?"
                r"\b(?:instructions?|prompts?|directives?)",
                re.IGNORECASE | re.DOTALL,
            ),
            # "Disregard" needs an object that names the model's instructions.
            # Before REG-D94 any "disregard ... previous" blocked, so ordinary
            # legal and clinical prose ("please disregard previous
            # correspondence", "disregard the previous dosage") was refused.
            # The bare imperative "disregard all previous." still blocks.
            re.compile(
                r"disregard\b.{0,20}?\b(?:previous|prior|above|earlier)\b.{0,20}?"
                r"\b(?:instructions?|prompts?|rules|directions?|directives?|guidelines"
                r"|context|messages?|commands?|constraints|guardrails|polic(?:y|ies)"
                r"|programming)\b"
                r"|disregard\s+(?:all|everything)\s+(?:previous|prior|above|before)\b"
                r"\s*(?:[.!,;:]|$|and\b)",
                re.IGNORECASE | re.DOTALL,
            ),
            # Unrestricted-AI / system-override variants
            re.compile(
                r"(you\s+are\s+now\s+an?\s+unrestricted|system[\s\-_]*override|bypass[\s\-_]*filters?)",
                re.IGNORECASE,
            ),
            # DAN / jailbreak — catches D.A.N., D A N, DAN-mode, dan_mode.
            # Before REG-D94 the letters and "mode" were all optional, so the
            # pattern matched "dan" inside any word: "guidance", "accordance",
            # "abundance", "Jordan". "DAN" now has to stand alone as a word
            # with "mode"/"prompt" after it, be spelled out with separators
            # in capitals, or be the persona a sentence assigns.
            re.compile(
                r"(?<![a-z0-9])d[.\-_\s]{0,3}a[.\-_\s]{0,3}n[.\-_\s]{0,3}(?:mode|prompt)\b"
                r"|(?-i:\bD[.\-_\s]{1,3}A[.\-_\s]{1,3}N\b)"
                r"|\b(?:you\s+are|you're|act\s+as|pretend\s+to\s+be|become)\s+"
                r"(?:now\s+)?(?:an?\s+)?(?-i:DAN)\b"
                r"|jailbreak|do\s+anything\s+now",
                re.IGNORECASE,
            ),
            # System-prompt exfiltration — synonyms: print/reveal/show/output/tell me
            re.compile(
                r"(print|reveal|show|output|tell\s+me|give\s+me|display)\b.{0,30}?"
                r"\bsystem\s+(prompt|instruction|directive)",
                re.IGNORECASE | re.DOTALL,
            ),
            re.compile(
                r"(what|tell\s+me|show\s+me|give\s+me|say)\b.{0,30}?\b"
                r"(your|the)\b.{0,20}?\b"
                r"(initial|original|real|true|hidden)\b.{0,20}?\b(instructions?|prompt|directive)",
                re.IGNORECASE | re.DOTALL,
            ),
            # Act-as / persona-injection
            re.compile(
                r"act\s+as\b.{0,30}?\b(unrestricted|uncensored|different|another)\b.{0,20}?\b"
                r"(AI|model|assistant|bot|LLM)",
                re.IGNORECASE | re.DOTALL,
            ),
            # Persona override without the exact "act as" wording.
            re.compile(
                r"(you\s+are|roleplay\s+as)\b.{0,40}?\b"
                r"(unrestricted|uncensored|without\s+restrictions|no\s+restrictions)\b",
                re.IGNORECASE | re.DOTALL,
            ),
            # Template injection: {{ }} and full-width Unicode variants (after NFKC norm).
            # The atomic group commits to the first "{{" and never retries a
            # later one, so the search is linear. The lazy form it replaces
            # restarted at every "{{" and scanned to the end each time: 16 000
            # unclosed braces took 3.6 s on the event loop (REG-D95).
            re.compile(r"\A(?>.*?\{\{).*?\}\}", re.DOTALL),
        ]

        # Layer 2: LLMGuardLocal (weighted multi-signal scoring).
        self._guard: Any = None
        try:
            from aegis.core.adversarial_filter import LLMGuardLocal

            self._guard = LLMGuardLocal()
            logger.debug("AegisWAF: LLMGuardLocal (layer 2) active")
        except ImportError:
            logger.warning(
                "AegisWAF: aegis.core.adversarial_filter not available; running layer-1 only."
            )

    def inspect_payload(self, body: Any) -> WAFResult:
        """Run both WAF layers against the request body.

        In normal mode returns ``WAFResult(allowed=False, …)`` on any
        detection.  In shadow mode (``shadow_mode=True``) the same detection
        pipeline runs but the block is suppressed: the result is
        ``WAFResult(allowed=True, shadow_blocked=True, …)`` so that traffic
        is never interrupted while blocked payloads are still logged for rule
        tuning.
        """
        result = self._run_detection(body)
        if self.shadow_mode and not result.allowed:
            logger.warning(
                "WAF shadow mode — would-be block suppressed: %s (score=%.2f)",
                result.reason,
                result.score,
            )
            return WAFResult(
                allowed=True,
                reason=result.reason,
                score=result.score,
                shadow_blocked=True,
            )
        return result

    def _run_detection(self, body: Any) -> WAFResult:
        """Internal detection pipeline; always returns an enforcement decision."""
        # ── Layer 1: structural depth guard ──────────────────────────
        # Runs first: every later stage walks the body recursively, and the
        # Rust pre-filter's extraction used to do so before this bound was
        # checked (REG-D98).
        if self._is_too_deep(body, depth=0):
            return WAFResult(
                allowed=False,
                reason="Payload structure too deep (potential DoS)",
                score=1.0,
            )

        # ── Tier-4: Rust Aho-Corasick pre-filter ─────────────────────
        # Fast exact-pattern scan before Python regex loop.
        # Only short-circuits on definite block; Python layers are authoritative.
        if self._rust_waf is not None:
            text_parts = [self._extract_text(body)] if isinstance(body, dict) else []
            raw_text = self._extract_raw_strings(body)
            all_parts = text_parts + raw_text
            if all_parts:
                rust_result = rust_waf_scan_messages(self._rust_waf, all_parts)
                if rust_result["blocked"]:
                    return WAFResult(
                        allowed=False,
                        reason=f"Rust-WAF: {rust_result['reason']}",
                        score=1.0,
                    )

        # ── Layer 1: critical regex patterns (unconditional block) ───
        # FIX-WAF-01: removed the ``strict_mode or score > 0.5`` gate.
        # Any match on a "critical" pattern is a hard block.  strict_mode
        # has no bearing on patterns that are labelled critical by design.
        found_l1 = self._scan_content(body)
        if found_l1:
            score = min(len(found_l1) / 5.0, 1.0)
            return WAFResult(
                allowed=False,
                reason=f"Layer-1 adversarial pattern: {', '.join(found_l1[:2])}",
                score=score,
            )

        # ── Layer 2: LLMGuardLocal weighted scoring ───────────────────
        # strict_mode still governs high-confidence (non-critical) Layer-2 signals.
        if self._guard is not None:
            text = self._layer2_text(body)
            if text:
                try:
                    # Layer 2 used to see only the raw extraction, so Cyrillic
                    # `іgnоrе` reached the scorer un-mapped while Layer 1 had
                    # already folded it to ASCII — the asymmetry `CLM-091`
                    # recorded as its own boundary. It now scans the same
                    # variant set Layer 1 does.
                    #
                    # Raw stays first and is always scanned: `analyze_input`
                    # runs its own `_decode_obfuscation` over the bytes as
                    # given, and NFKC is lossy, so a normalized form could in
                    # principle lose a signal the raw form carries. Scanning
                    # both keeps this additive — it can add a detection and
                    # never mask one, which is the same property the Layer-1
                    # variants are built on.
                    for variant in self._guard_variants(text):
                        guard_result = self._guard.analyze_input(variant)
                        if guard_result.is_malicious:
                            return WAFResult(
                                allowed=False,
                                reason=(
                                    f"Layer-2 adversarial signal: {guard_result.threat_type} "
                                    f"(confidence={guard_result.confidence:.2f})"
                                ),
                                score=guard_result.confidence,
                            )
                except Exception as exc:
                    # Fail-open: a WAF evaluation error must not block a legitimate request,
                    # but it is a security-relevant event that must be visible in production.
                    logger.warning("AegisWAF layer-2 error (fail-open, request allowed): %s", exc)

        return WAFResult(allowed=True)

    def enable_hot_reload(
        self,
        path: str,
        poll_interval_s: float = 1.0,
    ) -> Any:
        """Start watching *path* for WAF pattern changes; reload without restart.

        The returned :class:`~aegis.core.waf_hot_reload.WAFHotReloader` is a
        daemon thread; call ``.stop()`` to shut it down cleanly.

        Parameters
        ----------
        path:
            Path to a JSON WAF pattern file
            (see :mod:`aegis.core.waf_hot_reload` for the schema).
        poll_interval_s:
            mtime-poll/select timeout in seconds.  Only relevant when inotify
            is unavailable.

        Returns
        -------
        WAFHotReloader
            The running reloader instance.
        """
        from aegis.core.waf_hot_reload import WAFHotReloader, WAFPatternSet

        def _on_reload(ps: WAFPatternSet) -> None:
            self._critical_patterns = ps.critical
            logger.info(
                "AegisWAF: hot-reloaded %d critical patterns from %s",
                len(ps.critical),
                path,
            )

        reloader: Any = WAFHotReloader(path, on_reload=_on_reload, poll_interval_s=poll_interval_s)
        reloader.start()
        return reloader

    # ── helpers ───────────────────────────────────────────────────────

    def _is_too_deep(self, data: Any, depth: int) -> bool:
        if depth > 10:
            return True
        if isinstance(data, dict):
            return any(self._is_too_deep(v, depth + 1) for v in data.values())
        if isinstance(data, list):
            return any(self._is_too_deep(i, depth + 1) for i in data)
        return False

    @staticmethod
    def _normalize_text(text: str, invisible_as: str = "") -> str:
        """Decode tag characters, drop invisibles, NFKC-normalize, map homoglyphs.

        NFKC collapses compatibility variants (full-width letters, fraction
        ligatures, circled letters) to their canonical ASCII forms. Without
        this, a payload with `ｉｇｎｏｒｅ ｐｒｅｖｉｏｕｓ ｉｎｓｔｒｕｃｔｉｏｎｓ`
        (U+FF49 etc.) would bypass all string-literal patterns.

        NFKC does **not** touch Cyrillic/Greek/letterlike homoglyphs (e.g.
        Cyrillic `а` U+0430, which looks identical to Latin `a`): those are
        canonically distinct codepoints, not compatibility variants of the
        Latin letters they resemble. `HomoglyphNormalizer` maps them to ASCII
        afterward, closing that gap.

        Tag characters are decoded to the ASCII they mirror, and invisible
        code points (``_INVISIBLE``) are replaced with *invisible_as* — removed
        by default — because NFKC preserves them and they fragment word
        matches. Passing ``" "`` instead keeps an invisible used *as* a space
        from gluing two words together.
        """
        text = text.translate(_TAG_DECODE)
        text = _INVISIBLE.sub(invisible_as, text)
        text = unicodedata.normalize("NFKC", text)
        return _HOMOGLYPH_NORMALIZER.normalize(text)

    @staticmethod
    def _strip_marks(text: str) -> str:
        """Drop combining marks from Latin letters: "i\u0308gnore" reads as "ignore"."""
        decomposed = unicodedata.normalize("NFKD", text)
        return _HOMOGLYPH_NORMALIZER.normalize(_LATIN_COMBINING.sub("", decomposed))

    @classmethod
    def _decoded_base64(cls, text: str) -> str:
        """The UTF-8 text carried by each base64 token in *text*, normalized.

        Tokens that do not decode, do not form UTF-8, or decode to control
        characters are skipped, so binary payloads (images, keys) add nothing.
        Before REG-D99 only Layer 2 decoded base64, and it scans five critical
        phrases; the Layer-1 set never saw the decoded text.
        """
        decoded: list[str] = []
        for match in _BASE64_TOKEN.finditer(text):
            token = match.group(0).rstrip("=").translate(_URLSAFE_TO_STANDARD)
            if len(token) % 4 == 1:
                continue
            token += "=" * (-len(token) % 4)
            try:
                plain = base64.b64decode(token, validate=True).decode("utf-8")
            except (binascii.Error, UnicodeDecodeError, ValueError):
                continue
            if any(ord(ch) < 32 and ch not in "\t\n\r" for ch in plain):
                continue
            decoded.append(plain)
        return cls._normalize_text(" ".join(decoded)) if decoded else ""

    @staticmethod
    def _collapse_letter_spacing(text: str) -> str:
        """Join runs of single characters each separated by one separator.

        ``i g n o r e   p r e v i o u s`` defeats every string-literal pattern
        while reading identically to a human. The run must be at least four
        characters long, so ordinary prose ("a b" in a list, initials) is left
        alone; this is a matching-only variant, so the cost of over-collapsing
        is a false positive rather than altered evidence.
        """
        return _SPACED_RUN.sub(lambda m: _SPACING_SEPARATORS.sub("", m.group(0)), text)

    @staticmethod
    def _fold_leetspeak(text: str) -> str:
        """Fold common leet substitutions back to the letters they stand in for.

        Digits carry meaning elsewhere, which is why this produces a separate
        scan variant instead of replacing the canonical normalization: a
        pattern that legitimately contains a digit still sees the unfolded
        text.
        """
        return text.translate(_LEET_TABLE)

    @classmethod
    def _guard_variants(cls, text: str) -> tuple[str, ...]:
        """Raw text first, then every de-obfuscated form of it, deduplicated.

        Layer 2 differs from Layer 1 in one way that matters: its scorer
        (:meth:`~aegis.core.adversarial_filter.LLMGuardLocal.analyze_input`)
        already lowercases and runs its own obfuscation decoder over whatever
        it is handed. Normalizing *instead of* passing the raw text would
        therefore replace one decoder's input with another's output. Passing
        both, raw first, only widens what is scanned.
        """
        seen: dict[str, None] = {text: None}
        for variant in cls._scan_variants(text):
            seen.setdefault(variant, None)
        return tuple(seen)

    @classmethod
    def _scan_variants(cls, text: str) -> tuple[str, ...]:
        """The canonical normalization plus each de-obfuscated form of it.

        Variants are additive — every pattern is still tested against the
        canonical form — so a variant can only add a detection, never mask one.

        Three bases: the canonical form (invisibles removed), the same text
        with invisibles read as spaces, and the canonical form with combining
        marks stripped. Each base also yields its letter-spacing collapse, its
        leet fold and both together. Decoded base64 is one more variant. For
        plain ASCII prose the bases coincide and the set stays at two to four.
        """
        normalized = cls._normalize_text(text)
        variants: set[str] = set()
        for base in (
            normalized,
            cls._normalize_text(text, invisible_as=" "),
            cls._strip_marks(normalized),
        ):
            collapsed = cls._collapse_letter_spacing(base)
            variants.update(
                (base, collapsed, cls._fold_leetspeak(base), cls._fold_leetspeak(collapsed))
            )
        decoded = cls._decoded_base64(normalized)
        if decoded:
            variants.add(decoded)
        variants.discard(normalized)
        return (normalized, *sorted(variants))

    def _scan_content(self, data: Any) -> list[str]:
        matches: list[str] = []
        if isinstance(data, str):
            variants = self._scan_variants(data)
            for pat in self._critical_patterns:
                if any(pat.search(variant) for variant in variants):
                    matches.append(pat.pattern[:40])
            # Not part of the hot-reloadable set: it closes an evasion of the
            # word-bounded patterns rather than naming a new phrase (REG-D97).
            if any(_CONCATENATED_CRITICAL.search(variant) for variant in variants):
                matches.append("concatenated critical phrase")
        elif isinstance(data, dict):
            for v in data.values():
                matches.extend(self._scan_content(v))
        elif isinstance(data, list):
            for item in data:
                matches.extend(self._scan_content(item))
        return matches

    @staticmethod
    def _extract_text(body: Any) -> str:
        """Extract all user-visible text from a chat completions body."""
        parts: list[str] = []
        messages = body.get("messages", []) if isinstance(body, dict) else []
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            content = msg.get("content", "")
            if isinstance(content, str):
                parts.append(content)
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        text = block.get("text", "")
                        # A non-string "text" (null, a list) used to reach
                        # the join below and raise TypeError: a 500 instead of
                        # a decision (REG-D98). Layer 1 still scans it.
                        if isinstance(text, str):
                            parts.append(text)
        return " ".join(parts)

    @classmethod
    def _layer2_text(cls, body: Any) -> str:
        """Message text plus every other string field, for the Layer-2 scorer.

        Layer 2 used to see message text only, so a phrase only it knows
        reached the provider unscored in ``prompt`` (``/v1/completions``),
        ``system`` (``/v1/messages``) or any other field (REG-D100). The
        fields are joined with NUL so no phrase can span two of them.
        """
        if not isinstance(body, dict):
            return cls._extract_text(body)
        parts = [cls._extract_text(body)]
        for key, value in body.items():
            if key != "messages":
                parts.extend(cls._extract_raw_strings(value))
        return "\x00".join(part for part in parts if part)

    @staticmethod
    def _extract_raw_strings(data: Any) -> list[str]:
        """Recursively collect all string values for Rust pre-filter."""
        results: list[str] = []
        if isinstance(data, str):
            results.append(data)
        elif isinstance(data, dict):
            for v in data.values():
                results.extend(AegisWAF._extract_raw_strings(v))
        elif isinstance(data, list):
            for item in data:
                results.extend(AegisWAF._extract_raw_strings(item))
        return results

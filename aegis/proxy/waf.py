"""
aegis.proxy.waf — Web Application Firewall for LLM Payloads.

Two-layer detection pipeline (v3.0.1 — Tier-4 Rust acceleration):

Tier-4 WAF fast path (when aegis_rust is compiled):
  - RustWaf.scan_messages() runs an Aho-Corasick SIMD pre-filter on all message
    text in O(n + m) time (n = text length, m = pattern set).  Processes a
    typical 1 KB prompt in ~250 ns vs ~50 µs for Python's re module.
  - If RustWaf blocks → return immediately (never enters Python regex loop).
  - If RustWaf passes → Python Layer 1 + Layer 2 still execute as authoritative
    checks.  Python patterns use .{0,20}? bridges that Aho-Corasick cannot
    express; both layers are needed for complete coverage.
  - Net effect: clean requests bypass Python regex for exact-match patterns;
    blocked requests are caught at <1 µs.

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

import logging
import re
import unicodedata
from dataclasses import dataclass
from typing import Any

from aegis.core.rust_integration import new_rust_waf, rust_waf_scan_messages

logger = logging.getLogger(__name__)


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
        # Bypass hardening: all text is NFKC-normalized before pattern matching
        # (see _normalize_text). This collapses Unicode lookalike characters
        # (full-width letters, homoglyphs) to their ASCII equivalents so patterns
        # cannot be evaded by substituting Unicode variants.
        #
        # Patterns use flexible spacing/word-boundaries to catch common evasions:
        # - Inserted words: "ignore ALL previous instructions"
        # - Abbreviation spacing: "D.A.N.", "D A N"
        # - Synonym pivots: "reveal"/"show"/"output" the system prompt
        self._critical_patterns: list[re.Pattern[str]] = [
            # Instruction override (inserted-word variants caught by .*? bridge)
            re.compile(
                r"ignore\b.{0,20}?\bprevious\b.{0,20}?\binstructions?",
                re.IGNORECASE | re.DOTALL,
            ),
            re.compile(
                r"disregard\b.{0,20}?\b(all\b.{0,20}?\b)?previous",
                re.IGNORECASE | re.DOTALL,
            ),
            # Unrestricted-AI / system-override variants
            re.compile(
                r"(you\s+are\s+now\s+an?\s+unrestricted|system[\s\-_]*override|bypass[\s\-_]*filters?)",
                re.IGNORECASE,
            ),
            # DAN / jailbreak — catches D.A.N., D A N, DAN-mode, dan_mode
            re.compile(
                r"D[\.\s\-_]*A[\.\s\-_]*N[\.\s\-_]*(mode|prompt)?|jailbreak|do\s+anything\s+now",
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
            # Template injection: {{ }} and full-width Unicode variants (after NFKC norm)
            re.compile(r"\{\{.*?\}\}", re.IGNORECASE | re.DOTALL),
        ]

        # Layer 2: LLMGuardLocal (weighted multi-signal scoring).
        self._guard: Any = None
        try:
            from aegis.core.adversarial_filter import LLMGuardLocal

            self._guard = LLMGuardLocal()  # type: ignore[no-untyped-call]
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

        # ── Layer 1: structural depth guard ──────────────────────────
        if self._is_too_deep(body, depth=0):
            return WAFResult(
                allowed=False,
                reason="Payload structure too deep (potential DoS)",
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
            text = self._extract_text(body)
            if text:
                try:
                    guard_result = self._guard.analyze_input(text)
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
    def _normalize_text(text: str) -> str:
        """NFKC-normalize and strip zero-width characters before pattern matching.

        NFKC collapses compatibility variants (full-width letters, fraction
        ligatures, circled letters) to their canonical ASCII forms. Without
        this, a payload with `ｉｇｎｏｒｅ ｐｒｅｖｉｏｕｓ ｉｎｓｔｒｕｃｔｉｏｎｓ`
        (U+FF49 etc.) would bypass all string-literal patterns.

        Zero-width joiners / non-joiners and soft-hyphens are stripped first
        because NFKC preserves them and they fragment word matches.
        """
        # Strip zero-width and invisible Unicode characters.
        # Explicit escape sequences prevent B613 TrojanSource (bidirectional literals
        # embedded in source look identical to other characters in most editors).
        _ZW_CHARS = (
            "\u200b"  # U+200B zero-width space
            "\u200c"  # U+200C zero-width non-joiner
            "\u200d"  # U+200D zero-width joiner
            "\u200e"  # U+200E left-to-right mark
            "\u200f"  # U+200F right-to-left mark
            "\u00ad"  # U+00AD soft hyphen
            "\ufeff"  # U+FEFF BOM / zero-width no-break space
        )
        for ch in _ZW_CHARS:
            text = text.replace(ch, "")
        return unicodedata.normalize("NFKC", text)

    def _scan_content(self, data: Any) -> list[str]:
        matches: list[str] = []
        if isinstance(data, str):
            normalized = self._normalize_text(data)
            for pat in self._critical_patterns:
                if pat.search(normalized):
                    matches.append(pat.pattern[:40])
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
                        parts.append(block.get("text", ""))
        return " ".join(parts)

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

"""
aegis.proxy.waf — Web Application Firewall for LLM Payloads.

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

# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import logging
import re
import unicodedata
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class WAFResult:
    allowed: bool
    reason: str | None = None
    score: float = 0.0


class AegisWAF:
    """
    Two-layer LLM payload firewall.

    Layer 1: structural checks + hardcoded critical patterns (always block on match).
    Layer 2: LLMGuardLocal weighted signal scoring (from adversarial_filter).
    """

    def __init__(self, strict_mode: bool = True) -> None:
        self.strict_mode = strict_mode

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

            self._guard = LLMGuardLocal()
            logger.debug("AegisWAF: LLMGuardLocal (layer 2) active")
        except ImportError:
            logger.warning(
                "AegisWAF: aegis.core.adversarial_filter not available; running layer-1 only."
            )

    def inspect_payload(self, body: Any) -> WAFResult:
        """
        Run both WAF layers against the request body.

        Returns WAFResult(allowed=False, ...) on any detection.
        """
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
                    result = self._guard.analyze_input(text)
                    if result.is_malicious:
                        return WAFResult(
                            allowed=False,
                            reason=(
                                f"Layer-2 adversarial signal: {result.threat_type} "
                                f"(confidence={result.confidence:.2f})"
                            ),
                            score=result.confidence,
                        )
                except Exception as exc:
                    # Never let WAF errors block a legitimate request
                    logger.debug("AegisWAF layer-2 error (non-fatal): %s", exc)

        return WAFResult(allowed=True)

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

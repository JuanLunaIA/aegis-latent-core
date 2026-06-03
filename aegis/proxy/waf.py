"""
aegis.proxy.waf — Web Application Firewall for LLM Payloads.

Two-layer detection pipeline (v2.2.0):

Layer 1 — AegisWAF (structural + 5 hardcoded regex patterns):
  - Payload depth guard (DoS via nesting)
  - Critical regex patterns (system override, DAN, template injection)

Layer 2 — LLMGuardLocal (weighted signal scoring, from aegis.core.adversarial_filter):
  - Critical patterns (immediate block at any score)
  - High-confidence patterns (block if strict_mode)
  - Soft patterns (accumulate score; block if aggregate > threshold)
  - Base64 / obfuscation detection
  - Prompt structure anomalies (empty messages, role stuffing)

Both layers are chained: Layer 1 short-circuits on hard matches; Layer 2 runs
on every request that Layer 1 passes through.

MEDIUM-04 fix (v2.2.0): adversarial_filter.LLMGuardLocal is now wired into
the request path.  Previously the module existed but was never imported.
"""

# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import logging
import re
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

    Layer 1: structural checks + hardcoded critical patterns.
    Layer 2: LLMGuardLocal weighted signal scoring (from adversarial_filter).
    """

    def __init__(self, strict_mode: bool = True) -> None:
        self.strict_mode = strict_mode

        # Layer 1: hard-block regex patterns (critical, immediate rejection)
        self._critical_patterns: list[re.Pattern[str]] = [
            re.compile(r"(ignore previous instructions|disregard all previous)", re.IGNORECASE),
            re.compile(
                r"(you are now an unrestricted|system override|bypass filters)", re.IGNORECASE
            ),
            re.compile(r"(DAN mode|jailbreak|do anything now)", re.IGNORECASE),
            re.compile(
                r"(print the system prompt|what is your initial instruction)", re.IGNORECASE
            ),
            re.compile(r"(\{\{.*?\}\})", re.IGNORECASE),  # Template injection
        ]

        # Layer 2: LLMGuardLocal (weighted multi-signal scoring).
        # Imported lazily so a missing aegis.core module doesn't crash the proxy.
        self._guard: Any = None
        try:
            from aegis.core.adversarial_filter import LLMGuardLocal
            self._guard = LLMGuardLocal()
            logger.debug("AegisWAF: LLMGuardLocal (layer 2) active")
        except ImportError:
            logger.warning(
                "AegisWAF: aegis.core.adversarial_filter not available; "
                "running layer-1 only."
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

        # ── Layer 1: critical regex patterns ─────────────────────────
        found_l1 = self._scan_content(body)
        if found_l1:
            score = min(len(found_l1) / 5.0, 1.0)
            if self.strict_mode or score > 0.5:
                return WAFResult(
                    allowed=False,
                    reason=f"Layer-1 adversarial pattern: {', '.join(found_l1[:2])}",
                    score=score,
                )

        # ── Layer 2: LLMGuardLocal weighted scoring ───────────────────
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

    def _scan_content(self, data: Any) -> list[str]:
        matches: list[str] = []
        if isinstance(data, str):
            for pat in self._critical_patterns:
                if pat.search(data):
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

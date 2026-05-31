"""
aegis.proxy.waf — Web Application Firewall for LLM Payloads.
Analyzes incoming requests for prompt injection, adversarial patterns, and structural anomalies.
"""
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
    Linguistic and structural firewall to protect the LLM backend from
    adversarial inputs and prompt injection.
    """
    def __init__(self, strict_mode: bool = True):
        self.strict_mode = strict_mode

        # Known prompt injection patterns (Simplified for the implementation)
        self.adversarial_patterns = [
            re.compile(r"(ignore previous instructions|disregard all previous)", re.IGNORECASE),
            re.compile(r"(you are now an unrestricted|system override|bypass filters)", re.IGNORECASE),
            re.compile(r"(DAN mode|jailbreak|do anything now)", re.IGNORECASE),
            re.compile(r"(print the system prompt|what is your initial instruction)", re.IGNORECASE),
            re.compile(r"(\{\{.*?\}\})", re.IGNORECASE), # Possible template injection
        ]

    def inspect_payload(self, body: Any) -> WAFResult:
        """
        Recursively inspects the JSON payload for adversarial patterns.
        """
        # 1. Structural Analysis: Detect deeply nested objects (DoS attempt)
        if self._is_too_deep(body, depth=0):
            return WAFResult(allowed=False, reason="Payload structure too deep (Potential DoS)", score=1.0)

        # 2. Content Analysis: Scan all string values for adversarial patterns
        found_patterns = self._scan_content(body)

        if found_patterns:
            score = len(found_patterns) / 5.0 # Simple scoring
            if self.strict_mode or score > 0.5:
                return WAFResult(
                    allowed=False,
                    reason=f"Adversarial patterns detected: {', '.join(found_patterns)}",
                    score=min(score, 1.0)
                )

        return WAFResult(allowed=True)

    def _is_too_deep(self, data: Any, depth: int) -> bool:
        MAX_DEPTH = 10
        if depth > MAX_DEPTH:
            return True
        if isinstance(data, dict):
            return any(self._is_too_deep(v, depth + 1) for v in data.values())
        if isinstance(data, list):
            return any(self._is_too_deep(i, depth + 1) for i in data)
        return False

    def _scan_content(self, data: Any) -> list[str]:
        matches = []
        if isinstance(data, str):
            for pattern in self.adversarial_patterns:
                if pattern.search(data):
                    matches.append(pattern.pattern)
        elif isinstance(data, dict):
            for v in data.values():
                matches.extend(self._scan_content(v))
        elif isinstance(data, list):
            for i in data:
                matches.extend(self._scan_content(i))
        return matches

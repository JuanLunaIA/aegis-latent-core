"""
aegis.core.adversarial_filter — Advanced Adversarial AI Guard.
Implements a weighted signal-based detection pipeline to identify jailbreaks,
prompt injections, and obfuscation patterns.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import base64
import logging
import re
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class FilterResult:
    is_malicious: bool
    threat_type: str | None = None
    confidence: float = 0.0
    mitigation: str = "BLOCK"


class LLMGuardLocal:
    """
    Advanced pre-filter for detecting adversarial payloads.
    Uses a weighted scoring system: Multiple low-confidence signals
    can aggregate into a high-confidence block.
    """

    def __init__(self):
        # High-precision patterns (Immediate Block)
        self.critical_patterns = [
            re.compile(r"ignore (all )?previous instructions", re.IGNORECASE),
            re.compile(r"you are now (in|a) (dan|developer mode)", re.IGNORECASE),
            re.compile(r"system override", re.IGNORECASE),
            re.compile(r"bypass (all )?filters", re.IGNORECASE),
            re.compile(r"acting as an unrestricted", re.IGNORECASE),
        ]

        # Medium-precision patterns (Weighted Signals)
        self.weighted_patterns = {
            "jailbreak_signal": [
                re.compile(r"stay in character", re.IGNORECASE),
                re.compile(r"do anything now", re.IGNORECASE),
                re.compile(r"hypothetically", re.IGNORECASE),
                re.compile(r"imagine you are", re.IGNORECASE),
                re.compile(r"pretend you are", re.IGNORECASE),
                re.compile(r"in a world where", re.IGNORECASE),
                re.compile(r"forget your rules", re.IGNORECASE),
            ],
            "exfiltration_signal": [
                re.compile(
                    r"(print|show|echo) (your|the) (api[ _]key|secret|password|config)",
                    re.IGNORECASE,
                ),
                re.compile(r"read (the )?file (?:/etc/passwd|/etc/shadow)", re.IGNORECASE),
                re.compile(r"list (all )?directories", re.IGNORECASE),
            ],
        }

        # Obfuscation markers
        self.obfuscation_markers = [
            "YmFzZTY0",  # "base64" in base64
            "SGVsbG8=",  # "Hello" in base64
            "ROT13",
            "Cesar cipher",
        ]

    def _decode_obfuscation(self, text: str) -> str:
        """Attempts to normalize common obfuscation techniques."""
        normalized = text
        # Simple Base64 attempt
        try:
            # Look for base64-like blocks
            b64_pattern = re.compile(
                r"(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
            )
            for match in b64_pattern.finditer(text):
                decoded = base64.b64decode(match.group()).decode("utf-8", errors="ignore")
                if len(decoded) > 3:
                    normalized += f" {decoded}"
        except Exception:
            pass
        return normalized

    def analyze_input(self, text: str) -> FilterResult:
        """
        Analyzes input using a multi-stage weighted pipeline.
        """
        # Normalize and decode
        full_text = f"{text} {self._decode_obfuscation(text)}".lower()

        # Stage 1: Critical Patterns (Instant Block)
        for pattern in self.critical_patterns:
            if pattern.search(full_text):
                logger.warning("CRITICAL_JAILBREAK_DETECTED: Immediate block triggered.")
                return FilterResult(
                    is_malicious=True, threat_type="CRITICAL_JAILBREAK", confidence=1.0
                )

        # Stage 2: Weighted Signal Aggregation
        score = 0.0
        detected_types = set()

        for category, patterns in self.weighted_patterns.items():
            for pattern in patterns:
                if pattern.search(full_text):
                    score += 0.35
                    detected_types.add(category)

        # Stage 3: Obfuscation Detection
        for marker in self.obfuscation_markers:
            if marker in full_text:
                score += 0.5
                detected_types.add("OBFUSCATION")

        # Final Decision Logic
        if score >= 0.7:
            threat = (
                "AGGREGATED_ADVERSARIAL" if len(detected_types) > 1 else list(detected_types)[0]
            )
            logger.warning(
                f"ADVERSARIAL_INPUT_DETECTED: Score {score:.2f}, Types: {detected_types}"
            )
            return FilterResult(is_malicious=True, threat_type=threat, confidence=min(score, 1.0))

        return FilterResult(is_malicious=False)


# Singleton instance
llm_guard = LLMGuardLocal()

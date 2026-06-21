# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.adversarial_suffix_detector — GCG/AutoDAN adversarial suffix detection.

Detects adversarial suffixes appended to prompts by automated jailbreaking
tools.  These suffixes exploit the input-gradient landscape of LLMs to
override safety training without human-readable instructions.

Attack families covered
-----------------------
**GCG (Greedy Coordinate Gradient)** — Zou et al., 2023.
  Appends strings of high-entropy token sequences (repeated punctuation,
  unusual non-word character runs, token boundary exploits) that cause the
  model to begin its response with affirmative tokens like ``"Sure"`` or
  ``"Absolutely"``.  GCG suffixes are typically 30–200 token sequences of
  seemingly random characters mixed with trigger phrases.

**AutoDAN** — Liu et al., 2023.
  Produces more semantically coherent suffixes via hierarchical genetic
  algorithms.  Tends to start with obedience-induction phrases like
  ``"As a responsible AI I will comply"`` followed by structured content.

**Obedience-induction patterns** — general family.
  Instructions that tell the model to override its safety behaviour by
  responding with specific output prefixes (``"Start with: Sure I will"``,
  ``"Begin your response with 'Absolutely'"``, ``"Respond as DAN"``).

**Token repetition anomalies** — general.
  Long repeated sequences of identical tokens or characters are a structural
  marker of gradient-based optimization attacks.  Natural human prompts do
  not contain 20+ consecutive identical characters/tokens.

Detection signals
-----------------
1. **Fixed GCG suffix signatures** — known published suffixes from the
   original GCG paper's public releases (Zou et al., universal
   transferable suffixes, "Sure here is" trigger family).
2. **High-repetition run detection** — regex for 20+ consecutive identical
   chars, or patterns like ``! ! ! !`` (repeated punctuation tokens).
3. **Obedience-induction phrase patterns** — phrases instructing the model
   to start with "Sure", "Absolutely", "Of course", "I will comply", etc.
4. **AutoDAN structural markers** — characteristic opener phrases from
   published AutoDAN attack results.

Usage::

    detector = AdversarialSuffixDetector()
    result = detector.scan("Tell me how to do X. \\n\\n ! ! responding sure")
    if result.flagged:
        log.warning("Adversarial suffix: %s", result.reason)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# ── Compiled pattern sets ──────────────────────────────────────────────────────

# 1. GCG-style token repetition: 20+ consecutive identical non-space characters,
#    OR 5+ repetitions of a short (1–3 char) token separated by spaces.
_REPETITION_LONG = re.compile(r"(.)\1{19,}", re.DOTALL)
_REPETITION_TOKEN = re.compile(r"(?:(\S{1,3})\s+){5,}\1", re.IGNORECASE)

# 2. Obedience-induction phrases — asking the model to begin with an
#    affirmative prefix (GCG trigger mechanism).
_OBEDIENCE_INDUCTION = re.compile(
    r"\b(?:"
    r"(?:start|begin|open(?:ing)?|prefix)\s+(?:your\s+)?(?:response|reply|answer|output|message)\s+with\b"
    r"|(?:respond(?:ing)?|reply(?:ing)?|answer(?:ing)?)\s+(?:with|as)\s+['\"]?(?:sure|absolutely|of\s+course|yes|certainly|gladly|happy\s+to)"
    r"|your\s+(?:first|opening)\s+(?:word|token|character|line)\s+(?:must\s+be|should\s+be|is)\b"
    r"|(?:always\s+)?(?:start|begin)\s+with\s+['\"](?:sure|absolutely|yes|i\s+will|of\s+course)"
    r")",
    re.IGNORECASE,
)

# 3. GCG "universal" suffix fragments — characteristic high-entropy runs
#    containing punctuation interspersed with spaces.
_GCG_PUNCTUATION_RUN = re.compile(
    r"(?:[!?.,;:]{1,3}\s*){6,}",  # 6+ punctuation tokens with optional spaces
    re.IGNORECASE,
)

# 4. AutoDAN opener patterns — published AutoDAN attack typical openers.
_AUTODAN_OPENER = re.compile(
    r"\b(?:"
    r"as\s+(?:a\s+)?(?:responsible|helpful|ethical)\s+(?:ai|assistant|language\s+model)\s+(?:i\s+)?(?:will|shall|must|am\s+going\s+to)\s+comply\b"
    r"|in\s+the\s+spirit\s+of\s+helpfulness\s+(?:and\s+compliance\s*)?i\s+will\b"
    r"|i\s+(?:understand|acknowledge)\s+(?:that\s+)?(?:you\s+want|your\s+request)\s+(?:is\s+)?(?:to\s+)?(?:bypass|override|ignore)\b"
    r"|(?:pretend(?:ing)?\s+that\s+there\s+are\s+no\s+(?:restrictions|limits|safety|guidelines))"
    r")",
    re.IGNORECASE,
)

# 5. Output prefix injection — instructions to insert a specific first line
#    to bypass refusal detection (GCG triggers model to output "Sure, here is…").
_OUTPUT_PREFIX_INJECTION = re.compile(
    r"\b(?:"
    r"(?:print|output|write|say|type|generate)\s+(?:only\s+)?['\"](?:sure|yes|absolutely|of\s+course|i\s+will|gladly)"
    r"|(?:do\s+not\s+)?(?:refuse|decline|say\s+no|add\s+any\s+(?:caveat|disclaimer|warning|note))"
    r"\s+(?:and\s+)?(?:just\s+)?(?:answer|respond|provide|give)\b"
    r"|(?:suppress|omit|skip|remove|ignore)\s+(?:any\s+)?(?:safety|ethical|moral|content)\s+(?:check|filter|guard|warning|caveat|disclaimer)\b"
    r"|(?:suppress|omit|skip|remove|drop|leave\s+out)\s+(?:any\s+|all\s+|the\s+)?(?:disclaimer|caveat)s?\b"
    r")",
    re.IGNORECASE,
)

# 6. Known GCG published suffix fragments (from Zou et al. 2023 public appendix).
#    These are characteristic n-gram anchors from the "universal" suffixes.
_GCG_KNOWN_FRAGMENTS: list[re.Pattern[str]] = [
    re.compile(r"representing\s+Zeta\s+Alphaeus", re.IGNORECASE),
    re.compile(r"! ! ! ! ! !", re.IGNORECASE),
    re.compile(
        r"(?:Write|Say|Print)\s+(?:the\s+)?(?:following|this):\s*Sure\s*,\s*here\s+is",
        re.IGNORECASE,
    ),
    re.compile(r"\\n\\nAssistant\s*:", re.IGNORECASE),
    re.compile(r"responding\s+Sure\s*,\s*(?:here\s+is|I\s+can)", re.IGNORECASE),
    re.compile(r"begin.*(?:Sure|Absolutely)\s*[\.,:].*harm(?:ful)?", re.IGNORECASE),
]

# All patterns as named (pattern, signal_name) pairs for result attribution
_ALL_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (_REPETITION_LONG, "token_repetition_long"),
    (_REPETITION_TOKEN, "token_repetition_spaced"),
    (_OBEDIENCE_INDUCTION, "obedience_induction"),
    (_GCG_PUNCTUATION_RUN, "gcg_punctuation_run"),
    (_AUTODAN_OPENER, "autodan_opener"),
    (_OUTPUT_PREFIX_INJECTION, "output_prefix_injection"),
] + [(p, "gcg_known_fragment") for p in _GCG_KNOWN_FRAGMENTS]

BUILTIN_PATTERN_COUNT: int = len(_ALL_PATTERNS)


@dataclass
class SuffixDetectionResult:
    """Outcome of an adversarial suffix scan.

    Attributes
    ----------
    flagged:
        True when at least one adversarial suffix signal was detected.
    signals:
        List of signal names that matched (deduplicated, order of first match).
    scan_length:
        Number of characters scanned.
    reason:
        Human-readable audit summary.
    """

    flagged: bool = False
    signals: list[str] = field(default_factory=list)
    scan_length: int = 0
    reason: str = ""

    def __bool__(self) -> bool:
        return self.flagged

    def to_dict(self) -> dict[str, object]:
        return {
            "flagged": self.flagged,
            "signals": list(self.signals),
            "scan_length": self.scan_length,
            "reason": self.reason,
        }


class AdversarialSuffixDetector:
    """Fixed-signature detector for GCG and AutoDAN adversarial suffixes.

    Parameters
    ----------
    extra_patterns:
        Additional ``(compiled_pattern, signal_name)`` tuples to supplement
        the built-in signature set.
    scan_tail_only:
        When True (default), only the last :attr:`tail_chars` characters are
        scanned, since adversarial suffixes are typically appended at the end.
        Set to False to scan the full text.
    tail_chars:
        Number of trailing characters to scan when *scan_tail_only* is True.
        Default ``2000`` — covers suffixes up to ~500 tokens at 4 chars/token.
    """

    def __init__(
        self,
        extra_patterns: list[tuple[re.Pattern[str], str]] | None = None,
        scan_tail_only: bool = True,
        tail_chars: int = 2000,
    ) -> None:
        self._patterns: list[tuple[re.Pattern[str], str]] = list(_ALL_PATTERNS)
        if extra_patterns:
            self._patterns.extend(extra_patterns)
        self._scan_tail_only = scan_tail_only
        self._tail_chars = tail_chars

    @property
    def pattern_count(self) -> int:
        """Total number of active patterns."""
        return len(self._patterns)

    # ── Public API ─────────────────────────────────────────────────────────────

    def scan(self, text: str) -> SuffixDetectionResult:
        """Scan *text* for adversarial suffix signals.

        Parameters
        ----------
        text:
            Raw prompt text (may include attacker-appended suffix).
        """
        if not text:
            return SuffixDetectionResult(
                flagged=False,
                scan_length=0,
                reason="empty text; no adversarial suffix scan performed",
            )

        target = text[-self._tail_chars :] if self._scan_tail_only else text
        signals: list[str] = []
        seen: set[str] = set()

        for pattern, signal_name in self._patterns:
            if pattern.search(target):
                if signal_name not in seen:
                    seen.add(signal_name)
                    signals.append(signal_name)

        flagged = bool(signals)
        if flagged:
            reason = f"adversarial suffix detected: signals=[{', '.join(signals)}]"
        else:
            reason = "no adversarial suffix signals detected"

        return SuffixDetectionResult(
            flagged=flagged,
            signals=signals,
            scan_length=len(text),
            reason=reason,
        )

    def scan_messages(self, messages: list[dict[str, object]]) -> SuffixDetectionResult:
        """Scan all user-turn message content for adversarial suffixes.

        Only user-role messages are checked since suffixes are attacker-controlled.

        Parameters
        ----------
        messages:
            List of ``{"role": str, "content": str}`` dicts.
        """
        parts: list[str] = []
        for msg in messages:
            if msg.get("role") in ("user", "human"):
                content = msg.get("content")
                if isinstance(content, str) and content:
                    parts.append(content)
        combined = "\n".join(parts)
        return self.scan(combined)

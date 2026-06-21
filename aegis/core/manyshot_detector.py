# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.manyshot_detector — Many-shot jailbreak detection.

Flags prompts that embed more than N few-shot examples in the context, a
technique documented in "Many-Shot Jailbreaking" (Anthropic, 2024) where
an attacker pre-fills many Q&A examples of harmful behavior to override
model safety training via in-context learning.

Detection strategy
------------------
The detector uses a multi-signal approach to count few-shot examples:

1. **Q&A pair heuristic** — alternating ``Human:``/``Assistant:`` or
   ``User:``/``AI:`` / ``Q:``/``A:`` turn-delimiter patterns.
2. **Numbered-list examples** — ``1.``, ``2.``, … ``N.`` sequential numbering
   with a minimum per-item length threshold.
3. **Fenced example blocks** — ``Example N:`` / ``Sample N:`` headers.
4. **Bracketed shot markers** — ``[EXAMPLE]``/``[/EXAMPLE]`` or
   ``<example>``, ``<shot>`` delimiters.

Any single signal exceeding the configured threshold triggers a FLAG or BLOCK
decision (caller-selectable action threshold).

Usage::

    detector = ManyShotDetector(threshold=10)
    result = detector.evaluate("User: How do I ... Assistant: Sure ...")
    if result.shot_count >= detector.threshold:
        raise HTTPException(403, detail=result.reason)

    # Scan all messages in a chat request
    result = detector.evaluate_messages(request.messages)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# ── Compiled patterns ─────────────────────────────────────────────────────────

# Q&A turn delimiters — catches "Human:", "User:", "Q:", "Question:" with
# optional leading whitespace / newline, case-insensitive.
_QA_HUMAN = re.compile(
    r"(?:^|\n)\s*(?:human|user|q(?:uestion)?)\s*:",
    re.IGNORECASE,
)
_QA_ASSISTANT = re.compile(
    r"(?:^|\n)\s*(?:assistant|ai|a(?:nswer)?)\s*:",
    re.IGNORECASE,
)

# Numbered list: lines starting "1.", "2.", etc. with ≥20 chars of content.
_NUMBERED_ITEM = re.compile(
    r"(?:^|\n)\s*\d+\.\s+.{20,}",
    re.IGNORECASE,
)

# "Example N:" / "Sample N:" / "Shot N:" headers.
_EXAMPLE_HEADER = re.compile(
    r"(?:^|\n)\s*(?:example|sample|shot|case|scenario)\s+\d+\s*[:\-]",
    re.IGNORECASE,
)

# XML/bracket delimiters: <example>, [EXAMPLE], <shot>, [/EXAMPLE] etc.
_BRACKET_OPEN = re.compile(
    r"(?:<example>|\[example\]|<shot>|\[shot\])",
    re.IGNORECASE,
)


@dataclass
class ManyShotDetectionResult:
    """Outcome of a many-shot jailbreak scan.

    Attributes
    ----------
    shot_count:
        Estimated number of few-shot examples detected.  The maximum across
        all signals is used to avoid under-counting.
    signal_counts:
        Per-signal raw counts:
        ``{"qa_pairs", "numbered_items", "example_headers", "bracket_shots"}``.
    threshold:
        The configured detection threshold.
    exceeded:
        True when ``shot_count >= threshold``.
    reason:
        Human-readable audit message.
    scan_length:
        Number of characters scanned.
    """

    shot_count: int
    signal_counts: dict[str, int] = field(default_factory=dict)
    threshold: int = 10
    exceeded: bool = False
    reason: str = ""
    scan_length: int = 0

    def to_dict(self) -> dict[str, object]:
        return {
            "shot_count": self.shot_count,
            "signal_counts": dict(self.signal_counts),
            "threshold": self.threshold,
            "exceeded": self.exceeded,
            "reason": self.reason,
            "scan_length": self.scan_length,
        }


class ManyShotDetector:
    """Count-based many-shot jailbreak detector.

    Parameters
    ----------
    threshold:
        Number of detected few-shot examples at or above which ``exceeded``
        is set to True.  Default is ``10`` (consistent with Anthropic's
        published research showing most natural prompts have ≤5 examples).
    min_qa_ratio:
        Minimum ratio of assistant turns to human turns for the Q&A signal to
        be valid.  Default ``0.5`` — requires at least one assistant reply per
        two human turns (avoids false positives on transcripts with unanswered
        questions).
    """

    def __init__(
        self,
        threshold: int = 10,
        min_qa_ratio: float = 0.5,
    ) -> None:
        if threshold < 1:
            raise ValueError(f"threshold must be ≥ 1, got {threshold!r}")
        if not 0.0 <= min_qa_ratio <= 1.0:
            raise ValueError(f"min_qa_ratio must be in [0, 1], got {min_qa_ratio!r}")
        self.threshold = threshold
        self._min_qa_ratio = min_qa_ratio

    # ── Public API ────────────────────────────────────────────────────────────

    def evaluate(self, text: str) -> ManyShotDetectionResult:
        """Evaluate a single text block for many-shot jailbreak patterns.

        Parameters
        ----------
        text:
            Raw request text (system prompt + user message, or a single turn).
        """
        if not text:
            return ManyShotDetectionResult(
                shot_count=0,
                threshold=self.threshold,
                reason="empty text; no many-shot patterns",
                scan_length=0,
            )

        counts = self._count_signals(text)
        shot_count = max(counts.values()) if counts else 0
        exceeded = shot_count >= self.threshold

        if exceeded:
            reason = (
                f"many-shot jailbreak detected: {shot_count} examples "
                f"(threshold={self.threshold}); signals={counts}"
            )
        elif shot_count > 0:
            reason = f"{shot_count} few-shot examples detected (below threshold={self.threshold})"
        else:
            reason = "no many-shot patterns detected"

        return ManyShotDetectionResult(
            shot_count=shot_count,
            signal_counts=counts,
            threshold=self.threshold,
            exceeded=exceeded,
            reason=reason,
            scan_length=len(text),
        )

    def evaluate_messages(self, messages: list[dict[str, object]]) -> ManyShotDetectionResult:
        """Evaluate a list of chat message dicts by concatenating all content.

        Concatenation matters: an attacker may spread examples across multiple
        messages to evade per-message counting.  The combined text is scanned
        as a single block.

        Parameters
        ----------
        messages:
            List of ``{"role": str, "content": str}`` dicts.
        """
        parts: list[str] = []
        for msg in messages:
            content = msg.get("content")
            if isinstance(content, str) and content:
                parts.append(content)

        combined = "\n".join(parts)
        result = self.evaluate(combined)
        return result

    # ── Signal counting ───────────────────────────────────────────────────────

    def _count_signals(self, text: str) -> dict[str, int]:
        """Return per-signal example counts."""
        counts: dict[str, int] = {}

        # 1. Q&A pairs — count the minimum of human and assistant turns
        human_count = len(_QA_HUMAN.findall(text))
        assistant_count = len(_QA_ASSISTANT.findall(text))
        if human_count > 0 and assistant_count > 0:
            ratio = assistant_count / human_count
            if ratio >= self._min_qa_ratio:
                counts["qa_pairs"] = min(human_count, assistant_count)

        # 2. Numbered list items
        numbered = len(_NUMBERED_ITEM.findall(text))
        if numbered > 0:
            counts["numbered_items"] = numbered

        # 3. "Example N:" headers
        headers = len(_EXAMPLE_HEADER.findall(text))
        if headers > 0:
            counts["example_headers"] = headers

        # 4. Bracket-delimited shot markers
        brackets = len(_BRACKET_OPEN.findall(text))
        if brackets > 0:
            counts["bracket_shots"] = brackets

        return counts

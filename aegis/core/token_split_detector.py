# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.token_split_detector — Domain 5.2 token-split reassembly attack detection.

Detects WAF bypass attacks where a malicious pattern is split across token
boundaries.  LLM tokenizers may split strings like ``"igno\\nre"`` into
``["igno", "\\n", "re"]`` or ``"j@ilbreak"`` into ``["j", "@", "ilbreak"]``.
A naive character-level WAF misses these because the bad string never appears
in any single token.

Detection strategy
------------------
This scanner builds a sliding window over adjacent tokens, reassembles each
window by joining tokens with no separator (and separately with a space), and
checks the reassembled strings against a catalogue of critical injection
patterns.  It also strips non-alphanumeric characters from each reassembled
window to defeat punctuation-insertion evasion.

Usage::

    detector = TokenSplitDetector(window_size=5, stride=1)
    result = detector.scan(["ignore", " ", "previous", "instructions"])
    if result.flagged:
        raise HTTPException(403, result.reason)

    result = detector.scan_messages(request.messages)
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

# ── Constants ─────────────────────────────────────────────────────────────────

_NON_ALNUM = re.compile(r"[^a-z0-9 ]")


# ── Data classes ──────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class TokenSplitSignal:
    """A single detected cross-boundary injection pattern.

    Attributes
    ----------
    pattern:
        The critical pattern found in the reassembled window text.
    window_tokens:
        The token window (as a list of strings) where the pattern was found.
    window_start:
        Index of the first token in *window_tokens* within the full token list.
    severity:
        ``"critical"`` for known-bad injection strings; ``"soft"`` reserved for
        future lower-confidence signals.
    """

    pattern: str
    window_tokens: list[str]
    window_start: int
    severity: str


@dataclass
class TokenSplitResult:
    """Outcome of a :class:`TokenSplitDetector` scan.

    Attributes
    ----------
    flagged:
        True when at least one cross-boundary injection pattern was found.
    signals:
        List of :class:`TokenSplitSignal` objects (one per matched pattern per
        window, deduplication is not performed so the same pattern may appear
        more than once if it spans multiple windows).
    scan_windows:
        Number of token windows examined.
    reason:
        Human-readable audit message.
    """

    flagged: bool
    signals: list[TokenSplitSignal]
    scan_windows: int
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {
            "flagged": self.flagged,
            "signals": [
                {
                    "pattern": s.pattern,
                    "window_tokens": list(s.window_tokens),
                    "window_start": s.window_start,
                    "severity": s.severity,
                }
                for s in self.signals
            ],
            "scan_windows": self.scan_windows,
            "reason": self.reason,
        }


# ── Detector ──────────────────────────────────────────────────────────────────


class TokenSplitDetector:
    """Detects prompt injection patterns split across token boundaries.

    LLM tokenizers sometimes split strings like ``"igno\\nre"`` into
    ``["igno", "\\n", "re"]`` or ``"j@ilbreak"`` into ``["j", "@", "ilbreak"]``.
    A naive character-level WAF misses these.  This scanner reassembles N-token
    windows and applies pattern matching to the reassembled text, catching
    cross-boundary evasion.

    Parameters
    ----------
    window_size:
        Number of tokens to include in each reassembly window.  Default ``5``.
    stride:
        Number of tokens to advance the window between checks.  Default ``1``
        (fully overlapping windows).
    extra_patterns:
        Additional patterns to check beyond :attr:`_CRITICAL_PATTERNS`.
    """

    # Critical patterns to check in reassembled windows (subset of WAF patterns)
    _CRITICAL_PATTERNS: list[str] = [
        "ignore previous",
        "ignore all previous",
        "disregard",
        "forget all",
        "new instructions",
        "you are now",
        "act as",
        "pretend you",
        "jailbreak",
        "dan mode",
        "developer mode",
        "ignore your",
        "bypass",
        "override",
        "system prompt",
        "your instructions",
    ]

    def __init__(
        self,
        window_size: int = 5,
        stride: int = 1,
        extra_patterns: list[str] | None = None,
    ) -> None:
        if window_size < 1:
            raise ValueError(f"window_size must be >= 1, got {window_size!r}")
        if stride < 1:
            raise ValueError(f"stride must be >= 1, got {stride!r}")
        self.window_size = window_size
        self.stride = stride
        self._patterns: list[str] = list(self._CRITICAL_PATTERNS)
        if extra_patterns:
            self._patterns.extend(extra_patterns)

    # ── Factory ───────────────────────────────────────────────────────────────

    @classmethod
    def from_env(cls) -> TokenSplitDetector:
        """Construct a :class:`TokenSplitDetector` from environment variables.

        Environment variables
        ---------------------
        AEGIS_TOKEN_SPLIT_WINDOW:
            Token window size (int).  Default ``5``.
        AEGIS_TOKEN_SPLIT_STRIDE:
            Stride between windows (int).  Default ``1``.
        """
        window_size = int(os.environ.get("AEGIS_TOKEN_SPLIT_WINDOW", "5"))
        stride = int(os.environ.get("AEGIS_TOKEN_SPLIT_STRIDE", "1"))
        return cls(window_size=window_size, stride=stride)

    # ── Core scan ─────────────────────────────────────────────────────────────

    def scan(self, tokens: list[str]) -> TokenSplitResult:
        """Scan a pre-tokenised token list for cross-boundary injection patterns.

        Each window of ``window_size`` adjacent tokens is reassembled in three
        ways and checked against all patterns:

        1. Joined with no separator (``"".join(window)``).
        2. Joined with a single space (``" ".join(window)``).
        3. Non-alphanumeric characters stripped from the no-separator join.

        All comparisons are case-insensitive.

        Parameters
        ----------
        tokens:
            Ordered list of token strings (e.g., output of a tokenizer or
            whitespace split).

        Returns
        -------
        TokenSplitResult
        """
        if not tokens:
            return TokenSplitResult(
                flagged=False,
                signals=[],
                scan_windows=0,
                reason="empty token list; nothing to scan",
            )

        signals: list[TokenSplitSignal] = []
        n = len(tokens)
        windows_checked = 0

        pos = 0
        while pos < n:
            window = tokens[pos : pos + self.window_size]
            windows_checked += 1

            joined_bare = "".join(window).lower()
            joined_spaced = " ".join(window).lower()
            # Strip all non-alphanumeric (including spaces) to defeat
            # punctuation-insertion and whitespace-insertion evasion.
            joined_stripped = _NON_ALNUM.sub("", joined_bare)

            for pattern in self._patterns:
                hit_bare = pattern in joined_bare
                hit_spaced = pattern in joined_spaced
                # Also compare the pattern with spaces removed against the
                # fully-stripped window so that "ignore previous" matches
                # the no-separator reassembly "ignoreprevious".
                pattern_stripped = pattern.replace(" ", "")
                hit_stripped = pattern_stripped in joined_stripped

                if hit_bare or hit_spaced or hit_stripped:
                    signals.append(
                        TokenSplitSignal(
                            pattern=pattern,
                            window_tokens=list(window),
                            window_start=pos,
                            severity="critical",
                        )
                    )

            pos += self.stride

        flagged = bool(signals)
        if flagged:
            patterns_found = sorted({s.pattern for s in signals})
            reason = (
                f"token-split injection detected: patterns={patterns_found!r} "
                f"across {windows_checked} windows"
            )
        else:
            reason = f"no cross-boundary patterns found in {windows_checked} windows"

        return TokenSplitResult(
            flagged=flagged,
            signals=signals,
            scan_windows=windows_checked,
            reason=reason,
        )

    # ── Convenience wrappers ──────────────────────────────────────────────────

    def scan_text(
        self,
        text: str,
        tokenize_fn=None,
    ) -> TokenSplitResult:
        """Scan free-form text by tokenising it first.

        Parameters
        ----------
        text:
            Input text to tokenise and scan.
        tokenize_fn:
            Optional callable ``(text: str) -> list[str]``.  When provided,
            this function is used to tokenise *text*.  When ``None``, the text
            is split on whitespace (``str.split()``).

        Returns
        -------
        TokenSplitResult
        """
        if tokenize_fn is not None:
            tokens = tokenize_fn(text)
        else:
            tokens = text.split()
        return self.scan(tokens)

    def scan_messages(self, messages: list[dict]) -> TokenSplitResult:
        """Scan a list of chat message dicts, examining only user-role content.

        User messages are tokenised by whitespace and scanned independently.
        Results are merged: ``flagged`` is ``True`` if any message is flagged,
        and all signals from all messages are combined in the returned result.

        Parameters
        ----------
        messages:
            List of ``{"role": str, "content": str}`` dicts.

        Returns
        -------
        TokenSplitResult
        """
        all_signals: list[TokenSplitSignal] = []
        total_windows = 0

        for msg in messages:
            if msg.get("role") != "user":
                continue
            content = msg.get("content", "")
            if not isinstance(content, str) or not content:
                continue
            result = self.scan_text(content)
            all_signals.extend(result.signals)
            total_windows += result.scan_windows

        flagged = bool(all_signals)
        if flagged:
            patterns_found = sorted({s.pattern for s in all_signals})
            reason = (
                f"token-split injection detected in messages: "
                f"patterns={patterns_found!r} across {total_windows} windows"
            )
        elif total_windows == 0:
            reason = "no user-role messages to scan"
        else:
            reason = f"no cross-boundary patterns found across {total_windows} windows"

        return TokenSplitResult(
            flagged=flagged,
            signals=all_signals,
            scan_windows=total_windows,
            reason=reason,
        )

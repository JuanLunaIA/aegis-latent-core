# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
r"""aegis.core.clinical_claim_detector — de-novo clinical claim detection.

Detects LLM-generated text that asserts novel clinical trial results, drug
efficacy, or treatment outcomes **without citing a supporting source**.
Such claims may constitute unsubstantiated medical advice, fabricated evidence,
or hallucinated research that could harm patients or mislead clinicians.

Threat model
------------
Large language models frequently fabricate clinical statistics (e.g. "a study
showed 73% improvement"), invent trial identifiers (NCT numbers), or state
unsupported drug efficacy claims with high confidence.  When an LLM proxy is
deployed in a healthcare or life-sciences context (HIPAA, 21 CFR Part 11,
ISO 13485), these outputs must be intercepted before they reach end users.

Detection approach
------------------
Two-stage:

1. **Claim detection**: Regex patterns match phrases that assert clinical
   findings (e.g. "a randomised controlled trial showed …", "studies confirm
   that drug X reduces …", "our research demonstrates …").

2. **Citation check**: A citation counter looks for inline citations
   ([1], (Smith et al., 2024), doi:, PMID:, NCT\d+) within
   ``citation_window_chars`` characters of each claim.  A claim without a
   proximate citation is a *violation*.

Usage::

    from aegis.core.clinical_claim_detector import ClinicalClaimDetector

    detector = ClinicalClaimDetector()
    result = detector.scan(llm_response_text)
    if result.has_violations:
        for v in result.violations:
            print(v.claim_snippet, "—", v.reason)

Configuration
-------------
``AEGIS_CLINICAL_STRICT``
    Set to any non-empty value to treat **any** clinical claim as a violation
    regardless of whether a citation is present.  Default: off.

``AEGIS_CLINICAL_WINDOW``
    Number of characters to search around each claim for a citation.
    Default: ``300``.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

_DEFAULT_CITATION_WINDOW = 300

# ── Claim patterns ────────────────────────────────────────────────────────────
# Each pattern detects a phrase that asserts a clinical finding.
# Group named ``claim`` captures the trigger phrase for the excerpt.

_CLAIM_PATTERNS: list[re.Pattern[str]] = [
    # "a/the study/trial/research showed/found/demonstrated/concluded …"
    re.compile(
        r"\b(?:a|the|one|this|our|recent|new|landmark|pivotal)\s+"
        r"(?:randomis[ae]d\s+controlled\s+trial|rct|clinical\s+trial|"
        r"double[- ]blind(?:\s+study)?|placebo[- ]controlled(?:\s+trial)?|"
        r"phase\s+[12i]{1,3}[ab]?\s+trial|study|trial|research|meta[- ]analysis|"
        r"systematic\s+review|cohort\s+study|case[- ]control\s+study|"
        r"observational\s+study|retrospective\s+(?:study|analysis)|"
        r"prospective\s+(?:study|trial))"
        r"\s+(?:showed?|found|demonstrated|concluded|reported|revealed|"
        r"indicated|established|confirmed|proved?)\b",
        re.IGNORECASE,
    ),
    # "studies/trials/research show/confirm/demonstrate …"
    re.compile(
        r"\b(?:studies|trials|research|data|evidence|results|findings)\s+"
        r"(?:show|confirm|demonstrate|suggest|indicate|support|prove|establish|"
        r"reveal)\s+(?:that\s+)?(?:drug|medication|treatment|therapy|vaccine|"
        r"intervention|patients?\s+(?:who|treated|given)|[a-z]+\s+(?:reduces?|"
        r"improves?|increases?|decreases?|lowers?|raises?|prevents?|treats?))\b",
        re.IGNORECASE,
    ),
    # "X reduces/improves/prevents Y by N%"
    re.compile(
        r"\b(?:reduced?s?|improved?s?|increased?s?|decreased?s?|lowered?s?|"
        r"prevented?s?|treated?s?|eliminated?s?|cured?s?|reversed?s?)\s+"
        r"(?:[a-zA-Z\s]{2,40}\s+)?by\s+\d{1,3}(?:\.\d+)?[%\s]",
        re.IGNORECASE,
    ),
    # "efficacy of X was N%"
    re.compile(
        r"\b(?:efficacy|effectiveness|response\s+rate|survival\s+rate|"
        r"remission\s+rate|cure\s+rate|success\s+rate|mortality\s+reduction)\s+"
        r"(?:of\s+[a-zA-Z\s]{2,30}\s+)?was\s+\d{1,3}(?:\.\d+)?[%\s]",
        re.IGNORECASE,
    ),
    # "our research/analysis/investigation demonstrates/proves …"
    re.compile(
        r"\b(?:our|this|the)\s+(?:research|analysis|investigation|study|trial|"
        r"findings?|data|results)\s+(?:demonstrates?|proves?|shows?|confirms?|"
        r"establishes?|reveals?|indicates?)\b",
        re.IGNORECASE,
    ),
    # "clinical evidence shows that X is safe/effective …"
    re.compile(
        r"\bclinical\s+(?:evidence|data|studies?|trials?|research)\s+"
        r"(?:shows?|demonstrates?|confirms?|supports?|proves?|indicates?)\s+"
        r"(?:that\s+)?",
        re.IGNORECASE,
    ),
    # "in a study of N patients … X was found to …"
    re.compile(
        r"\bin\s+a\s+(?:study|trial|cohort|analysis|review)\s+of\s+\d+\s+"
        r"(?:patients?|subjects?|participants?|individuals?|adults?|children|"
        r"volunteers?|cases?)\b",
        re.IGNORECASE,
    ),
    # "drug X has been proven/shown to treat/reduce/prevent …"
    re.compile(
        r"\bhas\s+been\s+(?:proven|shown|demonstrated|found|confirmed|"
        r"established|documented)\s+to\s+(?:treat|reduce|prevent|cure|"
        r"eliminate|reverse|improve|increase|decrease|lower)\b",
        re.IGNORECASE,
    ),
]

# ── Citation patterns ─────────────────────────────────────────────────────────
# A citation near the claim exonerates it from the violation list.

_CITATION_PATTERNS: list[re.Pattern[str]] = [
    # Numeric reference [1], [1,2], [1-5]
    re.compile(r"\[\d+(?:[,\-]\d+)*\]"),
    # Author-year: (Smith et al., 2024) or (Smith and Jones, 2024)
    re.compile(
        r"\([A-Z][a-zA-Z]+(?:\s+(?:et\s+al\.?|and\s+[A-Z][a-zA-Z]+))?[.,]\s*(?:19|20)\d{2}[a-z]?\)"
    ),
    # DOI
    re.compile(r"\bdoi\s*:\s*10\.\d{4,}/\S+", re.IGNORECASE),
    # PubMed ID
    re.compile(r"\bPMID\s*:?\s*\d{6,}", re.IGNORECASE),
    # ClinicalTrials.gov NCT number
    re.compile(r"\bNCT\d{6,}\b", re.IGNORECASE),
    # URL to a recognisable medical resource
    re.compile(
        r"https?://(?:pubmed|clinicaltrials|nejm|lancet|jamanetwork|"
        r"bmj|cochranelibrary|embase|medline|who\.int)\.",
        re.IGNORECASE,
    ),
    # Superscript numeric citation ¹²³
    re.compile(r"[¹²³⁴⁵⁶⁷⁸⁹⁰]{1,3}"),
    # Footnote marker (footnote 1, ref. 3)
    re.compile(r"\b(?:footnote|ref(?:erence)?\.?)\s*\d{1,3}\b", re.IGNORECASE),
    # According to + source
    re.compile(
        r"\baccording\s+to\s+(?:the\s+)?(?:[A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)?|"
        r"(?:FDA|WHO|CDC|NIH|EMA|NICE|MHRA|TGA|Health\s+Canada))\b",
        re.IGNORECASE,
    ),
]


# ── Result types ──────────────────────────────────────────────────────────────


@dataclass
class ClinicalClaimViolation:
    """A de-novo clinical claim without a supporting citation.

    Attributes
    ----------
    claim_snippet:
        Short excerpt showing the claim (up to 100 chars).
    position:
        Character position in the scanned text where the claim starts.
    reason:
        Human-readable explanation.
    """

    claim_snippet: str
    position: int
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {
            "claim_snippet": self.claim_snippet,
            "position": self.position,
            "reason": self.reason,
        }


@dataclass
class ClinicalClaimResult:
    """Result of a :meth:`ClinicalClaimDetector.scan` call.

    Attributes
    ----------
    violations:
        Claims found without a proximate citation.
    total_claims:
        Total number of clinical claim phrases detected (cited + uncited).
    scanned_chars:
        Length of input text.
    strict:
        Whether strict mode was active (all claims are violations).
    """

    violations: list[ClinicalClaimViolation] = field(default_factory=list)
    total_claims: int = 0
    scanned_chars: int = 0
    strict: bool = False

    @property
    def has_violations(self) -> bool:
        return bool(self.violations)

    @property
    def violation_count(self) -> int:
        return len(self.violations)

    @property
    def cited_claims(self) -> int:
        return max(0, self.total_claims - len(self.violations))

    def to_dict(self) -> dict[str, object]:
        return {
            "has_violations": self.has_violations,
            "violation_count": self.violation_count,
            "total_claims": self.total_claims,
            "cited_claims": self.cited_claims,
            "scanned_chars": self.scanned_chars,
            "strict": self.strict,
            "violations": [v.to_dict() for v in self.violations],
        }


# ── Detector ──────────────────────────────────────────────────────────────────


class ClinicalClaimDetector:
    """Detects de-novo clinical claims without supporting citations in LLM output.

    Parameters
    ----------
    strict:
        When True, every clinical claim is a violation regardless of citations.
        Defaults to the ``AEGIS_CLINICAL_STRICT`` env var (False when unset).
    citation_window_chars:
        Number of characters to search around each claim for a citation.
        Defaults to ``AEGIS_CLINICAL_WINDOW`` env var (300 when unset).
    """

    def __init__(
        self,
        strict: bool | None = None,
        citation_window_chars: int | None = None,
    ) -> None:
        if strict is None:
            strict = bool(os.environ.get("AEGIS_CLINICAL_STRICT"))
        self.strict = strict

        if citation_window_chars is None:
            raw = os.environ.get("AEGIS_CLINICAL_WINDOW", str(_DEFAULT_CITATION_WINDOW))
            try:
                citation_window_chars = max(0, int(raw))
            except ValueError:
                logger.warning(
                    "clinical_claim_detector: invalid AEGIS_CLINICAL_WINDOW=%r; using %d",
                    raw,
                    _DEFAULT_CITATION_WINDOW,
                )
                citation_window_chars = _DEFAULT_CITATION_WINDOW
        self.citation_window_chars = citation_window_chars

    # ── Public API ────────────────────────────────────────────────────────────

    def scan(self, text: str) -> ClinicalClaimResult:
        """Scan *text* for de-novo clinical claims without citations.

        Parameters
        ----------
        text:
            LLM-generated response text.
        """
        result = ClinicalClaimResult(scanned_chars=len(text), strict=self.strict)
        seen_positions: set[int] = set()

        for pat in _CLAIM_PATTERNS:
            for match in pat.finditer(text):
                pos = match.start()
                # Skip overlapping claims (within 50 chars of an already-seen claim)
                if any(abs(pos - p) < 50 for p in seen_positions):
                    continue
                seen_positions.add(pos)
                result.total_claims += 1

                snippet = text[pos : pos + 100].replace("\n", " ")

                if self.strict:
                    result.violations.append(
                        ClinicalClaimViolation(
                            claim_snippet=snippet,
                            position=pos,
                            reason="strict mode: all clinical claims require citation",
                        )
                    )
                    continue

                # Check for a citation within the window
                window_start = max(0, pos - self.citation_window_chars)
                window_end = min(len(text), pos + len(match.group()) + self.citation_window_chars)
                window = text[window_start:window_end]

                if not self._has_citation(window):
                    result.violations.append(
                        ClinicalClaimViolation(
                            claim_snippet=snippet,
                            position=pos,
                            reason="clinical claim without a proximate citation",
                        )
                    )
                    logger.warning(
                        "clinical_claim_detector: uncited clinical claim at position %d: %r",
                        pos,
                        snippet[:60],
                    )

        return result

    def scan_messages(self, messages: list[dict[str, str]]) -> ClinicalClaimResult:
        """Scan assistant-role messages in an OpenAI-style message list."""
        combined = "\n".join(m.get("content", "") for m in messages if m.get("role") == "assistant")
        return self.scan(combined)

    # ── Internal ──────────────────────────────────────────────────────────────

    @staticmethod
    def _has_citation(window: str) -> bool:
        return any(pat.search(window) is not None for pat in _CITATION_PATTERNS)

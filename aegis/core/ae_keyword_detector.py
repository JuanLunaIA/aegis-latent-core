# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.ae_keyword_detector — Adverse Event keyword detection aligned to MedDRA.

Screens AI-generated responses for adverse event (AE) terminology aligned to
MedDRA (Medical Dictionary for Regulatory Activities) Preferred Terms (PTs).
When an LLM mentions AE-related terms in a clinical context, the output should
be flagged for human review before delivery to ensure accuracy and to meet
pharmacovigilance obligations under ICH E2A/E2B(R3) and 21 CFR 312.32.

MedDRA alignment
----------------
The built-in term set covers high-frequency PTs across the most clinically
significant System Organ Classes (SOCs) including:

* **Nervous system disorders** — headache, dizziness, tremor, paraesthesia, etc.
* **Cardiac disorders** — palpitations, tachycardia, bradycardia, arrhythmia, etc.
* **Gastrointestinal disorders** — nausea, vomiting, diarrhoea/diarrhea, etc.
* **Respiratory disorders** — dyspnoea/dyspnea, cough, bronchospasm, etc.
* **Skin disorders** — rash, urticaria, pruritus, angioedema, etc.
* **Hepatic disorders** — hepatotoxicity, jaundice, elevated liver enzymes, etc.
* **Renal disorders** — nephrotoxicity, proteinuria, haematuria, etc.
* **Musculoskeletal disorders** — myalgia, arthralgia, rhabdomyolysis, etc.
* **General / administration site conditions** — fatigue, fever, injection site reaction, etc.
* **Serious AE qualifiers** — death, hospitalisation, life-threatening, etc.

Usage::

    detector = AEKeywordDetector()
    result = detector.scan("Patient experienced nausea and vomiting after dose.")
    if result.flagged:
        log.warning("AE terms detected: %s", result.terms_found)

    # Scan a full response list
    results = detector.scan_messages([
        {"role": "assistant", "content": "The drug may cause hepatotoxicity."}
    ])
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# ── MedDRA-aligned preferred term set ─────────────────────────────────────────
# Each entry is (term, soc) where soc is the MedDRA System Organ Class abbreviation.
# Terms are matched case-insensitively as whole words.

_MEDDRA_TERMS: list[tuple[str, str]] = [
    # Nervous system disorders (NS)
    ("headache", "NS"),
    ("dizziness", "NS"),
    ("tremor", "NS"),
    ("paraesthesia", "NS"),
    ("paresthesia", "NS"),
    ("neuropathy", "NS"),
    ("peripheral neuropathy", "NS"),
    ("somnolence", "NS"),
    ("convulsion", "NS"),
    ("seizure", "NS"),
    ("syncope", "NS"),
    ("ataxia", "NS"),
    ("dysarthria", "NS"),
    ("encephalopathy", "NS"),
    ("peripheral sensory neuropathy", "NS"),
    # Cardiac disorders (CA)
    ("palpitations", "CA"),
    ("tachycardia", "CA"),
    ("bradycardia", "CA"),
    ("arrhythmia", "CA"),
    ("atrial fibrillation", "CA"),
    ("QT prolongation", "CA"),
    ("myocardial infarction", "CA"),
    ("cardiac arrest", "CA"),
    ("ventricular tachycardia", "CA"),
    ("ventricular fibrillation", "CA"),
    ("heart failure", "CA"),
    # Gastrointestinal disorders (GI)
    ("nausea", "GI"),
    ("vomiting", "GI"),
    ("diarrhoea", "GI"),
    ("diarrhea", "GI"),
    ("constipation", "GI"),
    ("abdominal pain", "GI"),
    ("dyspepsia", "GI"),
    ("gastrointestinal bleeding", "GI"),
    ("colitis", "GI"),
    ("pancreatitis", "GI"),
    ("stomatitis", "GI"),
    # Respiratory disorders (RS)
    ("dyspnoea", "RS"),
    ("dyspnea", "RS"),
    ("cough", "RS"),
    ("bronchospasm", "RS"),
    ("pneumonitis", "RS"),
    ("pulmonary embolism", "RS"),
    ("respiratory failure", "RS"),
    ("interstitial lung disease", "RS"),
    ("epistaxis", "RS"),
    # Skin and subcutaneous tissue disorders (SK)
    ("rash", "SK"),
    ("urticaria", "SK"),
    ("pruritus", "SK"),
    ("angioedema", "SK"),
    ("alopecia", "SK"),
    ("erythema", "SK"),
    ("Stevens-Johnson syndrome", "SK"),
    ("toxic epidermal necrolysis", "SK"),
    ("photosensitivity reaction", "SK"),
    # Hepatobiliary disorders (HE)
    ("hepatotoxicity", "HE"),
    ("jaundice", "HE"),
    ("hepatitis", "HE"),
    ("liver failure", "HE"),
    ("elevated liver enzymes", "HE"),
    ("cholestasis", "HE"),
    # Renal and urinary disorders (RE)
    ("nephrotoxicity", "RE"),
    ("proteinuria", "RE"),
    ("haematuria", "RE"),
    ("hematuria", "RE"),
    ("renal failure", "RE"),
    ("acute kidney injury", "RE"),
    # Musculoskeletal disorders (MU)
    ("myalgia", "MU"),
    ("arthralgia", "MU"),
    ("rhabdomyolysis", "MU"),
    ("myopathy", "MU"),
    ("muscle weakness", "MU"),
    # Blood and lymphatic disorders (BL)
    ("thrombocytopenia", "BL"),
    ("anaemia", "BL"),
    ("anemia", "BL"),
    ("neutropenia", "BL"),
    ("leucopenia", "BL"),
    ("leukopenia", "BL"),
    ("coagulopathy", "BL"),
    # Immune system disorders (IM)
    ("anaphylaxis", "IM"),
    ("hypersensitivity", "IM"),
    ("anaphylactic reaction", "IM"),
    ("anaphylactic shock", "IM"),
    # General / administration site disorders (GE)
    ("fatigue", "GE"),
    ("pyrexia", "GE"),
    ("fever", "GE"),
    ("injection site reaction", "GE"),
    ("oedema", "GE"),
    ("edema", "GE"),
    ("malaise", "GE"),
    ("asthenia", "GE"),
    ("chills", "GE"),
    ("injection site pain", "GE"),
    # Serious AE qualifiers (SA)
    ("death", "SA"),
    ("fatal", "SA"),
    ("life-threatening", "SA"),
    ("hospitalisation", "SA"),
    ("hospitalization", "SA"),
    ("disability", "SA"),
    ("congenital anomaly", "SA"),
    ("serious adverse event", "SA"),
    ("adverse event", "SA"),
    ("adverse reaction", "SA"),
    ("adverse drug reaction", "SA"),
    ("side effect", "SA"),
    ("toxicity", "SA"),
]

# Compile patterns: whole-word, case-insensitive
_COMPILED: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"\b" + re.escape(term) + r"\b", re.IGNORECASE), term, soc)
    for term, soc in _MEDDRA_TERMS
]

# Number of built-in terms (used in tests for pattern count assertions)
BUILTIN_TERM_COUNT: int = len(_MEDDRA_TERMS)


@dataclass
class AEDetectionResult:
    """Outcome of an adverse event keyword scan.

    Attributes
    ----------
    flagged:
        True when at least one AE term was detected.
    terms_found:
        List of ``(term, soc)`` tuples for each match (deduplicated, order of
        first occurrence preserved).
    soc_counts:
        Hit count per MedDRA System Organ Class abbreviation.
    scan_length:
        Number of characters scanned.
    reason:
        Human-readable audit summary.
    """

    flagged: bool = False
    terms_found: list[tuple[str, str]] = field(default_factory=list)
    soc_counts: dict[str, int] = field(default_factory=dict)
    scan_length: int = 0
    reason: str = ""

    def __bool__(self) -> bool:
        return self.flagged

    def to_dict(self) -> dict[str, object]:
        return {
            "flagged": self.flagged,
            "terms_found": [(t, s) for t, s in self.terms_found],
            "soc_counts": dict(self.soc_counts),
            "scan_length": self.scan_length,
            "reason": self.reason,
        }


class AEKeywordDetector:
    """MedDRA-aligned adverse event keyword detector.

    Parameters
    ----------
    extra_terms:
        Additional ``(term, soc)`` tuples to add to the built-in set.
        Useful for product-specific adverse event terminology.
    require_clinical_context:
        When True (default), AE terms are only flagged when the text also
        contains a clinical context marker (e.g., "patient", "dose", "drug",
        "medication", "treatment", "therapy", "clinical", "trial", "study",
        "adverse", "symptom", "reaction").  Reduces false positives on
        non-clinical content where words like "fatigue" or "rash" appear in
        everyday prose.  Set to False to flag any occurrence regardless of
        context.
    """

    _CLINICAL_CONTEXT = re.compile(
        r"\b(?:patient|dose|drug|medication|treatment|therapy|clinical|"
        r"trial|study|adverse|symptom|reaction|physician|prescri(?:be|ption)|"
        r"therapeutic|pharmacolog|side.?effect|toxicity)\b",
        re.IGNORECASE,
    )

    def __init__(
        self,
        extra_terms: list[tuple[str, str]] | None = None,
        require_clinical_context: bool = True,
    ) -> None:
        self._require_context = require_clinical_context
        if extra_terms:
            self._patterns: list[tuple[re.Pattern[str], str, str]] = list(_COMPILED) + [
                (re.compile(r"\b" + re.escape(t) + r"\b", re.IGNORECASE), t, s)
                for t, s in extra_terms
            ]
        else:
            self._patterns = _COMPILED

    @property
    def term_count(self) -> int:
        """Total number of terms (built-in + extra)."""
        return len(self._patterns)

    # ── Public API ─────────────────────────────────────────────────────────────

    def scan(self, text: str) -> AEDetectionResult:
        """Scan *text* for MedDRA adverse event terms.

        Parameters
        ----------
        text:
            Any string — typically an LLM response or a clinical note.
        """
        if not text:
            return AEDetectionResult(
                flagged=False,
                scan_length=0,
                reason="empty text; no AE terms scanned",
            )

        if self._require_context and not self._has_clinical_context(text):
            return AEDetectionResult(
                flagged=False,
                scan_length=len(text),
                reason="no clinical context detected; AE scan skipped",
            )

        terms_found: list[tuple[str, str]] = []
        seen: set[str] = set()
        soc_counts: dict[str, int] = {}

        for pattern, term, soc in self._patterns:
            if pattern.search(text):
                if term.lower() not in seen:
                    seen.add(term.lower())
                    terms_found.append((term, soc))
                soc_counts[soc] = soc_counts.get(soc, 0) + 1

        flagged = bool(terms_found)
        if flagged:
            soc_summary = ", ".join(f"{s}:{c}" for s, c in sorted(soc_counts.items()))
            reason = f"AE terms detected: {len(terms_found)} term(s) across SOCs [{soc_summary}]"
        else:
            reason = "no MedDRA AE terms detected"

        return AEDetectionResult(
            flagged=flagged,
            terms_found=terms_found,
            soc_counts=soc_counts,
            scan_length=len(text),
            reason=reason,
        )

    def scan_messages(self, messages: list[dict[str, object]]) -> AEDetectionResult:
        """Scan a list of chat message dicts for AE terms.

        Concatenates all assistant/tool message content before scanning so
        that AE terms spread across multiple response turns are caught.

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
        return self.scan(combined)

    def scan_text_bulk(self, texts: list[str]) -> list[AEDetectionResult]:
        """Scan multiple texts and return one result per text."""
        return [self.scan(t) for t in texts]

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _has_clinical_context(self, text: str) -> bool:
        """Return True if *text* contains a clinical context indicator."""
        return bool(self._CLINICAL_CONTEXT.search(text))

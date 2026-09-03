# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.icd_snomed_detector — ICD-11 / SNOMED-CT ontology-aware anomaly detection.

Detects responses that contain clinical classification codes (ICD-10-CM, ICD-11,
or SNOMED-CT) from a *different clinical domain* than the request context.  This
catches hallucinated diagnoses, cross-specialty code errors, and clinical content
mismatches before they reach end-users.

Detection strategy
------------------
1. **Code extraction**: regex patterns identify ICD-10-CM, ICD-11, and
   explicitly-referenced SNOMED-CT codes in both request and response text.
2. **Domain resolution**: each code is mapped to a clinical chapter/domain
   (e.g., ``"Respiratory"``, ``"Mental/Behavioral"``).
3. **Context inference**: when the request contains no explicit codes, clinical
   keywords (e.g., "diabetes", "cardiac arrest", "pneumonia") are used to
   infer the expected domain set.
4. **Mismatch detection**: if the response contains codes from a domain absent
   from the request's domain set, a mismatch is flagged.

Supported code types
--------------------
* **ICD-10-CM**: ``A00–Z99`` with decimal subdivisions (e.g., ``J18.9``,
  ``F32.0``).  The leading letter selects the clinical chapter.
* **ICD-11**: alphanumeric codes of the form ``XNN.N`` where the first
  character/digit selects the chapter (e.g., ``CA40.0``, ``6A80.1``).
* **SNOMED-CT**: detected only when explicitly labelled
  (e.g., ``SNOMED: 73211009``, ``SNOMED-CT 267036007``).

Usage::

    from aegis.core.icd_snomed_detector import ICDSNOMEDDetector

    detector = ICDSNOMEDDetector()
    result = detector.scan(
        request_text="Patient has type 2 diabetes mellitus.",
        response_text="Recommend treatment for pneumonia (J18.9).",
    )
    if result.mismatch_detected:
        print("Domain mismatch:", result.mismatch_domains)

Configuration
-------------
``AEGIS_ICD_STRICT``
    When set to ``"true"``, any response code that is not from the same domain
    as the request is flagged — even if no explicit codes were in the request
    (keyword inference only).  Default: ``"false"`` (strict mode off).
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# ── ICD-10-CM chapter map (leading letter → clinical domain) ─────────────────

_ICD10_CHAPTER: dict[str, str] = {
    "A": "Infectious/Parasitic",
    "B": "Infectious/Parasitic",
    "C": "Neoplasms",
    "D": "Neoplasms/Blood",
    "E": "Endocrine/Metabolic",
    "F": "Mental/Behavioral",
    "G": "Nervous System",
    "H": "Eye/Ear",
    "I": "Circulatory",
    "J": "Respiratory",
    "K": "Digestive",
    "L": "Skin",
    "M": "Musculoskeletal",
    "N": "Genitourinary",
    "O": "Pregnancy/Childbirth",
    "P": "Perinatal",
    "Q": "Congenital",
    "R": "Symptoms/Signs",
    "S": "Injury/Trauma",
    "T": "Injury/Poisoning",
    "V": "External Causes",
    "W": "External Causes",
    "X": "External Causes",
    "Y": "External Causes",
    "Z": "Health Status Factors",
}

# ── ICD-11 chapter map (first character → clinical domain) ───────────────────

_ICD11_CHAPTER: dict[str, str] = {
    "1": "Infectious/Parasitic",
    "2": "Neoplasms",
    "3": "Blood/Hematopoietic",
    "4": "Immune System",
    "5": "Endocrine/Metabolic",
    "6": "Mental/Behavioral",
    "7": "Sleep Disorders",
    "8": "Nervous System",
    "9": "Visual System",
    "A": "Ear/Mastoid",
    "B": "Circulatory",
    "C": "Respiratory",
    "D": "Digestive",
    "E": "Skin",
    "F": "Musculoskeletal",
    "G": "Genitourinary",
    "H": "Sexual Health",
    "J": "Pregnancy/Perinatal",
    "K": "Perinatal",
    "L": "Developmental Anomalies",
    "M": "Symptoms/Signs",
    "N": "Injury/Trauma",
    "P": "External Causes",
    "Q": "Supplementary Chapter",
    "S": "Traditional Medicine",
    "V": "Functioning Assessment",
    "X": "Extension Codes",
}

# ── Keyword → domain inference (for requests without explicit codes) ──────────

_KEYWORD_DOMAIN: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"\b(?:diabetes|insulin|glucose|thyroid|hyperthyroid|hypothyroid|HbA1c|A1C|endocrine|adrenal|cortisol|Cushing|Addison)\b",
            re.IGNORECASE,
        ),
        "Endocrine/Metabolic",
    ),
    (
        re.compile(
            r"\b(?:pneumonia|asthma|COPD|bronchitis|emphysema|respiratory|lung|pulmonary|dyspnea|wheez|tuberculosis|TB)\b",
            re.IGNORECASE,
        ),
        "Respiratory",
    ),
    (
        re.compile(
            r"\b(?:cancer|tumor|tumour|carcinoma|lymphoma|leukemia|leukaemia|melanoma|sarcoma|neoplasm|oncolog|malignant)\b",
            re.IGNORECASE,
        ),
        "Neoplasms",
    ),
    (
        re.compile(
            r"\b(?:depression|anxiety|bipolar|schizophrenia|psychosis|ADHD|autism|dementia|Alzheimer|mental health|psychiatric|PTSD)\b",
            re.IGNORECASE,
        ),
        "Mental/Behavioral",
    ),
    (
        re.compile(
            r"\b(?:heart|cardiac|coronary|myocardial|infarction|hypertension|stroke|atrial fibrillation|angina|arrhythmia|cardiovascular)\b",
            re.IGNORECASE,
        ),
        "Circulatory",
    ),
    (
        re.compile(
            r"\b(?:fracture|trauma|wound|injury|laceration|contusion|sprain|dislocation|burn|crush)\b",
            re.IGNORECASE,
        ),
        "Injury/Trauma",
    ),
    (
        re.compile(
            r"\b(?:pregnancy|prenatal|obstetric|maternal|fetal|foetal|labour|labor|cesarean|gestational)\b",
            re.IGNORECASE,
        ),
        "Pregnancy/Childbirth",
    ),
    (
        re.compile(
            r"\b(?:infection|virus|bacteria|sepsis|HIV|AIDS|hepatitis|influenza|COVID|SARS|malaria)\b",
            re.IGNORECASE,
        ),
        "Infectious/Parasitic",
    ),
    (
        re.compile(
            r"\b(?:arthritis|osteoporosis|fibromyalgia|rheumatoid|gout|musculoskeletal|joint|spine|scoliosis)\b",
            re.IGNORECASE,
        ),
        "Musculoskeletal",
    ),
    (
        re.compile(
            r"\b(?:kidney|renal|urinary|bladder|nephritis|dialysis|UTI|prostate|genitourinary)\b",
            re.IGNORECASE,
        ),
        "Genitourinary",
    ),
    (
        re.compile(
            r"\b(?:gastritis|colitis|IBD|Crohn|ulcer|intestinal|liver|hepatic|cirrhosis|pancreatitis|gastrointestinal|digestive)\b",
            re.IGNORECASE,
        ),
        "Digestive",
    ),
    (
        re.compile(
            r"\b(?:eczema|psoriasis|dermatitis|skin|rash|melanoma|acne|urticaria)\b", re.IGNORECASE
        ),
        "Skin",
    ),
    (
        re.compile(
            r"\b(?:epilepsy|seizure|Parkinson|multiple sclerosis|neuropathy|neurology|neurological|migraine|stroke)\b",
            re.IGNORECASE,
        ),
        "Nervous System",
    ),
]

# ── Regex patterns for code detection ────────────────────────────────────────

# ICD-10-CM: Letter + 2 digits, optional dot + 1-4 alphanumeric chars
# Negative lookahead prevents matching inside longer words like "B12" vitamin references
_ICD10_RE = re.compile(r"(?<![A-Z0-9])([A-TV-Z][0-9][0-9A-Z])(?:\.([0-9A-Z]{1,4}))?(?![A-Z0-9])")

# ICD-11: 3–4 char stem + dot + 1–4 alphanumeric.
# Two stem forms to avoid ambiguity with ICD-10-CM (which uses Letter+Digit+Digit):
#   • Digit-first  (e.g. 6A80):  [1-9][A-Z0-9]{2,3}
#   • Letter-first (e.g. CA40):  [A-NP-XV] followed by a LETTER (not digit) to distinguish
#     from ICD-10-CM stems like J18 where position-2 is always a digit.
_ICD11_RE = re.compile(
    r"(?<![A-Z0-9])([1-9][A-Z0-9]{2,3}|[A-NP-XV][A-Z][A-Z0-9]{1,2})\.([A-Z0-9]{1,4})(?![A-Z0-9])"
)

# SNOMED-CT: explicitly labelled numeric ID
_SNOMED_RE = re.compile(
    r"\bSNOMED(?:[\s\-]CT)?(?:\s+(?:concept|code))?[:\s#]?\s*([0-9]{6,18})\b",
    re.IGNORECASE,
)


# ── Data classes ──────────────────────────────────────────────────────────────


@dataclass
class ClinicalCodeFinding:
    """A clinical code detected in text.

    Attributes
    ----------
    code_type:
        ``"icd10"``, ``"icd11"``, or ``"snomed"``.
    code:
        The full code string (e.g., ``"J18.9"``).
    position:
        Character offset in the scanned text.
    domain:
        Clinical chapter/domain name.
    """

    code_type: str
    code: str
    position: int
    domain: str

    def to_dict(self) -> dict[str, object]:
        return {
            "code_type": self.code_type,
            "code": self.code,
            "position": self.position,
            "domain": self.domain,
        }


@dataclass
class ICDSNOMEDResult:
    """Result of a :meth:`ICDSNOMEDDetector.scan` call.

    Attributes
    ----------
    request_codes:
        Clinical codes detected in the request.
    response_codes:
        Clinical codes detected in the response.
    request_domains:
        Clinical domains inferred from the request (codes + keywords).
    response_domains:
        Clinical domains present in the response.
    mismatch_detected:
        True when the response contains codes from domains absent from
        the request context.
    mismatch_domains:
        The response domains that were not in the request domain set.
    """

    request_codes: list[ClinicalCodeFinding] = field(default_factory=list)
    response_codes: list[ClinicalCodeFinding] = field(default_factory=list)
    request_domains: set[str] = field(default_factory=set)
    response_domains: set[str] = field(default_factory=set)
    mismatch_detected: bool = False
    mismatch_domains: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "mismatch_detected": self.mismatch_detected,
            "mismatch_domains": self.mismatch_domains,
            "request_domains": sorted(self.request_domains),
            "response_domains": sorted(self.response_domains),
            "request_code_count": len(self.request_codes),
            "response_code_count": len(self.response_codes),
            "request_codes": [c.to_dict() for c in self.request_codes],
            "response_codes": [c.to_dict() for c in self.response_codes],
        }


# ── Detector ──────────────────────────────────────────────────────────────────


class ICDSNOMEDDetector:
    """Detects ICD-10-CM / ICD-11 / SNOMED-CT codes and flags domain mismatches.

    Parameters
    ----------
    strict:
        When True, flag any response code whose domain is not found in the
        request context — even when the request contained no explicit codes
        and domain was inferred from keywords.  Defaults to
        ``AEGIS_ICD_STRICT`` env var (default ``False``).
    """

    def __init__(self, strict: bool | None = None) -> None:
        if strict is None:
            strict = os.environ.get("AEGIS_ICD_STRICT", "false").lower() == "true"
        self.strict = strict

    def scan(self, request_text: str, response_text: str) -> ICDSNOMEDResult:
        """Scan *response_text* for domain mismatches relative to *request_text*.

        Parameters
        ----------
        request_text:
            The user request or system-prompt context.
        response_text:
            The model response to check.

        Returns
        -------
        ICDSNOMEDResult
            Contains extracted codes, domains, and mismatch flags.
        """
        result = ICDSNOMEDResult()

        # Extract codes
        result.request_codes = self.extract_codes(request_text)
        result.response_codes = self.extract_codes(response_text)

        # Build request domain set from explicit codes + keyword inference
        result.request_domains = {c.domain for c in result.request_codes}
        keyword_domains = self._keyword_domains(request_text)
        has_explicit_request_codes = bool(result.request_codes)
        result.request_domains |= keyword_domains

        # Build response domain set
        result.response_domains = {c.domain for c in result.response_codes}

        # Detect mismatches
        if result.response_codes and result.request_domains:
            extra = result.response_domains - result.request_domains
            if extra:
                if has_explicit_request_codes or self.strict:
                    result.mismatch_detected = True
                    result.mismatch_domains = sorted(extra)
        elif result.response_codes and not result.request_domains:
            # Response has codes but request context has no clinical domain at all
            if self.strict:
                result.mismatch_detected = True
                result.mismatch_domains = sorted(result.response_domains)

        return result

    def scan_messages(self, messages: list[dict[str, str]]) -> ICDSNOMEDResult:
        """Scan a conversation message list.

        Collects all ``user`` and ``system`` messages as request context and
        checks each ``assistant`` message for domain mismatches.

        Parameters
        ----------
        messages:
            List of ``{"role": str, "content": str}`` dicts.
        """
        request_parts: list[str] = []
        response_parts: list[str] = []
        for msg in messages:
            role = msg.get("role", "")
            content = msg.get("content", "")
            if role in ("user", "system"):
                request_parts.append(content)
            elif role == "assistant":
                response_parts.append(content)
        return self.scan(" ".join(request_parts), " ".join(response_parts))

    def extract_codes(self, text: str) -> list[ClinicalCodeFinding]:
        """Extract all ICD and SNOMED codes from *text*."""
        findings: list[ClinicalCodeFinding] = []

        # ICD-11 first (more specific pattern)
        for m in _ICD11_RE.finditer(text):
            prefix = m.group(1)[0]
            domain = _ICD11_CHAPTER.get(prefix, "Unknown")
            code = f"{m.group(1)}.{m.group(2)}"
            findings.append(
                ClinicalCodeFinding(
                    code_type="icd11",
                    code=code,
                    position=m.start(),
                    domain=domain,
                )
            )

        # ICD-10-CM
        icd11_spans = {(f.position, f.position + len(f.code)) for f in findings}
        for m in _ICD10_RE.finditer(text):
            # Skip spans already matched as ICD-11
            span = (m.start(), m.end())
            if any(s[0] <= span[0] < s[1] for s in icd11_spans):
                continue
            prefix = m.group(1)[0].upper()
            if prefix not in _ICD10_CHAPTER:
                continue
            domain = _ICD10_CHAPTER[prefix]
            suffix = f".{m.group(2)}" if m.group(2) else ""
            code = f"{m.group(1)}{suffix}"
            findings.append(
                ClinicalCodeFinding(
                    code_type="icd10",
                    code=code,
                    position=m.start(),
                    domain=domain,
                )
            )

        # SNOMED-CT (explicit label required)
        for m in _SNOMED_RE.finditer(text):
            findings.append(
                ClinicalCodeFinding(
                    code_type="snomed",
                    code=m.group(1),
                    position=m.start(),
                    domain="SNOMED-CT",
                )
            )

        return findings

    # ── Internal ──────────────────────────────────────────────────────────────

    def _keyword_domains(self, text: str) -> set[str]:
        """Return clinical domains inferred from keywords in *text*."""
        domains: set[str] = set()
        for pattern, domain in _KEYWORD_DOMAIN:
            if pattern.search(text):
                domains.add(domain)
        return domains

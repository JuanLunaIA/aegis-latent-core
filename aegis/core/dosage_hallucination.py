# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.dosage_hallucination — drug dosage hallucination detection.

Scans LLM-generated text for numeric drug dosage claims and compares them
against a curated reference database of clinically plausible ranges.  Claims
that fall outside the reference range are flagged as potential hallucinations.

Reference data is sourced from NLM DailyMed / RxNorm labelling conventions.
Ranges represent typical adult therapeutic doses; they are intentionally
conservative (wide) to minimise false positives.

Usage::

    from aegis.core.dosage_hallucination import DosageHallucinationDetector

    detector = DosageHallucinationDetector()
    result = detector.scan("Give ibuprofen 5000 mg every 4 hours")
    if result.has_violations:
        for v in result.violations:
            print(v.summary())   # "ibuprofen: 5000 mg exceeds max 800 mg"

Configuration
-------------
``AEGIS_DOSAGE_STRICT``
    Set to any non-empty value to treat *unknown* drugs as violations when
    a dosage is extracted but the drug is not in the reference database.
    Default: off (unknown drugs produce a ``DosageFinding`` with
    ``unknown_drug=True`` but are not included in ``violations``).
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from typing import NamedTuple

logger = logging.getLogger(__name__)

# ── Reference database ────────────────────────────────────────────────────────
# Each entry: (drug_name_lower, unit, min_mg_or_unit, max_mg_or_unit)
# Units: "mg", "mcg", "mg/kg", "units", "mEq"
# Ranges are per-single-dose (adult), not daily totals.


class _DrugEntry(NamedTuple):
    name: str
    unit: str
    min_val: float
    max_val: float
    aliases: tuple[str, ...] = ()


_DRUG_DB: list[_DrugEntry] = [
    # NSAIDs
    _DrugEntry("ibuprofen", "mg", 200, 800),
    _DrugEntry("naproxen", "mg", 220, 500, ("naproxen sodium",)),
    _DrugEntry("aspirin", "mg", 81, 1000, ("acetylsalicylic acid",)),
    _DrugEntry("celecoxib", "mg", 100, 400),
    _DrugEntry("diclofenac", "mg", 25, 75, ("voltaren",)),
    _DrugEntry("indomethacin", "mg", 25, 75, ("indocin",)),
    _DrugEntry("ketorolac", "mg", 10, 30, ("toradol",)),
    # Analgesics / opioids
    _DrugEntry("acetaminophen", "mg", 325, 1000, ("paracetamol", "tylenol", "panadol")),
    _DrugEntry("tramadol", "mg", 50, 100),
    _DrugEntry("morphine", "mg", 2, 30),
    _DrugEntry("oxycodone", "mg", 5, 30, ("oxycontin", "percocet")),
    _DrugEntry("hydrocodone", "mg", 5, 10, ("vicodin", "norco")),
    _DrugEntry("codeine", "mg", 15, 60),
    _DrugEntry("fentanyl", "mcg", 12, 200, ("duragesic",)),
    _DrugEntry("buprenorphine", "mg", 2, 32, ("subutex", "suboxone")),
    _DrugEntry("methadone", "mg", 2.5, 40),
    _DrugEntry("naloxone", "mg", 0.4, 2, ("narcan",)),
    # Antibiotics
    _DrugEntry("amoxicillin", "mg", 250, 875, ("amoxil",)),
    _DrugEntry("amoxicillin-clavulanate", "mg", 250, 875, ("augmentin",)),
    _DrugEntry("azithromycin", "mg", 250, 500, ("zithromax", "z-pak")),
    _DrugEntry("ciprofloxacin", "mg", 250, 750, ("cipro",)),
    _DrugEntry("levofloxacin", "mg", 250, 750, ("levaquin",)),
    _DrugEntry("doxycycline", "mg", 50, 200),
    _DrugEntry("metronidazole", "mg", 250, 500, ("flagyl",)),
    _DrugEntry("clindamycin", "mg", 150, 450),
    _DrugEntry("trimethoprim-sulfamethoxazole", "mg", 80, 160, ("bactrim", "septra")),
    _DrugEntry("vancomycin", "mg", 125, 500),
    _DrugEntry("cephalexin", "mg", 250, 1000, ("keflex",)),
    _DrugEntry("nitrofurantoin", "mg", 50, 100, ("macrobid", "macrodantin")),
    # Antihypertensives
    _DrugEntry("lisinopril", "mg", 2.5, 40),
    _DrugEntry("amlodipine", "mg", 2.5, 10, ("norvasc",)),
    _DrugEntry("metoprolol", "mg", 25, 200, ("lopressor", "toprol")),
    _DrugEntry("atenolol", "mg", 25, 100),
    _DrugEntry("losartan", "mg", 25, 100, ("cozaar",)),
    _DrugEntry("valsartan", "mg", 80, 320, ("diovan",)),
    _DrugEntry("hydrochlorothiazide", "mg", 12.5, 50, ("hctz",)),
    _DrugEntry("furosemide", "mg", 20, 80, ("lasix",)),
    _DrugEntry("carvedilol", "mg", 3.125, 25, ("coreg",)),
    _DrugEntry("spironolactone", "mg", 25, 100, ("aldactone",)),
    _DrugEntry("clonidine", "mg", 0.1, 0.4, ("catapres",)),
    # Statins / lipid-lowering
    _DrugEntry("atorvastatin", "mg", 10, 80, ("lipitor",)),
    _DrugEntry("simvastatin", "mg", 5, 40, ("zocor",)),
    _DrugEntry("rosuvastatin", "mg", 5, 40, ("crestor",)),
    _DrugEntry("pravastatin", "mg", 10, 80, ("pravachol",)),
    _DrugEntry("lovastatin", "mg", 10, 80, ("mevacor",)),
    # Anticoagulants / antiplatelets
    _DrugEntry("warfarin", "mg", 1, 10, ("coumadin",)),
    _DrugEntry("apixaban", "mg", 2.5, 10, ("eliquis",)),
    _DrugEntry("rivaroxaban", "mg", 10, 20, ("xarelto",)),
    _DrugEntry("clopidogrel", "mg", 75, 300, ("plavix",)),
    _DrugEntry("heparin", "units", 5000, 10000),
    _DrugEntry("enoxaparin", "mg", 20, 150, ("lovenox",)),
    # Diabetes
    _DrugEntry("metformin", "mg", 500, 1000, ("glucophage",)),
    _DrugEntry("glipizide", "mg", 2.5, 20, ("glucotrol",)),
    _DrugEntry("glyburide", "mg", 1.25, 10, ("diabeta", "micronase")),
    _DrugEntry("sitagliptin", "mg", 25, 100, ("januvia",)),
    _DrugEntry("insulin glargine", "units", 10, 100, ("lantus", "basaglar")),
    _DrugEntry("insulin lispro", "units", 4, 60, ("humalog",)),
    _DrugEntry("insulin aspart", "units", 4, 60, ("novolog", "novorapid")),
    _DrugEntry("empagliflozin", "mg", 10, 25, ("jardiance",)),
    # Psychiatric / neurological
    _DrugEntry("sertraline", "mg", 25, 200, ("zoloft",)),
    _DrugEntry("fluoxetine", "mg", 10, 60, ("prozac",)),
    _DrugEntry("escitalopram", "mg", 5, 20, ("lexapro",)),
    _DrugEntry("citalopram", "mg", 10, 40, ("celexa",)),
    _DrugEntry("paroxetine", "mg", 10, 60, ("paxil",)),
    _DrugEntry("bupropion", "mg", 75, 300, ("wellbutrin", "zyban")),
    _DrugEntry("venlafaxine", "mg", 37.5, 225, ("effexor",)),
    _DrugEntry("duloxetine", "mg", 20, 120, ("cymbalta",)),
    _DrugEntry("amitriptyline", "mg", 10, 150),
    _DrugEntry("quetiapine", "mg", 25, 800, ("seroquel",)),
    _DrugEntry("risperidone", "mg", 0.5, 8, ("risperdal",)),
    _DrugEntry("olanzapine", "mg", 5, 20, ("zyprexa",)),
    _DrugEntry("aripiprazole", "mg", 2, 30, ("abilify",)),
    _DrugEntry("lithium", "mg", 150, 600, ("lithobid",)),
    _DrugEntry("valproate", "mg", 250, 1000, ("depakote", "valproic acid")),
    _DrugEntry("lamotrigine", "mg", 25, 200, ("lamictal",)),
    _DrugEntry("levetiracetam", "mg", 250, 1500, ("keppra",)),
    _DrugEntry("gabapentin", "mg", 100, 900, ("neurontin",)),
    _DrugEntry("pregabalin", "mg", 50, 300, ("lyrica",)),
    _DrugEntry("topiramate", "mg", 25, 200, ("topamax",)),
    _DrugEntry("clonazepam", "mg", 0.5, 2, ("klonopin",)),
    _DrugEntry("lorazepam", "mg", 0.5, 4, ("ativan",)),
    _DrugEntry("diazepam", "mg", 2, 10, ("valium",)),
    _DrugEntry("alprazolam", "mg", 0.25, 1, ("xanax",)),
    _DrugEntry("zolpidem", "mg", 5, 10, ("ambien",)),
    # Pulmonary
    _DrugEntry("albuterol", "mg", 2, 4, ("salbutamol", "proventil", "ventolin")),
    _DrugEntry("tiotropium", "mcg", 18, 18, ("spiriva",)),
    _DrugEntry("fluticasone", "mcg", 44, 500, ("flovent", "flonase")),
    _DrugEntry("budesonide", "mcg", 90, 720, ("pulmicort",)),
    _DrugEntry("montelukast", "mg", 4, 10, ("singulair",)),
    _DrugEntry("theophylline", "mg", 100, 400),
    # GI
    _DrugEntry("omeprazole", "mg", 20, 40, ("prilosec",)),
    _DrugEntry("pantoprazole", "mg", 20, 80, ("protonix",)),
    _DrugEntry("esomeprazole", "mg", 20, 40, ("nexium",)),
    _DrugEntry("ranitidine", "mg", 75, 300, ("zantac",)),
    _DrugEntry("famotidine", "mg", 20, 40, ("pepcid",)),
    _DrugEntry("ondansetron", "mg", 4, 16, ("zofran",)),
    _DrugEntry("metoclopramide", "mg", 5, 10, ("reglan",)),
    _DrugEntry("loperamide", "mg", 2, 4, ("imodium",)),
    # Immunosuppressants / oncology (narrow therapeutic index)
    _DrugEntry("methotrexate", "mg", 2.5, 25, ("rheumatrex",)),
    _DrugEntry("prednisone", "mg", 5, 60),
    _DrugEntry("methylprednisolone", "mg", 4, 125, ("medrol",)),
    _DrugEntry("dexamethasone", "mg", 0.5, 10),
    _DrugEntry("cyclosporine", "mg", 25, 400, ("sandimmune", "neoral")),
    _DrugEntry("tacrolimus", "mg", 0.5, 5, ("prograf",)),
    # Thyroid
    _DrugEntry("levothyroxine", "mcg", 12.5, 300, ("synthroid", "levoxyl")),
    # Vitamins / minerals (OTC, but hallucination risk high for pediatric dosing)
    _DrugEntry("vitamin d", "units", 400, 4000, ("cholecalciferol", "vitamin d3")),
    _DrugEntry("folic acid", "mg", 0.4, 5, ("folate",)),
    _DrugEntry("iron", "mg", 45, 325, ("ferrous sulfate", "ferrous gluconate")),
]

# Build lookup dict: normalised name → entry
_DB: dict[str, _DrugEntry] = {}
for _e in _DRUG_DB:
    _DB[_e.name] = _e
    for _alias in _e.aliases:
        _DB[_alias] = _e

# ── Regex patterns ────────────────────────────────────────────────────────────

# Matches "<drug> <number> <unit>" or "<number> <unit> of <drug>"
# Unit captures: mg, mcg, µg, μg, ug, units, unit, mEq, IU
_UNIT_PAT = r"(?P<val>[\d,]+(?:\.\d+)?)\s*(?P<unit>mg|mcg|µg|μg|ug|units?|IU|mEq)"

# Forward pattern: "<drug name> ... <val> <unit>"
_FWD_CLAIM = re.compile(
    r"(?P<drug>[a-zA-Z][a-zA-Z0-9\-/\s]{1,40}?)\s+" + _UNIT_PAT,
    re.IGNORECASE,
)

# Reverse pattern: "<val> <unit> of <drug name>"
_REV_CLAIM = re.compile(
    _UNIT_PAT + r"\s+(?:of\s+)?(?P<drug>[a-zA-Z][a-zA-Z0-9\-/\s]{1,40})",
    re.IGNORECASE,
)

_UNIT_NORMALISE = {
    "mcg": "mcg",
    "µg": "mcg",
    "μg": "mcg",
    "ug": "mcg",
    "mg": "mg",
    "unit": "units",
    "units": "units",
    "iu": "units",
    "meq": "mEq",
}


# ── Result types ──────────────────────────────────────────────────────────────


@dataclass
class DosageFinding:
    """A single dosage claim extracted from text.

    Attributes
    ----------
    drug:
        Normalised drug name matched in the reference database (or the raw
        extracted name if ``unknown_drug`` is True).
    raw_drug:
        The drug name as it appeared in the text.
    value:
        Numeric dose value extracted from text.
    unit:
        Normalised unit (``"mg"``, ``"mcg"``, ``"units"``, ``"mEq"``).
    min_ref:
        Reference minimum for this drug (0 when unknown).
    max_ref:
        Reference maximum for this drug (0 when unknown).
    is_violation:
        True when the value falls outside [min_ref, max_ref].
    unknown_drug:
        True when the drug was not found in the reference database.
    context_snippet:
        Short surrounding text excerpt (up to 80 chars).
    """

    drug: str
    raw_drug: str
    value: float
    unit: str
    min_ref: float
    max_ref: float
    is_violation: bool
    unknown_drug: bool
    context_snippet: str = ""

    def summary(self) -> str:
        if self.unknown_drug:
            return f"{self.raw_drug!r}: {self.value} {self.unit} (drug not in reference database)"
        direction = "exceeds max" if self.value > self.max_ref else "below min"
        return (
            f"{self.drug}: {self.value} {self.unit} {direction} "
            f"({self.min_ref}–{self.max_ref} {self.unit})"
        )


@dataclass
class DosageScanResult:
    """Aggregated result of a :meth:`DosageHallucinationDetector.scan` call.

    Attributes
    ----------
    findings:
        All dosage claims extracted (violations and clean claims).
    violations:
        Subset of ``findings`` where ``is_violation`` is True (and optionally
        ``unknown_drug`` findings when ``strict=True``).
    scanned_chars:
        Length of the input text.
    """

    findings: list[DosageFinding] = field(default_factory=list)
    violations: list[DosageFinding] = field(default_factory=list)
    scanned_chars: int = 0

    @property
    def has_violations(self) -> bool:
        return bool(self.violations)

    @property
    def violation_count(self) -> int:
        return len(self.violations)

    def to_dict(self) -> dict[str, object]:
        return {
            "has_violations": self.has_violations,
            "violation_count": self.violation_count,
            "scanned_chars": self.scanned_chars,
            "findings": [
                {
                    "drug": f.drug,
                    "raw_drug": f.raw_drug,
                    "value": f.value,
                    "unit": f.unit,
                    "min_ref": f.min_ref,
                    "max_ref": f.max_ref,
                    "is_violation": f.is_violation,
                    "unknown_drug": f.unknown_drug,
                    "context_snippet": f.context_snippet,
                }
                for f in self.findings
            ],
        }


# ── Detector ──────────────────────────────────────────────────────────────────


class DosageHallucinationDetector:
    """Detects numeric drug dosage claims that fall outside clinically plausible ranges.

    All operations are stateless and thread-safe after construction.  The
    reference database covers ~100 common drugs across 12 therapeutic classes.

    Parameters
    ----------
    strict:
        When True, drug names not in the reference database are also added
        to ``violations``.  Defaults to the ``AEGIS_DOSAGE_STRICT`` env var
        (False when unset).
    extra_db:
        Additional drug entries to merge into the reference database.
        Useful for institution-specific formularies.
    """

    def __init__(
        self,
        strict: bool | None = None,
        extra_db: list[_DrugEntry] | None = None,
    ) -> None:
        if strict is None:
            strict = bool(os.environ.get("AEGIS_DOSAGE_STRICT"))
        self.strict = strict

        self._db: dict[str, _DrugEntry] = dict(_DB)
        if extra_db:
            for entry in extra_db:
                self._db[entry.name] = entry
                for alias in entry.aliases:
                    self._db[alias] = entry

    # ── Public API ────────────────────────────────────────────────────────────

    def scan(self, text: str) -> DosageScanResult:
        """Scan *text* for dosage hallucinations.

        Parameters
        ----------
        text:
            Raw LLM response text to scan.

        Returns
        -------
        DosageScanResult
        """
        result = DosageScanResult(scanned_chars=len(text))
        seen: set[tuple[str, float, str]] = set()

        for match in _FWD_CLAIM.finditer(text):
            self._process_match(
                match.group("drug"),
                match.group("val"),
                match.group("unit"),
                text,
                match.start(),
                result,
                seen,
            )

        for match in _REV_CLAIM.finditer(text):
            self._process_match(
                match.group("drug"),
                match.group("val"),
                match.group("unit"),
                text,
                match.start(),
                result,
                seen,
            )

        return result

    def scan_messages(self, messages: list[dict[str, str]]) -> DosageScanResult:
        """Scan a list of OpenAI-style message dicts (``{"role": ..., "content": ...}``).

        Only ``assistant`` role messages are scanned, since those contain
        model-generated content that may include dosage hallucinations.
        """
        combined = "\n".join(m.get("content", "") for m in messages if m.get("role") == "assistant")
        return self.scan(combined)

    def drug_entry(self, drug_name: str) -> _DrugEntry | None:
        """Return the reference entry for *drug_name*, or None if unknown."""
        return self._db.get(drug_name.lower().strip())

    # ── Internal ──────────────────────────────────────────────────────────────

    def _process_match(
        self,
        raw_drug: str,
        raw_val: str,
        raw_unit: str,
        text: str,
        pos: int,
        result: DosageScanResult,
        seen: set[tuple[str, float, str]],
    ) -> None:
        drug_norm = raw_drug.strip().lower()
        try:
            value = float(raw_val.replace(",", ""))
        except ValueError:
            return
        unit_norm = _UNIT_NORMALISE.get(raw_unit.lower(), raw_unit.lower())

        snippet = text[max(0, pos - 20) : pos + 60].replace("\n", " ")

        entry = self._lookup(drug_norm)
        # Dedup on canonical drug name so suffix-resolved matches don't double-count
        canonical = entry.name if entry is not None else drug_norm
        dedup_key = (canonical, value, unit_norm)
        if dedup_key in seen:
            return
        seen.add(dedup_key)
        if entry is None:
            finding = DosageFinding(
                drug=drug_norm,
                raw_drug=raw_drug.strip(),
                value=value,
                unit=unit_norm,
                min_ref=0.0,
                max_ref=0.0,
                is_violation=False,
                unknown_drug=True,
                context_snippet=snippet,
            )
            result.findings.append(finding)
            if self.strict:
                finding.is_violation = True
                result.violations.append(finding)
            return

        # Unit mismatch: skip comparison (can't compare mg to mcg meaningfully)
        if entry.unit != unit_norm:
            return

        is_violation = value < entry.min_val or value > entry.max_val
        finding = DosageFinding(
            drug=entry.name,
            raw_drug=raw_drug.strip(),
            value=value,
            unit=unit_norm,
            min_ref=entry.min_val,
            max_ref=entry.max_val,
            is_violation=is_violation,
            unknown_drug=False,
            context_snippet=snippet,
        )
        result.findings.append(finding)
        if is_violation:
            result.violations.append(finding)
            logger.warning("dosage_hallucination: potential hallucination — %s", finding.summary())

    def _lookup(self, drug_norm: str) -> _DrugEntry | None:
        """Multi-word fuzzy lookup: try full name, then word subsets."""
        if drug_norm in self._db:
            return self._db[drug_norm]
        # Try progressively longer suffix substrings (handles "take ibuprofen")
        words = drug_norm.split()
        for start in range(len(words)):
            candidate = " ".join(words[start:])
            if candidate in self._db:
                return self._db[candidate]
        return None


# ── Module-level singleton ────────────────────────────────────────────────────

_detector = DosageHallucinationDetector()


def scan_for_dosage_hallucinations(text: str, strict: bool = False) -> DosageScanResult:
    """Scan *text* for drug dosage hallucinations.

    Convenience wrapper around :class:`DosageHallucinationDetector`.
    Creates a one-shot detector; for repeated calls prefer reusing a
    :class:`DosageHallucinationDetector` instance.
    """
    d = _detector if not strict else DosageHallucinationDetector(strict=True)
    return d.scan(text)

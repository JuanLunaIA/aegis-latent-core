# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.atlas_tactic_mapper — MITRE ATLAS tactic mapping for WAF hits.

Maps WAF hit categories to MITRE ATLAS (Adversarial Threat Landscape for AI
Systems) tactic and technique identifiers.  MITRE ATLAS is the AI-systems
analogue to ATT&CK; this module provides a taxonomy layer so that audit logs
and SOC dashboards can express WAF detections in a standardised threat
intelligence vocabulary.

ATLAS tactic taxonomy used
--------------------------
::

    AML.TA0004  ML Attack Staging
    AML.TA0009  Exfiltration
    AML.TA0015  Defense Evasion
    AML.TA0034  Impact

Technique IDs follow the official MITRE ATLAS v3 numbering.  The module
exposes a stable :data:`ATLAS_TECHNIQUES` registry and a
:class:`ATLASTacticMapper` that accepts a WAF hit category string and returns
one or more annotated :class:`ATLASTechnique` objects.

Usage::

    mapper = ATLASTacticMapper()
    techniques = mapper.map("prompt_injection")
    for t in techniques:
        print(t.technique_id, t.name, t.tactic)

    # Enrich a WAF audit record
    enriched = mapper.enrich_waf_result(
        hit_category="jailbreak",
        reason="DAN-mode detected",
    )
    # enriched.techniques → list[ATLASTechnique]
    # enriched.to_dict()  → JSON-serializable dict
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ATLASTechnique:
    """A single MITRE ATLAS technique entry.

    Attributes
    ----------
    technique_id:
        Official MITRE ATLAS technique identifier (e.g. ``AML.T0051``).
    name:
        Human-readable technique name.
    tactic_id:
        Parent tactic identifier (e.g. ``AML.TA0004``).
    tactic:
        Human-readable tactic name.
    description:
        Brief description of the technique as it applies to this mapping.
    subtechnique_of:
        Parent technique ID when this is a sub-technique, else ``None``.
    """

    technique_id: str
    name: str
    tactic_id: str
    tactic: str
    description: str
    subtechnique_of: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "technique_id": self.technique_id,
            "name": self.name,
            "tactic_id": self.tactic_id,
            "tactic": self.tactic,
            "description": self.description,
            "subtechnique_of": self.subtechnique_of,
        }


@dataclass
class ATLASEnrichedHit:
    """WAF hit enriched with MITRE ATLAS taxonomy.

    Attributes
    ----------
    hit_category:
        The WAF hit category (e.g. ``"prompt_injection"``).
    original_reason:
        The human-readable reason string from the WAF.
    techniques:
        Mapped MITRE ATLAS techniques.
    tactic_ids:
        Unique tactic IDs across all mapped techniques.
    """

    hit_category: str
    original_reason: str = ""
    techniques: list[ATLASTechnique] = field(default_factory=list)

    @property
    def tactic_ids(self) -> list[str]:
        """Deduplicated tactic IDs, order of first occurrence."""
        seen: set[str] = set()
        result: list[str] = []
        for t in self.techniques:
            if t.tactic_id not in seen:
                seen.add(t.tactic_id)
                result.append(t.tactic_id)
        return result

    def to_dict(self) -> dict[str, object]:
        return {
            "hit_category": self.hit_category,
            "original_reason": self.original_reason,
            "techniques": [t.to_dict() for t in self.techniques],
            "tactic_ids": self.tactic_ids,
        }


# ── MITRE ATLAS technique registry ────────────────────────────────────────────
# Source: MITRE ATLAS v3 (atlas.mitre.org)

ATLAS_TECHNIQUES: dict[str, ATLASTechnique] = {
    "AML.T0051": ATLASTechnique(
        technique_id="AML.T0051",
        name="LLM Prompt Injection",
        tactic_id="AML.TA0004",
        tactic="ML Attack Staging",
        description=(
            "Adversary crafts prompts to override model instructions, "
            "alter behaviour, or make the model ignore its system prompt."
        ),
    ),
    "AML.T0051.000": ATLASTechnique(
        technique_id="AML.T0051.000",
        name="LLM Prompt Injection - Direct",
        tactic_id="AML.TA0004",
        tactic="ML Attack Staging",
        description=(
            "Adversary directly injects instructions into the user turn "
            "of an LLM conversation to override system-prompt directives."
        ),
        subtechnique_of="AML.T0051",
    ),
    "AML.T0051.001": ATLASTechnique(
        technique_id="AML.T0051.001",
        name="LLM Prompt Injection - Indirect",
        tactic_id="AML.TA0004",
        tactic="ML Attack Staging",
        description=(
            "Adversary embeds instructions in retrieved documents, tool "
            "outputs, or other indirect input sources consumed by the LLM."
        ),
        subtechnique_of="AML.T0051",
    ),
    "AML.T0054": ATLASTechnique(
        technique_id="AML.T0054",
        name="LLM Jailbreak",
        tactic_id="AML.TA0004",
        tactic="ML Attack Staging",
        description=(
            "Adversary uses role-playing, DAN-mode, hypothetical framing, "
            "or many-shot examples to bypass LLM safety guardrails."
        ),
    ),
    "AML.T0054.000": ATLASTechnique(
        technique_id="AML.T0054.000",
        name="LLM Jailbreak - Many-Shot",
        tactic_id="AML.TA0004",
        tactic="ML Attack Staging",
        description=(
            "Adversary embeds many in-context demonstrations of harmful "
            "behaviour to override safety training via in-context learning."
        ),
        subtechnique_of="AML.T0054",
    ),
    "AML.T0056": ATLASTechnique(
        technique_id="AML.T0056",
        name="LLM Data Leakage",
        tactic_id="AML.TA0009",
        tactic="Exfiltration",
        description=(
            "Adversary elicits sensitive data — system prompts, training "
            "data, or confidential context — from an LLM's responses."
        ),
    ),
    "AML.T0056.000": ATLASTechnique(
        technique_id="AML.T0056.000",
        name="LLM Meta-Prompt Extraction",
        tactic_id="AML.TA0009",
        tactic="Exfiltration",
        description=(
            "Adversary instructs the LLM to repeat, summarise, or translate "
            "its system prompt or hidden instructions."
        ),
        subtechnique_of="AML.T0056",
    ),
    "AML.T0047": ATLASTechnique(
        technique_id="AML.T0047",
        name="ML Attack Obfuscation",
        tactic_id="AML.TA0015",
        tactic="Defense Evasion",
        description=(
            "Adversary uses encoding (Base64, URL-encoding, homoglyphs, "
            "zero-width characters) to evade pattern-matching defences."
        ),
    ),
    "AML.T0048": ATLASTechnique(
        technique_id="AML.T0048",
        name="Erode ML Model Integrity",
        tactic_id="AML.TA0034",
        tactic="Impact",
        description=(
            "Adversary alters model outputs through crafted inputs to "
            "produce harmful, biased, or misleading responses."
        ),
    ),
    "AML.T0048.002": ATLASTechnique(
        technique_id="AML.T0048.002",
        name="Denial of ML Service",
        tactic_id="AML.TA0034",
        tactic="Impact",
        description=(
            "Adversary crafts inputs that consume excessive compute "
            "(e.g., deeply nested JSON, pathological regex input) to "
            "degrade or deny service."
        ),
        subtechnique_of="AML.T0048",
    ),
    "AML.T0043": ATLASTechnique(
        technique_id="AML.T0043",
        name="Craft Adversarial Data",
        tactic_id="AML.TA0004",
        tactic="ML Attack Staging",
        description=(
            "Adversary crafts input data specifically designed to cause "
            "misclassification or unexpected LLM behaviour."
        ),
    ),
}

# ── WAF category → ATLAS technique mapping ────────────────────────────────────
# Keys are canonical WAF hit category strings (lowercase, underscore-separated).
# Values are lists of technique IDs to associate with that hit category.

_CATEGORY_TO_TECHNIQUES: dict[str, list[str]] = {
    # Direct prompt injection (overriding system instructions)
    "prompt_injection": ["AML.T0051", "AML.T0051.000"],
    "system_prompt_override": ["AML.T0051", "AML.T0051.000"],
    "template_injection": ["AML.T0051", "AML.T0051.000"],
    "act_as_persona": ["AML.T0051", "AML.T0051.000"],
    # Jailbreak variants
    "jailbreak": ["AML.T0054"],
    "dan_mode": ["AML.T0054"],
    "roleplay_jailbreak": ["AML.T0054"],
    "many_shot_jailbreak": ["AML.T0054", "AML.T0054.000"],
    # System prompt exfiltration
    "system_prompt_exfiltration": ["AML.T0056", "AML.T0056.000"],
    "meta_prompt_extraction": ["AML.T0056.000"],
    # Encoding-based evasion
    "encoding_evasion": ["AML.T0047"],
    "base64_evasion": ["AML.T0047"],
    "url_encoding_evasion": ["AML.T0047"],
    "homoglyph_evasion": ["AML.T0047"],
    "zero_width_injection": ["AML.T0047"],
    # Adversarial crafting
    "adversarial_input": ["AML.T0043"],
    "classified_marker": ["AML.T0043"],
    # Denial of service
    "payload_too_deep": ["AML.T0048.002"],
    "dos_attempt": ["AML.T0048.002"],
    # Generic / multi-technique
    "critical_pattern": ["AML.T0051", "AML.T0054"],
    "soft_pattern": ["AML.T0051", "AML.T0043"],
    "layer1_block": ["AML.T0051", "AML.T0054"],
    "layer2_block": ["AML.T0051", "AML.T0043"],
    "session_escalation": ["AML.T0054", "AML.T0043"],
}


class ATLASTacticMapper:
    """Maps WAF hit categories to MITRE ATLAS tactic/technique objects.

    Parameters
    ----------
    extra_mappings:
        Additional ``{category: [technique_id, ...]}`` entries to supplement
        the built-in mapping.
    extra_techniques:
        Additional :class:`ATLASTechnique` objects to add to the registry.
        Required when ``extra_mappings`` references technique IDs not in
        :data:`ATLAS_TECHNIQUES`.
    """

    def __init__(
        self,
        extra_mappings: dict[str, list[str]] | None = None,
        extra_techniques: list[ATLASTechnique] | None = None,
    ) -> None:
        self._techniques: dict[str, ATLASTechnique] = dict(ATLAS_TECHNIQUES)
        if extra_techniques:
            for t in extra_techniques:
                self._techniques[t.technique_id] = t

        self._mapping: dict[str, list[str]] = dict(_CATEGORY_TO_TECHNIQUES)
        if extra_mappings:
            for cat, ids in extra_mappings.items():
                self._mapping[cat.lower()] = ids

    @property
    def known_categories(self) -> list[str]:
        """Sorted list of all known WAF hit categories."""
        return sorted(self._mapping)

    @property
    def known_technique_ids(self) -> list[str]:
        """Sorted list of all registered technique IDs."""
        return sorted(self._techniques)

    # ── Public API ─────────────────────────────────────────────────────────────

    def map(self, hit_category: str) -> list[ATLASTechnique]:
        """Return ATLAS techniques for a WAF *hit_category*.

        Category matching is case-insensitive and normalises spaces/hyphens
        to underscores.

        Returns an empty list if the category is not in the mapping.
        """
        key = self._normalise(hit_category)
        technique_ids = self._mapping.get(key, [])
        return [self._techniques[tid] for tid in technique_ids if tid in self._techniques]

    def enrich_waf_result(
        self,
        hit_category: str,
        reason: str = "",
    ) -> ATLASEnrichedHit:
        """Produce an enriched WAF hit record with ATLAS taxonomy.

        Parameters
        ----------
        hit_category:
            WAF hit category string (case-insensitive).
        reason:
            Original WAF reason string for audit log correlation.
        """
        techniques = self.map(hit_category)
        return ATLASEnrichedHit(
            hit_category=hit_category,
            original_reason=reason,
            techniques=techniques,
        )

    def tactic_summary(self, hit_category: str) -> dict[str, list[str]]:
        """Return a tactic → [technique_id, ...] summary for *hit_category*.

        Useful for structured logging / SIEM ingestion.
        """
        techniques = self.map(hit_category)
        summary: dict[str, list[str]] = {}
        for t in techniques:
            summary.setdefault(t.tactic, []).append(t.technique_id)
        return summary

    # ── Internal ───────────────────────────────────────────────────────────────

    @staticmethod
    def _normalise(category: str) -> str:
        """Lower-case and replace spaces/hyphens with underscores."""
        return category.lower().replace(" ", "_").replace("-", "_")

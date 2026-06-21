# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for MITRE ATLAS tactic mapping (aegis.core.atlas_tactic_mapper)."""

from __future__ import annotations

import json

from aegis.core.atlas_tactic_mapper import (
    ATLAS_TECHNIQUES,
    ATLASEnrichedHit,
    ATLASTacticMapper,
    ATLASTechnique,
)

# ── ATLASTechnique ─────────────────────────────────────────────────────────────


class TestATLASTechnique:
    def test_fields_accessible(self):
        t = ATLAS_TECHNIQUES["AML.T0051"]
        assert t.technique_id == "AML.T0051"
        assert t.tactic_id == "AML.TA0004"
        assert t.name
        assert t.tactic
        assert t.description

    def test_subtechnique_has_parent(self):
        t = ATLAS_TECHNIQUES["AML.T0051.000"]
        assert t.subtechnique_of == "AML.T0051"

    def test_root_technique_no_parent(self):
        t = ATLAS_TECHNIQUES["AML.T0051"]
        assert t.subtechnique_of is None

    def test_to_dict_structure(self):
        t = ATLAS_TECHNIQUES["AML.T0054"]
        d = t.to_dict()
        assert d["technique_id"] == "AML.T0054"
        assert "name" in d
        assert "tactic_id" in d
        assert "tactic" in d
        assert "description" in d
        assert "subtechnique_of" in d

    def test_to_dict_json_serializable(self):
        t = ATLAS_TECHNIQUES["AML.T0047"]
        json.dumps(t.to_dict())

    def test_frozen_immutable(self):
        t = ATLAS_TECHNIQUES["AML.T0051"]
        try:
            t.name = "new name"  # type: ignore[misc]
            raise AssertionError("should have raised on frozen dataclass")
        except (AttributeError, TypeError):
            pass  # frozen dataclass raises on assignment


# ── ATLAS_TECHNIQUES registry ──────────────────────────────────────────────────


class TestATLASTechniquesRegistry:
    def test_registry_not_empty(self):
        assert len(ATLAS_TECHNIQUES) > 0

    def test_all_ids_start_with_aml(self):
        for tid in ATLAS_TECHNIQUES:
            assert tid.startswith("AML.T"), f"{tid} does not start with AML.T"

    def test_subtechnique_parent_exists(self):
        for tid, t in ATLAS_TECHNIQUES.items():
            if t.subtechnique_of:
                assert t.subtechnique_of in ATLAS_TECHNIQUES, (
                    f"{tid}.subtechnique_of={t.subtechnique_of!r} not in registry"
                )

    def test_required_techniques_present(self):
        required = [
            "AML.T0051",
            "AML.T0051.000",
            "AML.T0051.001",
            "AML.T0054",
            "AML.T0054.000",
            "AML.T0056",
            "AML.T0056.000",
            "AML.T0047",
            "AML.T0048",
            "AML.T0048.002",
        ]
        for tid in required:
            assert tid in ATLAS_TECHNIQUES, f"{tid} missing from registry"


# ── ATLASEnrichedHit ───────────────────────────────────────────────────────────


class TestATLASEnrichedHit:
    def test_defaults(self):
        h = ATLASEnrichedHit(hit_category="jailbreak")
        assert h.original_reason == ""
        assert h.techniques == []
        assert h.tactic_ids == []

    def test_tactic_ids_deduplicated(self):
        t1 = ATLAS_TECHNIQUES["AML.T0051"]
        t2 = ATLAS_TECHNIQUES["AML.T0051.000"]
        h = ATLASEnrichedHit(
            hit_category="prompt_injection",
            techniques=[t1, t2],
        )
        assert h.tactic_ids == ["AML.TA0004"]

    def test_tactic_ids_multiple_tactics(self):
        t1 = ATLAS_TECHNIQUES["AML.T0051"]
        t2 = ATLAS_TECHNIQUES["AML.T0056"]
        h = ATLASEnrichedHit(
            hit_category="exfil_injection",
            techniques=[t1, t2],
        )
        tids = h.tactic_ids
        assert "AML.TA0004" in tids
        assert "AML.TA0009" in tids

    def test_to_dict_structure(self):
        t = ATLAS_TECHNIQUES["AML.T0054"]
        h = ATLASEnrichedHit(
            hit_category="jailbreak",
            original_reason="DAN mode detected",
            techniques=[t],
        )
        d = h.to_dict()
        assert d["hit_category"] == "jailbreak"
        assert d["original_reason"] == "DAN mode detected"
        assert len(d["techniques"]) == 1
        assert "tactic_ids" in d

    def test_to_dict_json_serializable(self):
        t = ATLAS_TECHNIQUES["AML.T0047"]
        h = ATLASEnrichedHit(hit_category="encoding_evasion", techniques=[t])
        json.dumps(h.to_dict())


# ── ATLASTacticMapper constructor ──────────────────────────────────────────────


class TestConstructor:
    def test_known_categories_not_empty(self):
        mapper = ATLASTacticMapper()
        assert len(mapper.known_categories) > 0

    def test_known_technique_ids_not_empty(self):
        mapper = ATLASTacticMapper()
        assert len(mapper.known_technique_ids) > 0

    def test_extra_mappings_added(self):
        mapper = ATLASTacticMapper(extra_mappings={"custom_attack": ["AML.T0051"]})
        assert "custom_attack" in mapper.known_categories

    def test_extra_techniques_added(self):
        extra = ATLASTechnique(
            technique_id="AML.T9999",
            name="Test Technique",
            tactic_id="AML.TA0004",
            tactic="ML Attack Staging",
            description="Test only",
        )
        mapper = ATLASTacticMapper(extra_techniques=[extra])
        assert "AML.T9999" in mapper.known_technique_ids

    def test_extra_technique_reachable(self):
        extra = ATLASTechnique(
            technique_id="AML.T9998",
            name="Custom Tech",
            tactic_id="AML.TA0034",
            tactic="Impact",
            description="Custom",
        )
        mapper = ATLASTacticMapper(
            extra_mappings={"my_category": ["AML.T9998"]},
            extra_techniques=[extra],
        )
        results = mapper.map("my_category")
        assert len(results) == 1
        assert results[0].technique_id == "AML.T9998"


# ── map() ──────────────────────────────────────────────────────────────────────


class TestMap:
    def test_prompt_injection_maps(self):
        mapper = ATLASTacticMapper()
        results = mapper.map("prompt_injection")
        ids = [t.technique_id for t in results]
        assert "AML.T0051" in ids

    def test_jailbreak_maps(self):
        mapper = ATLASTacticMapper()
        results = mapper.map("jailbreak")
        ids = [t.technique_id for t in results]
        assert "AML.T0054" in ids

    def test_many_shot_maps(self):
        mapper = ATLASTacticMapper()
        results = mapper.map("many_shot_jailbreak")
        ids = [t.technique_id for t in results]
        assert "AML.T0054.000" in ids

    def test_encoding_evasion_maps(self):
        mapper = ATLASTacticMapper()
        results = mapper.map("encoding_evasion")
        ids = [t.technique_id for t in results]
        assert "AML.T0047" in ids

    def test_payload_too_deep_maps(self):
        mapper = ATLASTacticMapper()
        results = mapper.map("payload_too_deep")
        ids = [t.technique_id for t in results]
        assert "AML.T0048.002" in ids

    def test_system_prompt_exfiltration_maps(self):
        mapper = ATLASTacticMapper()
        results = mapper.map("system_prompt_exfiltration")
        ids = [t.technique_id for t in results]
        assert "AML.T0056" in ids

    def test_unknown_category_returns_empty(self):
        mapper = ATLASTacticMapper()
        assert mapper.map("unknown_xyz_attack") == []

    def test_empty_category_returns_empty(self):
        mapper = ATLASTacticMapper()
        assert mapper.map("") == []

    def test_case_insensitive(self):
        mapper = ATLASTacticMapper()
        lower = mapper.map("jailbreak")
        upper = mapper.map("JAILBREAK")
        assert lower == upper

    def test_hyphen_normalised_to_underscore(self):
        mapper = ATLASTacticMapper()
        with_hyphen = mapper.map("prompt-injection")
        with_under = mapper.map("prompt_injection")
        assert with_hyphen == with_under

    def test_space_normalised_to_underscore(self):
        mapper = ATLASTacticMapper()
        with_space = mapper.map("prompt injection")
        with_under = mapper.map("prompt_injection")
        assert with_space == with_under

    def test_returns_list_of_technique_objects(self):
        mapper = ATLASTacticMapper()
        results = mapper.map("jailbreak")
        for r in results:
            assert isinstance(r, ATLASTechnique)


# ── enrich_waf_result() ────────────────────────────────────────────────────────


class TestEnrichWafResult:
    def test_returns_enriched_hit(self):
        mapper = ATLASTacticMapper()
        h = mapper.enrich_waf_result("jailbreak", "DAN mode detected")
        assert isinstance(h, ATLASEnrichedHit)

    def test_hit_category_preserved(self):
        mapper = ATLASTacticMapper()
        h = mapper.enrich_waf_result("encoding_evasion")
        assert h.hit_category == "encoding_evasion"

    def test_reason_preserved(self):
        mapper = ATLASTacticMapper()
        h = mapper.enrich_waf_result("jailbreak", "Layer-1 critical pattern")
        assert h.original_reason == "Layer-1 critical pattern"

    def test_techniques_populated(self):
        mapper = ATLASTacticMapper()
        h = mapper.enrich_waf_result("prompt_injection")
        assert len(h.techniques) > 0

    def test_empty_reason_allowed(self):
        mapper = ATLASTacticMapper()
        h = mapper.enrich_waf_result("jailbreak")
        assert h.original_reason == ""

    def test_unknown_category_empty_techniques(self):
        mapper = ATLASTacticMapper()
        h = mapper.enrich_waf_result("totally_unknown_xyz")
        assert h.techniques == []


# ── tactic_summary() ──────────────────────────────────────────────────────────


class TestTacticSummary:
    def test_returns_dict(self):
        mapper = ATLASTacticMapper()
        s = mapper.tactic_summary("jailbreak")
        assert isinstance(s, dict)

    def test_tactic_names_as_keys(self):
        mapper = ATLASTacticMapper()
        s = mapper.tactic_summary("prompt_injection")
        assert "ML Attack Staging" in s

    def test_technique_ids_as_values(self):
        mapper = ATLASTacticMapper()
        s = mapper.tactic_summary("jailbreak")
        for _tactic, ids in s.items():
            assert isinstance(ids, list)
            for tid in ids:
                assert tid.startswith("AML.T")

    def test_unknown_category_empty_summary(self):
        mapper = ATLASTacticMapper()
        assert mapper.tactic_summary("unknown") == {}

    def test_exfiltration_tactic_in_summary(self):
        mapper = ATLASTacticMapper()
        s = mapper.tactic_summary("system_prompt_exfiltration")
        assert "Exfiltration" in s

    def test_defense_evasion_tactic_in_summary(self):
        mapper = ATLASTacticMapper()
        s = mapper.tactic_summary("encoding_evasion")
        assert "Defense Evasion" in s


# ── Integration scenarios ──────────────────────────────────────────────────────


class TestIntegrationScenarios:
    def test_waf_hit_enrich_pipeline(self):
        """Simulate enriching a WAF block in the audit pipeline."""
        mapper = ATLASTacticMapper()
        waf_hits = [
            ("layer1_block", "Critical pattern: jailbreak instruction"),
            ("encoding_evasion", "Base64 obfuscation detected"),
            ("many_shot_jailbreak", "12 Q&A examples exceeded threshold"),
        ]
        enriched = [mapper.enrich_waf_result(cat, reason) for cat, reason in waf_hits]
        assert all(len(h.techniques) > 0 for h in enriched)
        assert all(isinstance(h.to_dict(), dict) for h in enriched)

    def test_all_mapped_categories_resolve(self):
        """Every built-in category must resolve to at least one technique."""
        mapper = ATLASTacticMapper()
        for cat in mapper.known_categories:
            techniques = mapper.map(cat)
            assert len(techniques) > 0, f"Category {cat!r} resolved to no techniques"

    def test_to_dict_full_pipeline(self):
        """End-to-end: enrich and serialise to dict."""
        mapper = ATLASTacticMapper()
        h = mapper.enrich_waf_result("prompt_injection", "System override detected")
        d = h.to_dict()
        json.dumps(d)
        assert d["hit_category"] == "prompt_injection"
        assert len(d["techniques"]) > 0
        assert len(d["tactic_ids"]) > 0

    def test_dos_tactic_maps_to_impact(self):
        mapper = ATLASTacticMapper()
        h = mapper.enrich_waf_result("payload_too_deep")
        tactic_ids = h.tactic_ids
        assert "AML.TA0034" in tactic_ids

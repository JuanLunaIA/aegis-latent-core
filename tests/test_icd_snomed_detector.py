# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.icd_snomed_detector."""

from __future__ import annotations

from aegis.core.icd_snomed_detector import (
    _ICD10_CHAPTER,
    _ICD11_CHAPTER,
    _KEYWORD_DOMAIN,
    ClinicalCodeFinding,
    ICDSNOMEDDetector,
    ICDSNOMEDResult,
)

# ── Chapter map sanity ────────────────────────────────────────────────────────


class TestICD10Chapter:
    def test_all_expected_letters_present(self):
        expected = set("ABCDEFGHIJKLMNOPQRSTVWXYZ")
        assert expected == set(_ICD10_CHAPTER.keys())

    def test_letter_u_not_present(self):
        assert "U" not in _ICD10_CHAPTER

    def test_sample_mappings(self):
        assert _ICD10_CHAPTER["A"] == "Infectious/Parasitic"
        assert _ICD10_CHAPTER["C"] == "Neoplasms"
        assert _ICD10_CHAPTER["E"] == "Endocrine/Metabolic"
        assert _ICD10_CHAPTER["F"] == "Mental/Behavioral"
        assert _ICD10_CHAPTER["J"] == "Respiratory"
        assert _ICD10_CHAPTER["Z"] == "Health Status Factors"

    def test_external_causes(self):
        for letter in "VWXY":
            assert _ICD10_CHAPTER[letter] == "External Causes"


class TestICD11Chapter:
    def test_has_entries(self):
        assert len(_ICD11_CHAPTER) > 20

    def test_sample_mappings(self):
        assert _ICD11_CHAPTER["1"] == "Infectious/Parasitic"
        assert _ICD11_CHAPTER["2"] == "Neoplasms"
        assert _ICD11_CHAPTER["5"] == "Endocrine/Metabolic"
        assert _ICD11_CHAPTER["6"] == "Mental/Behavioral"
        assert _ICD11_CHAPTER["C"] == "Respiratory"
        assert _ICD11_CHAPTER["B"] == "Circulatory"
        assert _ICD11_CHAPTER["G"] == "Genitourinary"

    def test_numeric_keys_are_strings(self):
        for key in _ICD11_CHAPTER:
            assert isinstance(key, str)
            assert len(key) == 1


# ── ClinicalCodeFinding ───────────────────────────────────────────────────────


class TestClinicalCodeFinding:
    def test_to_dict(self):
        f = ClinicalCodeFinding(code_type="icd10", code="J18.9", position=10, domain="Respiratory")
        d = f.to_dict()
        assert d["code_type"] == "icd10"
        assert d["code"] == "J18.9"
        assert d["position"] == 10
        assert d["domain"] == "Respiratory"

    def test_to_dict_keys(self):
        f = ClinicalCodeFinding(code_type="snomed", code="73211009", position=0, domain="SNOMED-CT")
        assert set(f.to_dict().keys()) == {"code_type", "code", "position", "domain"}


# ── ICDSNOMEDResult ───────────────────────────────────────────────────────────


class TestICDSNOMEDResult:
    def test_defaults(self):
        r = ICDSNOMEDResult()
        assert r.request_codes == []
        assert r.response_codes == []
        assert r.request_domains == set()
        assert r.response_domains == set()
        assert r.mismatch_detected is False
        assert r.mismatch_domains == []

    def test_to_dict_keys(self):
        r = ICDSNOMEDResult()
        d = r.to_dict()
        assert "mismatch_detected" in d
        assert "mismatch_domains" in d
        assert "request_domains" in d
        assert "response_domains" in d
        assert "request_code_count" in d
        assert "response_code_count" in d
        assert "request_codes" in d
        assert "response_codes" in d

    def test_to_dict_sorted_domains(self):
        r = ICDSNOMEDResult()
        r.request_domains = {"Respiratory", "Circulatory"}
        d = r.to_dict()
        assert d["request_domains"] == sorted(["Respiratory", "Circulatory"])

    def test_to_dict_code_counts(self):
        r = ICDSNOMEDResult()
        r.request_codes = [
            ClinicalCodeFinding("icd10", "J18.9", 0, "Respiratory"),
        ]
        r.response_codes = [
            ClinicalCodeFinding("icd10", "F32.0", 0, "Mental/Behavioral"),
            ClinicalCodeFinding("icd11", "CA40.0", 5, "Respiratory"),
        ]
        d = r.to_dict()
        assert d["request_code_count"] == 1
        assert d["response_code_count"] == 2
        assert len(d["request_codes"]) == 1
        assert len(d["response_codes"]) == 2


# ── ICDSNOMEDDetector construction ───────────────────────────────────────────


class TestDetectorConstruction:
    def test_default_strict_false(self):
        d = ICDSNOMEDDetector()
        assert d.strict is False

    def test_explicit_strict_true(self):
        d = ICDSNOMEDDetector(strict=True)
        assert d.strict is True

    def test_explicit_strict_false(self):
        d = ICDSNOMEDDetector(strict=False)
        assert d.strict is False

    def test_env_strict_true(self, monkeypatch):
        monkeypatch.setenv("AEGIS_ICD_STRICT", "true")
        d = ICDSNOMEDDetector()
        assert d.strict is True

    def test_env_strict_false_explicit(self, monkeypatch):
        monkeypatch.setenv("AEGIS_ICD_STRICT", "false")
        d = ICDSNOMEDDetector()
        assert d.strict is False

    def test_env_strict_case_insensitive(self, monkeypatch):
        monkeypatch.setenv("AEGIS_ICD_STRICT", "TRUE")
        d = ICDSNOMEDDetector()
        assert d.strict is True

    def test_explicit_overrides_env(self, monkeypatch):
        monkeypatch.setenv("AEGIS_ICD_STRICT", "true")
        d = ICDSNOMEDDetector(strict=False)
        assert d.strict is False


# ── extract_codes — ICD-10 ────────────────────────────────────────────────────


class TestExtractCodesICD10:
    def setup_method(self):
        self.det = ICDSNOMEDDetector()

    def test_simple_icd10(self):
        codes = self.det.extract_codes("Diagnosis J18.9 confirmed.")
        assert any(c.code == "J18.9" for c in codes)

    def test_icd10_without_suffix(self):
        codes = self.det.extract_codes("Code F32 is present")
        assert any(c.code == "F32" for c in codes)

    def test_icd10_domain(self):
        codes = self.det.extract_codes("J18.9")
        resp = next(c for c in codes if c.code == "J18.9")
        assert resp.domain == "Respiratory"
        assert resp.code_type == "icd10"

    def test_icd10_endocrine(self):
        codes = self.det.extract_codes("E11.9 type 2 diabetes")
        assert any(c.code == "E11.9" and c.domain == "Endocrine/Metabolic" for c in codes)

    def test_icd10_mental(self):
        codes = self.det.extract_codes("F32.0 major depressive disorder")
        assert any(c.code == "F32.0" and c.domain == "Mental/Behavioral" for c in codes)

    def test_icd10_multiple(self):
        codes = self.det.extract_codes("J18.9 and F32.0 co-morbid")
        code_strs = {c.code for c in codes}
        assert "J18.9" in code_strs
        assert "F32.0" in code_strs

    def test_icd10_position(self):
        text = "See code J18.9 for details"
        codes = self.det.extract_codes(text)
        j_code = next(c for c in codes if c.code == "J18.9")
        assert j_code.position == text.index("J18.9")

    def test_icd10_no_match_inside_word(self):
        # Negative lookbehind/lookahead: embedded alphanumeric should not match
        codes = self.det.extract_codes("AB12CD is not a code")
        assert not any(c.code_type == "icd10" for c in codes)

    def test_icd10_unknown_prefix_skipped(self):
        # "U" is not in _ICD10_CHAPTER
        codes = self.det.extract_codes("U07.1 COVID-19")
        icd10 = [c for c in codes if c.code_type == "icd10"]
        assert not icd10

    def test_icd10_neoplasm(self):
        codes = self.det.extract_codes("C50.9 breast carcinoma")
        assert any(c.domain == "Neoplasms" for c in codes)


# ── extract_codes — ICD-11 ────────────────────────────────────────────────────


class TestExtractCodesICD11:
    def setup_method(self):
        self.det = ICDSNOMEDDetector()

    def test_simple_icd11(self):
        codes = self.det.extract_codes("CA40.0 confirmed")
        assert any(c.code == "CA40.0" for c in codes)

    def test_icd11_code_type(self):
        codes = self.det.extract_codes("CA40.0")
        c = next(x for x in codes if x.code == "CA40.0")
        assert c.code_type == "icd11"

    def test_icd11_domain_respiratory(self):
        codes = self.det.extract_codes("CA40.0")
        c = next(x for x in codes if x.code == "CA40.0")
        assert c.domain == "Respiratory"

    def test_icd11_mental(self):
        codes = self.det.extract_codes("6A80.1 schizophrenia")
        assert any(c.code_type == "icd11" and c.domain == "Mental/Behavioral" for c in codes)

    def test_icd11_takes_priority_over_icd10(self):
        # A code matching ICD-11 pattern should not also be extracted as ICD-10
        codes = self.det.extract_codes("CA40.0")
        icd10_codes = [c for c in codes if c.code_type == "icd10"]
        icd11_codes = [c for c in codes if c.code_type == "icd11"]
        assert icd11_codes
        # ICD-10 should not double-match the same span
        assert not any("CA40" in c.code for c in icd10_codes)

    def test_icd11_unknown_prefix_returns_unknown(self):
        # A prefix not in _ICD11_CHAPTER maps to "Unknown"
        codes = self.det.extract_codes("ZA40.0")
        icd11 = [c for c in codes if c.code_type == "icd11"]
        if icd11:
            assert icd11[0].domain == "Unknown"


# ── extract_codes — SNOMED-CT ─────────────────────────────────────────────────


class TestExtractCodesSNOMED:
    def setup_method(self):
        self.det = ICDSNOMEDDetector()

    def test_snomed_with_colon(self):
        codes = self.det.extract_codes("SNOMED: 73211009")
        assert any(c.code == "73211009" and c.code_type == "snomed" for c in codes)

    def test_snomed_ct_hyphen(self):
        codes = self.det.extract_codes("SNOMED-CT 267036007")
        assert any(c.code == "267036007" for c in codes)

    def test_snomed_case_insensitive(self):
        codes = self.det.extract_codes("snomed: 73211009")
        assert any(c.code == "73211009" for c in codes)

    def test_snomed_concept(self):
        codes = self.det.extract_codes("SNOMED concept: 73211009")
        assert any(c.code == "73211009" for c in codes)

    def test_snomed_code_keyword(self):
        codes = self.det.extract_codes("SNOMED code: 73211009")
        assert any(c.code == "73211009" for c in codes)

    def test_snomed_domain_label(self):
        codes = self.det.extract_codes("SNOMED: 73211009")
        c = next(x for x in codes if x.code_type == "snomed")
        assert c.domain == "SNOMED-CT"

    def test_snomed_not_matched_without_label(self):
        # Bare 8-digit number without SNOMED label should not be extracted
        codes = self.det.extract_codes("Call 73211009 for info")
        snomed = [c for c in codes if c.code_type == "snomed"]
        assert not snomed

    def test_snomed_too_short_not_matched(self):
        codes = self.det.extract_codes("SNOMED: 12345")
        snomed = [c for c in codes if c.code_type == "snomed"]
        assert not snomed


# ── _keyword_domains ──────────────────────────────────────────────────────────


class TestKeywordDomains:
    def setup_method(self):
        self.det = ICDSNOMEDDetector()

    def test_diabetes_endocrine(self):
        domains = self.det._keyword_domains("Patient has type 2 diabetes")
        assert "Endocrine/Metabolic" in domains

    def test_pneumonia_respiratory(self):
        domains = self.det._keyword_domains("pneumonia treatment")
        assert "Respiratory" in domains

    def test_cancer_neoplasms(self):
        domains = self.det._keyword_domains("breast cancer screening")
        assert "Neoplasms" in domains

    def test_depression_mental(self):
        domains = self.det._keyword_domains("major depression diagnosis")
        assert "Mental/Behavioral" in domains

    def test_heart_circulatory(self):
        domains = self.det._keyword_domains("cardiac arrest protocol")
        assert "Circulatory" in domains

    def test_fracture_injury(self):
        domains = self.det._keyword_domains("fracture of femur")
        assert "Injury/Trauma" in domains

    def test_pregnancy(self):
        domains = self.det._keyword_domains("gestational diabetes")
        assert "Pregnancy/Childbirth" in domains

    def test_infection_infectious(self):
        domains = self.det._keyword_domains("HIV infection management")
        assert "Infectious/Parasitic" in domains

    def test_arthritis_musculoskeletal(self):
        domains = self.det._keyword_domains("rheumatoid arthritis flare")
        assert "Musculoskeletal" in domains

    def test_kidney_genitourinary(self):
        domains = self.det._keyword_domains("kidney disease management")
        assert "Genitourinary" in domains

    def test_digestive(self):
        domains = self.det._keyword_domains("Crohn disease exacerbation")
        assert "Digestive" in domains

    def test_skin(self):
        domains = self.det._keyword_domains("psoriasis treatment")
        assert "Skin" in domains

    def test_nervous_system(self):
        domains = self.det._keyword_domains("epilepsy seizure protocol")
        assert "Nervous System" in domains

    def test_empty_text(self):
        domains = self.det._keyword_domains("")
        assert domains == set()

    def test_unrelated_text(self):
        domains = self.det._keyword_domains("The quick brown fox jumps")
        assert domains == set()

    def test_multiple_domains(self):
        domains = self.det._keyword_domains("diabetes and pneumonia co-morbidity")
        assert "Endocrine/Metabolic" in domains
        assert "Respiratory" in domains

    def test_case_insensitive(self):
        domains = self.det._keyword_domains("DIABETES mellitus type 2")
        assert "Endocrine/Metabolic" in domains


# ── scan — mismatch detection ─────────────────────────────────────────────────


class TestScanMismatch:
    def setup_method(self):
        self.det = ICDSNOMEDDetector()

    def test_no_codes_no_mismatch(self):
        result = self.det.scan("Tell me about diabetes", "Diabetes is a metabolic disorder.")
        assert result.mismatch_detected is False

    def test_same_domain_no_mismatch(self):
        result = self.det.scan(
            "Patient has J18.9 pneumonia",
            "Recommend treatment for respiratory infection (J18.9).",
        )
        assert result.mismatch_detected is False

    def test_mismatch_different_domain(self):
        result = self.det.scan(
            "Patient has type 2 diabetes mellitus (E11.9).",
            "Recommend treatment for pneumonia (J18.9).",
        )
        assert result.mismatch_detected is True
        assert "Respiratory" in result.mismatch_domains

    def test_mismatch_domains_sorted(self):
        result = self.det.scan(
            "E11.9 diabetes present",
            "J18.9 pneumonia and F32.0 depression found",
        )
        assert result.mismatch_detected is True
        assert result.mismatch_domains == sorted(result.mismatch_domains)

    def test_request_domains_include_keywords(self):
        result = self.det.scan(
            "Patient has type 2 diabetes mellitus.",
            "Recommend treatment for pneumonia (J18.9).",
        )
        assert "Endocrine/Metabolic" in result.request_domains

    def test_keyword_only_request_no_explicit_codes_no_strict(self):
        # Request has keyword but no code → inferred domain
        # Non-strict mode: only flag if request had explicit codes
        result = self.det.scan(
            "Patient has diabetes.",
            "Recommend treatment for pneumonia (J18.9).",
        )
        # No explicit codes in request → no mismatch in non-strict mode
        assert result.mismatch_detected is False

    def test_keyword_only_request_strict_mode(self):
        det = ICDSNOMEDDetector(strict=True)
        result = det.scan(
            "Patient has diabetes.",
            "Recommend treatment for pneumonia (J18.9).",
        )
        assert result.mismatch_detected is True
        assert "Respiratory" in result.mismatch_domains

    def test_response_no_codes_no_mismatch(self):
        result = self.det.scan("E11.9 diabetes", "The patient is well.")
        assert result.mismatch_detected is False

    def test_request_no_domain_response_has_codes_non_strict(self):
        result = self.det.scan("Hello world", "J18.9 found")
        assert result.mismatch_detected is False

    def test_request_no_domain_response_has_codes_strict(self):
        det = ICDSNOMEDDetector(strict=True)
        result = det.scan("Hello world", "J18.9 found")
        assert result.mismatch_detected is True
        assert "Respiratory" in result.mismatch_domains

    def test_result_contains_codes(self):
        result = self.det.scan("E11.9 diabetes", "J18.9 pneumonia")
        assert any(c.code == "E11.9" for c in result.request_codes)
        assert any(c.code == "J18.9" for c in result.response_codes)

    def test_result_domains(self):
        result = self.det.scan("E11.9 diabetes", "J18.9 pneumonia")
        assert "Endocrine/Metabolic" in result.request_domains
        assert "Respiratory" in result.response_domains

    def test_subset_domain_no_mismatch(self):
        # Response domain is a subset of request domains
        result = self.det.scan(
            "E11.9 and J18.9 co-morbidity",
            "J18.9 treatment required",
        )
        assert result.mismatch_detected is False

    def test_mismatch_detected_flag(self):
        result = self.det.scan("E11.9 diabetes", "J18.9 pneumonia code found")
        # E11.9 explicitly in request → mismatch should fire for Respiratory response
        assert result.mismatch_detected is True


# ── scan — matching domain ────────────────────────────────────────────────────


class TestScanMatchingDomain:
    def setup_method(self):
        self.det = ICDSNOMEDDetector()

    def test_respiratory_request_and_response(self):
        result = self.det.scan(
            "Patient presents with pneumonia (J18.9).",
            "Prescribe antibiotics for J18.9.",
        )
        assert result.mismatch_detected is False

    def test_mental_health_both(self):
        result = self.det.scan("F32.0 depression screening", "F41.1 anxiety found (F32.0 comorbid)")
        assert result.mismatch_detected is False

    def test_broad_request_covers_all(self):
        # Request covers Endocrine + Respiratory; response only Respiratory
        result = self.det.scan(
            "E11.9 and J18.9 co-morbid patient",
            "J18.9 pneumonia treatment",
        )
        assert result.mismatch_detected is False


# ── scan_messages ─────────────────────────────────────────────────────────────


class TestScanMessages:
    def setup_method(self):
        self.det = ICDSNOMEDDetector()

    def test_user_role_is_request(self):
        messages = [
            {"role": "user", "content": "E11.9 diabetes query"},
            {"role": "assistant", "content": "J18.9 pneumonia found"},
        ]
        result = self.det.scan_messages(messages)
        assert any(c.code == "E11.9" for c in result.request_codes)
        assert any(c.code == "J18.9" for c in result.response_codes)

    def test_system_role_is_request(self):
        messages = [
            {"role": "system", "content": "Context: E11.9 diabetes management"},
            {"role": "assistant", "content": "J18.9 found in response"},
        ]
        result = self.det.scan_messages(messages)
        assert any(c.code == "E11.9" for c in result.request_codes)

    def test_assistant_role_is_response(self):
        messages = [
            {"role": "user", "content": "E11.9 management"},
            {"role": "assistant", "content": "F32.0 depression"},
        ]
        result = self.det.scan_messages(messages)
        assert any(c.code == "F32.0" for c in result.response_codes)

    def test_multiple_messages_aggregated(self):
        messages = [
            {"role": "user", "content": "E11.9 diabetes"},
            {"role": "user", "content": "Also J18.9 pneumonia"},
            {"role": "assistant", "content": "F32.0 depression found"},
        ]
        result = self.det.scan_messages(messages)
        req_codes = {c.code for c in result.request_codes}
        assert "E11.9" in req_codes
        assert "J18.9" in req_codes
        assert any(c.code == "F32.0" for c in result.response_codes)

    def test_empty_messages(self):
        result = self.det.scan_messages([])
        assert result.mismatch_detected is False

    def test_no_assistant_messages(self):
        messages = [{"role": "user", "content": "E11.9 diabetes"}]
        result = self.det.scan_messages(messages)
        assert result.response_codes == []
        assert result.mismatch_detected is False

    def test_unknown_role_ignored(self):
        messages = [
            {"role": "unknown", "content": "J18.9 respiratory"},
            {"role": "user", "content": "E11.9 diabetes"},
        ]
        result = self.det.scan_messages(messages)
        req_codes = {c.code for c in result.request_codes}
        assert "E11.9" in req_codes
        # "unknown" role is not aggregated
        assert "J18.9" not in req_codes

    def test_mismatch_detected_via_messages(self):
        messages = [
            {"role": "user", "content": "E11.9 diabetes treatment"},
            {"role": "assistant", "content": "J18.9 pneumonia antibiotic"},
        ]
        result = self.det.scan_messages(messages)
        assert result.mismatch_detected is True


# ── to_dict round-trip ────────────────────────────────────────────────────────


class TestToDictRoundTrip:
    def test_result_to_dict_structure(self):
        det = ICDSNOMEDDetector()
        result = det.scan("E11.9 diabetes", "J18.9 pneumonia")
        d = result.to_dict()
        assert isinstance(d["mismatch_detected"], bool)
        assert isinstance(d["mismatch_domains"], list)
        assert isinstance(d["request_domains"], list)
        assert isinstance(d["response_domains"], list)
        assert isinstance(d["request_code_count"], int)
        assert isinstance(d["response_code_count"], int)
        assert isinstance(d["request_codes"], list)
        assert isinstance(d["response_codes"], list)

    def test_finding_to_dict_in_result(self):
        det = ICDSNOMEDDetector()
        result = det.scan("E11.9 diabetes", "J18.9 pneumonia")
        d = result.to_dict()
        for item in d["request_codes"]:
            assert "code_type" in item
            assert "code" in item
            assert "position" in item
            assert "domain" in item


# ── SNOMED-CT edge cases ──────────────────────────────────────────────────────


class TestSNOMEDEdgeCases:
    def setup_method(self):
        self.det = ICDSNOMEDDetector()

    def test_snomed_ct_with_space(self):
        codes = self.det.extract_codes("SNOMED CT: 73211009")
        assert any(c.code == "73211009" for c in codes)

    def test_snomed_hash_separator(self):
        codes = self.det.extract_codes("SNOMED#73211009")
        assert any(c.code == "73211009" for c in codes)

    def test_multiple_snomed_codes(self):
        codes = self.det.extract_codes("SNOMED: 73211009 and SNOMED: 267036007")
        snomed = [c for c in codes if c.code_type == "snomed"]
        codes_found = {c.code for c in snomed}
        assert "73211009" in codes_found
        assert "267036007" in codes_found


# ── keyword inference patterns ────────────────────────────────────────────────


class TestKeywordPatternCount:
    def test_keyword_domain_list_not_empty(self):
        assert len(_KEYWORD_DOMAIN) >= 10

    def test_all_entries_are_tuples(self):
        import re as _re

        for entry in _KEYWORD_DOMAIN:
            assert isinstance(entry, tuple)
            assert len(entry) == 2
            assert isinstance(entry[0], _re.Pattern)
            assert isinstance(entry[1], str)


# ── Strict mode via env ───────────────────────────────────────────────────────


class TestStrictModeEnv:
    def test_strict_via_env_triggers_mismatch(self, monkeypatch):
        monkeypatch.setenv("AEGIS_ICD_STRICT", "true")
        det = ICDSNOMEDDetector()
        result = det.scan(
            "Patient has diabetes.",
            "J18.9 pneumonia treatment recommended.",
        )
        assert result.mismatch_detected is True

    def test_non_strict_env_no_mismatch(self, monkeypatch):
        monkeypatch.setenv("AEGIS_ICD_STRICT", "false")
        det = ICDSNOMEDDetector()
        result = det.scan(
            "Patient has diabetes.",
            "J18.9 pneumonia treatment recommended.",
        )
        assert result.mismatch_detected is False

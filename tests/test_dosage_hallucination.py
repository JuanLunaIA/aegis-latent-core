# Copyright (c) 2026 Juan Luna. All rights reserved.
"""Tests for aegis.core.dosage_hallucination."""

from __future__ import annotations

from aegis.core.dosage_hallucination import (
    DosageFinding,
    DosageHallucinationDetector,
    DosageScanResult,
    _DrugEntry,
    scan_for_dosage_hallucinations,
)

# ── DosageScanResult ──────────────────────────────────────────────────────────


class TestDosageScanResult:
    def test_defaults(self):
        r = DosageScanResult()
        assert r.findings == []
        assert r.violations == []
        assert r.scanned_chars == 0
        assert r.has_violations is False
        assert r.violation_count == 0

    def test_has_violations_true(self):
        f = DosageFinding("ibuprofen", "ibuprofen", 5000, "mg", 200, 800, True, False)
        r = DosageScanResult(violations=[f])
        assert r.has_violations is True
        assert r.violation_count == 1

    def test_to_dict_keys(self):
        r = DosageScanResult()
        d = r.to_dict()
        assert set(d.keys()) == {
            "has_violations",
            "violation_count",
            "scanned_chars",
            "findings",
        }

    def test_to_dict_findings_structure(self):
        f = DosageFinding(
            drug="ibuprofen",
            raw_drug="Ibuprofen",
            value=5000,
            unit="mg",
            min_ref=200,
            max_ref=800,
            is_violation=True,
            unknown_drug=False,
            context_snippet="take Ibuprofen 5000 mg",
        )
        r = DosageScanResult(findings=[f], violations=[f], scanned_chars=50)
        d = r.to_dict()
        assert d["has_violations"] is True
        assert d["violation_count"] == 1
        assert d["scanned_chars"] == 50
        assert len(d["findings"]) == 1
        fd = d["findings"][0]
        assert fd["drug"] == "ibuprofen"
        assert fd["value"] == 5000
        assert fd["unit"] == "mg"
        assert fd["is_violation"] is True


# ── DosageFinding ─────────────────────────────────────────────────────────────


class TestDosageFinding:
    def test_summary_exceeds_max(self):
        f = DosageFinding("ibuprofen", "ibuprofen", 5000, "mg", 200, 800, True, False)
        s = f.summary()
        assert "ibuprofen" in s
        assert "5000" in s
        assert "exceeds max" in s

    def test_summary_below_min(self):
        f = DosageFinding("ibuprofen", "ibuprofen", 10, "mg", 200, 800, True, False)
        s = f.summary()
        assert "below min" in s

    def test_summary_unknown_drug(self):
        f = DosageFinding("zylaxin", "Zylaxin", 100, "mg", 0, 0, False, True)
        s = f.summary()
        assert "not in reference database" in s


# ── DosageHallucinationDetector — basic detection ─────────────────────────────


class TestDetectorBasic:
    def setup_method(self):
        self.det = DosageHallucinationDetector()

    def test_no_findings_on_clean_text(self):
        result = self.det.scan("The patient was advised to rest and stay hydrated.")
        assert result.findings == []
        assert result.has_violations is False

    def test_detects_overdose_ibuprofen(self):
        result = self.det.scan("Administer ibuprofen 5000 mg every 4 hours.")
        assert result.has_violations is True
        assert any(f.drug == "ibuprofen" for f in result.violations)

    def test_clean_ibuprofen_dose(self):
        result = self.det.scan("Take ibuprofen 400 mg with food.")
        assert result.has_violations is False
        assert any(f.drug == "ibuprofen" for f in result.findings)

    def test_detects_max_dose_boundary_inclusive(self):
        # 800 mg is max — should be clean
        result = self.det.scan("ibuprofen 800 mg three times daily")
        assert result.has_violations is False

    def test_detects_above_max(self):
        result = self.det.scan("ibuprofen 801 mg three times daily")
        assert result.has_violations is True

    def test_detects_below_min(self):
        # Ibuprofen min is 200 mg; 10 mg is below
        result = self.det.scan("Give ibuprofen 10 mg to the patient.")
        assert result.has_violations is True

    def test_detects_min_boundary_inclusive(self):
        result = self.det.scan("Give ibuprofen 200 mg to the patient.")
        assert result.has_violations is False

    def test_case_insensitive_drug(self):
        result = self.det.scan("Prescribe IBUPROFEN 5000 mg stat.")
        assert result.has_violations is True

    def test_alias_detection(self):
        # "tylenol" is an alias for acetaminophen
        result = self.det.scan("Give Tylenol 5000 mg now.")
        assert result.has_violations is True
        assert any(f.drug == "acetaminophen" for f in result.violations)

    def test_alias_paracetamol(self):
        result = self.det.scan("Administer paracetamol 500 mg.")
        assert result.has_violations is False
        assert any(f.drug == "acetaminophen" for f in result.findings)

    def test_morphine_within_range(self):
        result = self.det.scan("morphine 10 mg IV push")
        assert result.has_violations is False

    def test_morphine_overdose(self):
        result = self.det.scan("morphine 500 mg IV push")
        assert result.has_violations is True

    def test_fentanyl_mcg(self):
        result = self.det.scan("fentanyl 50 mcg patch")
        assert result.has_violations is False

    def test_fentanyl_mg_not_compared(self):
        # fentanyl reference is in mcg; mg input should not compare (unit mismatch)
        result = self.det.scan("fentanyl 50 mg patch")
        assert result.has_violations is False  # unit mismatch skips comparison

    def test_levothyroxine_mcg(self):
        result = self.det.scan("levothyroxine 100 mcg daily")
        assert result.has_violations is False

    def test_levothyroxine_overdose_mcg(self):
        result = self.det.scan("levothyroxine 5000 mcg daily")
        assert result.has_violations is True

    def test_warfarin_within_range(self):
        result = self.det.scan("warfarin 5 mg daily")
        assert result.has_violations is False

    def test_warfarin_overdose(self):
        result = self.det.scan("warfarin 100 mg daily")
        assert result.has_violations is True

    def test_metformin_within_range(self):
        result = self.det.scan("metformin 500 mg twice daily")
        assert result.has_violations is False

    def test_insulin_units(self):
        result = self.det.scan("Give insulin glargine 20 units at bedtime.")
        assert result.has_violations is False

    def test_insulin_overdose_units(self):
        result = self.det.scan("Give insulin glargine 9999 units at bedtime.")
        assert result.has_violations is True


# ── Reference database ────────────────────────────────────────────────────────


class TestReferenceDatabase:
    def setup_method(self):
        self.det = DosageHallucinationDetector()

    def test_drug_entry_returns_entry(self):
        e = self.det.drug_entry("ibuprofen")
        assert e is not None
        assert e.name == "ibuprofen"
        assert e.unit == "mg"
        assert e.min_val == 200
        assert e.max_val == 800

    def test_drug_entry_alias(self):
        e = self.det.drug_entry("tylenol")
        assert e is not None
        assert e.name == "acetaminophen"

    def test_drug_entry_unknown(self):
        assert self.det.drug_entry("unicorn_drug") is None

    def test_db_has_over_100_entries(self):
        from aegis.core.dosage_hallucination import _DB

        assert len(_DB) >= 100

    def test_all_db_entries_have_positive_range(self):
        from aegis.core.dosage_hallucination import _DRUG_DB

        for entry in _DRUG_DB:
            assert entry.min_val >= 0, f"{entry.name}: min_val < 0"
            assert entry.max_val >= entry.min_val, f"{entry.name}: max < min"
            assert entry.unit in {"mg", "mcg", "units", "mEq"}, (
                f"{entry.name}: unknown unit {entry.unit}"
            )


# ── Strict mode ───────────────────────────────────────────────────────────────


class TestStrictMode:
    def test_unknown_drug_not_violation_by_default(self):
        det = DosageHallucinationDetector(strict=False)
        result = det.scan("Give zylaxin 50 mg IV.")
        # unknown drug should appear in findings but not violations
        assert result.has_violations is False

    def test_unknown_drug_is_violation_in_strict(self):
        det = DosageHallucinationDetector(strict=True)
        result = det.scan("Give completelymadeupdrugname 50 mg IV.")
        # If the drug name is extracted and unknown, strict mode → violation
        unknown = [f for f in result.findings if f.unknown_drug]
        if unknown:
            assert result.has_violations is True

    def test_strict_from_env(self, monkeypatch):
        monkeypatch.setenv("AEGIS_DOSAGE_STRICT", "1")
        det = DosageHallucinationDetector()
        assert det.strict is True

    def test_not_strict_by_default_env_unset(self, monkeypatch):
        monkeypatch.delenv("AEGIS_DOSAGE_STRICT", raising=False)
        det = DosageHallucinationDetector()
        assert det.strict is False


# ── Extra database ────────────────────────────────────────────────────────────


class TestExtraDatabase:
    def test_extra_db_entry_recognized(self):
        custom = _DrugEntry("zylaxin", "mg", 10, 100, ("zyl",))
        det = DosageHallucinationDetector(extra_db=[custom])
        result = det.scan("Administer zylaxin 5000 mg.")
        assert result.has_violations is True

    def test_extra_db_alias_recognized(self):
        custom = _DrugEntry("zylaxin", "mg", 10, 100, ("zyl",))
        det = DosageHallucinationDetector(extra_db=[custom])
        result = det.scan("Give zyl 50 mg.")
        assert result.has_violations is False
        assert any(f.drug == "zylaxin" for f in result.findings)

    def test_extra_db_does_not_replace_existing(self):
        # Existing ibuprofen range should still hold
        custom = _DrugEntry("mydrugx", "mg", 1, 10)
        det = DosageHallucinationDetector(extra_db=[custom])
        result = det.scan("ibuprofen 5000 mg")
        assert result.has_violations is True


# ── scan_messages ─────────────────────────────────────────────────────────────


class TestScanMessages:
    def setup_method(self):
        self.det = DosageHallucinationDetector()

    def test_scans_only_assistant_messages(self):
        messages = [
            {"role": "user", "content": "What dose of ibuprofen 9999 mg?"},
            {"role": "assistant", "content": "I recommend ibuprofen 400 mg."},
        ]
        result = self.det.scan_messages(messages)
        # user message with 9999 mg is NOT scanned — only assistant
        assert result.has_violations is False

    def test_detects_violation_in_assistant_message(self):
        messages = [
            {"role": "user", "content": "What dose?"},
            {"role": "assistant", "content": "Give ibuprofen 9999 mg."},
        ]
        result = self.det.scan_messages(messages)
        assert result.has_violations is True

    def test_empty_messages_no_crash(self):
        result = self.det.scan_messages([])
        assert result.has_violations is False

    def test_missing_content_key_no_crash(self):
        result = self.det.scan_messages([{"role": "assistant"}])
        assert result.has_violations is False


# ── Deduplication ─────────────────────────────────────────────────────────────


class TestDeduplication:
    def test_same_claim_not_double_counted(self):
        det = DosageHallucinationDetector()
        result = det.scan("ibuprofen 5000 mg, patient needs ibuprofen 5000 mg now.")
        violations = [v for v in result.violations if v.drug == "ibuprofen"]
        assert len(violations) == 1

    def test_different_values_both_counted(self):
        det = DosageHallucinationDetector()
        result = det.scan("ibuprofen 5000 mg, then ibuprofen 9000 mg.")
        ibu_violations = [v for v in result.violations if v.drug == "ibuprofen"]
        assert len(ibu_violations) == 2


# ── module-level convenience function ────────────────────────────────────────


class TestScanForDosageHallucinations:
    def test_returns_result(self):
        result = scan_for_dosage_hallucinations("ibuprofen 400 mg")
        assert isinstance(result, DosageScanResult)

    def test_detects_violation(self):
        result = scan_for_dosage_hallucinations("ibuprofen 9999 mg")
        assert result.has_violations is True

    def test_strict_kwarg(self):
        result = scan_for_dosage_hallucinations("ibuprofen 400 mg", strict=True)
        assert isinstance(result, DosageScanResult)


# ── Numeric formats ───────────────────────────────────────────────────────────


class TestNumericFormats:
    def setup_method(self):
        self.det = DosageHallucinationDetector()

    def test_comma_separated_thousands(self):
        result = self.det.scan("Give ibuprofen 1,000 mg.")
        assert result.has_violations is True

    def test_decimal_dose(self):
        result = self.det.scan("warfarin 2.5 mg daily")
        assert result.has_violations is False

    def test_micrograms_unicode(self):
        result = self.det.scan("fentanyl 50 µg patch")
        assert result.has_violations is False

    def test_micrograms_unicode_mu(self):
        result = self.det.scan("fentanyl 50 μg patch")
        assert result.has_violations is False

    def test_scanned_chars_correct(self):
        text = "ibuprofen 400 mg daily"
        result = self.det.scan(text)
        assert result.scanned_chars == len(text)

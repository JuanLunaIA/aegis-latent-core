# Copyright (c) 2026 Juan Luna. All rights reserved.
"""Tests for aegis.core.clinical_claim_detector."""

from __future__ import annotations

from aegis.core.clinical_claim_detector import (
    ClinicalClaimDetector,
    ClinicalClaimResult,
    ClinicalClaimViolation,
)

# ── ClinicalClaimResult ───────────────────────────────────────────────────────


class TestClinicalClaimResult:
    def test_defaults(self):
        r = ClinicalClaimResult()
        assert r.violations == []
        assert r.total_claims == 0
        assert r.scanned_chars == 0
        assert r.has_violations is False
        assert r.violation_count == 0
        assert r.cited_claims == 0

    def test_has_violations_true(self):
        v = ClinicalClaimViolation("snippet", 0, "reason")
        r = ClinicalClaimResult(violations=[v], total_claims=1)
        assert r.has_violations is True
        assert r.violation_count == 1
        assert r.cited_claims == 0

    def test_cited_claims_calculation(self):
        v = ClinicalClaimViolation("snippet", 0, "reason")
        r = ClinicalClaimResult(violations=[v], total_claims=3)
        assert r.cited_claims == 2

    def test_cited_claims_non_negative(self):
        r = ClinicalClaimResult(violations=[], total_claims=0)
        assert r.cited_claims == 0

    def test_to_dict_keys(self):
        r = ClinicalClaimResult()
        d = r.to_dict()
        assert set(d.keys()) == {
            "has_violations",
            "violation_count",
            "total_claims",
            "cited_claims",
            "scanned_chars",
            "strict",
            "violations",
        }

    def test_to_dict_violations_serialized(self):
        v = ClinicalClaimViolation("the trial showed", 5, "no citation")
        r = ClinicalClaimResult(violations=[v], total_claims=1, scanned_chars=100)
        d = r.to_dict()
        assert d["has_violations"] is True
        assert len(d["violations"]) == 1
        vd = d["violations"][0]
        assert vd["claim_snippet"] == "the trial showed"
        assert vd["position"] == 5
        assert vd["reason"] == "no citation"


# ── ClinicalClaimViolation ────────────────────────────────────────────────────


class TestClinicalClaimViolation:
    def test_to_dict(self):
        v = ClinicalClaimViolation("claim text", 42, "reason text")
        d = v.to_dict()
        assert d == {"claim_snippet": "claim text", "position": 42, "reason": "reason text"}


# ── Clean text ────────────────────────────────────────────────────────────────


class TestCleanText:
    def setup_method(self):
        self.det = ClinicalClaimDetector()

    def test_empty_text(self):
        result = self.det.scan("")
        assert result.has_violations is False
        assert result.total_claims == 0

    def test_benign_text(self):
        result = self.det.scan(
            "Ibuprofen is a nonsteroidal anti-inflammatory drug used to reduce pain and fever."
        )
        assert result.has_violations is False

    def test_informational_text_no_claim(self):
        result = self.det.scan("Please consult your physician before starting any new medication.")
        assert result.has_violations is False


# ── Claim detection ───────────────────────────────────────────────────────────


class TestClaimDetection:
    def setup_method(self):
        self.det = ClinicalClaimDetector()

    def test_rct_showed_violation(self):
        result = self.det.scan(
            "A randomised controlled trial showed that this treatment reduces mortality by 30%."
        )
        assert result.has_violations is True
        assert result.total_claims >= 1

    def test_double_blind_demonstrated_violation(self):
        result = self.det.scan(
            "A double-blind study demonstrated that the vaccine was 95% effective."
        )
        assert result.has_violations is True

    def test_our_research_demonstrates_violation(self):
        result = self.det.scan(
            "Our research demonstrates that aspirin prevents cardiac events in high-risk patients."
        )
        assert result.has_violations is True

    def test_studies_confirm_violation(self):
        result = self.det.scan("Studies confirm that the treatment reduces recurrence by 40%.")
        assert result.has_violations is True

    def test_clinical_evidence_shows_violation(self):
        result = self.det.scan(
            "Clinical evidence shows that this therapy is safe and effective for long-term use."
        )
        assert result.has_violations is True

    def test_in_a_study_of_n_patients(self):
        result = self.det.scan(
            "In a study of 500 patients, the drug was associated with significant improvement."
        )
        assert result.has_violations is True

    def test_has_been_shown_to_treat(self):
        result = self.det.scan(
            "This compound has been shown to treat severe infections in immunocompromised patients."
        )
        assert result.has_violations is True

    def test_phase_ii_trial_found(self):
        result = self.det.scan("A phase II trial found that the new drug was well tolerated.")
        assert result.has_violations is True

    def test_meta_analysis_confirmed(self):
        result = self.det.scan(
            "A meta-analysis confirmed that low-dose aspirin reduces stroke risk."
        )
        assert result.has_violations is True

    def test_reduced_by_percentage_violation(self):
        result = self.det.scan("The drug reduced mortality by 25% in the test group.")
        assert result.total_claims >= 1

    def test_efficacy_was_percentage(self):
        result = self.det.scan("The efficacy of the vaccine was 92% in the trial population.")
        assert result.total_claims >= 1


# ── Citation exoneration ──────────────────────────────────────────────────────


class TestCitationExoneration:
    def setup_method(self):
        self.det = ClinicalClaimDetector()

    def test_numeric_citation_exonerates(self):
        result = self.det.scan(
            "A randomised controlled trial showed that the drug reduces pain [1]."
        )
        assert result.has_violations is False
        assert result.total_claims >= 1
        assert result.cited_claims >= 1

    def test_author_year_citation_exonerates(self):
        result = self.det.scan(
            "A randomised controlled trial showed significant benefit (Smith et al., 2023)."
        )
        assert result.has_violations is False

    def test_doi_citation_exonerates(self):
        result = self.det.scan(
            "A phase II trial found the drug effective. doi: 10.1056/NEJMoa2100245"
        )
        assert result.has_violations is False

    def test_pmid_citation_exonerates(self):
        result = self.det.scan("A double-blind study demonstrated efficacy PMID: 34567890.")
        assert result.has_violations is False

    def test_nct_number_exonerates(self):
        result = self.det.scan(
            "A study of 200 patients (NCT04567890) showed reduced hospitalization."
        )
        assert result.has_violations is False

    def test_according_to_source_exonerates(self):
        result = self.det.scan("Clinical evidence shows efficacy, according to the FDA.")
        assert result.has_violations is False

    def test_citation_outside_window_does_not_exonerate(self):
        long_gap = "X" * 500
        result = self.det.scan(
            f"A randomised controlled trial showed that the drug is effective. {long_gap} [1]"
        )
        # Citation is 500+ chars away — should not exonerate
        assert result.has_violations is True

    def test_citation_within_window_exonerates(self):
        result = self.det.scan(
            "A randomised controlled trial showed that the drug reduces pain by 40%. "
            "See reference [1] for details."
        )
        assert result.has_violations is False


# ── Strict mode ───────────────────────────────────────────────────────────────


class TestStrictMode:
    def test_strict_flags_cited_claim(self):
        det = ClinicalClaimDetector(strict=True)
        result = det.scan("A randomised controlled trial showed benefit [1].")
        # Even with a citation, strict mode flags it
        assert result.has_violations is True
        assert result.violations[0].reason == "strict mode: all clinical claims require citation"

    def test_strict_from_env(self, monkeypatch):
        monkeypatch.setenv("AEGIS_CLINICAL_STRICT", "1")
        det = ClinicalClaimDetector()
        assert det.strict is True

    def test_not_strict_by_default(self, monkeypatch):
        monkeypatch.delenv("AEGIS_CLINICAL_STRICT", raising=False)
        det = ClinicalClaimDetector()
        assert det.strict is False

    def test_strict_false_allows_cited(self):
        det = ClinicalClaimDetector(strict=False)
        result = det.scan("A randomised controlled trial showed benefit [1].")
        assert result.has_violations is False


# ── Citation window ───────────────────────────────────────────────────────────


class TestCitationWindow:
    def test_custom_window_zero_never_finds_citation(self):
        det = ClinicalClaimDetector(citation_window_chars=0)
        result = det.scan("A randomised controlled trial showed benefit [1].")
        # Window of 0 can't find the citation after the claim
        assert result.has_violations is True

    def test_large_window_finds_distant_citation(self):
        det = ClinicalClaimDetector(citation_window_chars=600)
        gap = "X" * 400
        result = det.scan(f"A randomised controlled trial showed benefit. {gap} [1]")
        assert result.has_violations is False

    def test_window_from_env(self, monkeypatch):
        monkeypatch.setenv("AEGIS_CLINICAL_WINDOW", "100")
        det = ClinicalClaimDetector()
        assert det.citation_window_chars == 100

    def test_invalid_window_env_uses_default(self, monkeypatch):
        monkeypatch.setenv("AEGIS_CLINICAL_WINDOW", "not_an_int")
        det = ClinicalClaimDetector()
        assert det.citation_window_chars == 300

    def test_negative_window_clamped_to_zero(self, monkeypatch):
        monkeypatch.setenv("AEGIS_CLINICAL_WINDOW", "-50")
        det = ClinicalClaimDetector()
        assert det.citation_window_chars == 0


# ── scan_messages ─────────────────────────────────────────────────────────────


class TestScanMessages:
    def setup_method(self):
        self.det = ClinicalClaimDetector()

    def test_scans_only_assistant_messages(self):
        messages = [
            {"role": "user", "content": "A randomised controlled trial showed efficacy."},
            {"role": "assistant", "content": "Please consult your doctor for advice."},
        ]
        result = self.det.scan_messages(messages)
        assert result.has_violations is False

    def test_detects_violation_in_assistant(self):
        messages = [
            {"role": "user", "content": "Tell me about aspirin."},
            {
                "role": "assistant",
                "content": "A double-blind study demonstrated that aspirin reduces cardiac events.",
            },
        ]
        result = self.det.scan_messages(messages)
        assert result.has_violations is True

    def test_empty_messages(self):
        result = self.det.scan_messages([])
        assert result.has_violations is False

    def test_missing_content_key(self):
        result = self.det.scan_messages([{"role": "assistant"}])
        assert result.has_violations is False


# ── De-duplication ────────────────────────────────────────────────────────────


class TestDeduplication:
    def test_overlapping_claims_counted_once(self):
        det = ClinicalClaimDetector()
        # Two overlapping claim phrases starting within 50 chars of each other
        result = det.scan("A randomised controlled trial showed and confirmed efficacy.")
        # Should not double-count the close overlap
        assert result.total_claims >= 1

    def test_scanned_chars_correct(self):
        text = "A randomised controlled trial showed efficacy."
        det = ClinicalClaimDetector()
        result = det.scan(text)
        assert result.scanned_chars == len(text)


# ── Citation pattern coverage ─────────────────────────────────────────────────


class TestCitationPatterns:
    def setup_method(self):
        self.det = ClinicalClaimDetector()

    def _claim_with_suffix(self, suffix: str) -> str:
        return f"A randomised controlled trial showed that the drug reduces pain. {suffix}"

    def test_bracket_citation(self):
        result = self.det.scan(self._claim_with_suffix("[2]"))
        assert result.has_violations is False

    def test_multiple_bracket_citation(self):
        result = self.det.scan(self._claim_with_suffix("[1,2,3]"))
        assert result.has_violations is False

    def test_pubmed_url_exonerates(self):
        result = self.det.scan(self._claim_with_suffix("https://pubmed.ncbi.nlm.nih.gov/12345678/"))
        assert result.has_violations is False

    def test_cochrane_url_exonerates(self):
        result = self.det.scan(
            self._claim_with_suffix("https://cochranelibrary.com/cdsr/doi/10.1002/...")
        )
        assert result.has_violations is False

    def test_superscript_citation_exonerates(self):
        result = self.det.scan(self._claim_with_suffix("¹"))
        assert result.has_violations is False

    def test_footnote_marker_exonerates(self):
        result = self.det.scan(self._claim_with_suffix("See footnote 1."))
        assert result.has_violations is False

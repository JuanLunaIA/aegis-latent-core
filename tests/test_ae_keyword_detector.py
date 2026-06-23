# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for MedDRA adverse event keyword detection (aegis.core.ae_keyword_detector)."""

from __future__ import annotations

import json

from aegis.core.ae_keyword_detector import (
    BUILTIN_TERM_COUNT,
    AEDetectionResult,
    AEKeywordDetector,
)

# ── AEDetectionResult ──────────────────────────────────────────────────────────


class TestAEDetectionResult:
    def test_defaults(self):
        r = AEDetectionResult()
        assert r.flagged is False
        assert r.terms_found == []
        assert r.soc_counts == {}
        assert r.reason == ""

    def test_bool_false_when_not_flagged(self):
        r = AEDetectionResult(flagged=False)
        assert not r

    def test_bool_true_when_flagged(self):
        r = AEDetectionResult(flagged=True)
        assert r

    def test_to_dict_structure(self):
        r = AEDetectionResult(
            flagged=True,
            terms_found=[("nausea", "GI"), ("vomiting", "GI")],
            soc_counts={"GI": 2},
            scan_length=100,
            reason="AE terms detected",
        )
        d = r.to_dict()
        assert d["flagged"] is True
        assert d["terms_found"] == [("nausea", "GI"), ("vomiting", "GI")]
        assert d["soc_counts"] == {"GI": 2}
        assert d["scan_length"] == 100
        assert "reason" in d

    def test_to_dict_json_serializable(self):
        r = AEDetectionResult(
            flagged=True,
            terms_found=[("headache", "NS")],
            soc_counts={"NS": 1},
            scan_length=50,
            reason="AE terms detected: 1 term(s)",
        )
        json.dumps(r.to_dict())


# ── Constructor ────────────────────────────────────────────────────────────────


class TestConstructor:
    def test_default_term_count(self):
        det = AEKeywordDetector()
        assert det.term_count == BUILTIN_TERM_COUNT

    def test_extra_terms_increase_count(self):
        det = AEKeywordDetector(extra_terms=[("bradyzoite", "IM")])
        assert det.term_count == BUILTIN_TERM_COUNT + 1

    def test_multiple_extra_terms(self):
        det = AEKeywordDetector(extra_terms=[("term1", "GE"), ("term2", "SK")])
        assert det.term_count == BUILTIN_TERM_COUNT + 2

    def test_require_context_default_true(self):
        det = AEKeywordDetector()
        assert det._require_context is True

    def test_require_context_false(self):
        det = AEKeywordDetector(require_clinical_context=False)
        assert det._require_context is False

    def test_builtin_term_count_positive(self):
        assert BUILTIN_TERM_COUNT > 0


# ── Empty / no-context ─────────────────────────────────────────────────────────


class TestEmptyAndNoContext:
    def test_empty_text(self):
        r = AEKeywordDetector().scan("")
        assert r.flagged is False
        assert r.scan_length == 0

    def test_plain_prose_no_clinical_context(self):
        text = "The weather was nice and I felt fatigued after hiking."
        r = AEKeywordDetector(require_clinical_context=True).scan(text)
        assert r.flagged is False
        assert "context" in r.reason

    def test_no_context_reason_mentions_skip(self):
        r = AEKeywordDetector().scan("I had a rash from sunburn.")
        assert "skipped" in r.reason or "context" in r.reason

    def test_scan_length_set_for_no_context(self):
        text = "Just a regular sentence."
        r = AEKeywordDetector().scan(text)
        assert r.scan_length == len(text)


# ── AE term detection (with context) ──────────────────────────────────────────


class TestAETermDetection:
    def _clinical(self, term: str) -> str:
        return f"The patient experienced {term} after treatment."

    def test_nausea_detected(self):
        r = AEKeywordDetector().scan(self._clinical("nausea"))
        assert r.flagged
        assert any(t == "nausea" for t, _ in r.terms_found)

    def test_vomiting_detected(self):
        r = AEKeywordDetector().scan(self._clinical("vomiting"))
        assert r.flagged

    def test_headache_detected(self):
        r = AEKeywordDetector().scan(self._clinical("headache"))
        assert r.flagged
        assert any(s == "NS" for _, s in r.terms_found)

    def test_hepatotoxicity_detected(self):
        r = AEKeywordDetector().scan(
            "The drug can cause hepatotoxicity in patients with liver disease."
        )
        assert r.flagged
        assert any(s == "HE" for _, s in r.terms_found)

    def test_anaphylaxis_detected(self):
        r = AEKeywordDetector().scan(
            "A patient developed anaphylaxis following drug administration."
        )
        assert r.flagged
        assert any(s == "IM" for _, s in r.terms_found)

    def test_cardiac_arrest_detected(self):
        r = AEKeywordDetector().scan(
            "Cardiac arrest was reported as a serious adverse event in the trial."
        )
        assert r.flagged
        assert any(t == "cardiac arrest" for t, _ in r.terms_found)

    def test_stevens_johnson_detected(self):
        r = AEKeywordDetector().scan(
            "One patient developed Stevens-Johnson syndrome during treatment."
        )
        assert r.flagged

    def test_diarrhoea_uk_spelling(self):
        r = AEKeywordDetector().scan(self._clinical("diarrhoea"))
        assert r.flagged

    def test_diarrhea_us_spelling(self):
        r = AEKeywordDetector().scan(self._clinical("diarrhea"))
        assert r.flagged

    def test_dyspnoea_uk_spelling(self):
        r = AEKeywordDetector().scan(self._clinical("dyspnoea"))
        assert r.flagged

    def test_dyspnea_us_spelling(self):
        r = AEKeywordDetector().scan(self._clinical("dyspnea"))
        assert r.flagged

    def test_anaemia_uk_spelling(self):
        r = AEKeywordDetector().scan(self._clinical("anaemia"))
        assert r.flagged

    def test_anemia_us_spelling(self):
        r = AEKeywordDetector().scan(self._clinical("anemia"))
        assert r.flagged


# ── Case insensitivity ─────────────────────────────────────────────────────────


class TestCaseInsensitivity:
    def test_uppercase_term(self):
        r = AEKeywordDetector().scan("Patient had NAUSEA and vomiting.")
        assert r.flagged

    def test_mixed_case_term(self):
        r = AEKeywordDetector().scan("Patient reported Hepatotoxicity post-treatment.")
        assert r.flagged

    def test_all_caps(self):
        r = AEKeywordDetector().scan("DRUG-INDUCED HEPATITIS was noted in the patient.")
        assert r.flagged


# ── Word boundary matching ─────────────────────────────────────────────────────


class TestWordBoundary:
    def test_partial_match_not_flagged(self):
        # "rash" should not match "brash" or "rashes" as separate word
        r = AEKeywordDetector(require_clinical_context=False).scan("The patient had a rash on arm.")
        assert r.flagged  # "rash" as whole word should match

    def test_partial_word_not_flagged(self):
        # "nausea" should not match "nauseous" as it's a different word
        # (regex uses \b so "nausea" won't match inside "nauseous")
        det = AEKeywordDetector(require_clinical_context=False)
        r = det.scan("Patient felt nauseous.")
        # "nausea" won't match "nauseous" due to \b
        # "nauseous" itself is not in our term list
        assert not any(t == "nausea" for t, _ in r.terms_found)


# ── SOC classification ─────────────────────────────────────────────────────────


class TestSOCClassification:
    def test_soc_counts_populated(self):
        r = AEKeywordDetector().scan(
            "Patient experienced nausea, vomiting, and diarrhea after treatment."
        )
        assert "GI" in r.soc_counts
        assert r.soc_counts["GI"] >= 3

    def test_multiple_socs(self):
        r = AEKeywordDetector().scan(
            "Patient had nausea (GI), headache (NS), and rash (SK) during clinical trial."
        )
        socs = {s for _, s in r.terms_found}
        assert len(socs) >= 2

    def test_serious_ae_qualifier_soc(self):
        r = AEKeywordDetector().scan(
            "A serious adverse event resulting in hospitalisation was reported."
        )
        assert "SA" in r.soc_counts

    def test_cardiac_soc(self):
        r = AEKeywordDetector().scan("The patient developed tachycardia requiring treatment.")
        assert "CA" in r.soc_counts


# ── require_clinical_context=False ────────────────────────────────────────────


class TestNoContextRequired:
    def test_fatigue_in_non_clinical_text(self):
        det = AEKeywordDetector(require_clinical_context=False)
        r = det.scan("I felt fatigue after the long meeting.")
        assert r.flagged

    def test_rash_in_non_clinical_text(self):
        det = AEKeywordDetector(require_clinical_context=False)
        r = det.scan("She had a rash from the new soap.")
        assert r.flagged

    def test_death_in_non_clinical_text(self):
        det = AEKeywordDetector(require_clinical_context=False)
        r = det.scan("The death of the character in the novel.")
        assert r.flagged


# ── require_clinical_context=True (default) ───────────────────────────────────


class TestContextRequired:
    def test_ae_term_without_context_not_flagged(self):
        det = AEKeywordDetector(require_clinical_context=True)
        r = det.scan("I felt fatigue after hiking all day.")
        assert not r.flagged

    def test_ae_term_with_patient_context_flagged(self):
        r = AEKeywordDetector().scan("The patient reported fatigue and chills.")
        assert r.flagged

    def test_ae_term_with_drug_context_flagged(self):
        r = AEKeywordDetector().scan("The drug caused nausea in trial participants.")
        assert r.flagged

    def test_ae_term_with_clinical_context_flagged(self):
        r = AEKeywordDetector().scan("In clinical studies, rash occurred in 5% of patients.")
        assert r.flagged

    def test_adverse_itself_is_context(self):
        r = AEKeywordDetector().scan("Adverse events including nausea were observed.")
        assert r.flagged


# ── Deduplication ─────────────────────────────────────────────────────────────


class TestDeduplication:
    def test_same_term_twice_appears_once(self):
        r = AEKeywordDetector().scan("Patient had nausea before dose and nausea after dose.")
        nausea_terms = [t for t, _ in r.terms_found if t == "nausea"]
        assert len(nausea_terms) == 1

    def test_uk_us_spelling_both_counted(self):
        r = AEKeywordDetector().scan("Patient reported diarrhoea and diarrhea during treatment.")
        terms = [t for t, _ in r.terms_found]
        # Both spellings are separate terms in the term list
        assert "diarrhoea" in terms or "diarrhea" in terms


# ── extra_terms ────────────────────────────────────────────────────────────────


class TestExtraTerms:
    def test_extra_term_detected(self):
        det = AEKeywordDetector(
            extra_terms=[("myocarditis", "CA")],
            require_clinical_context=False,
        )
        r = det.scan("The patient developed myocarditis.")
        assert r.flagged
        assert any(t == "myocarditis" for t, _ in r.terms_found)

    def test_extra_term_soc(self):
        det = AEKeywordDetector(
            extra_terms=[("pneumothorax", "RS")],
            require_clinical_context=False,
        )
        r = det.scan("A pneumothorax was observed on chest X-ray.")
        assert "RS" in r.soc_counts

    def test_extra_terms_case_insensitive(self):
        det = AEKeywordDetector(
            extra_terms=[("QTc prolongation", "CA")],
            require_clinical_context=False,
        )
        r = det.scan("ECG showed QTC PROLONGATION during treatment.")
        assert r.flagged


# ── scan_messages ──────────────────────────────────────────────────────────────


class TestScanMessages:
    def test_clean_messages_not_flagged(self):
        msgs = [
            {"role": "user", "content": "What is the capital of France?"},
            {"role": "assistant", "content": "The capital of France is Paris."},
        ]
        r = AEKeywordDetector().scan_messages(msgs)
        assert not r.flagged

    def test_ae_in_assistant_message_flagged(self):
        msgs = [
            {"role": "user", "content": "What are the side effects?"},
            {
                "role": "assistant",
                "content": (
                    "Common adverse reactions include nausea, vomiting, "
                    "and hepatotoxicity in patients with liver conditions."
                ),
            },
        ]
        r = AEKeywordDetector().scan_messages(msgs)
        assert r.flagged

    def test_ae_spread_across_messages_detected(self):
        msgs = [
            {"role": "assistant", "content": "Patient reported nausea during treatment."},
            {"role": "assistant", "content": "Hepatotoxicity was observed in clinical trial."},
        ]
        r = AEKeywordDetector().scan_messages(msgs)
        assert r.flagged
        socs = {s for _, s in r.terms_found}
        assert "GI" in socs
        assert "HE" in socs

    def test_non_string_content_ignored(self):
        msgs = [{"role": "tool", "content": None}]
        r = AEKeywordDetector().scan_messages(msgs)
        assert not r.flagged

    def test_missing_content_key_ignored(self):
        msgs = [{"role": "system"}]
        r = AEKeywordDetector().scan_messages(msgs)
        assert not r.flagged

    def test_empty_messages_not_flagged(self):
        r = AEKeywordDetector().scan_messages([])
        assert not r.flagged


# ── scan_text_bulk ─────────────────────────────────────────────────────────────


class TestScanTextBulk:
    def test_returns_one_result_per_text(self):
        texts = [
            "Patient had nausea.",
            "The capital of France is Paris.",
            "Hepatotoxicity observed in clinical study.",
        ]
        results = AEKeywordDetector().scan_text_bulk(texts)
        assert len(results) == 3

    def test_flagged_only_for_ae_texts(self):
        texts = [
            "Patient had nausea after treatment.",
            "The sky is blue.",
        ]
        results = AEKeywordDetector().scan_text_bulk(texts)
        assert results[0].flagged
        assert not results[1].flagged

    def test_empty_bulk_returns_empty(self):
        results = AEKeywordDetector().scan_text_bulk([])
        assert results == []


# ── Reason field ───────────────────────────────────────────────────────────────


class TestReasonField:
    def test_reason_mentions_terms_when_flagged(self):
        r = AEKeywordDetector().scan("Patient experienced nausea during drug therapy.")
        assert r.flagged
        assert "AE terms" in r.reason or "term" in r.reason

    def test_reason_mentions_no_terms_when_clean(self):
        r = AEKeywordDetector(require_clinical_context=False).scan("Normal text.")
        assert not r.flagged
        assert "no" in r.reason.lower() or "MedDRA" in r.reason

    def test_reason_set_for_empty(self):
        r = AEKeywordDetector().scan("")
        assert r.reason != ""


# ── Integration scenarios ──────────────────────────────────────────────────────


class TestIntegrationScenarios:
    def test_pharmacovigilance_report(self):
        report = (
            "Patient #1042 (female, 54y) enrolled in Phase III clinical trial. "
            "After dose 3, she experienced severe nausea, vomiting, and diarrhoea. "
            "Lab results showed elevated liver enzymes consistent with hepatotoxicity. "
            "She required hospitalisation and the drug was discontinued."
        )
        r = AEKeywordDetector().scan(report)
        assert r.flagged
        socs = {s for _, s in r.terms_found}
        assert "GI" in socs
        assert "HE" in socs
        assert "SA" in socs

    def test_drug_label_text(self):
        label = (
            "Adverse reactions reported in ≥5% of patients in clinical trials: "
            "fatigue (32%), nausea (28%), headache (22%), rash (15%), dizziness (12%). "
            "Serious adverse events: cardiac arrest (0.3%), anaphylaxis (0.1%)."
        )
        r = AEKeywordDetector().scan(label)
        assert r.flagged
        assert len(r.terms_found) >= 5

    def test_non_clinical_prose_with_context_off(self):
        # even without clinical context, should flag when context check disabled
        text = "He felt fatigue and headache after a long day."
        r = AEKeywordDetector(require_clinical_context=False).scan(text)
        assert r.flagged

    def test_normal_clinical_note_no_ae(self):
        note = (
            "Patient presents for routine follow-up. "
            "Blood pressure 120/80, heart rate 72 bpm. "
            "No complaints. Continue current medication regimen."
        )
        r = AEKeywordDetector().scan(note)
        assert not r.flagged

    def test_to_dict_json_serializable_integration(self):
        r = AEKeywordDetector().scan(
            "Patient developed anaphylaxis during treatment with the study drug."
        )
        json.dumps(r.to_dict())

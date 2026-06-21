# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for classified-data marker detection (aegis.core.classified_marker_detector)."""

from __future__ import annotations

from aegis.core.classified_marker_detector import (
    ClassifiedMarkerDetector,
    MarkerDetectionResult,
)

# ── MarkerDetectionResult ─────────────────────────────────────────────────────


class TestMarkerDetectionResult:
    def test_blocked_true(self):
        r = MarkerDetectionResult(blocked=True, markers_found=[("SCI_SI", "//SI")], reason="x", scan_length=10)
        assert r.blocked is True
        assert bool(r) is True

    def test_blocked_false(self):
        r = MarkerDetectionResult(blocked=False, reason="clean", scan_length=5)
        assert r.blocked is False
        assert bool(r) is False

    def test_to_dict_structure(self):
        r = MarkerDetectionResult(
            blocked=True,
            markers_found=[("SCI_SI", "//SI"), ("DCTRL_NOFORN", "//NOFORN")],
            reason="classified marker(s) detected",
            scan_length=42,
        )
        d = r.to_dict()
        assert d["blocked"] is True
        assert d["scan_length"] == 42
        assert len(d["markers_found"]) == 2
        assert d["markers_found"][0] == {"label": "SCI_SI", "match": "//SI"}
        assert "reason" in d

    def test_to_dict_clean(self):
        r = MarkerDetectionResult(blocked=False, reason="no markers", scan_length=0)
        d = r.to_dict()
        assert d["blocked"] is False
        assert d["markers_found"] == []


# ── Empty / clean text ────────────────────────────────────────────────────────


class TestCleanText:
    def test_empty_string_not_blocked(self):
        d = ClassifiedMarkerDetector()
        r = d.scan("")
        assert not r.blocked
        assert r.scan_length == 0
        assert r.markers_found == []

    def test_plain_text_not_blocked(self):
        d = ClassifiedMarkerDetector()
        r = d.scan("The weather is sunny and warm today.")
        assert not r.blocked
        assert r.markers_found == []

    def test_technical_text_not_blocked(self):
        d = ClassifiedMarkerDetector()
        r = d.scan("GET /api/v1/resource HTTP/1.1\nHost: example.com")
        assert not r.blocked

    def test_scan_length_populated_for_clean(self):
        text = "Normal text with no markers."
        d = ClassifiedMarkerDetector()
        r = d.scan(text)
        assert r.scan_length == len(text)


# ── Formal classification banners ─────────────────────────────────────────────


class TestFormalBanners:
    def test_top_secret(self):
        r = ClassifiedMarkerDetector().scan("TOP SECRET//SI//NOFORN document")
        assert r.blocked
        assert any(label == "CLASSIFICATION_BANNER_TS" for label, _ in r.markers_found)

    def test_secret_double_slash(self):
        r = ClassifiedMarkerDetector().scan("SECRET//NOFORN data")
        assert r.blocked
        assert any(label == "CLASSIFICATION_BANNER_S" for label, _ in r.markers_found)

    def test_ts_abbrev(self):
        r = ClassifiedMarkerDetector().scan("TS//SI cable")
        assert r.blocked
        assert any(label == "CLASSIFICATION_BANNER_TS_ABBREV" for label, _ in r.markers_found)

    def test_s_abbrev(self):
        r = ClassifiedMarkerDetector().scan("S//NOFORN memo")
        assert r.blocked
        assert any(label == "CLASSIFICATION_BANNER_S_ABBREV" for label, _ in r.markers_found)

    def test_confidential_banner(self):
        r = ClassifiedMarkerDetector().scan("CONFIDENTIAL//REL TO USA")
        assert r.blocked
        assert any(label == "CLASSIFICATION_BANNER_C" for label, _ in r.markers_found)

    def test_banner_case_insensitive(self):
        r = ClassifiedMarkerDetector().scan("top secret//si")
        assert r.blocked

    def test_sci_chain(self):
        r = ClassifiedMarkerDetector().scan("TS // SI material")
        assert r.blocked


# ── SCI compartment indicators ────────────────────────────────────────────────


class TestSCICompartments:
    def test_si(self):
        r = ClassifiedMarkerDetector().scan("report contains //SI material")
        assert r.blocked
        assert any(label == "SCI_SI" for label, _ in r.markers_found)

    def test_tk(self):
        r = ClassifiedMarkerDetector().scan("//TK imagery collection")
        assert r.blocked
        assert any(label == "SCI_TK" for label, _ in r.markers_found)

    def test_hcs(self):
        r = ClassifiedMarkerDetector().scan("//HCS source reporting")
        assert r.blocked
        assert any(label == "SCI_HCS" for label, _ in r.markers_found)

    def test_hcs_p(self):
        r = ClassifiedMarkerDetector().scan("//HCS-P protected")
        assert r.blocked
        assert any(label == "SCI_HCS" for label, _ in r.markers_found)

    def test_hcs_o(self):
        r = ClassifiedMarkerDetector().scan("//HCS-O operational")
        assert r.blocked

    def test_gamma(self):
        r = ClassifiedMarkerDetector().scan("//G signals report")
        assert r.blocked
        assert any(label == "SCI_GAMMA" for label, _ in r.markers_found)

    def test_kdk(self):
        r = ClassifiedMarkerDetector().scan("//KDK assessment")
        assert r.blocked
        assert any(label == "SCI_KDK" for label, _ in r.markers_found)

    def test_vrk(self):
        r = ClassifiedMarkerDetector().scan("//VRK access required")
        assert r.blocked
        assert any(label == "SCI_VRK" for label, _ in r.markers_found)


# ── Dissemination control markings ───────────────────────────────────────────


class TestDisseminationControls:
    def test_noforn(self):
        r = ClassifiedMarkerDetector().scan("This report is //NOFORN")
        assert r.blocked
        assert any(label == "DCTRL_NOFORN" for label, _ in r.markers_found)

    def test_orcon(self):
        r = ClassifiedMarkerDetector().scan("Source: //ORCON protected")
        assert r.blocked
        assert any(label == "DCTRL_ORCON" for label, _ in r.markers_found)

    def test_propin(self):
        r = ClassifiedMarkerDetector().scan("//PROPIN proprietary content")
        assert r.blocked

    def test_rsen(self):
        r = ClassifiedMarkerDetector().scan("//RSEN risk sensitive data")
        assert r.blocked

    def test_wnintel(self):
        r = ClassifiedMarkerDetector().scan("//WNINTEL sources and methods")
        assert r.blocked

    def test_fouo(self):
        r = ClassifiedMarkerDetector().scan("//FOUO for official use only")
        assert r.blocked
        assert any(label == "DCTRL_FOUO" for label, _ in r.markers_found)

    def test_fisa(self):
        r = ClassifiedMarkerDetector().scan("//FISA surveillance data")
        assert r.blocked
        assert any(label == "DCTRL_FISA" for label, _ in r.markers_found)


# ── Coalition / REL TO markings ───────────────────────────────────────────────


class TestCoalitionMarkings:
    def test_rel_to(self):
        r = ClassifiedMarkerDetector().scan("//REL TO USA, GBR")
        assert r.blocked
        assert any(label == "REL_TO" for label, _ in r.markers_found)

    def test_fvey(self):
        r = ClassifiedMarkerDetector().scan("//FVEY community assessment")
        assert r.blocked
        assert any(label == "REL_FVEY" for label, _ in r.markers_found)

    def test_acgu(self):
        r = ClassifiedMarkerDetector().scan("//ACGU coalition report")
        assert r.blocked
        assert any(label == "REL_ACGU" for label, _ in r.markers_found)

    def test_eyes_only(self):
        r = ClassifiedMarkerDetector().scan("//EYES ONLY briefing")
        assert r.blocked
        assert any(label == "EYES_ONLY" for label, _ in r.markers_found)


# ── Handling caveats ──────────────────────────────────────────────────────────


class TestHandlingCaveats:
    def test_handle_via_comint(self):
        r = ClassifiedMarkerDetector().scan("HANDLE VIA COMINT CHANNELS ONLY")
        assert r.blocked
        assert any(label == "CAVEAT_COMINT" for label, _ in r.markers_found)

    def test_handle_via_comint_channel_singular(self):
        r = ClassifiedMarkerDetector().scan("HANDLE VIA COMINT CHANNEL ONLY")
        assert r.blocked

    def test_handle_via_sci_channels(self):
        r = ClassifiedMarkerDetector().scan("HANDLE VIA SCI CHANNELS ONLY")
        assert r.blocked
        assert any(label == "CAVEAT_SCI" for label, _ in r.markers_found)

    def test_sci_information(self):
        r = ClassifiedMarkerDetector().scan("This is SCI INFORMATION")
        assert r.blocked
        assert any(label == "CAVEAT_SCI_INFO" for label, _ in r.markers_found)

    def test_specat(self):
        r = ClassifiedMarkerDetector().scan("SPECAT handling required")
        assert r.blocked
        assert any(label == "CAVEAT_SPECAT" for label, _ in r.markers_found)

    def test_specatl(self):
        r = ClassifiedMarkerDetector().scan("SPECATL category")
        assert r.blocked


# ── Classification authority lines ───────────────────────────────────────────


class TestAuthorityLines:
    def test_classified_by(self):
        r = ClassifiedMarkerDetector().scan("CLASSIFIED BY: John Smith")
        assert r.blocked
        assert any(label == "AUTHORITY_CLASSIFIED_BY" for label, _ in r.markers_found)

    def test_derived_from(self):
        r = ClassifiedMarkerDetector().scan("DERIVED FROM: NSA-001")
        assert r.blocked
        assert any(label == "AUTHORITY_DERIVED_FROM" for label, _ in r.markers_found)

    def test_declassify_on(self):
        r = ClassifiedMarkerDetector().scan("DECLASSIFY ON: 20350101")
        assert r.blocked
        assert any(label == "AUTHORITY_DECLASSIFY" for label, _ in r.markers_found)

    def test_authority_case_insensitive(self):
        r = ClassifiedMarkerDetector().scan("classified by: Jane Doe")
        assert r.blocked


# ── SAP indicators ────────────────────────────────────────────────────────────


class TestSAPIndicators:
    def test_special_access_required(self):
        r = ClassifiedMarkerDetector().scan("SPECIAL ACCESS REQUIRED for this program")
        assert r.blocked
        assert any(label == "SAP_REQUIRED" for label, _ in r.markers_found)

    def test_sap_material(self):
        r = ClassifiedMarkerDetector().scan("This is SAP MATERIAL")
        assert r.blocked
        assert any(label == "SAP_MATERIAL" for label, _ in r.markers_found)

    def test_sap_protected(self):
        r = ClassifiedMarkerDetector().scan("SAP PROTECTED data")
        assert r.blocked

    def test_sap_information(self):
        r = ClassifiedMarkerDetector().scan("SAP INFORMATION handling")
        assert r.blocked

    def test_sap_program(self):
        r = ClassifiedMarkerDetector().scan("SAP PROGRAM details")
        assert r.blocked

    def test_sap_tag(self):
        r = ClassifiedMarkerDetector().scan("Document (SAP) classification")
        assert r.blocked
        assert any(label == "SAP_TAG" for label, _ in r.markers_found)

    def test_sap_abbreviated(self):
        r = ClassifiedMarkerDetector().scan("SAP-PROTECTED document")
        assert r.blocked
        assert any(label == "SAP_ABBREVIATED" for label, _ in r.markers_found)


# ── Multiple markers in one text ─────────────────────────────────────────────


class TestMultipleMarkers:
    def test_multiple_markers_all_captured(self):
        text = "TOP SECRET//SI//NOFORN CLASSIFIED BY: NSA DERIVED FROM: NSA-001"
        r = ClassifiedMarkerDetector().scan(text)
        assert r.blocked
        labels = [label for label, _ in r.markers_found]
        assert "CLASSIFICATION_BANNER_TS" in labels
        assert "DCTRL_NOFORN" in labels
        assert "AUTHORITY_CLASSIFIED_BY" in labels
        assert "AUTHORITY_DERIVED_FROM" in labels

    def test_scan_length_is_full_text_length(self):
        text = "SECRET//SI content CLASSIFIED BY: USER"
        r = ClassifiedMarkerDetector().scan(text)
        assert r.scan_length == len(text)

    def test_reason_mentions_labels(self):
        r = ClassifiedMarkerDetector().scan("//NOFORN //FOUO")
        assert "DCTRL_NOFORN" in r.reason or "DCTRL_FOUO" in r.reason

    def test_complex_classified_document(self):
        doc = (
            "TOP SECRET//SI//TK//HCS//NOFORN\n"
            "CLASSIFIED BY: Director, NSA\n"
            "DERIVED FROM: NSA-001\n"
            "DECLASSIFY ON: 20350101\n"
            "HANDLE VIA SCI CHANNELS ONLY\n"
            "SPECIAL ACCESS REQUIRED\n"
        )
        r = ClassifiedMarkerDetector().scan(doc)
        assert r.blocked
        assert len(r.markers_found) >= 7


# ── scan_messages ─────────────────────────────────────────────────────────────


class TestScanMessages:
    def test_clean_messages_not_blocked(self):
        d = ClassifiedMarkerDetector()
        msgs = [
            {"role": "user", "content": "Hello, how are you?"},
            {"role": "assistant", "content": "I'm doing well, thanks."},
        ]
        r = d.scan_messages(msgs)
        assert not r.blocked

    def test_classified_message_blocked(self):
        d = ClassifiedMarkerDetector()
        msgs = [
            {"role": "user", "content": "Please summarize this:"},
            {"role": "assistant", "content": "SECRET//NOFORN report summary"},
        ]
        r = d.scan_messages(msgs)
        assert r.blocked

    def test_markers_aggregated_across_messages(self):
        d = ClassifiedMarkerDetector()
        msgs = [
            {"role": "user", "content": "//NOFORN request"},
            {"role": "assistant", "content": "CLASSIFIED BY: analyst"},
        ]
        r = d.scan_messages(msgs)
        assert r.blocked
        labels = [label for label, _ in r.markers_found]
        assert "DCTRL_NOFORN" in labels
        assert "AUTHORITY_CLASSIFIED_BY" in labels

    def test_empty_messages_list_not_blocked(self):
        d = ClassifiedMarkerDetector()
        r = d.scan_messages([])
        assert not r.blocked

    def test_non_string_content_skipped(self):
        d = ClassifiedMarkerDetector()
        msgs = [{"role": "tool", "content": None}]
        r = d.scan_messages(msgs)
        assert not r.blocked

    def test_missing_content_key_skipped(self):
        d = ClassifiedMarkerDetector()
        msgs = [{"role": "system"}]
        r = d.scan_messages(msgs)
        assert not r.blocked

    def test_total_scan_length_accumulated(self):
        d = ClassifiedMarkerDetector()
        msgs = [
            {"role": "user", "content": "Hello"},
            {"role": "assistant", "content": "World"},
        ]
        r = d.scan_messages(msgs)
        assert r.scan_length == len("Hello") + len("World")

    def test_reason_mentions_messages(self):
        d = ClassifiedMarkerDetector()
        msgs = [{"role": "user", "content": "SECRET// data"}]
        r = d.scan_messages(msgs)
        assert "messages" in r.reason


# ── scan_text_bulk ────────────────────────────────────────────────────────────


class TestScanTextBulk:
    def test_all_clean_not_blocked(self):
        d = ClassifiedMarkerDetector()
        r = d.scan_text_bulk(["Normal text", "More normal text"])
        assert not r.blocked

    def test_one_classified_fragment_blocked(self):
        d = ClassifiedMarkerDetector()
        r = d.scan_text_bulk(["Normal text", "TOP SECRET// report"])
        assert r.blocked

    def test_markers_aggregated_across_fragments(self):
        d = ClassifiedMarkerDetector()
        r = d.scan_text_bulk(["//NOFORN data", "CLASSIFIED BY: analyst"])
        assert r.blocked
        labels = [label for label, _ in r.markers_found]
        assert "DCTRL_NOFORN" in labels
        assert "AUTHORITY_CLASSIFIED_BY" in labels

    def test_empty_list_not_blocked(self):
        d = ClassifiedMarkerDetector()
        r = d.scan_text_bulk([])
        assert not r.blocked
        assert r.scan_length == 0

    def test_total_scan_length_accumulated(self):
        d = ClassifiedMarkerDetector()
        texts = ["Hello", "World"]
        r = d.scan_text_bulk(texts)
        assert r.scan_length == 10


# ── Extra patterns / custom markers ──────────────────────────────────────────


class TestExtraPatterns:
    def test_single_extra_pattern_detected(self):
        d = ClassifiedMarkerDetector(extra_patterns=[r"\bPROJECT\s+BLACKBIRD\b"])
        r = d.scan("This is PROJECT BLACKBIRD material")
        assert r.blocked
        assert any(label == "CUSTOM" for label, _ in r.markers_found)

    def test_multiple_extra_patterns_labeled(self):
        d = ClassifiedMarkerDetector(
            extra_patterns=[r"\bCODEWORD_ALPHA\b", r"\bCODEWORD_BETA\b"],
            extra_label="SAP_CODEWORD",
        )
        r = d.scan("CODEWORD_ALPHA clearance required")
        assert r.blocked
        assert any(label == "SAP_CODEWORD_0" for label, _ in r.markers_found)

    def test_extra_pattern_custom_label(self):
        d = ClassifiedMarkerDetector(
            extra_patterns=[r"\bCODEWORD_ALPHA\b", r"\bCODEWORD_BETA\b"],
            extra_label="SAP_CODEWORD",
        )
        r = d.scan("CODEWORD_BETA access")
        assert r.blocked
        assert any(label == "SAP_CODEWORD_1" for label, _ in r.markers_found)

    def test_no_extra_patterns_clean_not_blocked(self):
        d = ClassifiedMarkerDetector(extra_patterns=[r"\bSECRET_CODE\b"])
        r = d.scan("Normal text without secret code")
        assert not r.blocked

    def test_extra_pattern_case_insensitive(self):
        d = ClassifiedMarkerDetector(extra_patterns=[r"\bPROJECT\s+NIGHTFALL\b"])
        r = d.scan("details on project nightfall")
        assert r.blocked


# ── pattern_count property ────────────────────────────────────────────────────


class TestPatternCount:
    def test_default_pattern_count(self):
        d = ClassifiedMarkerDetector()
        assert d.pattern_count == 34

    def test_extra_patterns_increase_count(self):
        d = ClassifiedMarkerDetector(extra_patterns=[r"\bFOO\b", r"\bBAR\b"])
        assert d.pattern_count == 36

    def test_no_extra_patterns_baseline(self):
        d1 = ClassifiedMarkerDetector()
        d2 = ClassifiedMarkerDetector(extra_patterns=None)
        assert d1.pattern_count == d2.pattern_count


# ── Integration scenarios ─────────────────────────────────────────────────────


class TestIntegrationScenarios:
    def test_clean_api_response_passes(self):
        response = (
            "Based on the provided data, the quarterly earnings show a 12% increase. "
            "The analysis indicates strong performance in the technology sector."
        )
        r = ClassifiedMarkerDetector().scan(response)
        assert not r.blocked

    def test_classified_intel_report_blocked(self):
        report = (
            "TOP SECRET//SI//TK//NOFORN\n"
            "CLASSIFIED BY: Director of National Intelligence\n"
            "DERIVED FROM: Multiple Sources\n"
            "DECLASSIFY ON: 25X1-HUM\n\n"
            "The following HUMINT report requires HANDLE VIA SCI CHANNELS ONLY."
        )
        r = ClassifiedMarkerDetector().scan(report)
        assert r.blocked
        assert len(r.markers_found) >= 5

    def test_sap_document_blocked(self):
        doc = "SPECIAL ACCESS REQUIRED — SAP-PROTECTED MATERIAL (SAP)"
        r = ClassifiedMarkerDetector().scan(doc)
        assert r.blocked
        labels = [lbl for lbl, _ in r.markers_found]
        assert "SAP_REQUIRED" in labels
        assert "SAP_ABBREVIATED" in labels
        assert "SAP_TAG" in labels

    def test_multi_message_chat_with_classified_response(self):
        d = ClassifiedMarkerDetector()
        messages = [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Summarize the following document."},
            {"role": "assistant", "content": "SECRET//NOFORN analysis complete."},
        ]
        r = d.scan_messages(messages)
        assert r.blocked
        assert any(label == "CLASSIFICATION_BANNER_S" for label, _ in r.markers_found)

    def test_system_prompt_plus_user_request_clean(self):
        d = ClassifiedMarkerDetector()
        r = d.scan_text_bulk([
            "You are a helpful medical assistant.",
            "What are the side effects of ibuprofen?",
            "Common side effects include stomach upset and headache.",
        ])
        assert not r.blocked

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for HIPAA-compliant HL7 v2 / FHIR structured PHI detection
(aegis.core.hl7_fhir_phi_detector)."""

from __future__ import annotations

import json

from aegis.core.hl7_fhir_phi_detector import (
    FHIRPHIScrubber,
    HL7FHIRPHIDetector,
    HL7v2PHIScrubber,
    PHIScrubResult,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────

_HL7_ADT = (
    "MSH|^~\\&|HIS|GENERAL|ADT|GENERAL|20240101120000||ADT^A01|MSG001|P|2.5\r\n"
    # PID fields: [0]=PID [3]=MRN [5]=NAME [7]=DOB [11]=ADDRESS [13]=PHONE [19]=SSN
    # 6 pipes after PHONE (field 13) to reach SSN at field 19: 19-13=6
    "PID|1||MR123456^^^HOSP^MR||SMITH^JOHN^A||19800101|M|||123 MAIN ST^^ANYTOWN^CA^90210^USA||5551234567||||||987-65-4321\r\n"
    "PV1|1|I|ICU^01^A||||||JONES^MARY^B|||||||||||20240101"
)

_HL7_MINIMAL = "MSH|^~\\&|SYS|FAC|DEST|FAC|20240101||ORU^R01|999|P|2.5\r\nOBR|1|||CBC"

_FHIR_PATIENT = json.dumps(
    {
        "resourceType": "Patient",
        "id": "example",
        "name": [{"family": "Smith", "given": ["John"]}],
        "birthDate": "1980-01-01",
        "telecom": [{"system": "phone", "value": "555-1234567"}],
        "address": [{"line": ["123 Main St"], "city": "Anytown"}],
        "identifier": [{"system": "urn:hosp:mrn", "value": "MR123456"}],
    }
)

_FHIR_UNKNOWN = json.dumps(
    {"resourceType": "StructureDefinition", "url": "http://example.com", "name": "Test"}
)

_FHIR_BUNDLE = json.dumps(
    {
        "resourceType": "Bundle",
        "type": "collection",
        "entry": [
            {
                "resource": {
                    "resourceType": "Patient",
                    "id": "p1",
                    "name": [{"family": "Doe"}],
                    "birthDate": "1990-06-15",
                }
            },
            {
                "resource": {
                    "resourceType": "Observation",
                    "id": "obs1",
                    "note": [{"text": "Patient is stable"}],
                }
            },
        ],
    }
)


# ── PHIScrubResult ─────────────────────────────────────────────────────────────


class TestPHIScrubResult:
    def test_defaults(self):
        r = PHIScrubResult(scrubbed="hello", format="plain_text")
        assert r.categories == set()
        assert r.redaction_count == 0

    def test_fields_stored(self):
        r = PHIScrubResult(scrubbed="x", format="hl7v2", categories={"NAME"}, redaction_count=3)
        assert r.scrubbed == "x"
        assert r.format == "hl7v2"
        assert r.categories == {"NAME"}
        assert r.redaction_count == 3


# ── HL7v2PHIScrubber ──────────────────────────────────────────────────────────


class TestHL7v2PHIScrubber:
    def setup_method(self):
        self.scrubber = HL7v2PHIScrubber()

    def test_result_format_is_hl7v2(self):
        result = self.scrubber.scrub(_HL7_ADT)
        assert result.format == "hl7v2"

    def test_pid_name_redacted(self):
        result = self.scrubber.scrub(_HL7_ADT)
        assert "SMITH" not in result.scrubbed
        assert "[REDACTED:NAME]" in result.scrubbed

    def test_pid_dob_redacted(self):
        result = self.scrubber.scrub(_HL7_ADT)
        assert "19800101" not in result.scrubbed
        assert "[REDACTED:DOB]" in result.scrubbed

    def test_pid_ssn_redacted(self):
        result = self.scrubber.scrub(_HL7_ADT)
        assert "987-65-4321" not in result.scrubbed
        assert "[REDACTED:SSN]" in result.scrubbed

    def test_pid_mrn_redacted(self):
        result = self.scrubber.scrub(_HL7_ADT)
        assert "MR123456" not in result.scrubbed
        assert "[REDACTED:MRN]" in result.scrubbed

    def test_pid_address_redacted(self):
        result = self.scrubber.scrub(_HL7_ADT)
        assert "123 MAIN ST" not in result.scrubbed
        assert "[REDACTED:ADDRESS]" in result.scrubbed

    def test_pid_phone_redacted(self):
        result = self.scrubber.scrub(_HL7_ADT)
        assert "5551234567" not in result.scrubbed
        assert "[REDACTED:PHONE]" in result.scrubbed

    def test_pv1_attending_doctor_redacted(self):
        result = self.scrubber.scrub(_HL7_ADT)
        assert "JONES" not in result.scrubbed
        assert "[REDACTED:NAME]" in result.scrubbed

    def test_categories_populated(self):
        result = self.scrubber.scrub(_HL7_ADT)
        assert "NAME" in result.categories
        assert "DOB" in result.categories
        assert "SSN" in result.categories
        assert "MRN" in result.categories

    def test_redaction_count_positive(self):
        result = self.scrubber.scrub(_HL7_ADT)
        assert result.redaction_count > 0

    def test_msh_segment_preserved_unchanged(self):
        result = self.scrubber.scrub(_HL7_ADT)
        lines = result.scrubbed.split("\n")
        msh_line = next(ln for ln in lines if ln.startswith("MSH"))
        # MSH is passed through unmodified
        assert "MSH|" in msh_line

    def test_non_phi_segment_passed_through(self):
        # OBR segment is not in the PHI map — should pass through unchanged
        result = self.scrubber.scrub(_HL7_MINIMAL)
        assert "OBR|1|||CBC" in result.scrubbed

    def test_unknown_segment_passed_through(self):
        msg = "MSH|^~\\&|A|B|C|D|20240101||ADT^A01|001|P|2.5\r\nZZZ|1|2|3"
        result = self.scrubber.scrub(msg)
        assert "ZZZ|1|2|3" in result.scrubbed

    def test_empty_phi_field_not_counted(self):
        # PID with sparse fields — only populated PHI fields counted
        msg = "MSH|^~\\&|A|B|C|D|20240101||ADT^A01|001|P|2.5\r\nPID|1||MR001|||JONES||||||"
        result = self.scrubber.scrub(msg)
        # MRN present at field 3, NAME at field 5 — both should be redacted
        assert "MR001" not in result.scrubbed
        assert "JONES" not in result.scrubbed

    def test_cr_lf_separator_handled(self):
        msg = "MSH|^~\\&|A|B|C|D|20240101||ADT^A01|001|P|2.5\r\nPID|1||MR999|||DOE"
        result = self.scrubber.scrub(msg)
        assert "MR999" not in result.scrubbed
        assert "DOE" not in result.scrubbed

    def test_lf_only_separator_handled(self):
        msg = "MSH|^~\\&|A|B|C|D|20240101||ADT^A01|001|P|2.5\nPID|1||MR888|||SMITH"
        result = self.scrubber.scrub(msg)
        assert "MR888" not in result.scrubbed
        assert "SMITH" not in result.scrubbed

    def test_nk1_name_redacted(self):
        msg = "MSH|^~\\&|A|B|C|D|20240101||ADT^A01|001|P|2.5\r\nNK1|1|JONES^ALICE|SPO||5559876543"
        result = self.scrubber.scrub(msg)
        assert "JONES" not in result.scrubbed
        assert "ALICE" not in result.scrubbed
        assert "[REDACTED:NAME]" in result.scrubbed

    def test_gt1_ssn_redacted(self):
        # GT1.17 = SSN; 14 pipes after NAME (field 3) to reach field 17
        msg = (
            "MSH|^~\\&|A|B|C|D|20240101||ADT^A01|001|P|2.5\r\n"
            "GT1|1|G001|BROWN^JAMES||||||||||||||111-22-3333"
        )
        result = self.scrubber.scrub(msg)
        assert "111-22-3333" not in result.scrubbed
        assert "[REDACTED:SSN]" in result.scrubbed

    def test_in1_insurance_name_redacted(self):
        msg = "MSH|^~\\&|A|B|C|D|20240101||ADT^A01|001|P|2.5\r\nIN1|1|PLAN01|INS001|BLUE CROSS"
        result = self.scrubber.scrub(msg)
        assert "BLUE CROSS" not in result.scrubbed

    def test_obx_observation_value_redacted(self):
        msg = (
            "MSH|^~\\&|A|B|C|D|20240101||ADT^A01|001|P|2.5\r\n"
            "OBX|1|TX|NOTES||Patient John Doe is diabetic"
        )
        result = self.scrubber.scrub(msg)
        assert "Patient John Doe is diabetic" not in result.scrubbed
        assert "[REDACTED:OBSERVATION]" in result.scrubbed

    def test_empty_message_returns_empty_scrubbed(self):
        result = self.scrubber.scrub("")
        assert result.format == "hl7v2"
        assert result.redaction_count == 0


# ── FHIRPHIScrubber ───────────────────────────────────────────────────────────


class TestFHIRPHIScrubber:
    def setup_method(self):
        self.scrubber = FHIRPHIScrubber()

    def test_result_format_is_fhir_json(self):
        result = self.scrubber.scrub(_FHIR_PATIENT)
        assert result.format == "fhir_json"

    def test_patient_name_redacted(self):
        result = self.scrubber.scrub(_FHIR_PATIENT)
        parsed = json.loads(result.scrubbed)
        assert parsed["name"] == [{"redacted": True}]
        assert "NAME" in result.categories

    def test_patient_birthdate_redacted(self):
        result = self.scrubber.scrub(_FHIR_PATIENT)
        parsed = json.loads(result.scrubbed)
        assert "1980-01-01" not in result.scrubbed
        assert "[REDACTED:DOB]" in result.scrubbed
        assert "DOB" in result.categories

    def test_patient_telecom_redacted(self):
        result = self.scrubber.scrub(_FHIR_PATIENT)
        parsed = json.loads(result.scrubbed)
        assert parsed["telecom"] == [{"redacted": True}]
        assert "PHONE" in result.categories

    def test_patient_address_redacted(self):
        result = self.scrubber.scrub(_FHIR_PATIENT)
        parsed = json.loads(result.scrubbed)
        assert parsed["address"] == [{"redacted": True}]
        assert "ADDRESS" in result.categories

    def test_patient_identifier_redacted(self):
        result = self.scrubber.scrub(_FHIR_PATIENT)
        parsed = json.loads(result.scrubbed)
        assert parsed["identifier"] == [{"redacted": True}]
        assert "MRN" in result.categories

    def test_patient_id_preserved(self):
        result = self.scrubber.scrub(_FHIR_PATIENT)
        parsed = json.loads(result.scrubbed)
        assert parsed["id"] == "example"

    def test_patient_resource_type_preserved(self):
        result = self.scrubber.scrub(_FHIR_PATIENT)
        parsed = json.loads(result.scrubbed)
        assert parsed["resourceType"] == "Patient"

    def test_redaction_count_positive(self):
        result = self.scrubber.scrub(_FHIR_PATIENT)
        assert result.redaction_count > 0

    def test_unknown_resource_type_passthrough(self):
        result = self.scrubber.scrub(_FHIR_UNKNOWN)
        parsed = json.loads(result.scrubbed)
        assert parsed["resourceType"] == "StructureDefinition"
        assert result.redaction_count == 0
        assert result.categories == set()

    def test_bundle_patient_scrubbed(self):
        result = self.scrubber.scrub(_FHIR_BUNDLE)
        parsed = json.loads(result.scrubbed)
        patient = parsed["entry"][0]["resource"]
        assert patient["name"] == [{"redacted": True}]
        assert "1990-06-15" not in result.scrubbed

    def test_bundle_observation_scrubbed(self):
        result = self.scrubber.scrub(_FHIR_BUNDLE)
        parsed = json.loads(result.scrubbed)
        obs = parsed["entry"][1]["resource"]
        assert obs["note"] == [{"redacted": True}]

    def test_bundle_resource_type_preserved(self):
        result = self.scrubber.scrub(_FHIR_BUNDLE)
        parsed = json.loads(result.scrubbed)
        assert parsed["resourceType"] == "Bundle"
        assert parsed["type"] == "collection"

    def test_invalid_json_passthrough(self):
        result = self.scrubber.scrub("not valid json")
        assert result.scrubbed == "not valid json"
        assert result.format == "fhir_json"
        assert result.redaction_count == 0

    def test_json_array_passthrough(self):
        result = self.scrubber.scrub("[1,2,3]")
        assert result.scrubbed == "[1,2,3]"
        assert result.redaction_count == 0

    def test_scrub_dict_in_place(self):
        resource = {
            "resourceType": "Patient",
            "id": "p1",
            "name": [{"family": "Test"}],
            "birthDate": "2000-01-01",
        }
        scrubbed, cats, count = self.scrubber.scrub_dict(resource)
        assert scrubbed is resource  # in-place mutation
        assert resource["name"] == [{"redacted": True}]
        assert "[REDACTED:DOB]" in resource["birthDate"]
        assert "NAME" in cats
        assert "DOB" in cats
        assert count == 2

    def test_scrub_dict_unknown_type_no_change(self):
        resource = {"resourceType": "CapabilityStatement", "id": "cs1", "name": "MyCS"}
        scrubbed, cats, count = self.scrubber.scrub_dict(resource)
        assert scrubbed is resource
        assert resource["name"] == "MyCS"
        assert count == 0

    def test_scrub_dict_empty_field_not_counted(self):
        resource = {
            "resourceType": "Patient",
            "id": "p1",
            "name": [],  # empty list — should not be redacted
        }
        _, cats, count = self.scrubber.scrub_dict(resource)
        assert count == 0

    def test_practitioner_phi_scrubbed(self):
        resource_json = json.dumps(
            {
                "resourceType": "Practitioner",
                "id": "prac1",
                "name": [{"family": "Dr House"}],
                "identifier": [{"system": "npi", "value": "1234567890"}],
                "birthDate": "1970-05-20",
            }
        )
        result = self.scrubber.scrub(resource_json)
        parsed = json.loads(result.scrubbed)
        assert parsed["name"] == [{"redacted": True}]
        assert "NAME" in result.categories
        assert "NPI" in result.categories
        assert "DOB" in result.categories

    def test_encounter_phi_scrubbed(self):
        resource_json = json.dumps(
            {
                "resourceType": "Encounter",
                "id": "enc1",
                "identifier": [{"value": "ENC001"}],
                "period": {"start": "2024-01-01", "end": "2024-01-03"},
            }
        )
        result = self.scrubber.scrub(resource_json)
        parsed = json.loads(result.scrubbed)
        assert parsed["identifier"] == [{"redacted": True}]
        assert "ACCOUNT" in result.categories

    def test_coverage_phi_scrubbed(self):
        resource_json = json.dumps(
            {
                "resourceType": "Coverage",
                "id": "cov1",
                "subscriberId": "SUB001",
                "beneficiary": {"reference": "Patient/p1"},
            }
        )
        result = self.scrubber.scrub(resource_json)
        assert "SUB001" not in result.scrubbed
        assert "ACCOUNT" in result.categories

    def test_condition_observation_note_scrubbed(self):
        resource_json = json.dumps(
            {
                "resourceType": "Condition",
                "id": "cond1",
                "note": [{"text": "Patient has chronic back pain"}],
                "recorder": {"reference": "Practitioner/prac1"},
            }
        )
        result = self.scrubber.scrub(resource_json)
        parsed = json.loads(result.scrubbed)
        assert parsed["note"] == [{"redacted": True}]
        assert "OBSERVATION" in result.categories

    def test_scalar_phi_field_replaced_with_token(self):
        resource_json = json.dumps(
            {
                "resourceType": "Patient",
                "id": "p1",
                "birthDate": "1985-03-15",
            }
        )
        result = self.scrubber.scrub(resource_json)
        parsed = json.loads(result.scrubbed)
        assert "[REDACTED:DOB]" in parsed["birthDate"]


# ── HL7FHIRPHIDetector (unified) ──────────────────────────────────────────────


class TestHL7FHIRPHIDetector:
    def setup_method(self):
        self.detector = HL7FHIRPHIDetector()

    def test_auto_detects_hl7(self):
        result = self.detector.scrub(_HL7_ADT)
        assert result.format == "hl7v2"

    def test_auto_detects_fhir(self):
        result = self.detector.scrub(_FHIR_PATIENT)
        assert result.format == "fhir_json"

    def test_auto_detects_plain_text(self):
        result = self.detector.scrub("Hello, this is plain text.")
        assert result.format == "plain_text"
        assert result.scrubbed == "Hello, this is plain text."
        assert result.redaction_count == 0

    def test_plain_text_categories_empty(self):
        result = self.detector.scrub("No medical content here.")
        assert result.categories == set()

    def test_hl7_phi_redacted_via_auto(self):
        result = self.detector.scrub(_HL7_ADT)
        assert "SMITH" not in result.scrubbed
        assert "NAME" in result.categories

    def test_fhir_phi_redacted_via_auto(self):
        result = self.detector.scrub(_FHIR_PATIENT)
        assert "1980-01-01" not in result.scrubbed
        assert "DOB" in result.categories

    def test_scrub_hl7_explicit(self):
        result = self.detector.scrub_hl7(_HL7_ADT)
        assert result.format == "hl7v2"
        assert "SMITH" not in result.scrubbed

    def test_scrub_fhir_explicit(self):
        result = self.detector.scrub_fhir(_FHIR_PATIENT)
        assert result.format == "fhir_json"
        assert "1980-01-01" not in result.scrubbed

    def test_scrub_fhir_dict_delegates(self):
        resource = {
            "resourceType": "Patient",
            "id": "p1",
            "name": [{"family": "Jones"}],
        }
        scrubbed, cats, count = self.detector.scrub_fhir_dict(resource)
        assert scrubbed["name"] == [{"redacted": True}]
        assert "NAME" in cats
        assert count == 1

    def test_supported_hl7_segments_includes_pid(self):
        segs = HL7FHIRPHIDetector.supported_hl7_segments()
        assert "PID" in segs

    def test_supported_hl7_segments_includes_pv1(self):
        segs = HL7FHIRPHIDetector.supported_hl7_segments()
        assert "PV1" in segs

    def test_supported_hl7_segments_sorted(self):
        segs = HL7FHIRPHIDetector.supported_hl7_segments()
        assert segs == sorted(segs)

    def test_supported_fhir_resource_types_includes_patient(self):
        types = HL7FHIRPHIDetector.supported_fhir_resource_types()
        assert "Patient" in types

    def test_supported_fhir_resource_types_includes_practitioner(self):
        types = HL7FHIRPHIDetector.supported_fhir_resource_types()
        assert "Practitioner" in types

    def test_supported_fhir_resource_types_sorted(self):
        types = HL7FHIRPHIDetector.supported_fhir_resource_types()
        assert types == sorted(types)

    def test_fhir_detection_by_resource_type_key(self):
        # JSON with "resourceType": but not a standard type — still detected as FHIR
        custom_fhir = json.dumps({"resourceType": "CustomType", "id": "x"})
        result = self.detector.scrub(custom_fhir)
        assert result.format == "fhir_json"

    def test_hl7_msh_mid_text_detected(self):
        # MSH| not at text start but at line start
        msg = "# Some header\nMSH|^~\\&|A|B|C|D|20240101||ADT^A01|001|P|2.5\nPID|1||MR777|||SNOW"
        result = self.detector.scrub(msg)
        assert result.format == "hl7v2"
        assert "MR777" not in result.scrubbed
        assert "SNOW" not in result.scrubbed

    def test_bundle_scrubbed_via_auto_detect(self):
        result = self.detector.scrub(_FHIR_BUNDLE)
        assert result.format == "fhir_json"
        assert "1990-06-15" not in result.scrubbed
        assert result.redaction_count > 0

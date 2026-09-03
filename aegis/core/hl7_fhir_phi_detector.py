# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.hl7_fhir_phi_detector — HL7 v2 / FHIR structured PHI detection.

Extends the best-effort regex approach in :mod:`aegis.core.phi_deidentifier`
with **structure-aware** de-identification for the two dominant clinical
message formats:

- **HL7 v2**: pipe-delimited messages.  PHI is redacted by *segment+field
  position* (e.g. PID-5 = patient name, PID-19 = SSN) rather than by
  pattern-scanning the full text — catching identifiers that generic regex
  would miss because they lack the expected surrounding tokens.
- **FHIR (R4 / R5)**: JSON resources.  PHI is redacted by *resource-type +
  JSON field path* (e.g. ``Patient.name``, ``Patient.birthDate``) so that
  structured values are scrubbed even when they lack the formatting cues regex
  depends on.

Regulatory basis
-----------------
- **HIPAA Privacy Rule 45 CFR § 164.514(b)**: a review reference only; complete
  Safe Harbor or Expert Determination is not established by these field rules.
- **HIPAA Security Rule 45 CFR § 164.312**: technical safeguards; de-ID is
  a recognised implementation specification.
- **EU GDPR Recital 26 / Art. 25**: de-identification as a privacy-by-design
  measure for health data.
- **HL7 v2.9 / IHE PIX-PDQ**: standard used in US hospital ADT/lab/order
  messages; HIPAA-covered entities transmit PHI in specific field positions.
- **HL7 FHIR R4 (US Core IG)**: standard for EHR interoperability; HIPAA
  PHI maps to specific FHIR resource paths defined by the US Core profiles.

Usage::

    from aegis.core.hl7_fhir_phi_detector import HL7FHIRPHIDetector

    detector = HL7FHIRPHIDetector()

    # HL7 v2 message
    result = detector.scrub(hl7_message_string)
    print(result.scrubbed)   # PHI fields replaced with [REDACTED:CATEGORY]
    print(result.categories) # {"NAME", "DOB", "SSN", ...}

    # FHIR Patient JSON
    result = detector.scrub(fhir_patient_json_string)
    print(result.scrubbed)   # PHI paths nulled/redacted
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

# ── Constants ─────────────────────────────────────────────────────────────────

# HL7 v2: segment → {1-based field index → PHI category}
# Field indices follow the HL7 v2.9 standard segment definitions.
_HL7_PHI_FIELDS: dict[str, dict[int, str]] = {
    "PID": {
        2: "MRN",  # Patient ID (external)
        3: "MRN",  # Patient identifier list
        4: "MRN",  # Alternate patient ID
        5: "NAME",  # Patient name (family^given^middle)
        6: "NAME",  # Mother's maiden name
        7: "DOB",  # Date of birth
        9: "NAME",  # Patient alias
        11: "ADDRESS",  # Patient address
        12: "COUNTY",  # County code
        13: "PHONE",  # Phone number – home
        14: "PHONE",  # Phone number – business
        18: "ACCOUNT",  # Patient account number
        19: "SSN",  # Social security number
        20: "LICENSE",  # Driver's license number
        21: "NAME",  # Mother's identifier
        22: "ETHNICITY",  # Ethnic group (may be PHI in context)
        26: "NATIONALITY",
        29: "DATE",  # Patient death date
        33: "LOCATION",  # Last update facility
    },
    "PV1": {
        3: "LOCATION",  # Assigned patient location
        6: "LOCATION",  # Prior patient location
        7: "NAME",  # Attending doctor
        8: "NAME",  # Referring doctor
        9: "NAME",  # Consulting doctor
        17: "NAME",  # Admitting doctor
        19: "ACCOUNT",  # Visit number
        44: "DATE",  # Admit date/time
        45: "DATE",  # Discharge date/time
    },
    "PV2": {
        1: "LOCATION",  # Prior pending location
    },
    "NK1": {
        2: "NAME",  # Next of kin name
        4: "ADDRESS",  # Address
        5: "PHONE",  # Phone number
        6: "PHONE",  # Business phone
        13: "DATE",  # Date of birth
        14: "NAME",  # Organization name
        30: "NAME",  # Contact person's name
        31: "PHONE",  # Contact person's telephone
        32: "ADDRESS",  # Contact person's address
    },
    "IN1": {
        2: "ACCOUNT",  # Insurance plan ID
        4: "NAME",  # Insurance company name
        5: "ADDRESS",  # Insurance company address
        7: "PHONE",  # Insurance company phone
        11: "ACCOUNT",  # Group number
        12: "NAME",  # Group name
        16: "NAME",  # Name of insured
        18: "DATE",  # Insured's date of birth
        19: "ADDRESS",  # Insured's address
        22: "ACCOUNT",  # Coordination of benefits
        26: "DATE",  # Plan effective date
        27: "DATE",  # Plan expiration date
        36: "ACCOUNT",  # Policy number
        49: "ACCOUNT",  # Insured's employee ID
    },
    "GT1": {
        3: "NAME",  # Guarantor name
        5: "ADDRESS",  # Guarantor address
        6: "PHONE",  # Guarantor phone – home
        7: "PHONE",  # Guarantor phone – business
        8: "DATE",  # Guarantor date of birth
        17: "SSN",  # Guarantor SSN
    },
    "AL1": {
        3: "DIAGNOSIS",  # Allergen code/mnemonic (clinical, not PHI per se, but retained for completeness)
    },
    "DG1": {
        3: "DIAGNOSIS",  # Diagnosis code
    },
    "OBX": {
        5: "OBSERVATION",  # Observation value (may contain narrative PHI)
    },
    "MSH": {
        4: "FACILITY",  # Sending facility
        6: "FACILITY",  # Receiving facility
    },
    "EVN": {
        5: "NAME",  # Operator ID
    },
    "PRD": {
        2: "NAME",  # Provider name
        3: "ADDRESS",  # Provider address
        5: "PHONE",  # Provider phone
    },
}

# FHIR R4: resource type → set of dot-notation field paths containing PHI
# Paths are relative to the resource root; nested paths use "." notation.
_FHIR_PHI_PATHS: dict[str, dict[str, str]] = {
    "Patient": {
        "name": "NAME",
        "telecom": "PHONE",
        "birthDate": "DOB",
        "deceasedDateTime": "DATE",
        "address": "ADDRESS",
        "photo": "PHOTO",
        "contact": "NAME",  # contact.name, contact.telecom, contact.address
        "identifier": "MRN",
        "generalPractitioner": "NAME",
        "link": "MRN",
    },
    "Practitioner": {
        "name": "NAME",
        "telecom": "PHONE",
        "address": "ADDRESS",
        "photo": "PHOTO",
        "identifier": "NPI",
        "birthDate": "DOB",
        "qualification": "LICENSE",
    },
    "RelatedPerson": {
        "name": "NAME",
        "telecom": "PHONE",
        "address": "ADDRESS",
        "birthDate": "DOB",
        "identifier": "MRN",
        "photo": "PHOTO",
    },
    "Person": {
        "name": "NAME",
        "telecom": "PHONE",
        "address": "ADDRESS",
        "birthDate": "DOB",
        "identifier": "MRN",
        "photo": "PHOTO",
    },
    "Organization": {
        "name": "NAME",
        "telecom": "PHONE",
        "address": "ADDRESS",
        "identifier": "ACCOUNT",
    },
    "Location": {
        "name": "NAME",
        "telecom": "PHONE",
        "address": "ADDRESS",
        "identifier": "LOCATION",
    },
    "Encounter": {
        "identifier": "ACCOUNT",
        "period": "DATE",
        "location": "LOCATION",
        "participant": "NAME",
        "reasonCode": "DIAGNOSIS",
    },
    "Observation": {
        "identifier": "ACCOUNT",
        "effectiveDateTime": "DATE",
        "performer": "NAME",
        "note": "OBSERVATION",
    },
    "DiagnosticReport": {
        "identifier": "ACCOUNT",
        "effectiveDateTime": "DATE",
        "performer": "NAME",
        "subject": "MRN",
    },
    "Condition": {
        "identifier": "ACCOUNT",
        "onsetDateTime": "DATE",
        "abatementDateTime": "DATE",
        "recorder": "NAME",
        "asserter": "NAME",
        "note": "OBSERVATION",
    },
    "Medication": {
        "identifier": "ACCOUNT",
    },
    "MedicationRequest": {
        "identifier": "ACCOUNT",
        "authoredOn": "DATE",
        "requester": "NAME",
        "subject": "MRN",
        "note": "OBSERVATION",
    },
    "AllergyIntolerance": {
        "identifier": "ACCOUNT",
        "onsetDateTime": "DATE",
        "recorder": "NAME",
        "asserter": "NAME",
        "note": "OBSERVATION",
    },
    "Coverage": {
        "identifier": "ACCOUNT",
        "subscriber": "NAME",
        "subscriberId": "ACCOUNT",
        "beneficiary": "MRN",
        "period": "DATE",
    },
}

_REDACT = "[REDACTED:{category}]"
_HL7_SEGMENT_PATTERN = re.compile(r"^[A-Z][A-Z0-9]{1,2}(?:\||\r\n|\n|$)")


# ── Result type ───────────────────────────────────────────────────────────────


@dataclass
class PHIScrubResult:
    """Result of a structured PHI scrub operation.

    Attributes
    ----------
    scrubbed:
        The de-identified text (HL7 message or FHIR JSON string).
    format:
        ``"hl7v2"``, ``"fhir_json"``, or ``"plain_text"`` (when input is
        neither HL7 nor FHIR and the detector falls back to no-op).
    categories:
        Set of PHI category labels that were redacted (e.g. ``{"NAME", "DOB"}``).
    redaction_count:
        Total number of field values redacted.
    """

    scrubbed: str
    format: str
    categories: set[str] = field(default_factory=set)
    redaction_count: int = 0


# ── HL7 v2 scrubber ───────────────────────────────────────────────────────────


class HL7v2PHIScrubber:
    """Scrub PHI from HL7 v2 pipe-delimited messages by segment+field position.

    Handles the MSH field separator definition (default ``|``); correctly
    parses component separator (``^``) within PHI fields.  Non-PHI segments
    and fields are passed through unchanged.
    """

    def scrub(self, message: str) -> PHIScrubResult:
        """Return a :class:`PHIScrubResult` with PHI fields redacted.

        Parameters
        ----------
        message:
            Raw HL7 v2 message string (CR or LF separated segments).
        """
        lines = message.strip().replace("\r\n", "\n").replace("\r", "\n").split("\n")
        scrubbed_lines: list[str] = []
        categories: set[str] = set()
        redaction_count = 0

        field_sep = "|"
        for line in lines:
            if not line.strip():
                scrubbed_lines.append(line)
                continue
            seg_id = line[:3]
            if seg_id == "MSH":
                # MSH-1 is the field separator itself
                if len(line) >= 4:
                    field_sep = line[3]
                scrubbed_lines.append(line)
                continue

            phi_map = _HL7_PHI_FIELDS.get(seg_id)
            if phi_map is None:
                scrubbed_lines.append(line)
                continue

            fields = line.split(field_sep)
            modified = False
            for idx_1based, category in phi_map.items():
                # fields[0] is the segment ID; field 1 is index 1
                field_idx = idx_1based  # 1-based → already correct as list offset
                if field_idx < len(fields) and fields[field_idx].strip():
                    fields[field_idx] = _REDACT.format(category=category)
                    categories.add(category)
                    redaction_count += 1
                    modified = True

            scrubbed_lines.append(field_sep.join(fields) if modified else line)

        return PHIScrubResult(
            scrubbed="\n".join(scrubbed_lines),
            format="hl7v2",
            categories=categories,
            redaction_count=redaction_count,
        )


# ── FHIR JSON scrubber ────────────────────────────────────────────────────────


class FHIRPHIScrubber:
    """Scrub PHI from FHIR R4/R5 JSON resources by resource type + field path.

    Accepts both a JSON string and a pre-parsed Python dict.  Unknown resource
    types are returned unchanged.  PHI fields are set to the redaction token
    (for scalar fields) or replaced with ``[{"redacted": true}]`` (for arrays).

    Bundle resources are handled recursively — each ``entry.resource`` is
    scrubbed individually.
    """

    def scrub_dict(self, resource: dict[str, Any]) -> tuple[dict[str, Any], set[str], int]:
        """Scrub a FHIR resource dict in-place.

        Returns
        -------
        tuple[dict, set[str], int]
            (scrubbed_dict, categories_hit, redaction_count)
        """
        categories: set[str] = set()
        redaction_count = 0
        resource_type = resource.get("resourceType", "")

        if resource_type == "Bundle":
            entries = resource.get("entry", [])
            for entry in entries:
                sub = entry.get("resource")
                if isinstance(sub, dict):
                    _, sub_cats, sub_count = self.scrub_dict(sub)
                    categories |= sub_cats
                    redaction_count += sub_count
            return resource, categories, redaction_count

        phi_map = _FHIR_PHI_PATHS.get(resource_type)
        if phi_map is None:
            return resource, categories, redaction_count

        for field_name, category in phi_map.items():
            if field_name in resource and resource[field_name] not in (None, "", [], {}):
                val = resource[field_name]
                if isinstance(val, list):
                    resource[field_name] = [{"redacted": True}]
                else:
                    resource[field_name] = _REDACT.format(category=category)
                categories.add(category)
                redaction_count += 1

        return resource, categories, redaction_count

    def scrub(self, json_text: str) -> PHIScrubResult:
        """Scrub a FHIR JSON string and return a :class:`PHIScrubResult`."""
        try:
            resource = json.loads(json_text)
        except (json.JSONDecodeError, ValueError):
            return PHIScrubResult(scrubbed=json_text, format="fhir_json")

        if not isinstance(resource, dict):
            return PHIScrubResult(scrubbed=json_text, format="fhir_json")

        scrubbed, cats, count = self.scrub_dict(resource)
        return PHIScrubResult(
            scrubbed=json.dumps(scrubbed, indent=2),
            format="fhir_json",
            categories=cats,
            redaction_count=count,
        )


# ── Unified detector ──────────────────────────────────────────────────────────

_HL7_HEADER = re.compile(r"^MSH\|", re.MULTILINE)
_FHIR_RESOURCETYPE = re.compile(r'"resourceType"\s*:', re.MULTILINE)


class HL7FHIRPHIDetector:
    """Unified PHI detector and scrubber for HL7 v2 and FHIR JSON.

    Automatically detects input format and routes to the appropriate scrubber.
    Falls back to a no-op pass-through for inputs that match neither format.

    Thread-safe after construction — all state is stateless.
    """

    def __init__(self) -> None:
        self._hl7 = HL7v2PHIScrubber()
        self._fhir = FHIRPHIScrubber()

    def scrub(self, text: str) -> PHIScrubResult:
        """Auto-detect format and scrub PHI from *text*.

        Detection order:
        1. If the text contains ``MSH|`` at the start of a line → HL7 v2.
        2. If the text contains ``"resourceType":`` → FHIR JSON.
        3. Otherwise → plain text pass-through (``format="plain_text"``).
        """
        if _HL7_HEADER.search(text):
            return self._hl7.scrub(text)
        if _FHIR_RESOURCETYPE.search(text):
            return self._fhir.scrub(text)
        return PHIScrubResult(scrubbed=text, format="plain_text")

    def scrub_hl7(self, message: str) -> PHIScrubResult:
        """Scrub an HL7 v2 message (explicit, no format detection)."""
        return self._hl7.scrub(message)

    def scrub_fhir(self, json_text: str) -> PHIScrubResult:
        """Scrub a FHIR JSON string (explicit, no format detection)."""
        return self._fhir.scrub(json_text)

    def scrub_fhir_dict(self, resource: dict[str, Any]) -> tuple[dict[str, Any], set[str], int]:
        """Scrub a FHIR resource dict in-place; return (dict, cats, count)."""
        return self._fhir.scrub_dict(resource)

    @staticmethod
    def supported_hl7_segments() -> list[str]:
        """Sorted list of HL7 segment IDs with PHI field mappings."""
        return sorted(_HL7_PHI_FIELDS)

    @staticmethod
    def supported_fhir_resource_types() -> list[str]:
        """Sorted list of FHIR resource types with PHI path mappings."""
        return sorted(_FHIR_PHI_PATHS)

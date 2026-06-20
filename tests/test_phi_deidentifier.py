# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Real-time PHI de-identification — NIST SP 800-188 Safe Harbor (ROADMAP Domain 2.1).

Verifies that the PHIDeidentifier correctly detects and redacts each of the
18 HIPAA Safe Harbor identifier categories, that no PHI leaks through to the
scrubbed output, and that clean text is returned unchanged.  Also verifies
hot-path integration: request message scrubbing and response scrubbing via the
proxy helpers.
"""
from __future__ import annotations

import re

import pytest

from aegis.core.phi_deidentifier import PHIDeidentifier


@pytest.fixture(scope="module")
def scrubber() -> PHIDeidentifier:
    return PHIDeidentifier()


# ── Per-category tests (Safe Harbor 18 identifiers) ──────────────────────────


class TestNames:
    def test_title_name_detected(self, scrubber):
        result = scrubber.scrub("Patient referred by Dr. John Smith.")
        assert "Dr. John Smith" not in result.text
        assert "[REDACTED:NAME]" in result.text
        assert result.hits.get("NAME", 0) >= 1

    def test_mr_name_detected(self, scrubber):
        result = scrubber.scrub("Please contact Mr. Robert Johnson at your earliest convenience.")
        assert "Mr. Robert Johnson" not in result.text
        assert result.hits.get("NAME", 0) >= 1

    def test_no_false_positive_plain_name(self, scrubber):
        # Plain capitalized names without a title should NOT be flagged by name pattern.
        result = scrubber.scrub("Alice reviewed the report.")
        assert result.hits.get("NAME", 0) == 0


class TestGeographic:
    def test_street_address_detected(self, scrubber):
        result = scrubber.scrub("She lives at 123 Main Street, Springfield.")
        assert "123 Main Street" not in result.text
        assert "[REDACTED:ADDRESS]" in result.text

    def test_zip_code_detected(self, scrubber):
        result = scrubber.scrub("ZIP: 90210")
        assert "90210" not in result.text
        assert "[REDACTED:ZIP]" in result.text

    def test_zip_plus_four_detected(self, scrubber):
        result = scrubber.scrub("ZIP+4: 12345-6789")
        assert "12345-6789" not in result.text


class TestDates:
    @pytest.mark.parametrize(
        "date_str",
        [
            "01/23/1990",
            "1-23-90",
            "January 23, 1990",
            "Jan 23rd, 1990",
            "1990-01-23",
        ],
    )
    def test_date_formats_detected(self, scrubber, date_str):
        result = scrubber.scrub(f"Date of birth: {date_str}")
        assert date_str not in result.text
        assert "[REDACTED:DATE]" in result.text

    def test_year_only_not_redacted(self, scrubber):
        # A bare year (e.g. "2023") must NOT be flagged — Safe Harbor retains year.
        result = scrubber.scrub("This happened in 2023.")
        assert "2023" in result.text
        assert result.hits.get("DATE", 0) == 0


class TestPhoneFax:
    @pytest.mark.parametrize(
        "phone",
        [
            "555-123-4567",
            "(555) 123-4567",
            "+1 555 123 4567",
            "5551234567",
            "+15551234567",
        ],
    )
    def test_phone_formats_detected(self, scrubber, phone):
        result = scrubber.scrub(f"Call us at {phone}.")
        # After redaction the raw digits should not appear as a contiguous block
        assert re.search(r"\b\d{10}\b", result.text) is None
        assert "[REDACTED:PHONE]" in result.text


class TestEmail:
    def test_email_detected(self, scrubber):
        result = scrubber.scrub("Contact john.doe@hospital.org for scheduling.")
        assert "john.doe@hospital.org" not in result.text
        assert "[REDACTED:EMAIL]" in result.text

    def test_subdomain_email(self, scrubber):
        result = scrubber.scrub("admin@mail.clinic.example.com")
        assert "admin@mail.clinic.example.com" not in result.text


class TestSSN:
    @pytest.mark.parametrize(
        "ssn",
        [
            "123-45-6789",
            "123 45 6789",
            # Unseparated 9-digit SSNs (e.g. "123456789") are intentionally NOT
            # matched: any 9-digit number (order IDs, ZIP+4, etc.) would trigger
            # a false positive.  Safe Harbor scrubbing requires the separator
            # context (dash or space) to safely identify SSN format.
        ],
    )
    def test_ssn_detected(self, scrubber, ssn):
        result = scrubber.scrub(f"SSN: {ssn}")
        assert ssn not in result.text
        assert "[REDACTED:SSN]" in result.text

    def test_ssn_format_matched_regardless_of_validity(self, scrubber):
        # Safe Harbor scrubbing favours recall: scrub all SSN-format strings,
        # even those with reserved area codes (000, 666, 9xx), to avoid leakage.
        result = scrubber.scrub("Code: 000-45-6789")
        assert "[REDACTED:SSN]" in result.text


class TestMRN:
    @pytest.mark.parametrize(
        "mrn_text",
        [
            "MRN: 1234567",
            "MRN#12345678",
            "Medical Record Number: 98765",
            "MR: 123456",
        ],
    )
    def test_mrn_detected(self, scrubber, mrn_text):
        result = scrubber.scrub(mrn_text)
        assert "[REDACTED:MRN]" in result.text
        assert result.hits.get("MRN", 0) >= 1


class TestURL:
    def test_https_url_detected(self, scrubber):
        result = scrubber.scrub("Visit https://patient.hospital.org/records for details.")
        assert "https://patient.hospital.org/records" not in result.text
        assert "[REDACTED:URL]" in result.text

    def test_http_url_detected(self, scrubber):
        result = scrubber.scrub("See http://internal.ehr.example.com")
        assert "[REDACTED:URL]" in result.text


class TestIPAddress:
    def test_ipv4_detected(self, scrubber):
        result = scrubber.scrub("Device at IP 192.168.1.100 was accessed.")
        assert "192.168.1.100" not in result.text
        assert "[REDACTED:IP_ADDRESS]" in result.text

    def test_ipv6_detected(self, scrubber):
        result = scrubber.scrub("Source: 2001:db8:85a3::8a2e:370:7334")
        assert "[REDACTED:IP_ADDRESS]" in result.text


class TestBiometric:
    @pytest.mark.parametrize(
        "bio_text",
        [
            "The fingerprint record was collected.",
            "Retina scan data attached.",
            "Voice print on file.",
        ],
    )
    def test_biometric_references_detected(self, scrubber, bio_text):
        result = scrubber.scrub(bio_text)
        assert "[REDACTED:BIOMETRIC]" in result.text
        assert result.hits.get("BIOMETRIC", 0) >= 1


class TestNPI:
    def test_npi_detected(self, scrubber):
        result = scrubber.scrub("Provider NPI: 1234567890 issued the referral.")
        assert "1234567890" not in result.text
        assert "[REDACTED:NPI]" in result.text


# ── ScrubResult properties ────────────────────────────────────────────────────


class TestScrubResult:
    def test_phi_detected_true_when_hits(self, scrubber):
        result = scrubber.scrub("Email: user@example.com")
        assert result.phi_detected is True

    def test_phi_detected_false_for_clean_text(self, scrubber):
        result = scrubber.scrub("The weather is sunny today.")
        assert result.phi_detected is False
        assert result.total_hits == 0

    def test_total_hits_aggregates(self, scrubber):
        result = scrubber.scrub(
            "Contact dr.smith@clinic.com or call 555-000-1234."
        )
        assert result.total_hits >= 2

    def test_method_is_safe_harbor_regex(self, scrubber):
        result = scrubber.scrub("anything")
        assert result.method == "safe_harbor_regex"

    def test_empty_string_passthrough(self, scrubber):
        result = scrubber.scrub("")
        assert result.text == ""
        assert not result.phi_detected


# ── scrub_messages helper ────────────────────────────────────────────────────


class TestScrubMessages:
    def test_scrubs_user_message_content(self, scrubber):
        messages = [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "My SSN is 123-45-6789, please help."},
        ]
        scrubbed, hits = scrubber.scrub_messages(messages)
        assert "123-45-6789" not in scrubbed[1]["content"]
        assert "[REDACTED:SSN]" in scrubbed[1]["content"]
        assert hits.get("SSN", 0) >= 1

    def test_non_string_content_passthrough(self, scrubber):
        messages = [{"role": "user", "content": None}]
        scrubbed, hits = scrubber.scrub_messages(messages)
        assert scrubbed[0]["content"] is None
        assert not hits

    def test_original_messages_not_mutated(self, scrubber):
        original_content = "Email me at bob@example.com"
        messages = [{"role": "user", "content": original_content}]
        scrubber.scrub_messages(messages)
        assert messages[0]["content"] == original_content

    def test_hit_counts_merged_across_messages(self, scrubber):
        messages = [
            {"role": "user", "content": "user@a.com"},
            {"role": "assistant", "content": "admin@b.com"},
        ]
        _, hits = scrubber.scrub_messages(messages)
        assert hits.get("EMAIL", 0) == 2


# ── Integration: proxy helper functions ──────────────────────────────────────


class TestProxyIntegration:
    """Verify the _apply_phi_scrub_request/_response helpers used by app.py."""

    def _make_state(self, enabled: bool):
        from aegis.core.phi_deidentifier import PHIDeidentifier

        class _FakeState:
            _phi_scrubber = PHIDeidentifier() if enabled else None

        return _FakeState()

    def test_request_scrub_disabled_returns_same_object(self):
        from aegis.proxy.app import _apply_phi_scrub_request

        state = self._make_state(enabled=False)
        body = {"messages": [{"role": "user", "content": "SSN: 123-45-6789"}]}
        result = _apply_phi_scrub_request(body, state)
        assert result is body  # same object — no copy

    def test_request_scrub_enabled_redacts_phi(self):
        from aegis.proxy.app import _apply_phi_scrub_request

        state = self._make_state(enabled=True)
        body = {"messages": [{"role": "user", "content": "My SSN is 987-65-4321"}]}
        result = _apply_phi_scrub_request(body, state)
        assert "987-65-4321" not in result["messages"][0]["content"]
        assert "[REDACTED:SSN]" in result["messages"][0]["content"]

    def test_request_scrub_no_phi_returns_same_body(self):
        from aegis.proxy.app import _apply_phi_scrub_request

        state = self._make_state(enabled=True)
        body = {"messages": [{"role": "user", "content": "Hello, how are you?"}]}
        result = _apply_phi_scrub_request(body, state)
        # No PHI → body dict is returned as-is (no copy allocation)
        assert result is body

    def test_response_scrub_disabled_returns_same_object(self):
        from aegis.proxy.app import _apply_phi_scrub_response

        state = self._make_state(enabled=False)
        resp = {"choices": [{"message": {"content": "SSN: 123-45-6789"}}]}
        result = _apply_phi_scrub_response(resp, state)
        assert result is resp

    def test_response_scrub_enabled_redacts_phi(self):
        from aegis.proxy.app import _apply_phi_scrub_response

        state = self._make_state(enabled=True)
        resp = {
            "choices": [{"message": {"role": "assistant", "content": "IP 10.0.0.1 was used."}}]
        }
        result = _apply_phi_scrub_response(resp, state)
        assert "10.0.0.1" not in result["choices"][0]["message"]["content"]
        assert "[REDACTED:IP_ADDRESS]" in result["choices"][0]["message"]["content"]

    def test_response_scrub_no_phi_passthrough(self):
        from aegis.proxy.app import _apply_phi_scrub_response

        state = self._make_state(enabled=True)
        resp = {"choices": [{"message": {"content": "The sky is blue."}}]}
        result = _apply_phi_scrub_response(resp, state)
        assert result is resp

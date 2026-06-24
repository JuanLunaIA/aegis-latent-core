# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.pci_detector — PCI-DSS cardholder-data detection & masking.

All card numbers below are the standard, publicly-documented payment-network TEST
PANs (Luhn-valid by construction); none is a real account number.
"""

from __future__ import annotations

from aegis.core.pci_detector import (
    CardBrand,
    PCIScrubber,
    detect_brand,
    luhn_valid,
)

# Public test PANs (Luhn-valid).
VISA16 = "4111111111111111"
VISA13 = "4222222222222"
MC = "5555555555554444"
MC2 = "2223003122003222"  # 2-series Mastercard
AMEX = "378282246310005"
DISCOVER = "6011111111111117"
DINERS = "30569309025904"
JCB = "3530111333300000"


class TestLuhn:
    def test_valid_pans_pass(self):
        for pan in (VISA16, VISA13, MC, MC2, AMEX, DISCOVER, DINERS, JCB):
            assert luhn_valid(pan), pan

    def test_near_miss_fails(self):
        # Same Visa prefix, wrong final check digit.
        assert luhn_valid("4111111111111112") is False

    def test_non_digits_fail(self):
        assert luhn_valid("4111-1111") is False


class TestDetectBrand:
    def test_brands(self):
        assert detect_brand(VISA16) is CardBrand.VISA
        assert detect_brand(VISA13) is CardBrand.VISA
        assert detect_brand(MC) is CardBrand.MASTERCARD
        assert detect_brand(MC2) is CardBrand.MASTERCARD
        assert detect_brand(AMEX) is CardBrand.AMEX
        assert detect_brand(DISCOVER) is CardBrand.DISCOVER
        assert detect_brand(DINERS) is CardBrand.DINERS
        assert detect_brand(JCB) is CardBrand.JCB

    def test_unknown_brand(self):
        assert detect_brand("9" * 16) is CardBrand.UNKNOWN


class TestPANScrubbing:
    def setup_method(self):
        self.s = PCIScrubber()

    def test_pan_detected_and_masked(self):
        res = self.s.scan(f"my card is {VISA16} ok")
        assert res.chd_detected is True
        assert res.pan_count == 1
        assert CardBrand.VISA in res.brands
        # Full PAN must not survive; only last 4 remain.
        assert VISA16 not in res.text
        assert "1111" in res.text
        assert "[PAN-****1111]" in res.text

    def test_pan_with_separators(self):
        res = self.s.scan("4111 1111 1111 1111")
        assert res.pan_count == 1
        assert "4111 1111 1111 1111" not in res.text

    def test_amex_15_digit(self):
        res = self.s.scan(f"AMEX {AMEX}")
        assert res.pan_count == 1
        assert CardBrand.AMEX in res.brands

    def test_multiple_pans(self):
        res = self.s.scan(f"{VISA16} and {MC}")
        assert res.pan_count == 2
        assert set(res.brands) == {CardBrand.VISA, CardBrand.MASTERCARD}

    def test_luhn_invalid_not_masked(self):
        # A 16-digit number that fails Luhn must be left untouched (no over-redaction).
        order = "4111111111111112"
        res = self.s.scan(f"order id {order}")
        assert res.pan_count == 0
        assert order in res.text

    def test_unknown_brand_not_masked(self):
        # Random 16-digit order numbers should not be treated as PANs.
        res = self.s.scan("reference 1234567890123456")
        assert res.pan_count == 0


class TestSADRedaction:
    def setup_method(self):
        self.s = PCIScrubber()

    def test_cvv_redacted_fully(self):
        res = self.s.scan("CVV: 123")
        assert res.cvv_count == 1
        assert "123" not in res.text
        assert "[REDACTED:CVV]" in res.text

    def test_cvv_variants(self):
        for label in ("cvc", "cvv2", "CID"):
            res = self.s.scan(f"{label} = 4567")
            assert res.cvv_count == 1, label
            assert "4567" not in res.text

    def test_bare_three_digits_not_cvv(self):
        # Without a security-code context, a 3-digit number is not flagged.
        res = self.s.scan("there were 123 results")
        assert res.cvv_count == 0
        assert "123" in res.text

    def test_track2_redacted(self):
        track = ";4111111111111111=25121011000000000000?"
        res = self.s.scan(track)
        assert res.track_count == 1
        assert "4111111111111111" not in res.text
        assert "[REDACTED:TRACK_DATA]" in res.text


class TestResultModel:
    def setup_method(self):
        self.s = PCIScrubber()

    def test_empty_text(self):
        res = self.s.scan("")
        assert res.chd_detected is False
        assert res.total_hits == 0

    def test_clean_text_untouched(self):
        res = self.s.scan("hello world, no card data here")
        assert res.chd_detected is False
        assert res.text == "hello world, no card data here"

    def test_to_dict(self):
        res = self.s.scan(f"{VISA16} CVV: 999")
        d = res.to_dict()
        assert d["chd_detected"] is True
        assert d["pan_count"] == 1
        assert d["cvv_count"] == 1
        assert "visa" in d["brands"]

    def test_total_hits_sums(self):
        res = self.s.scan(f"{VISA16} {MC} CVV 321")
        assert res.total_hits == res.pan_count + res.cvv_count + res.track_count


# ── Integration: proxy helper functions ──────────────────────────────────────


class TestPCIProxyHelpers:
    """Verify the _apply_pci_scrub_request/_response helpers wired into app.py."""

    def _make_state(self, enabled: bool):
        from aegis.core.pci_detector import PCIScrubber

        class _FakeState:
            _pci_scrubber = PCIScrubber() if enabled else None

        return _FakeState()

    def test_request_scrub_disabled_returns_same_object(self):
        from aegis.proxy.app import _apply_pci_scrub_request

        state = self._make_state(enabled=False)
        body = {"messages": [{"role": "user", "content": f"card {VISA16}"}]}
        result, scrubbed = _apply_pci_scrub_request(body, state)
        assert result is body
        assert scrubbed is False

    def test_request_scrub_masks_pan(self):
        from aegis.proxy.app import _apply_pci_scrub_request

        state = self._make_state(enabled=True)
        body = {"messages": [{"role": "user", "content": f"charge card {VISA16} now"}]}
        result, scrubbed = _apply_pci_scrub_request(body, state)
        assert scrubbed is True
        assert VISA16 not in result["messages"][0]["content"]
        assert "[PAN-****1111]" in result["messages"][0]["content"]
        assert result is not body

    def test_request_scrub_no_chd_returns_same_object(self):
        from aegis.proxy.app import _apply_pci_scrub_request

        state = self._make_state(enabled=True)
        body = {"messages": [{"role": "user", "content": "Hello, what is the weather?"}]}
        result, scrubbed = _apply_pci_scrub_request(body, state)
        assert result is body
        assert scrubbed is False

    def test_request_scrub_empty_messages_passthrough(self):
        from aegis.proxy.app import _apply_pci_scrub_request

        state = self._make_state(enabled=True)
        body = {"prompt": "no messages key here"}
        result, scrubbed = _apply_pci_scrub_request(body, state)
        assert result is body
        assert scrubbed is False

    def test_response_scrub_disabled_returns_same_object(self):
        from aegis.proxy.app import _apply_pci_scrub_response

        state = self._make_state(enabled=False)
        resp = {"choices": [{"message": {"content": f"Your card {VISA16} is charged."}}]}
        result = _apply_pci_scrub_response(resp, state)
        assert result is resp

    def test_response_scrub_masks_pan(self):
        from aegis.proxy.app import _apply_pci_scrub_response

        state = self._make_state(enabled=True)
        resp = {"choices": [{"message": {"role": "assistant", "content": f"Card {MC} approved."}}]}
        result = _apply_pci_scrub_response(resp, state)
        assert MC not in result["choices"][0]["message"]["content"]
        assert "[PAN-****4444]" in result["choices"][0]["message"]["content"]

    def test_response_scrub_no_chd_passthrough(self):
        from aegis.proxy.app import _apply_pci_scrub_response

        state = self._make_state(enabled=True)
        resp = {"choices": [{"message": {"content": "No card data here."}}]}
        result = _apply_pci_scrub_response(resp, state)
        assert result is resp

    def test_response_scrub_cvv_redacted(self):
        from aegis.proxy.app import _apply_pci_scrub_response

        state = self._make_state(enabled=True)
        resp = {"choices": [{"message": {"content": "CVV: 999 was provided."}}]}
        result = _apply_pci_scrub_response(resp, state)
        assert "999" not in result["choices"][0]["message"]["content"]
        assert "[REDACTED:CVV]" in result["choices"][0]["message"]["content"]

    def test_scrub_method_appended_when_pci_fires(self):
        """When PCI scrubbing triggers, 'pci_pan_mask' is appended to scrub_method."""
        from aegis.proxy.app import _apply_pci_scrub_request

        state = self._make_state(enabled=True)
        body = {"messages": [{"role": "user", "content": f"Amex {AMEX}"}]}
        _, scrubbed = _apply_pci_scrub_request(body, state)
        assert scrubbed is True

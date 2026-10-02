"""Malformed status rejection without changing granted receipt semantics."""

# Copyright (c) 2026 Juan Luna.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE.
from __future__ import annotations

import base64

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from aegis.core.rfc3161_timestamper import (
    RFC3161Timestamper,
    _der_sequence,
    _tlv,
    extract_token_from_response,
    parse_pki_status,
)


def _response(status: bytes) -> bytes:
    # Minimal token-shaped receipt; intentionally NOT a CMS verification fixture.
    return _der_sequence(_der_sequence(_tlv(0x02, status)), b"\x30\x00")


@pytest.mark.parametrize("status", [b"", b"\x00\x00", b"\x00\x01", b"\xff", b"\x06"])
def test_malformed_pki_status_is_rejected(status, monkeypatch):
    response = _response(status)
    with pytest.raises(ValueError, match="PKIStatus"):
        parse_pki_status(response)
    with pytest.raises(ValueError, match="PKIStatus"):
        extract_token_from_response(response)
    stamper = RFC3161Timestamper(tsa_url="https://tsa.invalid")
    monkeypatch.setattr(stamper, "_http_post", lambda _: response)
    result = stamper.stamp({"synthetic": True})
    assert result.success is False
    assert result.token_b64 == ""
    assert result.pki_status == -1
    assert result.error.startswith("Parse error:")


@pytest.mark.parametrize("status", range(6))
def test_defined_pki_status_values_remain_parseable(status):
    assert parse_pki_status(_response(bytes([status]))) == status


@pytest.mark.parametrize("status", [0, 1])
def test_granted_receipt_does_not_claim_cms_verification(status, monkeypatch):
    stamper = RFC3161Timestamper(tsa_url="https://tsa.invalid")
    monkeypatch.setattr(stamper, "_http_post", lambda _: _response(bytes([status])))
    package = {"synthetic": True}
    result = stamper.stamp(package)
    assert result.success is True
    assert result.pki_status == status
    assert result.token_b64 == base64.b64encode(b"\x30\x00").decode()
    assert package == {"synthetic": True}
    assert stamper.verify(result.package_dict).valid is False


@settings(max_examples=100, derandomize=True, deadline=500, database=None)
@given(st.binary(min_size=0, max_size=8))
def test_pki_status_encoding_domain_is_bounded(status):
    if len(status) == 1 and status[0] in range(6):
        assert parse_pki_status(_response(status)) == status[0]
    else:
        with pytest.raises(ValueError, match="PKIStatus"):
            parse_pki_status(_response(status))

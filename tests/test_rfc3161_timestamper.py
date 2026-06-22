# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
# Copyright (c) 2026 Juan Luna. All rights reserved.
"""Tests for aegis.core.rfc3161_timestamper."""

from __future__ import annotations

import base64
import hashlib
import json
from unittest.mock import patch

import pytest

from aegis.core.rfc3161_timestamper import (
    RFC3161StampResult,
    RFC3161Timestamper,
    RFC3161VerifyResult,
    _algorithm_identifier_sha256,
    _der_boolean_true,
    _der_integer,
    _der_null,
    _der_octet_string,
    _der_oid,
    _der_sequence,
    _parse_tlv,
    build_timestamp_request,
    extract_token_from_response,
    parse_pki_status,
)

# ── DER encoding helpers ──────────────────────────────────────────────────────


class TestDEREncoding:
    def test_integer_zero(self):
        enc = _der_integer(0)
        assert enc == b"\x02\x01\x00"

    def test_integer_one(self):
        enc = _der_integer(1)
        assert enc == b"\x02\x01\x01"

    def test_integer_127(self):
        enc = _der_integer(127)
        assert enc == b"\x02\x01\x7f"

    def test_integer_128_needs_sign_byte(self):
        enc = _der_integer(128)
        # 128 = 0x80 — needs leading 0x00 to prevent negative interpretation
        assert enc == b"\x02\x02\x00\x80"

    def test_integer_256(self):
        enc = _der_integer(256)
        assert enc == b"\x02\x02\x01\x00"

    def test_integer_large(self):
        n = 2**64
        enc = _der_integer(n)
        assert enc[0] == 0x02
        assert enc[1] > 0

    def test_octet_string_empty(self):
        enc = _der_octet_string(b"")
        assert enc == b"\x04\x00"

    def test_octet_string_content(self):
        enc = _der_octet_string(b"\xde\xad")
        assert enc == b"\x04\x02\xde\xad"

    def test_boolean_true(self):
        assert _der_boolean_true() == b"\x01\x01\xff"

    def test_null(self):
        assert _der_null() == b"\x05\x00"

    def test_sequence_empty(self):
        enc = _der_sequence()
        assert enc == b"\x30\x00"

    def test_sequence_wraps_items(self):
        enc = _der_sequence(b"\x02\x01\x01", b"\x02\x01\x02")
        assert enc[0] == 0x30
        assert enc[1] == 6  # length of two 3-byte INTEGER TLVs

    def test_oid_sha256(self):
        enc = _der_oid("2.16.840.1.101.3.4.2.1")
        assert enc[0] == 0x06
        # Known DER encoding of SHA-256 OID
        assert enc == bytes.fromhex("0609608648016503040201")

    def test_oid_single_arc(self):
        # 1.2 → first byte = 1*40+2 = 42 = 0x2a
        enc = _der_oid("1.2")
        assert enc == b"\x06\x01\x2a"

    def test_algorithm_identifier_sha256_structure(self):
        ai = _algorithm_identifier_sha256()
        assert ai[0] == 0x30  # SEQUENCE
        # Must contain SHA-256 OID
        sha256_oid = _der_oid("2.16.840.1.101.3.4.2.1")
        assert sha256_oid in ai


# ── build_timestamp_request ───────────────────────────────────────────────────


class TestBuildTimestampRequest:
    def _imprint(self):
        return hashlib.sha256(b"test evidence").digest()

    def test_returns_bytes(self):
        req = build_timestamp_request(self._imprint())
        assert isinstance(req, bytes)
        assert len(req) > 0

    def test_root_is_sequence(self):
        req = build_timestamp_request(self._imprint())
        assert req[0] == 0x30

    def test_version_is_1(self):
        req = build_timestamp_request(self._imprint())
        # After outer SEQUENCE tag+length, first element should be INTEGER 1
        tag, outer_val, _ = _parse_tlv(req, 0)
        tag, ver_val, _ = _parse_tlv(outer_val, 0)
        assert tag == 0x02
        assert ver_val == b"\x01"

    def test_contains_message_imprint(self):
        imprint = self._imprint()
        req = build_timestamp_request(imprint)
        # The imprint bytes should appear in the request
        assert imprint in req

    def test_random_nonce_used_when_none(self):
        imprint = self._imprint()
        req1 = build_timestamp_request(imprint, nonce=None)
        req2 = build_timestamp_request(imprint, nonce=None)
        # Different nonces should produce different requests
        assert req1 != req2

    def test_explicit_nonce_deterministic(self):
        imprint = self._imprint()
        req1 = build_timestamp_request(imprint, nonce=42)
        req2 = build_timestamp_request(imprint, nonce=42)
        assert req1 == req2

    def test_wrong_imprint_length_raises(self):
        with pytest.raises(ValueError, match="32 bytes"):
            build_timestamp_request(b"\x00" * 31)

    def test_cert_req_present(self):
        req = build_timestamp_request(self._imprint())
        # BOOLEAN TRUE (0x01 0x01 0xFF) should be present
        assert b"\x01\x01\xff" in req


# ── DER parser ────────────────────────────────────────────────────────────────


class TestParseTLV:
    def test_parse_integer(self):
        data = b"\x02\x01\x07"
        tag, val, nxt = _parse_tlv(data, 0)
        assert tag == 0x02
        assert val == b"\x07"
        assert nxt == 3

    def test_parse_long_form_length(self):
        # Long-form length: 0x81 0x80 = 128 bytes
        payload = b"\xab" * 128
        data = b"\x04\x81\x80" + payload
        tag, val, nxt = _parse_tlv(data, 0)
        assert tag == 0x04
        assert val == payload
        assert nxt == len(data)

    def test_parse_empty_sequence(self):
        data = b"\x30\x00"
        tag, val, nxt = _parse_tlv(data, 0)
        assert tag == 0x30
        assert val == b""
        assert nxt == 2

    def test_offset_parameter(self):
        data = b"\xff\x02\x01\x05"
        tag, val, nxt = _parse_tlv(data, 1)
        assert tag == 0x02
        assert val == b"\x05"

    def test_truncated_raises(self):
        with pytest.raises(ValueError):
            _parse_tlv(b"\x02", 0)

    def test_empty_data_raises(self):
        with pytest.raises(ValueError):
            _parse_tlv(b"", 0)


# ── parse_pki_status ──────────────────────────────────────────────────────────


def _make_tsp_response(status: int, token_bytes: bytes = b"") -> bytes:
    """Build a minimal DER TimeStampResp for testing."""
    pki_status = _der_integer(status)
    pki_status_info = _der_sequence(pki_status)
    return _der_sequence(pki_status_info, token_bytes)


class TestParsePKIStatus:
    def test_granted(self):
        resp = _make_tsp_response(0, b"\x30\x03\x02\x01\x00")
        assert parse_pki_status(resp) == 0

    def test_granted_with_mods(self):
        resp = _make_tsp_response(1, b"\x30\x03\x02\x01\x01")
        assert parse_pki_status(resp) == 1

    def test_rejection(self):
        resp = _make_tsp_response(2, b"")
        assert parse_pki_status(resp) == 2

    def test_invalid_root_tag_raises(self):
        with pytest.raises(ValueError, match="SEQUENCE"):
            parse_pki_status(b"\x02\x01\x00")

    def test_invalid_pki_status_info_tag_raises(self):
        with pytest.raises(ValueError):
            parse_pki_status(_der_sequence(b"\x02\x01\x00"))


# ── extract_token_from_response ───────────────────────────────────────────────


class TestExtractToken:
    def _dummy_token(self) -> bytes:
        return _der_sequence(_der_integer(42))

    def test_extract_granted(self):
        token = self._dummy_token()
        resp = _make_tsp_response(0, token)
        extracted = extract_token_from_response(resp)
        assert extracted == token

    def test_extract_granted_with_mods(self):
        token = self._dummy_token()
        resp = _make_tsp_response(1, token)
        extracted = extract_token_from_response(resp)
        assert extracted == token

    def test_rejection_raises(self):
        resp = _make_tsp_response(2, b"")
        with pytest.raises(ValueError, match="PKIStatus=2"):
            extract_token_from_response(resp)

    def test_missing_token_raises(self):
        resp = _make_tsp_response(0, b"")
        with pytest.raises(ValueError, match="no TimeStampToken"):
            extract_token_from_response(resp)


# ── RFC3161StampResult ────────────────────────────────────────────────────────


class TestRFC3161StampResult:
    def test_to_dict_keys(self):
        r = RFC3161StampResult(
            success=True,
            token_b64="abc123",  # noqa: S106
            tsa_url="http://tsa.example.com",
            pki_status=0,
            message_imprint_hex="aabbcc",
        )
        d = r.to_dict()
        assert set(d.keys()) == {
            "success",
            "token_b64",
            "tsa_url",
            "pki_status",
            "message_imprint_hex",
            "error",
        }
        assert d["success"] is True
        assert d["error"] == ""


# ── RFC3161VerifyResult ───────────────────────────────────────────────────────


class TestRFC3161VerifyResult:
    def test_valid(self):
        r = RFC3161VerifyResult(valid=True, pki_status=0)
        assert r.valid is True
        assert r.error == ""

    def test_invalid_with_error(self):
        r = RFC3161VerifyResult(valid=False, pki_status=2, error="rejected")
        assert r.valid is False
        assert r.error == "rejected"


# ── RFC3161Timestamper construction ──────────────────────────────────────────


class TestTimestamperConstruction:
    def test_tsa_url_from_param(self):
        t = RFC3161Timestamper(tsa_url="http://tsa.example.com")
        assert t.tsa_url == "http://tsa.example.com"

    def test_tsa_url_from_env(self, monkeypatch):
        monkeypatch.setenv("AEGIS_TSA_URL", "http://env.tsa.example.com")
        t = RFC3161Timestamper()
        assert t.tsa_url == "http://env.tsa.example.com"

    def test_tsa_url_empty_when_unset(self, monkeypatch):
        monkeypatch.delenv("AEGIS_TSA_URL", raising=False)
        t = RFC3161Timestamper()
        assert t.tsa_url == ""

    def test_default_timeout(self, monkeypatch):
        monkeypatch.delenv("AEGIS_TSA_TIMEOUT", raising=False)
        t = RFC3161Timestamper(tsa_url="http://tsa.example.com")
        assert t.timeout == 10

    def test_custom_timeout_param(self):
        t = RFC3161Timestamper(tsa_url="http://tsa.example.com", timeout=30)
        assert t.timeout == 30

    def test_timeout_from_env(self, monkeypatch):
        monkeypatch.setenv("AEGIS_TSA_TIMEOUT", "15")
        t = RFC3161Timestamper(tsa_url="http://tsa.example.com")
        assert t.timeout == 15

    def test_invalid_timeout_env_uses_default(self, monkeypatch):
        monkeypatch.setenv("AEGIS_TSA_TIMEOUT", "not_a_number")
        t = RFC3161Timestamper(tsa_url="http://tsa.example.com")
        assert t.timeout == 10

    def test_timeout_clamped_to_min_1(self, monkeypatch):
        monkeypatch.setenv("AEGIS_TSA_TIMEOUT", "0")
        t = RFC3161Timestamper(tsa_url="http://tsa.example.com")
        assert t.timeout >= 1


# ── stamp() — no TSA URL ─────────────────────────────────────────────────────


class TestStampNoURL:
    def test_stamp_without_tsa_url_fails(self):
        t = RFC3161Timestamper(tsa_url="")
        pkg = {"package_id": "abc", "integrity_seal": "xyz"}
        result = t.stamp(pkg)
        assert result.success is False
        assert "not configured" in result.error

    def test_stamp_without_url_returns_unmodified_package(self):
        t = RFC3161Timestamper(tsa_url="")
        pkg = {"package_id": "abc"}
        result = t.stamp(pkg)
        assert "rfc3161_token_b64" not in result.package_dict


# ── stamp() — mocked TSA ──────────────────────────────────────────────────────


def _dummy_token_bytes() -> bytes:
    return _der_sequence(_der_integer(999))


def _make_granted_response() -> bytes:
    return _make_tsp_response(0, _dummy_token_bytes())


class TestStampMocked:
    def _timestamper(self):
        return RFC3161Timestamper(tsa_url="http://tsa.example.com", timeout=5)

    def _pkg(self):
        return {"package_id": "pkg-001", "integrity_seal": "abc123"}

    def test_successful_stamp(self):
        t = self._timestamper()
        with patch.object(t, "_http_post", return_value=_make_granted_response()):
            result = t.stamp(self._pkg())
        assert result.success is True
        assert result.pki_status == 0
        assert result.token_b64 != ""
        assert result.tsa_url == "http://tsa.example.com"

    def test_token_b64_decodes_to_token(self):
        t = self._timestamper()
        with patch.object(t, "_http_post", return_value=_make_granted_response()):
            result = t.stamp(self._pkg())
        decoded = base64.b64decode(result.token_b64)
        assert decoded == _dummy_token_bytes()

    def test_package_dict_augmented(self):
        t = self._timestamper()
        with patch.object(t, "_http_post", return_value=_make_granted_response()):
            result = t.stamp(self._pkg())
        assert "rfc3161_token_b64" in result.package_dict
        assert "rfc3161_tsa_url" in result.package_dict
        assert result.package_dict["rfc3161_tsa_url"] == "http://tsa.example.com"
        assert "rfc3161_message_imprint_hex" in result.package_dict

    def test_original_pkg_not_mutated(self):
        t = self._timestamper()
        pkg = self._pkg()
        with patch.object(t, "_http_post", return_value=_make_granted_response()):
            t.stamp(pkg)
        assert "rfc3161_token_b64" not in pkg

    def test_http_error_returns_failure(self):
        t = self._timestamper()
        with patch.object(t, "_http_post", side_effect=OSError("connection refused")):
            result = t.stamp(self._pkg())
        assert result.success is False
        assert "HTTP error" in result.error

    def test_rejection_response_returns_failure(self):
        t = self._timestamper()
        rejection = _make_tsp_response(2, b"")
        with patch.object(t, "_http_post", return_value=rejection):
            result = t.stamp(self._pkg())
        assert result.success is False
        assert "PKIStatus=2" in result.error

    def test_imprint_hex_in_result(self):
        t = self._timestamper()
        pkg = self._pkg()
        with patch.object(t, "_http_post", return_value=_make_granted_response()):
            result = t.stamp(pkg)
        # Recompute expected imprint
        canonical = json.dumps(pkg, sort_keys=True, separators=(",", ":")).encode()
        expected = hashlib.sha256(canonical).hexdigest()
        assert result.message_imprint_hex == expected

    def test_granted_with_mods_is_success(self):
        t = self._timestamper()
        resp = _make_tsp_response(1, _dummy_token_bytes())
        with patch.object(t, "_http_post", return_value=resp):
            result = t.stamp(self._pkg())
        assert result.success is True
        assert result.pki_status == 1


# ── verify() ─────────────────────────────────────────────────────────────────


class TestVerify:
    def _timestamper(self):
        return RFC3161Timestamper(tsa_url="http://tsa.example.com")

    def _stamped_pkg(self) -> dict:
        t = self._timestamper()
        pkg = {"package_id": "pkg-001", "integrity_seal": "abc"}
        with patch.object(t, "_http_post", return_value=_make_granted_response()):
            result = t.stamp(pkg)
        return result.package_dict

    def test_valid_stamped_package(self):
        t = self._timestamper()
        stamped = self._stamped_pkg()
        verify_result = t.verify(stamped)
        assert verify_result.valid is True
        assert verify_result.error == ""

    def test_missing_token_field(self):
        t = self._timestamper()
        result = t.verify({"package_id": "abc"})
        assert result.valid is False
        assert "No RFC 3161 token" in result.error

    def test_tampered_package_imprint_mismatch(self):
        t = self._timestamper()
        stamped = self._stamped_pkg()
        stamped["integrity_seal"] = "tampered_value"
        result = t.verify(stamped)
        assert result.valid is False
        assert "mismatch" in result.error

    def test_invalid_base64_token(self):
        t = self._timestamper()
        pkg = {
            "rfc3161_token_b64": "!!!not_base64!!!",
            "rfc3161_message_imprint_hex": "aabbcc",
        }
        result = t.verify(pkg)
        assert result.valid is False
        assert "base64" in result.error.lower()

    def test_invalid_der_token(self):
        t = self._timestamper()
        pkg = {
            "package_id": "x",
            "rfc3161_token_b64": base64.b64encode(b"\xff\xff\xff").decode(),
            "rfc3161_message_imprint_hex": "placeholder",
        }
        # Imprint won't match, so mismatch error fires first
        result = t.verify(pkg)
        assert result.valid is False


# ── compute_message_imprint ───────────────────────────────────────────────────


class TestComputeMessageImprint:
    def test_returns_32_bytes(self):
        t = RFC3161Timestamper(tsa_url="http://tsa.example.com")
        imprint = t.compute_message_imprint({"key": "value"})
        assert len(imprint) == 32

    def test_deterministic(self):
        t = RFC3161Timestamper(tsa_url="http://tsa.example.com")
        pkg = {"a": 1, "b": 2}
        assert t.compute_message_imprint(pkg) == t.compute_message_imprint(pkg)

    def test_different_dicts_different_imprints(self):
        t = RFC3161Timestamper(tsa_url="http://tsa.example.com")
        assert t.compute_message_imprint({"a": 1}) != t.compute_message_imprint({"a": 2})

    def test_key_order_irrelevant(self):
        t = RFC3161Timestamper(tsa_url="http://tsa.example.com")
        # sorted_keys=True means {"b":2,"a":1} == {"a":1,"b":2}
        assert t.compute_message_imprint({"b": 2, "a": 1}) == t.compute_message_imprint(
            {"a": 1, "b": 2}
        )

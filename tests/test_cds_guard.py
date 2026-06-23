# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for cross-domain solution guard (aegis.core.cds_guard)."""

from __future__ import annotations

import pytest

from aegis.core.cds_guard import (
    CDSCheckResult,
    CDSGuard,
    CDSPolicy,
    CDSViolationError,
    ClassificationDomain,
)

# ── Aliases for brevity ───────────────────────────────────────────────────────

UC = ClassificationDomain.UNCLASSIFIED
CUI = ClassificationDomain.CUI
SEC = ClassificationDomain.SECRET
TS = ClassificationDomain.TOP_SECRET

_CLEAN_TEXT = "This is normal unclassified data."
_SECRET_TEXT = "SECRET//NOFORN This data is secret."  # noqa: S105
_TS_TEXT = "TOP SECRET//SI//NOFORN classified text."


# ── ClassificationDomain enum ────────────────────────────────────────────────


class TestClassificationDomain:
    def test_values(self):
        assert UC.value == "UNCLASSIFIED"
        assert CUI.value == "CUI"
        assert SEC.value == "SECRET"
        assert TS.value == "TOP_SECRET"

    def test_is_string_enum(self):
        assert isinstance(UC, str)


# ── CDSPolicy dataclass ───────────────────────────────────────────────────────


class TestCDSPolicy:
    def test_frozen(self):
        p = CDSPolicy(
            source_domain=UC,
            dest_domain=SEC,
            allowed=True,
            require_sanitization=False,
            audit_required=True,
        )
        with pytest.raises((AttributeError, TypeError)):
            p.allowed = False  # type: ignore[misc]


# ── CDSCheckResult ────────────────────────────────────────────────────────────


class TestCDSCheckResult:
    def test_to_dict_structure(self):
        result = CDSCheckResult(
            allowed=True,
            source_domain=UC,
            dest_domain=SEC,
            sanitized=False,
            classified_markers_found=["SCI_SI"],
            reason="ok",
        )
        d = result.to_dict()
        assert d["allowed"] is True
        assert d["source_domain"] == "UNCLASSIFIED"
        assert d["dest_domain"] == "SECRET"
        assert d["sanitized"] is False
        assert d["classified_markers_found"] == ["SCI_SI"]
        assert d["reason"] == "ok"

    def test_to_dict_serializable(self):
        import json

        result = CDSCheckResult(
            allowed=False,
            source_domain=TS,
            dest_domain=UC,
            sanitized=True,
            classified_markers_found=["CLASSIFICATION_BANNER_TS"],
            reason="blocked",
        )
        json.dumps(result.to_dict())


# ── Same-domain transfers (always allowed) ────────────────────────────────────


class TestSameDomainTransfers:
    def test_uc_to_uc(self):
        guard = CDSGuard()
        result = guard.check_transfer(_CLEAN_TEXT, UC, UC)
        assert result.allowed is True

    def test_sec_to_sec(self):
        guard = CDSGuard()
        result = guard.check_transfer(_CLEAN_TEXT, SEC, SEC)
        assert result.allowed is True

    def test_ts_to_ts(self):
        guard = CDSGuard()
        result = guard.check_transfer(_CLEAN_TEXT, TS, TS)
        assert result.allowed is True

    def test_cui_to_cui(self):
        guard = CDSGuard()
        result = guard.check_transfer(_CLEAN_TEXT, CUI, CUI)
        assert result.allowed is True


# ── Upward transfers (allowed without sanitization) ────────────────────────────


class TestUpwardTransfers:
    def test_uc_to_cui(self):
        guard = CDSGuard()
        result = guard.check_transfer(_CLEAN_TEXT, UC, CUI)
        assert result.allowed is True
        assert result.sanitized is False

    def test_uc_to_secret(self):
        guard = CDSGuard()
        result = guard.check_transfer(_CLEAN_TEXT, UC, SEC)
        assert result.allowed is True

    def test_uc_to_ts(self):
        guard = CDSGuard()
        result = guard.check_transfer(_CLEAN_TEXT, UC, TS)
        assert result.allowed is True

    def test_cui_to_secret(self):
        guard = CDSGuard()
        result = guard.check_transfer(_CLEAN_TEXT, CUI, SEC)
        assert result.allowed is True

    def test_secret_to_ts(self):
        guard = CDSGuard()
        result = guard.check_transfer(_CLEAN_TEXT, SEC, TS)
        assert result.allowed is True


# ── Downward transfers (require sanitization) ──────────────────────────────────


class TestDownwardTransfers:
    def test_secret_to_uc_clean_data(self):
        guard = CDSGuard()
        result = guard.check_transfer(_CLEAN_TEXT, SEC, UC)
        assert result.allowed is True

    def test_secret_to_uc_with_markers(self):
        guard = CDSGuard()
        result = guard.check_transfer(_SECRET_TEXT, SEC, UC)
        assert result.allowed is True
        assert result.sanitized is True
        assert len(result.classified_markers_found) > 0

    def test_ts_to_uc_clean_data(self):
        guard = CDSGuard()
        result = guard.check_transfer(_CLEAN_TEXT, TS, UC)
        assert result.allowed is True

    def test_ts_to_secret_with_markers(self):
        guard = CDSGuard()
        result = guard.check_transfer(_TS_TEXT, TS, SEC)
        assert result.allowed is True
        assert result.sanitized is True

    def test_cui_to_uc_clean(self):
        guard = CDSGuard()
        result = guard.check_transfer(_CLEAN_TEXT, CUI, UC)
        assert result.allowed is True

    def test_secret_to_cui_with_markers(self):
        guard = CDSGuard()
        result = guard.check_transfer(_SECRET_TEXT, SEC, CUI)
        assert result.allowed is True
        assert result.sanitized is True


# ── Strict mode ───────────────────────────────────────────────────────────────


class TestStrictMode:
    def test_strict_blocks_upward(self):
        guard = CDSGuard(strict_mode=True)
        result = guard.check_transfer(_CLEAN_TEXT, UC, SEC)
        assert result.allowed is False

    def test_strict_blocks_downward(self):
        guard = CDSGuard(strict_mode=True)
        result = guard.check_transfer(_CLEAN_TEXT, SEC, UC)
        assert result.allowed is False

    def test_strict_blocks_lateral(self):
        guard = CDSGuard(strict_mode=True)
        result = guard.check_transfer(_CLEAN_TEXT, SEC, CUI)
        assert result.allowed is False

    def test_strict_allows_same_domain(self):
        guard = CDSGuard(strict_mode=True)
        result = guard.check_transfer(_CLEAN_TEXT, SEC, SEC)
        assert result.allowed is True

    def test_strict_reason_mentions_blocked(self):
        guard = CDSGuard(strict_mode=True)
        result = guard.check_transfer(_CLEAN_TEXT, UC, TS)
        assert "blocked" in result.reason.lower()


# ── sanitize ──────────────────────────────────────────────────────────────────


class TestSanitize:
    def test_sanitize_removes_markers(self):
        guard = CDSGuard()
        sanitized = guard.sanitize(_SECRET_TEXT, SEC)
        assert "[REDACTED-CDS]" in sanitized

    def test_sanitize_clean_text_unchanged(self):
        guard = CDSGuard()
        sanitized = guard.sanitize(_CLEAN_TEXT, UC)
        assert sanitized == _CLEAN_TEXT

    def test_sanitize_ts_markers(self):
        guard = CDSGuard()
        sanitized = guard.sanitize(_TS_TEXT, TS)
        assert "[REDACTED-CDS]" in sanitized

    def test_sanitize_returns_string(self):
        guard = CDSGuard()
        result = guard.sanitize(_SECRET_TEXT, SEC)
        assert isinstance(result, str)

    def test_sanitize_original_not_mutated(self):
        guard = CDSGuard()
        original = "SECRET//SI data"
        _ = guard.sanitize(original, SEC)
        assert "SECRET//SI" in original


# ── gate_transfer ─────────────────────────────────────────────────────────────


class TestGateTransfer:
    def test_gate_raises_on_strict_mode(self):
        guard = CDSGuard(strict_mode=True)
        with pytest.raises(CDSViolationError):
            guard.gate_transfer(_CLEAN_TEXT, UC, SEC)

    def test_gate_returns_data_on_same_domain(self):
        guard = CDSGuard()
        result = guard.gate_transfer(_CLEAN_TEXT, SEC, SEC)
        assert result == _CLEAN_TEXT

    def test_gate_returns_sanitized_on_downward_with_markers(self):
        guard = CDSGuard()
        result = guard.gate_transfer(_SECRET_TEXT, SEC, UC)
        assert isinstance(result, str)
        assert "[REDACTED-CDS]" in result

    def test_gate_returns_bytes_when_bytes_input_allowed(self):
        guard = CDSGuard()
        data = b"normal data"
        result = guard.gate_transfer(data, UC, UC)
        assert result == data

    def test_gate_bytes_sanitized_returns_bytes(self):
        guard = CDSGuard()
        data = _SECRET_TEXT.encode()
        result = guard.gate_transfer(data, SEC, UC)
        assert isinstance(result, bytes)

    def test_gate_upward_clean_passes_through(self):
        guard = CDSGuard()
        result = guard.gate_transfer(_CLEAN_TEXT, UC, TS)
        assert result == _CLEAN_TEXT

    def test_gate_violation_error_has_reason(self):
        guard = CDSGuard(strict_mode=True)
        with pytest.raises(CDSViolationError) as exc_info:
            guard.gate_transfer(_CLEAN_TEXT, UC, SEC)
        assert str(exc_info.value)


# ── check_transfer — CDSCheckResult fields ────────────────────────────────────


class TestCheckTransferResult:
    def test_source_domain_populated(self):
        guard = CDSGuard()
        result = guard.check_transfer(_CLEAN_TEXT, SEC, UC)
        assert result.source_domain == SEC

    def test_dest_domain_populated(self):
        guard = CDSGuard()
        result = guard.check_transfer(_CLEAN_TEXT, SEC, UC)
        assert result.dest_domain == UC

    def test_markers_empty_on_clean_data(self):
        guard = CDSGuard()
        result = guard.check_transfer(_CLEAN_TEXT, SEC, UC)
        assert result.classified_markers_found == []

    def test_markers_populated_on_classified_data(self):
        guard = CDSGuard()
        result = guard.check_transfer(_SECRET_TEXT, SEC, UC)
        assert len(result.classified_markers_found) > 0

    def test_reason_not_empty(self):
        guard = CDSGuard()
        result = guard.check_transfer(_CLEAN_TEXT, UC, SEC)
        assert result.reason


# ── from_env ──────────────────────────────────────────────────────────────────


class TestFromEnv:
    def test_from_env_defaults(self, monkeypatch):
        monkeypatch.delenv("AEGIS_CDS_STRICT_MODE", raising=False)
        monkeypatch.delenv("AEGIS_CDS_SOURCE_DOMAIN", raising=False)
        guard = CDSGuard.from_env()
        result = guard.check_transfer(_CLEAN_TEXT, UC, SEC)
        assert result.allowed is True

    def test_from_env_strict_mode_true(self, monkeypatch):
        monkeypatch.setenv("AEGIS_CDS_STRICT_MODE", "true")
        monkeypatch.delenv("AEGIS_CDS_SOURCE_DOMAIN", raising=False)
        guard = CDSGuard.from_env()
        result = guard.check_transfer(_CLEAN_TEXT, UC, SEC)
        assert result.allowed is False

    def test_from_env_strict_mode_1(self, monkeypatch):
        monkeypatch.setenv("AEGIS_CDS_STRICT_MODE", "1")
        monkeypatch.delenv("AEGIS_CDS_SOURCE_DOMAIN", raising=False)
        guard = CDSGuard.from_env()
        result = guard.check_transfer(_CLEAN_TEXT, CUI, SEC)
        assert result.allowed is False

    def test_from_env_source_domain_set(self, monkeypatch):
        monkeypatch.delenv("AEGIS_CDS_STRICT_MODE", raising=False)
        monkeypatch.setenv("AEGIS_CDS_SOURCE_DOMAIN", "SECRET")
        guard = CDSGuard.from_env()
        assert guard._source_domain == SEC

    def test_from_env_invalid_domain_defaults_to_uc(self, monkeypatch):
        monkeypatch.delenv("AEGIS_CDS_STRICT_MODE", raising=False)
        monkeypatch.setenv("AEGIS_CDS_SOURCE_DOMAIN", "INVALID_DOMAIN")
        guard = CDSGuard.from_env()
        assert guard._source_domain == UC

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.archival_bundle — algorithm-agile long-retention bundles."""

from __future__ import annotations

import json

import pytest

from aegis.core.archival_bundle import (
    ArchivalBundle,
    ArchivalBundleError,
    ArchivalBundleManager,
    ArchivalBundleVerifyResult,
    MigrationEvent,
    _canonical_content,
    _compute_hash,
    _compute_sig,
    _verify_sig,
)

_KEY = "archival-test-signing-key-long-retention"  # noqa: S105
_CONTENT: dict = {"evidence": "chain-hash-abc", "operator": "alice", "count": 42}


# ── Helpers ───────────────────────────────────────────────────────────────────


class TestCanonicalContent:
    def test_is_bytes(self) -> None:
        assert isinstance(_canonical_content(_CONTENT), bytes)

    def test_deterministic(self) -> None:
        assert _canonical_content(_CONTENT) == _canonical_content(dict(_CONTENT))

    def test_sorted_keys(self) -> None:
        a = _canonical_content({"b": 1, "a": 2})
        b = _canonical_content({"a": 2, "b": 1})
        assert a == b

    def test_different_content_different_bytes(self) -> None:
        assert _canonical_content({"x": 1}) != _canonical_content({"x": 2})


class TestComputeHash:
    def test_sha2_256(self) -> None:
        h = _compute_hash("sha2-256", b"hello")
        assert len(h) == 64

    def test_sha2_384(self) -> None:
        h = _compute_hash("sha2-384", b"hello")
        assert len(h) == 96

    def test_sha2_512(self) -> None:
        h = _compute_hash("sha2-512", b"hello")
        assert len(h) == 128

    def test_sha3_256(self) -> None:
        h = _compute_hash("sha3-256", b"hello")
        assert len(h) == 64

    def test_sha3_512(self) -> None:
        h = _compute_hash("sha3-512", b"hello")
        assert len(h) == 128

    def test_unknown_algo_raises(self) -> None:
        with pytest.raises(ArchivalBundleError, match="Unsupported hash"):
            _compute_hash("md5", b"data")

    def test_deterministic(self) -> None:
        assert _compute_hash("sha2-256", b"data") == _compute_hash("sha2-256", b"data")


class TestComputeSig:
    def test_hmac_sha2_256(self) -> None:
        s = _compute_sig("hmac-sha2-256", _KEY, b"data")
        assert len(s) == 64

    def test_hmac_sha3_256(self) -> None:
        s = _compute_sig("hmac-sha3-256", _KEY, b"data")
        assert len(s) == 64

    def test_unknown_algo_raises(self) -> None:
        with pytest.raises(ArchivalBundleError, match="Unsupported signature"):
            _compute_sig("rsa-sha256", _KEY, b"data")

    def test_verify_correct(self) -> None:
        s = _compute_sig("hmac-sha2-256", _KEY, b"data")
        assert _verify_sig("hmac-sha2-256", _KEY, b"data", s)

    def test_verify_wrong_key(self) -> None:
        s = _compute_sig("hmac-sha2-256", _KEY, b"data")
        assert not _verify_sig("hmac-sha2-256", "other-key", b"data", s)

    def test_verify_wrong_data(self) -> None:
        s = _compute_sig("hmac-sha2-256", _KEY, b"data")
        assert not _verify_sig("hmac-sha2-256", _KEY, b"other", s)

    def test_verify_unknown_algo_false(self) -> None:
        assert not _verify_sig("md5", _KEY, b"data", "aabbcc")


# ── MigrationEvent ────────────────────────────────────────────────────────────


class TestMigrationEvent:
    def test_to_dict_keys(self) -> None:
        ev = MigrationEvent(timestamp="2026-01-01T00:00:00+00:00", algo="sha3-512", kind="hash")
        d = ev.to_dict()
        assert set(d) == {"timestamp", "algo", "kind", "operator"}

    def test_to_dict_values(self) -> None:
        ev = MigrationEvent(
            timestamp="2026-01-01T00:00:00+00:00",
            algo="sha3-512",
            kind="hash",
            operator="bob",
        )
        assert ev.to_dict()["operator"] == "bob"
        assert ev.to_dict()["algo"] == "sha3-512"

    def test_default_operator_empty(self) -> None:
        ev = MigrationEvent(timestamp="t", algo="a", kind="hash")
        assert ev.to_dict()["operator"] == ""


# ── ArchivalBundle ────────────────────────────────────────────────────────────


class TestArchivalBundle:
    def _make(self) -> ArchivalBundle:
        return ArchivalBundle(
            format_version="1.0",
            bundle_id="test-id",
            created_at="2026-01-01T00:00:00+00:00",
            content={"k": "v"},
            hash_manifest={"sha2-256": "aabbcc"},
            signature_manifest={"hmac-sha2-256": "ddeeff"},
            migration_log=[],
        )

    def test_to_dict_keys(self) -> None:
        d = self._make().to_dict()
        expected = {
            "format_version",
            "bundle_id",
            "created_at",
            "content",
            "hash_manifest",
            "signature_manifest",
            "migration_log",
        }
        assert set(d) == expected

    def test_to_dict_immutable_copy(self) -> None:
        b = self._make()
        d = b.to_dict()
        d["hash_manifest"]["new"] = "x"
        assert "new" not in b.hash_manifest


# ── ArchivalBundleManager construction ────────────────────────────────────────


class TestManagerConstruction:
    def test_defaults(self) -> None:
        mgr = ArchivalBundleManager(signing_key=_KEY)
        assert "sha2-256" in mgr._hash_algos
        assert "sha3-256" in mgr._hash_algos
        assert mgr._sig_algo == "hmac-sha2-256"

    def test_custom_hash_algos(self) -> None:
        mgr = ArchivalBundleManager(signing_key=_KEY, hash_algos=["sha2-512", "sha3-512"])
        assert mgr._hash_algos == ["sha2-512", "sha3-512"]

    def test_invalid_hash_algo_raises(self) -> None:
        with pytest.raises(ArchivalBundleError, match="Unsupported hash"):
            ArchivalBundleManager(signing_key=_KEY, hash_algos=["md5"])

    def test_custom_sig_algo(self) -> None:
        mgr = ArchivalBundleManager(signing_key=_KEY, sig_algo="hmac-sha3-256")
        assert mgr._sig_algo == "hmac-sha3-256"

    def test_invalid_sig_algo_raises(self) -> None:
        with pytest.raises(ArchivalBundleError, match="Unsupported signature"):
            ArchivalBundleManager(signing_key=_KEY, sig_algo="rsa-sha256")

    def test_no_key_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AEGIS_SIGNING_KEY", "env-key")
        mgr = ArchivalBundleManager()
        assert mgr._signing_key == "env-key"

    def test_explicit_key_overrides_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AEGIS_SIGNING_KEY", "env-key")
        mgr = ArchivalBundleManager(signing_key="explicit-key")
        assert mgr._signing_key == "explicit-key"

    def test_supported_hash_algos_property(self) -> None:
        mgr = ArchivalBundleManager(signing_key=_KEY)
        assert "sha2-256" in mgr.supported_hash_algos
        assert "sha3-512" in mgr.supported_hash_algos

    def test_supported_sig_algos_property(self) -> None:
        mgr = ArchivalBundleManager(signing_key=_KEY)
        assert "hmac-sha2-256" in mgr.supported_sig_algos
        assert "hmac-sha3-256" in mgr.supported_sig_algos


# ── seal() ────────────────────────────────────────────────────────────────────


class TestSeal:
    def setup_method(self) -> None:
        self.mgr = ArchivalBundleManager(signing_key=_KEY)

    def test_returns_archival_bundle(self) -> None:
        b = self.mgr.seal(_CONTENT)
        assert isinstance(b, ArchivalBundle)

    def test_format_version(self) -> None:
        b = self.mgr.seal(_CONTENT)
        assert b.format_version == "1.0"

    def test_bundle_id_is_uuid(self) -> None:
        import uuid

        b = self.mgr.seal(_CONTENT)
        uuid.UUID(b.bundle_id)  # raises if not UUID

    def test_unique_bundle_ids(self) -> None:
        b1 = self.mgr.seal(_CONTENT)
        b2 = self.mgr.seal(_CONTENT)
        assert b1.bundle_id != b2.bundle_id

    def test_created_at_set(self) -> None:
        from datetime import datetime

        b = self.mgr.seal(_CONTENT)
        dt = datetime.fromisoformat(b.created_at)
        assert dt.tzinfo is not None

    def test_content_stored(self) -> None:
        b = self.mgr.seal(_CONTENT)
        assert b.content == _CONTENT

    def test_hash_manifest_has_default_algos(self) -> None:
        b = self.mgr.seal(_CONTENT)
        assert "sha2-256" in b.hash_manifest
        assert "sha3-256" in b.hash_manifest

    def test_hash_values_are_hex(self) -> None:
        b = self.mgr.seal(_CONTENT)
        for h in b.hash_manifest.values():
            int(h, 16)  # raises if not hex

    def test_signature_manifest_has_sig(self) -> None:
        b = self.mgr.seal(_CONTENT)
        assert "hmac-sha2-256" in b.signature_manifest

    def test_migration_log_has_initial_event(self) -> None:
        b = self.mgr.seal(_CONTENT, operator="alice")
        assert len(b.migration_log) == 1
        assert b.migration_log[0]["kind"] == "initial-seal"

    def test_no_key_seals_without_signature(self) -> None:
        mgr = ArchivalBundleManager(signing_key="")
        b = mgr.seal(_CONTENT)
        assert b.signature_manifest == {}

    def test_custom_hash_algos_in_seal(self) -> None:
        mgr = ArchivalBundleManager(signing_key=_KEY, hash_algos=["sha2-512"])
        b = mgr.seal(_CONTENT)
        assert "sha2-512" in b.hash_manifest
        assert "sha2-256" not in b.hash_manifest


# ── add_hash() ────────────────────────────────────────────────────────────────


class TestAddHash:
    def setup_method(self) -> None:
        self.mgr = ArchivalBundleManager(signing_key=_KEY)
        self.bundle = self.mgr.seal(_CONTENT, operator="alice")

    def test_adds_new_algo(self) -> None:
        b2 = self.mgr.add_hash(self.bundle, "sha2-512")
        assert "sha2-512" in b2.hash_manifest

    def test_preserves_existing_algos(self) -> None:
        b2 = self.mgr.add_hash(self.bundle, "sha2-512")
        assert "sha2-256" in b2.hash_manifest
        assert "sha3-256" in b2.hash_manifest

    def test_hash_value_is_correct(self) -> None:
        b2 = self.mgr.add_hash(self.bundle, "sha2-512")
        raw = _canonical_content(_CONTENT)
        expected = _compute_hash("sha2-512", raw)
        assert b2.hash_manifest["sha2-512"] == expected

    def test_migration_log_updated(self) -> None:
        b2 = self.mgr.add_hash(self.bundle, "sha3-512", operator="bob")
        assert len(b2.migration_log) == 2
        last = b2.migration_log[-1]
        assert last["algo"] == "sha3-512"
        assert last["kind"] == "hash"
        assert last["operator"] == "bob"

    def test_original_bundle_unchanged(self) -> None:
        b2 = self.mgr.add_hash(self.bundle, "sha2-512")  # noqa: F841
        assert "sha2-512" not in self.bundle.hash_manifest

    def test_duplicate_algo_raises(self) -> None:
        with pytest.raises(ArchivalBundleError, match="already present"):
            self.mgr.add_hash(self.bundle, "sha2-256")

    def test_unsupported_algo_raises(self) -> None:
        with pytest.raises(ArchivalBundleError, match="Unsupported hash"):
            self.mgr.add_hash(self.bundle, "md5")

    def test_all_supported_algos_can_be_added(self) -> None:
        b = self.bundle
        for algo in ["sha2-384", "sha2-512", "sha3-512"]:
            b = self.mgr.add_hash(b, algo)
        for algo in ["sha2-384", "sha2-512", "sha3-512"]:
            assert algo in b.hash_manifest


# ── add_signature() ───────────────────────────────────────────────────────────


class TestAddSignature:
    def setup_method(self) -> None:
        self.mgr = ArchivalBundleManager(signing_key=_KEY)
        self.bundle = self.mgr.seal(_CONTENT, operator="alice")

    def test_adds_new_sig_algo(self) -> None:
        b2 = self.mgr.add_signature(self.bundle, "hmac-sha3-256")
        assert "hmac-sha3-256" in b2.signature_manifest

    def test_preserves_existing_sig(self) -> None:
        b2 = self.mgr.add_signature(self.bundle, "hmac-sha3-256")
        assert "hmac-sha2-256" in b2.signature_manifest

    def test_sig_value_verifies(self) -> None:
        b2 = self.mgr.add_signature(self.bundle, "hmac-sha3-256")
        raw = _canonical_content(_CONTENT)
        expected = _compute_sig("hmac-sha3-256", _KEY, raw)
        assert b2.signature_manifest["hmac-sha3-256"] == expected

    def test_migration_log_updated(self) -> None:
        b2 = self.mgr.add_signature(self.bundle, "hmac-sha3-256", operator="carol")
        assert len(b2.migration_log) == 2
        last = b2.migration_log[-1]
        assert last["algo"] == "hmac-sha3-256"
        assert last["kind"] == "signature"

    def test_duplicate_sig_algo_raises(self) -> None:
        with pytest.raises(ArchivalBundleError, match="already in signature_manifest"):
            self.mgr.add_signature(self.bundle, "hmac-sha2-256")

    def test_unsupported_sig_algo_raises(self) -> None:
        with pytest.raises(ArchivalBundleError, match="Unsupported signature"):
            self.mgr.add_signature(self.bundle, "rsa-sha256")

    def test_no_key_raises(self) -> None:
        mgr_no_key = ArchivalBundleManager(signing_key="")
        b = mgr_no_key.seal(_CONTENT)
        with pytest.raises(ArchivalBundleError, match="No signing key"):
            mgr_no_key.add_signature(b, "hmac-sha3-256")


# ── verify() ──────────────────────────────────────────────────────────────────


class TestVerify:
    def setup_method(self) -> None:
        self.mgr = ArchivalBundleManager(signing_key=_KEY)

    def test_fresh_seal_verifies(self) -> None:
        b = self.mgr.seal(_CONTENT)
        result = self.mgr.verify(b)
        assert result.valid

    def test_result_type(self) -> None:
        b = self.mgr.seal(_CONTENT)
        result = self.mgr.verify(b)
        assert isinstance(result, ArchivalBundleVerifyResult)

    def test_hash_results_keys(self) -> None:
        b = self.mgr.seal(_CONTENT)
        result = self.mgr.verify(b)
        assert "sha2-256" in result.hash_results
        assert "sha3-256" in result.hash_results

    def test_sig_results_keys(self) -> None:
        b = self.mgr.seal(_CONTENT)
        result = self.mgr.verify(b)
        assert "hmac-sha2-256" in result.sig_results

    def test_all_true_on_valid_bundle(self) -> None:
        b = self.mgr.seal(_CONTENT)
        result = self.mgr.verify(b)
        assert all(result.hash_results.values())
        assert all(result.sig_results.values())

    def test_tampered_content_fails(self) -> None:
        b = self.mgr.seal(_CONTENT)
        # Mutate content directly (simulates tamper)
        tampered = ArchivalBundle(
            format_version=b.format_version,
            bundle_id=b.bundle_id,
            created_at=b.created_at,
            content={"evidence": "TAMPERED"},
            hash_manifest=dict(b.hash_manifest),
            signature_manifest=dict(b.signature_manifest),
            migration_log=list(b.migration_log),
        )
        result = self.mgr.verify(tampered)
        assert not result.valid
        assert len(result.failed_algos) > 0

    def test_tampered_hash_fails(self) -> None:
        b = self.mgr.seal(_CONTENT)
        bad_manifest = dict(b.hash_manifest)
        bad_manifest["sha2-256"] = "a" * 64
        tampered = ArchivalBundle(
            format_version=b.format_version,
            bundle_id=b.bundle_id,
            created_at=b.created_at,
            content=b.content,
            hash_manifest=bad_manifest,
            signature_manifest=dict(b.signature_manifest),
            migration_log=list(b.migration_log),
        )
        result = self.mgr.verify(tampered)
        assert not result.valid
        assert "sha2-256" in result.failed_algos

    def test_tampered_signature_fails(self) -> None:
        b = self.mgr.seal(_CONTENT)
        bad_sigs = dict(b.signature_manifest)
        bad_sigs["hmac-sha2-256"] = "b" * 64
        tampered = ArchivalBundle(
            format_version=b.format_version,
            bundle_id=b.bundle_id,
            created_at=b.created_at,
            content=b.content,
            hash_manifest=dict(b.hash_manifest),
            signature_manifest=bad_sigs,
            migration_log=list(b.migration_log),
        )
        result = self.mgr.verify(tampered)
        assert not result.valid
        assert "hmac-sha2-256" in result.failed_algos

    def test_no_key_sig_fails(self) -> None:
        b = self.mgr.seal(_CONTENT)
        mgr_no_key = ArchivalBundleManager(signing_key="")
        result = mgr_no_key.verify(b)
        assert not result.valid
        assert "hmac-sha2-256" in result.failed_algos

    def test_bundle_without_sig_verifies_hashes(self) -> None:
        mgr_no_key = ArchivalBundleManager(signing_key="")
        b = mgr_no_key.seal(_CONTENT)
        assert b.signature_manifest == {}
        result = mgr_no_key.verify(b)
        assert result.valid

    def test_migrated_bundle_verifies(self) -> None:
        b = self.mgr.seal(_CONTENT)
        b = self.mgr.add_hash(b, "sha3-512")
        b = self.mgr.add_signature(b, "hmac-sha3-256")
        result = self.mgr.verify(b)
        assert result.valid
        assert "sha3-512" in result.hash_results
        assert "hmac-sha3-256" in result.sig_results

    def test_reason_empty_on_success(self) -> None:
        b = self.mgr.seal(_CONTENT)
        result = self.mgr.verify(b)
        assert result.reason == ""

    def test_reason_mentions_failed_algos(self) -> None:
        b = self.mgr.seal(_CONTENT)
        tampered = ArchivalBundle(
            format_version=b.format_version,
            bundle_id=b.bundle_id,
            created_at=b.created_at,
            content={"x": "tampered"},
            hash_manifest=dict(b.hash_manifest),
            signature_manifest=dict(b.signature_manifest),
            migration_log=list(b.migration_log),
        )
        result = self.mgr.verify(tampered)
        assert "sha2-256" in result.reason or "sha3-256" in result.reason

    def test_failed_algos_empty_on_success(self) -> None:
        b = self.mgr.seal(_CONTENT)
        result = self.mgr.verify(b)
        assert result.failed_algos == []

    def test_to_dict_shape(self) -> None:
        b = self.mgr.seal(_CONTENT)
        result = self.mgr.verify(b)
        d = result.to_dict()
        assert set(d) == {"valid", "hash_results", "sig_results", "failed_algos", "reason"}


# ── export / import ───────────────────────────────────────────────────────────


class TestExportImport:
    def setup_method(self) -> None:
        self.mgr = ArchivalBundleManager(signing_key=_KEY)

    def test_export_json_returns_string(self) -> None:
        b = self.mgr.seal(_CONTENT)
        s = self.mgr.export_json(b)
        assert isinstance(s, str)

    def test_export_is_valid_json(self) -> None:
        b = self.mgr.seal(_CONTENT)
        json.loads(self.mgr.export_json(b))

    def test_roundtrip_verifies(self) -> None:
        b = self.mgr.seal(_CONTENT)
        s = self.mgr.export_json(b)
        b2 = self.mgr.import_json(s)
        result = self.mgr.verify(b2)
        assert result.valid

    def test_import_restores_fields(self) -> None:
        b = self.mgr.seal(_CONTENT)
        s = self.mgr.export_json(b)
        b2 = self.mgr.import_json(s)
        assert b2.bundle_id == b.bundle_id
        assert b2.content == b.content
        assert b2.hash_manifest == b.hash_manifest
        assert b2.signature_manifest == b.signature_manifest

    def test_import_invalid_json_raises(self) -> None:
        with pytest.raises(ArchivalBundleError, match="Invalid bundle JSON"):
            self.mgr.import_json("not-json")

    def test_import_missing_fields_raises(self) -> None:
        with pytest.raises(ArchivalBundleError, match="missing required fields"):
            self.mgr.import_json(json.dumps({"format_version": "1.0"}))

    def test_import_with_empty_manifests(self) -> None:
        d = {
            "format_version": "1.0",
            "bundle_id": "x",
            "created_at": "t",
            "content": {"k": "v"},
        }
        b = self.mgr.import_json(json.dumps(d))
        assert b.hash_manifest == {}
        assert b.signature_manifest == {}
        assert b.migration_log == []

    def test_migrated_bundle_roundtrip(self) -> None:
        b = self.mgr.seal(_CONTENT)
        b = self.mgr.add_hash(b, "sha3-512")
        b = self.mgr.add_signature(b, "hmac-sha3-256")
        s = self.mgr.export_json(b)
        b2 = self.mgr.import_json(s)
        result = self.mgr.verify(b2)
        assert result.valid
        assert len(b2.migration_log) == 3  # initial + add_hash + add_signature


# ── ArchivalBundleVerifyResult defaults ───────────────────────────────────────


class TestVerifyResultDefaults:
    def test_defaults(self) -> None:
        r = ArchivalBundleVerifyResult(valid=True)
        assert r.hash_results == {}
        assert r.sig_results == {}
        assert r.failed_algos == []
        assert r.reason == ""

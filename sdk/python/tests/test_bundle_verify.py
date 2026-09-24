# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Offline forensic-bundle verification: what passes, what fails, and why.

The fixture is a real bundle the gateway built (``scripts/generate_sdk_bundle_fixture.py``).
The tamper cases rebuild it the way someone who can rewrite the archive could:
re-hashing files and re-sealing the manifest so every internal digest agrees.
The point those cases pin is the module's central boundary — such a rewrite is
caught by the manifest signature and by nothing else, so without a verified
signature the result must stay ``incomplete``.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import sys
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from aegis_sdk import bundle as bundle_module
from aegis_sdk.bundle import (
    BundleInputError,
    BundleReport,
    load_ed25519_public_key,
    verify_bundle,
)

SHARED = Path(__file__).parents[2] / "shared"
FIXTURE = SHARED / "forensic-bundle-v1.zip"
FIXTURE_KEY = load_ed25519_public_key((SHARED / "forensic-bundle-v1.pub.hex").read_bytes())
EVIDENCE = ("audit_certificate.pdf", "ledger_slice.cbor", "merkle_proof.json")


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _members(raw: bytes) -> dict[str, bytes]:
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def _zip(members: dict[str, bytes], compression: int = zipfile.ZIP_DEFLATED) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=compression) as archive:
        for name, payload in members.items():
            archive.writestr(name, payload)
    return out.getvalue()


def _reissue(
    members: dict[str, bytes],
    *,
    edit: Callable[[dict[str, Any]], None] | None = None,
    sign_with: Ed25519PrivateKey | None = None,
) -> bytes:
    """Rebuild the manifest over the evidence bytes, exactly as the gateway would."""
    manifest = json.loads(members["manifest.json"])
    payload = {key: value for key, value in manifest.items() if key != "manifest_payload_sha256"}
    payload["files"] = [
        {
            "name": name,
            "sha256": hashlib.sha256(members[name]).hexdigest(),
            "size": len(members[name]),
        }
        for name in EVIDENCE
    ]
    cid = bytes([0x01, 0x71, 0x12, 0x20]) + hashlib.sha256(members["ledger_slice.cbor"]).digest()
    payload["ledger_slice_cid"] = "b" + base64.b32encode(cid).decode().lower().rstrip("=")
    if edit is not None:
        edit(payload)
    raw = _canonical(
        {**payload, "manifest_payload_sha256": hashlib.sha256(_canonical(payload)).hexdigest()}
    )
    rebuilt = dict(members)
    rebuilt["manifest.json"] = raw
    if sign_with is not None:
        rebuilt["manifest.json.sig"] = sign_with.sign(raw)
    return _zip(rebuilt)


def _pem(raw: bytes) -> bytes:
    """The SubjectPublicKeyInfo PEM an operator would hand out (what VERIFY.sh reads)."""
    return Ed25519PublicKey.from_public_bytes(raw).public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _failed_at(report: BundleReport) -> str:
    assert report.result == "failed"
    return next(check.name for check in report.checks if check.status == "fail")


def _status(report: BundleReport, name: str) -> str:
    return next(check.status for check in report.checks if check.name == name)


@pytest.fixture
def fixture_bytes() -> bytes:
    return FIXTURE.read_bytes()


# ── the gateway-issued bundle ────────────────────────────────────────────────


def test_the_gateway_issued_bundle_verifies_against_its_out_of_band_key() -> None:
    report = verify_bundle(FIXTURE, public_key=FIXTURE_KEY)
    assert report.result == "verified"
    assert [(check.name, check.status) for check in report.checks] == [
        ("archive", "pass"),
        ("manifest", "pass"),
        ("file_digests", "pass"),
        ("ledger_slice_cid", "pass"),
        ("mmr_proofs", "pass"),
        ("trusted_root", "skip"),
        ("manifest_signature", "pass"),
        ("node_signatures", "skip"),
    ]


def test_without_a_key_a_signed_bundle_is_incomplete_not_verified() -> None:
    report = verify_bundle(FIXTURE)
    assert report.result == "incomplete"
    assert _status(report, "manifest_signature") == "skip"


def test_without_cryptography_the_signature_is_reported_unchecked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(sys.modules, "cryptography.hazmat.primitives.asymmetric.ed25519", None)
    report = verify_bundle(FIXTURE, public_key=FIXTURE_KEY)
    assert report.result == "incomplete"
    detail = next(c.detail for c in report.checks if c.name == "manifest_signature")
    assert "NOT checked" in detail
    assert "aegis-latent-sdk[verify]" in detail


def test_a_different_key_fails_the_signature() -> None:
    other = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    assert _failed_at(verify_bundle(FIXTURE, public_key=other)) == "manifest_signature"


def test_bytes_and_path_inputs_agree(fixture_bytes: bytes) -> None:
    assert verify_bundle(fixture_bytes, public_key=FIXTURE_KEY).result == "verified"


def test_a_matching_trusted_root_passes_and_a_different_one_fails(fixture_bytes: bytes) -> None:
    root = json.loads(_members(fixture_bytes)["manifest.json"])["terminal_mmr_root"]
    assert _status(verify_bundle(FIXTURE, trusted_root=root), "trusted_root") == "pass"
    assert _failed_at(verify_bundle(FIXTURE, trusted_root="0" * 64)) == "trusted_root"


# ── a consistent rewrite: caught only by the signature ──────────────────────


def test_a_consistent_rewrite_is_caught_by_the_signature_and_only_by_it(
    fixture_bytes: bytes,
) -> None:
    def relabel(payload: dict[str, Any]) -> None:
        payload["operator"] = "someone-else"

    rewritten = _reissue(_members(fixture_bytes), edit=relabel)
    assert verify_bundle(rewritten).result == "incomplete"
    assert _failed_at(verify_bundle(rewritten, public_key=FIXTURE_KEY)) == "manifest_signature"


def test_a_rewrite_re_signed_with_another_key_fails_against_the_real_key(
    fixture_bytes: bytes,
) -> None:
    forger = Ed25519PrivateKey.generate()
    rewritten = _reissue(_members(fixture_bytes), sign_with=forger)
    assert _failed_at(verify_bundle(rewritten, public_key=FIXTURE_KEY)) == "manifest_signature"
    assert (
        verify_bundle(rewritten, public_key=forger.public_key().public_bytes_raw()).result
        == "verified"
    ), (
        "the forger's key verifies the forger's signature — which is why the key must come out of band"
    )


def test_a_stripped_signature_fails_when_a_key_is_supplied(fixture_bytes: bytes) -> None:
    members = _members(fixture_bytes)
    del members["manifest.json.sig"]
    stripped = _zip(members)
    assert _failed_at(verify_bundle(stripped, public_key=FIXTURE_KEY)) == "manifest_signature"
    unsigned = verify_bundle(stripped)
    assert unsigned.result == "incomplete"
    assert "unsigned" in next(c.detail for c in unsigned.checks if c.name == "manifest_signature")


def test_a_truncated_signature_fails(fixture_bytes: bytes) -> None:
    members = _members(fixture_bytes)
    members["manifest.json.sig"] = members["manifest.json.sig"][:63]
    report = verify_bundle(_zip(members), public_key=FIXTURE_KEY)
    assert _failed_at(report) == "manifest_signature"


# ── corruption the digests catch without any key ───────────────────────────


@pytest.mark.parametrize("name", EVIDENCE)
def test_a_changed_evidence_byte_fails_its_digest(fixture_bytes: bytes, name: str) -> None:
    members = _members(fixture_bytes)
    members[name] = members[name][:-1] + bytes([members[name][-1] ^ 0x01])
    assert _failed_at(verify_bundle(_zip(members))) == "file_digests"


def test_an_edited_manifest_that_is_not_resealed_fails(fixture_bytes: bytes) -> None:
    members = _members(fixture_bytes)
    manifest = json.loads(members["manifest.json"])
    manifest["operator"] = "someone-else"
    members["manifest.json"] = _canonical(manifest)
    assert _failed_at(verify_bundle(_zip(members))) == "manifest"


def test_a_non_canonical_manifest_fails(fixture_bytes: bytes) -> None:
    members = _members(fixture_bytes)
    members["manifest.json"] = json.dumps(json.loads(members["manifest.json"]), indent=1).encode()
    assert _failed_at(verify_bundle(_zip(members))) == "manifest"


def test_a_manifest_with_a_duplicate_key_fails(fixture_bytes: bytes) -> None:
    members = _members(fixture_bytes)
    members["manifest.json"] = b'{"node_count":1,' + members["manifest.json"][1:]
    assert _failed_at(verify_bundle(_zip(members))) == "manifest"


def test_a_wrong_ledger_cid_fails(fixture_bytes: bytes) -> None:
    def wrong_cid(payload: dict[str, Any]) -> None:
        payload["ledger_slice_cid"] = "b" + "a" * 58

    assert _failed_at(verify_bundle(_reissue(_members(fixture_bytes), edit=wrong_cid))) == (
        "ledger_slice_cid"
    )


def test_a_wrong_node_count_fails(fixture_bytes: bytes) -> None:
    def miscount(payload: dict[str, Any]) -> None:
        payload["node_count"] += 1

    assert _failed_at(verify_bundle(_reissue(_members(fixture_bytes), edit=miscount))) == (
        "manifest"
    )


# ── MMR proofs, even when the manifest is consistent ────────────────────────


def _edit_proofs(fixture_bytes: bytes, edit: Callable[[list[dict[str, Any]]], None]) -> bytes:
    members = _members(fixture_bytes)
    proof_set = json.loads(members["merkle_proof.json"])
    edit(proof_set["proofs"])
    members["merkle_proof.json"] = _canonical(proof_set)
    return _reissue(members)


def test_a_forged_leaf_hash_fails_its_inclusion_proof(fixture_bytes: bytes) -> None:
    def forge(proofs: list[dict[str, Any]]) -> None:
        proofs[1]["leaf_hash"] = "ab" * 32

    assert _failed_at(verify_bundle(_edit_proofs(fixture_bytes, forge))) == "mmr_proofs"


def test_a_proof_for_a_node_the_manifest_does_not_list_fails(fixture_bytes: bytes) -> None:
    def rename(proofs: list[dict[str, Any]]) -> None:
        proofs[0]["state_id"] = "not-in-the-manifest"

    assert _failed_at(verify_bundle(_edit_proofs(fixture_bytes, rename))) == "mmr_proofs"


def test_a_repeated_proof_fails(fixture_bytes: bytes) -> None:
    def repeat(proofs: list[dict[str, Any]]) -> None:
        proofs.append(dict(proofs[0]))

    assert _failed_at(verify_bundle(_edit_proofs(fixture_bytes, repeat))) == "mmr_proofs"


def test_a_position_that_disagrees_with_the_proof_fails(fixture_bytes: bytes) -> None:
    def shift(proofs: list[dict[str, Any]]) -> None:
        proofs[2]["leaf_index"] = 0

    assert _failed_at(verify_bundle(_edit_proofs(fixture_bytes, shift))) == "mmr_proofs"


def test_a_terminal_root_other_than_the_last_nodes_root_fails(fixture_bytes: bytes) -> None:
    def reroot(payload: dict[str, Any]) -> None:
        payload["terminal_mmr_root"] = "cd" * 32

    assert _failed_at(verify_bundle(_reissue(_members(fixture_bytes), edit=reroot))) == (
        "mmr_proofs"
    )


def test_a_bundle_without_proofs_skips_rather_than_passes(fixture_bytes: bytes) -> None:
    report = verify_bundle(_edit_proofs(fixture_bytes, lambda proofs: proofs.clear()))
    assert _status(report, "mmr_proofs") == "skip"


# ── the archive itself ───────────────────────────────────────────────────────


def test_an_undeclared_member_fails(fixture_bytes: bytes) -> None:
    members = _members(fixture_bytes)
    members["README.txt"] = b"trust me"
    assert _failed_at(verify_bundle(_zip(members))) == "archive"


def test_a_duplicated_member_fails(fixture_bytes: bytes) -> None:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as archive:
        for name, payload in _members(fixture_bytes).items():
            archive.writestr(name, payload)
        with pytest.warns(UserWarning, match="Duplicate name"):
            archive.writestr("ledger_slice.cbor", b"second copy")
    assert _failed_at(verify_bundle(out.getvalue())) == "archive"


def test_a_missing_member_fails(fixture_bytes: bytes) -> None:
    members = _members(fixture_bytes)
    del members["merkle_proof.json"]
    assert _failed_at(verify_bundle(_zip(members))) == "archive"


def test_an_unsupported_compression_method_fails(fixture_bytes: bytes) -> None:
    rebuilt = _zip(_members(fixture_bytes), compression=zipfile.ZIP_BZIP2)
    assert _failed_at(verify_bundle(rebuilt)) == "archive"


def test_something_that_is_not_a_zip_fails() -> None:
    assert _failed_at(verify_bundle(b"PK-but-not-really")) == "archive"


def test_an_archive_over_the_size_cap_is_refused_unopened(
    fixture_bytes: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(bundle_module, "MAX_ARCHIVE_BYTES", len(fixture_bytes) - 1)
    assert _failed_at(verify_bundle(fixture_bytes)) == "archive"
    assert _failed_at(verify_bundle(FIXTURE)) == "archive"


def test_decompression_is_capped_on_bytes_read_not_declared(
    fixture_bytes: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(bundle_module, "MAX_MEMBER_BYTES", 16)
    report = verify_bundle(fixture_bytes)
    assert _failed_at(report) == "archive"
    assert "decompresses past" in report.checks[-1].detail


# ── inputs ───────────────────────────────────────────────────────────────────


def test_public_key_encodings() -> None:
    raw = FIXTURE_KEY
    assert load_ed25519_public_key(_pem(raw)) == raw
    assert load_ed25519_public_key(_pem(raw).replace(b"\n", b"\r\n")) == raw
    assert load_ed25519_public_key(raw.hex().encode() + b"\n") == raw
    assert load_ed25519_public_key(raw.hex().upper().encode()) == raw
    assert load_ed25519_public_key(raw) == raw


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"not a key",
        b"-----BEGIN PUBLIC KEY-----\n!!!!\n-----END PUBLIC KEY-----\n",
        b"-----BEGIN PUBLIC KEY-----\nAAAA\n",
        b"\x00" * 31,
    ],
)
def test_malformed_public_keys_are_refused(data: bytes) -> None:
    with pytest.raises(BundleInputError):
        load_ed25519_public_key(data)


def test_a_non_ed25519_pem_is_refused() -> None:
    from cryptography.hazmat.primitives.asymmetric import ec

    pem = (
        ec.generate_private_key(ec.SECP256R1())
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    with pytest.raises(BundleInputError, match="not an Ed25519"):
        load_ed25519_public_key(pem)


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"public_key": b"\x00" * 31}, "32 raw bytes"),
        ({"trusted_root": "AB" * 32}, "lowercase 64-hex"),
        ({"trusted_root": "ab"}, "lowercase 64-hex"),
    ],
)
def test_malformed_arguments_are_input_errors(kwargs: dict[str, Any], message: str) -> None:
    with pytest.raises(BundleInputError, match=message):
        verify_bundle(FIXTURE, **kwargs)


def test_a_missing_path_is_an_input_error(tmp_path: Path) -> None:
    with pytest.raises(BundleInputError, match="cannot read bundle"):
        verify_bundle(tmp_path / "absent.zip")


def test_the_report_serialises_deterministically() -> None:
    mapping = verify_bundle(FIXTURE, public_key=FIXTURE_KEY).to_mapping()
    assert mapping["result"] == "verified"
    assert [check["name"] for check in mapping["checks"]][0] == "archive"
    assert json.loads(json.dumps(mapping, sort_keys=True)) == mapping


# ── hostile archives: bounded work, nothing printed raw ──────────────────────


def test_a_central_directory_with_thousands_of_entries_is_refused_before_iterating() -> None:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as archive:
        for index in range(5_000):
            archive.writestr(f"m{index}", b"")
    report = verify_bundle(out.getvalue())
    assert _failed_at(report) == "archive"
    assert "at most 6" in report.checks[-1].detail


def test_archive_supplied_names_are_escaped_before_they_can_reach_a_terminal(
    fixture_bytes: bytes,
) -> None:
    members = _members(fixture_bytes)
    del members["VERIFY.sh"]
    members["\x1b[2Jevil"] = b""
    detail = verify_bundle(_zip(members)).checks[-1].detail
    assert "\x1b" not in detail
    assert "\\x1b" in detail


def test_manifest_supplied_schemes_are_escaped_and_capped(fixture_bytes: bytes) -> None:
    def hostile(payload: dict[str, Any]) -> None:
        payload["signatures"][0]["scheme"] = "\x1b[31mred"

    report = verify_bundle(_reissue(_members(fixture_bytes), edit=hostile))
    detail = next(c.detail for c in report.checks if c.name == "node_signatures")
    assert "\x1b" not in detail
    assert "\\x1b" in detail


def test_a_manifest_nested_past_the_parser_limit_fails_instead_of_crashing(
    fixture_bytes: bytes,
) -> None:
    members = _members(fixture_bytes)
    members["manifest.json"] = b"[" * 200_000 + b"]" * 200_000
    report = verify_bundle(_zip(members))
    assert _failed_at(report) == "manifest"

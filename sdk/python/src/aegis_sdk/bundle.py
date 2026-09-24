# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Offline verification of an Aegis forensic bundle (``aegis-forensic-bundle-v1``).

The gateway's export endpoint writes a ZIP holding ``manifest.json``, three
evidence files, an optional detached Ed25519 signature over the manifest
(``manifest.json.sig``) and a ``VERIFY.sh``. This module re-derives everything
in that archive that can be re-derived without the gateway, using only the
standard library, and says precisely what it did not check.

What a ``verified`` result means, and no more:

* every member is one the bundle format defines, and none is duplicated;
* ``manifest.json`` is byte-canonical and its self-seal matches;
* each evidence file's size and SHA-256 match the manifest;
* the ledger slice's CID matches its bytes;
* every MMR inclusion proof in ``merkle_proof.json`` verifies against the root
  recorded beside it, and the last node's root is the manifest's terminal root;
* ``manifest.json`` carries an Ed25519 signature that verifies against a public
  key **the caller supplied**, obtained out of band.

Without that last step the digests detect corruption, not tampering: anyone who
can rewrite a record can rewrite the manifest beside it. So a bundle that is
unsigned, or checked without a key, or checked where the ``cryptography``
package is absent, is reported ``incomplete`` — never ``verified``.

Not checked here: the per-node signatures (their keys and node-hash preimage are
outside the manifest contract), the contents of the CBOR ledger slice beyond its
digest, the PDF certificate beyond its digest, and whether any root is one the
caller should trust — pass ``trusted_root`` for that. Nothing here establishes
time, identity, custody or legal admissibility.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import json
import os
import re
import zipfile
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from typing import IO, Any, Literal

from aegis_sdk.proof import AegisProofError, InclusionProof, verify_inclusion_hash

BUNDLE_VERSION = "aegis-forensic-bundle-v1"
PROOF_SET_VERSION = "aegis-mmr-proof-set-v1"

#: The gateway refuses to build a bundle larger than this, so a verifier has no
#: reason to open one that is.
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
#: Enforced on bytes actually decompressed, not on the size a header declares.
MAX_MEMBER_BYTES = 256 * 1024 * 1024
#: The manifest, proof set and signature are held in memory; nothing else is.
MAX_IN_MEMORY_BYTES = 64 * 1024 * 1024

MANIFEST = "manifest.json"
MANIFEST_SIGNATURE = "manifest.json.sig"
VERIFY_SCRIPT = "VERIFY.sh"
EVIDENCE_FILES = frozenset({"audit_certificate.pdf", "ledger_slice.cbor", "merkle_proof.json"})
_ALLOWED_MEMBERS = EVIDENCE_FILES | {MANIFEST, MANIFEST_SIGNATURE, VERIFY_SCRIPT}
_KEPT_IN_MEMORY = frozenset({MANIFEST, MANIFEST_SIGNATURE, "merkle_proof.json"})

_SEAL_KEY = "manifest_payload_sha256"
_MANIFEST_KEYS = frozenset(
    {
        "bundle_version",
        "canonicalization",
        "created_at",
        "operator",
        "acquisition_reason",
        "scope_start",
        "scope_end",
        "node_count",
        "terminal_mmr_root",
        "ledger_slice_cid",
        "files",
        "signatures",
        "limitations",
        _SEAL_KEY,
    }
)
_FILE_ENTRY_KEYS = frozenset({"name", "sha256", "size"})
_NODE_SIGNATURE_KEYS = frozenset({"state_id", "node_hash", "scheme", "signature", "public_key"})
_PROOF_ENTRY_KEYS = frozenset(
    {"state_id", "leaf_hash", "leaf_index", "leaf_count", "root", "proof"}
)
_HEX64 = re.compile(r"[0-9a-f]{64}")

# SubjectPublicKeyInfo DER prefix for an Ed25519 key (RFC 8410): the PEM form
# `openssl pkey -pubout` writes and `VERIFY.sh` reads.
_ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")

CheckStatus = Literal["pass", "fail", "skip"]
Result = Literal["verified", "incomplete", "failed"]


class BundleInputError(ValueError):
    """The caller's input could not be used at all (missing file, bad key, bad root)."""


@dataclass(frozen=True)
class Check:
    """One named step and its outcome. ``detail`` says what was compared."""

    name: str
    status: CheckStatus
    detail: str


@dataclass(frozen=True)
class BundleReport:
    checks: tuple[Check, ...]

    @property
    def result(self) -> Result:
        """``verified`` only when nothing failed *and* the manifest signature verified."""
        if any(check.status == "fail" for check in self.checks):
            return "failed"
        signature = next((c for c in self.checks if c.name == "manifest_signature"), None)
        if signature is not None and signature.status == "pass":
            return "verified"
        return "incomplete"

    def to_mapping(self) -> dict[str, Any]:
        return {
            "result": self.result,
            "checks": [
                {"name": check.name, "status": check.status, "detail": check.detail}
                for check in self.checks
            ],
        }


class _FailedCheckError(Exception):
    """Internal: ends verification with a failed check."""

    def __init__(self, name: str, detail: str) -> None:
        super().__init__(detail)
        self.check = Check(name, "fail", detail)


def _shown(value: object, limit: int = 80) -> str:
    """Archive-supplied text as it may be printed: ASCII-escaped and truncated.

    Member names, schemes and other strings come from the bundle, which may be
    hostile; printing them raw would let it write terminal control sequences.
    """
    text = ascii(value)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def load_ed25519_public_key(data: bytes) -> bytes:
    """Return the raw 32-byte key from PEM (SPKI), 64-char hex, or raw bytes.

    Stdlib-only, so a malformed key file is reported even where ``cryptography``
    is not installed. Any other encoding is refused rather than guessed at.
    """
    text = data.strip()
    if text.startswith(b"-----BEGIN PUBLIC KEY-----"):
        lines = text.splitlines()
        if lines[-1].strip() != b"-----END PUBLIC KEY-----":
            raise BundleInputError("public key PEM is not terminated")
        try:
            der = base64.b64decode(b"".join(line.strip() for line in lines[1:-1]), validate=True)
        except (ValueError, binascii.Error) as exc:
            raise BundleInputError("public key PEM body is not valid base64") from exc
        if len(der) != 44 or not der.startswith(_ED25519_SPKI_PREFIX):
            raise BundleInputError("public key PEM is not an Ed25519 SubjectPublicKeyInfo")
        return der[len(_ED25519_SPKI_PREFIX) :]
    if len(text) == 64 and _HEX64.fullmatch(text.decode("ascii", "replace").lower()):
        return bytes.fromhex(text.decode("ascii"))
    if len(data) == 32:
        return data
    raise BundleInputError("public key must be Ed25519: PEM, 64 hex characters, or 32 raw bytes")


def _ed25519_verify(public_key: bytes, signature: bytes, message: bytes) -> bool | None:
    """``True``/``False`` for a real check; ``None`` when ``cryptography`` is absent."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        return None
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except InvalidSignature:
        return False
    return True


def _canonical(value: Any) -> bytes:
    """The gateway's canonical form: sorted keys, no whitespace, UTF-8, no NaN."""
    return json.dumps(
        value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _strict_json(raw: bytes, check: str, what: str) -> Any:
    def reject_constant(token: str) -> Any:
        raise ValueError(f"non-finite number {token}")

    def unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate key {key!r}")
            result[key] = value
        return result

    try:
        return json.loads(
            raw.decode("utf-8"), object_pairs_hook=unique_keys, parse_constant=reject_constant
        )
    except RecursionError as exc:
        raise _FailedCheckError(check, f"{what} nests too deeply to parse") from exc
    except (UnicodeDecodeError, ValueError) as exc:
        raise _FailedCheckError(check, f"{what} is not strict UTF-8 JSON: {exc}") from exc


def _dag_cbor_cid(sha256_digest: bytes) -> str:
    """CIDv1, dag-cbor codec (0x71), sha2-256 multihash, base32 lowercase."""
    cid = bytes([0x01, 0x71, 0x12, 0x20]) + sha256_digest
    return "b" + base64.b32encode(cid).decode("ascii").lower().rstrip("=")


@dataclass(frozen=True)
class _Member:
    size: int
    sha256: bytes
    content: bytes | None


def _read_member(handle: IO[bytes], name: str) -> _Member:
    keep = name in _KEPT_IN_MEMORY
    limit = MAX_IN_MEMORY_BYTES if keep else MAX_MEMBER_BYTES
    digest = hashlib.sha256()
    chunks: list[bytes] = []
    total = 0
    while chunk := handle.read(1 << 16):
        total += len(chunk)
        if total > limit:
            raise _FailedCheckError("archive", f"{name} decompresses past {limit} bytes")
        digest.update(chunk)
        if keep:
            chunks.append(chunk)
    return _Member(total, digest.digest(), b"".join(chunks) if keep else None)


def _open_source(source: bytes | str | os.PathLike[str]) -> IO[bytes]:
    if isinstance(source, bytes):
        if len(source) > MAX_ARCHIVE_BYTES:
            raise _FailedCheckError("archive", f"archive is larger than {MAX_ARCHIVE_BYTES} bytes")
        return io.BytesIO(source)
    try:
        size = os.stat(source).st_size
    except OSError as exc:
        raise BundleInputError(f"cannot read bundle: {exc}") from exc
    if size > MAX_ARCHIVE_BYTES:
        raise _FailedCheckError("archive", f"archive is larger than {MAX_ARCHIVE_BYTES} bytes")
    try:
        return open(source, "rb")
    except OSError as exc:
        raise BundleInputError(f"cannot read bundle: {exc}") from exc


def _read_archive(source: bytes | str | os.PathLike[str]) -> dict[str, _Member]:
    with _open_source(source) as stream:
        try:
            archive = zipfile.ZipFile(stream)
        except (zipfile.BadZipFile, OSError) as exc:
            raise _FailedCheckError("archive", f"not a readable ZIP archive: {exc}") from exc
        with archive:
            infos = archive.infolist()
            # Checked before anything iterates the names: a 64 MiB central
            # directory can list on the order of a million entries.
            if len(infos) > len(_ALLOWED_MEMBERS):
                raise _FailedCheckError(
                    "archive",
                    f"{len(infos)} members; the bundle format defines at most "
                    f"{len(_ALLOWED_MEMBERS)}",
                )
            names = Counter(info.filename for info in infos)
            unexpected = sorted(set(names) - _ALLOWED_MEMBERS)
            if unexpected:
                raise _FailedCheckError(
                    "archive",
                    "members the bundle format does not define: "
                    + ", ".join(_shown(name) for name in unexpected),
                )
            duplicates = sorted(name for name, count in names.items() if count > 1)
            if duplicates:
                raise _FailedCheckError(
                    "archive", "duplicate members: " + ", ".join(_shown(n) for n in duplicates)
                )
            members: dict[str, _Member] = {}
            for info in infos:
                if info.flag_bits & 0x1:
                    raise _FailedCheckError("archive", f"{_shown(info.filename)} is encrypted")
                if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                    raise _FailedCheckError(
                        "archive", f"{_shown(info.filename)} uses unsupported compression method"
                    )
                try:
                    with archive.open(info) as handle:
                        members[info.filename] = _read_member(handle, info.filename)
                except (zipfile.BadZipFile, OSError, EOFError) as exc:
                    raise _FailedCheckError(
                        "archive", f"{info.filename} is corrupt: {exc}"
                    ) from exc
            return members


def _require_mapping(value: Any, keys: frozenset[str], check: str, what: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise _FailedCheckError(check, f"{what} does not have the {BUNDLE_VERSION} field set")
    return value


def _require_int(value: Any, check: str, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise _FailedCheckError(check, f"{what} must be a non-negative integer")
    return int(value)


def _require_hex64(value: Any, check: str, what: str) -> str:
    if not isinstance(value, str) or _HEX64.fullmatch(value) is None:
        raise _FailedCheckError(check, f"{what} must be a lowercase SHA-256 hex digest")
    return value


def verify_bundle(
    source: bytes | str | os.PathLike[str],
    *,
    public_key: bytes | None = None,
    trusted_root: str | None = None,
) -> BundleReport:
    """Verify a forensic bundle offline. See the module docstring for scope.

    Args:
        source: The ZIP's bytes or a path to it.
        public_key: The operator's raw 32-byte Ed25519 public key, obtained out
            of band — never from the bundle. See :func:`load_ed25519_public_key`.
        trusted_root: A lowercase 64-hex MMR root the caller already trusts;
            compared with the manifest's terminal root.

    Raises:
        BundleInputError: the source cannot be read, or an argument is malformed.
    """
    if public_key is not None and len(public_key) != 32:
        raise BundleInputError("public_key must be 32 raw bytes")
    if trusted_root is not None and _HEX64.fullmatch(trusted_root) is None:
        raise BundleInputError("trusted_root must be a lowercase 64-hex SHA-256 digest")

    checks: list[Check] = []
    try:
        _verify_into(checks, source, public_key=public_key, trusted_root=trusted_root)
    except _FailedCheckError as reject:
        checks.append(reject.check)
    return BundleReport(tuple(checks))


def _verify_into(
    checks: list[Check],
    source: bytes | str | os.PathLike[str],
    *,
    public_key: bytes | None,
    trusted_root: str | None,
) -> None:
    members = _read_archive(source)
    missing = sorted((EVIDENCE_FILES | {MANIFEST}) - set(members))
    if missing:
        raise _FailedCheckError("archive", f"required members are missing: {', '.join(missing)}")
    checks.append(
        Check("archive", "pass", f"{len(members)} members, each one the bundle format defines")
    )

    # ── manifest.json ────────────────────────────────────────────────────────
    manifest_raw = members[MANIFEST].content
    assert manifest_raw is not None
    manifest_value = _strict_json(manifest_raw, "manifest", MANIFEST)
    manifest = _require_mapping(manifest_value, _MANIFEST_KEYS, "manifest", MANIFEST)
    if manifest["bundle_version"] != BUNDLE_VERSION:
        raise _FailedCheckError("manifest", f"bundle_version is not {BUNDLE_VERSION!r}")
    if _canonical(manifest) != manifest_raw:
        raise _FailedCheckError("manifest", "manifest.json is not in canonical form")
    payload = {key: value for key, value in manifest.items() if key != _SEAL_KEY}
    seal = _require_hex64(manifest[_SEAL_KEY], "manifest", _SEAL_KEY)
    if hashlib.sha256(_canonical(payload)).hexdigest() != seal:
        raise _FailedCheckError("manifest", "manifest_payload_sha256 does not match the manifest")
    node_signatures = manifest["signatures"]
    if not isinstance(node_signatures, list) or not node_signatures:
        raise _FailedCheckError("manifest", "signatures must be a non-empty list")
    state_ids: list[str] = []
    for entry in node_signatures:
        fields = _require_mapping(entry, _NODE_SIGNATURE_KEYS, "manifest", "a signatures entry")
        if not isinstance(fields["state_id"], str):
            raise _FailedCheckError("manifest", "signatures[].state_id must be a string")
        state_ids.append(fields["state_id"])
    if len(set(state_ids)) != len(state_ids):
        raise _FailedCheckError("manifest", "signatures lists a state_id more than once")
    if _require_int(manifest["node_count"], "manifest", "node_count") != len(state_ids):
        raise _FailedCheckError(
            "manifest", "node_count does not equal the number of signatures entries"
        )
    terminal_root = _require_hex64(manifest["terminal_mmr_root"], "manifest", "terminal_mmr_root")
    checks.append(Check("manifest", "pass", "canonical JSON; self-seal matches"))

    # ── evidence files ───────────────────────────────────────────────────────
    files = manifest["files"]
    if not isinstance(files, list):
        raise _FailedCheckError("file_digests", "files must be a list")
    listed: set[str] = set()
    for entry in files:
        fields = _require_mapping(entry, _FILE_ENTRY_KEYS, "file_digests", "a files entry")
        name = fields["name"]
        if name not in EVIDENCE_FILES or name in listed:
            raise _FailedCheckError(
                "file_digests", f"files lists {_shown(name)}, which is not allowed there"
            )
        listed.add(name)
        member = members[name]
        if _require_int(fields["size"], "file_digests", f"{name} size") != member.size:
            raise _FailedCheckError(
                "file_digests", f"{name} is {member.size} bytes; the manifest says {fields['size']}"
            )
        expected = _require_hex64(fields["sha256"], "file_digests", f"{name} sha256")
        if member.sha256.hex() != expected:
            raise _FailedCheckError("file_digests", f"{name} does not match its manifest SHA-256")
    if listed != EVIDENCE_FILES:
        raise _FailedCheckError(
            "file_digests",
            f"manifest does not list: {', '.join(sorted(EVIDENCE_FILES - listed))}",
        )
    checks.append(
        Check("file_digests", "pass", f"{len(listed)} evidence files match size and SHA-256")
    )

    cid = _dag_cbor_cid(members["ledger_slice.cbor"].sha256)
    if manifest["ledger_slice_cid"] != cid:
        raise _FailedCheckError(
            "ledger_slice_cid", "ledger_slice_cid does not match ledger_slice.cbor"
        )
    checks.append(Check("ledger_slice_cid", "pass", cid))

    # ── MMR inclusion proofs ─────────────────────────────────────────────────
    proof_raw = members["merkle_proof.json"].content
    assert proof_raw is not None
    proof_set = _require_mapping(
        _strict_json(proof_raw, "mmr_proofs", "merkle_proof.json"),
        frozenset({"proofs", "version"}),
        "mmr_proofs",
        "merkle_proof.json",
    )
    if proof_set["version"] != PROOF_SET_VERSION or not isinstance(proof_set["proofs"], list):
        raise _FailedCheckError("mmr_proofs", f"merkle_proof.json is not {PROOF_SET_VERSION!r}")
    if _canonical(proof_set) != proof_raw:
        raise _FailedCheckError("mmr_proofs", "merkle_proof.json is not in canonical form")
    known = set(state_ids)
    roots: dict[str, str] = {}
    for entry in proof_set["proofs"]:
        fields = _require_mapping(entry, _PROOF_ENTRY_KEYS, "mmr_proofs", "a proofs entry")
        state_id = fields["state_id"]
        if not isinstance(state_id, str) or state_id not in known or state_id in roots:
            raise _FailedCheckError(
                "mmr_proofs", f"proof for {_shown(state_id)} names no node, or repeats one"
            )
        label = _shown(state_id)
        leaf_hash = _require_hex64(fields["leaf_hash"], "mmr_proofs", f"{label} leaf_hash")
        root = _require_hex64(fields["root"], "mmr_proofs", f"{label} root")
        if not isinstance(fields["proof"], dict):
            raise _FailedCheckError("mmr_proofs", f"{label} proof must be an object")
        try:
            proof = InclusionProof.from_mapping(fields["proof"])
        except AegisProofError as exc:
            raise _FailedCheckError("mmr_proofs", f"{label}: {exc}") from exc
        if (proof.leaf_index, proof.leaf_count) != (
            _require_int(fields["leaf_index"], "mmr_proofs", f"{label} leaf_index"),
            _require_int(fields["leaf_count"], "mmr_proofs", f"{label} leaf_count"),
        ):
            raise _FailedCheckError("mmr_proofs", f"{label}: entry and proof disagree on position")
        if not verify_inclusion_hash(leaf_hash, proof, root):
            raise _FailedCheckError("mmr_proofs", f"{label}: inclusion proof does not verify")
        roots[state_id] = root
    last = state_ids[-1]
    if last in roots and roots[last] != terminal_root:
        raise _FailedCheckError(
            "mmr_proofs", "the last node's root is not the manifest's terminal root"
        )
    if roots:
        checks.append(
            Check(
                "mmr_proofs",
                "pass",
                f"{len(roots)} of {len(state_ids)} nodes carry an inclusion proof; "
                "each verifies against the root recorded with it",
            )
        )
    else:
        checks.append(Check("mmr_proofs", "skip", "the bundle carries no inclusion proofs"))

    if trusted_root is None:
        checks.append(
            Check(
                "trusted_root",
                "skip",
                "terminal root not compared with an independently trusted checkpoint",
            )
        )
    elif trusted_root != terminal_root:
        raise _FailedCheckError(
            "trusted_root", "terminal_mmr_root is not the trusted root supplied"
        )
    else:
        checks.append(Check("trusted_root", "pass", "terminal_mmr_root equals the trusted root"))

    # ── manifest signature ───────────────────────────────────────────────────
    signature = members[MANIFEST_SIGNATURE].content if MANIFEST_SIGNATURE in members else None
    if signature is None:
        if public_key is not None:
            # A key says the caller expects a signed bundle. Accepting an
            # unsigned one would let whoever stripped the signature choose
            # the outcome.
            raise _FailedCheckError(
                "manifest_signature",
                "a public key was supplied but the bundle carries no manifest.json.sig",
            )
        checks.append(
            Check(
                "manifest_signature",
                "skip",
                "the bundle is unsigned; manifest signing is opt-in on the gateway",
            )
        )
    elif public_key is None:
        checks.append(
            Check(
                "manifest_signature",
                "skip",
                "the bundle is signed, but no out-of-band public key was supplied",
            )
        )
    elif len(signature) != 64:
        raise _FailedCheckError(
            "manifest_signature", "manifest.json.sig is not a 64-byte Ed25519 signature"
        )
    else:
        outcome = _ed25519_verify(public_key, signature, manifest_raw)
        if outcome is None:
            checks.append(
                Check(
                    "manifest_signature",
                    "skip",
                    "signature NOT checked: the 'cryptography' package is not installed "
                    "(pip install 'aegis-latent-sdk[verify]')",
                )
            )
        elif not outcome:
            raise _FailedCheckError(
                "manifest_signature",
                "manifest.json signature does not verify (tampered or wrong key)",
            )
        else:
            checks.append(
                Check("manifest_signature", "pass", "Ed25519 over the exact manifest.json bytes")
            )

    distinct = sorted(
        {str(entry["scheme"]) for entry in node_signatures if isinstance(entry, dict)}
    )
    schemes = [_shown(scheme, 40) for scheme in distinct[:5]] + (
        [f"+{len(distinct) - 5} more"] if len(distinct) > 5 else []
    )
    checks.append(
        Check(
            "node_signatures",
            "skip",
            f"{len(state_ids)} per-node signatures ({', '.join(schemes)}) are not checked by "
            "this tool",
        )
    )

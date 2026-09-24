"""
aegis.core.crypto_audit — Cryptographic audit ledger with a Merkle-linked evidence chain.

Architecture:
  - CryptographicAuditLedger: append-only Merkle chain backed by WAL.
  - AuditNode: immutable record with forensic fields, HMAC/PQC signature,
    and a computed node_hash linking the chain.
  - Signing: HMAC-SHA256 when signing_key is provided; no legal conclusion is implied.
    PQC-ML-DSA via aegis_rust extension when available.
  - WAL: line-delimited JSON. A commit does not return until its record is
    fsynced, but the fsync is coalesced across concurrent commits by
    ``aegis.core.group_commit`` — durability per record, one device round trip
    per batch.
  - Memory: collections.deque(maxlen=N) — O(1) eviction, no pop(0) overhead.

FIX-CAL-01: WAL file handle lifecycle.

  Original behaviour: _wal_handle was only opened in __enter__ (context-manager
  path).  In app.py the ledger is used directly (not as a context manager), so
  _wal_handle was always None.  _persist_node's else-branch then opened a new
  file handle on every single commit_state call:

      open(path, "a") → write → flush → fsync → close   # per request

  Under load this incurs:
    - One open() + close() syscall pair per LLM request.
    - On ext4 with data=ordered: extra journal transactions per commit.
    - No handle reuse, defeating the amortisation that a persistent handle
      provides.

  Fix: _open_wal() is called at the end of __init__ after WAL reconstruction.
  The handle stays open for the lifetime of the ledger.  __enter__ now re-uses
  the already-open handle (noop if already open).  __exit__ / close() are
  unchanged.  _persist_node's else-branch is retained as a safety fallback for
  callers who instantiate and immediately destroy the ledger without calling
  close() (e.g. tests using ledger in a with-block where __init__ races with
  __enter__).
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import math
import os
import stat
import sys
import time
import uuid

try:  # POSIX advisory locking. Absent on Windows; see _lock_wal_fd.
    import fcntl
except ImportError:  # pragma: no cover - platform dependent
    fcntl = None  # type: ignore[assignment]
try:  # Windows byte-range locking. Absent on POSIX; see _lock_wal_fd.
    import msvcrt as _msvcrt_module
except ImportError:  # pragma: no cover - platform dependent
    _msvcrt_module = None  # type: ignore[assignment]
from collections import deque
from collections.abc import Callable
from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path
from threading import Lock
from typing import Any, Final, Literal, TextIO

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from aegis.core.crypto_shredder import (
    SHRED_SCHEME_UNSEALED,
    SHRED_SCHEME_V1,
    CryptoShredder,
    SealedPayload,
)
from aegis.core.forensic import (
    WAF_VERDICT_UNRECORDED,
    build_merkle_leaf,
    build_stream_merkle_leaf,
    sha256_hex,
    validate_waf_verdict,
)
from aegis.core.forensic_bundle import canonical_jcs_bytes
from aegis.core.group_commit import (
    DEFAULT_LINGER_SECONDS,
    DEFAULT_MAX_BATCH,
    CoalescedCommitEngine,
    GroupCommitStats,
    WalDurabilityError,
)
from aegis.core.hsm import HSMSigningBackend, HSMUnavailableError
from aegis.core.mmr import (
    HASH_SCHEME_V1,
    HASH_SCHEME_V2,
    MMR_PROOF_VERSION_V1,
    MMR_PROOF_VERSION_V2,
    MerkleMountainRange,
    MMRInclusionProofV1,
    MMRPeak,
)
from aegis.core.pqc_signer import PQCSigner, PQCUnavailableError
from aegis.core.pqc_signer import backend_available as pqc_backend_available

#: Sentinel for "decide the scheme from the chain": a new chain starts on
#: :data:`MMR_NEW_CHAIN_DEFAULT_SCHEME`, an existing one reopens under whatever
#: its WAL recorded. This is the default because the alternative defaults are
#: both wrong. Defaulting to v1 leaves every new chain on the construction that
#: admits leaf/interior type confusion; defaulting to v2 outright would refuse
#: to open every chain already in the field, turning an upgrade into an outage.
MMR_SCHEME_AUTO: str = "auto"

#: The construction a chain created today is built on.
MMR_NEW_CHAIN_DEFAULT_SCHEME: str = HASH_SCHEME_V2

#: Which proof version each hash scheme stamps on the proofs it issues. Used to
#: recognise, on reopening a WAL, that the chain on disk was written under a
#: different construction from the one this ledger is configured for.
_SCHEME_PROOF_VERSIONS: dict[str, str] = {
    HASH_SCHEME_V1: MMR_PROOF_VERSION_V1,
    HASH_SCHEME_V2: MMR_PROOF_VERSION_V2,
}

#: The same mapping read the other way, for adopting a chain's own scheme.
_PROOF_VERSION_SCHEMES: dict[str, str] = {
    version: scheme for scheme, version in _SCHEME_PROOF_VERSIONS.items()
}

logger = logging.getLogger(__name__)

# The Windows locking primitive, or None where the platform has none. Bound
# here rather than at the import so the annotation can be ``Any``: typeshed
# guards the whole ``msvcrt`` module behind ``sys.platform == "win32"``, so on
# any other checker platform its members resolve to nothing. One untyped
# binding is honest about that, where a per-attribute ignore would only hide
# it — and it admits the stand-in the tests install in this name's place.
msvcrt: Any = _msvcrt_module

MAX_PAYLOAD_BYTES: int = 1_048_576  # 1 MiB hard cap
# Reserved for a stream-terminal node replayed from the durable outbox (REG-D32);
# only commit_forensic_summary's digest form may carry it.
RECOVERED_TERMINAL_MEANING = "stream-terminal-evidence-recovered"

# Schema version of the ``<wal>.mmr.state`` peak-set checkpoint. Bump only for
# an incompatible field change: an unrecognised version is ignored and the WAL
# is replayed, so a bump degrades performance rather than correctness.
_MMR_STATE_VERSION: int = 1
_DEFAULT_MAX_FORENSIC_BYTES: int = 65_536


def _resolve_commit_batch_max_size(explicit: int | None) -> int:
    """Queue depth at which the group-commit syncer stops waiting for company.

    An explicit argument wins; otherwise ``AEGIS_COMMIT_BATCH_MAX_SIZE``, then
    the module default. An unparseable or out-of-range environment value falls
    back to the default rather than raising: a malformed tuning knob must not
    stop the ledger from opening, because refusing to record evidence is a worse
    outcome than recording it with default batching.
    """
    if explicit is not None:
        return explicit
    raw = os.environ.get("AEGIS_COMMIT_BATCH_MAX_SIZE", "")
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_MAX_BATCH
    return value if value >= 1 else DEFAULT_MAX_BATCH


def _resolve_commit_batch_linger(explicit_ms: float | None) -> float:
    """Longest the syncer may wait for company, in seconds.

    Configured in milliseconds (``AEGIS_COMMIT_BATCH_TIMEOUT_MS``) because that
    is the scale an operator thinks in; stored in seconds because that is what
    ``threading.Condition.wait`` takes. Same fallback rule as above.
    """
    if explicit_ms is not None:
        return max(0.0, explicit_ms) / 1000.0
    raw = os.environ.get("AEGIS_COMMIT_BATCH_TIMEOUT_MS", "")
    try:
        value = float(raw)
    except ValueError:
        return DEFAULT_LINGER_SECONDS
    return max(0.0, value) / 1000.0 if value >= 0.0 else DEFAULT_LINGER_SECONDS


class WalWriterConflictError(RuntimeError):
    """Another process already holds the append lock for this WAL path.

    Two processes appending to one WAL path produce divergent ``prev_hash``
    relationships that the loader cannot represent as a single verified chain.
    The topology is documented as unsupported; this exception makes it
    enforced rather than merely documented, so the fork cannot occur silently.
    """


# Platform selector for the WAL lock, kept as a module constant so the branch
# not taken by the running interpreter is still reachable under test.
_WINDOWS: bool = os.name == "nt"

# Byte offset of the Windows lock region.
#
# ``msvcrt.locking`` maps to ``LockFile``, which is *mandatory*: a locked range
# is denied to every other handle, readers included. POSIX ``flock`` is
# advisory and denies nothing. That difference matters here because the WAL is
# read while a writer holds it — ``_load_from_wal`` replays the whole file in
# ``__init__`` before ``_open_wal`` ever asks for the lock, and the verifier
# reads segments out of band. A lock placed over live bytes would therefore
# turn "another process holds this path" into "this WAL cannot be read", on
# Windows only, and the second writer would fail with a corruption error rather
# than WalWriterConflictError.
#
# The region is placed past any WAL that can exist, where it holds no record
# and acts purely as a mutex. Locking beyond end-of-file is well defined on
# Windows and does not extend the file: only a write does that, and nothing
# ever seeks here to write.
#
# 1 TiB is chosen to sit inside the maximum file size of every filesystem the
# gateway is deployed on (NTFS 256 TiB, ext4 16 TiB, APFS and XFS far above
# that) while remaining orders of magnitude beyond a rotating WAL. The offset
# cannot simply be made enormous: a seek past the filesystem maximum fails with
# EINVAL, and a first writer must never be refused because the sentinel could
# not be positioned. ``_SentinelUnavailableError`` keeps those two outcomes apart.
_WINDOWS_LOCK_OFFSET: int = 1 << 40


class _SentinelUnavailableError(RuntimeError):
    """The lock sentinel could not be positioned on this filesystem.

    Distinct from a lock conflict: it means the guard could not be applied at
    all, not that another writer holds the path.
    """


def _windows_lock_region(fd: int, mode: int) -> None:
    """Apply ``mode`` to the one-byte sentinel region of ``fd``.

    ``msvcrt.locking`` acts at the descriptor's current offset, so the offset
    is moved to the sentinel and restored afterwards. Restoring matters even
    though the WAL is opened ``O_APPEND`` — appends ignore the offset, but
    leaving it past end-of-file would surprise anything that later reads it.

    Raises ``_SentinelUnavailableError`` if the sentinel cannot be reached, and
    ``OSError`` only from the lock call itself, so the caller can tell a
    conflict from a filesystem that cannot address the offset.
    """
    assert msvcrt is not None  # guarded by the caller
    try:
        saved = os.lseek(fd, 0, os.SEEK_CUR)
        os.lseek(fd, _WINDOWS_LOCK_OFFSET, os.SEEK_SET)
    except OSError as exc:
        raise _SentinelUnavailableError(str(exc)) from exc
    try:
        msvcrt.locking(fd, mode, 1)
    finally:
        os.lseek(fd, saved, os.SEEK_SET)


def _lock_wal_fd(fd: int, path: str) -> None:
    """Take an exclusive, non-blocking lock on an open WAL fd.

    POSIX uses ``fcntl.flock``; Windows uses ``msvcrt.locking`` over the
    sentinel region described above. Both are exclusive and both fail
    immediately rather than waiting, so a losing writer is refused instead of
    blocking the process that started it.

    The lock is released automatically when the descriptor is closed or the
    process exits, so a restart re-acquires it without operator action.

    On a platform offering neither primitive the guard cannot be enforced
    in-process and single-writer discipline remains an operator
    responsibility; that case is logged at warning level rather than failing
    open silently.
    """
    if _WINDOWS:
        if msvcrt is None:  # pragma: no cover - platform dependent
            _warn_unlocked(path)
            return
        try:
            _windows_lock_region(fd, msvcrt.LK_NBLCK)
        except _SentinelUnavailableError as exc:
            # The guard could not be applied. Refusing here would reject the
            # first writer as though it were the second.
            _warn_unlocked(path, detail=str(exc))
            return
        except OSError as exc:
            raise WalWriterConflictError(
                f"WAL path is already locked by another writer: {path}. "
                "Exactly one process may append to a WAL path; concurrent "
                "writers fork the evidence chain."
            ) from exc
        return
    if fcntl is None:  # pragma: no cover - platform dependent
        _warn_unlocked(path)
        return
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        raise WalWriterConflictError(
            f"WAL path is already locked by another writer: {path}. "
            "Exactly one process may append to a WAL path; concurrent writers "
            "fork the evidence chain."
        ) from exc


def _unlock_wal_fd(fd: int) -> None:
    """Release the WAL lock held on ``fd``, best effort.

    Closing the descriptor releases the lock on both platforms, so this is not
    what prevents a stuck lock. It makes the release explicit at rotation,
    where the process keeps running and immediately reopens the same path, and
    it keeps Windows from holding a mandatory region a moment longer than the
    writer that owns it. A failure here must never mask the caller's own error
    path, so every failure is swallowed.
    """
    try:
        if _WINDOWS:
            if msvcrt is None:  # pragma: no cover - platform dependent
                return
            _windows_lock_region(fd, msvcrt.LK_UNLCK)
            return
        if fcntl is None:  # pragma: no cover - platform dependent
            return
        fcntl.flock(fd, fcntl.LOCK_UN)
    except (OSError, ValueError, _SentinelUnavailableError):
        # Swallowed deliberately: callers are close() and rotation, where a
        # failure to release must not mask the caller's own error path. Closing
        # the descriptor releases the lock on both platforms regardless, so
        # nothing is leaked by giving up here.
        pass


def _warn_unlocked(path: str, detail: str = "") -> None:
    """Record that no lock primitive could be applied to ``path``."""
    logger.warning(
        "WAL locking is unavailable on %s%s; single-writer discipline for %s "
        "is operator-enforced, not process-enforced.",
        sys.platform,
        f" ({detail})" if detail else "",
        path,
    )


# ── Rust / PQC detection ──────────────────────────────────────────────────────
try:
    import aegis_rust  # type: ignore[import]

    RUST_AVAILABLE: bool = True
except ImportError:
    RUST_AVAILABLE = False
    logger.debug("aegis_rust extension not available; using HMAC-SHA256 signing")


# ── AuditNode ─────────────────────────────────────────────────────────────────


class SignatureAssurance(StrEnum):
    """How strongly a signed node's signature can be trusted, weakest first.

    Ranked to match ``CryptographicAuditLedger._sign``'s own tier priority
    (HSM > persistent PQC identity > HMAC > ephemeral Ed25519), so the
    ordering here is read off the signer's own tier selection rather than
    invented separately from it.

    UNSIGNED
        No recognised scheme. Unreachable via ``_sign`` — every commit path
        either signs under a known tier or raises before a node exists — so
        this is a defensive floor for corrupt or newer-than-this-build WAL
        data, not a state a live commit can produce.
    COMPROMISED_EPHEMERAL
        ``ed25519-fallback``: a fresh keypair minted per node and never
        persisted. Verifiable within the process that signed it, not across
        a restart, and not attributable to any held identity.
    SYMMETRIC_AUTHENTICATED
        ``hmac-sha256``: verifiable by anyone holding the shared signing
        key. Requires that key to stay in process memory.
    ASYMMETRIC_SOFTWARE
        ``pqc-ml-dsa``: a persistent post-quantum identity, verifiable
        against a published public key, but the private key lives in
        process memory rather than a hardware boundary.
    ASYMMETRIC_HARDWARE_ATTESTED
        ``pkcs11-rsa-pss-sha256`` / ``pkcs11-ecdsa-sha256``: signed by an
        HSM-resident key that never leaves the token boundary.
    """

    UNSIGNED = "UNSIGNED"
    COMPROMISED_EPHEMERAL = "COMPROMISED_EPHEMERAL"
    SYMMETRIC_AUTHENTICATED = "SYMMETRIC_AUTHENTICATED"
    ASYMMETRIC_SOFTWARE = "ASYMMETRIC_SOFTWARE"
    ASYMMETRIC_HARDWARE_ATTESTED = "ASYMMETRIC_HARDWARE_ATTESTED"


#: Rank for min()-style comparison. Higher is stronger.
_ASSURANCE_RANK: Final[dict[SignatureAssurance, int]] = {
    SignatureAssurance.UNSIGNED: 0,
    SignatureAssurance.COMPROMISED_EPHEMERAL: 1,
    SignatureAssurance.SYMMETRIC_AUTHENTICATED: 2,
    SignatureAssurance.ASYMMETRIC_SOFTWARE: 3,
    SignatureAssurance.ASYMMETRIC_HARDWARE_ATTESTED: 4,
}

#: Maps each ``AuditNode.signature_scheme`` value this codebase actually
#: produces (see ``CryptographicAuditLedger._sign`` and
#: ``HSMSigningBackend.sign``) to the tier that produced it.
_SCHEME_ASSURANCE: Final[dict[str, SignatureAssurance]] = {
    "ed25519-fallback": SignatureAssurance.COMPROMISED_EPHEMERAL,
    "hmac-sha256": SignatureAssurance.SYMMETRIC_AUTHENTICATED,
    "pqc-ml-dsa": SignatureAssurance.ASYMMETRIC_SOFTWARE,
    "pkcs11-rsa-pss-sha256": SignatureAssurance.ASYMMETRIC_HARDWARE_ATTESTED,
    "pkcs11-ecdsa-sha256": SignatureAssurance.ASYMMETRIC_HARDWARE_ATTESTED,
}


def node_signature_assurance(node: AuditNode) -> SignatureAssurance:
    """The assurance tier ``node`` was actually signed under.

    Reads ``node.signature_scheme`` — recorded at commit time by whichever
    tier ``_sign`` used for that node — rather than the ledger's current
    configuration. A node keeps the assurance it was actually signed with
    even after the ledger is reconfigured with a stronger signer, which is
    the property CLM-defect-P3-1 was filed against: the old
    ``legal_admissibility`` read current config instead of chain history,
    so a chain written entirely under ``ed25519-fallback`` (no key
    configured yet) silently became "High" the moment an operator added a
    signing key and restarted — the fallback-signed history never
    re-examined. An unrecognised scheme maps to ``UNSIGNED`` rather than
    raising, so a reader auditing unfamiliar WAL data gets the floor
    assurance instead of a crash.

    The label is only trusted when the recorded material is *consistent*
    with it: a node whose ``signature`` / ``public_key`` cannot belong to
    the declared scheme (see :func:`scheme_material_inconsistency`) reports
    ``UNSIGNED`` regardless of the label. Rewriting the label to a stronger
    tier — the v5.0.1-prep audit's P1 (``REG-D06``) — therefore cannot buy
    that tier here.
    """

    if scheme_material_inconsistency(node) is not None:
        return SignatureAssurance.UNSIGNED
    return _SCHEME_ASSURANCE.get(node.signature_scheme, SignatureAssurance.UNSIGNED)


def validate_signature_scheme(scheme: str) -> str:
    """Return ``scheme`` if it is one this codebase writes, else raise.

    The scheme travels inside the signed payload (AUD-27), so it is held to the
    same standard as the other bound fields: a closed vocabulary with no
    delimiter in it. ``_SCHEME_MATERIAL`` is that vocabulary — it is already the
    set :func:`scheme_material_inconsistency` enforces on the reading side, so a
    label that can be *written* here is exactly a label that can be *checked*
    there, and no other.

    Raises
    ------
    ValueError
        For any label outside the vocabulary, including an empty one. Callers
        that legitimately have no label (the pre-binding payload builder) simply
        omit the argument.
    """
    if scheme not in _SCHEME_MATERIAL:
        raise ValueError(
            f"signature scheme {scheme!r} is not one this codebase writes "
            f"({sorted(_SCHEME_MATERIAL)}); it cannot be bound into a signed payload"
        )
    return scheme


def _is_hex_token(value: str) -> bool:
    """True for a non-empty, even-length hexadecimal token."""

    return (
        bool(value)
        and len(value) % 2 == 0
        and all(character in "0123456789abcdefABCDEF" for character in value)
    )


#: Static material invariants per scheme: ``(signature hex length, public-key
#: hex length)``, where ``0`` means "must be absent" and ``None`` means "must
#: be present; length is pinned by the implementation, not by this table".
#: Only the invariants this codebase can assert without its verifiers are
#: pinned exactly (HMAC-SHA256 = 32-byte tag, Ed25519 = 64-byte signature /
#: 32-byte key); the HSM and ML-DSA tiers are shape-checked for presence —
#: the real HSM backend raises ``HSMUnavailableError`` when the token
#: cannot export the public key, so a public key is always present for
#: ``pkcs11-*`` (``aegis/core/hsm.py``).
_SCHEME_MATERIAL: Final[dict[str, tuple[int | None, int | None]]] = {
    "hmac-sha256": (64, 0),
    "ed25519-fallback": (128, 64),
    "pqc-ml-dsa": (None, None),
    "pkcs11-rsa-pss-sha256": (None, None),
    "pkcs11-ecdsa-sha256": (None, None),
}


def scheme_material_inconsistency(node: AuditNode) -> str | None:
    """Reason the recorded material cannot belong to the declared scheme.

    Shape-only, deterministic, and cheap: no key material is read and no
    signature is computed. Returns ``None`` when the material satisfies the
    scheme's invariants, otherwise a human-readable reason. This is the
    allowlist half of the ``REG-D06`` fix — a declared scheme outside
    :data:`_SCHEME_MATERIAL` is itself an inconsistency, so an unknown label
    fails closed instead of falling through to ``unverified``.
    """

    invariant = _SCHEME_MATERIAL.get(node.signature_scheme)
    if invariant is None:
        return f"unrecognised signature scheme {node.signature_scheme!r}"
    expected_signature, expected_public_key = invariant
    signature = node.signature or ""
    public_key = node.public_key or ""
    if not _is_hex_token(signature):
        return "signature is not a non-empty even-length hex token"
    if public_key and not _is_hex_token(public_key):
        return "public key is not an even-length hex token"
    if expected_signature is not None and len(signature) != expected_signature:
        return (
            f"signature length {len(signature)} does not match scheme "
            f"{node.signature_scheme!r} ({expected_signature})"
        )
    if expected_public_key == 0:
        if public_key:
            return f"scheme {node.signature_scheme!r} does not carry a public key"
    elif expected_public_key is None:
        if not public_key:
            return f"scheme {node.signature_scheme!r} requires a public key"
    elif len(public_key) != expected_public_key:
        return (
            f"public key length {len(public_key)} does not match scheme "
            f"{node.signature_scheme!r} ({expected_public_key})"
        )
    return None


def chain_signature_assurance(nodes: list[AuditNode]) -> SignatureAssurance | None:
    """Weakest-link assurance over ``nodes``, or ``None`` if ``nodes`` is empty.

    Shared by :attr:`CryptographicAuditLedger.signature_assurance` and
    ``aegis.core.iso27037_evidence.build_evidence_package``, which both need
    the same chain-history reduction but take their own chain snapshot under
    the ledger's lock (this function does not lock).
    """

    if not nodes:
        return None
    return min(
        (node_signature_assurance(node) for node in nodes),
        key=lambda tier: _ASSURANCE_RANK[tier],
    )


@dataclass
class AuditNode:
    """Immutable forensic record committed to the Merkle chain.

    Invariants:
    - ``node_hash`` is deterministic: same fields → same hash.
    - ``prev_hash`` links this node to its predecessor (genesis: 64 zeros).
    - ``signature`` covers ``merkle_root`` with the configured signing scheme.
    - ``payload_hash`` is a property alias for ``request_hash`` (backward compat
      with audit_api endpoints that expose it as ``payload_hash``).
    """

    state_id: str
    timestamp: float
    entropy: float
    tenant_id: str
    sampling_params: dict[str, Any]
    prev_hash: str
    merkle_root: str
    signature: str  # hex-encoded
    # One of the keys in _SCHEME_ASSURANCE: "hmac-sha256" | "pqc-ml-dsa" |
    # "ed25519-fallback" | "pkcs11-rsa-pss-sha256" | "pkcs11-ecdsa-sha256".
    signature_scheme: str
    public_key: str  # hex-encoded; empty string when HMAC scheme
    request_hash: str  # sha256(request_bytes)
    response_hash: str  # sha256(response_bytes) or ""
    model: str
    endpoint: str
    token_trail_count: int
    is_fallback: bool = False
    phi_scrubbed: bool = False
    scrub_method: str = ""
    # 21 CFR Part 11 §11.50 electronic signature annotation fields
    signer_name: str = ""
    signature_meaning: str = ""
    # EU Annex 11 §4.8 migration traceability
    audit_trail_version: str = "1"
    # Admission outcome. "committed" for a node recording an interaction that
    # reached the model; "rejected" for one recording a request the gateway
    # refused before admission (see ``commit_rejection``). Deliberately NOT a
    # ``node_hash`` input: every node written before this field existed hashes
    # identically with and without it, so existing chains stay verifiable and
    # already-issued MMR proofs keep validating.
    status: str = "committed"
    # Portable MMR inclusion snapshot. Empty on legacy WAL records.
    mmr_leaf_hash: str = ""
    mmr_leaf_index: int = -1
    mmr_leaf_count: int = 0
    mmr_proof: dict[str, Any] | None = None
    # Cryptographic-erasure envelope. Empty unless the ledger was configured
    # with ``enable_cryptographic_shredding``. When present, ``mmr_leaf_hash``
    # is the commitment SHA-256(0x00 || nonce || ciphertext) rather than a
    # digest of the leaf bytes, and the leaf's content is recoverable only by a
    # holder of the subject's key. Like ``status``, these are deliberately NOT
    # ``node_hash`` inputs: the hash covers a fixed field list, so every node
    # written before they existed hashes identically and already-issued proofs
    # keep validating.
    sealed_subject_id: str = ""
    sealed_nonce: str = ""  # hex-encoded 96-bit GCM nonce
    sealed_ciphertext: str = ""  # hex-encoded AES-256-GCM ciphertext
    # Which construction produced this record's commitment. Empty means the
    # record was not sealed, so ``mmr_leaf_hash`` is a digest of the leaf bytes.
    #
    # The presence of ``sealed_ciphertext`` above already tells a reader *that*
    # a record is sealed; this says *how*. That is the gap it closes, and it is
    # a forward-compatibility one rather than a present ambiguity: a verifier
    # recomputing `SHA-256(0x00 || nonce || ciphertext)` against a record sealed
    # under some later construction would see a mismatch it could not attribute,
    # indistinguishable from tampering. The MMR carries `hash_scheme` for
    # exactly this reason (`aegis/core/mmr.py`); the envelope had no equivalent.
    #
    # Unbound, like the rest of this group and like ``status``. That is coherent
    # rather than convenient: ``mmr_leaf_hash`` is itself not a ``node_hash``
    # input, so binding the label while leaving the thing it labels unbound
    # would buy nothing. The MMR snapshot's authority is the accumulator root,
    # not the node signature.
    shredding_version: str = ""
    # The WAF outcome recorded at admission, from the closed vocabulary in
    # `aegis.core.forensic`. Empty on every node written before the field
    # existed, which is "not recorded" and not a third outcome.
    #
    # Deliberately NOT a ``node_hash`` input, for the same reason as the fields
    # above: that hash covers a fixed list, so leaving it alone is what lets
    # every pre-existing node hash identically and keeps issued proofs valid.
    # Two other structures do bind it, which is what makes it evidence rather
    # than annotation — the node signature (`_build_signed_payload`) and the MMR
    # leaf (`build_merkle_leaf`). The leaf is the one a zero-knowledge inclusion
    # proof can speak about, because the tree commits to those bytes.
    waf_verdict: str = ""

    def __post_init__(self) -> None:
        self.__creation_hash__: str = self.node_hash

    # ── computed fields ──
    @property
    def payload_hash(self) -> str:
        """Alias for audit_api backward compatibility."""
        return self.request_hash

    @property
    def node_hash(self) -> str:
        """SHA-256 over canonical chain fields — deterministic, tamper-evident.

        ``prev_hash`` is the FIRST field so that ``node_hash`` is a true
        chain accumulator: each node's hash commits to its predecessor's hash.
        Editing ``prev_hash`` in storage therefore changes ``node_hash``, which
        breaks the ``node[i].prev_hash == node[i-1].node_hash`` linkage checked
        in ``verify_integrity`` — closing the node-reordering gap that existed
        when ``prev_hash`` was excluded from the hashed material.
        """
        content = "|".join(
            [
                self.prev_hash,
                self.state_id,
                f"{self.timestamp:.9f}",
                str(self.entropy),
                self.tenant_id,
                self.merkle_root,
                self.signature,
                self.request_hash,
                self.response_hash,
            ]
        )
        return hashlib.sha256(content.encode()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dict (excludes computed properties)."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditNode:
        """Reconstruct from a WAL record; fills in defaults for forward-compat."""
        defaults: dict[str, Any] = {
            "signature_scheme": "hmac-sha256",
            "public_key": "",
            "request_hash": data.get("payload", ""),  # old WAL field
            "response_hash": "",
            "model": "unknown",
            "endpoint": "unknown",
            "token_trail_count": 0,  # nosec B105 - a counter field named token_trail_count, not a credential
            "is_fallback": False,
            "phi_scrubbed": False,
            "scrub_method": "",
            "signer_name": "",
            "signature_meaning": "",
            "audit_trail_version": "1",
            "status": "committed",
            "mmr_leaf_hash": "",
            "mmr_leaf_index": -1,
            "mmr_leaf_count": 0,
            "mmr_proof": None,
            "sealed_subject_id": "",
            "sealed_nonce": "",
            "sealed_ciphertext": "",
            # A flat "" default would be wrong for a node written by the
            # shredder *before* this field existed: it has a real
            # ``sealed_ciphertext`` and no ``shredding_version`` key, and a flat
            # default would report it as unsealed — misrepresenting a genuinely
            # sealed record as one whose ``mmr_leaf_hash`` is a plain leaf
            # digest. SHRED_SCHEME_V1 is the only construction that has ever
            # produced ciphertext in this codebase, so a non-empty
            # ``sealed_ciphertext`` with no version key can only mean that one.
            "shredding_version": (SHRED_SCHEME_V1 if data.get("sealed_ciphertext") else ""),
            "waf_verdict": "",
        }
        # Remove legacy field if present
        data.pop("payload", None)
        merged = {**defaults, **data}
        # Keep only known fields to avoid TypeError on unexpected keys
        known = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in merged.items() if k in known}
        return cls(**filtered)


# ── Signing helpers ───────────────────────────────────────────────────────────


NODE_STATUS_COMMITTED = "committed"
NODE_STATUS_REJECTED = "rejected"
_NODE_STATUSES = frozenset({NODE_STATUS_COMMITTED, NODE_STATUS_REJECTED})


def validate_node_status(status: str) -> str:
    """Return *status* if it is a member of the closed vocabulary, else raise.

    Mirrors :func:`aegis.core.forensic.validate_waf_verdict`. The vocabulary is
    closed and delimiter-free so no status value can smuggle a ``|`` into the
    signed material. A status outside it is a verification failure rather than a
    silent omission: :meth:`CryptographicAuditLedger.signature_status` maps the
    ``ValueError`` to ``invalid``.
    """
    if not isinstance(status, str) or status not in _NODE_STATUSES:
        raise ValueError(f"status must be one of {sorted(_NODE_STATUSES)!r}, got {status!r}")
    return status


def _require_finite_json(value: Any, *, field: str) -> None:
    """Reject anything the durable WAL cannot represent as RFC 8259 JSON.

    ``sampling_params`` and the merged ``usage`` reach :meth:`_persist_node`,
    which serialises the node into the WAL — the replay authority. CPython's
    ``json.dumps`` emits the ECMA-262 extensions ``NaN`` / ``Infinity`` for
    non-finite floats, and ``json.loads`` accepts them on the way in, so a client
    (or a library caller) could place bytes in the ledger that no strict JSON
    reader can parse: serde_json, Go's encoding/json and ``JSON.parse`` all
    reject the line, while Python's lenient replay keeps reporting a healthy
    chain. That is a silent cross-language verification failure, so the value is
    refused at ingest instead — before the lock, like the other caller errors in
    :meth:`commit_forensic`, so nothing is latched and no rollback is needed.

    Walks dict/list/tuple so a non-finite float nested inside metadata is caught
    too, and rejects values ``json.dumps`` cannot serialise at all (bytes,
    ``datetime``, ``Decimal``) so a caller finds out at the call, not while the
    ledger lock is held mid-commit.
    """
    if isinstance(value, bool) or value is None or isinstance(value, (int, str)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(
                f"{field} contains a non-finite float ({value!r}); the WAL must stay "
                "valid RFC 8259 JSON and NaN/Infinity are not JSON numbers"
            )
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{field} keys must be strings, got {type(key).__name__}")
            _require_finite_json(item, field=f"{field}.{key}")
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _require_finite_json(item, field=f"{field}[{index}]")
        return
    raise ValueError(
        f"{field} contains {type(value).__name__}, which is not JSON-representable; "
        "pass JSON-native types only"
    )


def _part11_annotation_token(signer_name: str, signature_meaning: str) -> str:
    """SHA-256 over both Part 11 annotation fields, as one payload field.

    The fields are free text, so unlike the closed WAF vocabulary they cannot be
    fenced against the ``|`` delimiter that separates payload fields. Hashing the
    pair keeps the binding exact — any change to either value changes the token —
    while making it impossible for a crafted name to serialise two different
    field lists alike.
    """
    return hashlib.sha256(f"{signer_name}\x00{signature_meaning}".encode()).hexdigest()


def _build_signed_payload(
    prev_hash: str,
    merkle_root: str,
    request_hash: str,
    response_hash: str,
    waf_verdict: str = WAF_VERDICT_UNRECORDED,
    signer_name: str = "",
    signature_meaning: str = "",
    status: str = NODE_STATUS_COMMITTED,
    signature_scheme: str = "",
) -> bytes:
    """Canonical bytes covered by a node's signature.

    The signature binds chain linkage (``prev_hash``) AND content
    (``request_hash`` / ``response_hash``) together with the ``merkle_root``.

    Mechanism (why this is necessary): ``verify_integrity`` recomputes the HMAC
    over the *stored* fields and compares it to the stored signature. Signing
    ``merkle_root`` alone left ``prev_hash`` cryptographically unbound — an
    adversary with WAL write access could reorder nodes and rewrite each
    ``prev_hash`` to the new predecessor's ``node_hash`` while the per-node
    signatures (over an untouched ``merkle_root``) still verified. Including
    ``prev_hash`` here makes any such edit invalidate the signature.

    ``waf_verdict`` is appended **only when non-empty**, and that conditional is
    what makes the field additive rather than breaking. Verification rebuilds
    this payload from the node's own stored fields, so a node written before the
    field existed carries an empty verdict, rebuilds the original four-field
    payload, and its signature verifies exactly as it always did.

    The conditional is also why tampering with the verdict cannot succeed in
    either direction. Blanking a recorded verdict rebuilds a four-field payload
    where a five-field one was signed; adding a verdict to a node that never had
    one rebuilds five where four were signed. Both mismatch, so the field is
    bound by the signature without a version flag to keep in step. Its
    vocabulary is closed and delimiter-free (`validate_waf_verdict`), so no
    verdict can smuggle a ``|`` and make two different field lists serialise
    alike.

    The Part 11 annotation (``signer_name`` / ``signature_meaning``) and the
    admission ``status`` follow the same value-derived conditional, which is what
    keeps AUD-10's binding additive:

    - an annotation is appended only when one of its two fields is non-empty, so
      a node written before annotations existed rebuilds the same payload it was
      signed over, and blanking a recorded name rebuilds the shorter list while
      adding one to a node that had none rebuilds the longer — both mismatch;
    - ``status`` is appended only when it differs from the committed default, so
      relabelling a rejection as committed drops a field where one was signed and
      relabelling a committed node as rejected adds one where none was signed —
      both mismatch as well.

    Old rejection records are the exception that proves the rule: they were
    signed *before* the field was bound, so their stored signature matches the
    pre-binding material and not the annotated one. :meth:`signature_status`
    therefore tries the annotated payload first and falls back to the pre-binding
    payload only when it differs — which no edit of a node written by this build
    can reach, because that node's stored signature is over the annotated
    material. The pre-binding gap that remains for already-written records is
    published as ``UC-055``.

    ``signature_scheme`` (AUD-27) follows the same pattern with one difference:
    the caller passes the label the signing tier *will* use, so the scheme is an
    input to the bytes rather than a report about them. Before this, verification
    dispatched on ``node.signature_scheme`` — a self-declared value — and checked
    the signature over material that did not contain it, so the label was
    authenticated only by the shape of the material beside it (``REG-D06``). A
    relabel inside one shape class (the presence-only tiers ``pqc-ml-dsa`` /
    ``pkcs11-*``) changed which verifier was consulted and nothing else. Bound,
    the label cannot be rewritten without invalidating the signature — and a
    verifier that has the tier's key now checks the claim instead of trusting it.

    The label is appended only when the signing tier supplied it, so a payload
    rebuilt from a record signed before this binding reproduces its original
    shape exactly. ``signature_scheme`` is validated against the closed scheme
    vocabulary for the same reason ``waf_verdict`` is: a label carrying ``|``
    could make two different field lists serialise alike.
    """
    fields = [prev_hash, merkle_root, request_hash, response_hash]
    if validate_waf_verdict(waf_verdict) != WAF_VERDICT_UNRECORDED:
        fields.append(waf_verdict)
    annotation_token = (
        _part11_annotation_token(signer_name, signature_meaning)
        if (signer_name or signature_meaning)
        else ""
    )
    if annotation_token:
        fields.append(annotation_token)
    if validate_node_status(status) != NODE_STATUS_COMMITTED:
        fields.append(status)
    if signature_scheme:
        fields.append(validate_signature_scheme(signature_scheme))
    return "|".join(fields).encode()


def _build_prebinding_signed_payload(
    prev_hash: str,
    merkle_root: str,
    request_hash: str,
    response_hash: str,
    waf_verdict: str = WAF_VERDICT_UNRECORDED,
) -> bytes:
    """The payload as it was before the Part 11 annotation was bound (AUD-10).

    Kept as a named builder rather than a default-argument call so that the shape
    it reproduces is explicit at the one call site that needs it, and so a future
    change to the current builder cannot silently redefine legacy verification.
    """
    fields = [prev_hash, merkle_root, request_hash, response_hash]
    if validate_waf_verdict(waf_verdict) != WAF_VERDICT_UNRECORDED:
        fields.append(waf_verdict)
    return "|".join(fields).encode()


def signed_payload_candidates_for(node: AuditNode) -> list[bytes]:
    """Every payload a node's signature may legitimately be over, newest first.

    Three shapes, newest first:

    1. **scheme-bound** (AUD-27) — the annotated payload with the node's own
       declared scheme appended, offered when that scheme is in the vocabulary.
       A record written by this build is signed over this shape, so rewriting its
       ``signature_scheme`` produces a candidate list in which nothing matches.
    2. **annotated** — the current four/five/seven-field shape without a scheme,
       which is what records written between AUD-10 and this binding were signed
       over.
    3. **pre-binding** — offered only when it differs, which keeps chains written
       before AUD-10 verifiable.

    Each older shape is reachable only by a signature that was actually made over
    it, because a node written by this build has its stored signature over shape
    1: the fallbacks exist for records that predate the binding, not as an
    alternative reading of a current one.
    """
    annotated = _build_signed_payload(
        prev_hash=node.prev_hash,
        merkle_root=node.merkle_root,
        request_hash=node.request_hash,
        response_hash=node.response_hash,
        waf_verdict=node.waf_verdict,
        signer_name=node.signer_name,
        signature_meaning=node.signature_meaning,
        status=node.status,
    )
    prebinding = _build_prebinding_signed_payload(
        prev_hash=node.prev_hash,
        merkle_root=node.merkle_root,
        request_hash=node.request_hash,
        response_hash=node.response_hash,
        waf_verdict=node.waf_verdict,
    )
    candidates: list[bytes] = []
    if node.signature_scheme in _SCHEME_MATERIAL:
        candidates.append(
            _build_signed_payload(
                prev_hash=node.prev_hash,
                merkle_root=node.merkle_root,
                request_hash=node.request_hash,
                response_hash=node.response_hash,
                waf_verdict=node.waf_verdict,
                signer_name=node.signer_name,
                signature_meaning=node.signature_meaning,
                status=node.status,
                signature_scheme=node.signature_scheme,
            )
        )
    for candidate in (annotated, prebinding):
        if candidate not in candidates:
            candidates.append(candidate)
    return candidates


def _hmac_sign(signing_key: str, data: bytes) -> str:
    """Return HMAC-SHA256 hex digest. Constant-time safe for string signing keys."""
    return hmac.new(
        signing_key.encode(),
        data,
        hashlib.sha256,
    ).hexdigest()


def _hmac_verify(signing_key: str, data: bytes, expected_hex: str) -> bool:
    actual = _hmac_sign(signing_key, data)
    return hmac.compare_digest(actual, expected_hex)


def _ed25519_sign(data: bytes) -> tuple[str, str, str]:
    """Per-node Ed25519 ephemeral key. Returns (signature_hex, pubkey_hex, scheme)."""
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    sig = priv.sign(data)
    # Explicit del drops the reference immediately, triggering OpenSSL's
    # OPENSSL_cleanse on the private key bytes before this frame returns (I-08).
    del priv
    return sig.hex(), pub.public_bytes_raw().hex(), "ed25519-fallback"


# ── Ledger ────────────────────────────────────────────────────────────────────


class CryptographicAuditLedger:
    """
    Append-only Merkle chain of forensic LLM interaction records.

    Thread-safety: all mutations are guarded by a reentrant Lock.

    WAL durability
    --------------
    A commit does not return until its record is on stable storage, but the
    ``fsync`` is shared: concurrent commits are coalesced into one device round
    trip by ``aegis.core.group_commit``. Two consequences are worth stating
    exactly, because they differ from the older per-record ``fsync``.

    A node enters the in-memory chain once its bytes are written and ordered,
    which is *before* its batch is synced — necessary, because the next
    committer has to be able to read the tip to link against it while this one
    is still waiting. Nothing observes that node in the meantime: the commit
    call has not returned. If the process dies in that window the in-memory
    chain dies with it, and replay rebuilds a shorter, internally consistent
    chain from the WAL.

    A batch is durable together or not at all. A failed ``fsync`` fails every
    commit waiting on it and latches ``wal_persist_failed``, which
    ``_require_intact_ledger`` in the proxy reads to answer 503 and stop
    extending the chain. Individual nodes are deliberately *not* unwound: later
    nodes have already linked against them, so there is no single node whose
    removal leaves a consistent chain.

    Parameters
    ----------
    persistence_path : str
        Path to the WAL file (line-delimited JSON).
    signing_key : str
        HMAC-SHA256 signing key, used when no HSM or PQC identity is
        configured. If empty and no stronger tier is available, the
        fallback ephemeral Ed25519 tier is used and ``signature_assurance``
        reflects that per node actually signed under it, not from this
        parameter alone (see ``signature_assurance``).
    max_memory_nodes : int
        Sliding-window deque size. Oldest nodes are evicted when the cap is hit.
    max_forensic_bytes : int
        Maximum bytes of request/response stored in the Merkle leaf envelope.
    max_wal_bytes : int
        When > 0, the active WAL is rotated into an immutable archived segment
        once it reaches this many bytes; a fresh active WAL is then opened. 0
        (the default) disables rotation, preserving the single-file behaviour.
        Archived segments are named ``<persistence_path>.NNNNNN`` (zero-padded,
        ascending), keep 0o600 permissions, and are replayed in order on
        startup. Rotation NEVER drops nodes: the full append-only audit chain is
        always reconstructable across every segment.
    mmr_fast_restore : bool
        When True, a validated ``<persistence_path>.mmr.state`` checkpoint
        reseats the Merkle Mountain Range from its peak set in O(log N) instead
        of replaying every leaf, and only leaves committed after the checkpoint
        are replayed. Default False, which preserves full replay.

        The trade is startup cost against in-memory historical proofs: a
        peak-set restore summarises the leaves below it, so their inclusion
        proofs can no longer be derived from the live accumulator. No evidence
        is lost — each committed node carries its own self-contained
        ``mmr_proof`` — and the restored root is accepted only after it is
        checked against the root the last committed node recorded. A missing,
        stale, corrupt or disagreeing checkpoint always falls back to full
        replay. The checkpoint is written whether or not the flag is set.
    """

    def __init__(
        self,
        persistence_path: str,
        signing_key: str = "",
        max_memory_nodes: int = 100_000,
        max_forensic_bytes: int = _DEFAULT_MAX_FORENSIC_BYTES,
        max_wal_bytes: int = 0,
        # Backward-compat alias accepted but ignored (old API used async_mode)
        async_mode: bool = False,
        hsm_backend: HSMSigningBackend | None = None,
        require_strong_signing: bool = False,
        fsync_fn: Callable[[int], None] | None = None,
        mmr_fast_restore: bool = False,
        mmr_hash_scheme: str = MMR_SCHEME_AUTO,
        pqc_identity_path: str | os.PathLike[str] | None = None,
        enable_cryptographic_shredding: bool = False,
        shredder_vault_path: str | os.PathLike[str] | None = None,
        commit_batch_max_size: int | None = None,
        commit_batch_timeout_ms: float | None = None,
    ) -> None:
        if mmr_hash_scheme not in _SCHEME_PROOF_VERSIONS and mmr_hash_scheme != MMR_SCHEME_AUTO:
            raise ValueError(
                f"mmr_hash_scheme must be {MMR_SCHEME_AUTO!r} or one of "
                f"{sorted(_SCHEME_PROOF_VERSIONS)}, got {mmr_hash_scheme!r}"
            )
        # ``auto`` is resolved during replay, once the WAL has said which scheme
        # it was written under. Until then the accumulator is built on the
        # new-chain default, which is what an empty WAL will keep.
        self._scheme_pinned = mmr_hash_scheme != MMR_SCHEME_AUTO
        self.mmr_hash_scheme = (
            mmr_hash_scheme if self._scheme_pinned else MMR_NEW_CHAIN_DEFAULT_SCHEME
        )
        mmr_hash_scheme = self.mmr_hash_scheme
        self.persistence_path = persistence_path
        self._signing_key = signing_key
        self._fsync = fsync_fn or os.fsync
        self._hsm_backend = hsm_backend
        #: Scheme label learned from a signature when the backend cannot resolve
        #: its key type up front (AUD-27). Empty means "not learned yet".
        self._hsm_learned_scheme = ""
        self._require_strong_signing = require_strong_signing
        self.max_memory_nodes = max_memory_nodes
        self.max_forensic_bytes = max_forensic_bytes
        self.max_wal_bytes = max_wal_bytes
        self._mmr_fast_restore = mmr_fast_restore
        self.chain: deque[AuditNode] = deque(maxlen=max_memory_nodes)
        self._window_anchor_hash = "0" * 64
        self._lock = Lock()
        # Guards *which descriptor is current*, not the ledger state. The
        # group-commit syncer runs with `_lock` released — that is the whole
        # point — so it needs something to hold the WAL handle still against a
        # concurrent rotation. Lock order is always `_lock` then `_sync_lock`;
        # the syncer takes only `_sync_lock`, so there is no cycle.
        self._sync_lock = Lock()
        self._wal_handle: TextIO | None = None
        self._wal_bytes = 0
        self._fault_state: str = "healthy"
        self._commit_engine = CoalescedCommitEngine(
            max_batch=_resolve_commit_batch_max_size(commit_batch_max_size),
            linger_seconds=_resolve_commit_batch_linger(commit_batch_timeout_ms),
        )
        self.pqc_identity_path = str(pqc_identity_path) if pqc_identity_path else ""
        self.enable_cryptographic_shredding = enable_cryptographic_shredding
        self._shredder: CryptoShredder | None = None
        if enable_cryptographic_shredding:
            # Default the vault beside the WAL: the two have the same custody
            # requirement, and separating them by default would invite a
            # deployment that backs up one and not the other — which either
            # loses every plaintext or preserves keys past an erasure.
            vault = (
                str(shredder_vault_path)
                if shredder_vault_path
                else f"{persistence_path}.shredder.db"
            )
            self._shredder = CryptoShredder(vault)
        # Resolved lazily and cached: loading the identity touches the
        # filesystem, and a ledger that never signs should not pay for it.
        # ``False`` distinguishes "not yet looked up" from "looked up, absent".
        self._pqc_identity: PQCSigner | None | Literal[False] = False
        # Read configuration only, never `_configured_signing_ceiling()`: that
        # calls `_pqc_signer()`, which would force the identity load the line
        # above exists to defer.
        if (
            self._signing_key
            and not (self._hsm_backend and self._hsm_backend.available)
            and not self.pqc_identity_path
        ):
            logger.warning(
                "Ledger is configured for symmetric signing only (hmac-sha256): "
                "Symmetric signing provides no non-repudiation; any key holder "
                "can forge. Commits will report signature_assurance=%s. "
                "Configure an HSM backend or a PQC identity path for an "
                "asymmetric tier.",
                SignatureAssurance.SYMMETRIC_AUTHENTICATED.value,
            )
        self._mmr = MerkleMountainRange(hash_scheme=mmr_hash_scheme)
        # Set during replay when the WAL's own proofs name a different scheme.
        self._wal_proof_version: str | None = None
        self._load_from_wal()
        # FIX-CAL-01: open the WAL handle eagerly after reconstruction.
        # Previously the handle was only opened in __enter__ (context-manager
        # path).  In app.py the ledger is used directly, so _wal_handle was
        # always None and _persist_node opened+closed a new fd on every write.
        self._open_wal()

    # ── Public properties ──────────────────────────────────────────────────

    def _configured_signing_ceiling(self) -> SignatureAssurance:
        """The tier a commit right now would sign under, without signing anything.

        Mirrors ``_sign``'s own tier checks (HSM availability, a configured
        PQC identity, a configured HMAC key) in the same priority order, but
        reads configuration only. Used solely by :attr:`signature_assurance`
        for a chain with no nodes yet: there is no signing history to
        report, so the honest statement is "here is what the next commit
        would use", not a claim about history that does not exist.
        """

        if self._hsm_backend and self._hsm_backend.available:
            return SignatureAssurance.ASYMMETRIC_HARDWARE_ATTESTED
        if self._pqc_signer() is not None:
            return SignatureAssurance.ASYMMETRIC_SOFTWARE
        if self._signing_key:
            return SignatureAssurance.SYMMETRIC_AUTHENTICATED
        return SignatureAssurance.COMPROMISED_EPHEMERAL

    @property
    def signature_assurance(self) -> SignatureAssurance:
        """The weakest assurance tier actually used across the whole chain.

        Computed per node from ``AuditNode.signature_scheme`` — what each
        node was actually signed with — never from the ledger's current
        signing configuration. That distinction is the point: this replaces
        the former ``legal_admissibility`` property, which read
        ``self._signing_key`` (fixed at construction) instead of the chain,
        so a chain replayed from a WAL written entirely under
        ``ed25519-fallback`` (no key configured at the time) silently
        reported "High" the moment a later process configured a key and
        restarted — the fallback-signed history was never re-examined.

        Weakest-link over the chain on purpose: one fallback-signed node
        means the chain as a whole cannot be presented as fully
        attributable, no matter how every other node was signed or how the
        ledger is configured now.

        An empty chain has no signing history to report, so this falls back
        to :meth:`_configured_signing_ceiling`.
        """

        with self._lock:
            chain_snapshot = list(self.chain)
        return chain_signature_assurance(chain_snapshot) or self._configured_signing_ceiling()

    @property
    def archived_segments(self) -> list[str]:
        """Paths of rotated, immutable WAL archive segments (oldest first)."""
        with self._lock:
            return self._segment_paths()

    def chain_snapshot(self) -> list[AuditNode]:
        """A consistent copy of the retained in-memory chain.

        Readers MUST iterate this, never ``self.chain`` directly. Commits
        append to the deque from worker threads (``asyncio.to_thread``) while
        request handlers iterate it, and a mutation landing between two
        ``__next__`` calls raises ``RuntimeError('deque mutated during
        iteration')`` out of the handler — a 500 with no audit data, on reads
        that had already passed authentication and scope checks (AUD-08).

        Every mutation of ``self.chain`` happens under ``self._lock``
        (``_append_memory_node`` is only reached from within it), so a copy
        taken under the same lock is both consistent and safe to iterate. The
        commit path deliberately releases the lock before waiting on the
        ``fsync``, so this does not block on storage I/O.

        One snapshot per handler, not one per field: taking it twice lets a
        commit land in between, so a count and a tail hash can describe
        different chains in the same response.

        Do not call this while already holding ``self._lock``: it is a
        non-reentrant :class:`threading.Lock`.
        """

        with self._lock:
            return list(self.chain)

    @property
    def window_anchor_hash(self) -> str:
        """Hash immediately preceding the first retained in-memory node."""
        return self._window_anchor_hash

    def _append_memory_node(self, node: AuditNode) -> None:
        if self.chain.maxlen is not None and len(self.chain) == self.chain.maxlen:
            self._window_anchor_hash = self.chain[0].node_hash
        self.chain.append(node)

    # ── Core API ───────────────────────────────────────────────────────────

    def commit_forensic(
        self,
        *,
        state_id: str,
        request_bytes: bytes,
        response_bytes: bytes | None = None,
        entropy: float = 0.0,
        tenant_id: str = "default",
        model: str = "unknown",
        endpoint: str = "unknown",
        token_trail: list[dict[str, Any]] | None = None,
        usage: dict[str, Any] | None = None,
        sampling_params: dict[str, Any] | None = None,
        phi_scrubbed: bool = False,
        scrub_method: str = "",
        signer_name: str = "",
        signature_meaning: str = "",
        waf_verdict: str = WAF_VERDICT_UNRECORDED,
    ) -> AuditNode:
        """Commit a full forensic record (request + response) to the chain.

        Args:
            state_id: Unique identifier for this interaction (e.g. request_id).
            request_bytes: Raw request body bytes (will be hashed, not stored).
            response_bytes: Raw response body bytes (will be hashed, not stored).
            entropy: Mean Shannon entropy of the response logprobs.
            tenant_id: Session/tenant identifier.
            model: LLM model name.
            endpoint: API endpoint (e.g. "chat.completions").
            token_trail: Per-token logprob records for evidence tracing.
            usage: OpenAI usage dict (prompt_tokens, completion_tokens, etc.).
            sampling_params: Temperature, top_p, etc.

        Returns:
            The committed AuditNode.

        Raises:
            ValueError: On invalid input (non-finite entropy, NULL in state_id, etc.).
        """
        if "\x00" in state_id:
            raise ValueError("state_id containing NULL byte is rejected")
        if not math.isfinite(entropy):
            raise ValueError("entropy must be a finite number")
        if len(request_bytes) > MAX_PAYLOAD_BYTES:
            raise ValueError("request_bytes exceeds 1 MiB hard cap")

        params = {**(sampling_params or {})}
        if usage:
            params["usage"] = usage
        _require_finite_json(params, field="sampling_params")

        req_hash = self._payload_digest(request_bytes, tenant_id)
        resp_hash = self._payload_digest(response_bytes, tenant_id) if response_bytes else ""

        # Build canonical MMR leaf
        # Validate before the lock: a bad verdict must be a caller error, not a
        # half-written commit discovered while holding the ledger lock.
        waf_verdict = validate_waf_verdict(waf_verdict)
        leaf = build_merkle_leaf(
            state_id=state_id,
            request_bytes=request_bytes,
            response_bytes=response_bytes,
            model=model,
            endpoint=endpoint,
            max_bytes=self.max_forensic_bytes,
            waf_verdict=waf_verdict,
        )

        with self._lock:
            prev_hash = self.chain[-1].node_hash if self.chain else "0" * 64
            timestamp = time.time()
            # O(log n) rollback token, not a copy of the accumulator: this runs
            # on every commit, so a deep copy would make commit cost grow with
            # the length of the chain.
            mmr_before = self._mmr.checkpoint()
            # Seal before appending: with shredding on, the tree commits to
            # the envelope's commitment, so the digest has to exist first.
            mmr_leaf_hash, sealed = self._seal_leaf(leaf, tenant_id)
            merkle_root = self._mmr.add_leaf_hash(mmr_leaf_hash)
            mmr_leaf_count = self._mmr.get_leaf_count()
            mmr_leaf_index = mmr_leaf_count - 1
            mmr_proof = self._mmr.get_portable_inclusion_proof(mmr_leaf_index).to_dict()

            # Sign over prev_hash + merkle_root + request/response hashes so the
            # signature binds chain linkage, not merkle_root alone (see
            # _build_signed_payload).
            # AUD-27: the signing tier is selected first and its scheme is
            # appended to the payload, so the recorded label is part of what the
            # signature covers (see _sign_bound).
            try:
                signature, pub_key_hex, scheme, is_fallback, signed_payload = self._sign_bound(
                    lambda bound_scheme: _build_signed_payload(
                        prev_hash=prev_hash,
                        merkle_root=merkle_root,
                        request_hash=req_hash,
                        response_hash=resp_hash,
                        waf_verdict=waf_verdict,
                        signer_name=signer_name,
                        signature_meaning=signature_meaning,
                        status=NODE_STATUS_COMMITTED,
                        signature_scheme=bound_scheme,
                    )
                )
            except Exception:
                self._mmr.rollback_to(mmr_before)
                self._fault_state = "signing_failed"
                raise

            node = AuditNode(
                state_id=state_id,
                timestamp=timestamp,
                entropy=entropy,
                tenant_id=tenant_id,
                sampling_params=params,
                prev_hash=prev_hash,
                merkle_root=merkle_root,
                signature=signature,
                signature_scheme=scheme,
                public_key=pub_key_hex,
                request_hash=req_hash,
                response_hash=resp_hash,
                model=model,
                endpoint=endpoint,
                token_trail_count=len(token_trail or []),
                is_fallback=is_fallback,
                phi_scrubbed=phi_scrubbed,
                scrub_method=scrub_method,
                signer_name=signer_name,
                signature_meaning=signature_meaning,
                mmr_leaf_hash=mmr_leaf_hash,
                mmr_leaf_index=mmr_leaf_index,
                mmr_leaf_count=mmr_leaf_count,
                mmr_proof=mmr_proof,
                sealed_subject_id=sealed.subject_id if sealed else "",
                sealed_nonce=sealed.nonce.hex() if sealed else "",
                sealed_ciphertext=sealed.ciphertext.hex() if sealed else "",
                shredding_version=sealed.scheme if sealed else SHRED_SCHEME_UNSEALED,
                waf_verdict=waf_verdict,
            )

            try:
                ticket = self._persist_node(node)
            except Exception:
                self._mmr.rollback_to(mmr_before)
                self._fault_state = "wal_persist_failed"
                raise
            self._append_memory_node(node)
        # Outside the lock on purpose. Waiting for the fsync here is what lets
        # the next committer write while this one is still waiting, so a burst
        # of concurrent commits costs one device round trip rather than one
        # each. The node is not returned — not reported committed — until its
        # record is on stable storage.
        self._await_durable(ticket)
        return node

    def commit_rejection(
        self,
        *,
        request_bytes: bytes,
        rejection_code: int,
        reason_category: str,
        tenant_id: str | None = None,
        state_id: str | None = None,
        endpoint: str = "rejected",
    ) -> AuditNode:
        """Commit a signed record of a request refused before admission.

        A request the gateway blocks never reaches a model, so it produces no
        forensic interaction record — historically it left no durable trace at
        all beyond a log line, which is not evidence: logs are mutable and
        unchained. This commits the refusal itself to the same append-only
        Merkle chain, so "the gateway blocked this request" becomes a claim
        backed by a signature and an inclusion proof rather than by a log.

        The request body is hashed, never stored: a blocked request is
        frequently hostile input, and the chain must not become a repository of
        attack payloads. The synthetic response hash binds the decision — code
        and category — so a rejection cannot later be rewritten as a different
        outcome without breaking the signature.

        Args:
            request_bytes: Raw request body. Hashed into the leaf, not retained.
            rejection_code: HTTP status the gateway returned (403, 429, 413).
            reason_category: Stable machine-readable reason, e.g. ``waf_block``.
            tenant_id: Session/tenant identifier when one was resolved. A
                request may be refused before authentication, so this is
                optional and defaults to ``"unattributed"`` rather than to a
                tenant that was never established.
            state_id: Rejection identifier. Generated when not supplied.
            endpoint: Endpoint the request targeted.

        Returns:
            The committed ``AuditNode``, carrying ``status="rejected"`` and its
            portable MMR inclusion proof.

        Raises:
            ValueError: On a NULL byte in ``state_id`` or an over-cap body,
                matching ``commit_forensic``.
        """
        rejection_id = state_id or f"rej-{uuid.uuid4().hex}"
        if "\x00" in rejection_id:
            raise ValueError("state_id containing NULL byte is rejected")
        if len(request_bytes) > MAX_PAYLOAD_BYTES:
            raise ValueError("request_bytes exceeds 1 MiB hard cap")

        # The decision, in a form that hashes deterministically.
        decision = f"REJECTED:{rejection_code}:{reason_category}".encode()
        req_hash = self._payload_digest(request_bytes, tenant_id or "unattributed")
        resp_hash = self._payload_digest(decision, tenant_id or "unattributed")

        leaf = build_merkle_leaf(
            state_id=rejection_id,
            request_bytes=request_bytes,
            response_bytes=decision,
            model="none",
            endpoint=endpoint,
            max_bytes=self.max_forensic_bytes,
        )

        with self._lock:
            prev_hash = self.chain[-1].node_hash if self.chain else "0" * 64
            timestamp = time.time()
            mmr_before = self._mmr.checkpoint()
            # Seal before appending: with shredding on, the tree commits to
            # the envelope's commitment, so the digest has to exist first.
            # Same fallback the node itself uses: a request refused before
            # authentication has no subject to attribute erasure to, so it
            # seals under "unattributed" rather than under a tenant that was
            # never established.
            mmr_leaf_hash, sealed = self._seal_leaf(leaf, tenant_id or "unattributed")
            merkle_root = self._mmr.add_leaf_hash(mmr_leaf_hash)
            mmr_leaf_count = self._mmr.get_leaf_count()
            mmr_leaf_index = mmr_leaf_count - 1
            mmr_proof = self._mmr.get_portable_inclusion_proof(mmr_leaf_index).to_dict()

            # AUD-27: scheme bound into the signed bytes, as on the committed path.
            try:
                signature, pub_key_hex, scheme, is_fallback, signed_payload = self._sign_bound(
                    lambda bound_scheme: _build_signed_payload(
                        prev_hash=prev_hash,
                        merkle_root=merkle_root,
                        request_hash=req_hash,
                        response_hash=resp_hash,
                        status=NODE_STATUS_REJECTED,
                        signature_scheme=bound_scheme,
                    )
                )
            except Exception:
                self._mmr.rollback_to(mmr_before)
                self._fault_state = "signing_failed"
                raise

            node = AuditNode(
                state_id=rejection_id,
                timestamp=timestamp,
                entropy=0.0,
                tenant_id=tenant_id or "unattributed",
                sampling_params={
                    "rejection_code": rejection_code,
                    "reason_category": reason_category,
                },
                prev_hash=prev_hash,
                merkle_root=merkle_root,
                signature=signature,
                signature_scheme=scheme,
                public_key=pub_key_hex,
                request_hash=req_hash,
                response_hash=resp_hash,
                model="none",
                endpoint=endpoint,
                token_trail_count=0,
                is_fallback=is_fallback,
                status="rejected",
                mmr_leaf_hash=mmr_leaf_hash,
                mmr_leaf_index=mmr_leaf_index,
                mmr_leaf_count=mmr_leaf_count,
                mmr_proof=mmr_proof,
                sealed_subject_id=sealed.subject_id if sealed else "",
                sealed_nonce=sealed.nonce.hex() if sealed else "",
                sealed_ciphertext=sealed.ciphertext.hex() if sealed else "",
                shredding_version=sealed.scheme if sealed else SHRED_SCHEME_UNSEALED,
            )

            try:
                ticket = self._persist_node(node)
            except Exception:
                self._mmr.rollback_to(mmr_before)
                self._fault_state = "wal_persist_failed"
                raise
            self._append_memory_node(node)
        # Outside the lock on purpose. Waiting for the fsync here is what lets
        # the next committer write while this one is still waiting, so a burst
        # of concurrent commits costs one device round trip rather than one
        # each. The node is not returned — not reported committed — until its
        # record is on stable storage.
        self._await_durable(ticket)
        return node

    def commit_state(
        self,
        state_id: str,
        entropy: float,
        payload: bytes,
        tenant_id: str = "default",
        sampling_params: dict[str, Any] | None = None,
        phi_scrubbed: bool = False,
        scrub_method: str = "",
        signer_name: str = "",
        signature_meaning: str = "",
    ) -> AuditNode:
        """Backward-compatible API used by app.py (request-only commit).

        Delegates to commit_forensic with response_bytes=None.
        """
        params = sampling_params or {}
        return self.commit_forensic(
            state_id=state_id,
            request_bytes=payload,
            response_bytes=None,
            entropy=entropy,
            tenant_id=tenant_id,
            model=str(params.get("model", "unknown")),
            endpoint=str(params.get("endpoint", "chat.completions")),
            sampling_params=params,
            phi_scrubbed=phi_scrubbed,
            scrub_method=scrub_method,
            signer_name=signer_name,
            signature_meaning=signature_meaning,
        )

    def commit_forensic_summary(
        self,
        *,
        state_id: str,
        request_bytes: bytes | None = None,
        response_hash: str,
        response_size: int,
        response_preview: bytes,
        terminal_outcome: str,
        final_marker_included: bool,
        token_count: int,
        elapsed_seconds: float,
        redaction_hits: dict[str, int] | None = None,
        tenant_id: str = "default",
        model: str = "unknown",
        endpoint: str = "chat.completions",
        phi_scrubbed: bool = False,
        scrub_method: str = "",
        signer_name: str = "",
        signature_meaning: str = "stream-terminal-evidence",
        request_digest: tuple[str, int] | None = None,
    ) -> AuditNode:
        """Commit one terminal record for an incrementally hashed response.

        The caller supplies the SHA-256 digest and bounded preview accumulated at
        the ASGI body-iterator boundary.  No full response is retained or reread.

        Exactly one of ``request_bytes`` and ``request_digest`` is given. The
        digest form — ``(sha256 hex, size)`` with no request preview — is for
        replaying a record that was spooled without its content (REG-D32). The
        form decides the labels: the digest form must be signed as
        ``RECOVERED_TERMINAL_MEANING`` and is stored as ``recovered-terminal``;
        the byte form may not use that meaning and is ``durable-terminal``.
        Every field is type-checked here, before the lock, so a malformed value
        is refused rather than failing inside signing and latching a fault.
        """
        allowed_outcomes = {
            "complete",
            "client_disconnected",
            "upstream_error",
            "upstream_incomplete",
            "timeout",
            "byte_limit",
            "event_limit",
            "privacy_failure",
            "shutdown_cancelled",
        }
        for name, value in (
            ("state_id", state_id),
            ("tenant_id", tenant_id),
            ("model", model),
            ("endpoint", endpoint),
            ("scrub_method", scrub_method),
            ("signer_name", signer_name),
            ("signature_meaning", signature_meaning),
            ("terminal_outcome", terminal_outcome),
        ):
            if not isinstance(value, str):
                raise ValueError(f"{name} must be a string")
        if "\x00" in state_id:
            raise ValueError("state_id containing NULL byte is rejected")
        if (request_bytes is None) == (request_digest is None):
            raise ValueError("exactly one of request_bytes and request_digest is required")
        if request_bytes is not None:
            if signature_meaning == RECOVERED_TERMINAL_MEANING:
                raise ValueError("the recovered signature meaning is reserved for request_digest")
            if len(request_bytes) > MAX_PAYLOAD_BYTES:
                raise ValueError("request_bytes exceeds 1 MiB hard cap")
            request_hash = sha256_hex(request_bytes)
            request_size = len(request_bytes)
            request_preview = request_bytes[: self.max_forensic_bytes]
            evidence_status = "durable-terminal"
        else:
            # request_digest is not None: exactly one of the two was checked above.
            if signature_meaning != RECOVERED_TERMINAL_MEANING:
                raise ValueError(
                    "request_digest is recovery-only and must be signed as "
                    f"{RECOVERED_TERMINAL_MEANING!r}"
                )
            if not isinstance(request_digest, tuple) or len(request_digest) != 2:
                raise ValueError("request_digest must be a (hash, size) pair")
            request_hash, request_size = request_digest
            if (
                not isinstance(request_hash, str)
                or len(request_hash) != 64
                or any(ch not in "0123456789abcdef" for ch in request_hash)
            ):
                raise ValueError("request_digest hash must be a lowercase SHA-256 hex digest")
            if (
                isinstance(request_size, bool)
                or not isinstance(request_size, int)
                or not 0 <= request_size <= MAX_PAYLOAD_BYTES
            ):
                raise ValueError("request_digest size must be an integer within [0, 1 MiB]")
            request_preview = b""
            evidence_status = "recovered-terminal"
        if (
            not isinstance(response_hash, str)
            or len(response_hash) != 64
            or any(ch not in "0123456789abcdef" for ch in response_hash)
        ):
            raise ValueError("response_hash must be a lowercase SHA-256 hex digest")
        if (
            isinstance(response_size, bool)
            or not isinstance(response_size, int)
            or response_size < 0
        ):
            raise ValueError("response_size must be a non-negative integer")
        if isinstance(token_count, bool) or not isinstance(token_count, int) or token_count < 0:
            raise ValueError("token_count must be a non-negative integer")
        if not isinstance(final_marker_included, bool):
            raise ValueError("final_marker_included must be a bool")
        if (
            isinstance(elapsed_seconds, bool)
            or not isinstance(elapsed_seconds, (int, float))
            or not math.isfinite(elapsed_seconds)
            or elapsed_seconds < 0
        ):
            raise ValueError("elapsed_seconds must be finite and non-negative")
        if len(response_preview) > self.max_forensic_bytes:
            raise ValueError("response_preview exceeds max_forensic_bytes")
        if terminal_outcome not in allowed_outcomes:
            raise ValueError("unsupported terminal_outcome")
        if redaction_hits is not None and not isinstance(redaction_hits, dict):
            raise ValueError("redaction_hits must be a dictionary")
        hits = dict(redaction_hits or {})
        if any(
            not isinstance(key, str)
            or not key
            or isinstance(value, bool)
            or not isinstance(value, int)
            or value < 0
            for key, value in hits.items()
        ):
            raise ValueError("redaction_hits must contain non-negative integer counts")

        leaf = build_stream_merkle_leaf(
            state_id=state_id,
            request_hash=request_hash,
            response_hash=response_hash,
            request_size=request_size,
            response_size=response_size,
            request_preview=request_preview,
            response_preview=response_preview,
            model=model,
            endpoint=endpoint,
            terminal_outcome=terminal_outcome,
            final_marker_included=final_marker_included,
            token_count=token_count,
            redaction_hits=hits,
        )
        params: dict[str, Any] = {
            "evidence_status": evidence_status,
            "elapsed_seconds": elapsed_seconds,
            "final_marker_included": final_marker_included,
            "leaf_version": 2,
            "redaction_hits": dict(sorted(hits.items())),
            "response_size": response_size,
            "terminal_outcome": terminal_outcome,
            "token_count": token_count,
        }

        with self._lock:
            prev_hash = self.chain[-1].node_hash if self.chain else "0" * 64
            timestamp = time.time()
            # See commit_forensic: rollback token rather than a snapshot.
            mmr_before = self._mmr.checkpoint()
            # Seal before appending: with shredding on, the tree commits to
            # the envelope's commitment, so the digest has to exist first.
            mmr_leaf_hash, sealed = self._seal_leaf(leaf, tenant_id)
            merkle_root = self._mmr.add_leaf_hash(mmr_leaf_hash)
            mmr_leaf_count = self._mmr.get_leaf_count()
            mmr_leaf_index = mmr_leaf_count - 1
            mmr_proof = self._mmr.get_portable_inclusion_proof(mmr_leaf_index).to_dict()
            # AUD-27: scheme bound into the signed bytes, as on the ingest path.
            try:
                signature, pub_key_hex, scheme, is_fallback, signed_payload = self._sign_bound(
                    lambda bound_scheme: _build_signed_payload(
                        prev_hash=prev_hash,
                        merkle_root=merkle_root,
                        request_hash=request_hash,
                        response_hash=response_hash,
                        signer_name=signer_name,
                        signature_meaning=signature_meaning,
                        status=NODE_STATUS_COMMITTED,
                        signature_scheme=bound_scheme,
                    )
                )
            except Exception:
                self._mmr.rollback_to(mmr_before)
                self._fault_state = "signing_failed"
                raise
            node = AuditNode(
                state_id=state_id,
                timestamp=timestamp,
                entropy=0.0,
                tenant_id=tenant_id,
                sampling_params=params,
                prev_hash=prev_hash,
                merkle_root=merkle_root,
                signature=signature,
                signature_scheme=scheme,
                public_key=pub_key_hex,
                request_hash=request_hash,
                response_hash=response_hash,
                model=model,
                endpoint=endpoint,
                token_trail_count=token_count,
                is_fallback=is_fallback,
                phi_scrubbed=phi_scrubbed or bool(hits),
                scrub_method=scrub_method,
                signer_name=signer_name,
                signature_meaning=signature_meaning,
                audit_trail_version="2",
                mmr_leaf_hash=mmr_leaf_hash,
                mmr_leaf_index=mmr_leaf_index,
                mmr_leaf_count=mmr_leaf_count,
                mmr_proof=mmr_proof,
                sealed_subject_id=sealed.subject_id if sealed else "",
                sealed_nonce=sealed.nonce.hex() if sealed else "",
                sealed_ciphertext=sealed.ciphertext.hex() if sealed else "",
                shredding_version=sealed.scheme if sealed else SHRED_SCHEME_UNSEALED,
            )
            try:
                ticket = self._persist_node(node)
            except Exception:
                self._mmr.rollback_to(mmr_before)
                self._fault_state = "wal_persist_failed"
                raise
            self._append_memory_node(node)
        # Outside the lock on purpose. Waiting for the fsync here is what lets
        # the next committer write while this one is still waiting, so a burst
        # of concurrent commits costs one device round trip rather than one
        # each. The node is not returned — not reported committed — until its
        # record is on stable storage.
        self._await_durable(ticket)
        return node

    def verify_integrity(self) -> tuple[bool, int | None]:
        """O(N) full-chain integrity sweep.

        Checks:
        1. Each node's node_hash is self-consistent.
        2. Each node's prev_hash matches the preceding node's node_hash.
        3. Each node's signature is valid under its declared scheme through
           the dispatcher in :meth:`signature_status`; an invalid signature,
           a scheme/material mismatch, or an unrecognised scheme fails the
           sweep. A signature this build cannot check reports ``unverified``
           and does not fail — the published boundary is ``UC-054``.

        Returns:
            (True, None) if valid; (False, error_index) on first violation.
        """
        with self._lock:
            chain_list = list(self.chain)
            window_anchor = self._window_anchor_hash

        for i, node in enumerate(chain_list):
            creation_hash = getattr(node, "__creation_hash__", None)
            if creation_hash is not None and node.node_hash != creation_hash:
                logger.error(
                    "Integrity violation: node %d in-memory tamper detected "
                    "(creation_hash=%s…, current_hash=%s…)",
                    i,
                    creation_hash[:16],
                    node.node_hash[:16],
                )
                return False, i

            expected_prev = window_anchor if i == 0 else chain_list[i - 1].node_hash
            if node.prev_hash != expected_prev:
                logger.error(
                    "Integrity violation: node %d prev_hash mismatch (expected %s, got %s)",
                    i,
                    expected_prev[:16],
                    node.prev_hash[:16],
                )
                return False, i

            if self._require_strong_signing and node.is_fallback:
                logger.error("Integrity violation: fallback signature at node %d", i)
                return False, i
            # Signature verification runs through the scheme dispatcher for
            # every node, not only for HMAC-labelled ones: a rewritten label
            # or a failed verification is a violation. A tier this build has
            # no verifier for reports ``unverified`` and does not fail the
            # sweep — that boundary is published as UC-054.
            if self.signature_status(node) == "invalid":
                logger.error(
                    "Integrity violation: node %d signature invalid (scheme %s)",
                    i,
                    node.signature_scheme,
                )
                return False, i
            if node.mmr_proof is not None:
                try:
                    proof = MMRInclusionProofV1.from_dict(node.mmr_proof)
                except (TypeError, ValueError, KeyError):
                    logger.error("Integrity violation: node %d malformed MMR proof", i)
                    return False, i
                if (
                    proof.leaf_index != node.mmr_leaf_index
                    or proof.leaf_count != node.mmr_leaf_count
                    or not MerkleMountainRange.verify_portable_inclusion_hash(
                        node.mmr_leaf_hash, proof, node.merkle_root
                    )
                ):
                    logger.error("Integrity violation: node %d invalid MMR proof", i)
                    return False, i

        return True, None

    def signature_status(self, node: AuditNode) -> str:
        """Return ``valid``, ``invalid``, or ``unverified`` for one node.

        The scheme label is fenced by :func:`scheme_material_inconsistency`
        first: material that cannot belong to the declared scheme — or a
        scheme outside the allowlist — is ``invalid``, not ``unverified``,
        so a rewritten label is a positive detection rather than an absence
        of information. ``unverified`` is reserved for material that is
        consistent with its scheme but cannot be checked by this build (no
        signing key in memory, or an HSM / ML-DSA tier whose verifier is not
        available here).

        Since AUD-27 the candidate material includes the node's own declared
        scheme for records written by this build, so a rewritten label does not
        merely change which verifier is consulted — it changes the bytes that
        verifier is asked about, and nothing matches.
        """
        if scheme_material_inconsistency(node) is not None:
            return "invalid"
        try:
            # AUD-10: the Part 11 annotation and the admission status are part of
            # the annotated payload; the pre-binding payload is offered only as a
            # fallback for records signed before they were bound. A status outside
            # the closed vocabulary raises here and is reported as ``invalid``.
            # AUD-27: the node's declared scheme is bound the same way, so the
            # first candidate is the shape this build writes, and the two older
            # shapes are reachable only by signatures actually made over them.
            payloads = signed_payload_candidates_for(node)
            if node.signature_scheme == "hmac-sha256":
                if not self._signing_key:
                    return "unverified"
                if any(
                    _hmac_verify(self._signing_key, payload, node.signature) for payload in payloads
                ):
                    return "valid"
                return "invalid"
            if node.signature_scheme == "ed25519-fallback":
                public_key = ed25519.Ed25519PublicKey.from_public_bytes(
                    bytes.fromhex(node.public_key)
                )
                for payload in payloads:
                    try:
                        public_key.verify(bytes.fromhex(node.signature), payload)
                    except InvalidSignature:
                        continue
                    return "valid"
                return "invalid"
            if node.signature_scheme == "pqc-ml-dsa" and RUST_AVAILABLE:
                if any(
                    aegis_rust.verify_pqc_signature(  # type: ignore[name-defined]
                        payload,
                        bytes.fromhex(node.signature),
                        bytes.fromhex(node.public_key),
                    )
                    for payload in payloads
                ):
                    return "valid"
                return "invalid"
        except (ValueError, TypeError, InvalidSignature):
            return "invalid"
        except Exception:
            logger.exception("node signature verification failed")
            return "unverified"
        return "unverified"

    def export_part11_signatures(self) -> list[dict[str, Any]]:
        """Return signature annotation fields that may support a Part 11 review.

        Each record includes three fields associated with 21 CFR 11.50 review:
        - ``signer_name``      — printed name of the signer
        - ``signature_meaning``— human-readable meaning (authored/reviewed/approved)
        - ``timestamp_iso``    — date and time when the signature was executed (UTC ISO-8601)

        Plus the fields that link the record to the chain:
        - ``signature``        — hex-encoded cryptographic signature. For nodes
          written by this build the signed material includes both annotation
          fields and the admission status, so a rewritten ``signer_name``,
          ``signature_meaning`` or ``status`` fails verification. Records signed
          before that binding was introduced verify against the pre-binding
          material instead; that gap is published as ``UC-055``.
        - ``signature_scheme`` — signing algorithm used. For records written by
          this build the label is part of the signed material, so it cannot be
          rewritten without failing verification; records signed before AUD-27
          carry it unanchored, which is the boundary published as ``UC-054`` (b).
        - ``node_hash``        — SHA-256 chain accumulator over the node's hashed
          fields, which do not include the annotation. It links the record into
          the chain (and into its MMR leaf) but is not itself the annotation's
          binding — ``signature`` is.
        - ``state_id``         — unique node identifier

        Records with no signer_name are included with empty strings so that
        every chain node is represented in the export.
        """
        from datetime import UTC, datetime  # noqa: PLC0415

        with self._lock:
            chain_list = list(self.chain)

        records: list[dict[str, Any]] = []
        for node in chain_list:
            records.append(
                {
                    "state_id": node.state_id,
                    "signer_name": node.signer_name,
                    "signature_meaning": node.signature_meaning,
                    "timestamp_iso": datetime.fromtimestamp(node.timestamp, tz=UTC).isoformat(),
                    "node_hash": node.node_hash,
                    "signature": node.signature,
                    "signature_scheme": node.signature_scheme,
                }
            )
        return records

    def close(self) -> None:
        with self._lock:
            # Checkpoint before releasing the handle: a clean shutdown is the
            # case where the next start can skip the whole replay.
            self._save_mmr_state()
            with self._sync_lock:
                if self._wal_handle is not None:
                    try:
                        self._wal_handle.flush()
                        self._fsync(self._wal_handle.fileno())
                    except OSError as exc:
                        # Still swallowed for the caller: close() must release
                        # the handle even when the final flush fails, or it
                        # leaks the descriptor and the WAL lock with it. But the
                        # group-commit engine is told, so any commit still
                        # waiting on this fsync fails closed instead of being
                        # released against a write that never landed.
                        self._commit_engine.fail(exc)
                    else:
                        self._commit_engine.note_external_sync()
                    _unlock_wal_fd(self._wal_handle.fileno())
                    self._wal_handle.close()
                    self._wal_handle = None

    # ── Context manager ────────────────────────────────────────────────────

    def __enter__(self) -> CryptographicAuditLedger:
        # FIX-CAL-01: _open_wal() is idempotent; if already open from __init__
        # this is a no-op.
        with self._lock:
            self._open_wal()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # ── Private helpers ────────────────────────────────────────────────────

    def _open_wal(self) -> None:
        """Open the WAL append handle if not already open.

        FIX-CAL-01: called from __init__ so _persist_node always uses the
        persistent handle rather than opening a new fd per write.
        Idempotent: no-op if _wal_handle is already set.
        Must be called under self._lock when invoked from __enter__.
        """
        if self._wal_handle is not None:
            return
        try:
            os.makedirs(os.path.dirname(os.path.abspath(self.persistence_path)), exist_ok=True)
            # Create with owner-only permissions (0o600): the WAL holds forensic
            # audit metadata (tenant_id, model, request/response hashes, sampling
            # params). umask-default modes can leave it group/other-readable.
            fd = os.open(
                self.persistence_path,
                os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                0o600,
            )
            # WAL-02: exactly one writer per WAL path. Acquire before the
            # handle is published so a losing writer never appends a frame.
            try:
                _lock_wal_fd(fd, self.persistence_path)
            except WalWriterConflictError:
                os.close(fd)
                raise
            # Tighten a pre-existing WAL whose mode predates this hardening.
            try:
                os.chmod(self.persistence_path, 0o600)
            except OSError:
                # Swallowed deliberately: tightening a pre-existing WAL's mode
                # is opportunistic. A filesystem that refuses chmod (a mounted
                # share, a foreign owner) must not stop the ledger opening; the
                # descriptor is already open with the mode os.open granted.
                pass
            self._wal_handle = os.fdopen(fd, "a")
            # Track the on-disk size of the active segment so rotation can be
            # triggered without an fstat() on every write.
            try:
                self._wal_bytes = os.path.getsize(self.persistence_path)
            except OSError:
                self._wal_bytes = 0
            logger.debug("WAL handle opened: %s", self.persistence_path)
        except OSError as exc:
            logger.error(
                "Failed to open WAL at %s: %s — writes will fall back to per-commit open()",
                self.persistence_path,
                exc,
            )

    def _segment_paths(self) -> list[str]:
        """Return archived WAL segment paths in ascending sequence order.

        Segments are immutable forensic archives produced by rotation, named
        ``<persistence_path>.NNNNNN`` (zero-padded sequence). The active WAL
        itself (no numeric suffix) is never included.
        """
        prefix = os.path.basename(self.persistence_path) + "."
        directory = os.path.dirname(os.path.abspath(self.persistence_path))
        segments: list[tuple[int, str]] = []
        try:
            names = os.listdir(directory)
        except OSError:
            return []
        for name in names:
            if not name.startswith(prefix):
                continue
            suffix = name[len(prefix) :]
            if suffix.isdigit():
                segments.append((int(suffix), os.path.join(directory, name)))
        segments.sort(key=lambda t: t[0])
        return [p for _, p in segments]

    def _next_segment_seq(self) -> int:
        """Next archive sequence number (1-based, monotonically increasing)."""
        existing = self._segment_paths()
        if not existing:
            return 1
        return int(existing[-1].rsplit(".", 1)[1]) + 1

    def _rotate_wal(self) -> None:
        """Archive the active WAL into an immutable segment and open a fresh one.

        Must be called under ``self._lock``. Forensic invariant: rotation never
        drops nodes — every committed record is preserved in an archived
        segment (0o600) and replayed on the next startup. Failures degrade
        gracefully: the ledger keeps writing to the current/active WAL.

        Takes ``_sync_lock`` for its whole body, because it is the one thing
        that replaces the descriptor a group-commit syncer may be inside an
        ``fsync`` on.
        """
        with self._sync_lock:
            self._rotate_wal_locked()

    def _rotate_wal_locked(self) -> None:
        """Body of :meth:`_rotate_wal`, with ``_sync_lock`` already held."""
        # Checkpoint the accumulator at the rotation boundary. The leaves it
        # summarises are the ones about to move into the archived segment, so
        # a restart replays only what was written after this point.
        self._save_mmr_state()

        # Flush + fsync + close so the segment is fully durable before rename.
        if self._wal_handle is not None:
            try:
                self._wal_handle.flush()
                self._fsync(self._wal_handle.fileno())
            except OSError as exc:
                # Rotation itself still proceeds — abandoning it would leave the
                # active WAL growing past its threshold — but the failure is NOT
                # swallowed any more. This fsync is what would have made every
                # pending group-commit ticket durable, so if it failed those
                # records are not on the disk and their commits must not be
                # allowed to report success.
                self._commit_engine.fail(exc)
                logger.error(
                    "WAL rotation could not fsync the outgoing segment (%s); "
                    "pending commits will fail closed",
                    exc,
                )
            else:
                # The outgoing segment is on stable storage, and with it every
                # record written to this descriptor. Waiters can go.
                self._commit_engine.note_external_sync()
            # Release before the rename: on Windows the lock is mandatory and
            # the same process is about to reopen this path.
            _unlock_wal_fd(self._wal_handle.fileno())
            self._wal_handle.close()
            self._wal_handle = None

        if not os.path.exists(self.persistence_path):
            self._wal_bytes = 0
            self._open_wal()
            return

        seq = self._next_segment_seq()
        segment_path = f"{self.persistence_path}.{seq:06d}"
        try:
            os.rename(self.persistence_path, segment_path)
            try:
                os.chmod(segment_path, 0o600)
            except OSError:
                # Swallowed deliberately: the segment inherits the active WAL's
                # 0o600 through the rename, so this only re-asserts it. Failing
                # rotation over it would be worse than the mode it cannot fix.
                pass
            logger.info("Rotated WAL into archived segment %s", segment_path)
        except OSError as exc:
            logger.error("WAL rotation failed (%s) — continuing on active WAL", exc)
            self._open_wal()
            return

        self._wal_bytes = 0
        self._open_wal()

    def _sign_bound(
        self, build_payload: Callable[[str], bytes]
    ) -> tuple[str, str, str, bool, bytes]:
        """Select a tier, bind its scheme into the payload, then sign it.

        Returns ``(signature_hex, pubkey_hex, scheme, is_fallback, signed_payload)``.

        AUD-27's shape: the tier is chosen **before** the bytes exist, and the
        payload is rebuilt for each attempt with that attempt's own scheme
        appended, so the label the node records is the label that was signed
        over. The previous shape signed once and learned the scheme as the
        *result*, which left the label authenticated only by the shape of the
        material beside it — a relabel inside one shape class (the presence-only
        tiers ``pqc-ml-dsa`` / ``pkcs11-*``) changed which verifier was consulted
        and nothing else.

        The cost of building per attempt is a handful of string joins; the cost
        of an HSM fallback is one extra call, and it is bounded by the tier order
        below, which is unchanged (highest security first):

        1. HSM/PKCS#11: key never leaves the token boundary. Its label is read
           from the key type before signing (``scheme_label``); a backend that
           cannot answer falls back to signing once to learn it and signs again
           over the labelled payload, so the security property never depends on
           the backend's introspection.
        2. PQC ML-DSA under a configured persistent identity.
        3. HMAC-SHA256 with the ledger's signing key.
        4. Ed25519 ephemeral fallback (flagged; non-verifiable across restarts).

        ``build_payload`` raises ``ValueError`` for a label outside the closed
        vocabulary; that happens only when a tier reports a label this build does
        not know how to check, which is a bug in that tier, not input to accept.
        """
        # ── 1. HSM/PKCS#11 path ───────────────────────────────────────────
        if self._hsm_backend and self._hsm_backend.available:
            try:
                scheme = self._hsm_label_or_empty()
                if scheme:
                    payload = build_payload(scheme)
                    sig_bytes, pub_hex, reported = self._hsm_backend.sign(payload)
                    if reported != scheme:
                        # The token answered with a different label than its key
                        # type predicted; the payload must be rebuilt over what it
                        # actually produced, or the binding would be wrong.
                        payload = build_payload(reported)
                        sig_bytes, pub_hex, reported = self._hsm_backend.sign(payload)
                    return sig_bytes.hex(), pub_hex, reported, False, payload
                # No introspection: sign once to learn the label, then sign the
                # labelled payload. The first signature is discarded unread.
                # No introspection: sign once to learn the label, then sign the
                # labelled payload. The first signature is discarded unread, and
                # the label is remembered so the extra call happens at most once
                # per ledger, not once per record.
                probe = build_payload("")
                _sig, _pub, reported = self._hsm_backend.sign(probe)
                self._hsm_learned_scheme = reported
                payload = build_payload(reported)
                sig_bytes, pub_hex, reported = self._hsm_backend.sign(payload)
                return sig_bytes.hex(), pub_hex, reported, False, payload
            except HSMUnavailableError as exc:
                logger.warning("HSM signing failed (%s); falling back to next tier", exc)
            except ValueError as exc:
                logger.warning("HSM reported an unknown scheme (%s); falling back", exc)

        # ── 2. ML-DSA path, under a *persistent* identity ──────────────────
        #
        # This tier used to call ``generate_pqc_keypair()`` on every commit and
        # discard the private half immediately. Each node was therefore signed
        # by a different, one-shot identity that nobody holds, which is not a
        # signature in any useful sense: it attributes nothing, links nothing,
        # and cannot be checked against a published key. It also put an ML-DSA
        # keygen on the commit path.
        #
        # The tier now runs only when an operator has configured an identity to
        # sign under. Without one there is nothing to attribute to, so it falls
        # through to HMAC rather than minting a key per signature.
        signer = self._pqc_signer()
        if signer is not None:
            try:
                payload = build_payload("pqc-ml-dsa")
                sig_bytes = bytes(signer.sign(payload))
                pub_bytes: bytes = signer.public_key
                return sig_bytes.hex(), pub_bytes.hex(), "pqc-ml-dsa", False, payload
            except ValueError:
                raise
            except Exception as exc:
                logger.warning("ML-DSA signing failed (%s); falling back", exc)

        # ── 3. HMAC-SHA256 path ───────────────────────────────────────────
        if self._signing_key:
            payload = build_payload("hmac-sha256")
            return _hmac_sign(self._signing_key, payload), "", "hmac-sha256", False, payload

        # ── 4. Ed25519 ephemeral fallback ─────────────────────────────────
        if self._require_strong_signing:
            raise RuntimeError("strong signing required; no verifiable signer is available")
        payload = build_payload("ed25519-fallback")
        sig_hex, pub_hex, scheme = _ed25519_sign(payload)
        return sig_hex, pub_hex, scheme, True, payload

    def _hsm_label_or_empty(self) -> str:
        """The HSM tier's scheme label before signing, or ``""`` if unanswerable.

        ``""`` is not a downgrade: it means the backend cannot resolve its key
        type up front, and :meth:`_sign_bound` then learns the label from a
        signature instead of assuming one. A backend that answers must answer
        with a label this build knows, or the binding refuses it.
        """
        if self._hsm_learned_scheme:
            return self._hsm_learned_scheme
        getter = getattr(self._hsm_backend, "scheme_label", None)
        if getter is None:
            return ""
        try:
            label = str(getter() or "")
        except HSMUnavailableError:
            raise
        except Exception as exc:
            logger.warning("HSM scheme lookup failed (%s)", type(exc).__name__)
            return ""
        if label and label not in _SCHEME_MATERIAL:
            logger.warning("HSM reported an unknown scheme %r; learning it by signing", label)
            return ""
        return label

    def _payload_digest(self, data: bytes, subject_id: str) -> str:
        """Digest a request or response body for storage on the node.

        With shredding off this is the plain ``SHA-256`` every existing
        deployment has written, and nothing about those chains changes.

        With it on the digest is keyed to the subject (`REG-012`): a plain hash
        survives ``crypto_shred`` and still answers "was the erased content
        this?" for any guessable plaintext, which makes the envelope encryption
        beside it much weaker than it looks. The keyed digest dies with the key.
        """

        if self._shredder is None or not subject_id:
            return sha256_hex(data)
        return self._shredder.digest(subject_id, data)

    def _seal_leaf(self, leaf: bytes, subject_id: str) -> tuple[str, SealedPayload | None]:
        """Return ``(leaf_digest, sealed)`` for one commit.

        With shredding off this is the accumulator's own leaf digest and no
        envelope, which is the behaviour every existing deployment has.

        With it on, the leaf — which carries the request and response previews,
        the actual content — is encrypted under the subject's key and the MMR
        commits to ``SHA-256(0x00 || nonce || ciphertext)`` instead. That
        commitment is computable by anyone holding the ciphertext and **not**
        the key, which is exactly what lets an inclusion proof keep verifying
        after the key is destroyed: erasure removes the ability to read the
        leaf, and moves no hash the tree is built from.
        """

        if self._shredder is None:
            return self._mmr.leaf_digest(leaf), None
        sealed = self._shredder.seal(subject_id, leaf)
        return sealed.commitment_hex, sealed

    def crypto_shred(self, subject_id: str) -> bool:
        """Destroy ``subject_id``'s key. Returns whether one was present.

        The ledger does not move: every root, peak, node hash and previously
        issued inclusion proof is bit-for-bit what it was. What changes is that
        the sealed leaves for this subject can no longer be opened.

        What this establishes, and only this: the sealed leaf content is
        unrecoverable **to a holder of the ciphertext alone**, at the strength
        of AES-256-GCM. It is not a media-sanitisation guarantee — see the
        :mod:`aegis.core.crypto_shredder` docstring on pages, journals, swap,
        snapshots, backups and replicas, none of which are under this process's
        control — and it does not erase the request and response *digests* the
        node still carries. Those are not plaintext, but they are not nothing
        either: a guessed plaintext can be confirmed against them, so a
        low-entropy input is not protected by their presence being hashed.
        Whether that satisfies a specific regulator is a legal question this
        code does not answer.
        """

        if self._shredder is None:
            raise RuntimeError(
                "cryptographic shredding is not enabled on this ledger; construct it with "
                "enable_cryptographic_shredding=True (AEGIS_ENABLE_CRYPTOGRAPHIC_SHREDDING)"
            )
        with self._lock:
            return self._shredder.erase(subject_id)

    def open_sealed_leaf(self, node: AuditNode) -> bytes:
        """Decrypt the sealed leaf a node commits to.

        Raises ``ShredderKeyDestroyedError`` once the subject has been shredded,
        which is the observable difference erasure makes.
        """

        if self._shredder is None:
            raise RuntimeError("cryptographic shredding is not enabled on this ledger")
        if not node.sealed_ciphertext:
            raise ValueError(f"node {node.state_id!r} carries no sealed envelope")
        with self._lock:
            return self._shredder.open(
                SealedPayload(
                    subject_id=node.sealed_subject_id,
                    nonce=bytes.fromhex(node.sealed_nonce),
                    ciphertext=bytes.fromhex(node.sealed_ciphertext),
                )
            )

    def _pqc_signer(self) -> PQCSigner | None:
        """The ML-DSA identity this ledger signs under, or ``None``.

        ``None`` means the ML-DSA tier is skipped — no identity is configured,
        the backend is absent, or the stored identity could not be loaded. A
        one-shot keypair is never minted as a substitute: a signature under a
        key that is discarded immediately attributes nothing, and emitting one
        under the ``pqc-ml-dsa`` scheme label would misrepresent what the node
        carries.

        The identity is created on first use if the configured path does not
        exist yet, and reused from then on. Creating it here rather than
        requiring a separate provisioning step is what makes the tier usable;
        the file holds the raw ML-DSA-65 private key, so it needs the same
        custody as any other signing secret and must live on storage the
        operator controls. One created here is written ``0600``; one provisioned
        elsewhere is *checked* rather than trusted, and refused if its mode lets
        group or other read it.
        """

        if self._pqc_identity is not False:
            return self._pqc_identity

        self._pqc_identity = None
        if not self.pqc_identity_path:
            return None
        if not pqc_backend_available():
            logger.warning(
                "AEGIS_PQC_IDENTITY_PATH is set but no ML-DSA backend is available; "
                "signing falls through to the next tier"
            )
            return None

        path = Path(self.pqc_identity_path)
        try:
            signer = self._load_pqc_identity(path)
            if signer is None:
                signer = self._create_pqc_identity(path)
        except (PQCUnavailableError, OSError, TypeError, ValueError) as exc:
            logger.warning(
                "ML-DSA identity at %s unusable (%s); signing falls through to the next tier",
                path,
                exc,
            )
            return None

        self._pqc_identity = signer
        return signer

    @staticmethod
    def _load_pqc_identity(path: Path) -> PQCSigner | None:
        """Load the identity at ``path``, or ``None`` if there is no file there.

        Refuses a file the operating system is showing to anyone but its owner.
        The tier's whole value is that a signature attributes to a held key, and
        a key readable by every account on the host attributes to all of them —
        so a permissive mode is rejected rather than quietly tightened. Tightening
        would not un-expose a key that has already been readable, and it would
        hide the provisioning mistake that made it so. Rejection is loud and
        leaves signing on HMAC, which is a weaker claim and a true one.
        """

        try:
            info = path.stat()
        except FileNotFoundError:
            return None
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("identity path is not a regular file")
        if info.st_mode & 0o077:
            raise ValueError(
                f"identity file mode is {stat.filemode(info.st_mode)} "
                f"({info.st_mode & 0o777:04o}); it must not be readable by group or other"
            )

        raw = path.read_bytes()
        expected = PQCSigner.PUBLIC_KEY_BYTES + PQCSigner.PRIVATE_KEY_BYTES
        if len(raw) != expected:
            raise ValueError(
                f"identity file holds {len(raw)} bytes; expected {expected} "
                f"({PQCSigner.PUBLIC_KEY_BYTES}-byte public + "
                f"{PQCSigner.PRIVATE_KEY_BYTES}-byte private key)"
            )
        signer = PQCSigner.from_keys(
            raw[: PQCSigner.PUBLIC_KEY_BYTES], raw[PQCSigner.PUBLIC_KEY_BYTES :]
        )
        logger.info("Loaded persistent ML-DSA signing identity from %s", path)
        return signer

    def _create_pqc_identity(self, path: Path) -> PQCSigner:
        """Create the identity at ``path``, or adopt the one that beat us to it.

        Two processes pointed at one identity path will both find it absent and
        both generate a keypair — ML-DSA keygen is slow enough to hold that
        window wide open. Whoever publishes second must therefore *discard* what
        it generated and sign under what is on disk, or its nodes carry a
        ``pqc-ml-dsa`` public key that exists nowhere and attributes to nobody:
        precisely the defect the persistent identity was introduced to fix.

        So publication is a create-if-absent, not a replace. The bytes are
        written to a *uniquely named* private temporary file and linked into
        place; ``os.link`` fails rather than overwriting when the target exists,
        which makes the winner unambiguous without a lock. A per-process
        temporary name matters as much as the atomic publish: a shared one lets
        a second writer truncate the file the first is still writing and then
        consume it, leaving the first to fail on a path that has vanished.
        """

        signer = PQCSigner(require_real=True)
        path.parent.mkdir(parents=True, exist_ok=True)
        material = signer.public_key + signer.export_private_key()
        # Created 0600 rather than chmod-ed after the bytes are on disk, so the
        # private key is never momentarily world-readable.
        temporary = path.with_name(f"{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
        try:
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(material)
                handle.flush()
                self._fsync(handle.fileno())
            try:
                os.link(temporary, path)
            except FileExistsError:
                adopted = self._load_pqc_identity(path)
                if adopted is None:  # pragma: no cover - the file cannot vanish here
                    raise
                logger.info(
                    "Another writer created the ML-DSA identity at %s first; "
                    "adopting it and discarding the keypair generated here",
                    path,
                )
                return adopted
            logger.info("Created persistent ML-DSA signing identity at %s", path)
            return signer
        finally:
            try:
                os.unlink(temporary)
            except OSError:  # pragma: no cover - best-effort cleanup
                logger.debug("Could not remove temporary identity file %s", temporary)

    def _persist_node(self, node: AuditNode) -> int | None:
        """Append node as a JSON line to the WAL. Must be called under self._lock.

        Writes and flushes, but does **not** ``fsync``. The record is in the
        operating system's hands and correctly ordered against every other
        record, and is not yet on stable storage — so this returns a
        group-commit ticket, and the caller must pass it to
        :meth:`_await_durable` *after releasing the lock* before reporting the
        node as committed. Splitting it that way is the whole point: it lets one
        ``fsync`` retire every record written while it was in flight, instead of
        charging each request a separate device round trip inside the lock.

        Returns:
            A ticket for :meth:`_await_durable`, or ``None`` when the record was
            already made durable inline (the handle-less fallback path below).
        """
        line = json.dumps(node.to_dict(), separators=(",", ":"), allow_nan=False) + "\n"
        nbytes = len(line.encode("utf-8"))
        ticket: int | None = None
        if self._wal_handle is not None:
            self._wal_handle.write(line)
            self._wal_handle.flush()
            ticket = self._commit_engine.enqueue()
            self._wal_bytes += nbytes
        else:
            # Safety fallback: _open_wal() failed at init time.
            try:
                os.makedirs(os.path.dirname(os.path.abspath(self.persistence_path)), exist_ok=True)
            except OSError:
                # Swallowed deliberately: this is already the fallback path for
                # an _open_wal that failed. The os.open below is what decides
                # whether the write can proceed, and it raises with the real
                # errno; pre-empting it here would report a worse one.
                pass
            # Owner-only perms here too (mirrors _open_wal); the fallback path
            # must not widen the WAL's mode.
            fd = os.open(
                self.persistence_path,
                os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                0o600,
            )
            with os.fdopen(fd, "a") as f:
                f.write(line)
                f.flush()
                self._fsync(f.fileno())
            try:
                self._wal_bytes = os.path.getsize(self.persistence_path)
            except OSError:
                self._wal_bytes += nbytes

        # Rotate AFTER the node's bytes are in the file: the just-written record
        # is safely inside the segment that gets archived, so no node is ever in
        # flight during the rename. Rotation flushes and fsyncs the outgoing
        # segment before closing it, which is what makes every pending ticket
        # durable — `_rotate_wal` tells the engine so, and the ticket returned
        # here then resolves without a second sync.
        if self.max_wal_bytes > 0 and self._wal_bytes >= self.max_wal_bytes:
            self._rotate_wal()
        return ticket

    def _sync_wal(self) -> None:
        """Force the WAL to stable storage. The group-commit engine's syncer.

        Runs with the ledger lock released, so it takes ``_sync_lock`` to stop
        a rotation from closing the descriptor mid-``fsync``.

        No flush here: writers flush under the ledger lock, so by the time a
        ticket exists its bytes are already with the kernel. ``fsync`` on the
        descriptor then covers every record written to it, which is exactly the
        property the batching rests on.
        """
        with self._sync_lock:
            handle = self._wal_handle
            if handle is None or handle.closed:
                # The only thing that replaces the handle is rotation, and it
                # flushes and fsyncs the outgoing segment first. Anything this
                # batch wrote is therefore already durable in that segment;
                # there is nothing left here to force.
                return
            self._fsync(handle.fileno())

    def _await_durable(self, ticket: int | None) -> None:
        """Block until a ticketed record is on stable storage.

        Must be called with the ledger lock **released**.

        A failure here poisons the ledger rather than unwinding one node. The
        batch that failed may hold records from several concurrent commits, and
        later nodes have already linked against this one, so there is no single
        node to roll back to a consistent state. Latching
        ``wal_persist_failed`` is what the proxy's ``_require_intact_ledger``
        already reads to answer 503 and stop extending the chain.
        """
        if ticket is None:
            return
        try:
            self._commit_engine.await_durable(ticket, self._sync_wal)
        except WalDurabilityError:
            with self._lock:
                self._fault_state = "wal_persist_failed"
            raise

    @property
    def group_commit_stats(self) -> GroupCommitStats:
        """How well concurrent commits are coalescing onto single ``fsync``s."""
        return self._commit_engine.stats

    # ── MMR peak-set checkpoint ────────────────────────────────────────────
    #
    # The JSONL WAL is authoritative and always sufficient on its own: every
    # committed node carries its leaf hash, and replaying them rebuilds the
    # accumulator exactly. This file is a pure optimisation over that replay
    # and is never trusted beyond what the WAL independently confirms — the
    # restored root must equal the root the last committed node recorded, or
    # the checkpoint is discarded and the full replay runs. A missing, stale,
    # truncated, corrupt or mismatched checkpoint is therefore never an error.

    def _mmr_state_path(self) -> str:
        """Path of the peak-set checkpoint beside the active WAL.

        ``persistence_path`` is annotated ``str`` but callers pass ``Path`` too,
        and every other use here goes through ``os.path``, which accepts both.
        ``os.fspath`` keeps that tolerance; plain concatenation would not.
        """
        return os.fspath(self.persistence_path) + ".mmr.state"

    def _mmr_state_body(self) -> dict[str, Any]:
        """Checksummed fields of the checkpoint. Must be called under the lock."""
        ordered_peaks = sorted(self._mmr.peaks, key=lambda peak: peak.height, reverse=True)
        return {
            "version": _MMR_STATE_VERSION,
            "leaf_count": self._mmr.get_leaf_count(),
            "peaks": [{"height": peak.height, "hash": peak.hash} for peak in ordered_peaks],
            "bagged_root": self._mmr.get_root_hash(),
        }

    def _save_mmr_state(self, path: str | None = None) -> bool:
        """Atomically write the peak-set checkpoint. Must be called under the lock.

        Never raises: the checkpoint is an optimisation, and a ledger that
        could not write one is still fully correct — it simply replays on the
        next start. Returns whether the file was written.
        """
        target = path or self._mmr_state_path()
        try:
            body = self._mmr_state_body()
            if int(body["leaf_count"]) < 1:
                # Nothing to summarise. Remove any earlier checkpoint rather
                # than leaving one that outlives the leaves it described.
                try:
                    os.unlink(target)
                except FileNotFoundError:
                    # Swallowed deliberately: no checkpoint to remove is the
                    # desired end state, which is what this branch is for.
                    pass
                return False
            document = {
                **body,
                "state_checksum": sha256_hex(canonical_jcs_bytes(body)),
            }
            payload = canonical_jcs_bytes(document)
            tmp = target + ".tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
                handle.flush()
                self._fsync(handle.fileno())
            os.replace(tmp, target)
            # A rename is only durable once the directory entry is synced.
            dir_fd = os.open(os.path.dirname(os.path.abspath(target)), os.O_RDONLY)
            try:
                self._fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except (OSError, ValueError, TypeError) as exc:
            logger.warning("could not write MMR checkpoint %s: %s", target, exc)
            return False
        return True

    def _load_mmr_state(self, path: str | None = None) -> tuple[int, list[MMRPeak]] | None:
        """Read and validate the peak-set checkpoint, or return None.

        Returns None for every failure mode — absent, unreadable, malformed,
        wrong version, or failing its own checksum — because each has the same
        remedy: replay the WAL.
        """
        target = path or self._mmr_state_path()
        try:
            with open(target, "rb") as handle:
                document = json.loads(handle.read().decode("utf-8"))
        except FileNotFoundError:
            return None
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            logger.warning("MMR checkpoint %s unreadable (%s) — replaying WAL", target, exc)
            return None

        if not isinstance(document, dict):
            logger.warning("MMR checkpoint %s is not an object — replaying WAL", target)
            return None
        recorded_checksum = document.get("state_checksum")
        body = {key: value for key, value in document.items() if key != "state_checksum"}
        try:
            if body.get("version") != _MMR_STATE_VERSION:
                logger.warning(
                    "MMR checkpoint %s version %r unsupported — replaying WAL",
                    target,
                    body.get("version"),
                )
                return None
            if recorded_checksum != sha256_hex(canonical_jcs_bytes(body)):
                logger.warning("MMR checkpoint %s failed its checksum — replaying WAL", target)
                return None
            leaf_count = body["leaf_count"]
            raw_peaks = body["peaks"]
            if not isinstance(leaf_count, int) or isinstance(leaf_count, bool):
                raise TypeError("leaf_count must be an integer")
            if not isinstance(raw_peaks, list):
                raise TypeError("peaks must be a list")
            peaks = [
                MMRPeak(height=int(entry["height"]), hash=str(entry["hash"])) for entry in raw_peaks
            ]
        except (KeyError, TypeError, ValueError) as exc:
            logger.warning("MMR checkpoint %s malformed (%s) — replaying WAL", target, exc)
            return None
        return leaf_count, peaks

    def _restore_mmr(self, portable_suffix: list[tuple[str, str, str]]) -> None:
        """Rebuild the accumulator for the replayed leaves, fastest path first.

        ``portable_suffix`` is the contiguous trailing run of committed nodes
        that carry a portable MMR leaf, oldest first, as
        ``(leaf_hash, recorded_root, state_id)``.

        The checkpoint, when it validates, replaces the first ``leaf_count``
        of those appends with one O(log N) restore; any leaves committed after
        it — the ordinary case after a crash, and after a rotation — are then
        replayed on top. The result is accepted only if the final root equals
        the root the last committed node recorded. Anything else falls back to
        replaying every leaf, which is the behaviour that predates this file.

        **Opt-in, and off by default.** Restoring from peaks discards the
        interior nodes of the leaves it summarises, so their inclusion proofs
        can no longer be *derived in memory* — ``get_inclusion_proof`` raises
        ``MMRHistoricalLeafUnavailableError`` for them. Full replay keeps that
        capability, and ``tests/test_mmr_restart.py`` asserts it deliberately:
        proving every historical leaf is a stronger structural check on a
        reconstructed accumulator than root equality alone, because the right
        peaks can be reached with the wrong interior shape.

        Nothing forensic is lost either way — every committed node stores its
        own self-contained ``mmr_proof``, and the ledger only ever asks the
        live accumulator to prove the leaf it just appended. The trade is
        startup cost against in-memory historical proofs, and it is the
        operator's to make, so it is taken only when ``mmr_fast_restore=True``
        was passed. The checkpoint file is written regardless, so enabling the
        flag needs no migration.
        """
        # A chain's hash scheme decides every root it has recorded. Reopening a
        # v1 chain as v2 would replay every leaf to a different root, and the
        # integrity check would report the chain corrupt — a true statement
        # about the wrong thing, and an alarming one for evidence that is
        # actually intact. Recognise the misconfiguration by name instead, and
        # do it before replay so the diagnosis is the cause rather than the
        # symptom. There is no in-place upgrade: a scheme change means a new
        # chain, because a root cannot be recomputed under a different
        # construction without rewriting history.
        #
        # Unless the caller left the scheme on ``auto``, in which case there is
        # no misconfiguration to report: the chain names its own construction
        # and this ledger adopts it. That is what lets the new-chain default
        # move to v2 without refusing to open the chains already in the field.
        if not self._scheme_pinned and self._wal_proof_version is not None:
            adopted = _PROOF_VERSION_SCHEMES.get(self._wal_proof_version)
            if adopted is None:
                logger.error(
                    "WAL records MMR proof version %s, which this build does not implement",
                    self._wal_proof_version,
                )
                self._fault_state = "mmr_scheme_mismatch"
                return
            if adopted != self.mmr_hash_scheme:
                logger.info("Adopting the MMR scheme this chain was written under: %s", adopted)
                self.mmr_hash_scheme = adopted
                self._mmr = MerkleMountainRange(hash_scheme=adopted)

        expected_version = _SCHEME_PROOF_VERSIONS[self.mmr_hash_scheme]
        if self._wal_proof_version is not None and self._wal_proof_version != expected_version:
            logger.error(
                "WAL was written under MMR proof version %s but this ledger is configured for "
                "%s (%s). A chain cannot change hash scheme in place; start a new chain or "
                "reopen with the scheme it was written under.",
                self._wal_proof_version,
                expected_version,
                self.mmr_hash_scheme,
            )
            self._fault_state = "mmr_scheme_mismatch"
            return

        if not portable_suffix:
            return

        expected_root = portable_suffix[-1][1]
        checkpoint = self._load_mmr_state() if self._mmr_fast_restore else None
        if checkpoint is not None:
            leaf_count, peaks = checkpoint
            if 0 < leaf_count <= len(portable_suffix):
                try:
                    self._mmr.restore_from_peaks(leaf_count=leaf_count, peaks=peaks)
                    for leaf_hash, _, _ in portable_suffix[leaf_count:]:
                        self._mmr.add_leaf_hash(leaf_hash)
                except ValueError as exc:
                    logger.warning("MMR checkpoint rejected (%s) — replaying WAL", exc)
                else:
                    if self._mmr.get_root_hash() == expected_root:
                        logger.info(
                            "MMR restored from checkpoint: %d peaks summarise %d leaves, "
                            "%d replayed",
                            len(peaks),
                            leaf_count,
                            len(portable_suffix) - leaf_count,
                        )
                        return
                    logger.warning(
                        "MMR checkpoint root disagrees with the WAL — replaying every leaf"
                    )
                # Discard whatever the rejected fast path built.
                self._mmr = MerkleMountainRange(hash_scheme=self.mmr_hash_scheme)
            elif leaf_count > len(portable_suffix):
                logger.warning(
                    "MMR checkpoint describes %d leaves but the WAL holds %d — replaying WAL",
                    leaf_count,
                    len(portable_suffix),
                )

        for leaf_hash, recorded_root, state_id in portable_suffix:
            rebuilt_root = self._mmr.add_leaf_hash(leaf_hash)
            if rebuilt_root != recorded_root:
                logger.error("portable MMR replay root mismatch at state_id=%s", state_id)
                self._fault_state = "mmr_replay_mismatch"
                return

    def _load_from_wal(self) -> None:
        # Replay archived segments (oldest first) then the active WAL so the
        # full chain is reconstructed across any number of rotations.
        files = self._segment_paths()
        if os.path.exists(self.persistence_path):
            files.append(self.persistence_path)

        if not files:
            logger.info("No WAL found at %s — starting fresh.", self.persistence_path)
            return

        count = 0
        stop = False
        portable_suffix: list[tuple[str, str, str]] = []
        for path in files:
            logger.info("Reconstructing ledger from %s", path)
            with open(path) as f:
                for lineno, raw in enumerate(f, 1):
                    raw = raw.strip()
                    if not raw:
                        continue
                    try:
                        data = json.loads(raw)
                        node = AuditNode.from_dict(data)
                        if isinstance(node.mmr_proof, dict):
                            recorded = node.mmr_proof.get("version")
                            if isinstance(recorded, str):
                                self._wal_proof_version = recorded
                        if node.mmr_leaf_hash:
                            portable_suffix.append(
                                (node.mmr_leaf_hash, node.merkle_root, node.state_id)
                            )
                        else:
                            portable_suffix.clear()
                        self._append_memory_node(node)
                        count += 1
                    except (json.JSONDecodeError, TypeError, KeyError) as exc:
                        logger.error(
                            "WAL %s line %d corrupt (%s) — stopping reconstruction.",
                            path,
                            lineno,
                            exc,
                        )
                        self._fault_state = "wal_corrupt"
                        stop = True
                        break
            if stop:
                break

        logger.info("Reconstructed %d nodes from WAL.", count)
        self._restore_mmr(portable_suffix)


# ── Compat shims kept for import compatibility ────────────────────────────────


@dataclass
class PQCSignatureAnchor:
    """Shim retained for import compatibility with existing code."""

    public_key: bytes
    algorithm: str = "HMAC-SHA256"

    def verify(self, data: bytes, signature: bytes) -> bool:  # noqa: ARG002
        return False  # Stateless anchor without key material is unverifiable

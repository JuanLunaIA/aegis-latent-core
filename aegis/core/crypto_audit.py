"""
aegis.core.crypto_audit — Cryptographic audit ledger with Merkle chain-of-custody.

Architecture:
  - CryptographicAuditLedger: append-only Merkle chain backed by WAL.
  - AuditNode: immutable record with forensic fields, HMAC/PQC signature,
    and a computed node_hash linking the chain.
  - Signing: HMAC-SHA256 when signing_key is provided; no legal conclusion is implied.
    PQC-ML-DSA via aegis_rust extension when available.
  - WAL: line-delimited JSON; crash-consistent via fsync after each write.
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
import os
import sys
import time
import uuid

try:  # POSIX advisory locking. Absent on Windows; see _lock_wal_fd.
    import fcntl
except ImportError:  # pragma: no cover - platform dependent
    fcntl = None  # type: ignore[assignment]
from collections import deque
from collections.abc import Callable
from dataclasses import asdict, dataclass
from threading import Lock
from typing import Any, TextIO

import numpy as np
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from aegis.core.forensic import build_merkle_leaf, build_stream_merkle_leaf, sha256_hex
from aegis.core.forensic_bundle import canonical_jcs_bytes
from aegis.core.hsm import HSMSigningBackend, HSMUnavailableError
from aegis.core.mmr import MerkleMountainRange, MMRInclusionProofV1, MMRPeak

logger = logging.getLogger(__name__)

MAX_PAYLOAD_BYTES: int = 1_048_576  # 1 MiB hard cap

# Schema version of the ``<wal>.mmr.state`` peak-set checkpoint. Bump only for
# an incompatible field change: an unrecognised version is ignored and the WAL
# is replayed, so a bump degrades performance rather than correctness.
_MMR_STATE_VERSION: int = 1
_DEFAULT_MAX_FORENSIC_BYTES: int = 65_536


class WalWriterConflictError(RuntimeError):
    """Another process already holds the append lock for this WAL path.

    Two processes appending to one WAL path produce divergent ``prev_hash``
    relationships that the loader cannot represent as a single verified chain.
    The topology is documented as unsupported; this exception makes it
    enforced rather than merely documented, so the fork cannot occur silently.
    """


def _lock_wal_fd(fd: int, path: str) -> None:
    """Take an exclusive, non-blocking advisory lock on an open WAL fd.

    The lock is released automatically when the descriptor is closed or the
    process exits, so a restart re-acquires it without operator action.

    On platforms without ``fcntl`` the guard cannot be enforced in-process and
    single-writer discipline remains an operator responsibility; that case is
    logged at warning level rather than failing open silently.
    """
    if fcntl is None:  # pragma: no cover - platform dependent
        logger.warning(
            "Advisory WAL locking is unavailable on %s; single-writer "
            "discipline for %s is operator-enforced, not process-enforced.",
            sys.platform,
            path,
        )
        return
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        raise WalWriterConflictError(
            f"WAL path is already locked by another writer: {path}. "
            "Exactly one process may append to a WAL path; concurrent writers "
            "fork the evidence chain."
        ) from exc


# ── Rust / PQC detection ──────────────────────────────────────────────────────
try:
    import aegis_rust  # type: ignore[import]

    RUST_AVAILABLE: bool = True
except ImportError:
    RUST_AVAILABLE = False
    logger.debug("aegis_rust extension not available; using HMAC-SHA256 signing")


# ── AuditNode ─────────────────────────────────────────────────────────────────


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
    signature_scheme: str  # "hmac-sha256" | "pqc-ml-dsa" | "ed25519-fallback"
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
        }
        # Remove legacy field if present
        data.pop("payload", None)
        merged = {**defaults, **data}
        # Keep only known fields to avoid TypeError on unexpected keys
        known = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in merged.items() if k in known}
        return cls(**filtered)


# ── Signing helpers ───────────────────────────────────────────────────────────


def _build_signed_payload(
    prev_hash: str,
    merkle_root: str,
    request_hash: str,
    response_hash: str,
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
    """
    return "|".join([prev_hash, merkle_root, request_hash, response_hash]).encode()


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
    WAL: each node is fsync'd before the in-memory chain is updated, ensuring
    no committed node is lost across crashes.

    Parameters
    ----------
    persistence_path : str
        Path to the WAL file (line-delimited JSON).
    signing_key : str
        HMAC-SHA256 signing key.  If non-empty, ``legal_admissibility`` is "High".
        If empty and RUST_AVAILABLE is False, the fallback ephemeral Ed25519 is
        used and admissibility drops to "Compromised".
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
    ) -> None:
        self.persistence_path = persistence_path
        self._signing_key = signing_key
        self._fsync = fsync_fn or os.fsync
        self._hsm_backend = hsm_backend
        self._require_strong_signing = require_strong_signing
        self.max_memory_nodes = max_memory_nodes
        self.max_forensic_bytes = max_forensic_bytes
        self.max_wal_bytes = max_wal_bytes
        self._mmr_fast_restore = mmr_fast_restore
        self.chain: deque[AuditNode] = deque(maxlen=max_memory_nodes)
        self._window_anchor_hash = "0" * 64
        self._lock = Lock()
        self._wal_handle: TextIO | None = None
        self._wal_bytes = 0
        self._fault_state: str = "healthy"
        self._mmr = MerkleMountainRange()
        self._load_from_wal()
        # FIX-CAL-01: open the WAL handle eagerly after reconstruction.
        # Previously the handle was only opened in __enter__ (context-manager
        # path).  In app.py the ledger is used directly, so _wal_handle was
        # always None and _persist_node opened+closed a new fd on every write.
        self._open_wal()

    # ── Public properties ──────────────────────────────────────────────────

    @property
    def legal_admissibility(self) -> str:
        if self._signing_key:
            return "High"
        if any(n.is_fallback for n in self.chain):
            return "Compromised"
        return "High"

    @property
    def archived_segments(self) -> list[str]:
        """Paths of rotated, immutable WAL archive segments (oldest first)."""
        with self._lock:
            return self._segment_paths()

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
            token_trail: Per-token logprob records for chain-of-custody.
            usage: OpenAI usage dict (prompt_tokens, completion_tokens, etc.).
            sampling_params: Temperature, top_p, etc.

        Returns:
            The committed AuditNode.

        Raises:
            ValueError: On invalid input (non-finite entropy, NULL in state_id, etc.).
        """
        if "\x00" in state_id:
            raise ValueError("state_id containing NULL byte is rejected")
        if not np.isfinite(entropy):
            raise ValueError("entropy must be a finite number")
        if len(request_bytes) > MAX_PAYLOAD_BYTES:
            raise ValueError("request_bytes exceeds 1 MiB hard cap")

        params = {**(sampling_params or {})}
        if usage:
            params["usage"] = usage

        req_hash = sha256_hex(request_bytes)
        resp_hash = sha256_hex(response_bytes) if response_bytes else ""

        # Build canonical MMR leaf
        leaf = build_merkle_leaf(
            state_id=state_id,
            request_bytes=request_bytes,
            response_bytes=response_bytes,
            model=model,
            endpoint=endpoint,
            max_bytes=self.max_forensic_bytes,
        )

        with self._lock:
            prev_hash = self.chain[-1].node_hash if self.chain else "0" * 64
            timestamp = time.time()
            # O(log n) rollback token, not a copy of the accumulator: this runs
            # on every commit, so a deep copy would make commit cost grow with
            # the length of the chain.
            mmr_before = self._mmr.checkpoint()
            merkle_root = self._mmr.add_leaf(leaf)
            mmr_leaf_count = self._mmr.get_leaf_count()
            mmr_leaf_index = mmr_leaf_count - 1
            mmr_leaf_hash = sha256_hex(leaf)
            mmr_proof = self._mmr.get_portable_inclusion_proof(mmr_leaf_index).to_dict()

            # Sign over prev_hash + merkle_root + request/response hashes so the
            # signature binds chain linkage, not merkle_root alone (see
            # _build_signed_payload).
            signed_payload = _build_signed_payload(
                prev_hash=prev_hash,
                merkle_root=merkle_root,
                request_hash=req_hash,
                response_hash=resp_hash,
            )
            try:
                signature, pub_key_hex, scheme, is_fallback = self._sign(signed_payload)
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
            )

            try:
                self._persist_node(node)
            except Exception:
                self._mmr.rollback_to(mmr_before)
                self._fault_state = "wal_persist_failed"
                raise
            self._append_memory_node(node)
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
        req_hash = sha256_hex(request_bytes)
        resp_hash = sha256_hex(decision)

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
            merkle_root = self._mmr.add_leaf(leaf)
            mmr_leaf_count = self._mmr.get_leaf_count()
            mmr_leaf_index = mmr_leaf_count - 1
            mmr_leaf_hash = sha256_hex(leaf)
            mmr_proof = self._mmr.get_portable_inclusion_proof(mmr_leaf_index).to_dict()

            signed_payload = _build_signed_payload(
                prev_hash=prev_hash,
                merkle_root=merkle_root,
                request_hash=req_hash,
                response_hash=resp_hash,
            )
            try:
                signature, pub_key_hex, scheme, is_fallback = self._sign(signed_payload)
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
            )

            try:
                self._persist_node(node)
            except Exception:
                self._mmr.rollback_to(mmr_before)
                self._fault_state = "wal_persist_failed"
                raise
            self._append_memory_node(node)
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
        request_bytes: bytes,
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
    ) -> AuditNode:
        """Commit one terminal record for an incrementally hashed response.

        The caller supplies the SHA-256 digest and bounded preview accumulated at
        the ASGI body-iterator boundary.  No full response is retained or reread.
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
        if "\x00" in state_id:
            raise ValueError("state_id containing NULL byte is rejected")
        if len(request_bytes) > MAX_PAYLOAD_BYTES:
            raise ValueError("request_bytes exceeds 1 MiB hard cap")
        if len(response_hash) != 64 or any(ch not in "0123456789abcdef" for ch in response_hash):
            raise ValueError("response_hash must be a lowercase SHA-256 hex digest")
        if response_size < 0 or token_count < 0:
            raise ValueError("response_size and token_count must be non-negative")
        if not np.isfinite(elapsed_seconds) or elapsed_seconds < 0:
            raise ValueError("elapsed_seconds must be finite and non-negative")
        if len(response_preview) > self.max_forensic_bytes:
            raise ValueError("response_preview exceeds max_forensic_bytes")
        if terminal_outcome not in allowed_outcomes:
            raise ValueError("unsupported terminal_outcome")
        hits = dict(redaction_hits or {})
        if any(not key or not isinstance(value, int) or value < 0 for key, value in hits.items()):
            raise ValueError("redaction_hits must contain non-negative integer counts")

        request_hash = sha256_hex(request_bytes)
        request_preview = request_bytes[: self.max_forensic_bytes]
        leaf = build_stream_merkle_leaf(
            state_id=state_id,
            request_hash=request_hash,
            response_hash=response_hash,
            request_size=len(request_bytes),
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
            "evidence_status": "durable-terminal",
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
            merkle_root = self._mmr.add_leaf(leaf)
            mmr_leaf_count = self._mmr.get_leaf_count()
            mmr_leaf_index = mmr_leaf_count - 1
            mmr_leaf_hash = sha256_hex(leaf)
            mmr_proof = self._mmr.get_portable_inclusion_proof(mmr_leaf_index).to_dict()
            signed_payload = _build_signed_payload(
                prev_hash=prev_hash,
                merkle_root=merkle_root,
                request_hash=request_hash,
                response_hash=response_hash,
            )
            try:
                signature, pub_key_hex, scheme, is_fallback = self._sign(signed_payload)
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
            )
            try:
                self._persist_node(node)
            except Exception:
                self._mmr.rollback_to(mmr_before)
                self._fault_state = "wal_persist_failed"
                raise
            self._append_memory_node(node)
            return node

    def verify_integrity(self) -> tuple[bool, int | None]:
        """O(N) full-chain integrity sweep.

        Checks:
        1. Each node's node_hash is self-consistent.
        2. Each node's prev_hash matches the preceding node's node_hash.
        3. HMAC signature is valid (when signing_key is set).

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
            if self._signing_key and node.signature_scheme == "hmac-sha256":
                payload = _build_signed_payload(
                    prev_hash=node.prev_hash,
                    merkle_root=node.merkle_root,
                    request_hash=node.request_hash,
                    response_hash=node.response_hash,
                )
                if not _hmac_verify(
                    self._signing_key,
                    payload,
                    node.signature,
                ):
                    logger.error("Integrity violation: node %d HMAC signature invalid", i)
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
        """Return ``valid``, ``invalid``, or ``unverified`` for one node."""
        payload = _build_signed_payload(
            prev_hash=node.prev_hash,
            merkle_root=node.merkle_root,
            request_hash=node.request_hash,
            response_hash=node.response_hash,
        )
        try:
            if node.signature_scheme == "hmac-sha256":
                if not self._signing_key:
                    return "unverified"
                return (
                    "valid"
                    if _hmac_verify(self._signing_key, payload, node.signature)
                    else "invalid"
                )
            if node.signature_scheme == "ed25519-fallback":
                public_key = ed25519.Ed25519PublicKey.from_public_bytes(
                    bytes.fromhex(node.public_key)
                )
                public_key.verify(bytes.fromhex(node.signature), payload)
                return "valid"
            if node.signature_scheme == "pqc-ml-dsa" and RUST_AVAILABLE:
                return (
                    "valid"
                    if aegis_rust.verify_pqc_signature(  # type: ignore[name-defined]
                        payload,
                        bytes.fromhex(node.signature),
                        bytes.fromhex(node.public_key),
                    )
                    else "invalid"
                )
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

        Plus cryptographic binding fields that link the annotation to the node:
        - ``node_hash``        — SHA-256 chain accumulator (tamper-evident binding)
        - ``signature``        — hex-encoded cryptographic signature
        - ``signature_scheme`` — signing algorithm used
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
            if self._wal_handle is not None:
                try:
                    self._wal_handle.flush()
                    self._fsync(self._wal_handle.fileno())
                except OSError:
                    pass
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
        """
        # Checkpoint the accumulator at the rotation boundary. The leaves it
        # summarises are the ones about to move into the archived segment, so
        # a restart replays only what was written after this point.
        self._save_mmr_state()

        # Flush + fsync + close so the segment is fully durable before rename.
        if self._wal_handle is not None:
            try:
                self._wal_handle.flush()
                self._fsync(self._wal_handle.fileno())
            except OSError:
                pass
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
                pass
            logger.info("Rotated WAL into archived segment %s", segment_path)
        except OSError as exc:
            logger.error("WAL rotation failed (%s) — continuing on active WAL", exc)
            self._open_wal()
            return

        self._wal_bytes = 0
        self._open_wal()

    def _sign(self, data: bytes) -> tuple[str, str, str, bool]:
        """Sign ``data``. Returns (signature_hex, pubkey_hex, scheme, is_fallback).

        Priority order (highest security first):
        1. HSM/PKCS#11: key never leaves token boundary.
        2. PQC ML-DSA via Rust extension (FIPS 204 post-quantum signing).
        3. HMAC-SHA256: fast, verifiable, requires signing_key in memory.
        4. Ed25519 ephemeral fallback: non-verifiable across restarts.
        """
        # ── 1. HSM/PKCS#11 path ───────────────────────────────────────────
        if self._hsm_backend and self._hsm_backend.available:
            try:
                sig_bytes, pub_hex, scheme = self._hsm_backend.sign(data)
                return sig_bytes.hex(), pub_hex, scheme, False
            except HSMUnavailableError as exc:
                logger.warning("HSM signing failed (%s); falling back to next tier", exc)

        # ── 2. Rust PQC ML-DSA path ───────────────────────────────────────
        if RUST_AVAILABLE:
            try:
                keypair = aegis_rust.generate_pqc_keypair()  # type: ignore[name-defined]
                sig_bytes = bytes(keypair.sign(data))
                pub_bytes: bytes = bytes(keypair.public_key)
                return sig_bytes.hex(), pub_bytes.hex(), "pqc-ml-dsa", False
            except Exception as exc:
                logger.warning("aegis_rust PQC sign failed (%s); falling back", exc)

        # ── 3. HMAC-SHA256 path ───────────────────────────────────────────
        if self._signing_key:
            sig = _hmac_sign(self._signing_key, data)
            return sig, "", "hmac-sha256", False

        # ── 4. Ed25519 ephemeral fallback ─────────────────────────────────
        if self._require_strong_signing:
            raise RuntimeError("strong signing required; no verifiable signer is available")
        sig_hex, pub_hex, scheme = _ed25519_sign(data)
        return sig_hex, pub_hex, scheme, True

    def _persist_node(self, node: AuditNode) -> None:
        """Append node as a JSON line to the WAL. Must be called under self._lock."""
        line = json.dumps(node.to_dict(), separators=(",", ":")) + "\n"
        nbytes = len(line.encode("utf-8"))
        if self._wal_handle is not None:
            self._wal_handle.write(line)
            self._wal_handle.flush()
            self._fsync(self._wal_handle.fileno())
            self._wal_bytes += nbytes
        else:
            # Safety fallback: _open_wal() failed at init time.
            try:
                os.makedirs(os.path.dirname(os.path.abspath(self.persistence_path)), exist_ok=True)
            except OSError:
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

        # Rotate AFTER the node is durably written: the just-written record is
        # safely inside the segment that gets archived, so no node is ever in
        # flight during the rename.
        if self.max_wal_bytes > 0 and self._wal_bytes >= self.max_wal_bytes:
            self._rotate_wal()

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
                self._mmr = MerkleMountainRange()
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

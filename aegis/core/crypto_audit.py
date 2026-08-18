"""
aegis.core.crypto_audit — Cryptographic audit ledger with Merkle chain-of-custody.

Architecture:
  - CryptographicAuditLedger: append-only Merkle chain backed by WAL.
  - AuditNode: immutable record with forensic fields, HMAC/PQC signature,
    and a computed node_hash linking the chain.
  - Signing: HMAC-SHA256 when signing_key is provided (default, "High" admissibility).
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
import time
from collections import deque
from collections.abc import Callable
from dataclasses import asdict, dataclass
from threading import Lock
from typing import Any

import numpy as np
from cryptography.hazmat.primitives.asymmetric import ed25519

from aegis.core.forensic import build_merkle_leaf, sha256_hex
from aegis.core.hsm import HSMSigningBackend, HSMUnavailableError
from aegis.core.mmr import MerkleMountainRange

logger = logging.getLogger(__name__)

MAX_PAYLOAD_BYTES: int = 1_048_576  # 1 MiB hard cap
_DEFAULT_MAX_FORENSIC_BYTES: int = 65_536

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
            "token_trail_count": 0,
            "is_fallback": False,
            "phi_scrubbed": False,
            "scrub_method": "",
            "signer_name": "",
            "signature_meaning": "",
            "audit_trail_version": "1",
        }
        # Remove legacy field if present
        data.pop("payload", None)
        merged = {**defaults, **data}
        # Keep only known fields to avoid TypeError on unexpected keys
        known = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
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
    ) -> None:
        self.persistence_path = persistence_path
        self._signing_key = signing_key
        self._fsync = fsync_fn or os.fsync
        self._hsm_backend = hsm_backend
        self._require_strong_signing = require_strong_signing
        self.max_memory_nodes = max_memory_nodes
        self.max_forensic_bytes = max_forensic_bytes
        self.max_wal_bytes = max_wal_bytes
        self.chain: deque[AuditNode] = deque(maxlen=max_memory_nodes)
        self._lock = Lock()
        self._wal_handle = None
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
            merkle_root = self._mmr.add_leaf(leaf)

            # Sign over prev_hash + merkle_root + request/response hashes so the
            # signature binds chain linkage, not merkle_root alone (see
            # _build_signed_payload).
            signed_payload = _build_signed_payload(
                prev_hash=prev_hash,
                merkle_root=merkle_root,
                request_hash=req_hash,
                response_hash=resp_hash,
            )
            signature, pub_key_hex, scheme, is_fallback = self._sign(signed_payload)

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
            )

            self._persist_node(node)
            self.chain.append(node)
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

            expected_prev = "0" * 64 if i == 0 else chain_list[i - 1].node_hash
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

        return True, None

    def export_part11_signatures(self) -> list[dict[str, Any]]:
        """Return 21 CFR Part 11 §11.50-compliant signature records for all nodes.

        Each record includes the three mandatory Part 11 fields:
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
                        self.chain.append(node)
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


# ── Compat shims kept for import compatibility ────────────────────────────────


@dataclass
class PQCSignatureAnchor:
    """Shim retained for import compatibility with existing code."""

    public_key: bytes
    algorithm: str = "HMAC-SHA256"

    def verify(self, data: bytes, signature: bytes) -> bool:  # noqa: ARG002
        return False  # Stateless anchor without key material is unverifiable

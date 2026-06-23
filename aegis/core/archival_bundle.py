# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.archival_bundle — algorithm-agile evidence bundle for 30-year retention.

Evidence bundles sealed today must remain verifiable decades from now even as
hash and HMAC algorithms are deprecated.  This module solves that by storing a
*manifest* of multiple independent digests and signatures, each keyed by
algorithm identifier.

When an algorithm ages out an operator calls :meth:`ArchivalBundleManager.add_hash`
or :meth:`ArchivalBundleManager.add_signature` to layer in a newer algorithm —
producing an augmented bundle that old verifiers still accept (they check their
own slot in the manifest) while new verifiers additionally check the stronger
algorithm.

Supported hash algorithms
--------------------------
* ``sha2-256`` — SHA-256 (current baseline, NIST FIPS 180-4)
* ``sha2-384`` — SHA-384 (Suite B / CNSA 1.0)
* ``sha2-512`` — SHA-512 (high-security baseline)
* ``sha3-256`` — SHA3-256 (NIST FIPS 202, post-SHA-2 migration path)
* ``sha3-512`` — SHA3-512

Signature algorithms
---------------------
* ``hmac-sha2-256`` — HMAC-SHA-256 keyed with ``AEGIS_SIGNING_KEY``
* ``hmac-sha3-256`` — HMAC-SHA3-256 (migration target when SHA-2 deprecated)

Usage::

    from aegis.core.archival_bundle import ArchivalBundleManager

    mgr = ArchivalBundleManager(signing_key="my-secret")
    bundle = mgr.seal({"evidence": "...", "chain_hash": "abc123"}, operator="alice")

    # Years later — add SHA3-512 alongside SHA3-256:
    bundle = mgr.add_hash(bundle, "sha3-512", operator="alice")

    result = mgr.verify(bundle)
    assert result.valid
"""

from __future__ import annotations

import hashlib
import hmac as _hmac_module
import json
import logging
import os
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

logger = logging.getLogger(__name__)

_FORMAT_VERSION = "1.0"
_DEFAULT_HASH_ALGOS = ["sha2-256", "sha3-256"]
_DEFAULT_SIG_ALGO = "hmac-sha2-256"

_HASH_REGISTRY: dict[str, object] = {
    "sha2-256": hashlib.sha256,
    "sha2-384": hashlib.sha384,
    "sha2-512": hashlib.sha512,
    "sha3-256": hashlib.sha3_256,
    "sha3-512": hashlib.sha3_512,
}

_SIG_ALGOS = {"hmac-sha2-256", "hmac-sha3-256"}


# ── Exceptions ────────────────────────────────────────────────────────────────


class ArchivalBundleError(Exception):
    """Raised when bundle creation, migration, or verification fails."""


# ── Data classes ──────────────────────────────────────────────────────────────


@dataclass
class MigrationEvent:
    """Record of a single algorithm-migration operation.

    Attributes
    ----------
    timestamp:
        ISO-8601 UTC timestamp of the migration.
    algo:
        Algorithm identifier added (e.g., ``"sha3-512"``).
    kind:
        ``"hash"`` or ``"signature"``.
    operator:
        Identity of the operator who performed the migration.
    """

    timestamp: str
    algo: str
    kind: str
    operator: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "timestamp": self.timestamp,
            "algo": self.algo,
            "kind": self.kind,
            "operator": self.operator,
        }


@dataclass
class ArchivalBundle:
    """A long-retention evidence bundle with multi-algorithm integrity proofs.

    Attributes
    ----------
    format_version:
        Bundle format version (currently ``"1.0"``).
    bundle_id:
        UUID identifying this bundle.
    created_at:
        ISO-8601 UTC timestamp when the bundle was first sealed.
    content:
        The evidence payload (arbitrary JSON-serializable dict).
    hash_manifest:
        Mapping of ``algo → hex_digest``, one per registered hash algorithm.
    signature_manifest:
        Mapping of ``algo → hex_hmac``, one per registered HMAC algorithm.
    migration_log:
        Ordered list of :class:`MigrationEvent` dicts recording algorithm
        additions after initial sealing.
    """

    format_version: str
    bundle_id: str
    created_at: str
    content: dict[str, object]
    hash_manifest: dict[str, str] = field(default_factory=dict)
    signature_manifest: dict[str, str] = field(default_factory=dict)
    migration_log: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "format_version": self.format_version,
            "bundle_id": self.bundle_id,
            "created_at": self.created_at,
            "content": self.content,
            "hash_manifest": dict(self.hash_manifest),
            "signature_manifest": dict(self.signature_manifest),
            "migration_log": list(self.migration_log),
        }


@dataclass
class ArchivalBundleVerifyResult:
    """Result of :meth:`ArchivalBundleManager.verify`.

    Attributes
    ----------
    valid:
        True when all hashes and signatures in the manifests check out.
    hash_results:
        Per-algorithm hash verification (``algo → True/False``).
    sig_results:
        Per-algorithm signature verification (``algo → True/False``).
    failed_algos:
        Algorithms that did not verify (empty when ``valid`` is True).
    reason:
        Human-readable failure description when ``valid`` is False.
    """

    valid: bool
    hash_results: dict[str, bool] = field(default_factory=dict)
    sig_results: dict[str, bool] = field(default_factory=dict)
    failed_algos: list[str] = field(default_factory=list)
    reason: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "valid": self.valid,
            "hash_results": dict(self.hash_results),
            "sig_results": dict(self.sig_results),
            "failed_algos": list(self.failed_algos),
            "reason": self.reason,
        }


# ── Helpers ───────────────────────────────────────────────────────────────────


def _canonical_content(content: dict[str, object]) -> bytes:
    """Stable UTF-8 JSON serialisation of *content* for digest computation."""
    return json.dumps(content, sort_keys=True, separators=(",", ":"), default=str).encode()


def _compute_hash(algo: str, data: bytes) -> str:
    factory = _HASH_REGISTRY.get(algo)
    if factory is None:
        raise ArchivalBundleError(f"Unsupported hash algorithm: {algo!r}")
    return factory(data).hexdigest()  # type: ignore[call-arg]


def _compute_sig(algo: str, signing_key: str, data: bytes) -> str:
    if algo == "hmac-sha2-256":
        return _hmac_module.new(signing_key.encode(), data, hashlib.sha256).hexdigest()
    if algo == "hmac-sha3-256":
        return _hmac_module.new(signing_key.encode(), data, hashlib.sha3_256).hexdigest()
    raise ArchivalBundleError(f"Unsupported signature algorithm: {algo!r}")


def _verify_sig(algo: str, signing_key: str, data: bytes, expected: str) -> bool:
    try:
        actual = _compute_sig(algo, signing_key, data)
    except ArchivalBundleError:
        return False
    return _hmac_module.compare_digest(actual, expected)


# ── Manager ───────────────────────────────────────────────────────────────────


class ArchivalBundleManager:
    """Create, migrate, and verify long-retention evidence bundles.

    Parameters
    ----------
    signing_key:
        Master HMAC key.  Falls back to ``AEGIS_SIGNING_KEY`` env var.
    hash_algos:
        Hash algorithms included when first sealing a bundle.
        Default ``["sha2-256", "sha3-256"]``.
    sig_algo:
        HMAC algorithm used when first sealing a bundle.
        Default ``"hmac-sha2-256"``.
    """

    def __init__(
        self,
        signing_key: str | None = None,
        hash_algos: list[str] | None = None,
        sig_algo: str | None = None,
    ) -> None:
        if signing_key is None:
            signing_key = os.environ.get("AEGIS_SIGNING_KEY", "")
        self._signing_key = signing_key

        self._hash_algos: list[str] = list(hash_algos) if hash_algos else list(_DEFAULT_HASH_ALGOS)
        for algo in self._hash_algos:
            if algo not in _HASH_REGISTRY:
                raise ArchivalBundleError(f"Unsupported hash algorithm: {algo!r}")

        self._sig_algo: str = sig_algo or _DEFAULT_SIG_ALGO
        if self._sig_algo not in _SIG_ALGOS:
            raise ArchivalBundleError(f"Unsupported signature algorithm: {self._sig_algo!r}")

    # ── Public API ─────────────────────────────────────────────────────────────

    def seal(self, content: dict[str, object], operator: str = "") -> ArchivalBundle:
        """Seal *content* into an :class:`ArchivalBundle`.

        Computes one digest per configured hash algorithm and one HMAC
        signature.  The bundle is immediately verifiable offline.

        Parameters
        ----------
        content:
            Evidence payload.  Must be JSON-serializable.
        operator:
            Identity of the sealing operator (recorded in migration log as
            the initial seal event).

        Returns
        -------
        ArchivalBundle

        Raises
        ------
        ArchivalBundleError
            When no signing key is configured and a signature is requested,
            or when content is not serializable.
        """
        bundle_id = str(uuid.uuid4())
        now = datetime.now(tz=UTC).isoformat()

        try:
            raw = _canonical_content(content)
        except (TypeError, ValueError) as exc:
            raise ArchivalBundleError(f"Content is not JSON-serializable: {exc}") from exc

        hash_manifest: dict[str, str] = {}
        for algo in self._hash_algos:
            hash_manifest[algo] = _compute_hash(algo, raw)

        sig_manifest: dict[str, str] = {}
        if self._signing_key:
            sig_manifest[self._sig_algo] = _compute_sig(self._sig_algo, self._signing_key, raw)
        else:
            logger.warning("archival_bundle: no signing key — bundle sealed without signature")

        migration_log: list[dict[str, str]] = [
            MigrationEvent(
                timestamp=now,
                algo=",".join(self._hash_algos),
                kind="initial-seal",
                operator=operator,
            ).to_dict()
        ]

        logger.info(
            "archival_bundle: sealed bundle %s algos=%s",
            bundle_id,
            list(hash_manifest),
        )
        return ArchivalBundle(
            format_version=_FORMAT_VERSION,
            bundle_id=bundle_id,
            created_at=now,
            content=content,
            hash_manifest=hash_manifest,
            signature_manifest=sig_manifest,
            migration_log=migration_log,
        )

    def add_hash(self, bundle: ArchivalBundle, algo: str, operator: str = "") -> ArchivalBundle:
        """Add a new hash algorithm to an existing bundle (algorithm migration).

        Parameters
        ----------
        bundle:
            The bundle to augment.
        algo:
            Hash algorithm identifier to add (e.g., ``"sha3-512"``).
        operator:
            Identity performing the migration (recorded in migration log).

        Returns
        -------
        ArchivalBundle
            The same bundle with *algo* added to ``hash_manifest``.

        Raises
        ------
        ArchivalBundleError
            When *algo* is not supported or is already present.
        """
        if algo not in _HASH_REGISTRY:
            raise ArchivalBundleError(f"Unsupported hash algorithm: {algo!r}")
        if algo in bundle.hash_manifest:
            raise ArchivalBundleError(f"Algorithm {algo!r} already present in bundle")

        raw = _canonical_content(bundle.content)
        new_hash_manifest = dict(bundle.hash_manifest)
        new_hash_manifest[algo] = _compute_hash(algo, raw)

        event = MigrationEvent(
            timestamp=datetime.now(tz=UTC).isoformat(),
            algo=algo,
            kind="hash",
            operator=operator,
        ).to_dict()

        logger.info("archival_bundle: added hash algo %r to bundle %s", algo, bundle.bundle_id)
        return ArchivalBundle(
            format_version=bundle.format_version,
            bundle_id=bundle.bundle_id,
            created_at=bundle.created_at,
            content=bundle.content,
            hash_manifest=new_hash_manifest,
            signature_manifest=dict(bundle.signature_manifest),
            migration_log=list(bundle.migration_log) + [event],
        )

    def add_signature(
        self, bundle: ArchivalBundle, sig_algo: str, operator: str = ""
    ) -> ArchivalBundle:
        """Add a new HMAC signature algorithm to an existing bundle.

        Parameters
        ----------
        bundle:
            The bundle to augment.
        sig_algo:
            Signature algorithm identifier (e.g., ``"hmac-sha3-256"``).
        operator:
            Identity performing the migration.

        Returns
        -------
        ArchivalBundle
            The same bundle with *sig_algo* added to ``signature_manifest``.

        Raises
        ------
        ArchivalBundleError
            When *sig_algo* is not supported, already present, or no signing
            key is configured.
        """
        if sig_algo not in _SIG_ALGOS:
            raise ArchivalBundleError(f"Unsupported signature algorithm: {sig_algo!r}")
        if sig_algo in bundle.signature_manifest:
            raise ArchivalBundleError(f"Algorithm {sig_algo!r} already in signature_manifest")
        if not self._signing_key:
            raise ArchivalBundleError("No signing key configured; cannot add signature")

        raw = _canonical_content(bundle.content)
        new_sig_manifest = dict(bundle.signature_manifest)
        new_sig_manifest[sig_algo] = _compute_sig(sig_algo, self._signing_key, raw)

        event = MigrationEvent(
            timestamp=datetime.now(tz=UTC).isoformat(),
            algo=sig_algo,
            kind="signature",
            operator=operator,
        ).to_dict()

        logger.info("archival_bundle: added sig algo %r to bundle %s", sig_algo, bundle.bundle_id)
        return ArchivalBundle(
            format_version=bundle.format_version,
            bundle_id=bundle.bundle_id,
            created_at=bundle.created_at,
            content=bundle.content,
            hash_manifest=dict(bundle.hash_manifest),
            signature_manifest=new_sig_manifest,
            migration_log=list(bundle.migration_log) + [event],
        )

    def verify(self, bundle: ArchivalBundle) -> ArchivalBundleVerifyResult:
        """Verify all hashes and signatures in *bundle*'s manifests.

        Parameters
        ----------
        bundle:
            The bundle to verify.

        Returns
        -------
        ArchivalBundleVerifyResult
            ``valid=True`` when every manifest entry passes.
        """
        raw = _canonical_content(bundle.content)
        hash_results: dict[str, bool] = {}
        sig_results: dict[str, bool] = {}
        failed: list[str] = []

        for algo, expected in bundle.hash_manifest.items():
            try:
                actual = _compute_hash(algo, raw)
                ok = _hmac_module.compare_digest(actual, expected)
            except ArchivalBundleError:
                ok = False
            hash_results[algo] = ok
            if not ok:
                failed.append(algo)

        for algo, expected in bundle.signature_manifest.items():
            if not self._signing_key:
                sig_results[algo] = False
                failed.append(algo)
                continue
            ok = _verify_sig(algo, self._signing_key, raw, expected)
            sig_results[algo] = ok
            if not ok:
                failed.append(algo)

        valid = not failed
        reason = "" if valid else f"Failed algorithms: {failed}"
        if not valid:
            logger.warning(
                "archival_bundle: verification FAILED bundle=%s failed=%s",
                bundle.bundle_id,
                failed,
            )
        else:
            logger.debug("archival_bundle: verified bundle %s", bundle.bundle_id)

        return ArchivalBundleVerifyResult(
            valid=valid,
            hash_results=hash_results,
            sig_results=sig_results,
            failed_algos=failed,
            reason=reason,
        )

    def export_json(self, bundle: ArchivalBundle) -> str:
        """Serialise *bundle* to a JSON string for long-term storage."""
        return json.dumps(bundle.to_dict(), sort_keys=True, separators=(",", ":"), default=str)

    def import_json(self, data: str) -> ArchivalBundle:
        """Deserialise a bundle previously produced by :meth:`export_json`.

        Raises
        ------
        ArchivalBundleError
            When the JSON is malformed or missing required fields.
        """
        try:
            d = json.loads(data)
        except json.JSONDecodeError as exc:
            raise ArchivalBundleError(f"Invalid bundle JSON: {exc}") from exc

        required = ("format_version", "bundle_id", "created_at", "content")
        missing = [k for k in required if k not in d]
        if missing:
            raise ArchivalBundleError(f"Bundle missing required fields: {missing}")

        return ArchivalBundle(
            format_version=d["format_version"],
            bundle_id=d["bundle_id"],
            created_at=d["created_at"],
            content=d["content"],
            hash_manifest=d.get("hash_manifest", {}),
            signature_manifest=d.get("signature_manifest", {}),
            migration_log=d.get("migration_log", []),
        )

    @property
    def supported_hash_algos(self) -> list[str]:
        """Hash algorithms supported by this manager."""
        return list(_HASH_REGISTRY)

    @property
    def supported_sig_algos(self) -> list[str]:
        """Signature algorithms supported by this manager."""
        return list(_SIG_ALGOS)

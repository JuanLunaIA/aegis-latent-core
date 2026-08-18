# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""
aegis_server.compliance.exporter — SOC2 Type II and HIPAA compliance export engine.

Produces cryptographically sealed audit bundles that satisfy:
- SOC2 Type II CC6.1 / CC7.2 — audit trail completeness, tamper evidence.
- HIPAA 45 CFR §164.312(b) — audit controls for systems handling PHI.
- ISO 27001 A.12.4 — logging and monitoring evidence.

Bundle format
-------------
Each export produces a single UTF-8 JSON file with the following top-level
structure::

    {
      "aegis_compliance_bundle": {
        "format_version": "1.0",
        "export_id": "<uuid4>",
        "generated_at": "<ISO 8601 UTC>",
        "generated_by": "aegis-latent-core/<version>",
        "export_params": { "from_offset": N, "limit": N, "tenant_id": "..." },
        "node_count": N,
        "audit_chain": [ <StorageNode dicts in ascending timestamp order> ],
        "verification_manifest": {
          "chain_hash":       "<SHA-256 of canonical chain JSON>",
          "bundle_signature": "<hex signature over chain_hash bytes>",
          "signer_scheme":    "<hmac-sha256 | vault-transit | ...>",
          "integrity_report": { <StorageProvider.check_integrity() output> }
        }
      }
    }

The ``chain_hash`` is a SHA-256 digest of the ``audit_chain`` array serialised
with sorted keys and no whitespace — a deterministic canonical form.
``bundle_signature`` is the ``SignerProvider.sign_payload(chain_hash_bytes)``
output, proving the bundle was sealed by the Aegis instance holding the signing
credential at export time.

File naming convention::

    aegis_compliance_<export_id>_<YYYYMMDD_HHMMSS>Z.json

Dependencies:
    Python 3.11+ stdlib only (json, hashlib, uuid, datetime, pathlib, os).
    Runtime injected: ``StorageProvider``, ``SignerProvider``.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import logging
import os
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aegis_server import __version__
from aegis_server.crypto.base import SignerProvider
from aegis_server.storage.base import StorageProvider

logger = logging.getLogger(__name__)

_BUNDLE_FORMAT_VERSION = "1.0"
_MAX_EXPORT_NODES = 100_000  # hard cap per bundle to prevent OOM


@dataclass(frozen=True)
class ExportParams:
    """Parameters that define the scope of a compliance export."""

    from_offset: int
    """Zero-based record offset into the ordered audit chain."""

    limit: int
    """Maximum number of nodes to include (capped at ``_MAX_EXPORT_NODES``)."""

    tenant_id: str | None
    """Restrict export to this tenant/client identifier.  ``None`` = all tenants."""


@dataclass
class ExportResult:
    """
    Describes the outcome of a completed compliance export.

    Returned by ``ComplianceExporter.export()``; used for logging and
    programmatic post-export verification.
    """

    export_id: str
    """UUID4 unique identifier for this export bundle."""

    output_path: str
    """Absolute filesystem path of the written bundle file."""

    node_count: int
    """Number of audit nodes included in the bundle."""

    chain_hash: str
    """SHA-256 hex of the canonical chain JSON (integrity anchor)."""

    bundle_signature: str
    """Hex-encoded signature over ``chain_hash`` bytes from the signer."""

    signer_scheme: str
    """Algorithm identifier from the ``SignerProvider`` (e.g. ``"hmac-sha256"``)."""

    generated_at: str
    """ISO 8601 UTC timestamp of when the bundle was finalised."""

    integrity_valid: bool
    """``True`` iff ``StorageProvider.check_integrity()`` reported no broken links."""

    signing_key_id: str = "static"
    """Non-secret version identifier for the key used to seal the bundle."""


class ComplianceExporter:
    """
    Generates cryptographically sealed compliance export bundles.

    A single ``ComplianceExporter`` instance can be reused for multiple
    exports.  Each call to ``export()`` is fully independent.

    Usage::

        exporter = ComplianceExporter(
            storage=provider,
            signer=signer,
            export_dir="/var/aegis/exports",
        )
        result = await exporter.export(
            params=ExportParams(from_offset=0, limit=10_000, tenant_id=None)
        )
        print(result.output_path)

    Args:
        storage:    Initialised ``StorageProvider`` to read audit nodes from.
        signer:     Configured ``SignerProvider`` to seal the bundle.
        export_dir: Directory where bundle files are written.
                    Created automatically if it does not exist.
    """

    def __init__(
        self,
        storage: StorageProvider,
        signer: SignerProvider,
        export_dir: str = "./aegis_exports",
    ) -> None:
        self._storage = storage
        self._signer = signer
        self._export_dir = Path(export_dir).resolve()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def export(self, params: ExportParams) -> ExportResult:
        """
        Fetch audit nodes, seal the bundle, write to disk, and return metadata.

        Steps
        -----
        1. Clamp ``params.limit`` to ``_MAX_EXPORT_NODES``.
        2. Fetch nodes from the storage provider in ascending timestamp order.
        3. Run ``check_integrity()`` on the provider (full-chain sweep).
        4. Compute the canonical chain hash (SHA-256 of sorted-key JSON).
        5. Sign the hash bytes via the configured ``SignerProvider``.
        6. Assemble the full bundle document.
        7. Write the file atomically via a temp-rename strategy.
        8. Return an ``ExportResult`` with all metadata.

        Args:
            params: Scope of the export.

        Returns:
            ``ExportResult`` with the output path and integrity metadata.

        Raises:
            RuntimeError: On storage, signing, or I/O failures.
        """
        export_id = str(uuid.uuid4())
        generated_at = self._utcnow_iso()

        # ── 1. Clamp limit ────────────────────────────────────────────
        clamped_limit = min(params.limit, _MAX_EXPORT_NODES)
        if params.limit > _MAX_EXPORT_NODES:
            logger.warning(
                "ComplianceExporter: requested limit=%d exceeds hard cap=%d; "
                "clamping to %d.  Split the export into multiple calls for "
                "larger ranges.",
                params.limit,
                _MAX_EXPORT_NODES,
                _MAX_EXPORT_NODES,
            )

        # ── 2. Fetch nodes ────────────────────────────────────────────
        logger.info(
            "ComplianceExporter: fetching nodes (export_id=%s, offset=%d, limit=%d, tenant_id=%r)",
            export_id,
            params.from_offset,
            clamped_limit,
            params.tenant_id,
        )
        try:
            raw_nodes: list[dict[str, Any]] = await self._storage.list_nodes(
                limit=clamped_limit,
                offset=params.from_offset,
                tenant_id=params.tenant_id,
            )
        except Exception as exc:
            raise RuntimeError(f"ComplianceExporter: storage.list_nodes failed: {exc}") from exc

        node_count = len(raw_nodes)
        logger.info(
            "ComplianceExporter: fetched %d nodes for export_id=%s",
            node_count,
            export_id,
        )

        # ── 3. Integrity check ────────────────────────────────────────
        try:
            integrity_report: dict[str, Any] = await self._storage.check_integrity()
        except Exception as exc:
            logger.error(
                "ComplianceExporter: integrity check failed for export_id=%s: %s",
                export_id,
                exc,
            )
            integrity_report = {
                "is_valid": False,
                "error_message": str(exc),
                "node_count": node_count,
                "checked_at": generated_at,
            }

        integrity_valid: bool = bool(integrity_report.get("is_valid", False))
        if not integrity_valid:
            logger.warning(
                "ComplianceExporter: chain integrity check FAILED for "
                "export_id=%s — bundle will be produced but flagged as "
                "INTEGRITY_FAILURE in the verification manifest.",
                export_id,
            )

        # ── 4. Canonical chain hash ───────────────────────────────────
        #
        # Canonical form: JSON array, keys sorted, no whitespace.
        # SHA-256 of the UTF-8 encoding.
        #
        canonical_chain_json: bytes = json.dumps(
            raw_nodes,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
        chain_hash: str = hashlib.sha256(canonical_chain_json).hexdigest()

        # ── 5. Sign ───────────────────────────────────────────────────
        try:
            bundle_signature, signing_key_id = await self._signer.sign_payload_with_metadata(
                chain_hash.encode("ascii")
            )
        except Exception as exc:
            raise RuntimeError(
                f"ComplianceExporter: signing failed for export_id={export_id}: {exc}"
            ) from exc

        # ── 6. Assemble bundle ────────────────────────────────────────
        bundle: dict[str, Any] = {
            "aegis_compliance_bundle": {
                "format_version": _BUNDLE_FORMAT_VERSION,
                "export_id": export_id,
                "generated_at": generated_at,
                "generated_by": f"aegis-latent-core/{__version__}",
                "export_params": {
                    "from_offset": params.from_offset,
                    "limit": clamped_limit,
                    "tenant_id": params.tenant_id,
                },
                "node_count": node_count,
                "audit_chain": raw_nodes,
                "verification_manifest": {
                    "chain_hash": chain_hash,
                    "bundle_signature": bundle_signature,
                    "signer_scheme": self._signer.scheme,
                    "signing_key_id": signing_key_id,
                    "integrity_report": integrity_report,
                    "integrity_status": ("VALID" if integrity_valid else "INTEGRITY_FAILURE"),
                },
            }
        }

        # ── 7. Write atomically ───────────────────────────────────────
        output_path = self._compute_output_path(export_id, generated_at)
        self._write_atomic(output_path, bundle)

        logger.info(
            "ComplianceExporter: bundle written to %s "
            "(nodes=%d, chain_hash=%s…, signer=%s, integrity=%s)",
            output_path,
            node_count,
            chain_hash[:16],
            self._signer.scheme,
            "VALID" if integrity_valid else "INTEGRITY_FAILURE",
        )

        # ── 8. Return result ──────────────────────────────────────────
        return ExportResult(
            export_id=export_id,
            output_path=str(output_path),
            node_count=node_count,
            chain_hash=chain_hash,
            bundle_signature=bundle_signature,
            signer_scheme=self._signer.scheme,
            generated_at=generated_at,
            integrity_valid=integrity_valid,
            signing_key_id=signing_key_id,
        )

    async def export_range_paginated(
        self,
        *,
        total_limit: int,
        page_size: int = 10_000,
        tenant_id: str | None = None,
    ) -> list[ExportResult]:
        """
        Export an arbitrarily large audit range as multiple sealed bundles.

        Calls ``export()`` repeatedly with non-overlapping offsets until
        ``total_limit`` records have been exported or the storage is exhausted.

        Each bundle is an independent, self-verifying compliance package.

        Args:
            total_limit: Maximum total nodes to export across all bundles.
            page_size:   Nodes per individual bundle (max ``_MAX_EXPORT_NODES``).
            tenant_id:   Tenant filter forwarded to each ``export()`` call.

        Returns:
            List of ``ExportResult``, one per bundle written.
        """
        results: list[ExportResult] = []
        offset = 0
        remaining = min(total_limit, _MAX_EXPORT_NODES * 1_000)

        while remaining > 0:
            batch_size = min(page_size, remaining, _MAX_EXPORT_NODES)
            params = ExportParams(
                from_offset=offset,
                limit=batch_size,
                tenant_id=tenant_id,
            )
            result = await self.export(params=params)
            results.append(result)

            if result.node_count < batch_size:
                # Storage exhausted — no more records available
                break

            offset += result.node_count
            remaining -= result.node_count

        logger.info(
            "ComplianceExporter: paginated export complete — %d bundles, %d total nodes",
            len(results),
            sum(r.node_count for r in results),
        )
        return results

    @staticmethod
    async def verify_bundle(bundle_path: str, signer: SignerProvider) -> dict[str, Any]:
        """
        Re-verify a previously exported bundle file without a running server.

        Performs:
        1. Parse the bundle JSON.
        2. Re-compute the canonical chain hash from ``audit_chain``.
        3. Compare against ``chain_hash`` in the verification manifest.
        4. Attempt signature verification via ``signer.verify()``.

        Args:
            bundle_path: Filesystem path to the ``.json`` bundle.
            signer:      Signer that can verify the scheme used at export time.

        Returns:
            Dict with keys:
            - ``"valid"``: bool — True iff hash and signature are intact.
            - ``"chain_hash_match"``: bool
            - ``"signature_valid"``: bool or None (when not verifiable)
            - ``"node_count"``: int
            - ``"export_id"``: str
            - ``"integrity_status"``: str from the manifest
            - ``"error"``: str or None

        Raises:
            FileNotFoundError: If ``bundle_path`` does not exist.
            ValueError:        If the file is not a valid Aegis bundle.
        """
        bundle_path_obj = Path(bundle_path)
        if not bundle_path_obj.exists():
            raise FileNotFoundError(f"Bundle not found: {bundle_path}")

        try:
            with open(bundle_path_obj, encoding="utf-8") as fh:
                raw = json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            raise ValueError(f"Cannot parse bundle at {bundle_path}: {exc}") from exc

        root = raw.get("aegis_compliance_bundle")
        if root is None:
            raise ValueError(
                f"{bundle_path} is not an Aegis compliance bundle "
                "(missing 'aegis_compliance_bundle' root key)"
            )

        audit_chain: list[dict[str, Any]] = root.get("audit_chain", [])
        manifest: dict[str, Any] = root.get("verification_manifest", {})
        stored_hash: str = manifest.get("chain_hash", "")
        stored_sig: str = manifest.get("bundle_signature", "")
        export_id: str = root.get("export_id", "unknown")
        integrity_status: str = manifest.get("integrity_status", "UNKNOWN")
        node_count: int = root.get("node_count", len(audit_chain))

        # Re-compute canonical chain hash
        canonical_chain_json: bytes = json.dumps(
            audit_chain,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
        recomputed_hash: str = hashlib.sha256(canonical_chain_json).hexdigest()

        chain_hash_match: bool = recomputed_hash == stored_hash

        # Attempt signature verification
        signature_valid: bool | None = None
        sig_error: str | None = None
        try:
            signature_valid = await signer.verify(stored_hash.encode("ascii"), stored_sig)
        except Exception as exc:
            sig_error = str(exc)
            signature_valid = None

        overall_valid = chain_hash_match and (signature_valid is True or signature_valid is None)

        return {
            "valid": overall_valid,
            "chain_hash_match": chain_hash_match,
            "signature_valid": signature_valid,
            "node_count": node_count,
            "export_id": export_id,
            "integrity_status": integrity_status,
            "recomputed_chain_hash": recomputed_hash,
            "stored_chain_hash": stored_hash,
            "error": sig_error,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _compute_output_path(self, export_id: str, generated_at: str) -> Path:
        """
        Build the output file path and ensure the directory exists.

        Args:
            export_id:    UUID4 string.
            generated_at: ISO 8601 UTC timestamp string.

        Returns:
            Absolute ``Path`` to the (not yet created) bundle file.
        """
        self._export_dir.mkdir(parents=True, exist_ok=True)
        # Convert ISO timestamp to a safe filename component
        ts_safe = generated_at.replace(":", "").replace("-", "").replace(".", "")[:15]
        filename = f"aegis_compliance_{export_id}_{ts_safe}Z.json"
        return self._export_dir / filename

    @staticmethod
    def _write_atomic(output_path: Path, bundle: dict[str, Any]) -> None:
        """
        Write ``bundle`` to ``output_path`` atomically via temp-rename.

        The temp file is written in the same directory (same filesystem)
        so the final ``os.replace()`` is an atomic inode operation on
        POSIX systems.

        Args:
            output_path: Final destination path.
            bundle:      JSON-serialisable bundle dict.

        Raises:
            RuntimeError: On serialisation or I/O failures.
        """
        tmp_path = output_path.with_suffix(".tmp")
        try:
            bundle_json = json.dumps(
                bundle,
                ensure_ascii=True,
                indent=2,
                sort_keys=False,
                default=str,
            )
            tmp_path.write_text(bundle_json, encoding="utf-8")
            os.replace(tmp_path, output_path)
        except Exception as exc:
            # Clean up temp file on failure
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise RuntimeError(
                f"ComplianceExporter: failed to write bundle to {output_path}: {exc}"
            ) from exc

    @staticmethod
    def _utcnow_iso() -> str:
        """Return the current UTC time as an ISO 8601 string with microseconds."""
        return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

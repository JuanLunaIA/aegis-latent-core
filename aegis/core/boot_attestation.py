"""
aegis.core.boot_attestation — Trusted Boot Verification.

Verifies the system is in a known-good state before initializing the proxy by
comparing live TPM PCR values against **golden measurements loaded from a
cryptographically-signed vendor manifest** — never from in-source constants.

The manifest is JSON of the form::

    {
      "version": "2026.06-rev1",
      "measurements": {"0": "<64-hex>", "1": "<64-hex>", ...},
      "algorithm": "ml-dsa-65" | "hmac-sha512",
      "signature": "<hex>"
    }

The signature covers the canonical JSON of ``{"version", "measurements"}`` (keys
sorted, no whitespace). It is verified before the measurements are trusted:

* ``ml-dsa-65``  — real post-quantum signature; verify with the vendor's ML-DSA
  public key (``PQCSigner.verify``).
* ``hmac-sha512`` — symmetric MAC; verify with the shared provisioning key.

A manifest with a missing or invalid signature is rejected with
:class:`BootAttestationError`; there is no unsigned fallback.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path

from aegis.core.pqc_signer import PQCSigner
from aegis.core.tpm import TPMManager

logger = logging.getLogger(__name__)

_HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")
_ALG_ML_DSA = "ml-dsa-65"
_ALG_HMAC = "hmac-sha512"


class BootAttestationError(Exception):
    """Raised when a golden-measurement manifest is malformed or unverifiable."""


@dataclass(frozen=True)
class GoldenManifest:
    """A verified set of golden PCR measurements from a signed vendor manifest."""

    version: str
    measurements: dict[int, str]  # PCR index -> expected SHA-256 hex


def _canonical_payload(version: str, measurements_str_keyed: dict[str, str]) -> bytes:
    """Deterministic bytes the signature covers (stable across re-serialization)."""
    return json.dumps(
        {"version": version, "measurements": measurements_str_keyed},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def load_signed_manifest(
    manifest_path: str | Path,
    *,
    public_key: bytes | None = None,
    hmac_key: bytes | None = None,
) -> GoldenManifest:
    """Load and cryptographically verify a vendor golden-measurement manifest.

    Exactly one verification key must be supplied, matching the manifest's
    ``algorithm``: *public_key* for ``ml-dsa-65`` or *hmac_key* for
    ``hmac-sha512``. Raises :class:`BootAttestationError` on any malformation or
    verification failure — never returns unverified measurements.
    """
    path = Path(manifest_path)
    if not path.exists():
        raise BootAttestationError(f"manifest not found: {path}")

    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise BootAttestationError(f"manifest is not readable JSON: {exc}") from exc

    if not isinstance(doc, dict):
        raise BootAttestationError("manifest must be a JSON object")

    version = doc.get("version")
    measurements = doc.get("measurements")
    algorithm = doc.get("algorithm")
    signature_hex = doc.get("signature")

    if not isinstance(version, str) or not version:
        raise BootAttestationError("manifest 'version' must be a non-empty string")
    if not isinstance(measurements, dict) or not measurements:
        raise BootAttestationError("manifest 'measurements' must be a non-empty object")
    if not isinstance(signature_hex, str) or not signature_hex:
        raise BootAttestationError("manifest 'signature' is missing")

    # Validate each measurement before trusting it.
    parsed: dict[int, str] = {}
    str_keyed: dict[str, str] = {}
    for key, value in measurements.items():
        if not isinstance(value, str) or not _HEX64.match(value):
            raise BootAttestationError(
                f"measurement for PCR {key!r} must be a 64-char lowercase hex SHA-256"
            )
        try:
            idx = int(key)
        except (TypeError, ValueError) as exc:
            raise BootAttestationError(f"PCR index {key!r} is not an integer") from exc
        parsed[idx] = value
        str_keyed[str(key)] = value

    payload = _canonical_payload(version, str_keyed)

    try:
        signature = bytes.fromhex(signature_hex)
    except ValueError as exc:
        raise BootAttestationError("manifest 'signature' is not valid hex") from exc

    if algorithm == _ALG_ML_DSA:
        if public_key is None:
            raise BootAttestationError("ml-dsa-65 manifest requires a vendor public_key")
        if not PQCSigner.verify(payload, signature, public_key):
            raise BootAttestationError("manifest ML-DSA-65 signature verification FAILED")
    elif algorithm == _ALG_HMAC:
        if hmac_key is None:
            raise BootAttestationError("hmac-sha512 manifest requires an hmac_key")
        expected = hmac.new(bytes(hmac_key), payload, hashlib.sha512).digest()
        if not hmac.compare_digest(expected, signature):
            raise BootAttestationError("manifest HMAC-SHA512 signature verification FAILED")
    else:
        raise BootAttestationError(f"unsupported manifest algorithm: {algorithm!r}")

    logger.info(
        "Golden-measurement manifest verified (version=%s, %d PCRs, alg=%s).",
        version,
        len(parsed),
        algorithm,
    )
    return GoldenManifest(version=version, measurements=parsed)


class BootAttestationManager:
    """Verifies system state against golden measurements using TPM PCRs.

    Construct with a :class:`GoldenManifest` obtained from
    :func:`load_signed_manifest` — there is no in-source golden default.
    """

    def __init__(self, manifest: GoldenManifest):
        if not isinstance(manifest, GoldenManifest):
            raise TypeError("manifest must be a verified GoldenManifest")
        self.manifest = manifest
        # One TPMManager per monitored PCR index.
        self._tpms: dict[int, TPMManager] = {
            idx: TPMManager(pcr_index=idx) for idx in manifest.measurements
        }

    @classmethod
    def from_signed_manifest(
        cls,
        manifest_path: str | Path,
        *,
        public_key: bytes | None = None,
        hmac_key: bytes | None = None,
    ) -> BootAttestationManager:
        """Load+verify a signed manifest and build the manager in one step."""
        manifest = load_signed_manifest(manifest_path, public_key=public_key, hmac_key=hmac_key)
        return cls(manifest)

    def measure_component(self, pcr_index: int, component_path: str) -> str:
        """Measure a file into its TPM PCR and return the new PCR value."""
        tpm = self._tpms.get(pcr_index) or TPMManager(pcr_index=pcr_index)
        self._tpms[pcr_index] = tpm
        try:
            new_value = tpm.measure_binary(component_path)
        except (FileNotFoundError, RuntimeError) as exc:
            logger.error("Failed to measure %s into PCR[%d]: %s", component_path, pcr_index, exc)
            raise RuntimeError(f"Boot integrity failure: {component_path}") from exc
        logger.info("Component [%s] measured into PCR[%d]", component_path, pcr_index)
        return new_value

    def verify_boot_state(self) -> bool:
        """Verify every golden PCR matches the live TPM value (fail-closed)."""
        for index, expected_hash in self.manifest.measurements.items():
            actual_hash = self._tpms[index].get_pcr_value()
            if actual_hash != expected_hash:
                logger.critical("BOOT INTEGRITY VIOLATION: PCR[%d] mismatch!", index)
                logger.critical("Expected: %s | Actual: %s", expected_hash, actual_hash)
                return False
        logger.info("Boot state verified. System is in a TRUSTED state.")
        return True

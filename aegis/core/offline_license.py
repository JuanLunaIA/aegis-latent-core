# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.offline_license — Domain 1.3 offline license validation.

Validates HMAC-SHA256-signed license files with no network calls.  The license
is a JSON file containing licensee metadata and a hex HMAC-SHA256 signature
computed over the canonical (sorted-key) JSON of the remaining fields.

Key design points
-----------------
* The signing key (``AEGIS_LICENSE_KEY``) must differ from ``AEGIS_SIGNING_KEY``
  to prevent cross-system key reuse.
* All validation is purely local — no DNS, no OCSP, no revocation endpoint.
* ``OfflineLicenseValidator.from_env()`` reads ``AEGIS_LICENSE_FILE`` and
  ``AEGIS_LICENSE_KEY`` from the process environment.

Usage::

    validator = OfflineLicenseValidator.from_env()
    result = validator.validate()
    if not result.valid:
        raise LicenseExpiredError(result.reason)
    if validator.has_feature("hipaa"):
        enable_hipaa_controls()
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass
from typing import Any, cast

logger = logging.getLogger(__name__)

# ── Exceptions ────────────────────────────────────────────────────────────────


class LicenseError(Exception):
    """Base error for offline license failures."""


class LicenseExpiredError(LicenseError):
    """Raised when the license has passed its expiry timestamp."""


class LicenseTamperError(LicenseError):
    """Raised when the HMAC signature does not verify."""


class LicenseNotFoundError(LicenseError):
    """Raised when the license file path does not exist or cannot be read."""


# ── Data types ────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class LicenseRecord:
    """Immutable representation of a signed license file.

    Attributes
    ----------
    licensee:
        Human-readable name of the licensed entity.
    issued_at:
        UTC epoch (float) when the license was generated.
    expires_at:
        UTC epoch (float) after which the license is invalid.
    features:
        Frozenset of enabled feature tokens (e.g. ``"enterprise"``, ``"pqc"``).
    license_id:
        UUID string uniquely identifying this license grant.
    signature:
        Hex HMAC-SHA256 of the canonical JSON of the other five fields.
    """

    licensee: str
    issued_at: float
    expires_at: float
    features: frozenset[str]
    license_id: str
    signature: str


@dataclass
class LicenseValidationResult:
    """Outcome of :meth:`OfflineLicenseValidator.validate`.

    Attributes
    ----------
    valid:
        True when the signature verifies and the license is not expired.
    record:
        The parsed :class:`LicenseRecord` (present even when invalid).
    reason:
        Human-readable explanation of the validation outcome.
    days_remaining:
        Positive = days until expiry; negative = days since expiry.
    """

    valid: bool
    record: LicenseRecord | None
    reason: str
    days_remaining: int


# ── Core class ────────────────────────────────────────────────────────────────


class OfflineLicenseValidator:
    """Validates an HMAC-SHA256-signed JSON license file with no network calls.

    Instantiate via :meth:`from_env` in production; inject *license_path* and
    *license_key_hex* directly in tests.

    Parameters
    ----------
    license_path:
        Filesystem path to the JSON license file.
    license_key_hex:
        Hex-encoded HMAC key (must differ from ``AEGIS_SIGNING_KEY``).
    """

    def __init__(self, license_path: str, license_key_hex: str) -> None:
        self._license_path = license_path
        self._license_key_hex = license_key_hex

    # ── Factory ───────────────────────────────────────────────────────────────

    @classmethod
    def from_env(cls) -> OfflineLicenseValidator:
        """Construct from environment variables.

        Reads
        -----
        ``AEGIS_LICENSE_FILE``
            Path to the JSON license file.
        ``AEGIS_LICENSE_KEY``
            Hex HMAC key for signature verification.

        Raises
        ------
        LicenseError
            If either variable is absent, or if the license key equals
            ``AEGIS_SIGNING_KEY`` (cross-system key reuse forbidden).
        """
        path = os.environ.get("AEGIS_LICENSE_FILE", "")
        if not path:
            raise LicenseError("AEGIS_LICENSE_FILE environment variable is not set")

        key_hex = os.environ.get("AEGIS_LICENSE_KEY", "")
        if not key_hex:
            raise LicenseError("AEGIS_LICENSE_KEY environment variable is not set")

        signing_key = os.environ.get("AEGIS_SIGNING_KEY", "")
        if signing_key and key_hex == signing_key:
            raise LicenseError(
                "AEGIS_LICENSE_KEY must differ from AEGIS_SIGNING_KEY; "
                "cross-system key reuse is not permitted"
            )

        return cls(license_path=path, license_key_hex=key_hex)

    # ── Validation ────────────────────────────────────────────────────────────

    def validate(self) -> LicenseValidationResult:
        """Load, parse, and cryptographically verify the license file.

        Returns
        -------
        LicenseValidationResult
            Always returns a result object; raises are reserved for callers
            who prefer exception-style usage.
        """
        try:
            raw = self._load_file()
        except LicenseNotFoundError as exc:
            return LicenseValidationResult(
                valid=False, record=None, reason=str(exc), days_remaining=0
            )

        try:
            record = self._parse_record(raw)
        except (KeyError, TypeError, ValueError) as exc:
            return LicenseValidationResult(
                valid=False,
                record=None,
                reason=f"license file malformed: {exc}",
                days_remaining=0,
            )

        if not self._verify_signature(record):
            return LicenseValidationResult(
                valid=False,
                record=record,
                reason="license signature verification failed; file may have been tampered",
                days_remaining=0,
            )

        now = time.time()
        days_remaining = int((record.expires_at - now) / 86400)

        if now > record.expires_at:
            return LicenseValidationResult(
                valid=False,
                record=record,
                reason=f"license expired {abs(days_remaining)} day(s) ago",
                days_remaining=days_remaining,
            )

        return LicenseValidationResult(
            valid=True,
            record=record,
            reason="license valid",
            days_remaining=days_remaining,
        )

    def has_feature(self, feature: str) -> bool:
        """Return True if the current license grants *feature* and is valid.

        A feature check always re-validates the license to prevent stale caching.
        """
        result = self.validate()
        if not result.valid or result.record is None:
            return False
        return feature in result.record.features

    # ── Static helpers ────────────────────────────────────────────────────────

    @staticmethod
    def sign_license(record_dict: dict[str, Any], key_hex: str) -> str:
        """Compute HMAC-SHA256 over canonical JSON of *record_dict* (sorted keys).

        Parameters
        ----------
        record_dict:
            The license fields dict (without the ``"signature"`` key).
        key_hex:
            Hex-encoded HMAC key.

        Returns
        -------
        str
            Lowercase hex HMAC-SHA256 digest.
        """
        payload = _canonical_json(record_dict)
        key = bytes.fromhex(key_hex)
        return hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()

    @staticmethod
    def generate_license(
        licensee: str,
        features: list[str],
        days_valid: int,
        key_hex: str,
    ) -> dict[str, Any]:
        """Build and sign a license dict ready to persist as JSON.

        Parameters
        ----------
        licensee:
            Name of the licensed entity.
        features:
            List of feature token strings to enable.
        days_valid:
            Number of days from now until expiry.
        key_hex:
            Hex-encoded HMAC key for signing.

        Returns
        -------
        dict
            Complete license dict including ``"signature"``.
        """
        now = time.time()
        record = {
            "licensee": licensee,
            "issued_at": now,
            "expires_at": now + days_valid * 86400,
            "features": sorted(features),
            "license_id": str(uuid.uuid4()),
        }
        record["signature"] = OfflineLicenseValidator.sign_license(record, key_hex)
        return record

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _load_file(self) -> dict[str, Any]:
        try:
            with open(self._license_path, encoding="utf-8") as fh:
                return cast("dict[str, Any]", json.load(fh))
        except FileNotFoundError:
            raise LicenseNotFoundError(f"license file not found: {self._license_path}") from None
        except PermissionError:
            raise LicenseNotFoundError(
                f"permission denied reading license file: {self._license_path}"
            ) from None
        except json.JSONDecodeError as exc:
            raise LicenseNotFoundError(f"license file is not valid JSON: {exc}") from exc

    @staticmethod
    def _parse_record(raw: dict[str, Any]) -> LicenseRecord:
        features_raw = raw["features"]
        if isinstance(features_raw, list):
            features = frozenset(str(f) for f in features_raw)
        else:
            raise ValueError(f"features must be a list, got {type(features_raw).__name__}")

        return LicenseRecord(
            licensee=str(raw["licensee"]),
            issued_at=float(raw["issued_at"]),
            expires_at=float(raw["expires_at"]),
            features=features,
            license_id=str(raw["license_id"]),
            signature=str(raw["signature"]),
        )

    def _verify_signature(self, record: LicenseRecord) -> bool:
        payload = {
            "licensee": record.licensee,
            "issued_at": record.issued_at,
            "expires_at": record.expires_at,
            "features": sorted(record.features),
            "license_id": record.license_id,
        }
        try:
            expected = OfflineLicenseValidator.sign_license(payload, self._license_key_hex)
        except ValueError:
            return False
        return hmac.compare_digest(expected, record.signature)


# ── Utility ───────────────────────────────────────────────────────────────────


def _canonical_json(obj: dict[str, Any]) -> str:
    """Serialize *obj* to canonical JSON with sorted keys, no extra whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))

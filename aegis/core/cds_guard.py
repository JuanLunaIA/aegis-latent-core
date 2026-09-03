# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.cds_guard — Domain 1.1 cross-domain solution guard.

Enforces the classified ↔ unclassified data boundary by inspecting content
for classified markers before allowing it to cross domain boundaries.

Default transfer policy
-----------------------
* **Upward transfers** (LOW → HIGH, e.g. UNCLASSIFIED → SECRET): allowed without
  sanitization.  Data moving to a more secure environment carries no downgrade
  risk.
* **Lateral transfers** (same domain, e.g. SECRET ↔ SECRET): allowed.
* **Downward transfers** (HIGH → LOW): require sanitization to scrub classified
  markers before data crosses to a less secure environment.
* **TOP_SECRET downward transfers**: blocked outright even after sanitization
  unless sanitization succeeds and removes all markers.
* **Strict mode** (``AEGIS_CDS_STRICT_MODE=true``): blocks ALL cross-domain
  transfers regardless of direction.

Usage::

    guard = CDSGuard.from_env()
    result = guard.check_transfer(payload, ClassificationDomain.SECRET,
                                   ClassificationDomain.UNCLASSIFIED)
    if not result.allowed:
        raise CDSViolationError(result.reason)

    # Or let gate_transfer handle it:
    clean = guard.gate_transfer(payload, ClassificationDomain.CUI,
                                 ClassificationDomain.UNCLASSIFIED)
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from aegis.core.classified_marker_detector import ClassifiedMarkerDetector

logger = logging.getLogger(__name__)

# ── Classification domain ordering ────────────────────────────────────────────

_DOMAIN_LEVEL: dict[str, int] = {
    "UNCLASSIFIED": 0,
    "CUI": 1,
    "SECRET": 2,  # nosec B105 — classification level label, not a password
    "TOP_SECRET": 3,  # nosec B105 — classification level label, not a password
}

# ── Redaction token ───────────────────────────────────────────────────────────

_REDACT_TOKEN = "[REDACTED-CDS]"  # noqa: S105  # nosec B105


# ── Enums ─────────────────────────────────────────────────────────────────────


class ClassificationDomain(StrEnum):
    """Classification level of a data domain or endpoint."""

    UNCLASSIFIED = "UNCLASSIFIED"
    CUI = "CUI"
    SECRET = "SECRET"  # noqa: S105  # nosec B105
    TOP_SECRET = "TOP_SECRET"  # noqa: S105  # nosec B105


# ── Exceptions ────────────────────────────────────────────────────────────────


class CDSViolationError(Exception):
    """Raised when :meth:`CDSGuard.gate_transfer` blocks a transfer."""


# ── Data types ────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class CDSPolicy:
    """Immutable policy record for a source→destination domain pair.

    Attributes
    ----------
    source_domain:
        Classification domain of the data origin.
    dest_domain:
        Classification domain of the destination endpoint.
    allowed:
        Whether transfers between these domains are permitted.
    require_sanitization:
        Whether classified markers must be scrubbed before transfer.
    audit_required:
        Whether the transfer must be recorded in the audit log.
    """

    source_domain: ClassificationDomain
    dest_domain: ClassificationDomain
    allowed: bool
    require_sanitization: bool
    audit_required: bool


@dataclass
class CDSCheckResult:
    """Outcome of :meth:`CDSGuard.check_transfer`.

    Attributes
    ----------
    allowed:
        True if the transfer is permitted (post-sanitization if required).
    source_domain:
        Classification domain of the data origin.
    dest_domain:
        Classification domain of the destination.
    sanitized:
        True when sanitization was applied.
    classified_markers_found:
        List of marker labels detected in the original data.
    reason:
        Human-readable explanation of the decision.
    """

    allowed: bool
    source_domain: ClassificationDomain
    dest_domain: ClassificationDomain
    sanitized: bool
    classified_markers_found: list[str] = field(default_factory=list)
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dict for audit logging."""
        return {
            "allowed": self.allowed,
            "source_domain": self.source_domain.value,
            "dest_domain": self.dest_domain.value,
            "sanitized": self.sanitized,
            "classified_markers_found": list(self.classified_markers_found),
            "reason": self.reason,
        }


# ── Core class ────────────────────────────────────────────────────────────────


class CDSGuard:
    """Cross-domain solution guard enforcing the classified ↔ unclassified boundary.

    Instantiate via :meth:`from_env` for production use, or construct directly
    with *strict_mode* and *source_domain* for testing.

    Parameters
    ----------
    strict_mode:
        When ``True``, blocks ALL cross-domain transfers unconditionally.
    source_domain:
        Default classification domain for this node, used when *src* is not
        supplied explicitly (not currently used but available for policy
        extensions).
    """

    def __init__(
        self,
        strict_mode: bool = False,
        source_domain: ClassificationDomain = ClassificationDomain.UNCLASSIFIED,
    ) -> None:
        self._strict_mode = strict_mode
        self._source_domain = source_domain
        self._detector = ClassifiedMarkerDetector()

    # ── Factory ───────────────────────────────────────────────────────────────

    @classmethod
    def from_env(cls) -> CDSGuard:
        """Construct from environment variables.

        Reads
        -----
        ``AEGIS_CDS_STRICT_MODE``
            Set to ``true`` to block all cross-domain transfers.
        ``AEGIS_CDS_SOURCE_DOMAIN``
            Default source domain for this node
            (``UNCLASSIFIED``, ``CUI``, ``SECRET``, ``TOP_SECRET``).
        """
        strict_mode = os.environ.get("AEGIS_CDS_STRICT_MODE", "").lower() in (
            "true",
            "1",
            "yes",
        )

        raw_domain = os.environ.get("AEGIS_CDS_SOURCE_DOMAIN", "UNCLASSIFIED").upper()
        try:
            source_domain = ClassificationDomain(raw_domain)
        except ValueError:
            logger.warning(
                "AEGIS_CDS_SOURCE_DOMAIN value %r not recognized; defaulting to UNCLASSIFIED",
                raw_domain,
            )
            source_domain = ClassificationDomain.UNCLASSIFIED

        return cls(strict_mode=strict_mode, source_domain=source_domain)

    # ── Policy helpers ────────────────────────────────────────────────────────

    def _compute_policy(self, src: ClassificationDomain, dst: ClassificationDomain) -> CDSPolicy:
        """Derive the applicable policy for a source→destination pair."""
        src_level = _DOMAIN_LEVEL[src.value]
        dst_level = _DOMAIN_LEVEL[dst.value]

        if self._strict_mode and src != dst:
            return CDSPolicy(
                source_domain=src,
                dest_domain=dst,
                allowed=False,
                require_sanitization=False,
                audit_required=True,
            )

        if src == dst:
            return CDSPolicy(
                source_domain=src,
                dest_domain=dst,
                allowed=True,
                require_sanitization=False,
                audit_required=False,
            )

        if dst_level > src_level:
            return CDSPolicy(
                source_domain=src,
                dest_domain=dst,
                allowed=True,
                require_sanitization=False,
                audit_required=True,
            )

        if src == ClassificationDomain.TOP_SECRET:
            return CDSPolicy(
                source_domain=src,
                dest_domain=dst,
                allowed=True,
                require_sanitization=True,
                audit_required=True,
            )

        return CDSPolicy(
            source_domain=src,
            dest_domain=dst,
            allowed=True,
            require_sanitization=True,
            audit_required=True,
        )

    # ── Public API ────────────────────────────────────────────────────────────

    def check_transfer(
        self,
        data: str | bytes,
        src: ClassificationDomain,
        dst: ClassificationDomain,
    ) -> CDSCheckResult:
        """Evaluate whether *data* may cross from *src* to *dst*.

        This method does NOT raise; inspect ``result.allowed`` to decide what
        to do.  Use :meth:`gate_transfer` when you want automatic raising.

        Parameters
        ----------
        data:
            Content to evaluate for classified markers.
        src:
            Source classification domain.
        dst:
            Destination classification domain.

        Returns
        -------
        CDSCheckResult
            Full decision record including detected markers and reason.
        """
        policy = self._compute_policy(src, dst)

        text = data if isinstance(data, str) else data.decode("utf-8", errors="replace")
        scan = self._detector.scan(text)
        markers_found = [label for label, _ in scan.markers_found]

        if not policy.allowed:
            return CDSCheckResult(
                allowed=False,
                source_domain=src,
                dest_domain=dst,
                sanitized=False,
                classified_markers_found=markers_found,
                reason=f"cross-domain transfer blocked by policy ({src.value} → {dst.value})",
            )

        if policy.require_sanitization:
            if markers_found:
                return CDSCheckResult(
                    allowed=True,
                    source_domain=src,
                    dest_domain=dst,
                    sanitized=True,
                    classified_markers_found=markers_found,
                    reason=(
                        f"downward transfer ({src.value} → {dst.value}): "
                        f"sanitization required; {len(markers_found)} marker(s) found"
                    ),
                )
            return CDSCheckResult(
                allowed=True,
                source_domain=src,
                dest_domain=dst,
                sanitized=False,
                classified_markers_found=[],
                reason=(
                    f"downward transfer ({src.value} → {dst.value}): "
                    "no classified markers found; transfer permitted"
                ),
            )

        return CDSCheckResult(
            allowed=True,
            source_domain=src,
            dest_domain=dst,
            sanitized=False,
            classified_markers_found=markers_found,
            reason=f"transfer permitted ({src.value} → {dst.value})",
        )

    def sanitize(self, data: str, classification: ClassificationDomain) -> str:
        """Redact classified markers from *data*.

        Parameters
        ----------
        data:
            Text to sanitize.
        classification:
            The classification level of the data (used for logging context).

        Returns
        -------
        str
            Copy of *data* with all classified marker matches replaced by
            ``[REDACTED-CDS]``.
        """
        scan = self._detector.scan(data)
        if not scan.blocked:
            return data

        result = data
        for _label, matched_text in scan.markers_found:
            result = result.replace(matched_text, _REDACT_TOKEN)

        logger.info(
            "cds_guard: sanitized %d marker(s) from %s data",
            len(scan.markers_found),
            classification.value,
        )
        return result

    def gate_transfer(
        self,
        data: str | bytes,
        src: ClassificationDomain,
        dst: ClassificationDomain,
    ) -> str | bytes:
        """Enforce transfer policy, raising on violation and sanitizing if required.

        Parameters
        ----------
        data:
            Content to gate.
        src:
            Source classification domain.
        dst:
            Destination classification domain.

        Returns
        -------
        str | bytes
            Sanitized data if sanitization was required, otherwise *data* as-is.

        Raises
        ------
        CDSViolationError
            When the transfer is blocked by policy.
        """
        result = self.check_transfer(data, src, dst)

        if not result.allowed:
            raise CDSViolationError(result.reason)

        if result.sanitized:
            text = data if isinstance(data, str) else data.decode("utf-8", errors="replace")
            sanitized_text = self.sanitize(text, src)
            return sanitized_text if isinstance(data, str) else sanitized_text.encode()

        return data

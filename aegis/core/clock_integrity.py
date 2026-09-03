# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.clock_integrity — System clock integrity assertion.

Verifies NTP synchronization status at startup and provides per-node clock
drift detection for audit trail timestamps.

21 CFR Part 11 Annex 11 §4.8 and NIST SP 800-53 AU-8 require that
audit timestamps be generated from a trusted time source.  This module:

1. **Startup assertion** — reads NTP sync status from ``timedatectl`` (systemd)
   or ``/proc/driver/rtc`` / ``adjtimex(2)`` on Linux; falls back to a
   warning on platforms where these are unavailable.
2. **Per-node drift check** — compares each audit node timestamp against
   the current system clock and flags nodes where the offset exceeds a
   configurable ``max_drift_seconds`` threshold.

Usage::

    from aegis.core.clock_integrity import ClockIntegrityAssertion

    cia = ClockIntegrityAssertion()
    startup = cia.assert_startup()
    # startup.ntp_synchronized → True/False/None (None = unknown)
    # startup.source            → "timedatectl" | "adjtimex" | "unavailable"
    # startup.warning           → human-readable message if not synced

    drift = cia.check_node_drift(node_timestamp=audit_node.timestamp)
    # drift.drift_seconds → abs(now - node_timestamp)
    # drift.within_tolerance → True/False
"""

from __future__ import annotations

import logging
import shutil
import subprocess  # nosec B404 - subprocess is required to probe host hardening state; every call site uses a fixed argv list, never a shell
import time
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

_DEFAULT_MAX_DRIFT_SECONDS = 5.0
_DEFAULT_MAX_STARTUP_DRIFT_SECONDS = 60.0


@dataclass
class NTPSyncStatus:
    """Result of a startup NTP synchronization check.

    Attributes
    ----------
    ntp_synchronized:
        ``True`` if a trusted time source confirmed sync; ``False`` if
        explicitly not synced; ``None`` if the status could not be determined.
    source:
        Which mechanism reported the status (``"timedatectl"``,
        ``"adjtimex"``, or ``"unavailable"``).
    reference_time:
        System clock reading at the moment of the check (seconds since epoch).
    warning:
        Non-empty when ``ntp_synchronized`` is not ``True``; suitable for
        audit logging.
    raw_output:
        Raw text returned by the probing command, for forensic logging.
    """

    ntp_synchronized: bool | None = None
    source: str = "unavailable"
    reference_time: float = field(default_factory=time.time)
    warning: str = ""
    raw_output: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "ntp_synchronized": self.ntp_synchronized,
            "source": self.source,
            "reference_time": self.reference_time,
            "warning": self.warning,
        }


@dataclass
class ClockDriftResult:
    """Result of a per-node clock drift check.

    Attributes
    ----------
    node_timestamp:
        The timestamp stored in the audit node (seconds since epoch, UTC).
    reference_time:
        The system clock reading at the moment of the check.
    drift_seconds:
        ``abs(reference_time - node_timestamp)``.
    max_drift_seconds:
        The configured tolerance threshold.
    within_tolerance:
        True when ``drift_seconds <= max_drift_seconds``.
    warning:
        Non-empty when ``within_tolerance`` is False.
    """

    node_timestamp: float
    reference_time: float
    drift_seconds: float
    max_drift_seconds: float
    within_tolerance: bool
    warning: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "node_timestamp": self.node_timestamp,
            "reference_time": self.reference_time,
            "drift_seconds": self.drift_seconds,
            "max_drift_seconds": self.max_drift_seconds,
            "within_tolerance": self.within_tolerance,
            "warning": self.warning,
        }


class ClockIntegrityAssertion:
    """Startup NTP sync check and per-node clock drift detector.

    Parameters
    ----------
    max_drift_seconds:
        Maximum accepted abs(now - node_timestamp) in seconds.  Defaults to
        ``5.0`` seconds.  Regulatory environments (21 CFR Part 11) typically
        require timestamps accurate to within 1 second.
    timedatectl_timeout:
        Timeout in seconds for the ``timedatectl`` subprocess call.
    """

    def __init__(
        self,
        max_drift_seconds: float = _DEFAULT_MAX_DRIFT_SECONDS,
        timedatectl_timeout: float = 3.0,
    ) -> None:
        if max_drift_seconds < 0:
            raise ValueError(f"max_drift_seconds must be ≥ 0, got {max_drift_seconds!r}")
        self._max_drift = max_drift_seconds
        self._timedatectl_timeout = timedatectl_timeout

    # ── Startup assertion ────────────────────────────────────────────────────

    def assert_startup(self) -> NTPSyncStatus:
        """Check NTP synchronization status at startup.

        Tries ``timedatectl show`` first (systemd), then ``adjtimex`` via
        ctypes, then returns ``source="unavailable"`` with a warning.

        This method should be called once during application startup and the
        result logged to the audit trail.
        """
        status = self._check_timedatectl()
        if status is not None:
            self._log_status(status)
            return status

        status = self._check_adjtimex()
        if status is not None:
            self._log_status(status)
            return status

        status = NTPSyncStatus(
            ntp_synchronized=None,
            source="unavailable",
            warning=(
                "NTP sync status could not be determined: timedatectl and adjtimex both unavailable"
            ),
        )
        logger.warning("clock_integrity: %s", status.warning)
        return status

    # ── Per-node drift check ─────────────────────────────────────────────────

    def check_node_drift(
        self,
        node_timestamp: float,
        *,
        reference_time: float | None = None,
    ) -> ClockDriftResult:
        """Check whether a node's timestamp is within the drift tolerance.

        Parameters
        ----------
        node_timestamp:
            The ``timestamp`` field from an :class:`~aegis.core.crypto_audit.AuditNode`.
        reference_time:
            Override the "now" reference (seconds since epoch).  Defaults to
            ``time.time()``; override in tests for determinism.
        """
        now = reference_time if reference_time is not None else time.time()
        drift = abs(now - node_timestamp)
        within = drift <= self._max_drift
        warning = (
            f"clock drift {drift:.3f}s exceeds tolerance {self._max_drift}s" if not within else ""
        )
        if warning:
            logger.warning("clock_integrity: node_timestamp=%.3f %s", node_timestamp, warning)
        return ClockDriftResult(
            node_timestamp=node_timestamp,
            reference_time=now,
            drift_seconds=drift,
            max_drift_seconds=self._max_drift,
            within_tolerance=within,
            warning=warning,
        )

    # ── Internal probing methods ─────────────────────────────────────────────

    def _check_timedatectl(self) -> NTPSyncStatus | None:
        """Run ``timedatectl show`` and parse ``NTPSynchronized=``."""
        try:
            proc = subprocess.run(  # nosec B603 - argv list built from literals and configuration, never from request data; shell=False throughout
                [shutil.which("timedatectl") or "timedatectl", "show"],
                capture_output=True,
                text=True,
                timeout=self._timedatectl_timeout,
            )
            if proc.returncode != 0:
                return None
            output = proc.stdout
            for line in output.splitlines():
                if line.startswith("NTPSynchronized="):
                    value = line.split("=", 1)[1].strip().lower()
                    synced = value == "yes"
                    warning = "" if synced else "NTP is not synchronized (timedatectl)"
                    return NTPSyncStatus(
                        ntp_synchronized=synced,
                        source="timedatectl",
                        warning=warning,
                        raw_output=output,
                    )
            # timedatectl ran but NTPSynchronized not in output (e.g., old version)
            return NTPSyncStatus(
                ntp_synchronized=None,
                source="timedatectl",
                warning="timedatectl output did not contain NTPSynchronized field",
                raw_output=output,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None
        except Exception as exc:
            logger.debug("clock_integrity: timedatectl probe failed: %s", exc)
            return None

    def _check_adjtimex(self) -> NTPSyncStatus | None:
        """Use ``adjtimex(2)`` via ctypes to check TIME_OK / TIME_INS / TIME_DEL.

        The kernel ``adjtimex`` call returns a status code:
        * 0 = TIME_OK  — clock synchronized
        * 1 = TIME_INS — insert leap second
        * 2 = TIME_DEL — delete leap second
        * 3 = TIME_OOP — leap second in progress
        * 4 = TIME_WAIT — leap second just occurred
        * 5 = TIME_ERROR / TIME_BAD — clock not synchronized

        Statuses 0–4 indicate a synchronized (or recently synced) clock.
        Status 5 (TIME_ERROR) means the clock is not trusted.
        """
        try:
            import ctypes
            import ctypes.util
            import sys as _sys

            if _sys.platform != "linux":
                return None

            libc_path = ctypes.util.find_library("c")
            if not libc_path:
                return None
            libc = ctypes.CDLL(libc_path, use_errno=True)

            # struct timex is large; we only need the first int (modes) and
            # the return value.  Pass a zeroed 200-byte buffer (more than enough).
            buf = ctypes.create_string_buffer(200)
            ret = libc.adjtimex(buf)

            # ret < 0 means error; ret == 5 means TIME_ERROR (not synced)
            synced = 0 <= ret <= 4
            warning = (
                "" if synced else f"adjtimex returned TIME_ERROR ({ret}); clock not synchronized"
            )
            return NTPSyncStatus(
                ntp_synchronized=synced,
                source="adjtimex",
                warning=warning,
                raw_output=f"adjtimex_return={ret}",
            )
        except Exception as exc:
            logger.debug("clock_integrity: adjtimex probe failed: %s", exc)
            return None

    @staticmethod
    def _log_status(status: NTPSyncStatus) -> None:
        if status.ntp_synchronized is True:
            logger.info(
                "clock_integrity: NTP synchronized via %s at %.3f",
                status.source,
                status.reference_time,
            )
        else:
            logger.warning(
                "clock_integrity: %s (source=%s)",
                status.warning or "NTP status unknown",
                status.source,
            )

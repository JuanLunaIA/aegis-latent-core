# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.intermittent_connectivity — WAL backpressure monitor for disconnected ops.

In intermittent-connectivity deployments (OT edge nodes, air-gapped industrial
controllers) the local WAL queues audit events indefinitely while the upstream
control plane is unreachable.  This module provides a :class:`WALBackpressureMonitor`
that inspects the on-disk WAL depth (entry count and byte size) and signals a
backpressure condition when either threshold is exceeded.

Backpressure signal
-------------------
When active the monitor raises :data:`BackpressureStatus.active` and emits the
``aegis_wal_backpressure_active`` Prometheus Gauge (value 1).  Callers should
propagate the signal upstream (e.g., HTTP ``Retry-After`` header, 503 with
``Backpressure: true``, or an out-of-band control-plane notification) so that
originating systems can shed load until the WAL drains.

Configuration
-------------
``AEGIS_WAL_BACKPRESSURE_THRESHOLD``
    Maximum WAL entry count before backpressure activates.  Default ``1000``.
``AEGIS_WAL_BACKPRESSURE_BYTES``
    Maximum total WAL size in bytes before backpressure activates.  Default
    ``104857600`` (100 MiB).

Usage::

    from aegis.core.intermittent_connectivity import WALBackpressureMonitor

    monitor = WALBackpressureMonitor(wal_path="/var/aegis/audit.wal")
    status = monitor.check()
    if status.active:
        # propagate backpressure upstream
        pass
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

_DEFAULT_ENTRY_THRESHOLD = 1_000
_DEFAULT_BYTES_THRESHOLD = 100 * 1024 * 1024  # 100 MiB

try:
    from prometheus_client import Gauge as _Gauge

    _BACKPRESSURE_GAUGE: _Gauge | None = _Gauge(
        "aegis_wal_backpressure_active",
        "1 when WAL backpressure is active (queue depth exceeds threshold), 0 otherwise",
    )
except Exception:  # pragma: no cover — prometheus_client absent in some envs
    _BACKPRESSURE_GAUGE = None


# ── Data classes ──────────────────────────────────────────────────────────────


@dataclass
class BackpressureStatus:
    """Result of :meth:`WALBackpressureMonitor.check`.

    Attributes
    ----------
    active:
        ``True`` when backpressure should be signalled upstream.
    entry_count:
        Total WAL entries counted across all segments.
    entry_threshold:
        Entry count at which backpressure activates.
    size_bytes:
        Total on-disk WAL size in bytes across all segments.
    size_threshold_bytes:
        Byte threshold at which backpressure activates.
    signal_reasons:
        Human-readable list of threshold(s) exceeded.
    wal_path:
        Canonical WAL path that was inspected.
    """

    active: bool
    entry_count: int
    entry_threshold: int
    size_bytes: int
    size_threshold_bytes: int
    signal_reasons: list[str] = field(default_factory=list)
    wal_path: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "active": self.active,
            "entry_count": self.entry_count,
            "entry_threshold": self.entry_threshold,
            "size_bytes": self.size_bytes,
            "size_threshold_bytes": self.size_threshold_bytes,
            "signal_reasons": self.signal_reasons,
            "wal_path": self.wal_path,
        }


# ── Monitor ───────────────────────────────────────────────────────────────────


class WALBackpressureMonitor:
    """Monitor WAL depth and signal backpressure when thresholds are exceeded.

    Parameters
    ----------
    wal_path:
        Path to the active WAL file (JSONL).  Rotated segments at
        ``<wal_path>.NNNNNN`` are included in depth calculations.
    entry_threshold:
        Maximum entry count before backpressure activates.  Defaults to
        ``AEGIS_WAL_BACKPRESSURE_THRESHOLD`` (default ``1000``).
    bytes_threshold:
        Maximum total WAL bytes before backpressure activates.  Defaults to
        ``AEGIS_WAL_BACKPRESSURE_BYTES`` (default 100 MiB).
    """

    def __init__(
        self,
        wal_path: str,
        entry_threshold: int | None = None,
        bytes_threshold: int | None = None,
    ) -> None:
        self.wal_path = wal_path

        if entry_threshold is None:
            raw = os.environ.get("AEGIS_WAL_BACKPRESSURE_THRESHOLD", str(_DEFAULT_ENTRY_THRESHOLD))
            try:
                entry_threshold = max(1, int(raw))
            except ValueError:
                logger.warning(
                    "intermittent_connectivity: invalid AEGIS_WAL_BACKPRESSURE_THRESHOLD=%r; "
                    "using %d",
                    raw,
                    _DEFAULT_ENTRY_THRESHOLD,
                )
                entry_threshold = _DEFAULT_ENTRY_THRESHOLD
        self.entry_threshold = max(1, entry_threshold)

        if bytes_threshold is None:
            raw = os.environ.get("AEGIS_WAL_BACKPRESSURE_BYTES", str(_DEFAULT_BYTES_THRESHOLD))
            try:
                bytes_threshold = max(1, int(raw))
            except ValueError:
                logger.warning(
                    "intermittent_connectivity: invalid AEGIS_WAL_BACKPRESSURE_BYTES=%r; using %d",
                    raw,
                    _DEFAULT_BYTES_THRESHOLD,
                )
                bytes_threshold = _DEFAULT_BYTES_THRESHOLD
        self.bytes_threshold = max(1, bytes_threshold)

    # ── Public API ─────────────────────────────────────────────────────────────

    def check(self) -> BackpressureStatus:
        """Inspect the WAL and return the current backpressure status.

        Counts entries and total bytes across the active WAL and all rotated
        segments (``<wal_path>.NNNNNN``).  Never raises: any I/O error is
        logged and the affected file is skipped.

        Returns
        -------
        BackpressureStatus
            ``active=True`` when either threshold is breached.
        """
        paths = self._all_segment_paths()
        entry_count = 0
        size_bytes = 0

        for path in paths:
            ec, sb = self._inspect_file(path)
            entry_count += ec
            size_bytes += sb

        reasons: list[str] = []
        if entry_count >= self.entry_threshold:
            reasons.append(f"entry_count={entry_count} >= threshold={self.entry_threshold}")
        if size_bytes >= self.bytes_threshold:
            reasons.append(f"size_bytes={size_bytes} >= threshold={self.bytes_threshold}")

        active = bool(reasons)
        status = BackpressureStatus(
            active=active,
            entry_count=entry_count,
            entry_threshold=self.entry_threshold,
            size_bytes=size_bytes,
            size_threshold_bytes=self.bytes_threshold,
            signal_reasons=reasons,
            wal_path=self.wal_path,
        )

        self._emit_metric(active)

        if active:
            logger.warning(
                "intermittent_connectivity: backpressure ACTIVE — %s",
                "; ".join(reasons),
            )
        else:
            logger.debug(
                "intermittent_connectivity: backpressure OK (entries=%d/%d, bytes=%d/%d)",
                entry_count,
                self.entry_threshold,
                size_bytes,
                self.bytes_threshold,
            )

        return status

    # ── Internal ───────────────────────────────────────────────────────────────

    def _all_segment_paths(self) -> list[str]:
        """Return rotated segments (ascending) + active WAL, each only if it exists."""
        segments: list[str] = []
        # Rotated segments follow the naming convention <wal_path>.NNNNNN
        base_dir = os.path.dirname(self.wal_path) or "."
        base_name = os.path.basename(self.wal_path)
        try:
            entries = sorted(os.listdir(base_dir))
        except OSError:
            entries = []

        prefix = base_name + "."
        for entry in entries:
            if entry.startswith(prefix):
                suffix = entry[len(prefix) :]
                if suffix.isdigit():
                    segments.append(os.path.join(base_dir, entry))

        if os.path.exists(self.wal_path):
            segments.append(self.wal_path)

        return segments

    def _inspect_file(self, path: str) -> tuple[int, int]:
        """Return ``(entry_count, size_bytes)`` for a single WAL segment.

        Counts non-empty lines as entries (JSONL format).  Returns ``(0, 0)``
        on any I/O error.
        """
        try:
            stat = os.stat(path)
            size_bytes = stat.st_size
        except OSError as exc:
            logger.debug("intermittent_connectivity: cannot stat %s: %s", path, exc)
            return 0, 0

        entry_count = 0
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if line.strip():
                        entry_count += 1
        except OSError as exc:
            logger.debug("intermittent_connectivity: cannot read %s: %s", path, exc)
            return 0, size_bytes

        return entry_count, size_bytes

    @staticmethod
    def _emit_metric(active: bool) -> None:
        if _BACKPRESSURE_GAUGE is not None:
            try:
                _BACKPRESSURE_GAUGE.set(1 if active else 0)
            except Exception as exc:  # pragma: no cover
                logger.debug("intermittent_connectivity: prometheus metric emit failed: %s", exc)

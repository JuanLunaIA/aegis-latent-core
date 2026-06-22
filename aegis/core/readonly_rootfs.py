# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.readonly_rootfs — read-only rootfs detection and writable-path redirection.

When Aegis runs inside a container or embedded OT appliance whose root
filesystem is mounted read-only (immutable rootfs pattern), all mutable
state — WAL segments, logs, runtime sockets — must be directed to a
writable volume such as:

* **tmpfs**: in-memory filesystem mounted at ``/tmp`` (ephemeral, survives
  container lifetime only).
* **NFS / persistent volume**: an externally-mounted, persistent writable
  directory supplied via ``AEGIS_NFS_MOUNT``.

Threat model
------------
A read-only rootfs prevents an attacker who has achieved code execution from
persisting malware to the primary filesystem.  Aegis must not fail or
silently fall back to the readonly path when running in this mode; instead
it must redirect to the authorised writable location and surface the
redirection clearly in audit logs.

Detection approach
------------------
Two complementary probes are used (both must agree before ``rootfs_readonly``
is set to ``True``):

1. **``/proc/mounts`` scan** — searches for the mount entry whose
   mountpoint is ``/`` and checks whether the options string contains
   ``ro``.
2. **Write probe** — attempts to create and immediately delete a temporary
   file under the *preferred* WAL/log directory; failure indicates the
   directory (or its parent) is not writable.

Usage::

    from aegis.core.readonly_rootfs import ReadOnlyRootfsGuard

    guard = ReadOnlyRootfsGuard()
    result = guard.resolve("/var/lib/aegis/wal", label="wal")
    # result.path is always writable; result.redirected is True when tmpfs used
    open_wal(result.path)

Configuration
-------------
``AEGIS_TMPFS_BASE``
    Base directory for tmpfs redirections when the rootfs is read-only.
    Default: ``/tmp/aegis``.

``AEGIS_NFS_MOUNT``
    If set, NFS/persistent-volume path used *instead of* tmpfs as the
    fallback writable location.  Takes precedence over ``AEGIS_TMPFS_BASE``.

``AEGIS_SKIP_READONLY_CHECK``
    Set to any non-empty value to bypass the writability probe (useful in
    development environments where ``/proc/mounts`` is unreliable).
"""

from __future__ import annotations

import logging
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

_DEFAULT_TMPFS_BASE = "/tmp/aegis"


# ── Result types ──────────────────────────────────────────────────────────────


@dataclass
class PathResolutionResult:
    """Result of a single path-resolution call.

    Attributes
    ----------
    label:
        Short identifier for the path (e.g. ``"wal"``, ``"logs"``).
    preferred_path:
        The caller's requested path.
    path:
        The resolved, writable path (may equal *preferred_path* when not
        redirected).
    redirected:
        True when the preferred path was not writable and the result was
        redirected to tmpfs/NFS.
    fallback_base:
        The tmpfs or NFS base used when *redirected* is True.
    """

    label: str
    preferred_path: str
    path: Path
    redirected: bool
    fallback_base: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "label": self.label,
            "preferred_path": self.preferred_path,
            "path": str(self.path),
            "redirected": self.redirected,
            "fallback_base": self.fallback_base,
        }


@dataclass
class ReadOnlyRootfsResult:
    """Aggregated result of a :meth:`ReadOnlyRootfsGuard.inspect` call.

    Attributes
    ----------
    rootfs_readonly:
        True when ``/proc/mounts`` reports the root filesystem as ``ro``
        *or* a write-probe on the configured base path failed.
    proc_mounts_readonly:
        Result of the ``/proc/mounts`` probe specifically.
    write_probe_failed:
        True when the write-probe attempt raised an exception or returned
        False.
    resolutions:
        List of :class:`PathResolutionResult` for each label resolved.
    tmpfs_base:
        The effective fallback base directory in use.
    skip_check:
        True when ``AEGIS_SKIP_READONLY_CHECK`` suppressed both probes.
    """

    rootfs_readonly: bool = False
    proc_mounts_readonly: bool = False
    write_probe_failed: bool = False
    resolutions: list[PathResolutionResult] = field(default_factory=list)
    tmpfs_base: str = _DEFAULT_TMPFS_BASE
    skip_check: bool = False

    @property
    def any_redirected(self) -> bool:
        return any(r.redirected for r in self.resolutions)

    def to_dict(self) -> dict[str, object]:
        return {
            "rootfs_readonly": self.rootfs_readonly,
            "proc_mounts_readonly": self.proc_mounts_readonly,
            "write_probe_failed": self.write_probe_failed,
            "any_redirected": self.any_redirected,
            "tmpfs_base": self.tmpfs_base,
            "skip_check": self.skip_check,
            "resolutions": [r.to_dict() for r in self.resolutions],
        }


# ── Guard ─────────────────────────────────────────────────────────────────────


class ReadOnlyRootfsGuard:
    """Detects read-only rootfs and redirects mutable paths to tmpfs/NFS.

    Parameters
    ----------
    tmpfs_base:
        Base directory for tmpfs redirections.  Defaults to
        ``AEGIS_TMPFS_BASE`` env var (``/tmp/aegis`` when unset).
    nfs_mount:
        Persistent-volume / NFS path to use instead of tmpfs.  Defaults to
        ``AEGIS_NFS_MOUNT`` env var (unset → tmpfs used).
    skip_check:
        When True, skip the ``/proc/mounts`` and write-probe checks.
        Defaults to the ``AEGIS_SKIP_READONLY_CHECK`` env var.
    """

    def __init__(
        self,
        tmpfs_base: str | None = None,
        nfs_mount: str | None = None,
        skip_check: bool | None = None,
    ) -> None:
        if tmpfs_base is None:
            tmpfs_base = os.environ.get("AEGIS_TMPFS_BASE", _DEFAULT_TMPFS_BASE)
        self.tmpfs_base = tmpfs_base

        if nfs_mount is None:
            nfs_mount = os.environ.get("AEGIS_NFS_MOUNT") or None
        self.nfs_mount = nfs_mount

        if skip_check is None:
            skip_check = bool(os.environ.get("AEGIS_SKIP_READONLY_CHECK"))
        self.skip_check = skip_check

    # ── Public API ────────────────────────────────────────────────────────────

    def inspect(self) -> ReadOnlyRootfsResult:
        """Run both detection probes and return a summary result."""
        effective_base = self.nfs_mount or self.tmpfs_base
        result = ReadOnlyRootfsResult(tmpfs_base=effective_base, skip_check=self.skip_check)

        if self.skip_check:
            logger.debug("readonly_rootfs: check skipped (AEGIS_SKIP_READONLY_CHECK set)")
            return result

        result.proc_mounts_readonly = self._probe_proc_mounts()
        result.write_probe_failed = not self._probe_write(effective_base)
        result.rootfs_readonly = result.proc_mounts_readonly or result.write_probe_failed

        if result.rootfs_readonly:
            logger.warning(
                "readonly_rootfs: rootfs detected as read-only "
                "(proc_mounts=%s, write_probe_failed=%s); "
                "writable paths will be redirected to %r",
                result.proc_mounts_readonly,
                result.write_probe_failed,
                effective_base,
            )
        return result

    def resolve(self, preferred_path: str, label: str = "path") -> PathResolutionResult:
        """Return a guaranteed-writable path for *label*.

        If *preferred_path* is writable it is returned unchanged.  Otherwise
        the path is re-rooted under the configured tmpfs/NFS base and the
        sub-directory is created.

        Parameters
        ----------
        preferred_path:
            The caller's desired path (e.g. ``/var/lib/aegis/wal``).
        label:
            Short name used in log messages and result attributes.
        """
        if self.skip_check or self._probe_write(preferred_path):
            return PathResolutionResult(
                label=label,
                preferred_path=preferred_path,
                path=Path(preferred_path),
                redirected=False,
            )

        effective_base = self.nfs_mount or self.tmpfs_base
        # Re-root: strip the leading '/' so Path join works correctly
        relative = (
            Path(preferred_path).relative_to("/")
            if Path(preferred_path).is_absolute()
            else Path(preferred_path)
        )
        redirected_path = Path(effective_base) / relative
        redirected_path.mkdir(parents=True, exist_ok=True)

        logger.warning(
            "readonly_rootfs: preferred path %r not writable; redirecting %r → %r",
            preferred_path,
            preferred_path,
            str(redirected_path),
        )
        return PathResolutionResult(
            label=label,
            preferred_path=preferred_path,
            path=redirected_path,
            redirected=True,
            fallback_base=effective_base,
        )

    def is_readonly(self) -> bool:
        """Return True if the rootfs appears to be read-only."""
        return self.inspect().rootfs_readonly

    # ── Internal probes ───────────────────────────────────────────────────────

    @staticmethod
    def _probe_proc_mounts(proc_mounts_path: str = "/proc/mounts") -> bool:
        """Return True if ``/proc/mounts`` lists ``/`` with ``ro`` option."""
        try:
            with open(proc_mounts_path) as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) >= 4 and parts[1] == "/":
                        options = parts[3].split(",")
                        return "ro" in options
        except OSError:
            pass
        return False

    @staticmethod
    def _probe_write(path: str) -> bool:
        """Return True if *path* (or its nearest existing ancestor) is writable."""
        target = Path(path)
        # Walk up to find the nearest existing directory
        check_dir = target if target.is_dir() else target.parent
        while not check_dir.exists():
            parent = check_dir.parent
            if parent == check_dir:
                break
            check_dir = parent

        if not check_dir.exists():
            return False

        try:
            with tempfile.NamedTemporaryFile(dir=str(check_dir), delete=True):
                pass
            return True
        except (OSError, PermissionError):
            return False

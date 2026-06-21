# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.waf_hot_reload — WAF pattern hot-reload without process restart.

Operators can push new WAF patterns to a JSON file on disk; the
:class:`WAFHotReloader` picks up the change within one event cycle and
atomically replaces the running pattern set — zero-downtime rule updates.

File watching mechanism
-----------------------
On Linux (the production target) the reloader uses the kernel's **inotify**
API (via ``ctypes``) to receive file-system events with millisecond latency.
Watched events: ``IN_CLOSE_WRITE``, ``IN_MOVED_TO``, ``IN_MODIFY``.

On non-Linux systems (tests, macOS dev boxes) or when the inotify syscall is
unavailable, the reloader falls back to ``os.stat()`` mtime polling on a
configurable interval (default 1 s).

Pattern file schema (JSON)
--------------------------
.. code-block:: json

    {
        "version": 2,
        "critical": [
            "ignore\\\\b.{0,20}?\\\\bprevious\\\\b.{0,20}?\\\\binstructions?",
            "system[\\\\s\\\\-_]*override"
        ],
        "soft": [
            "hypothetically",
            "pretend you are"
        ]
    }

- ``version`` (int, optional): monotonically increasing schema version for audit.
- ``critical`` (list[str]): regex patterns compiled with ``re.IGNORECASE | re.DOTALL``.
  Any match immediately blocks the request.
- ``soft`` (list[str]): weighted signal patterns fed to the aggregation layer.

Usage::

    def on_new_patterns(ps: WAFPatternSet) -> None:
        waf._critical_patterns = ps.critical  # atomic swap

    reloader = WAFHotReloader(
        path="/etc/aegis/waf_patterns.json",
        on_reload=on_new_patterns,
        poll_interval_s=0.5,
    )
    reloader.start()
    # ... serve traffic ...
    reloader.stop()
"""

from __future__ import annotations

import ctypes
import ctypes.util
import json
import logging
import os
import re
import select
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# ── inotify constants ─────────────────────────────────────────────────────────

_IN_MODIFY: int = 0x00000002
_IN_CLOSE_WRITE: int = 0x00000008
_IN_MOVED_TO: int = 0x00000080
_INOTIFY_MASK: int = _IN_CLOSE_WRITE | _IN_MOVED_TO | _IN_MODIFY
_O_NONBLOCK: int = 0x00000800

_PATTERN_FLAGS = re.IGNORECASE | re.DOTALL

# ── inotify helpers ───────────────────────────────────────────────────────────


def _load_libc() -> ctypes.CDLL | None:
    libc_name = ctypes.util.find_library("c")
    if libc_name is None:
        return None
    try:
        return ctypes.CDLL(libc_name, use_errno=True)
    except OSError:
        return None


def _inotify_available() -> bool:
    """Return True if the inotify kernel interface is accessible."""
    libc = _load_libc()
    return libc is not None and hasattr(libc, "inotify_init1")


def _inotify_init() -> int:
    """Call ``inotify_init1(O_NONBLOCK)``; return the fd or -1 on error."""
    libc = _load_libc()
    if libc is None or not hasattr(libc, "inotify_init1"):
        return -1
    libc.inotify_init1.restype = ctypes.c_int
    libc.inotify_init1.argtypes = [ctypes.c_int]
    return int(libc.inotify_init1(_O_NONBLOCK))


def _inotify_add_watch(fd: int, path: str) -> int:
    """Add an inotify watch for *path*; return the watch descriptor or -1."""
    libc = _load_libc()
    if libc is None or not hasattr(libc, "inotify_add_watch"):
        return -1
    libc.inotify_add_watch.restype = ctypes.c_int
    libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
    return int(libc.inotify_add_watch(fd, path.encode(), _INOTIFY_MASK))


# ── Data classes ──────────────────────────────────────────────────────────────


@dataclass
class WAFPatternSet:
    """A compiled set of WAF patterns loaded from a pattern file.

    Attributes
    ----------
    critical:
        Compiled critical regex patterns.  Any match is an immediate block.
    soft:
        Compiled soft/weighted signal patterns.
    source_path:
        Absolute path to the JSON file the patterns were loaded from.
    loaded_at:
        Unix timestamp when this set was loaded.
    version:
        Schema version from the JSON file (default 1).
    """

    critical: list[re.Pattern[str]]
    soft: list[re.Pattern[str]]
    source_path: str
    loaded_at: float = field(default_factory=time.time)
    version: int = 1

    def to_dict(self) -> dict[str, object]:
        return {
            "critical_count": len(self.critical),
            "soft_count": len(self.soft),
            "source_path": self.source_path,
            "loaded_at": self.loaded_at,
            "version": self.version,
        }


# ── Pattern file I/O ──────────────────────────────────────────────────────────


class WAFPatternFileError(ValueError):
    """Raised when a pattern file fails validation or compilation."""


def load_pattern_file(path: str) -> WAFPatternSet:
    """Load and compile WAF patterns from *path* (JSON).

    Parameters
    ----------
    path:
        Path to the JSON pattern file.

    Returns
    -------
    WAFPatternSet
        Compiled critical + soft patterns.

    Raises
    ------
    WAFPatternFileError
        If the file does not exist, cannot be parsed as JSON, or contains
        patterns that fail :func:`re.compile`.
    FileNotFoundError
        If *path* does not exist.
    """
    abs_path = os.path.abspath(path)
    try:
        with open(abs_path) as fh:
            data = json.load(fh)
    except FileNotFoundError:
        raise
    except (OSError, json.JSONDecodeError) as exc:
        raise WAFPatternFileError(f"Cannot read pattern file {path!r}: {exc}") from exc

    if not isinstance(data, dict):
        raise WAFPatternFileError(f"Pattern file must be a JSON object, got {type(data).__name__}")

    version = int(data.get("version", 1))
    critical_raw = data.get("critical", [])
    soft_raw = data.get("soft", [])

    if not isinstance(critical_raw, list) or not isinstance(soft_raw, list):
        raise WAFPatternFileError("'critical' and 'soft' must be JSON arrays")

    def _compile_list(patterns: list[object], label: str) -> list[re.Pattern[str]]:
        compiled: list[re.Pattern[str]] = []
        for i, p in enumerate(patterns):
            if not isinstance(p, str):
                raise WAFPatternFileError(f"{label}[{i}] must be a string, got {type(p).__name__}")
            try:
                compiled.append(re.compile(p, _PATTERN_FLAGS))
            except re.error as exc:
                raise WAFPatternFileError(f"Invalid regex in {label}[{i}] {p!r}: {exc}") from exc
        return compiled

    critical = _compile_list(critical_raw, "critical")
    soft = _compile_list(soft_raw, "soft")

    return WAFPatternSet(
        critical=critical,
        soft=soft,
        source_path=abs_path,
        loaded_at=time.time(),
        version=version,
    )


# ── Hot-reloader ──────────────────────────────────────────────────────────────


class WAFHotReloader:
    """Background file watcher that reloads WAF patterns on change.

    Parameters
    ----------
    path:
        Path to the JSON pattern file to watch.
    on_reload:
        Callback invoked (in the watcher thread) whenever a new
        :class:`WAFPatternSet` is successfully loaded.  The callback must be
        thread-safe — typical usage is to do an atomic assignment:
        ``waf._critical_patterns = ps.critical``.
    poll_interval_s:
        Fallback mtime-poll interval in seconds when inotify is unavailable.
        Also used as the ``select()`` timeout in inotify mode so that the
        stop event is checked regularly.  Default ``1.0``.
    """

    def __init__(
        self,
        path: str,
        on_reload: Callable[[WAFPatternSet], None],
        poll_interval_s: float = 1.0,
    ) -> None:
        if poll_interval_s <= 0:
            raise ValueError(f"poll_interval_s must be > 0, got {poll_interval_s!r}")
        self._path = os.path.abspath(path)
        self._on_reload = on_reload
        self._poll_interval = poll_interval_s
        self._current: WAFPatternSet | None = None
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._use_inotify: bool = _inotify_available()

    # ── Public API ─────────────────────────────────────────────────────────

    def start(self) -> None:
        """Load patterns immediately, then start the background watcher.

        Idempotent: calling :meth:`start` on an already-running reloader is a
        no-op.
        """
        if self._thread is not None and self._thread.is_alive():
            return
        self.reload_now()
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._watch_loop,
            daemon=True,
            name=f"waf-hot-reload:{os.path.basename(self._path)}",
        )
        self._thread.start()
        logger.info(
            "WAFHotReloader started: watching %s (mechanism=%s, interval=%.2fs)",
            self._path,
            "inotify" if self._use_inotify else "poll",
            self._poll_interval,
        )

    def stop(self, timeout: float = 5.0) -> None:
        """Signal the watcher thread to stop and wait for it to exit."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None

    def reload_now(self) -> WAFPatternSet:
        """Force an immediate synchronous reload from the pattern file.

        Returns
        -------
        WAFPatternSet
            The newly loaded pattern set.

        Raises
        ------
        WAFPatternFileError
            If the file cannot be loaded or compiled.
        FileNotFoundError
            If the path does not exist.
        """
        ps = load_pattern_file(self._path)
        with self._lock:
            self._current = ps
        self._on_reload(ps)
        logger.info(
            "WAFHotReloader: reloaded %d critical + %d soft patterns from %s (v%d)",
            len(ps.critical),
            len(ps.soft),
            self._path,
            ps.version,
        )
        return ps

    @property
    def current(self) -> WAFPatternSet | None:
        """The most recently loaded :class:`WAFPatternSet`, or ``None`` before first load."""
        with self._lock:
            return self._current

    @property
    def is_running(self) -> bool:
        """True when the background watcher thread is alive."""
        return self._thread is not None and self._thread.is_alive()

    # ── Internal ───────────────────────────────────────────────────────────

    def _watch_loop(self) -> None:
        if self._use_inotify:
            self._inotify_loop()
        else:
            self._poll_loop()

    def _poll_loop(self) -> None:
        last_mtime = self._get_mtime()
        while not self._stop_event.wait(self._poll_interval):
            mtime = self._get_mtime()
            if mtime != last_mtime:
                last_mtime = mtime
                self._safe_reload()

    def _inotify_loop(self) -> None:
        fd = _inotify_init()
        if fd < 0:
            logger.warning(
                "WAFHotReloader: inotify_init failed (errno=%d); falling back to poll",
                ctypes.get_errno(),
            )
            self._poll_loop()
            return
        try:
            wd = _inotify_add_watch(fd, self._path)
            if wd < 0:
                logger.warning(
                    "WAFHotReloader: inotify_add_watch failed (errno=%d); falling back to poll",
                    ctypes.get_errno(),
                )
                os.close(fd)
                self._poll_loop()
                return
            while not self._stop_event.is_set():
                try:
                    readable, _, _ = select.select([fd], [], [], self._poll_interval)
                    if readable:
                        os.read(fd, 4096)  # drain events
                        self._safe_reload()
                except (OSError, ValueError):
                    break
        finally:
            try:
                os.close(fd)
            except OSError:
                pass

    def _safe_reload(self) -> None:
        try:
            self.reload_now()
        except Exception as exc:
            logger.warning("WAFHotReloader: reload failed — keeping old patterns: %s", exc)

    def _get_mtime(self) -> float:
        try:
            return os.stat(self._path).st_mtime
        except OSError:
            return 0.0

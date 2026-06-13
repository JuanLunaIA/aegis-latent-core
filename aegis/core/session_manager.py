"""
session_manager.py - Session Lifecycle & Isolation Layer

Provides a centralized manager for telemetry monitors to ensure strict isolation
between concurrent users/sessions, preventing EMA contamination.

FIX BUG-05: The original implementation had a memory leak — sessions were
inserted into _sessions but terminate_session() was never called by any internal
code path.  In high-throughput scenarios (e.g. one UUID per HTTP request) the
dict would grow without bound until process OOM.

Fix: bounded LRU cache via collections.OrderedDict.  When max_sessions is
reached, the least-recently-used session is evicted automatically.  Callers
that require explicit lifecycle control can still call terminate_session().
The LRU contract is documented so that callers are not surprised by eviction.
"""

# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import threading
import uuid
from collections import OrderedDict

from aegis.core.telemetry import LogitEntropyMonitor


class SessionLifecycleManager:
    """
    Thread-safe, LRU-bounded manager for per-session LogitEntropyMonitor
    instances.

    Parameters
    ----------
    max_sessions : int
        Maximum number of concurrent sessions held in memory.  When the cap is
        reached the least-recently-used session is evicted before inserting the
        new one.  Default: 1 000.

    Notes
    -----
    - Session monitors are isolated: each session has its own EMA state.
    - Eviction is silent.  If a caller retains a reference to an evicted
      monitor the monitor remains valid; only the manager's internal mapping is
      removed.
    - Thread-safe: a single RLock guards all mutations.
    """

    def __init__(self, max_sessions: int = 1_000) -> None:
        if max_sessions < 1:
            raise ValueError("max_sessions must be >= 1")
        self._max_sessions = max_sessions
        # OrderedDict preserves insertion/access order for O(1) LRU ops.
        self._sessions: OrderedDict[str, LogitEntropyMonitor] = OrderedDict()
        self._lock = threading.RLock()

    def get_monitor(
        self,
        session_id: str | None = None,
        ema_alpha: float = 0.1,
    ) -> tuple[str, LogitEntropyMonitor]:
        """
        Retrieve or create the monitor for *session_id*.

        Accessing an existing session moves it to the MRU position, resetting
        its eviction priority.

        Args:
            session_id: Caller-supplied session key.  A UUID-4 is generated when
                        None is passed.
            ema_alpha:  Smoothing factor for newly-created monitors.  Ignored
                        when *session_id* already exists.

        Returns:
            (session_id, LogitEntropyMonitor) tuple.
        """
        with self._lock:
            if session_id is None:
                session_id = str(uuid.uuid4())

            if session_id in self._sessions:
                # Move to MRU end.
                self._sessions.move_to_end(session_id)
                return session_id, self._sessions[session_id]

            # Evict LRU entry if at capacity.
            if len(self._sessions) >= self._max_sessions:
                self._sessions.popitem(last=False)  # pop oldest (LRU)

            monitor = LogitEntropyMonitor(ema_alpha=ema_alpha)
            self._sessions[session_id] = monitor
            return session_id, monitor

    def terminate_session(self, session_id: str) -> None:
        """Explicitly remove a session from memory."""
        with self._lock:
            self._sessions.pop(session_id, None)

    def active_sessions_count(self) -> int:
        """Return the number of currently tracked sessions."""
        with self._lock:
            return len(self._sessions)

    def close(self) -> None:
        """Clears all tracked sessions and stops monitoring."""
        with self._lock:
            self._sessions.clear()

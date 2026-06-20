# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.session_manager — LRU-bounded session lifecycle."""

from __future__ import annotations

import threading
import uuid

import pytest

from aegis.core.session_manager import SessionLifecycleManager
from aegis.core.telemetry import LogitEntropyMonitor


# ── constructor ───────────────────────────────────────────────────────────────


def test_constructor_rejects_zero_max_sessions():
    with pytest.raises(ValueError, match="max_sessions"):
        SessionLifecycleManager(max_sessions=0)


def test_constructor_rejects_negative_max_sessions():
    with pytest.raises(ValueError, match="max_sessions"):
        SessionLifecycleManager(max_sessions=-5)


def test_constructor_accepts_one():
    mgr = SessionLifecycleManager(max_sessions=1)
    assert mgr.active_sessions_count() == 0


# ── get_monitor — auto UUID ───────────────────────────────────────────────────


def test_get_monitor_none_generates_uuid():
    mgr = SessionLifecycleManager()
    sid, monitor = mgr.get_monitor(session_id=None)
    assert isinstance(sid, str)
    # Must be a valid UUID-4
    parsed = uuid.UUID(sid, version=4)
    assert str(parsed) == sid


def test_get_monitor_creates_logit_entropy_monitor():
    mgr = SessionLifecycleManager()
    _, monitor = mgr.get_monitor()
    assert isinstance(monitor, LogitEntropyMonitor)


def test_get_monitor_same_id_returns_same_monitor():
    mgr = SessionLifecycleManager()
    sid, m1 = mgr.get_monitor(session_id="sess-1")
    _, m2 = mgr.get_monitor(session_id="sess-1")
    assert m1 is m2


def test_get_monitor_different_ids_return_different_monitors():
    mgr = SessionLifecycleManager()
    _, m1 = mgr.get_monitor(session_id="a")
    _, m2 = mgr.get_monitor(session_id="b")
    assert m1 is not m2


def test_get_monitor_increments_count():
    mgr = SessionLifecycleManager()
    assert mgr.active_sessions_count() == 0
    mgr.get_monitor(session_id="x")
    assert mgr.active_sessions_count() == 1
    mgr.get_monitor(session_id="y")
    assert mgr.active_sessions_count() == 2


# ── LRU eviction ─────────────────────────────────────────────────────────────


def test_lru_evicts_oldest_when_at_capacity():
    mgr = SessionLifecycleManager(max_sessions=3)
    mgr.get_monitor(session_id="a")
    mgr.get_monitor(session_id="b")
    mgr.get_monitor(session_id="c")
    assert mgr.active_sessions_count() == 3

    # Adding "d" should evict "a" (LRU)
    mgr.get_monitor(session_id="d")
    assert mgr.active_sessions_count() == 3

    # "a" was evicted; requesting it creates a new one
    _, mon_a_new = mgr.get_monitor(session_id="a")
    assert mon_a_new is not None


def test_lru_access_moves_to_mru():
    mgr = SessionLifecycleManager(max_sessions=2)
    _, m1 = mgr.get_monitor(session_id="first")
    _, m2 = mgr.get_monitor(session_id="second")

    # Access "first" to move it to MRU
    mgr.get_monitor(session_id="first")

    # Adding "third" should evict "second" (now LRU)
    mgr.get_monitor(session_id="third")
    assert mgr.active_sessions_count() == 2

    # "first" should still be there (was accessed recently)
    _, m1_again = mgr.get_monitor(session_id="first")
    assert m1_again is m1


# ── terminate_session ─────────────────────────────────────────────────────────


def test_terminate_session_removes_session():
    mgr = SessionLifecycleManager()
    mgr.get_monitor(session_id="removeme")
    assert mgr.active_sessions_count() == 1
    mgr.terminate_session("removeme")
    assert mgr.active_sessions_count() == 0


def test_terminate_session_nonexistent_is_noop():
    mgr = SessionLifecycleManager()
    mgr.terminate_session("does-not-exist")  # Must not raise


# ── active_sessions_count ─────────────────────────────────────────────────────


def test_active_sessions_count_zero_initially():
    mgr = SessionLifecycleManager()
    assert mgr.active_sessions_count() == 0


def test_active_sessions_count_after_close():
    mgr = SessionLifecycleManager()
    mgr.get_monitor(session_id="x")
    mgr.get_monitor(session_id="y")
    mgr.close()
    assert mgr.active_sessions_count() == 0


# ── close ─────────────────────────────────────────────────────────────────────


def test_close_clears_all_sessions():
    mgr = SessionLifecycleManager()
    for i in range(10):
        mgr.get_monitor(session_id=f"s{i}")
    mgr.close()
    assert mgr.active_sessions_count() == 0


# ── thread safety ─────────────────────────────────────────────────────────────


def test_concurrent_get_monitor_is_thread_safe():
    mgr = SessionLifecycleManager(max_sessions=1000)
    errors: list[Exception] = []

    def create_session(i: int) -> None:
        try:
            mgr.get_monitor(session_id=f"thread-{i}")
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=create_session, args=(i,)) for i in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    assert mgr.active_sessions_count() == 50

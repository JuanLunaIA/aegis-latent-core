# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

"""The real SessionLifecycleManager against specs/aegis_session_manager.tla.

TLC checks the model's invariants over every interleaving of get_monitor,
terminate_session and close on three session IDs. That says nothing about the
Python class unless something checks that the class behaves like the model.
This file is that check: a Hypothesis state machine drives the real manager
with random operation sequences, keeps the model's state beside it, and after
every step asserts the model's invariants on the real object:

* Bounded       - at most ``max_sessions`` live sessions;
* NoDuplicates / LRU order - the live sessions, in eviction order, are exactly
  the model's ``order`` sequence;
* Isolation     - two live sessions never share a monitor object;
* MonitorOwnership - a monitor handed to one session is never handed to
  another, including after its session is evicted or terminated (the
  pooled-monitor configuration of the TLA model shows why that matters: a
  reused monitor carries one user's EMA state into another user's session);
* StableOnReaccess - getting a live session returns the same object.

The test keeps a strong reference to every monitor it has been handed, so a
freed object's id can never be recycled into a false pass.
"""

from __future__ import annotations

from hypothesis import settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, initialize, invariant, rule

from aegis.core.session_manager import SessionLifecycleManager
from aegis.core.telemetry import LogitEntropyMonitor

SESSION_IDS = st.sampled_from([f"session-{i}" for i in range(5)])


class SessionManagerConformance(RuleBasedStateMachine):
    def __init__(self) -> None:
        super().__init__()
        self.manager = SessionLifecycleManager(max_sessions=1)
        self.max_sessions = 1
        # The model: live sessions from least to most recently used.
        self.order: list[str] = []
        self.monitor_of: dict[str, LogitEntropyMonitor] = {}
        # Every monitor ever handed out, with the one session it belongs to.
        self.handed_out: list[tuple[str, LogitEntropyMonitor]] = []

    @initialize(capacity=st.integers(min_value=1, max_value=4))
    def create_manager(self, capacity: int) -> None:
        self.manager = SessionLifecycleManager(max_sessions=capacity)
        self.max_sessions = capacity

    @rule(session_id=SESSION_IDS)
    def get_monitor(self, session_id: str) -> None:
        returned_id, monitor = self.manager.get_monitor(session_id)
        assert returned_id == session_id

        if session_id in self.order:
            # Reaccess: the same object, moved to the most recently used end.
            assert monitor is self.monitor_of[session_id]
            self.order.remove(session_id)
            self.order.append(session_id)
            return

        # Create: evict the least recently used session when full, then
        # allocate a monitor nobody has held before.
        if len(self.order) >= self.max_sessions:
            evicted = self.order.pop(0)
            del self.monitor_of[evicted]
        for _, earlier in self.handed_out:
            assert monitor is not earlier, "a monitor was handed to a second session"
        self.order.append(session_id)
        self.monitor_of[session_id] = monitor
        self.handed_out.append((session_id, monitor))

    @rule(session_id=SESSION_IDS)
    def terminate(self, session_id: str) -> None:
        self.manager.terminate_session(session_id)
        if session_id in self.order:
            self.order.remove(session_id)
            del self.monitor_of[session_id]

    @rule()
    def close(self) -> None:
        self.manager.close()
        self.order.clear()
        self.monitor_of.clear()

    @invariant()
    def bounded(self) -> None:
        count = self.manager.active_sessions_count()
        assert count <= self.max_sessions
        assert count == len(self.order)

    @invariant()
    def eviction_order_matches_the_model(self) -> None:
        # The OrderedDict's iteration order is the eviction order: its first
        # key is the next one popitem(last=False) removes.
        assert list(self.manager._sessions) == self.order

    @invariant()
    def live_sessions_are_isolated(self) -> None:
        live = [self.manager._sessions[s] for s in self.order]
        assert len({id(m) for m in live}) == len(live)
        for session_id in self.order:
            assert self.manager._sessions[session_id] is self.monitor_of[session_id]


SessionManagerConformance.TestCase.settings = settings(
    max_examples=300, stateful_step_count=40, derandomize=True, deadline=None
)
TestSessionManagerConformance = SessionManagerConformance.TestCase


def test_an_evicted_session_comes_back_with_a_fresh_monitor() -> None:
    # The concrete trace behind MonitorOwnership: fill, evict, re-create.
    manager = SessionLifecycleManager(max_sessions=1)
    _, first = manager.get_monitor("a")
    first.update_ema(0.9)
    _, other = manager.get_monitor("b")
    _, again = manager.get_monitor("a")
    assert again is not first
    assert again is not other
    # The re-created session starts with no EMA state of its own or anyone else's.
    assert again.current_ema is None
    assert other.current_ema is None

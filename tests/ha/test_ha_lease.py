# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""The chain writer lease, against a real Redis.

A chain may have one writer. These tests hold the lease to that: a second
holder is refused while the first holds it, a holder that was superseded can
never renew its way back, epochs only increase, an abandoned lease expires so a
standby can take over, and a holder's own view of the lease ends *before*
Redis's does.
"""

from __future__ import annotations

import threading
import time
import uuid

import pytest

from aegis.core.ha import ChainLease, LeaseKeeper, LeaseUnavailableError, wait_for_lease


def _chain() -> str:
    return f"chain-{uuid.uuid4().hex[:10]}"


def _lease(client: object, chain: str, holder: str, ttl: float = 5.0) -> ChainLease:
    return ChainLease(client, chain, holder, ttl)


def test_one_holder_at_a_time_and_epochs_only_increase(redis_client: object) -> None:
    chain = _chain()
    first, second = _lease(redis_client, chain, "a:1"), _lease(redis_client, chain, "b:2")
    assert first.acquire() == 1
    assert second.acquire() is None, "a second replica took a lease that was held"
    assert first.holds()
    first.release()
    assert not first.holds()
    assert second.acquire() == 2
    second.release()
    assert first.acquire() == 3, "epochs must order every holder the chain has had"


def test_a_superseded_holder_cannot_renew_its_way_back(redis_client: object) -> None:
    chain = _chain()
    old, new = _lease(redis_client, chain, "old:1", ttl=2.0), _lease(redis_client, chain, "new:2")
    assert old.acquire() == 1
    # Simulate old being paused past its TTL: the key expires, new takes it.
    redis_client.delete(old.key)  # type: ignore[attr-defined]
    assert new.acquire() == 2
    assert old.renew() is False
    assert not old.holds()
    assert new.renew() is True
    assert new.holds()


def test_an_abandoned_lease_expires_and_a_standby_takes_over(redis_client: object) -> None:
    chain = _chain()
    crashed = _lease(redis_client, chain, "crashed:1", ttl=1.0)
    standby = _lease(redis_client, chain, "standby:2", ttl=1.0)
    assert crashed.acquire() == 1
    assert standby.acquire() is None
    time.sleep(1.3)  # no renewal: the process "died"
    assert standby.acquire() == 2


def test_a_holders_own_view_ends_before_redis_expiry(redis_client: object) -> None:
    now = [100.0]
    chain = _chain()
    lease = ChainLease(redis_client, chain, "h:1", 10.0, clock=lambda: now[0])
    assert lease.acquire() == 1
    # Measured from before the command was sent, minus a fifth of the TTL.
    assert lease.seconds_remaining() == pytest.approx(8.0)
    now[0] += 7.9
    assert lease.holds()
    now[0] += 0.2
    assert not lease.holds(), "the holder must stop before Redis could hand the lease on"
    ttl_ms = redis_client.pttl(lease.key)  # type: ignore[attr-defined]
    assert ttl_ms > 0, "Redis still holds it: the local view is the conservative one"


def test_the_keeper_renews_and_reports_a_takeover(redis_client: object) -> None:
    chain = _chain()
    lease = _lease(redis_client, chain, "kept:1", ttl=1.5)
    assert lease.acquire() == 1
    lost: list[str] = []
    keeper = LeaseKeeper(lease, lost.append)
    keeper.start()
    try:
        time.sleep(2.5)  # longer than the TTL: only renewal keeps it
        assert lease.holds()
        assert not lost
        redis_client.set(lease.key, "intruder:9|99")  # type: ignore[attr-defined]
        keeper.join(timeout=3)
        assert lost
        assert "took it over" in lost[0]
        assert not lease.holds()
    finally:
        keeper.stop()


def test_a_standby_waits_until_the_lease_is_released(redis_client: object) -> None:
    chain = _chain()
    holder, standby = _lease(redis_client, chain, "h:1"), _lease(redis_client, chain, "s:2")
    assert holder.acquire() == 1
    got: list[int] = []
    waiter = threading.Thread(target=lambda: got.append(wait_for_lease(standby, 0.1)))
    waiter.start()
    time.sleep(0.5)
    assert not got, "the standby acquired a lease that was held"
    holder.release()
    waiter.join(timeout=5)
    assert got == [2]


def test_a_stopped_standby_gives_up_without_the_lease(redis_client: object) -> None:
    chain = _chain()
    holder, standby = _lease(redis_client, chain, "h:1"), _lease(redis_client, chain, "s:2")
    holder.acquire()
    stop = threading.Event()
    stop.set()
    with pytest.raises(LeaseUnavailableError):
        wait_for_lease(standby, 0.05, stop)


@pytest.mark.parametrize("chain", ["", "a|b", "line\nbreak"])
def test_chain_ids_that_could_forge_a_lease_value_are_refused(chain: str) -> None:
    class Stub:
        def register_script(self, _: str) -> object:
            return object()

    with pytest.raises(ValueError, match="chain_id"):
        ChainLease(Stub(), chain, "h:1", 5.0)

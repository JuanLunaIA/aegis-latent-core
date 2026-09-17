"""
tests/test_wal_headroom_preflight.py — refuse before the provider is billed.

REG-049 was seeded as a "disk-full deadlock". **It is not one.** Injecting
``ENOSPC`` at both real failure points on this tree — the buffered WAL write and
the ``fsync`` — produces a raise and a latched ``wal_persist_failed`` in each
case, with the ledger still responsive afterwards and no hang. That probe is
recorded at ``evidence/registry/reg-049_probe.txt``, and the seed premise is
corrected in the registry rather than quietly worked around.

The real residual is narrower and about *timing*. Without a preflight the first
sign of a full volume arrives at commit time, which is after the upstream
provider has been called and billed. The caller pays for a request whose
evidence could never have been written.

``AEGIS_WAL_MIN_FREE_BYTES`` refuses those requests before dispatch. What these
tests pin:

* below the floor, governed traffic is refused **and the forwarder is never
  awaited** — the whole point is the saved upstream call;
* above the floor, nothing changes;
* the check is off unless configured, because a false refusal on a nearly-full
  but working volume is a total outage, which is worse than the late detection
  it replaces;
* a failed ``stat`` does not invent an outage — an unreadable volume is not
  evidence of a full one, and the commit path still decides.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
from fastapi.testclient import TestClient

from aegis.config import AegisSettings
from aegis.proxy.app import create_app

_AUTH = {"Authorization": "Bearer sk-valid"}
_PAYLOAD = {"model": "gpt-4", "messages": [{"role": "user", "content": "hi"}]}


def _settings(tmp_path: Any, **overrides: Any) -> AegisSettings:
    defaults = dict(
        backend_api_key="sk-backend",
        backend_url="http://mock-upstream",
        api_keys="sk-valid",
        wal_path=str(tmp_path / "test.wal"),
        log_level="WARNING",
        auth_disabled=False,
        waf_strict_mode=False,
        analysis_sample_rate=0.0,
    )
    defaults.update(overrides)
    return AegisSettings(**defaults)


def _forwarder() -> MagicMock:
    data = {
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "ok"},
                "finish_reason": "stop",
                "logprobs": None,
            }
        ],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
    }
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = 200
    resp.content = json.dumps(data).encode()
    resp.json.return_value = data
    resp.headers = {"content-type": "application/json"}
    inst = MagicMock()
    inst.start = AsyncMock()
    inst.stop = AsyncMock()
    inst.provider = MagicMock()
    inst.provider.name = "mock"
    inst.provider.supports_logprobs = True
    inst.forward_json = AsyncMock(return_value=resp)
    inst.stream_sse = AsyncMock(return_value=iter([]))
    return inst


def _usage(free: int) -> MagicMock:
    stat = MagicMock()
    stat.free = free
    stat.total = free * 10 or 1
    stat.used = 0
    return stat


def _post(tmp_path: Any, *, free: int | None, **overrides: Any):
    forwarder = _forwarder()
    with patch("aegis.proxy.app.LLMForwarder", return_value=forwarder):
        app = create_app(_settings(tmp_path, **overrides))
        with TestClient(app) as client:
            if free is None:
                response = client.post("/v1/chat/completions", headers=_AUTH, json=_PAYLOAD)
            else:
                with patch("aegis.proxy.app.shutil.disk_usage", return_value=_usage(free)):
                    response = client.post("/v1/chat/completions", headers=_AUTH, json=_PAYLOAD)
    return response, forwarder


def test_below_the_floor_traffic_is_refused(tmp_path: Any) -> None:
    response, _ = _post(tmp_path, free=1_000, wal_min_free_bytes=10_000_000)
    assert response.status_code == 503
    assert "below the configured floor" in response.json()["detail"]


def test_the_refused_request_never_reaches_the_provider(tmp_path: Any) -> None:
    """The saved upstream call is the entire value of the preflight.

    Refusing after dispatch would be no better than the commit-time failure it
    replaces — the caller would already have been billed.
    """
    _, forwarder = _post(tmp_path, free=1_000, wal_min_free_bytes=10_000_000)
    forwarder.forward_json.assert_not_awaited()


def test_above_the_floor_nothing_changes(tmp_path: Any) -> None:
    response, forwarder = _post(tmp_path, free=50_000_000, wal_min_free_bytes=10_000_000)
    assert response.status_code == 200
    forwarder.forward_json.assert_awaited()


def test_the_check_is_off_unless_configured(tmp_path: Any) -> None:
    """Default off: a false refusal is a worse outage than late detection.

    Even with almost nothing free, an unconfigured deployment behaves exactly as
    it always has and lets the commit path decide.
    """
    response, forwarder = _post(tmp_path, free=1)
    assert response.status_code == 200
    forwarder.forward_json.assert_awaited()


def test_a_failed_stat_does_not_invent_an_outage(tmp_path: Any) -> None:
    """An unreadable volume is not evidence of a full one.

    Refusing traffic because ``disk_usage`` raised would manufacture the outage
    the check exists to avoid. The commit path is still the thing that cannot be
    fooled.
    """
    forwarder = _forwarder()
    with patch("aegis.proxy.app.LLMForwarder", return_value=forwarder):
        app = create_app(_settings(tmp_path, wal_min_free_bytes=10_000_000))
        with TestClient(app) as client:
            with patch(
                "aegis.proxy.app.shutil.disk_usage", side_effect=OSError("stat failed")
            ):
                response = client.post("/v1/chat/completions", headers=_AUTH, json=_PAYLOAD)
    assert response.status_code == 200
    forwarder.forward_json.assert_awaited()

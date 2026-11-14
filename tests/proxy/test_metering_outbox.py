# Copyright (c) 2026 Juan Luna. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
# Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
"""Cloud usage metering: a durable outbox drained to ``/v1/usage/batch`` over HMAC.

The earlier reporter (PR #273) held reports in memory and posted them with one
tenant's API key, so a restart lost unsent usage and a multi-tenant gateway could
bill every request to one organisation. These tests pin the replacement: events
survive a restart, each organisation is billed from the authenticated principal,
retries cannot double count, and a rejection is set aside instead of retried.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
from fastapi.testclient import TestClient

from aegis.proxy import metering
from aegis.proxy.app import create_app
from aegis.proxy.metering import UsageOutbox, cloud_config
from tests.proxy.test_pii_vault_gateway import _chat, _completion, _forwarder, _settings

SECRET = "s" * 40


@pytest.fixture(autouse=True)
def _cloud(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGIS_CLOUD_URL", "https://cloud.example")
    monkeypatch.setenv("AEGIS_CLOUD_INTERNAL_HMAC", SECRET)


def _transport(*statuses: int, seen: list[httpx.Request] | None = None) -> httpx.MockTransport:
    replies = iter(statuses)

    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        return httpx.Response(next(replies, statuses[-1]), json={"accepted": True})

    return httpx.MockTransport(handler)


def _record(outbox: UsageOutbox, request_id: str, org: str = "acme") -> None:
    assert outbox.record(
        request_id, tenant_id=org, model="gpt-x", provider="openai", usage=(10, 5, 0)
    )


def _flush(outbox: UsageOutbox) -> int:
    return asyncio.run(outbox.flush_once())


def test_batch_is_signed_the_way_the_control_plane_verifies(tmp_path: Path) -> None:
    seen: list[httpx.Request] = []
    outbox = UsageOutbox(tmp_path / "usage.jsonl", transport=_transport(202, seen=seen))
    _record(outbox, "req-1")
    _record(outbox, "req-2")

    assert _flush(outbox) == 2
    (request,) = seen
    assert request.url.path == "/v1/usage/batch"
    body = request.content
    message = (
        f"{request.headers['x-aegis-timestamp']}\n{request.headers['x-aegis-nonce']}\n"
        f"POST\n/v1/usage/batch\n{hashlib.sha256(body).hexdigest()}"
    ).encode()
    expected = hmac.new(SECRET.encode(), message, hashlib.sha256).hexdigest()
    assert hmac.compare_digest(request.headers["x-aegis-signature"], expected)
    payload = json.loads(body)
    assert payload["org_slug"] == "acme"
    assert [e["request_id"] for e in payload["events"]] == ["req-1", "req-2"]
    assert all("org_slug" not in e for e in payload["events"])
    assert not list(tmp_path.glob("usage.jsonl*"))


def test_unsent_events_survive_a_restart_and_keep_the_same_batch_id(tmp_path: Path) -> None:
    first: list[httpx.Request] = []
    outbox = UsageOutbox(tmp_path / "usage.jsonl", transport=_transport(503, seen=first))
    _record(outbox, "req-1")
    assert _flush(outbox) == 0

    second: list[httpx.Request] = []
    restarted = UsageOutbox(tmp_path / "usage.jsonl", transport=_transport(202, seen=second))
    assert _flush(restarted) == 1
    batch_ids = [json.loads(r.content)["batch_id"] for r in (*first, *second)]
    assert batch_ids[0] == batch_ids[1]


def test_a_rejected_batch_is_set_aside_and_not_retried(tmp_path: Path) -> None:
    seen: list[httpx.Request] = []
    outbox = UsageOutbox(tmp_path / "usage.jsonl", transport=_transport(422, seen=seen))
    _record(outbox, "req-1")

    assert _flush(outbox) == 0
    assert _flush(outbox) == 0
    assert len(seen) == 1
    rejected = (tmp_path / "usage.jsonl.rejected").read_text().splitlines()
    assert json.loads(rejected[0])["request_id"] == "req-1"


def test_a_partial_failure_retries_only_the_failed_organisation(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        org = json.loads(request.content)["org_slug"]
        return httpx.Response(503 if org == "beta" else 202, json={})

    outbox = UsageOutbox(tmp_path / "usage.jsonl", transport=httpx.MockTransport(handler))
    _record(outbox, "a-1", org="acme")
    _record(outbox, "b-1", org="beta")

    assert _flush(outbox) == 1
    (segment,) = tmp_path.glob("usage.jsonl.*.sending")
    assert [json.loads(line)["org_slug"] for line in segment.read_text().splitlines()] == ["beta"]


def test_large_backlogs_are_split_into_batches_of_at_most_100(tmp_path: Path) -> None:
    seen: list[httpx.Request] = []
    outbox = UsageOutbox(tmp_path / "usage.jsonl", transport=_transport(202, seen=seen))
    for index in range(150):
        _record(outbox, f"req-{index}")

    assert _flush(outbox) == 150
    assert [len(json.loads(r.content)["events"]) for r in seen] == [100, 50]


def test_a_torn_final_line_is_skipped(tmp_path: Path) -> None:
    seen: list[httpx.Request] = []
    outbox = UsageOutbox(tmp_path / "usage.jsonl", transport=_transport(202, seen=seen))
    _record(outbox, "req-1")
    with (tmp_path / "usage.jsonl").open("a") as handle:
        handle.write('{"org_slug":"acme","request_id":"req-')

    assert _flush(outbox) == 1


def test_a_tenant_that_is_not_an_organisation_slug_is_not_reported(tmp_path: Path) -> None:
    outbox = UsageOutbox(tmp_path / "usage.jsonl")
    assert not outbox.record("r", tenant_id="Tenant A", model="m", provider="p", usage=(1, 1, 0))
    assert not (tmp_path / "usage.jsonl").exists()


def test_metering_refuses_plain_http_and_short_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGIS_CLOUD_URL", "http://cloud.example")
    assert cloud_config() is None
    monkeypatch.setenv("AEGIS_CLOUD_URL", "http://127.0.0.1:8080")
    assert cloud_config() == ("http://127.0.0.1:8080", SECRET)
    monkeypatch.setenv("AEGIS_CLOUD_INTERNAL_HMAC", "short")
    assert cloud_config() is None


def test_a_committed_chat_completion_is_queued_for_its_tenant(tmp_path: Path) -> None:
    async def reply(path, body, extra_headers=None):
        return _completion("ok")

    settings = _settings(tmp_path)
    # Hold the flusher still so the queued event stays on disk for inspection.
    with (
        patch("aegis.proxy.app.LLMForwarder", return_value=_forwarder(reply)),
        patch.object(metering.UsageOutbox, "run", new=lambda self, *a, **k: asyncio.sleep(3600)),
        patch.object(metering.UsageOutbox, "flush_once", new=lambda self: asyncio.sleep(0)),
    ):
        app = create_app(settings)
        with TestClient(app) as client:
            response = _chat(client, "hola")
            assert response.status_code == 200
            tenant = app.state.aegis.ledger.chain[-1].tenant_id

    outbox = Path(str(settings.wal_path) + ".usage-outbox.jsonl")
    (line,) = outbox.read_text().splitlines()
    event = json.loads(line)
    assert event["org_slug"] == tenant
    assert event["request_id"] == response.headers["x-aegis-request-id"]
    assert event["provider"] == "openai"


def test_an_empty_outbox_sends_nothing(tmp_path: Path) -> None:
    seen: list[httpx.Request] = []
    outbox = UsageOutbox(tmp_path / "usage.jsonl", transport=_transport(202, seen=seen))

    assert _flush(outbox) == 0
    assert seen == []


def test_a_missing_tenant_is_not_reported(tmp_path: Path) -> None:
    outbox = UsageOutbox(tmp_path / "usage.jsonl")
    missing: str = None  # type: ignore[assignment]
    assert not outbox.record("r", tenant_id=missing, model=missing, provider="p", usage=(0, 0, 0))
    assert not (tmp_path / "usage.jsonl").exists()


def test_flush_does_nothing_when_metering_is_off(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[httpx.Request] = []
    outbox = UsageOutbox(tmp_path / "usage.jsonl", transport=_transport(202, seen=seen))
    _record(outbox, "req-1")
    monkeypatch.delenv("AEGIS_CLOUD_INTERNAL_HMAC")

    assert _flush(outbox) == 0
    assert seen == []
    assert (tmp_path / "usage.jsonl").exists()


def test_a_full_spool_drops_new_events_instead_of_filling_the_wal_volume(tmp_path: Path) -> None:
    outbox = UsageOutbox(tmp_path / "usage.jsonl", max_spool_bytes=400)
    accepted = sum(
        outbox.record(f"req-{i}", tenant_id="acme", model="m", provider="p", usage=(1, 1, 0))
        for i in range(20)
    )

    assert 0 < accepted < 20
    assert (tmp_path / "usage.jsonl").stat().st_size <= 400


def test_the_rejected_file_is_bounded_too(tmp_path: Path) -> None:
    outbox = UsageOutbox(
        tmp_path / "usage.jsonl", transport=_transport(422), max_spool_bytes=10_000
    )
    for round_ in range(5):
        for i in range(30):
            _record(outbox, f"req-{round_}-{i}")
        _flush(outbox)

    assert (tmp_path / "usage.jsonl.rejected").stat().st_size < 10_000 + 6_000


async def _stream_summary(events: list[dict], *, protocol: str = "openai"):
    from aegis.proxy.streaming import BoundedStreamProxy

    summaries = []

    async def upstream():
        for event in events:
            yield b"data: " + json.dumps(event).encode() + b"\n\n", event
        yield b"data: [DONE]\n\n", None

    async def commit(summary) -> None:
        summaries.append(summary)

    proxy = BoundedStreamProxy(
        upstream(),
        terminal_commit=commit,
        max_response_bytes=65536,
        max_duration_seconds=2,
        max_event_bytes=8192,
        queue_max_items=16,
        queue_max_bytes=65536,
        protocol=protocol,
    )
    _ = [part async for part in proxy]
    (summary,) = summaries
    return summary


def test_streamed_openai_tool_calls_are_counted_once_per_call() -> None:
    def call(index: int, args: str) -> dict:
        tool = {"index": index, "function": {"arguments": args}}
        return {"choices": [{"index": 0, "delta": {"tool_calls": [tool]}}]}

    summary = asyncio.run(_stream_summary([call(0, '{"a"'), call(0, ":1}"), call(1, "{}")]))
    assert summary.tool_calls == 2
    assert summary.token_count == 0


def test_streamed_anthropic_tool_use_blocks_are_counted() -> None:
    events = [
        {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
        {"type": "content_block_start", "index": 1, "content_block": {"type": "tool_use"}},
        {"type": "content_block_start", "index": 2, "content_block": {"type": "tool_use"}},
    ]
    summary = asyncio.run(_stream_summary(events, protocol="anthropic"))
    assert summary.tool_calls == 2

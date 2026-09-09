# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

"""Splunk HEC connector: it must never be able to break the evidence path.

The properties under test are all about *not* propagating failure. A SIEM that
is down, slow, or returning 503 has to degrade into counters and spool files,
never into an exception reaching a governed request. Bounds are the other half:
a telemetry buffer that grows without limit is how monitoring takes down the
thing it monitors.

No network is used. ``httpx.MockTransport`` answers every request in-process.
"""

from __future__ import annotations

import json

import httpx
import pytest

from aegis.connectors.siem.splunk_hec import SplunkHECClient, SplunkHECConfig

pytestmark = pytest.mark.asyncio


def _config(tmp_path, **overrides) -> SplunkHECConfig:
    params = {
        "url": "https://splunk.example.invalid:8088/services/collector",
        "token": "test-token",
        "spool_dir": str(tmp_path / "spool"),
        "flush_interval_seconds": 3600,  # never fires during a test
    }
    params.update(overrides)
    return SplunkHECConfig(**params)


def _ok_transport(captured: list[bytes]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request.content)
        return httpx.Response(200, json={"text": "Success", "code": 0})

    return httpx.MockTransport(handler)


def _failing_transport(status: int = 503) -> httpx.MockTransport:
    return httpx.MockTransport(lambda request: httpx.Response(status, json={"code": 8}))


def _exploding_transport() -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    return httpx.MockTransport(handler)


class TestDelivery:
    async def test_events_are_delivered_as_newline_delimited_json(self, tmp_path):
        captured: list[bytes] = []
        client = SplunkHECClient(_config(tmp_path), transport=_ok_transport(captured))
        try:
            await client.emit({"event_type": "waf_block", "state_id": "req-1"})
            await client.emit({"event_type": "commit", "state_id": "req-2"})
            attempted = await client.flush()
        finally:
            await client.aclose()

        assert attempted == 2
        assert client.stats.delivered == 2
        body = b"".join(captured)
        lines = [json.loads(line) for line in body.splitlines() if line.strip()]
        assert len(lines) == 2
        assert lines[0]["event"]["state_id"] == "req-1"
        assert lines[0]["sourcetype"] == "aegis:evidence"

    async def test_the_payload_is_not_a_json_array(self, tmp_path):
        """HEC takes concatenated objects; an array is rejected by the indexer."""

        captured: list[bytes] = []
        client = SplunkHECClient(_config(tmp_path), transport=_ok_transport(captured))
        try:
            await client.emit({"a": 1})
            await client.flush()
        finally:
            await client.aclose()
        assert not captured[0].lstrip().startswith(b"[")

    async def test_the_index_is_included_only_when_configured(self, tmp_path):
        captured: list[bytes] = []
        client = SplunkHECClient(
            _config(tmp_path, index="aegis_evidence"), transport=_ok_transport(captured)
        )
        try:
            await client.emit({"a": 1})
            await client.flush()
        finally:
            await client.aclose()
        assert json.loads(captured[0].splitlines()[0])["index"] == "aegis_evidence"

    async def test_batches_respect_the_configured_size(self, tmp_path):
        captured: list[bytes] = []
        client = SplunkHECClient(_config(tmp_path, batch_size=2), transport=_ok_transport(captured))
        try:
            for i in range(5):
                await client.emit({"i": i})
            await client.flush()
        finally:
            await client.aclose()
        # 5 events at batch_size 2 -> 3 posts.
        assert len(captured) == 3


class TestFailureIsContained:
    async def test_a_connection_error_does_not_raise_into_the_caller(self, tmp_path):
        client = SplunkHECClient(_config(tmp_path), transport=_exploding_transport())
        try:
            accepted = await client.emit({"event_type": "commit"})
            attempted = await client.flush()
        finally:
            await client.aclose()
        assert accepted is True
        assert attempted == 1
        assert client.stats.delivery_failures >= 1
        assert client.stats.delivered == 0

    async def test_an_http_error_spools_rather_than_dropping(self, tmp_path):
        client = SplunkHECClient(_config(tmp_path), transport=_failing_transport())
        try:
            await client.emit({"event_type": "commit"})
            await client.flush()
        finally:
            await client.aclose()
        spooled = list((tmp_path / "spool").glob("*.ndjson"))
        assert len(spooled) == 1
        assert client.stats.spooled_batches == 1

    async def test_a_full_queue_drops_rather_than_blocking(self, tmp_path):
        """Blocking here would let a slow indexer stall the evidence path."""

        client = SplunkHECClient(
            _config(tmp_path, queue_max_events=2), transport=_failing_transport()
        )
        try:
            accepted = [await client.emit({"i": i}) for i in range(4)]
        finally:
            await client.aclose()
        assert accepted == [True, True, False, False]
        assert client.stats.dropped_queue_full == 2


class TestSpoolReplay:
    async def test_a_spooled_batch_is_replayed_once_delivery_recovers(self, tmp_path):
        config = _config(tmp_path)

        down = SplunkHECClient(config, transport=_failing_transport())
        try:
            await down.emit({"event_type": "commit", "state_id": "req-1"})
            await down.flush()
        finally:
            await down.aclose()
        assert len(list((tmp_path / "spool").glob("*.ndjson"))) == 1

        captured: list[bytes] = []
        up = SplunkHECClient(config, transport=_ok_transport(captured))
        try:
            replayed = await up.replay_spool()
        finally:
            await up.aclose()

        assert replayed == 1
        assert list((tmp_path / "spool").glob("*.ndjson")) == []
        assert json.loads(captured[0].splitlines()[0])["event"]["state_id"] == "req-1"

    async def test_replay_stops_at_the_first_failure_and_keeps_the_rest(self, tmp_path):
        """Draining into a still-broken indexer would lose the spool."""

        config = _config(tmp_path)
        down = SplunkHECClient(config, transport=_failing_transport())
        try:
            for i in range(3):
                await down.emit({"i": i})
                await down.flush()
        finally:
            await down.aclose()
        assert len(list((tmp_path / "spool").glob("*.ndjson"))) == 3

        still_down = SplunkHECClient(config, transport=_failing_transport())
        try:
            replayed = await still_down.replay_spool()
        finally:
            await still_down.aclose()

        assert replayed == 0
        assert len(list((tmp_path / "spool").glob("*.ndjson"))) == 3

    async def test_the_spool_is_bounded_and_evicts_oldest_first(self, tmp_path):
        client = SplunkHECClient(
            _config(tmp_path, spool_max_bytes=400), transport=_failing_transport()
        )
        try:
            for i in range(12):
                await client.emit({"index": i, "padding": "x" * 100})
                await client.flush()
        finally:
            await client.aclose()

        spooled = list((tmp_path / "spool").glob("*.ndjson"))
        total = sum(f.stat().st_size for f in spooled)
        assert total <= 400 + 200, f"spool grew to {total} bytes past its bound"
        assert client.stats.discarded_spool_batches > 0

    async def test_no_spool_directory_configured_is_not_an_error(self, tmp_path):
        client = SplunkHECClient(_config(tmp_path, spool_dir=None), transport=_failing_transport())
        try:
            await client.emit({"a": 1})
            await client.flush()
        finally:
            await client.aclose()
        assert client.stats.delivery_failures == 1
        assert client.stats.spooled_batches == 0


class TestConfiguration:
    @pytest.mark.parametrize(
        ("overrides", "message"),
        [
            ({"url": ""}, "url must not be empty"),
            ({"token": ""}, "token must not be empty"),
            ({"batch_size": 0}, "batch_size"),
            ({"queue_max_events": 0}, "queue_max_events"),
        ],
    )
    async def test_invalid_configuration_is_refused(self, tmp_path, overrides, message):
        with pytest.raises(ValueError, match=message):
            _config(tmp_path, **overrides)

    async def test_stats_expose_every_counter(self, tmp_path):
        client = SplunkHECClient(_config(tmp_path), transport=_failing_transport())
        try:
            snapshot = client.stats.as_dict()
        finally:
            await client.aclose()
        assert set(snapshot) == {
            "queued",
            "delivered",
            "dropped_queue_full",
            "spooled_batches",
            "replayed_batches",
            "discarded_spool_batches",
            "delivery_failures",
        }

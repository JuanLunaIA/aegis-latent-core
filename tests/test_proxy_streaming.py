# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import AsyncIterator
from typing import Any

import pytest

from aegis.core.crypto_audit import CryptographicAuditLedger
from aegis.core.streaming_deidentifier import (
    StreamingDeidentificationError,
    StreamingDeidentifier,
)
from aegis.proxy.streaming import BoundedStreamProxy, StreamEvidenceSummary


def _event(content: str) -> tuple[bytes, dict[str, Any]]:
    parsed = {"choices": [{"index": 0, "delta": {"content": content}}]}
    return b"data: " + json.dumps(parsed).encode() + b"\n\n", parsed


async def _collect(proxy: BoundedStreamProxy) -> tuple[bytes, list[StreamEvidenceSummary]]:
    summaries: list[StreamEvidenceSummary] = []
    original = proxy._terminal_commit

    async def capture(summary: StreamEvidenceSummary) -> None:
        summaries.append(summary)
        await original(summary)

    proxy._terminal_commit = capture
    parts = [part async for part in proxy]
    return b"".join(parts), summaries


def test_streaming_deidentifier_redacts_split_ssn_pan_and_cvv() -> None:
    deidentifier = StreamingDeidentifier(window_chars=128, enable_phi=True, enable_pci=True)
    chunks = [
        "SSN: 123-",
        "45-6789 card 4111 1111 ",
        "1111 1111 and CV",
        "V: 123",
    ]
    output = "".join(deidentifier.feed(chunk) for chunk in chunks) + deidentifier.flush()
    assert "123-45-6789" not in output
    assert "4111 1111 1111 1111" not in output
    assert "CVV: 123" not in output
    assert "[REDACTED:SSN]" in output
    assert "[PAN-****1111]" in output
    assert "[REDACTED:CVV]" in output
    assert deidentifier.retained_chars == 0
    assert deidentifier.stats.total_hits >= 3


def test_streaming_deidentifier_fails_closed_on_overlong_open_url() -> None:
    deidentifier = StreamingDeidentifier(window_chars=64, enable_phi=True)
    with pytest.raises(StreamingDeidentificationError, match="open URL"):
        deidentifier.feed("https://example.test/" + "a" * 128)


def test_streaming_deidentifier_fails_closed_on_uppercase_open_url() -> None:
    """The URL detector is case-insensitive, so the open-candidate guard must be.

    Searching only for the lowercase marker let an uppercase scheme past the
    guard entirely — a fail-open on the very grammar the guard exists for.
    """
    deidentifier = StreamingDeidentifier(window_chars=64, enable_phi=True)
    with pytest.raises(StreamingDeidentificationError, match="open URL"):
        deidentifier.feed("HTTPS://EXAMPLE.TEST/" + "A" * 128)


@pytest.mark.parametrize(
    "opening",
    [
        ";4111111111111111=25121010000012345678",
        "%B4111111111111111^DOE/JOHN^2512101000001",
        "%b4111111111111111^DOE/JOHN^2512101000001",
    ],
)
def test_streaming_deidentifier_fails_closed_on_overlong_open_track_data(opening: str) -> None:
    """An unterminated track-1 or track-2 run must still fail closed.

    Lowercase ``%b`` is included because the track-1 detector is
    case-insensitive; the guard has to search the same way the detector matches.
    """
    deidentifier = StreamingDeidentifier(window_chars=64, enable_pci=True)
    with pytest.raises(StreamingDeidentificationError, match="track-data"):
        deidentifier.feed(opening + "0" * 200)


def test_streaming_deidentifier_fails_closed_on_overlong_open_email() -> None:
    """An address longer than the window with no whitespace cannot settle."""
    deidentifier = StreamingDeidentifier(window_chars=64, enable_phi=True)
    with pytest.raises(StreamingDeidentificationError, match="open email"):
        deidentifier.feed("a" * 100 + "@example.test" + "b" * 100)


@pytest.mark.parametrize(
    ("label", "text"),
    [
        (
            "semicolon in prose",
            "We shipped it; " + "the rollout went smoothly across every region today. " * 4,
        ),
        (
            "email mentioned mid-stream",
            "Please contact our support desk at support@example.test and we will get back "
            "to you within one business day about the invoice you mentioned earlier.",
        ),
        (
            "email early with a long tail",
            "support@example.test is the address; " + "and the explanation continues here. " * 4,
        ),
        (
            "at-sign in code",
            "@dataclass class Config: pass  " + "followed by more explanatory prose here. " * 4,
        ),
        (
            "terminated URL followed by prose",
            "See https://example.test/docs for details. " + "More prose follows after it. " * 4,
        ),
    ],
)
def test_streaming_deidentifier_does_not_abort_on_ordinary_prose(label: str, text: str) -> None:
    """Ordinary text must stream through, whole or byte-chunked.

    Each of these aborted the stream before the open-candidate guards were
    tightened to test for a viable prefix of the detector they guard. A raised
    ``StreamingDeidentificationError`` reaches the client as a
    ``privacy_failure`` terminal outcome, so a false positive here is a
    user-visible failure on text containing nothing sensitive.
    """
    for chunks in ([text], [text[i : i + 7] for i in range(0, len(text), 7)]):
        deidentifier = StreamingDeidentifier(window_chars=128, enable_phi=True, enable_pci=True)
        output = "".join(deidentifier.feed(chunk) for chunk in chunks) + deidentifier.flush()
        assert output, f"{label} produced no output"


@pytest.mark.asyncio
async def test_success_hashes_exact_output_and_commits_before_done() -> None:
    release_commit = asyncio.Event()
    commit_started = asyncio.Event()
    summaries: list[StreamEvidenceSummary] = []

    async def upstream() -> AsyncIterator[tuple[bytes, Any]]:
        yield _event("hello")
        yield b"data: [DONE]\n\n", None

    async def commit(summary: StreamEvidenceSummary) -> None:
        summaries.append(summary)
        commit_started.set()
        await release_commit.wait()

    proxy = BoundedStreamProxy(
        upstream(),
        terminal_commit=commit,
        max_response_bytes=4096,
        max_duration_seconds=2,
        max_event_bytes=1024,
        queue_max_items=2,
        queue_max_bytes=2048,
    )
    iterator = proxy.__aiter__()
    first = await anext(iterator)
    done_task = asyncio.create_task(anext(iterator))
    await asyncio.wait_for(commit_started.wait(), timeout=1)
    assert not done_task.done()
    release_commit.set()
    done = await asyncio.wait_for(done_task, timeout=1)
    assert done == b"data: [DONE]\n\n"
    expected = first + done
    assert len(summaries) == 1
    assert summaries[0].terminal_outcome == "complete"
    assert summaries[0].final_marker_included is True
    assert summaries[0].response_size == len(expected)
    assert summaries[0].response_hash == hashlib.sha256(expected).hexdigest()
    with pytest.raises(StopAsyncIteration):
        await anext(iterator)


@pytest.mark.asyncio
async def test_first_event_arrives_before_upstream_second_event() -> None:
    permit_second = asyncio.Event()
    first_emitted = asyncio.Event()

    async def upstream() -> AsyncIterator[tuple[bytes, Any]]:
        yield _event("first")
        first_emitted.set()
        await permit_second.wait()
        yield _event("second")
        yield b"data: [DONE]", None

    async def commit(_summary: StreamEvidenceSummary) -> None:
        return

    proxy = BoundedStreamProxy(
        upstream(),
        terminal_commit=commit,
        max_response_bytes=4096,
        max_duration_seconds=2,
        max_event_bytes=1024,
        queue_max_items=2,
        queue_max_bytes=2048,
    )
    iterator = proxy.__aiter__()
    first = await asyncio.wait_for(anext(iterator), timeout=1)
    assert b"first" in first
    assert first_emitted.is_set()
    assert not permit_second.is_set()
    permit_second.set()
    remainder = b"".join([part async for part in iterator])
    assert b"second" in remainder
    assert remainder.endswith(b"data: [DONE]\n\n")


@pytest.mark.asyncio
async def test_split_phi_is_redacted_before_hash_and_delivery() -> None:
    summaries: list[StreamEvidenceSummary] = []

    async def upstream() -> AsyncIterator[tuple[bytes, Any]]:
        yield _event("SSN: 123-")
        yield _event("45-6789")
        yield b"data: [DONE]", None

    async def commit(summary: StreamEvidenceSummary) -> None:
        summaries.append(summary)

    proxy = BoundedStreamProxy(
        upstream(),
        terminal_commit=commit,
        max_response_bytes=8192,
        max_duration_seconds=2,
        max_event_bytes=2048,
        queue_max_items=4,
        queue_max_bytes=4096,
        deidentifier_window_chars=128,
        enable_phi=True,
    )
    output = b"".join([part async for part in proxy])
    assert b"123-45-6789" not in output
    assert b"[REDACTED:SSN]" in output
    assert summaries[0].response_hash == hashlib.sha256(output).hexdigest()
    assert summaries[0].redaction_hits["SSN"] == 1


@pytest.mark.asyncio
async def test_native_anthropic_stream_preserves_events_and_redacts_before_block_stop() -> None:
    summaries: list[StreamEvidenceSummary] = []

    def anthropic_event(event_type: str, payload: dict[str, Any]) -> tuple[bytes, Any]:
        raw = (
            f"event: {event_type}\ndata: {json.dumps(payload, separators=(',', ':'))}\n\n"
        ).encode()
        return raw, payload

    async def upstream() -> AsyncIterator[tuple[bytes, Any]]:
        yield anthropic_event(
            "message_start", {"type": "message_start", "message": {"id": "msg-1"}}
        )
        yield anthropic_event(
            "content_block_start",
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text", "text": ""},
            },
        )
        yield anthropic_event(
            "content_block_delta",
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": "SSN 123-"},
            },
        )
        yield anthropic_event(
            "content_block_delta",
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": "45-6789"},
            },
        )
        yield anthropic_event("content_block_stop", {"type": "content_block_stop", "index": 0})
        yield anthropic_event("message_stop", {"type": "message_stop"})

    async def commit(summary: StreamEvidenceSummary) -> None:
        summaries.append(summary)

    marker = b'event: message_stop\ndata: {"type":"message_stop"}\n\n'
    proxy = BoundedStreamProxy(
        upstream(),
        terminal_commit=commit,
        max_response_bytes=16_384,
        max_duration_seconds=2,
        max_event_bytes=4096,
        queue_max_items=8,
        queue_max_bytes=8192,
        enable_phi=True,
        protocol="anthropic",
        terminal_predicate=lambda _raw, parsed: (
            isinstance(parsed, dict) and parsed.get("type") == "message_stop"
        ),
        terminal_marker=marker,
    )
    output = b"".join([part async for part in proxy])
    assert b"123-45-6789" not in output
    assert b"[REDACTED:SSN]" in output
    assert output.index(b"[REDACTED:SSN]") < output.index(b"content_block_stop")
    assert output.endswith(marker)
    assert summaries[0].terminal_outcome == "complete"
    assert summaries[0].response_hash == hashlib.sha256(output).hexdigest()


@pytest.mark.asyncio
async def test_byte_limit_closes_without_done_and_commits_once() -> None:
    summaries: list[StreamEvidenceSummary] = []
    closed = asyncio.Event()

    async def upstream() -> AsyncIterator[tuple[bytes, Any]]:
        try:
            for _ in range(100):
                yield _event("x" * 30)
        finally:
            closed.set()

    async def commit(summary: StreamEvidenceSummary) -> None:
        summaries.append(summary)

    proxy = BoundedStreamProxy(
        upstream(),
        terminal_commit=commit,
        max_response_bytes=1024,
        max_duration_seconds=2,
        max_event_bytes=512,
        queue_max_items=2,
        queue_max_bytes=512,
    )
    output = b"".join([part async for part in proxy])
    assert b"[DONE]" not in output
    assert await asyncio.wait_for(closed.wait(), timeout=1) is True
    assert len(summaries) == 1
    assert summaries[0].terminal_outcome == "byte_limit"


@pytest.mark.asyncio
async def test_timeout_and_oversized_event_fail_without_done() -> None:
    timeout_summaries: list[StreamEvidenceSummary] = []

    async def slow_upstream() -> AsyncIterator[tuple[bytes, Any]]:
        yield _event("first")
        await asyncio.sleep(1)

    async def timeout_commit(summary: StreamEvidenceSummary) -> None:
        timeout_summaries.append(summary)

    timeout_proxy = BoundedStreamProxy(
        slow_upstream(),
        terminal_commit=timeout_commit,
        max_response_bytes=4096,
        max_duration_seconds=0.05,
        max_event_bytes=1024,
        queue_max_items=2,
        queue_max_bytes=2048,
    )
    timeout_output = b"".join([part async for part in timeout_proxy])
    assert b"first" in timeout_output
    assert b"[DONE]" not in timeout_output
    assert timeout_summaries[0].terminal_outcome == "timeout"

    event_summaries: list[StreamEvidenceSummary] = []

    async def oversized_upstream() -> AsyncIterator[tuple[bytes, Any]]:
        yield b"x" * 257, None

    async def event_commit(summary: StreamEvidenceSummary) -> None:
        event_summaries.append(summary)

    event_proxy = BoundedStreamProxy(
        oversized_upstream(),
        terminal_commit=event_commit,
        max_response_bytes=4096,
        max_duration_seconds=1,
        max_event_bytes=256,
        queue_max_items=2,
        queue_max_bytes=2048,
    )
    assert b"".join([part async for part in event_proxy]) == b""
    assert event_summaries[0].terminal_outcome == "event_limit"


@pytest.mark.asyncio
async def test_cancellation_closes_upstream_and_commits_once() -> None:
    summaries: list[StreamEvidenceSummary] = []
    closed = asyncio.Event()

    async def upstream() -> AsyncIterator[tuple[bytes, Any]]:
        try:
            yield _event("first")
            await asyncio.Event().wait()
        finally:
            closed.set()

    async def commit(summary: StreamEvidenceSummary) -> None:
        summaries.append(summary)

    proxy = BoundedStreamProxy(
        upstream(),
        terminal_commit=commit,
        max_response_bytes=4096,
        max_duration_seconds=5,
        max_event_bytes=1024,
        queue_max_items=2,
        queue_max_bytes=2048,
    )
    iterator = proxy.__aiter__()
    assert b"first" in await anext(iterator)
    pending = asyncio.create_task(anext(iterator))
    await asyncio.sleep(0)
    pending.cancel()
    with pytest.raises(asyncio.CancelledError):
        await pending
    await asyncio.wait_for(closed.wait(), timeout=1)
    assert len(summaries) == 1
    assert summaries[0].terminal_outcome == "client_disconnected"


@pytest.mark.asyncio
async def test_commit_failure_omits_done() -> None:
    calls = 0

    async def upstream() -> AsyncIterator[tuple[bytes, Any]]:
        yield _event("hello")
        yield b"data: [DONE]", None

    async def commit(_summary: StreamEvidenceSummary) -> None:
        nonlocal calls
        calls += 1
        raise OSError("fsync failed")

    proxy = BoundedStreamProxy(
        upstream(),
        terminal_commit=commit,
        max_response_bytes=4096,
        max_duration_seconds=2,
        max_event_bytes=1024,
        queue_max_items=2,
        queue_max_bytes=2048,
    )
    output = b"".join([part async for part in proxy])
    assert b"hello" in output
    assert b"[DONE]" not in output
    assert calls == 1


@pytest.mark.asyncio
async def test_large_logical_stream_retained_memory_is_bounded() -> None:
    count = 100_000
    calls = 0

    async def upstream() -> AsyncIterator[tuple[bytes, Any]]:
        for _ in range(count):
            yield _event("x")
        yield b"data: [DONE]", None

    async def commit(_summary: StreamEvidenceSummary) -> None:
        nonlocal calls
        calls += 1

    proxy = BoundedStreamProxy(
        upstream(),
        terminal_commit=commit,
        max_response_bytes=32_000_000,
        max_duration_seconds=30,
        max_event_bytes=1024,
        queue_max_items=4,
        queue_max_bytes=4096,
        preview_bytes=1024,
    )
    observed = 0
    async for part in proxy:
        observed += len(part)
        assert proxy.retained_bytes <= 1024 + 4096 + 512
    assert observed > 5_000_000
    assert proxy.peak_queue_items <= 4
    assert proxy.peak_queue_bytes <= 4096
    assert calls == 1


def test_prehashed_terminal_commit_binds_outcome_and_replays(tmp_path) -> None:
    wal = tmp_path / "stream.wal"
    ledger = CryptographicAuditLedger(
        persistence_path=str(wal), signing_key="test-signing-key", require_strong_signing=True
    )
    response = b"data: sanitized\n\ndata: [DONE]\n\n"
    node = ledger.commit_forensic_summary(
        state_id="stream-1",
        request_bytes=b'{"stream":true}',
        response_hash=hashlib.sha256(response).hexdigest(),
        response_size=len(response),
        response_preview=response,
        terminal_outcome="complete",
        final_marker_included=True,
        token_count=1,
        elapsed_seconds=0.25,
        redaction_hits={"SSN": 1},
    )
    assert node.audit_trail_version == "2"
    assert node.response_hash == hashlib.sha256(response).hexdigest()
    assert node.sampling_params["terminal_outcome"] == "complete"
    assert ledger.verify_integrity() == (True, None)
    ledger.close()

    replayed = CryptographicAuditLedger(
        persistence_path=str(wal), signing_key="test-signing-key", require_strong_signing=True
    )
    assert len(replayed.chain) == 1
    assert replayed.chain[0].audit_trail_version == "2"
    assert replayed.verify_integrity() == (True, None)
    replayed.close()


def test_failed_terminal_persistence_rolls_back_in_memory_mmr(tmp_path, monkeypatch) -> None:
    ledger = CryptographicAuditLedger(
        persistence_path=str(tmp_path / "rollback.wal"),
        signing_key="test-signing-key",
        require_strong_signing=True,
    )
    root_before = ledger._mmr.get_root_hash()
    monkeypatch.setattr(
        ledger, "_persist_node", lambda _node: (_ for _ in ()).throw(OSError("disk"))
    )
    with pytest.raises(OSError, match="disk"):
        ledger.commit_forensic_summary(
            state_id="stream-failed",
            request_bytes=b"{}",
            response_hash=hashlib.sha256(b"").hexdigest(),
            response_size=0,
            response_preview=b"",
            terminal_outcome="upstream_error",
            final_marker_included=False,
            token_count=0,
            elapsed_seconds=0.1,
        )
    assert len(ledger.chain) == 0
    assert ledger._mmr.get_root_hash() == root_before
    ledger.close()


def test_portable_mmr_replays_from_wal_leaf_hashes(tmp_path) -> None:
    wal = tmp_path / "portable-replay.wal"
    ledger = CryptographicAuditLedger(
        persistence_path=str(wal),
        signing_key="test-signing-key",
        require_strong_signing=True,
    )
    ledger.commit_forensic(state_id="one", request_bytes=b"one", response_bytes=b"1")
    second = ledger.commit_forensic(state_id="two", request_bytes=b"two", response_bytes=b"2")
    second_root = second.merkle_root
    ledger.close()

    replayed = CryptographicAuditLedger(
        persistence_path=str(wal),
        signing_key="test-signing-key",
        require_strong_signing=True,
    )
    assert replayed._mmr.get_leaf_count() == 2
    assert replayed._mmr.get_root_hash() == second_root
    third = replayed.commit_forensic(state_id="three", request_bytes=b"three", response_bytes=b"3")
    assert third.mmr_leaf_index == 2
    assert third.mmr_leaf_count == 3
    assert third.mmr_proof is not None
    assert third.mmr_proof["root"] == third.merkle_root
    replayed.close()


def test_integrity_sweep_rejects_tampered_portable_proof(tmp_path) -> None:
    ledger = CryptographicAuditLedger(
        persistence_path=str(tmp_path / "proof-tamper.wal"),
        signing_key="test-signing-key",
        require_strong_signing=True,
    )
    node = ledger.commit_forensic(
        state_id="proof", request_bytes=b"request", response_bytes=b"response"
    )
    assert node.mmr_proof is not None
    node.mmr_proof["root"] = "f" * 64
    valid, error_index = ledger.verify_integrity()
    assert valid is False
    assert error_index == 0
    ledger.close()


def test_bounded_memory_window_tracks_predecessor_anchor_across_replay(tmp_path) -> None:
    wal = tmp_path / "window-anchor.wal"
    ledger = CryptographicAuditLedger(
        persistence_path=str(wal),
        signing_key="test-signing-key",
        require_strong_signing=True,
        max_memory_nodes=2,
    )
    first = ledger.commit_forensic(state_id="one", request_bytes=b"one", response_bytes=b"1")
    ledger.commit_forensic(state_id="two", request_bytes=b"two", response_bytes=b"2")
    ledger.commit_forensic(state_id="three", request_bytes=b"three", response_bytes=b"3")
    assert ledger.window_anchor_hash == first.node_hash
    assert ledger.verify_integrity() == (True, None)
    ledger.close()

    replayed = CryptographicAuditLedger(
        persistence_path=str(wal),
        signing_key="test-signing-key",
        require_strong_signing=True,
        max_memory_nodes=2,
    )
    assert replayed.window_anchor_hash == first.node_hash
    assert replayed.verify_integrity() == (True, None)
    replayed.chain[0].prev_hash = "f" * 64
    assert replayed.verify_integrity() == (False, 0)
    replayed.close()

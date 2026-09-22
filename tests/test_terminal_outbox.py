# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""A handed-off terminal commit must survive the process that handed it off.

REG-D32 / AUD-28: ``REG-D07`` moved terminal evidence for a torn-down stream onto
an app-owned handoff, but in process — a crash or SIGKILL between teardown and
the drained commit lost the node, and a full queue dropped it. The opt-in outbox
spools a content-free record first and replays it at the next start.

These tests drive the properties rather than the happy path: the record survives
a real SIGKILL; a replay commits exactly once, including when the crash fell
between the commit and its done marker; replay refuses to extend a ledger that is
not healthy; a full queue defers to the next start instead of losing the node; a
spool that is full or failing never costs the in-memory commit; and a recovered
node matches the live one in everything but its previews and its two markers.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import signal
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest

from aegis.core.crypto_audit import CryptographicAuditLedger
from aegis.proxy.streaming import StreamEvidenceSummary, TerminalCommitHandoff
from aegis.proxy.terminal_outbox import (
    RECOVERED_MEANING,
    TerminalOutbox,
    TerminalReplayContext,
    replay_pending,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
REQUEST = b'{"model":"m","stream":true,"messages":[{"role":"user","content":"hello"}]}'
RESPONSE = b"data: sanitized\n\ndata: [DONE]\n\n"


def _ledger(tmp_path: Path, name: str = "chain.wal") -> CryptographicAuditLedger:
    return CryptographicAuditLedger(
        persistence_path=str(tmp_path / name),
        signing_key="test-signing-key",
        require_strong_signing=True,
    )


def _context(state_id: str = "req-1", *, append: bool = True) -> TerminalReplayContext:
    return TerminalReplayContext(
        state_id=state_id,
        request_hash=hashlib.sha256(REQUEST).hexdigest(),
        request_size=len(REQUEST),
        tenant_id="tenant-a",
        model="m",
        endpoint="chat.completions",
        phi_scrubbed=False,
        scrub_method="regex",
        append_stream_window_method=append,
        signer_name="svc@example",
    )


def _summary(
    preview: bytes = RESPONSE, hits: dict[str, int] | None = None
) -> StreamEvidenceSummary:
    return StreamEvidenceSummary(
        response_hash=hashlib.sha256(RESPONSE).hexdigest(),
        response_size=len(RESPONSE),
        response_preview=preview,
        terminal_outcome="client_disconnected",
        final_marker_included=False,
        token_count=3,
        elapsed_seconds=0.5,
        redaction_hits=dict(hits or {}),
    )


def _open(path: Path, **kwargs: Any) -> TerminalOutbox:
    return TerminalOutbox.open(path, max_bytes=kwargs.pop("max_bytes", 1 << 20), **kwargs)


def _nodes_for(ledger: CryptographicAuditLedger, state_id: str) -> list[Any]:
    return [node for node in ledger.chain_snapshot() if node.state_id == state_id]


# ── the spool ────────────────────────────────────────────────────────────────


def test_the_spool_holds_no_content_and_is_owner_only(tmp_path: Path) -> None:
    sentinel = b"SENTINEL-RESPONSE-CONTENT-7f3a"
    path = tmp_path / "outbox.jsonl"
    outbox = _open(path)
    assert outbox.record(_context(), _summary(preview=RESPONSE + sentinel)) is not None
    outbox.close()

    raw = path.read_bytes()
    assert sentinel not in raw
    assert REQUEST not in raw
    assert b"hello" not in raw
    assert os.stat(path).st_mode & 0o777 == 0o600


def test_a_record_survives_sigkill_right_after_it_is_written(tmp_path: Path) -> None:
    """The process-death half of the durability claim, exercised for real."""

    path = tmp_path / "outbox.jsonl"
    probe = textwrap.dedent(
        f"""
        import os, signal, sys
        from pathlib import Path
        sys.path.insert(0, {str(REPO_ROOT)!r})
        from tests.test_terminal_outbox import _context, _summary, _open
        outbox = _open(Path(sys.argv[1]))
        assert outbox.record(_context("killed-1"), _summary()) is not None
        os.kill(os.getpid(), signal.SIGKILL)
        """
    )
    proc = subprocess.run(  # noqa: S603 - fixed interpreter, inline probe
        [sys.executable, "-c", probe, str(path)], capture_output=True, text=True, timeout=120
    )
    assert proc.returncode == -signal.SIGKILL, proc.stderr

    reopened = _open(path)
    try:
        [entry] = reopened.pending_entries()
        assert entry.context.state_id == "killed-1"
        assert entry.summary.token_count == 3
    finally:
        reopened.close()


def test_a_torn_tail_is_skipped_and_counted_not_fatal(tmp_path: Path) -> None:
    path = tmp_path / "outbox.jsonl"
    outbox = _open(path)
    outbox.record(_context("whole"), _summary())
    outbox.close()
    with path.open("ab") as handle:
        handle.write(b'{"v":1,"op":"pending","id":"torn","ctx":{"state_')

    reopened = _open(path)
    try:
        assert [e.context.state_id for e in reopened.pending_entries()] == ["whole"]
        assert reopened.corrupt_lines == 1
    finally:
        reopened.close()


# ── replay against a real ledger ─────────────────────────────────────────────


async def test_replay_commits_a_pending_record_exactly_once_and_marks_it(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    path = tmp_path / "outbox.jsonl"
    outbox = _open(path)
    outbox.record(_context("lost-1"), _summary(hits={"SSN": 1}))
    outbox.close()  # the process "died" before the worker reached it

    reopened = _open(path)
    report = await replay_pending(reopened, ledger=ledger, commit=ledger.commit_forensic_summary)

    assert (report.pending, report.recovered, report.deduplicated, report.failed) == (1, 1, 0, 0)
    [node] = _nodes_for(ledger, "lost-1")
    assert node.signature_meaning == RECOVERED_MEANING
    assert node.sampling_params["evidence_status"] == "recovered-terminal"
    assert node.request_hash == hashlib.sha256(REQUEST).hexdigest()
    assert node.sampling_params["terminal_outcome"] == "client_disconnected"
    assert node.scrub_method == "regex+stream_window_regex"
    assert node.phi_scrubbed is True
    assert ledger.verify_integrity() == (True, None)
    assert reopened.pending_count == 0
    assert path.read_bytes() == b""  # compacted: nothing left pending

    again = await replay_pending(reopened, ledger=ledger, commit=ledger.commit_forensic_summary)
    assert again.pending == 0
    assert len(_nodes_for(ledger, "lost-1")) == 1
    reopened.close()
    ledger.close()


async def test_a_crash_between_commit_and_done_marker_is_not_committed_twice(
    tmp_path: Path,
) -> None:
    ledger = _ledger(tmp_path)
    path = tmp_path / "outbox.jsonl"
    outbox = _open(path)
    outbox.record(_context("landed-1"), _summary())
    outbox.close()
    # The live commit landed; the process died before writing the done marker.
    ledger.commit_forensic_summary(
        state_id="landed-1",
        request_bytes=REQUEST,
        response_hash=hashlib.sha256(RESPONSE).hexdigest(),
        response_size=len(RESPONSE),
        response_preview=RESPONSE,
        terminal_outcome="client_disconnected",
        final_marker_included=False,
        token_count=3,
        elapsed_seconds=0.5,
    )

    reopened = _open(path)
    report = await replay_pending(reopened, ledger=ledger, commit=ledger.commit_forensic_summary)

    assert (report.recovered, report.deduplicated) == (0, 1)
    assert len(_nodes_for(ledger, "landed-1")) == 1
    assert reopened.pending_count == 0
    reopened.close()
    ledger.close()


async def test_replay_refuses_a_ledger_that_is_not_healthy(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    before = len(ledger.chain_snapshot())
    path = tmp_path / "outbox.jsonl"
    outbox = _open(path)
    outbox.record(_context("held-1"), _summary())
    outbox.close()
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    ledger._fault_state = "wal_corrupt"

    reopened = _open(path)
    report = await replay_pending(reopened, ledger=ledger, commit=ledger.commit_forensic_summary)

    assert report.refused_fault_state == "wal_corrupt"
    assert report.recovered == 0
    assert len(ledger.chain_snapshot()) == before
    assert reopened.pending_count == 1
    assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
    reopened.close()
    ledger.close()


async def test_a_recovered_node_matches_the_live_one_but_for_previews_and_markers(
    tmp_path: Path,
) -> None:
    live_ledger = _ledger(tmp_path, "live.wal")
    live = live_ledger.commit_forensic_summary(
        state_id="same-1",
        request_bytes=REQUEST,
        response_hash=hashlib.sha256(RESPONSE).hexdigest(),
        response_size=len(RESPONSE),
        response_preview=RESPONSE,
        terminal_outcome="client_disconnected",
        final_marker_included=False,
        token_count=3,
        elapsed_seconds=0.5,
        redaction_hits={"SSN": 1},
        tenant_id="tenant-a",
        model="m",
        endpoint="chat.completions",
        phi_scrubbed=False,
        scrub_method="regex+stream_window_regex",
        signer_name="svc@example",
    )
    replay_ledger = _ledger(tmp_path, "replay.wal")
    outbox = _open(tmp_path / "outbox.jsonl")
    outbox.record(_context("same-1"), _summary(hits={"SSN": 1}))
    await replay_pending(outbox, ledger=replay_ledger, commit=replay_ledger.commit_forensic_summary)
    [recovered] = _nodes_for(replay_ledger, "same-1")

    for field in (
        "state_id",
        "tenant_id",
        "request_hash",
        "response_hash",
        "model",
        "endpoint",
        "token_trail_count",
        "phi_scrubbed",
        "scrub_method",
        "signer_name",
    ):
        assert getattr(recovered, field) == getattr(live, field), field
    live_params = dict(live.sampling_params)
    recovered_params = dict(recovered.sampling_params)
    assert live_params.pop("evidence_status") == "durable-terminal"
    assert recovered_params.pop("evidence_status") == "recovered-terminal"
    assert recovered_params == live_params
    assert (live.signature_meaning, recovered.signature_meaning) == (
        "stream-terminal-evidence",
        RECOVERED_MEANING,
    )
    outbox.close()
    live_ledger.close()
    replay_ledger.close()


# ── the handoff with an outbox attached ──────────────────────────────────────


async def test_a_committed_handoff_leaves_nothing_pending(tmp_path: Path) -> None:
    outbox = _open(tmp_path / "outbox.jsonl")
    handoff = TerminalCommitHandoff()
    handoff.attach_outbox(outbox)
    handoff.start()
    landed: list[StreamEvidenceSummary] = []

    async def commit(summary: StreamEvidenceSummary) -> None:
        landed.append(summary)

    assert handoff.submit(commit, _summary(), replay=_context("ok-1")) is True
    assert outbox.pending_count == 1  # spooled before the worker ran
    await handoff.stop(timeout=5.0)

    assert len(landed) == 1
    assert outbox.pending_count == 0
    outbox.close()


async def test_a_failed_commit_stays_pending_for_the_next_start(tmp_path: Path) -> None:
    outbox = _open(tmp_path / "outbox.jsonl")
    handoff = TerminalCommitHandoff()
    handoff.attach_outbox(outbox)
    handoff.start()

    async def failing(summary: StreamEvidenceSummary) -> None:
        raise OSError("disk went away")

    handoff.submit(failing, _summary(), replay=_context("fails-1"))
    await handoff.stop(timeout=5.0)

    assert handoff.committed == 0
    assert [e.context.state_id for e in outbox.pending_entries()] == ["fails-1"]
    outbox.close()


async def test_a_full_queue_defers_the_commit_to_the_next_start(tmp_path: Path) -> None:
    path = tmp_path / "outbox.jsonl"
    outbox = _open(path)
    handoff = TerminalCommitHandoff(max_pending=1)
    handoff.attach_outbox(outbox)
    handoff.start()
    gate = asyncio.Event()

    async def slow(summary: StreamEvidenceSummary) -> None:
        await gate.wait()

    assert handoff.submit(slow, _summary(), replay=_context("q-0")) is True
    while handoff.pending:
        await asyncio.sleep(0)
    assert handoff.submit(slow, _summary(), replay=_context("q-1")) is True
    assert handoff.submit(slow, _summary(), replay=_context("q-2")) is False  # queue full
    assert handoff.dropped == 1
    gate.set()
    await handoff.stop(timeout=5.0)
    outbox.close()

    ledger = _ledger(tmp_path)
    reopened = _open(path)
    report = await replay_pending(reopened, ledger=ledger, commit=ledger.commit_forensic_summary)
    assert report.recovered == 1
    assert len(_nodes_for(ledger, "q-2")) == 1  # the dropped one was not lost
    reopened.close()
    ledger.close()


async def test_a_full_spool_costs_durability_not_the_in_memory_commit(tmp_path: Path) -> None:
    outbox = _open(tmp_path / "outbox.jsonl", max_bytes=1)
    outbox.record(_context("fills"), _summary())  # size is now past the cap
    handoff = TerminalCommitHandoff()
    handoff.attach_outbox(outbox)
    handoff.start()
    landed: list[StreamEvidenceSummary] = []

    async def commit(summary: StreamEvidenceSummary) -> None:
        landed.append(summary)

    assert handoff.submit(commit, _summary(), replay=_context("over-1")) is True
    await handoff.stop(timeout=5.0)

    assert outbox.skipped == 1
    assert len(landed) == 1
    outbox.close()


async def test_a_spool_write_failure_never_reaches_teardown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    outbox = _open(tmp_path / "outbox.jsonl")
    handoff = TerminalCommitHandoff()
    handoff.attach_outbox(outbox)
    handoff.start()
    landed: list[StreamEvidenceSummary] = []

    async def commit(summary: StreamEvidenceSummary) -> None:
        landed.append(summary)

    def enospc(fd: int, data: bytes) -> int:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr("aegis.proxy.terminal_outbox.os.write", enospc)
    assert handoff.submit(commit, _summary(), replay=_context("enospc-1")) is True
    monkeypatch.undo()
    await handoff.stop(timeout=5.0)

    assert outbox.errors == 1
    assert outbox.pending_count == 0
    assert len(landed) == 1
    outbox.close()


# ── the ledger's digest form ─────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"request_bytes": REQUEST, "request_digest": ("0" * 64, 1)}, "exactly one"),
        ({}, "exactly one"),
        ({"request_digest": ("Z" * 64, 1)}, "lowercase SHA-256"),
        ({"request_digest": ("0" * 64, (1 << 20) + 1)}, "size"),
        ({"request_bytes": REQUEST, "evidence_status": "made-up"}, "evidence_status"),
    ],
)
def test_the_digest_form_is_validated(tmp_path: Path, kwargs: dict[str, Any], message: str) -> None:
    ledger = _ledger(tmp_path)
    with pytest.raises(ValueError, match=message):
        ledger.commit_forensic_summary(
            state_id="bad",
            response_hash="0" * 64,
            response_size=0,
            response_preview=b"",
            terminal_outcome="complete",
            final_marker_included=True,
            token_count=0,
            elapsed_seconds=0.0,
            **kwargs,
        )
    ledger.close()


# ── the app ──────────────────────────────────────────────────────────────────


def _settings(tmp_path: Path, **overrides: Any) -> Any:
    from aegis.config import AegisSettings

    return AegisSettings(
        security_enforcement_mode="development",
        wal_path=str(tmp_path / "app.wal.jsonl"),
        backend_api_key="k",
        **overrides,
    )


def test_the_app_replays_the_spool_before_serving(tmp_path: Path) -> None:
    from fastapi.testclient import TestClient

    from aegis.proxy.app import create_app

    spool = tmp_path / "app.wal.jsonl.terminal-outbox.jsonl"
    outbox = _open(spool)
    outbox.record(_context("from-before"), _summary())
    outbox.close()

    app = create_app(_settings(tmp_path, terminal_outbox_enabled=True))
    with TestClient(app):
        state = app.state.aegis
        [node] = _nodes_for(state.ledger, "from-before")
        assert node.signature_meaning == RECOVERED_MEANING
        assert state.terminal_outbox is not None
        assert state.terminal_outbox.pending_count == 0
    assert spool.read_bytes() == b""
    records = [json.loads(line) for line in spool.read_bytes().splitlines()]
    assert records == []


def test_the_outbox_is_off_by_default(tmp_path: Path) -> None:
    from fastapi.testclient import TestClient

    from aegis.proxy.app import create_app

    app = create_app(_settings(tmp_path))
    with TestClient(app):
        assert app.state.aegis.terminal_outbox is None
    assert not (tmp_path / "app.wal.jsonl.terminal-outbox.jsonl").exists()

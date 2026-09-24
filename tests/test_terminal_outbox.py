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
import contextlib
import gc
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
    derive_mac_key,
    has_terminal_node,
    replay_pending,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
REQUEST = b'{"model":"m","stream":true,"messages":[{"role":"user","content":"hello"}]}'
RESPONSE = b"data: sanitized\n\ndata: [DONE]\n\n"
SIGNING_KEY = "test-signing-key"
MAC_KEY = derive_mac_key(SIGNING_KEY)


def _ledger(tmp_path: Path, name: str = "chain.wal") -> CryptographicAuditLedger:
    return CryptographicAuditLedger(
        persistence_path=str(tmp_path / name),
        signing_key=SIGNING_KEY,
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
    kwargs.setdefault("mac_key", MAC_KEY)
    kwargs.setdefault("max_bytes", 1 << 20)
    return TerminalOutbox.open(path, **kwargs)


def _signed_line(payload: dict[str, Any], key: bytes = MAC_KEY) -> bytes:
    import hmac

    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    mac = hmac.new(key, body, hashlib.sha256).hexdigest()
    return json.dumps({**payload, "mac": mac}, sort_keys=True, separators=(",", ":")).encode()


def _pending_payload(state_id: str, **ctx_overrides: Any) -> dict[str, Any]:
    from dataclasses import asdict

    from aegis.proxy.terminal_outbox import SpooledSummary

    summary = _summary()
    ctx = {**asdict(_context(state_id)), **ctx_overrides}
    spooled = SpooledSummary(
        response_hash=summary.response_hash,
        response_size=summary.response_size,
        terminal_outcome=summary.terminal_outcome,
        final_marker_included=summary.final_marker_included,
        token_count=summary.token_count,
        elapsed_seconds=summary.elapsed_seconds,
        redaction_hits={},
    )
    return {"v": 1, "op": "pending", "id": state_id + "-id", "ctx": ctx, "summary": asdict(spooled)}


def _nodes_for(ledger: CryptographicAuditLedger, state_id: str) -> list[Any]:
    return [node for node in ledger.chain_snapshot() if node.state_id == state_id]


# ── the spool ────────────────────────────────────────────────────────────────


def test_the_spool_holds_no_content_and_is_owner_only(tmp_path: Path) -> None:
    sentinel = b"SENTINEL-RESPONSE-CONTENT-7f3a"
    path = tmp_path / "outbox.jsonl"
    outbox = _open(path)
    spooled = outbox.record(_context(), _summary(preview=RESPONSE + sentinel))
    assert spooled is not None
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
        spooled = outbox.record(_context("killed-1"), _summary())
        assert spooled is not None
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


def test_a_torn_tail_is_quarantined_and_the_next_record_is_not_lost(tmp_path: Path) -> None:
    """Review finding 2: the record written after a torn tail used to be lost with it."""

    path = tmp_path / "outbox.jsonl"
    outbox = _open(path)
    outbox.record(_context("whole"), _summary())
    outbox.close()
    torn = b'{"v":1,"op":"pending","id":"torn","ctx":{"state_'
    with path.open("ab") as handle:
        handle.write(torn)  # power lost mid-write: no newline

    after_torn = _open(path)
    after_torn.record(_context("after-torn"), _summary())
    after_torn.close()

    reopened = _open(path)
    try:
        assert sorted(e.context.state_id for e in reopened.pending_entries()) == [
            "after-torn",
            "whole",
        ]
        assert torn in (tmp_path / "outbox.jsonl.quarantine").read_bytes()
    finally:
        reopened.close()


def test_a_torn_tail_is_newline_isolated_even_if_compaction_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Opening normally also compacts the fragment away; this pins the newline guard
    on its own, for the case where that compaction cannot run."""

    path = tmp_path / "outbox.jsonl"
    path.write_bytes(b'{"v":1,"op":"pending","id":"torn","ctx":{"state_')
    monkeypatch.setattr(TerminalOutbox, "compact", lambda self: None)
    outbox = _open(path)
    outbox.record(_context("after-torn"), _summary())
    outbox.close()
    monkeypatch.undo()

    reopened = _open(path)
    try:
        assert [e.context.state_id for e in reopened.pending_entries()] == ["after-torn"]
    finally:
        reopened.close()


def test_a_forged_or_foreign_line_is_quarantined_never_replayed(tmp_path: Path) -> None:
    """Review finding 1: replay signs what it reads, so it reads only what it wrote."""

    path = tmp_path / "outbox.jsonl"
    forged = _signed_line(_pending_payload("forged"), key=derive_mac_key("attacker-guess"))
    unsigned = json.dumps(_pending_payload("unsigned"), sort_keys=True).encode()
    path.write_bytes(forged + b"\n" + unsigned + b"\n")

    outbox = _open(path)
    try:
        assert outbox.pending_count == 0
        assert outbox.corrupt_lines == 2
        quarantined = (tmp_path / "outbox.jsonl.quarantine").read_bytes()
        assert forged in quarantined
        assert unsigned in quarantined
        assert path.read_bytes() == b""  # compacted; the lines live on in quarantine
    finally:
        outbox.close()


@pytest.mark.parametrize(
    "override",
    [
        {"request_hash": list("0" * 64)},
        {"request_size": True},
        {"signer_name": ["svc"]},
        {"phi_scrubbed": "yes"},
    ],
)
def test_an_authenticated_line_with_wrong_types_is_quarantined(
    tmp_path: Path, override: dict[str, Any]
) -> None:
    """A malformed record must be refused at load, never reach the ledger lock."""

    path = tmp_path / "outbox.jsonl"
    path.write_bytes(_signed_line(_pending_payload("typed", **override)) + b"\n")
    outbox = _open(path)
    try:
        assert outbox.pending_count == 0
        assert outbox.corrupt_lines == 1
    finally:
        outbox.close()


def test_another_record_version_survives_compaction_in_quarantine(tmp_path: Path) -> None:
    """Review finding 3: compaction used to erase lines it could not read."""

    path = tmp_path / "outbox.jsonl"
    newer = _signed_line({**_pending_payload("v2"), "v": 2})
    path.write_bytes(newer + b"\n")
    outbox = _open(path)
    outbox.record(_context("kept"), _summary())
    outbox.compact()
    outbox.close()

    assert newer in (tmp_path / "outbox.jsonl.quarantine").read_bytes()
    assert newer not in path.read_bytes()


def test_a_small_spool_keeps_accepting_records(tmp_path: Path) -> None:
    """Review finding 4: below 1 MiB the outbox used to fill once and stay full."""

    outbox = _open(tmp_path / "outbox.jsonl", max_bytes=64 * 1024)
    try:
        for index in range(600):  # ~0.6 MiB of pending+done lines through a 64 KiB cap
            entry_id = outbox.record(_context(f"s-{index}"), _summary())
            assert entry_id is not None, f"refused at record {index}"
            outbox.mark_done(entry_id)
        assert outbox.skipped == 0
        assert (tmp_path / "outbox.jsonl").stat().st_size < 64 * 1024
    finally:
        outbox.close()


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
    live_status = live_params.pop("evidence_status")
    recovered_status = recovered_params.pop("evidence_status")
    assert live_status == "durable-terminal"
    assert recovered_status == "recovered-terminal"
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


async def test_a_node_that_landed_is_done_even_if_a_later_step_fails(tmp_path: Path) -> None:
    """Review finding 5: rate-limit settlement failing after the commit used to leave
    a landed node pending, to be replayed as a duplicate past the retained window."""

    ledger = _ledger(tmp_path)
    outbox = _open(tmp_path / "outbox.jsonl")
    handoff = TerminalCommitHandoff()
    handoff.attach_outbox(outbox, landed=lambda sid: has_terminal_node(ledger, sid))
    handoff.start()

    async def commit_then_fail(summary: StreamEvidenceSummary) -> None:
        ledger.commit_forensic_summary(
            state_id="landed-then-failed",
            request_bytes=REQUEST,
            response_hash=summary.response_hash,
            response_size=summary.response_size,
            response_preview=b"",
            terminal_outcome=summary.terminal_outcome,
            final_marker_included=False,
            token_count=0,
            elapsed_seconds=0.0,
        )
        raise RuntimeError("reservation.finalize failed after the commit")

    handoff.submit(commit_then_fail, _summary(), replay=_context("landed-then-failed"))
    await handoff.stop(timeout=5.0)

    assert outbox.pending_count == 0
    assert len(_nodes_for(ledger, "landed-then-failed")) == 1
    outbox.close()
    ledger.close()


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


_DIGEST = hashlib.sha256(REQUEST).hexdigest()


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"request_bytes": REQUEST, "request_digest": (_DIGEST, 1)}, "exactly one"),
        ({}, "exactly one"),
        ({"request_digest": ("Z" * 64, 1), "signature_meaning": RECOVERED_MEANING}, "SHA-256"),
        (
            {"request_digest": (list("0" * 64), 1), "signature_meaning": RECOVERED_MEANING},
            "SHA-256",
        ),
        (
            {"request_digest": (_DIGEST, (1 << 20) + 1), "signature_meaning": RECOVERED_MEANING},
            "size",
        ),
        ({"request_digest": (_DIGEST, True), "signature_meaning": RECOVERED_MEANING}, "size"),
        ({"request_digest": (_DIGEST, 1)}, "recovery-only"),
        ({"request_bytes": REQUEST, "signature_meaning": RECOVERED_MEANING}, "reserved"),
        ({"request_bytes": REQUEST, "signer_name": ["svc"]}, "signer_name"),
    ],
)
def test_the_digest_form_is_validated_before_the_lock(
    tmp_path: Path, kwargs: dict[str, Any], message: str
) -> None:
    """A malformed value is refused up front; it must not fail inside signing and
    latch the ledger's fault state (the reviewer's probe latched signing_failed)."""

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
    assert ledger._fault_state == "healthy"
    ledger.close()


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"response_size": "5"}, "response_size"),
        ({"response_size": -1}, "response_size"),
        ({"response_size": True}, "response_size"),
        ({"token_count": "5"}, "token_count"),
        ({"token_count": -1}, "token_count"),
        ({"token_count": True}, "token_count"),
        ({"final_marker_included": 1}, "final_marker_included"),
        ({"final_marker_included": "yes"}, "final_marker_included"),
        ({"elapsed_seconds": "0.5"}, "elapsed_seconds"),
        ({"elapsed_seconds": True}, "elapsed_seconds"),
        ({"elapsed_seconds": -0.1}, "elapsed_seconds"),
        ({"redaction_hits": {1: 5}}, "redaction_hits"),
        ({"redaction_hits": {"pii": True}}, "redaction_hits"),
        ({"redaction_hits": {"pii": -1}}, "redaction_hits"),
        ({"redaction_hits": []}, "redaction_hits"),
        ({"redaction_hits": [("pii", 1)]}, "redaction_hits"),
        ({"redaction_hits": "not-a-dict"}, "redaction_hits"),
        ({"redaction_hits": 5}, "redaction_hits"),
    ],
)
def test_a_malformed_scalar_or_redaction_field_raises_value_error(
    tmp_path: Path, kwargs: dict[str, Any], message: str
) -> None:
    """Sourcery review on PR #197: ``response_size``/``token_count`` reached a
    bare ``< 0`` and ``elapsed_seconds`` reached ``math.isfinite`` before being
    type-checked, so a non-comparable value (a string) raised an incidental
    ``TypeError`` instead of the ``ValueError`` the docstring promises every
    field gets; ``final_marker_included`` had no check at all; and
    ``redaction_hits``' ``isinstance(value, int)`` let a ``bool`` through and
    never checked that a key was a ``str``. A second Sourcery round on the
    fix for this same PR found ``redaction_hits`` itself was never checked to
    be a ``dict`` before ``dict(redaction_hits or {})``: a falsy non-dict
    (``[]``, ``0``) silently became ``{}``, an iterable of pairs
    (``[("pii", 1)]``) was silently accepted despite violating the annotated
    ``dict[str, int]``, and any other non-dict raised whatever ``TypeError``
    or ``ValueError`` the built-in ``dict()`` call happened to raise instead
    of the documented one. Mirrors
    ``test_the_digest_form_is_validated_before_the_lock``'s shape."""

    ledger = _ledger(tmp_path)
    base: dict[str, Any] = {
        "state_id": "bad-scalar",
        "request_bytes": REQUEST,
        "response_hash": "0" * 64,
        "response_size": 0,
        "response_preview": b"",
        "terminal_outcome": "complete",
        "final_marker_included": True,
        "token_count": 0,
        "elapsed_seconds": 0.0,
    }
    base.update(kwargs)
    with pytest.raises(ValueError, match=message):
        ledger.commit_forensic_summary(**base)
    assert ledger._fault_state == "healthy"
    ledger.close()


# ── the app ──────────────────────────────────────────────────────────────────


def _settings(tmp_path: Path, **overrides: Any) -> Any:
    from aegis.config import AegisSettings

    base: dict[str, Any] = {
        "security_enforcement_mode": "development",
        "wal_path": str(tmp_path / "app.wal.jsonl"),
        "backend_api_key": "k",
        "signing_key": SIGNING_KEY,
    }
    base.update(overrides)
    return AegisSettings(**base)


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


def test_enabling_the_outbox_without_a_signing_key_refuses_startup(tmp_path: Path) -> None:
    from fastapi.testclient import TestClient

    from aegis.proxy.app import create_app

    app = create_app(_settings(tmp_path, terminal_outbox_enabled=True, signing_key=""))
    with pytest.raises(RuntimeError, match="AEGIS_SIGNING_KEY"), TestClient(app):
        pass


def test_a_refused_outbox_open_starts_no_other_service(tmp_path: Path) -> None:
    """Review finding: ``lifespan`` is ``@asynccontextmanager``, so a startup step
    that raises skips this function's entire post-``yield`` shutdown half — a
    service already started above the raising line would leak. The outbox open
    (which can raise: a bad path, a missing signing key) now runs before SIEM
    export starts, not after, so a refusal here has nothing above it to leak.
    """
    from fastapi.testclient import TestClient

    from aegis.proxy.app import create_app

    app = create_app(
        _settings(
            tmp_path,
            terminal_outbox_enabled=True,
            signing_key="",
            siem_url="https://siem.example/collector",
            siem_spool_path=tmp_path / "siem.sqlite3",
        )
    )
    with pytest.raises(RuntimeError, match="AEGIS_SIGNING_KEY"), TestClient(app):
        pass
    state = app.state.aegis
    assert state.siem_exporter is not None  # constructed outside the lifespan
    assert state.siem_exporter._thread is None  # never started


def test_a_later_startup_failure_still_closes_the_outbox(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review finding on this PR: the fix above (``test_a_refused_outbox_open_
    starts_no_other_service``) only closed the gap for the outbox's own
    ``open()`` call raising. Once that succeeds, ``lifespan`` still runs
    several more steps before ``yield`` — SIEM/S3 startup, the handoff worker,
    LSM, vault, the forwarder, gossip, seccomp — and any of those raising
    leaves an already-open outbox fd with nothing to close it, for the same
    underlying reason: Starlette skips this function's whole post-``yield``
    half when startup raises. ``lifespan`` now wraps that whole span in an
    ``AsyncExitStack`` that stops every resource it started on any exception,
    not just the outbox (see ``test_a_much_later_startup_failure_stops_the_
    handoff_worker_too`` below for a resource started after the outbox).
    This simulates the handoff worker's own (unconditional, config-free)
    start raising, since it is the very next statement after the outbox is
    wired into ``state``.
    """
    from fastapi.testclient import TestClient

    from aegis.proxy.app import create_app

    def _boom(self: TerminalCommitHandoff) -> None:
        raise RuntimeError("simulated later-startup failure")

    app = create_app(_settings(tmp_path, terminal_outbox_enabled=True))
    # Patch the class of the instance lifespan will call, not a name imported
    # here: a module reloaded earlier in the session leaves the two different.
    monkeypatch.setattr(type(app.state.aegis.terminal_handoff), "start", _boom)
    with pytest.raises(RuntimeError, match="simulated later-startup failure"), TestClient(app):
        pass
    state = app.state.aegis
    assert state.terminal_outbox is not None  # wired into state before the failure
    assert state.terminal_outbox._fd is None  # AsyncExitStack closed it on the way out


def test_a_much_later_startup_failure_stops_the_handoff_worker_too(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Sourcery review on this PR: the fix above only registered a cleanup
    callback for the outbox. Once ``state.terminal_handoff.start()`` succeeds,
    several more steps still run before ``yield`` (LSM, vault, the forwarder,
    gossip, seccomp); any of those raising left the handoff worker — and
    whatever else had already started — running with nothing to stop it, for
    the same reason: Starlette skips this function's whole post-``yield``
    shutdown when startup raises. ``lifespan`` now registers a stop callback
    for every resource right after it starts, not just the outbox. Simulates
    the forwarder's own ``start()`` raising, well after the handoff worker is
    already running, and asserts the worker was stopped anyway.
    """
    from fastapi.testclient import TestClient

    import aegis.proxy.app as app_module

    # Both classes are taken from where lifespan resolves them, not imported
    # here: tests/test_coverage_final.py reloads aegis.proxy.forwarder, after
    # which `from aegis.proxy.forwarder import LLMForwarder` is a new class
    # object that app.py never calls — patching it made this test pass under
    # xdist and fail in CI's serial run.
    app = app_module.create_app(_settings(tmp_path, terminal_outbox_enabled=True))
    handoff_cls = type(app.state.aegis.terminal_handoff)
    forwarder_cls = app_module.LLMForwarder

    stopped = False
    real_stop = handoff_cls.stop

    async def _spy_stop(self: TerminalCommitHandoff, *, timeout: float) -> None:
        nonlocal stopped
        stopped = True
        await real_stop(self, timeout=timeout)

    def _boom(self: object) -> None:
        raise RuntimeError("simulated forwarder startup failure")

    monkeypatch.setattr(handoff_cls, "stop", _spy_stop)
    monkeypatch.setattr(forwarder_cls, "start", _boom)

    with pytest.raises(RuntimeError, match="simulated forwarder startup failure"), TestClient(app):
        pass
    assert stopped  # the handoff worker, started long before the forwarder, was stopped too


@pytest.mark.parametrize("provider", ["openai", "anthropic"])
async def test_the_real_app_spools_exactly_what_its_live_commit_signs(
    tmp_path: Path, provider: str
) -> None:
    """Review note 9: the parity test above builds both sides from helpers. This one
    drives the real /v1/chat/completions closure through a client disconnect and
    replays the record the app itself spooled into a second ledger: the two nodes
    must agree on everything but previews, markers and timestamp."""

    from types import SimpleNamespace
    from unittest.mock import MagicMock

    from aegis.proxy.app import create_app

    app = create_app(
        _settings(
            tmp_path,
            api_keys="sk-valid",
            auth_disabled=False,
            waf_strict_mode=False,
            provider=provider,
        )
    )
    state = app.state.aegis
    spool = tmp_path / "spool.jsonl"
    outbox = _open(spool)
    state.terminal_outbox = outbox
    state.terminal_handoff.attach_outbox(
        outbox, landed=lambda sid: has_terminal_node(state.ledger, sid)
    )

    async def fake_openai(_path: str, _body: Any, extra_headers: Any = None) -> Any:
        for _ in range(200):
            yield b'data: {"choices":[{"delta":{"content":"x"}}]}\n', {"choices": [{}]}
            await asyncio.sleep(0)

    async def fake_anthropic(_body: Any, extra_headers: Any = None) -> Any:
        delta = {"type": "content_block_delta", "delta": {"type": "text_delta", "text": "x"}}
        for _ in range(200):
            yield (
                b"event: content_block_delta\ndata: " + json.dumps(delta).encode() + b"\n\n",
                delta,
            )
            await asyncio.sleep(0)

    forwarder = MagicMock()
    forwarder.stream_sse = MagicMock(side_effect=fake_openai)
    forwarder.stream_native_anthropic = MagicMock(side_effect=fake_anthropic)
    forwarder.provider = SimpleNamespace(name=provider, supports_logprobs=False)
    state.forwarder = forwarder

    # A raw ASGI call whose send fails after the first body chunk: a client that
    # went away mid-stream, delivered the way the server stack delivers it (the
    # REG-D07 reproduction). httpx's ASGITransport buffers the whole response, so
    # it cannot produce a teardown at all.
    path = "/v1/chat/completions" if provider == "openai" else "/v1/messages"
    request = {"model": "m", "messages": [{"role": "user", "content": "hi"}], "stream": True}
    if provider == "anthropic":
        request["max_tokens"] = 16
    body = json.dumps(request).encode()
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": [
            (b"host", b"test"),
            (b"content-type", b"application/json"),
            (b"authorization", b"Bearer sk-valid"),
            (b"content-length", str(len(body)).encode()),
        ],
        "client": ("127.0.0.1", 50000),
        "server": ("test", 80),
    }
    delivered = False
    statuses: list[int] = []

    async def receive() -> dict[str, Any]:
        nonlocal delivered
        if not delivered:
            delivered = True
            return {"type": "http.request", "body": body, "more_body": False}
        await asyncio.sleep(3600)
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        if message["type"] == "http.response.start":
            statuses.append(message["status"])
        if message["type"] == "http.response.body" and message.get("body"):
            raise OSError("client went away")

    try:
        with contextlib.suppress(Exception):
            await app(scope, receive, send)
        assert statuses == [200]
        # The response generator the failed send abandoned is closed by asyncio's
        # async-generator finalizer when it is collected — that aclose() is the
        # teardown the handoff exists for. Collect it here, inside the test.
        for _ in range(100):
            gc.collect()
            await asyncio.sleep(0.05)
            if outbox.spooled == 1 and outbox.pending_count == 0:
                break

        assert outbox.spooled == 1, "the disconnect did not go through the spooling handoff"
        [live] = [
            n
            for n in state.ledger.chain_snapshot()
            if n.signature_meaning == "stream-terminal-evidence"
        ]
        pending = [
            json.loads(line)
            for line in spool.read_bytes().splitlines()
            if b'"op":"pending"' in line
        ]
        assert len(pending) == 1
        from aegis.proxy.terminal_outbox import OutboxEntry, _context_from, _summary_from

        entry = OutboxEntry(
            entry_id=pending[0]["id"],
            context=_context_from(pending[0]["ctx"]),
            summary=_summary_from(pending[0]["summary"]),
        )
        assert entry.context.state_id == live.state_id

        replay_ledger = _ledger(tmp_path, "replay.wal")
        replay_ledger.commit_forensic_summary(**entry.commit_kwargs())
        [recovered] = _nodes_for(replay_ledger, live.state_id)
        for field in (
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
        live_status = live_params.pop("evidence_status")
        recovered_status = recovered_params.pop("evidence_status")
        assert live_status == "durable-terminal"
        assert recovered_status == "recovered-terminal"
        assert recovered_params == live_params
        replay_ledger.close()
    finally:
        outbox.close()
        state.ledger.close()

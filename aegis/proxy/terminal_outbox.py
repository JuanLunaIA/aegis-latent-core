# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Durable outbox for terminal stream evidence handed off at teardown (REG-D32).

``TerminalCommitHandoff`` (``streaming.py``) commits a torn-down stream's
terminal node outside the cancelled request scope, but in process: a crash or
SIGKILL between teardown and the drained commit loses it, and so does a full
handoff queue. With the outbox enabled, the handoff first appends one JSON line
per commit to a spool beside the WAL, the worker marks it done once the commit
has landed, and the next start replays whatever is still pending before any
traffic is served.

The spool is content-free by construction: digests, sizes, counts, labels and
flags — never a request body, a response preview or any other customer content.
It therefore adds no plaintext at rest and has nothing for crypto-shredding to
miss. The cost is honest and visible: a recovered node carries empty previews,
its timestamp is the replay time, and it is signed as
``stream-terminal-evidence-recovered`` with ``evidence_status`` set to
``recovered-terminal``, so it cannot be mistaken for a live commit.

Durability, stated exactly: a record survives process death once ``record()``
returns (one ``write`` to an ``O_APPEND`` descriptor, in the page cache), and
survives power loss once the worker's ``sync()`` has run, which it does before
every commit. Replay refuses to run against a ledger whose fault state is not
``healthy``; the spool is kept intact for the next start.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from aegis.core import observability

if TYPE_CHECKING:
    from aegis.proxy.streaming import StreamEvidenceSummary

logger = logging.getLogger(__name__)

RECORD_VERSION = 1
RECOVERED_MEANING = "stream-terminal-evidence-recovered"
TERMINAL_MEANINGS = frozenset({"stream-terminal-evidence", RECOVERED_MEANING})
_DEFAULT_MAX_PENDING = 4096
_COMPACT_AT_BYTES = 1 << 20


@dataclass(frozen=True)
class TerminalReplayContext:
    """What a handed-off commit needs to be replayed without the request in memory."""

    state_id: str
    request_hash: str
    request_size: int
    tenant_id: str
    model: str
    endpoint: str
    phi_scrubbed: bool
    scrub_method: str
    append_stream_window_method: bool
    signer_name: str


@dataclass(frozen=True)
class SpooledSummary:
    """The scalar half of a ``StreamEvidenceSummary`` — its preview is left out."""

    response_hash: str
    response_size: int
    terminal_outcome: str
    final_marker_included: bool
    token_count: int
    elapsed_seconds: float
    redaction_hits: dict[str, int]


@dataclass(frozen=True)
class OutboxEntry:
    entry_id: str
    context: TerminalReplayContext
    summary: SpooledSummary

    def commit_kwargs(self) -> dict[str, Any]:
        """Keyword arguments for ``commit_forensic_summary`` in its digest form.

        Mirrors the live closures in ``aegis/proxy/app.py`` field for field,
        except the request/response previews (not spooled) and the two markers
        that make a recovered node distinguishable.
        """
        hits = dict(self.summary.redaction_hits)
        scrub_method = self.context.scrub_method
        if self.context.append_stream_window_method and hits:
            scrub_method = (scrub_method + "+stream_window_regex").lstrip("+")
        return {
            "state_id": self.context.state_id,
            "request_digest": (self.context.request_hash, self.context.request_size),
            "response_hash": self.summary.response_hash,
            "response_size": self.summary.response_size,
            "response_preview": b"",
            "terminal_outcome": self.summary.terminal_outcome,
            "final_marker_included": self.summary.final_marker_included,
            "token_count": self.summary.token_count,
            "elapsed_seconds": self.summary.elapsed_seconds,
            "redaction_hits": hits,
            "tenant_id": self.context.tenant_id,
            "model": self.context.model,
            "endpoint": self.context.endpoint,
            "phi_scrubbed": self.context.phi_scrubbed or bool(hits),
            "scrub_method": scrub_method,
            "signer_name": self.context.signer_name,
            "signature_meaning": RECOVERED_MEANING,
            "evidence_status": "recovered-terminal",
        }


@dataclass
class ReplayReport:
    pending: int = 0
    recovered: int = 0
    deduplicated: int = 0
    failed: int = 0
    refused_fault_state: str = ""


def _line(payload: dict[str, Any]) -> bytes:
    return (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _fsync_directory(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class TerminalOutbox:
    """Append-only spool of pending terminal commits.

    Every mutating call runs on the event-loop thread (``record`` from stream
    teardown, ``mark_done`` and ``compact`` from the handoff worker between
    awaits), so they never interleave. ``record`` and ``mark_done`` never raise:
    a spool failure is counted and the in-memory handoff proceeds as it did
    before the outbox existed.
    """

    def __init__(
        self,
        path: Path,
        fd: int,
        *,
        max_bytes: int,
        max_pending: int = _DEFAULT_MAX_PENDING,
        pending: dict[str, OutboxEntry] | None = None,
        size: int = 0,
        corrupt_lines: int = 0,
    ) -> None:
        self._path = path
        self._fd: int | None = fd
        self._max_bytes = max_bytes
        self._max_pending = max_pending
        self._pending: dict[str, OutboxEntry] = dict(pending or {})
        self._size = size
        self.corrupt_lines = corrupt_lines
        self.spooled = 0
        self.skipped = 0
        self.errors = 0

    # ── construction ──────────────────────────────────────────────────────

    @classmethod
    def open(
        cls, path: Path, *, max_bytes: int, max_pending: int = _DEFAULT_MAX_PENDING
    ) -> TerminalOutbox:
        """Open (creating 0600) and load the pending set. Raises on failure."""

        created = not path.exists()
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.chmod(path, 0o600)
            if created:
                os.fsync(fd)
                _fsync_directory(path.parent)
            pending, corrupt = cls._load(path)
            size = os.fstat(fd).st_size
        except BaseException:
            os.close(fd)
            raise
        if corrupt:
            observability.TERMINAL_OUTBOX_ERRORS.inc(corrupt)
            logger.error(
                "terminal outbox %s: %d unparseable line(s) skipped (a torn tail from a "
                "crash mid-write, or damage); the records they held cannot be replayed",
                path,
                corrupt,
            )
        return cls(
            path,
            fd,
            max_bytes=max_bytes,
            max_pending=max_pending,
            pending=pending,
            size=size,
            corrupt_lines=corrupt,
        )

    @staticmethod
    def _load(path: Path) -> tuple[dict[str, OutboxEntry], int]:
        pending: dict[str, OutboxEntry] = {}
        corrupt = 0
        for raw in path.read_bytes().splitlines():
            if not raw.strip():
                continue
            try:
                record = json.loads(raw)
                if record.get("v") != RECORD_VERSION:
                    raise ValueError("unsupported record version")
                entry_id = str(record["id"])
                if record["op"] == "done":
                    pending.pop(entry_id, None)
                elif record["op"] == "pending":
                    pending[entry_id] = OutboxEntry(
                        entry_id=entry_id,
                        context=TerminalReplayContext(**record["ctx"]),
                        summary=SpooledSummary(**record["summary"]),
                    )
                else:
                    raise ValueError("unknown op")
            except (ValueError, KeyError, TypeError):
                corrupt += 1
        return pending, corrupt

    # ── state ─────────────────────────────────────────────────────────────

    @property
    def path(self) -> Path:
        return self._path

    @property
    def pending_count(self) -> int:
        return len(self._pending)

    def pending_entries(self) -> list[OutboxEntry]:
        return list(self._pending.values())

    # ── writes ────────────────────────────────────────────────────────────

    def _append(self, data: bytes) -> None:
        if self._fd is None:
            raise OSError("terminal outbox is closed")
        written = os.write(self._fd, data)
        if written != len(data):
            raise OSError(f"short write to terminal outbox ({written}/{len(data)} bytes)")
        self._size += written

    def record(self, context: TerminalReplayContext, summary: StreamEvidenceSummary) -> str | None:
        """Spool one handed-off commit. Synchronous, no await, never raises."""

        if len(self._pending) >= self._max_pending or self._size >= self._max_bytes:
            self.skipped += 1
            observability.TERMINAL_OUTBOX_ERRORS.inc()
            logger.error(
                "terminal outbox full (pending=%d, bytes=%d); this commit is in-memory only",
                len(self._pending),
                self._size,
            )
            return None
        entry = OutboxEntry(
            entry_id=uuid.uuid4().hex,
            context=context,
            summary=SpooledSummary(
                response_hash=summary.response_hash,
                response_size=summary.response_size,
                terminal_outcome=summary.terminal_outcome,
                final_marker_included=summary.final_marker_included,
                token_count=summary.token_count,
                elapsed_seconds=summary.elapsed_seconds,
                redaction_hits=dict(summary.redaction_hits),
            ),
        )
        try:
            self._append(self._pending_line(entry))
        except Exception:  # teardown must never lose the in-memory commit to a spool error
            self.errors += 1
            observability.TERMINAL_OUTBOX_ERRORS.inc()
            logger.exception("terminal outbox write failed; this commit is in-memory only")
            return None
        self._pending[entry.entry_id] = entry
        self.spooled += 1
        return entry.entry_id

    @staticmethod
    def _pending_line(entry: OutboxEntry) -> bytes:
        return _line(
            {
                "v": RECORD_VERSION,
                "op": "pending",
                "id": entry.entry_id,
                "ctx": asdict(entry.context),
                "summary": asdict(entry.summary),
            }
        )

    def mark_done(self, entry_id: str) -> None:
        """Record that ``entry_id`` has landed in the ledger. Never raises."""

        if self._pending.pop(entry_id, None) is None:
            return
        try:
            self._append(_line({"v": RECORD_VERSION, "op": "done", "id": entry_id}))
        except Exception:
            # The entry stays pending on disk and will be replayed; replay's
            # state_id check is what keeps that from becoming a duplicate.
            self.errors += 1
            observability.TERMINAL_OUTBOX_ERRORS.inc()
            logger.exception("terminal outbox done-marker write failed")
            return
        if self._size >= _COMPACT_AT_BYTES:
            self.compact()

    async def sync(self) -> None:
        """Push spooled records to stable storage. Counts, never raises."""

        fd = self._fd
        if fd is None:
            return
        try:
            await asyncio.to_thread(os.fsync, fd)
        except Exception:
            self.errors += 1
            observability.TERMINAL_OUTBOX_ERRORS.inc()
            logger.exception("terminal outbox fsync failed")

    def compact(self) -> None:
        """Rewrite the spool as just the pending records, by atomic rename."""

        if self._fd is None:
            return
        tmp = self._path.with_name(self._path.name + ".compact")
        data = b"".join(self._pending_line(entry) for entry in self._pending.values())
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                view = memoryview(data)
                while view:
                    view = view[os.write(fd, view) :]
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(tmp, self._path)
            _fsync_directory(self._path.parent)
            new_fd = os.open(self._path, os.O_WRONLY | os.O_APPEND)
        except Exception:
            self.errors += 1
            observability.TERMINAL_OUTBOX_ERRORS.inc()
            logger.exception("terminal outbox compaction failed; continuing on the old spool")
            return
        old_fd, self._fd = self._fd, new_fd
        self._size = len(data)
        try:
            os.close(old_fd)
        except OSError:
            logger.warning("terminal outbox: closing the pre-compaction descriptor failed")

    def close(self) -> None:
        if self._fd is not None:
            fd, self._fd = self._fd, None
            os.close(fd)


def _committed_terminal_state_ids(ledger: Any) -> set[str]:
    return {
        node.state_id
        for node in ledger.chain_snapshot()
        if getattr(node, "signature_meaning", "") in TERMINAL_MEANINGS
    }


async def replay_pending(
    outbox: TerminalOutbox,
    *,
    ledger: Any,
    commit: Callable[..., Any],
) -> ReplayReport:
    """Commit every pending spool entry through ``commit``, before traffic.

    Fail-closed: nothing is appended unless the ledger's fault state is
    ``healthy``, re-checked before each commit, and the spool is left intact
    when it is not. An entry whose ``state_id`` already has a terminal node in
    the retained chain is marked done without a second commit — the case of a
    crash after the commit landed but before its done marker was written.
    """

    report = ReplayReport(pending=outbox.pending_count)
    if report.pending == 0:
        return report
    committed = _committed_terminal_state_ids(ledger)
    for entry in outbox.pending_entries():
        fault = getattr(ledger, "_fault_state", "healthy")
        if fault != "healthy":
            report.refused_fault_state = str(fault)
            logger.error(
                "terminal outbox replay refused: ledger fault_state=%s; %d record(s) kept "
                "in %s for the next start",
                fault,
                outbox.pending_count,
                outbox.path,
            )
            return report
        if entry.context.state_id in committed:
            outbox.mark_done(entry.entry_id)
            report.deduplicated += 1
            continue
        try:
            await asyncio.to_thread(commit, **entry.commit_kwargs())
        except Exception:
            report.failed += 1
            observability.TERMINAL_OUTBOX_ERRORS.inc()
            logger.exception(
                "terminal outbox replay failed for state_id=%s; kept for the next start",
                entry.context.state_id,
            )
            continue
        committed.add(entry.context.state_id)
        outbox.mark_done(entry.entry_id)
        report.recovered += 1
        observability.TERMINAL_OUTBOX_RECOVERED.inc()
    outbox.compact()
    return report

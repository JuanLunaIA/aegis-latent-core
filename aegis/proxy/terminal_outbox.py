# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Durable outbox for terminal stream evidence handed off at teardown (REG-D32).

``TerminalCommitHandoff`` (``streaming.py``) commits a torn-down stream's
terminal node outside the cancelled request scope, but in process: a crash or
SIGKILL between teardown and the drained commit loses it, and so does a full
handoff queue. With the outbox enabled, the handoff first appends one JSON line
per commit to a spool beside the WAL, the worker marks it done once the ledger
holds the node, and the next start replays whatever is still pending before any
traffic is served.

The spool holds no request body and no response preview. It does hold, per
record, the plain SHA-256 digests of the request and response, the tenant label
and the signer name — the same values a stream-terminal node stores — and those
linger on disk after a record is done until the spool is next compacted.
``crypto_shred`` does not reach the spool. A recovered node carries empty
previews, its timestamp is the replay time, and it is signed as
``stream-terminal-evidence-recovered``; the ledger derives its
``evidence_status`` (``recovered-terminal``) from the request form, so a caller
cannot label a recovered node as a live one.

Every line carries an HMAC-SHA256 under a key derived from the ledger's signing
key. A line that fails it — forged, damaged, torn, or from another record
version — is never replayed: it is moved to ``<spool>.quarantine`` (kept, not
deleted) and counted. Without that, write access to the WAL's volume would be
enough to have the gateway sign an arbitrary record at the next start.

Durability, stated exactly: a record survives process death once ``record()``
returns (one ``write`` to an ``O_APPEND`` descriptor, in the page cache), and
survives power loss once the worker's ``sync()`` has run, which it does before
every commit. Replay refuses to run against a ledger whose fault state is not
``healthy``; the spool is kept intact for the next start.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import math
import os
import uuid
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Protocol

from aegis.core import observability
from aegis.core.crypto_audit import RECOVERED_TERMINAL_MEANING

logger = logging.getLogger(__name__)

RECORD_VERSION = 1
RECOVERED_MEANING = RECOVERED_TERMINAL_MEANING
TERMINAL_MEANINGS = frozenset({"stream-terminal-evidence", RECOVERED_MEANING})
_MAC_DOMAIN = b"aegis-terminal-outbox-mac-v1"
_DEFAULT_MAX_PENDING = 4096
_COMPACT_AT_BYTES = 1 << 20
_MAX_PAYLOAD_BYTES = 1 << 20
_HEX = frozenset("0123456789abcdef")


def derive_mac_key(signing_key: str | bytes) -> bytes:
    """The spool's authentication key, derived from — never equal to — the signing key."""

    raw = signing_key.encode("utf-8") if isinstance(signing_key, str) else signing_key
    if not raw:
        raise ValueError(
            "the terminal outbox needs a non-empty signing key to authenticate its spool"
        )
    return hmac.new(raw, _MAC_DOMAIN, hashlib.sha256).digest()


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


class TerminalSummary(Protocol):
    """What ``record`` reads from a ``streaming.StreamEvidenceSummary``.

    Structural on purpose: ``streaming`` imports this module's types, so importing
    ``StreamEvidenceSummary`` back would make the two modules a cycle.
    """

    @property
    def response_hash(self) -> str:
        pass

    @property
    def response_size(self) -> int:
        pass

    @property
    def terminal_outcome(self) -> str:
        pass

    @property
    def final_marker_included(self) -> bool:
        pass

    @property
    def token_count(self) -> int:
        pass

    @property
    def elapsed_seconds(self) -> float:
        pass

    @property
    def redaction_hits(self) -> Mapping[str, int]:
        pass


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
        except the previews (not spooled) and the recovered signature meaning;
        ``tests/test_terminal_outbox.py`` checks that against the real app.
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
        }


@dataclass
class ReplayReport:
    pending: int = 0
    recovered: int = 0
    deduplicated: int = 0
    failed: int = 0
    refused_fault_state: str = ""


# ── strict decoding: a replayed record is signed, so every field is checked ───


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_digest(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and set(value) <= _HEX


def _context_from(raw: object) -> TerminalReplayContext:
    if not isinstance(raw, dict) or set(raw) != set(TerminalReplayContext.__dataclass_fields__):
        raise ValueError("context fields do not match")
    for name in ("state_id", "tenant_id", "model", "endpoint", "scrub_method", "signer_name"):
        if not isinstance(raw[name], str):
            raise ValueError(f"{name} is not a string")
    for name in ("phi_scrubbed", "append_stream_window_method"):
        if not isinstance(raw[name], bool):
            raise ValueError(f"{name} is not a bool")
    if not _is_digest(raw["request_hash"]):
        raise ValueError("request_hash is not a SHA-256 hex digest")
    if not _is_int(raw["request_size"]) or not 0 <= raw["request_size"] <= _MAX_PAYLOAD_BYTES:
        raise ValueError("request_size out of range")
    return TerminalReplayContext(**raw)


def _summary_from(raw: object) -> SpooledSummary:
    if not isinstance(raw, dict) or set(raw) != set(SpooledSummary.__dataclass_fields__):
        raise ValueError("summary fields do not match")
    if not _is_digest(raw["response_hash"]):
        raise ValueError("response_hash is not a SHA-256 hex digest")
    for name in ("response_size", "token_count"):
        if not _is_int(raw[name]) or raw[name] < 0:
            raise ValueError(f"{name} out of range")
    if not isinstance(raw["terminal_outcome"], str):
        raise ValueError("terminal_outcome is not a string")
    if not isinstance(raw["final_marker_included"], bool):
        raise ValueError("final_marker_included is not a bool")
    elapsed = raw["elapsed_seconds"]
    if isinstance(elapsed, bool) or not isinstance(elapsed, (int, float)):
        raise ValueError("elapsed_seconds is not a number")
    if not math.isfinite(elapsed) or elapsed < 0:
        raise ValueError("elapsed_seconds out of range")
    hits = raw["redaction_hits"]
    if not isinstance(hits, dict) or any(
        not isinstance(k, str) or not _is_int(v) or v < 0 for k, v in hits.items()
    ):
        raise ValueError("redaction_hits is not a str -> non-negative int map")
    return SpooledSummary(**{**raw, "elapsed_seconds": float(elapsed)})


def _fsync_directory(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _fsync_and_close(fd: int) -> None:
    """Runs in a worker thread that owns ``fd``, so no caller can close it early."""

    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class TerminalOutbox:
    """Append-only, authenticated spool of pending terminal commits.

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
        mac_key: bytes,
        max_bytes: int,
        max_pending: int = _DEFAULT_MAX_PENDING,
        pending: dict[str, OutboxEntry] | None = None,
        size: int = 0,
        corrupt_lines: int = 0,
    ) -> None:
        if not mac_key:
            raise ValueError("mac_key must be non-empty")
        self._path = path
        self._fd: int | None = fd
        self._mac_key = mac_key
        self._max_bytes = max_bytes
        self._max_pending = max_pending
        self._compact_at = max(1, min(_COMPACT_AT_BYTES, max_bytes // 2))
        self._pending: dict[str, OutboxEntry] = dict(pending or {})
        self._size = size
        self.corrupt_lines = corrupt_lines
        self.spooled = 0
        self.skipped = 0
        self.errors = 0

    # ── construction ──────────────────────────────────────────────────────

    @classmethod
    def open(
        cls,
        path: Path,
        *,
        mac_key: bytes,
        max_bytes: int,
        max_pending: int = _DEFAULT_MAX_PENDING,
    ) -> TerminalOutbox:
        """Open (creating 0600), isolate a torn tail, quarantine what cannot be
        authenticated, load the pending set, and compact. Raises on failure."""

        if not mac_key:
            raise ValueError("mac_key must be non-empty")
        created = not path.exists()
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.chmod(path, 0o600)
            if created:
                os.fsync(fd)
                _fsync_directory(path.parent)
            data = path.read_bytes()
            if data and not data.endswith(b"\n"):
                # A power loss mid-write leaves a line with no newline; the next
                # record would be appended onto it and lost with it.
                os.write(fd, b"\n")
                os.fsync(fd)
            pending, rejected = cls._load(data, mac_key)
            if rejected:
                cls._quarantine(path, rejected)
            size = os.fstat(fd).st_size
        except BaseException:
            os.close(fd)
            raise
        if rejected:
            observability.TERMINAL_OUTBOX_ERRORS.inc(len(rejected))
            logger.error(
                "terminal outbox %s: %d line(s) failed authentication or parsing (a torn "
                "tail, damage, another record version, or tampering); moved to %s and not "
                "replayed",
                path,
                len(rejected),
                cls._quarantine_path(path),
            )
        outbox = cls(
            path,
            fd,
            mac_key=mac_key,
            max_bytes=max_bytes,
            max_pending=max_pending,
            pending=pending,
            size=size,
            corrupt_lines=len(rejected),
        )
        if rejected or size >= outbox._compact_at:
            outbox.compact()
        return outbox

    @staticmethod
    def _quarantine_path(path: Path) -> Path:
        return path.with_name(path.name + ".quarantine")

    @classmethod
    def _quarantine(cls, path: Path, lines: list[bytes]) -> None:
        target = cls._quarantine_path(path)
        fd = os.open(target, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, b"".join(line + b"\n" for line in lines))
            os.fsync(fd)
        finally:
            os.close(fd)

    @staticmethod
    def _load(data: bytes, mac_key: bytes) -> tuple[dict[str, OutboxEntry], list[bytes]]:
        pending: dict[str, OutboxEntry] = {}
        rejected: list[bytes] = []
        for raw in data.splitlines():
            if not raw.strip():
                continue
            try:
                record = json.loads(raw)
                if not isinstance(record, dict):
                    raise ValueError("not an object")
                mac = record.pop("mac", None)
                expected = hmac.new(mac_key, _canonical(record), hashlib.sha256).hexdigest()
                if not isinstance(mac, str) or not hmac.compare_digest(mac, expected):
                    raise ValueError("authentication failed")
                if record.get("v") != RECORD_VERSION:
                    raise ValueError("unsupported record version")
                entry_id = record["id"]
                if not isinstance(entry_id, str) or not entry_id:
                    raise ValueError("bad id")
                if record["op"] == "done":
                    pending.pop(entry_id, None)
                elif record["op"] == "pending":
                    pending[entry_id] = OutboxEntry(
                        entry_id=entry_id,
                        context=_context_from(record["ctx"]),
                        summary=_summary_from(record["summary"]),
                    )
                else:
                    raise ValueError("unknown op")
            except (ValueError, KeyError, TypeError):
                rejected.append(raw)
        return pending, rejected

    # ── state ─────────────────────────────────────────────────────────────

    @property
    def path(self) -> Path:
        return self._path

    @property
    def pending_count(self) -> int:
        return len(self._pending)

    def pending_entries(self) -> list[OutboxEntry]:
        return list(self._pending.values())

    def entry(self, entry_id: str) -> OutboxEntry | None:
        return self._pending.get(entry_id)

    # ── writes ────────────────────────────────────────────────────────────

    def _line(self, payload: dict[str, Any]) -> bytes:
        mac = hmac.new(self._mac_key, _canonical(payload), hashlib.sha256).hexdigest()
        return _canonical({**payload, "mac": mac}) + b"\n"

    def _append(self, data: bytes) -> None:
        if self._fd is None:
            raise OSError("terminal outbox is closed")
        written = os.write(self._fd, data)
        if written != len(data):
            raise OSError(f"short write to terminal outbox ({written}/{len(data)} bytes)")
        self._size += written

    def record(self, context: TerminalReplayContext, summary: TerminalSummary) -> str | None:
        """Spool one handed-off commit. Synchronous, no await, never raises."""

        try:
            if self._size >= self._max_bytes:
                self.compact()
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
            self._append(self._pending_line(entry))
        except Exception:  # teardown must never lose the in-memory commit to a spool error
            self.errors += 1
            observability.TERMINAL_OUTBOX_ERRORS.inc()
            logger.exception("terminal outbox write failed; this commit is in-memory only")
            return None
        self._pending[entry.entry_id] = entry
        self.spooled += 1
        return entry.entry_id

    def _pending_line(self, entry: OutboxEntry) -> bytes:
        return self._line(
            {
                "v": RECORD_VERSION,
                "op": "pending",
                "id": entry.entry_id,
                "ctx": asdict(entry.context),
                "summary": asdict(entry.summary),
            }
        )

    def mark_done(self, entry_id: str) -> None:
        """Record that ``entry_id``'s node is in the ledger. Never raises."""

        if self._pending.pop(entry_id, None) is None:
            return
        try:
            self._append(self._line({"v": RECORD_VERSION, "op": "done", "id": entry_id}))
            if self._size >= self._compact_at:
                self.compact()
        except Exception:
            # The entry stays pending on disk and will be replayed; replay's
            # state_id check is what keeps that from becoming a duplicate.
            self.errors += 1
            observability.TERMINAL_OUTBOX_ERRORS.inc()
            logger.exception("terminal outbox done-marker write failed")

    async def sync(self) -> None:
        """Push spooled records to stable storage. Counts, never raises.

        The fsync runs on a duplicate descriptor owned by the worker thread, so a
        shutdown that closes the outbox while an fsync is still in flight cannot
        close the descriptor under it, or let its number be reused.
        """

        if self._fd is None:
            return
        try:
            owned = os.dup(self._fd)
            await asyncio.to_thread(_fsync_and_close, owned)
        except Exception:
            self.errors += 1
            observability.TERMINAL_OUTBOX_ERRORS.inc()
            logger.exception("terminal outbox fsync failed")

    def compact(self) -> None:
        """Rewrite the spool as just the pending records, by atomic rename.

        Lines that could not be authenticated or parsed were already moved to the
        quarantine file when the spool was opened, so nothing unread is dropped.
        """

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


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode(
        "utf-8"
    )


def has_terminal_node(ledger: Any, state_id: str) -> bool:
    """True when the retained chain holds a terminal node for ``state_id``."""

    return any(
        node.state_id == state_id and getattr(node, "signature_meaning", "") in TERMINAL_MEANINGS
        for node in reversed(ledger.chain_snapshot())
    )


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

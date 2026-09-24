# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.ha — running more than one gateway replica without forking evidence.

Selected by ``AEGIS_HA_MODE``; ``single`` (the default) changes nothing. Neither
mechanism below touches how an evidence node is built, signed or made durable:
each replica's local, fsynced WAL stays the authoritative record of what it
committed (``AD-17`` in ``docs/architecture/DECISIONS.md`` revises ``AD-16``).

**Chain writer lease** (``active_passive``, ``active_active``). A chain has at
most one writer. Before it opens a WAL a replica takes a Redis lease on that
chain, ``aegis:ha:lease:<chain_id>``, whose value names the holder and a
monotonic *epoch* (``INCR aegis:ha:epoch:<chain_id>``). The holder renews every
third of the TTL from a dedicated thread. It stops admitting requests once its
own conservative view of the lease — measured from *before* each renewal was
sent, minus a margin — has run out, and on loss it shuts down so the
orchestrator restarts it as a standby. A standby answers ``/health`` and
refuses everything else until it wins the lease; the new holder records the
handover in its chain as a signed state node carrying the epoch.

**Global sequence** (``active_active``; optional for ``active_passive``). Every
durable node of every replica is referenced, in one total order, by a
hash-linked entry in a shared table (PostgreSQL in production). Appends are
compare-and-append on the table's tip, so concurrent replicas can interleave but
never fork it, and each append also checks, *in the same transaction*, that the
chain's previous entry is this node's predecessor and that the writer's lease
epoch is not older than the chain's last one. That last check is a real
storage-side fence: a paused former holder is refused, not merely detected.
Sequencing trails the local commit by a bounded, monitored lag; admission is
refused while the lag exceeds ``AEGIS_HA_MAX_SEQUENCING_LAG_SECONDS``.

What this does **not** establish: consensus over node *content* (each chain's
content is its writer's), clock agreement (timestamps are each writer's),
availability of Redis or the sequence store (their outage stops admission —
the fail-closed direction), or that a lease holder paused past its TTL cannot
append one more node to its *local* WAL. The global sequence's epoch fence is
what bounds the damage of that last case: the stale node is never sequenced,
and ``verify_global_sequence`` plus ``verify_chain_references`` expose it.
"""

from __future__ import annotations

import asyncio
import datetime
import hashlib
import json
import logging
import os
import secrets
import signal
import socket
import ssl
import threading
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from aegis.config import AegisSettings
    from aegis.core.crypto_audit import AuditNode

logger = logging.getLogger(__name__)

HA_MODE_SINGLE = "single"
HA_MODE_ACTIVE_PASSIVE = "active_passive"
HA_MODE_ACTIVE_ACTIVE = "active_active"

GENESIS_HASH = "0" * 64
SEQUENCE_DOMAIN = b"aegis-global-sequence-v1\x00"
SEQUENCE_TABLE = "aegis_global_sequence"


class LeaseUnavailableError(RuntimeError):
    """Another replica holds the chain's writer lease."""


class SequenceDivergedError(RuntimeError):
    """The sequence store refused an append that would contradict it.

    Raised when a chain's previous entry is not this node's predecessor (a second
    writer, or a WAL that is not the one the sequence was built from) or when the
    writer's lease epoch is older than the chain's last entry (a stale holder).
    Never retried: it is a fence, not contention.
    """


# ── Chain writer lease ──────────────────────────────────────────────────────

# KEYS[1] lease key, KEYS[2] epoch counter; ARGV[1] holder id, ARGV[2] TTL (ms).
# A fresh acquisition always draws a new epoch, so epochs order every holder the
# chain has ever had. Re-acquiring a lease this holder already owns keeps its
# epoch (holder ids are unique per process, so this is only ever the same process).
_ACQUIRE_LUA = """
local current = redis.call('GET', KEYS[1])
if current == false then
  local epoch = redis.call('INCR', KEYS[2])
  redis.call('SET', KEYS[1], ARGV[1] .. '|' .. epoch, 'PX', ARGV[2])
  return epoch
end
local sep = string.find(current, '|', 1, true)
if sep and string.sub(current, 1, sep - 1) == ARGV[1] then
  redis.call('PEXPIRE', KEYS[1], ARGV[2])
  return tonumber(string.sub(current, sep + 1))
end
return false
"""

# KEYS[1] lease key; ARGV[1] the exact value we set, ARGV[2] TTL (ms).
_RENEW_LUA = """
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('PEXPIRE', KEYS[1], ARGV[2])
end
return 0
"""

_RELEASE_LUA = """
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
end
return 0
"""


def new_holder_id() -> str:
    """A holder id unique to this process: host, pid and a random suffix."""
    return f"{socket.gethostname()}:{os.getpid()}:{secrets.token_hex(6)}"


class ChainLease:
    """Exclusive, expiring, epoch-numbered right to write one chain.

    ``client`` is a synchronous ``redis.Redis``; every mutation is a single Lua
    script, so check-and-set is atomic on the server. ``holds()`` is this
    process's conservative view: the lease counts as held only until
    ``(time before the last successful renewal was sent) + ttl − margin``.
    """

    def __init__(
        self,
        client: Any,
        chain_id: str,
        holder_id: str,
        ttl_seconds: float,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not chain_id or any(ch in chain_id for ch in "|\r\n\x00"):
            raise ValueError("chain_id must be non-empty and contain no '|' or control characters")
        if "|" in holder_id:
            raise ValueError("holder_id must not contain '|'")
        if ttl_seconds < 1.0:
            raise ValueError("ttl_seconds must be at least 1")
        self.chain_id = chain_id
        self.holder_id = holder_id
        self.ttl_seconds = ttl_seconds
        self.margin_seconds = max(0.2 * ttl_seconds, 0.5)
        self.key = f"aegis:ha:lease:{chain_id}"
        self.epoch_key = f"aegis:ha:epoch:{chain_id}"
        self._client = client
        self._clock = clock
        self._state_lock = threading.Lock()
        self._epoch: int | None = None
        self._valid_until = 0.0
        self._acquire_script = client.register_script(_ACQUIRE_LUA)
        self._renew_script = client.register_script(_RENEW_LUA)
        self._release_script = client.register_script(_RELEASE_LUA)

    @property
    def epoch(self) -> int | None:
        with self._state_lock:
            return self._epoch

    @property
    def _ttl_ms(self) -> int:
        return int(self.ttl_seconds * 1000)

    def _value(self, epoch: int) -> str:
        return f"{self.holder_id}|{epoch}"

    def acquire(self) -> int | None:
        """Take the lease if it is free; return its epoch, or None if held elsewhere."""
        sent = self._clock()
        result = self._acquire_script(
            keys=[self.key, self.epoch_key], args=[self.holder_id, self._ttl_ms]
        )
        if result is None:
            return None
        epoch = int(result)
        with self._state_lock:
            self._epoch = epoch
            self._valid_until = sent + self.ttl_seconds - self.margin_seconds
        return epoch

    def renew(self) -> bool:
        """Extend the lease. False means it is gone (expired, or taken over)."""
        epoch = self.epoch
        if epoch is None:
            return False
        sent = self._clock()
        renewed = int(self._renew_script(keys=[self.key], args=[self._value(epoch), self._ttl_ms]))
        with self._state_lock:
            if renewed == 1:
                self._valid_until = sent + self.ttl_seconds - self.margin_seconds
                return True
            self._valid_until = 0.0
            return False

    def release(self) -> None:
        """Give the lease up, only if it is still ours."""
        epoch = self.epoch
        with self._state_lock:
            self._valid_until = 0.0
        if epoch is not None:
            self._release_script(keys=[self.key], args=[self._value(epoch)])

    def holds(self) -> bool:
        with self._state_lock:
            return self._clock() < self._valid_until

    def seconds_remaining(self) -> float:
        with self._state_lock:
            return max(0.0, self._valid_until - self._clock())


class LeaseKeeper(threading.Thread):
    """Renews a held lease every third of its TTL; calls ``on_lost`` once if it goes.

    A thread, not an event-loop task, on purpose: the lease is taken before the
    WAL is replayed, and replay can outlast a TTL. The seccomp filter is loaded
    with thread synchronization (REG-D82), so this thread is under it too.
    """

    def __init__(self, lease: ChainLease, on_lost: Callable[[str], None]) -> None:
        super().__init__(name=f"aegis-lease-{lease.chain_id}", daemon=True)
        self._lease = lease
        self._on_lost = on_lost
        self._stop_event = threading.Event()

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        interval = self._lease.ttl_seconds / 3.0
        retry = min(1.0, self._lease.ttl_seconds / 10.0)
        wait = interval
        while not self._stop_event.wait(wait):
            try:
                if self._lease.renew():
                    wait = interval
                    continue
                self._on_lost("the lease expired in Redis or another replica took it over")
                return
            except Exception as exc:
                if not self._lease.holds():
                    self._on_lost(f"the lease could not be renewed before it ran out ({exc})")
                    return
                logger.warning(
                    "writer lease renewal failed, %.1fs of lease left; retrying: %s",
                    self._lease.seconds_remaining(),
                    exc,
                )
                wait = retry


def wait_for_lease(
    lease: ChainLease,
    poll_seconds: float,
    stop: threading.Event | None = None,
) -> int:
    """Block until *lease* is acquired; return its epoch.

    Redis errors are logged and retried like a held lease: a standby that cannot
    reach Redis must not conclude that it may write.
    """
    announced = ""
    while True:
        try:
            epoch = lease.acquire()
            if epoch is not None:
                logger.info(
                    "writer lease acquired: chain=%s epoch=%d holder=%s",
                    lease.chain_id,
                    epoch,
                    lease.holder_id,
                )
                return epoch
            state = "held by another replica"
        except Exception as exc:
            state = f"unreachable ({type(exc).__name__})"
        if state != announced:
            logger.warning("standby: writer lease for chain %s is %s", lease.chain_id, state)
            announced = state
        if stop is not None and stop.wait(poll_seconds):
            raise LeaseUnavailableError("stopped while waiting for the writer lease")
        if stop is None:
            time.sleep(poll_seconds)


class StandbyResponder:
    """Minimal listener for a standby replica: alive, not ready, serves nothing.

    ``GET /health`` answers 200 ``{"status": "standby"}`` so a liveness probe does
    not restart a healthy standby; everything else, ``/ready`` included, answers
    503 so no traffic is routed to it. Stopped before the gateway binds the port.
    """

    def __init__(
        self,
        host: str,
        port: int,
        chain_id: str,
        *,
        ssl_certfile: str | None = None,
        ssl_keyfile: str | None = None,
    ) -> None:
        self._host = host
        self._port = port
        self._chain_id = chain_id
        self._ssl = (ssl_certfile, ssl_keyfile) if ssl_certfile and ssl_keyfile else None
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        chain_id = self._chain_id

        class Handler(BaseHTTPRequestHandler):
            def _answer(self, code: int, body: dict[str, str]) -> None:
                data = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self) -> None:  # noqa: N802 - http.server API
                if self.path.split("?", 1)[0] == "/health":
                    self._answer(200, {"status": "standby", "chain_id": chain_id})
                else:
                    self._refuse()

            def do_POST(self) -> None:  # noqa: N802 - http.server API
                self._refuse()

            def _refuse(self) -> None:
                self._answer(
                    503,
                    {"detail": "standby replica: it does not hold the chain writer lease"},
                )

            def log_message(self, *args: object) -> None:
                return

        server = ThreadingHTTPServer((self._host, self._port), Handler)
        if self._ssl is not None:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(*self._ssl)
            server.socket = context.wrap_socket(server.socket, server_side=True)
        self._server = server
        self._thread = threading.Thread(
            target=server.serve_forever, name="aegis-standby", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None


# ── Global sequence ─────────────────────────────────────────────────────────


@dataclass(frozen=True)
class SequenceEntry:
    """One reference, in the global order, to one durable node of one chain."""

    seq: int
    prev_entry_hash: str
    chain_id: str
    chain_epoch: int
    local_seq: int
    node_hash: str
    local_prev_hash: str
    recorded_at: str
    entry_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "prev_entry_hash": self.prev_entry_hash,
            "chain_id": self.chain_id,
            "chain_epoch": self.chain_epoch,
            "local_seq": self.local_seq,
            "node_hash": self.node_hash,
            "local_prev_hash": self.local_prev_hash,
            "recorded_at": self.recorded_at,
            "entry_hash": self.entry_hash,
        }


def compute_entry_hash(
    *,
    seq: int,
    prev_entry_hash: str,
    chain_id: str,
    chain_epoch: int,
    local_seq: int,
    node_hash: str,
    local_prev_hash: str,
    recorded_at: str,
) -> str:
    """Domain-separated SHA-256 over the entry's canonical JSON (sorted keys)."""
    body = json.dumps(
        {
            "seq": seq,
            "prev_entry_hash": prev_entry_hash,
            "chain_id": chain_id,
            "chain_epoch": chain_epoch,
            "local_seq": local_seq,
            "node_hash": node_hash,
            "local_prev_hash": local_prev_hash,
            "recorded_at": recorded_at,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(SEQUENCE_DOMAIN + body).hexdigest()


@dataclass(frozen=True)
class PendingNode:
    """A durable local node waiting to be sequenced."""

    local_seq: int
    node_hash: str
    local_prev_hash: str


def plan_append(
    last: SequenceEntry | None,
    epoch: int,
    items: Sequence[PendingNode],
) -> list[PendingNode]:
    """Return the items still to append, or raise SequenceDivergedError.

    The fence, applied inside the append transaction: items already sequenced
    are dropped (idempotent retry); the first new item must continue the chain's
    last entry exactly; and a writer whose epoch is older than that entry's is
    refused.
    """
    for earlier, later in zip(items, items[1:], strict=False):
        if later.local_seq != earlier.local_seq + 1 or later.local_prev_hash != earlier.node_hash:
            raise ValueError("pending nodes must be contiguous and linked")
    if last is None:
        return list(items)
    if epoch < last.chain_epoch:
        raise SequenceDivergedError(
            f"chain {last.chain_id}: writer epoch {epoch} is older than the sequenced "
            f"epoch {last.chain_epoch}; a newer lease holder exists"
        )
    remaining = [item for item in items if item.local_seq > last.local_seq]
    for item in items:
        if item.local_seq == last.local_seq and item.node_hash != last.node_hash:
            raise SequenceDivergedError(
                f"chain {last.chain_id}: position {item.local_seq} is already sequenced "
                "as a different node"
            )
    if not remaining:
        return []
    first = remaining[0]
    if first.local_seq != last.local_seq + 1 or first.local_prev_hash != last.node_hash:
        raise SequenceDivergedError(
            f"chain {last.chain_id}: node at position {first.local_seq} does not continue "
            f"the sequenced chain (last sequenced position {last.local_seq})"
        )
    return remaining


def _build_entries(
    tip: tuple[int, str] | None,
    chain_id: str,
    epoch: int,
    items: Sequence[PendingNode],
) -> list[SequenceEntry]:
    seq, prev = tip if tip is not None else (0, GENESIS_HASH)
    recorded_at = (
        datetime.datetime.now(datetime.UTC)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )
    entries: list[SequenceEntry] = []
    for item in items:
        seq += 1
        entry_hash = compute_entry_hash(
            seq=seq,
            prev_entry_hash=prev,
            chain_id=chain_id,
            chain_epoch=epoch,
            local_seq=item.local_seq,
            node_hash=item.node_hash,
            local_prev_hash=item.local_prev_hash,
            recorded_at=recorded_at,
        )
        entries.append(
            SequenceEntry(
                seq=seq,
                prev_entry_hash=prev,
                chain_id=chain_id,
                chain_epoch=epoch,
                local_seq=item.local_seq,
                node_hash=item.node_hash,
                local_prev_hash=item.local_prev_hash,
                recorded_at=recorded_at,
                entry_hash=entry_hash,
            )
        )
        prev = entry_hash
    return entries


# Every statement is a literal; all values are bound parameters.
_SQLITE_CREATE = (
    "CREATE TABLE IF NOT EXISTS aegis_global_sequence ("
    "seq INTEGER PRIMARY KEY, prev_entry_hash TEXT NOT NULL, chain_id TEXT NOT NULL, "
    "chain_epoch INTEGER NOT NULL, local_seq INTEGER NOT NULL, node_hash TEXT NOT NULL, "
    "local_prev_hash TEXT NOT NULL, recorded_at TEXT NOT NULL, entry_hash TEXT NOT NULL UNIQUE, "
    "UNIQUE (chain_id, local_seq), UNIQUE (chain_id, node_hash))"
)
_SQLITE_LAST = (
    "SELECT seq, prev_entry_hash, chain_id, chain_epoch, local_seq, node_hash, local_prev_hash, recorded_at, entry_hash "
    "FROM aegis_global_sequence WHERE chain_id = ? ORDER BY local_seq DESC LIMIT 1"
)
_SQLITE_TIP = "SELECT seq, entry_hash FROM aegis_global_sequence ORDER BY seq DESC LIMIT 1"
_SQLITE_INSERT = (
    "INSERT INTO aegis_global_sequence (seq, prev_entry_hash, chain_id, chain_epoch, local_seq, node_hash, local_prev_hash, recorded_at, entry_hash) "
    "VALUES (?,?,?,?,?,?,?,?,?)"
)
_SQLITE_ENTRIES = (
    "SELECT seq, prev_entry_hash, chain_id, chain_epoch, local_seq, node_hash, local_prev_hash, recorded_at, entry_hash "
    "FROM aegis_global_sequence WHERE seq > ? ORDER BY seq LIMIT ?"
)
_PG_CREATE = (
    "CREATE TABLE IF NOT EXISTS aegis_global_sequence ("
    "seq BIGINT PRIMARY KEY, prev_entry_hash TEXT NOT NULL, chain_id TEXT NOT NULL, "
    "chain_epoch BIGINT NOT NULL, local_seq BIGINT NOT NULL, node_hash TEXT NOT NULL, "
    "local_prev_hash TEXT NOT NULL, recorded_at TEXT NOT NULL, entry_hash TEXT NOT NULL UNIQUE, "
    "UNIQUE (chain_id, local_seq), UNIQUE (chain_id, node_hash))"
)
_PG_LAST = (
    "SELECT seq, prev_entry_hash, chain_id, chain_epoch, local_seq, node_hash, local_prev_hash, recorded_at, entry_hash "
    "FROM aegis_global_sequence WHERE chain_id = $1 ORDER BY local_seq DESC LIMIT 1"
)
_PG_TIP = "SELECT seq, entry_hash FROM aegis_global_sequence ORDER BY seq DESC LIMIT 1"
_PG_INSERT = (
    "INSERT INTO aegis_global_sequence (seq, prev_entry_hash, chain_id, chain_epoch, local_seq, node_hash, local_prev_hash, recorded_at, entry_hash) "
    "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)"
)
_PG_ENTRIES = (
    "SELECT seq, prev_entry_hash, chain_id, chain_epoch, local_seq, node_hash, local_prev_hash, recorded_at, entry_hash "
    "FROM aegis_global_sequence WHERE seq > $1 ORDER BY seq LIMIT $2"
)


def _entry_from_row(row: Sequence[Any]) -> SequenceEntry:
    return SequenceEntry(
        seq=int(row[0]),
        prev_entry_hash=str(row[1]),
        chain_id=str(row[2]),
        chain_epoch=int(row[3]),
        local_seq=int(row[4]),
        node_hash=str(row[5]),
        local_prev_hash=str(row[6]),
        recorded_at=str(row[7]),
        entry_hash=str(row[8]),
    )


class SequenceStore(Protocol):
    async def open(self) -> None: ...
    async def close(self) -> None: ...
    async def last_for_chain(self, chain_id: str) -> SequenceEntry | None: ...
    async def append(
        self, chain_id: str, epoch: int, items: Sequence[PendingNode]
    ) -> list[SequenceEntry]: ...
    async def entries(self, after_seq: int = 0, limit: int = 1000) -> list[SequenceEntry]: ...


class SQLiteSequenceStore:
    """Single-host sequence store. ``BEGIN IMMEDIATE`` serializes appenders across
    processes on the same file. Not for network filesystems, and refused in
    strict mode (``AegisSettings._validate_ha``)."""

    def __init__(self, path: str, *, busy_timeout_seconds: float = 30.0) -> None:
        self._path = path
        self._timeout = busy_timeout_seconds
        self._db: Any = None
        self._lock = asyncio.Lock()

    async def open(self) -> None:
        import aiosqlite

        self._db = await aiosqlite.connect(self._path, timeout=self._timeout, isolation_level=None)
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute("PRAGMA synchronous=FULL")
        await self._db.execute(_SQLITE_CREATE)

    async def close(self) -> None:
        if self._db is not None:
            await self._db.close()
            self._db = None

    async def _last(self, chain_id: str) -> SequenceEntry | None:
        cursor = await self._db.execute(
            _SQLITE_LAST,
            (chain_id,),
        )
        row = await cursor.fetchone()
        return _entry_from_row(row) if row is not None else None

    async def last_for_chain(self, chain_id: str) -> SequenceEntry | None:
        async with self._lock:
            return await self._last(chain_id)

    async def append(
        self, chain_id: str, epoch: int, items: Sequence[PendingNode]
    ) -> list[SequenceEntry]:
        async with self._lock:
            await self._db.execute("BEGIN IMMEDIATE")
            try:
                todo = plan_append(await self._last(chain_id), epoch, items)
                cursor = await self._db.execute(_SQLITE_TIP)
                row = await cursor.fetchone()
                entries = _build_entries(
                    (int(row[0]), str(row[1])) if row else None, chain_id, epoch, todo
                )
                await self._db.executemany(
                    _SQLITE_INSERT,
                    [tuple(e.to_dict().values()) for e in entries],
                )
                await self._db.execute("COMMIT")
                return entries
            except BaseException:
                await self._db.execute("ROLLBACK")
                raise

    async def entries(self, after_seq: int = 0, limit: int = 1000) -> list[SequenceEntry]:
        async with self._lock:
            cursor = await self._db.execute(
                _SQLITE_ENTRIES,
                (after_seq, limit),
            )
            return [_entry_from_row(row) for row in await cursor.fetchall()]


class PostgresSequenceStore:
    """Production sequence store. Two appenders that read the same tip both try
    to insert the same ``seq``; the primary key lets exactly one commit and the
    other retries against the new tip, so the table interleaves but never forks.
    ``UNIQUE (chain_id, local_seq)`` backstops the per-chain fence."""

    def __init__(self, dsn: str, *, max_attempts: int = 50) -> None:
        self._dsn = dsn
        self._max_attempts = max_attempts
        self._pool: Any = None

    async def open(self) -> None:
        import asyncpg

        self._pool = await asyncpg.create_pool(self._dsn, min_size=1, max_size=4)
        async with self._pool.acquire() as conn:
            await conn.execute(_PG_CREATE)

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    @staticmethod
    async def _last(conn: Any, chain_id: str) -> SequenceEntry | None:
        row = await conn.fetchrow(
            _PG_LAST,
            chain_id,
        )
        return _entry_from_row(tuple(row)) if row is not None else None

    async def last_for_chain(self, chain_id: str) -> SequenceEntry | None:
        async with self._pool.acquire() as conn:
            return await self._last(conn, chain_id)

    async def append(
        self, chain_id: str, epoch: int, items: Sequence[PendingNode]
    ) -> list[SequenceEntry]:
        import asyncpg

        for attempt in range(self._max_attempts):
            async with self._pool.acquire() as conn:
                try:
                    async with conn.transaction():
                        todo = plan_append(await self._last(conn, chain_id), epoch, items)
                        row = await conn.fetchrow(_PG_TIP)
                        entries = _build_entries(
                            (int(row[0]), str(row[1])) if row else None, chain_id, epoch, todo
                        )
                        await conn.executemany(
                            _PG_INSERT,
                            [tuple(e.to_dict().values()) for e in entries],
                        )
                    return entries
                except asyncpg.UniqueViolationError:
                    # Lost the race for the tip; the next attempt reads the new
                    # one (and the per-chain fence re-runs against it).
                    await asyncio.sleep(min(0.2, 0.002 * (attempt + 1)) * secrets.randbelow(4))
        raise RuntimeError(
            f"global sequence append kept losing the tip race ({self._max_attempts})"
        )

    async def entries(self, after_seq: int = 0, limit: int = 1000) -> list[SequenceEntry]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                _PG_ENTRIES,
                after_seq,
                limit,
            )
            return [_entry_from_row(tuple(row)) for row in rows]


def open_sequence_store(url: str) -> SequenceStore:
    if url.startswith("sqlite:///"):
        return SQLiteSequenceStore(url[len("sqlite://") :])
    if url.startswith(("postgresql://", "postgres://")):
        return PostgresSequenceStore(url)
    raise ValueError("sequence store URL must be postgresql://… or sqlite:///absolute/path")


@dataclass
class SequenceReport:
    valid: bool
    entries: int
    chains: dict[str, int] = field(default_factory=dict)
    error_seq: int | None = None
    reason: str = ""


def verify_global_sequence(entries: Iterable[SequenceEntry]) -> SequenceReport:
    """Check a complete global sequence, from ``seq`` 1, entry by entry.

    Each entry must recompute to its ``entry_hash`` and link to its predecessor;
    within each chain, positions must be contiguous, each node must name the
    previous one as its predecessor, and lease epochs must never go backwards.
    """
    prev_hash = GENESIS_HASH
    expected = 1
    last_by_chain: dict[str, SequenceEntry] = {}
    count = 0
    for entry in entries:
        count += 1
        if entry.seq != expected:
            return SequenceReport(False, count, _counts(last_by_chain), entry.seq, "gap in seq")
        if entry.prev_entry_hash != prev_hash:
            return SequenceReport(False, count, _counts(last_by_chain), entry.seq, "broken link")
        recomputed = compute_entry_hash(
            seq=entry.seq,
            prev_entry_hash=entry.prev_entry_hash,
            chain_id=entry.chain_id,
            chain_epoch=entry.chain_epoch,
            local_seq=entry.local_seq,
            node_hash=entry.node_hash,
            local_prev_hash=entry.local_prev_hash,
            recorded_at=entry.recorded_at,
        )
        if recomputed != entry.entry_hash:
            return SequenceReport(False, count, _counts(last_by_chain), entry.seq, "entry altered")
        previous = last_by_chain.get(entry.chain_id)
        if previous is not None:
            if entry.local_seq != previous.local_seq + 1:
                return SequenceReport(
                    False, count, _counts(last_by_chain), entry.seq, "chain position skipped"
                )
            if entry.local_prev_hash != previous.node_hash:
                return SequenceReport(
                    False, count, _counts(last_by_chain), entry.seq, "chain link broken"
                )
            if entry.chain_epoch < previous.chain_epoch:
                return SequenceReport(
                    False, count, _counts(last_by_chain), entry.seq, "lease epoch went backwards"
                )
        last_by_chain[entry.chain_id] = entry
        prev_hash = entry.entry_hash
        expected += 1
    return SequenceReport(True, count, _counts(last_by_chain))


def _counts(last_by_chain: dict[str, SequenceEntry]) -> dict[str, int]:
    return {chain: entry.local_seq for chain, entry in sorted(last_by_chain.items())}


def verify_chain_references(
    entries: Iterable[SequenceEntry],
    chain_id: str,
    nodes: Iterable[tuple[str, str]],
) -> tuple[bool, str]:
    """Check that every entry for *chain_id* names the node at that position.

    *nodes* is the chain in order as ``(node_hash, prev_hash)`` pairs — for a
    WAL, ``((n.node_hash, n.prev_hash) for n in ledger.iter_wal_nodes())``.
    """
    by_position = {entry.local_seq: entry for entry in entries if entry.chain_id == chain_id}
    if not by_position:
        return True, "no entries for this chain"
    first = min(by_position)
    for position, (node_hash, prev_hash) in enumerate(nodes, start=first):
        entry = by_position.pop(position, None)
        if entry is None:
            continue
        if entry.node_hash != node_hash or entry.local_prev_hash != prev_hash:
            return False, f"position {position}: the sequence names a different node"
    if by_position:
        return False, f"{len(by_position)} sequenced node(s) are not in this chain"
    return True, "every sequenced node is in the chain at its recorded position"


class GlobalSequencer:
    """Follows one replica's durable commits and appends them to the global sequence.

    ``notify`` is registered as a ledger commit listener and may be called from
    any thread; the loop orders what it receives by ``prev_hash`` linkage, since
    notifications for concurrent commits can arrive out of chain order.
    """

    def __init__(
        self,
        store: SequenceStore,
        chain_id: str,
        epoch: Callable[[], int | None],
        *,
        max_lag_seconds: float,
        batch_size: int = 256,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        self._store = store
        self._chain_id = chain_id
        self._epoch = epoch
        self._max_lag = max_lag_seconds
        self._batch_size = batch_size
        self._wall_clock = wall_clock
        self._pending: dict[str, tuple[str, float]] = {}
        self._pending_lock = threading.Lock()
        self._next_prev = GENESIS_HASH
        self._next_local_seq = 1
        self._backfilled = False
        self._diverged = ""
        self._last_error = ""
        self._sequenced = 0
        self._loop: asyncio.AbstractEventLoop | None = None
        self._wake: asyncio.Event | None = None
        self._task: asyncio.Task[None] | None = None

    def notify(self, node: AuditNode) -> None:
        with self._pending_lock:
            self._pending[node.prev_hash] = (node.node_hash, node.timestamp)
        loop, wake = self._loop, self._wake
        if loop is not None and wake is not None:
            loop.call_soon_threadsafe(wake.set)

    async def start(self, wal_nodes: Callable[[], Iterable[AuditNode]]) -> None:
        """Open the store, sequence everything the WAL has that the sequence lacks,
        then keep following. Admission stays refused until the backlog is within
        the lag bound."""
        self._loop = asyncio.get_running_loop()
        self._wake = asyncio.Event()
        await self._store.open()
        await self._backfill(wal_nodes)
        self._task = asyncio.create_task(self._run(), name=f"aegis-sequencer-{self._chain_id}")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        await self._store.close()

    async def _backfill(self, wal_nodes: Callable[[], Iterable[AuditNode]]) -> None:
        last = await self._store.last_for_chain(self._chain_id)
        found = last is None
        first_prev: str | None = None
        position = 0
        # Collected outside the lock: reading a long WAL must not stall the
        # commit listener, which takes the same lock on every durable commit.
        unsequenced: dict[str, tuple[str, float]] = {}
        for node in wal_nodes():
            position += 1
            if first_prev is None:
                first_prev = node.prev_hash
            if not found:
                if last is not None and node.node_hash == last.node_hash:
                    if position != last.local_seq:
                        self._diverged = (
                            f"node {node.node_hash[:16]}… is sequenced at position "
                            f"{last.local_seq} but is at {position} in this WAL"
                        )
                        return
                    found = True
                continue
            unsequenced[node.prev_hash] = (node.node_hash, node.timestamp)
        with self._pending_lock:
            self._pending.update(unsequenced)
        if not found:
            assert last is not None
            self._diverged = (
                f"the last sequenced node of chain {self._chain_id} "
                f"({last.node_hash[:16]}…, position {last.local_seq}) is not in this WAL"
            )
            return
        if last is not None:
            self._next_prev, self._next_local_seq = last.node_hash, last.local_seq + 1
        elif first_prev is not None:
            self._next_prev, self._next_local_seq = first_prev, 1
        self._backfilled = True
        # Drain synchronously so a restart with a backlog is not admitted until
        # the backlog is inside the bound.
        while await self._sequence_ready():
            pass

    def _ready_batch(self) -> list[PendingNode]:
        batch: list[PendingNode] = []
        prev, position = self._next_prev, self._next_local_seq
        with self._pending_lock:
            while len(batch) < self._batch_size and prev in self._pending:
                node_hash, _ = self._pending[prev]
                batch.append(PendingNode(position, node_hash, prev))
                prev, position = node_hash, position + 1
        return batch

    async def _sequence_ready(self) -> bool:
        batch = self._ready_batch()
        if not batch or self._diverged:
            return False
        epoch = self._epoch()
        if epoch is None:
            self._last_error = "no writer lease epoch"
            return False
        try:
            await self._store.append(self._chain_id, epoch, batch)
        except SequenceDivergedError as exc:
            self._diverged = str(exc)
            logger.error("global sequence refused this replica: %s", exc)
            return False
        except Exception as exc:
            self._last_error = f"{type(exc).__name__}: {exc}"
            logger.warning("global sequence append failed; will retry: %s", self._last_error)
            return False
        with self._pending_lock:
            for item in batch:
                self._pending.pop(item.local_prev_hash, None)
        last = batch[-1]
        self._next_prev, self._next_local_seq = last.node_hash, last.local_seq + 1
        self._sequenced += len(batch)
        self._last_error = ""
        return True

    async def _run(self) -> None:
        assert self._wake is not None
        while True:
            try:
                await asyncio.wait_for(self._wake.wait(), timeout=0.5)
            except TimeoutError:
                pass
            self._wake.clear()
            while await self._sequence_ready():
                pass
            if self._last_error:
                await asyncio.sleep(0.5)

    def lag_seconds(self) -> float:
        with self._pending_lock:
            if not self._pending:
                return 0.0
            oldest = min(timestamp for _, timestamp in self._pending.values())
        return max(0.0, self._wall_clock() - oldest)

    def admission_error(self) -> str | None:
        if self._diverged:
            return f"global sequence diverged: {self._diverged}"
        if not self._backfilled:
            return "global sequence backfill has not completed"
        lag = self.lag_seconds()
        if lag > self._max_lag:
            detail = f" ({self._last_error})" if self._last_error else ""
            return f"global sequencing lag {lag:.1f}s exceeds {self._max_lag:.1f}s{detail}"
        return None

    def status(self) -> dict[str, Any]:
        with self._pending_lock:
            backlog = len(self._pending)
        return {
            "chain_id": self._chain_id,
            "backfilled": self._backfilled,
            "sequenced_since_start": self._sequenced,
            "backlog": backlog,
            "lag_seconds": round(self.lag_seconds(), 3),
            "diverged": bool(self._diverged),
            "last_error": self._last_error,
        }


# ── Controller ──────────────────────────────────────────────────────────────


class HAController:
    """What the gateway consults: may this replica admit a governed request?"""

    def __init__(
        self,
        mode: str,
        chain_id: str,
        lease: ChainLease | None,
        sequencer: GlobalSequencer | None,
    ) -> None:
        self.mode = mode
        self.chain_id = chain_id
        self.lease = lease
        self.sequencer = sequencer
        self._keeper: LeaseKeeper | None = None
        self._lost = ""

    def start_keeper(self, *, shutdown_on_loss: bool = True) -> None:
        if self.lease is None or self._keeper is not None:
            return

        def on_lost(reason: str) -> None:
            self._lost = reason
            logger.critical(
                "chain writer lease LOST (chain=%s): %s — refusing requests and shutting down",
                self.chain_id,
                reason,
            )
            if shutdown_on_loss:
                # raise() is tgkill, which the seccomp allowlist permits; kill is not.
                signal.raise_signal(signal.SIGTERM)

        self._keeper = LeaseKeeper(self.lease, on_lost)
        self._keeper.start()

    def stop(self) -> None:
        if self._keeper is not None:
            self._keeper.stop()
            self._keeper = None
        if self.lease is not None and not self._lost:
            try:
                self.lease.release()
            except Exception as exc:
                logger.warning("could not release the writer lease: %s", exc)

    def admission_error(self) -> str | None:
        if self._lost:
            return f"chain writer lease lost: {self._lost}"
        if self.lease is not None and not self.lease.holds():
            return "chain writer lease is not held"
        if self.sequencer is not None:
            return self.sequencer.admission_error()
        return None

    def status(self) -> dict[str, Any]:
        out: dict[str, Any] = {"mode": self.mode, "chain_id": self.chain_id}
        if self.lease is not None:
            out["lease"] = {
                "epoch": self.lease.epoch,
                "held": self.lease.holds(),
                "seconds_remaining": round(self.lease.seconds_remaining(), 3),
            }
        if self.sequencer is not None:
            out["sequence"] = self.sequencer.status()
        out["admitting"] = self.admission_error() is None
        return out


def chain_id_for(cfg: AegisSettings) -> str:
    return cfg.ha_chain_id or socket.gethostname()


def controller_from_settings(cfg: AegisSettings) -> HAController | None:
    """Build (but do not start) the controller ``cfg`` asks for; None for ``single``."""
    if cfg.ha_mode == HA_MODE_SINGLE:
        return None
    import redis

    chain_id = chain_id_for(cfg)
    client = redis.Redis.from_url(cfg.ha_redis_url or cfg.redis_url, socket_timeout=5.0)
    lease = ChainLease(client, chain_id, new_holder_id(), cfg.ha_lease_ttl_seconds)
    sequencer = None
    if cfg.ha_sequencer_url:
        sequencer = GlobalSequencer(
            open_sequence_store(cfg.ha_sequencer_url),
            chain_id,
            lambda: lease.epoch,
            max_lag_seconds=cfg.ha_max_sequencing_lag_seconds,
        )
    return HAController(cfg.ha_mode, chain_id, lease, sequencer)


_ACTIVE: HAController | None = None


def activate(controller: HAController | None) -> None:
    """Hand the controller ``main()`` built (lease already held) to ``create_app``."""
    global _ACTIVE
    _ACTIVE = controller


def active_controller() -> HAController | None:
    return _ACTIVE


def handover_record(controller: HAController) -> bytes:
    """The payload of the signed state node that records a writer handover."""
    assert controller.lease is not None
    return json.dumps(
        {
            "event": "ha_writer_lease_acquired",
            "mode": controller.mode,
            "chain_id": controller.chain_id,
            "epoch": controller.lease.epoch,
            "holder": controller.lease.holder_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


# ── Verification command ────────────────────────────────────────────────────


async def _read_all(url: str) -> list[SequenceEntry]:
    store = open_sequence_store(url)
    await store.open()
    try:
        entries: list[SequenceEntry] = []
        while True:
            page = await store.entries(after_seq=entries[-1].seq if entries else 0, limit=10_000)
            if not page:
                return entries
            entries.extend(page)
    finally:
        await store.close()


def _wal_chain(path: str) -> tuple[list[tuple[str, str]], list[int]]:
    """The chain as (node_hash, prev_hash) pairs, and the writer epochs its
    handover records name, in order."""
    from aegis.core.crypto_audit import AuditNode

    nodes: list[tuple[str, str]] = []
    epochs: list[int] = []
    with open(path) as handle:
        for raw in handle:
            if raw.strip():
                node = AuditNode.from_dict(json.loads(raw))
                nodes.append((node.node_hash, node.prev_hash))
                if node.state_id.startswith("ha-lease-"):
                    epochs.append(int(node.state_id.rsplit("-", 1)[1]))
    return nodes, epochs


def verify_command(sequencer_url: str, wals: dict[str, str]) -> dict[str, Any]:
    """What ``python -m aegis.core.ha verify`` checks and reports, as a dict."""
    entries = asyncio.run(_read_all(sequencer_url))
    report = verify_global_sequence(entries)
    result: dict[str, Any] = {
        "valid": report.valid,
        "entries": report.entries,
        "chains": report.chains,
        "error_seq": report.error_seq,
        "reason": report.reason,
        "wal": {},
    }
    for chain_id, path in sorted(wals.items()):
        nodes, epochs = _wal_chain(path)
        linked = all(
            later[1] == earlier[0] for earlier, later in zip(nodes, nodes[1:], strict=False)
        )
        ok, why = verify_chain_references(entries, chain_id, nodes)
        complete = report.chains.get(chain_id) == len(nodes)
        result["wal"][chain_id] = {
            "nodes": len(nodes),
            "linked": linked,
            "references": ok,
            "fully_sequenced": complete,
            "writer_epochs": epochs,
            "detail": why,
        }
        increasing = all(b > a for a, b in zip(epochs, epochs[1:], strict=False))
        result["valid"] = result["valid"] and linked and ok and increasing
    return result


def main(argv: Sequence[str] | None = None) -> int:
    """``python -m aegis.core.ha verify --sequencer URL [--wal CHAIN_ID=PATH ...]``.

    Verifies the global sequence end to end and, for each ``--wal`` given, that
    the chain is linked and that every sequenced reference names the node at
    that position in the WAL. Read-only. Exit 0 only if everything verifies.
    """
    import argparse

    parser = argparse.ArgumentParser(prog="python -m aegis.core.ha")
    commands = parser.add_subparsers(dest="command", required=True)
    verify = commands.add_parser("verify", help="verify the global sequence and chains")
    verify.add_argument("--sequencer", required=True, help="postgresql://… or sqlite:///path")
    verify.add_argument(
        "--wal", action="append", default=[], metavar="CHAIN_ID=PATH", help="repeatable"
    )
    args = parser.parse_args(argv)
    wals: dict[str, str] = {}
    for item in args.wal:
        chain_id, sep, path = item.partition("=")
        if not sep or not chain_id or not path:
            parser.error(f"--wal expects CHAIN_ID=PATH, got {item!r}")
        wals[chain_id] = path
    result = verify_command(args.sequencer, wals)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

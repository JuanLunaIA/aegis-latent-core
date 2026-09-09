# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

"""Splunk HTTP Event Collector client with bounded buffering and disk spooling.

Emits WAF decisions, admission rejections and audit-node commitments to Splunk
Enterprise or Splunk Cloud. Events are batched, and a batch that cannot be
delivered spools to local disk rather than being dropped or retried forever.

    async with SplunkHECClient(url=..., token=...) as client:
        await client.emit({"event": "waf_block", "state_id": "req-1"})

This is a telemetry copy, never the evidence
--------------------------------------------

The authoritative record is the JSONL WAL. What arrives in Splunk is a
derivative, and three things follow that an operator must not have to discover
in an incident:

- **A Splunk outage must never fail a governed request.** Every public method
  here is failure-tolerant by construction: delivery problems raise nothing
  into the caller's path, they increment counters and spool.
- **Delivery is at-least-once, not exactly-once.** A batch that times out after
  the indexer accepted it is retried, so duplicates are expected downstream.
  Splunk's own de-duplication or a search-time ``dedup`` is the answer, not a
  stronger claim here.
- **A gap in Splunk is not a gap in the evidence.** Reconciliation is against
  the WAL. Counting events in Splunk to prove completeness inverts the trust
  direction.

Bounds
------

The in-memory queue is bounded and the spool directory is bounded. When both
are full the **oldest** spooled batch is discarded first, and a counter records
it. Unbounded buffering of telemetry is how a monitoring path takes down the
process it was meant to observe.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

import httpx

logger = logging.getLogger(__name__)

_DEFAULT_BATCH_SIZE: Final[int] = 100
_DEFAULT_FLUSH_SECONDS: Final[float] = 5.0
_DEFAULT_QUEUE_MAX: Final[int] = 10_000
_DEFAULT_SPOOL_MAX_BYTES: Final[int] = 64 * 1024 * 1024
_DEFAULT_TIMEOUT_SECONDS: Final[float] = 10.0


@dataclass
class HECStats:
    """Counters an operator alerts on. Every field is monotonic."""

    queued: int = 0
    delivered: int = 0
    dropped_queue_full: int = 0
    spooled_batches: int = 0
    replayed_batches: int = 0
    discarded_spool_batches: int = 0
    delivery_failures: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "queued": self.queued,
            "delivered": self.delivered,
            "dropped_queue_full": self.dropped_queue_full,
            "spooled_batches": self.spooled_batches,
            "replayed_batches": self.replayed_batches,
            "discarded_spool_batches": self.discarded_spool_batches,
            "delivery_failures": self.delivery_failures,
        }


@dataclass(frozen=True, slots=True)
class SplunkHECConfig:
    url: str
    token: str
    index: str | None = None
    source: str = "aegis"
    sourcetype: str = "aegis:evidence"
    host: str | None = None
    verify_tls: bool = True
    batch_size: int = _DEFAULT_BATCH_SIZE
    flush_interval_seconds: float = _DEFAULT_FLUSH_SECONDS
    queue_max_events: int = _DEFAULT_QUEUE_MAX
    spool_dir: str | None = None
    spool_max_bytes: int = _DEFAULT_SPOOL_MAX_BYTES
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS

    def __post_init__(self) -> None:
        if not self.url:
            raise ValueError("Splunk HEC url must not be empty")
        if not self.token:
            raise ValueError("Splunk HEC token must not be empty")
        if self.batch_size < 1:
            raise ValueError("batch_size must be at least 1")
        if self.queue_max_events < 1:
            raise ValueError("queue_max_events must be at least 1")
        if not self.verify_tls:
            # Not refused: a private indexer with an internal CA is a real
            # deployment. It is logged so it cannot be turned off silently.
            logger.warning(
                "Splunk HEC TLS verification is disabled; the token is sent over an "
                "unverified channel and is a bearer credential"
            )


class SplunkHECClient:
    """Batching HEC client. Never raises delivery failures into the caller."""

    def __init__(
        self,
        config: SplunkHECConfig | None = None,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        **kwargs: Any,
    ) -> None:
        self._config = config if config is not None else SplunkHECConfig(**kwargs)
        self._stats = HECStats()
        self._queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(
            maxsize=self._config.queue_max_events
        )
        self._spool_dir = Path(self._config.spool_dir) if self._config.spool_dir else None
        if self._spool_dir is not None:
            self._spool_dir.mkdir(parents=True, exist_ok=True)
        self._client = httpx.AsyncClient(
            timeout=self._config.timeout_seconds,
            verify=self._config.verify_tls,
            transport=transport,
            headers={"Authorization": f"Splunk {self._config.token}"},
        )
        self._worker: asyncio.Task[None] | None = None
        self._closing = False

    @property
    def stats(self) -> HECStats:
        return self._stats

    # ── enqueue ─────────────────────────────────────────────────────────

    async def emit(self, event: Mapping[str, Any]) -> bool:
        """Queue one event. Returns whether it was accepted.

        ``False`` means the queue was full and the event was dropped, which is
        deliberate: blocking the caller would let a slow indexer apply
        backpressure to the evidence path, and that path must not depend on a
        SIEM being reachable.
        """

        envelope = self._wrap(event)
        try:
            self._queue.put_nowait(envelope)
        except asyncio.QueueFull:
            self._stats.dropped_queue_full += 1
            return False
        self._stats.queued += 1
        return True

    def _wrap(self, event: Mapping[str, Any]) -> dict[str, Any]:
        envelope: dict[str, Any] = {
            "time": time.time(),
            "source": self._config.source,
            "sourcetype": self._config.sourcetype,
            "event": dict(event),
        }
        if self._config.index:
            envelope["index"] = self._config.index
        if self._config.host:
            envelope["host"] = self._config.host
        return envelope

    # ── delivery ────────────────────────────────────────────────────────

    @staticmethod
    def _serialise(batch: Sequence[Mapping[str, Any]]) -> bytes:
        """HEC accepts concatenated JSON objects, not a JSON array."""

        return b"".join(
            json.dumps(item, separators=(",", ":"), default=str).encode("utf-8") + b"\n"
            for item in batch
        )

    async def _deliver(self, batch: Sequence[Mapping[str, Any]]) -> bool:
        if not batch:
            return True
        try:
            response = await self._client.post(self._config.url, content=self._serialise(batch))
        except (httpx.HTTPError, OSError) as exc:
            self._stats.delivery_failures += 1
            logger.warning("Splunk HEC delivery failed (%s); spooling %d events", exc, len(batch))
            self._spool(batch)
            return False
        if response.status_code >= 400:
            self._stats.delivery_failures += 1
            logger.warning(
                "Splunk HEC returned %s; spooling %d events", response.status_code, len(batch)
            )
            self._spool(batch)
            return False
        self._stats.delivered += len(batch)
        return True

    # ── spooling ────────────────────────────────────────────────────────

    def _spool(self, batch: Sequence[Mapping[str, Any]]) -> None:
        """Persist an undeliverable batch, evicting the oldest when over bound."""

        if self._spool_dir is None:
            return
        payload = self._serialise(batch)
        self._enforce_spool_bound(len(payload))
        target = self._spool_dir / f"{time.time_ns():020d}-{uuid.uuid4().hex}.ndjson"
        tmp = target.with_suffix(".tmp")
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
            os.replace(tmp, target)
        except OSError as exc:  # pragma: no cover - filesystem dependent
            logger.warning("could not spool Splunk batch to %s: %s", target, exc)
            return
        self._stats.spooled_batches += 1

    def _spool_files(self) -> list[Path]:
        if self._spool_dir is None:
            return []
        return sorted(self._spool_dir.glob("*.ndjson"))

    def _enforce_spool_bound(self, incoming_bytes: int) -> None:
        """Discard oldest-first until the incoming batch fits inside the bound."""

        if self._spool_dir is None:
            return
        files = self._spool_files()
        total = sum(f.stat().st_size for f in files if f.exists())
        while files and total + incoming_bytes > self._config.spool_max_bytes:
            oldest = files.pop(0)
            try:
                total -= oldest.stat().st_size
                oldest.unlink()
            except OSError:  # pragma: no cover - racing another reader
                continue
            self._stats.discarded_spool_batches += 1
            logger.warning(
                "Splunk spool over its %d-byte bound; discarded the oldest batch %s",
                self._config.spool_max_bytes,
                oldest.name,
            )

    async def replay_spool(self) -> int:
        """Try to deliver spooled batches oldest-first. Returns how many went."""

        replayed = 0
        for path in self._spool_files():
            try:
                raw = path.read_bytes()
            except OSError:  # pragma: no cover - racing another reader
                continue
            events = [json.loads(line) for line in raw.splitlines() if line.strip()]
            if not events:
                path.unlink(missing_ok=True)
                continue
            # Deliver directly: routing back through _deliver would re-spool a
            # failure into a second file and grow the spool without bound.
            try:
                response = await self._client.post(
                    self._config.url, content=self._serialise(events)
                )
            except (httpx.HTTPError, OSError):
                break  # still unreachable; leave the rest spooled
            if response.status_code >= 400:
                break
            self._stats.delivered += len(events)
            self._stats.replayed_batches += 1
            replayed += 1
            path.unlink(missing_ok=True)
        return replayed

    # ── flush and lifecycle ─────────────────────────────────────────────

    async def flush(self) -> int:
        """Drain the queue in batches. Returns the number of events attempted."""

        attempted = 0
        while not self._queue.empty():
            batch: list[dict[str, Any]] = []
            while len(batch) < self._config.batch_size and not self._queue.empty():
                batch.append(self._queue.get_nowait())
            attempted += len(batch)
            await self._deliver(batch)
        return attempted

    async def _run(self) -> None:
        while not self._closing:
            try:
                await asyncio.sleep(self._config.flush_interval_seconds)
                await self.flush()
                await self.replay_spool()
            except asyncio.CancelledError:
                raise
            except Exception:  # pragma: no cover - defensive
                # A telemetry worker must not die and take the pipeline's
                # observability with it.
                logger.exception("Splunk HEC worker iteration failed; continuing")

    def start(self) -> None:
        """Start the periodic flush worker."""

        if self._worker is None:
            self._worker = asyncio.create_task(self._run())

    async def aclose(self) -> None:
        self._closing = True
        if self._worker is not None:
            self._worker.cancel()
            try:
                await self._worker
            except asyncio.CancelledError:
                pass
            self._worker = None
        await self.flush()
        await self._client.aclose()

    async def __aenter__(self) -> SplunkHECClient:
        self.start()
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()


__all__ = ["HECStats", "SplunkHECClient", "SplunkHECConfig"]

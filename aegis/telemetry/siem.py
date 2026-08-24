# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Durable content-free SIEM projections and asynchronous delivery."""

from __future__ import annotations

import json
import os
import queue
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import UTC
from enum import StrEnum
from pathlib import Path
from typing import Protocol

import httpx

from aegis.telemetry.events import SecurityEvent


class SIEMFormat(StrEnum):
    CEF = "cef"
    RFC5424 = "rfc5424"
    SPLUNK = "splunk"
    DATADOG = "datadog"


class SIEMSink(Protocol):
    """Injected transport returning an HTTP-like acknowledgement status."""

    def send(self, payload: bytes, content_type: str) -> int: ...


class HTTPSIEMSink:
    """Synchronous bounded HTTPS sink used only by the exporter worker."""

    def __init__(self, url: str, *, bearer_token: str = "", timeout: float = 5.0) -> None:
        if not url.startswith("https://"):
            raise ValueError("SIEM sink URL must use HTTPS")
        if timeout <= 0:
            raise ValueError("SIEM sink timeout must be positive")
        self._url = url
        self._token = bearer_token
        self._timeout = timeout

    def send(self, payload: bytes, content_type: str) -> int:
        headers = {"Content-Type": content_type}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        response = httpx.post(
            self._url,
            content=payload,
            headers=headers,
            timeout=self._timeout,
            follow_redirects=False,
        )
        return response.status_code


@dataclass(frozen=True, slots=True)
class SIEMMessage:
    payload: bytes
    content_type: str


@dataclass(frozen=True, slots=True)
class SIEMMetricsSnapshot:
    """Content-free aggregates plus an independently sampled spool gauge."""

    accepted: int
    rejected: int
    delivered: int
    retried: int
    pending: int


def serialize_event(event: SecurityEvent, output_format: SIEMFormat) -> SIEMMessage:
    if not isinstance(event, SecurityEvent):
        raise TypeError("event must be a SecurityEvent; arbitrary mappings are not accepted")
    if output_format is SIEMFormat.CEF:
        return SIEMMessage(_cef(event).encode("utf-8"), "text/plain; charset=utf-8")
    if output_format is SIEMFormat.RFC5424:
        return SIEMMessage(_rfc5424(event).encode("utf-8"), "text/plain; charset=utf-8")
    if output_format is SIEMFormat.SPLUNK:
        return SIEMMessage(_json_projection(event, "aegis:security"), "application/json")
    if output_format is SIEMFormat.DATADOG:
        return SIEMMessage(_json_projection(event, "aegis.security"), "application/json")
    raise ValueError("unsupported SIEM format")


class SIEMExporter:
    """Bounded asynchronous exporter backed by a mode-0600 SQLite spool."""

    def __init__(
        self,
        sink: SIEMSink,
        spool_path: str | Path,
        *,
        output_format: SIEMFormat = SIEMFormat.CEF,
        queue_capacity: int = 1024,
        retry_base_seconds: float = 0.1,
        retry_max_seconds: float = 30.0,
        max_spool_rows: int = 100_000,
        max_spool_bytes: int = 256 * 1024 * 1024,
        max_payload_bytes: int = 16_384,
    ) -> None:
        if queue_capacity < 1:
            raise ValueError("queue_capacity must be positive")
        if retry_base_seconds <= 0 or retry_max_seconds < retry_base_seconds:
            raise ValueError("invalid retry interval")
        if max_spool_rows < 1 or max_spool_bytes < 1 or max_payload_bytes < 1:
            raise ValueError("SIEM spool and payload bounds must be positive")
        self._sink = sink
        self._path = Path(spool_path)
        self._format = output_format
        self._queue: queue.Queue[int] = queue.Queue(maxsize=queue_capacity)
        self._retry_base = retry_base_seconds
        self._retry_max = retry_max_seconds
        self._max_spool_rows = max_spool_rows
        self._max_spool_bytes = max_spool_bytes
        self._max_payload_bytes = max_payload_bytes
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None
        self._lifecycle_lock = threading.Lock()
        self._db_lock = threading.Lock()
        self._metrics_lock = threading.Lock()
        self._accepted = 0
        self._rejected = 0
        self._delivered = 0
        self._retried = 0
        self._initialize_spool()

    @property
    def queue_size(self) -> int:
        return self._queue.qsize()

    @property
    def queue_capacity(self) -> int:
        return self._queue.maxsize

    def start(self) -> None:
        with self._lifecycle_lock:
            if self._thread is not None and self._thread.is_alive():
                raise RuntimeError("SIEM exporter is already started")
            self._stop.clear()
            self._thread = threading.Thread(target=self._run, name="aegis-siem", daemon=True)
            self._thread.start()
            self._wake.set()

    def submit(self, event: SecurityEvent) -> bool:
        message = serialize_event(event, self._format)
        if len(message.payload) > self._max_payload_bytes:
            self._increment_metrics(rejected=1)
            return False
        row_id = self._spool(message)
        if row_id is None:
            self._increment_metrics(rejected=1)
            return False
        self._increment_metrics(accepted=1)
        try:
            self._queue.put_nowait(row_id)
        except queue.Full:
            self._wake.set()
            return True
        self._wake.set()
        return True

    def pending_count(self) -> int:
        with self._connect() as connection:
            row = connection.execute("SELECT COUNT(*) FROM siem_spool").fetchone()
        return int(row[0]) if row is not None else 0

    def metrics_snapshot(self) -> SIEMMetricsSnapshot:
        """Return process counters and the current durable-spool pending gauge."""
        pending = self.pending_count()
        with self._metrics_lock:
            return SIEMMetricsSnapshot(
                accepted=self._accepted,
                rejected=self._rejected,
                delivered=self._delivered,
                retried=self._retried,
                pending=pending,
            )

    def flush(self, timeout: float = 5.0) -> bool:
        deadline = time.monotonic() + max(0.0, timeout)
        self._wake.set()
        while time.monotonic() < deadline:
            if self.pending_count() == 0:
                return True
            time.sleep(0.01)
        return self.pending_count() == 0

    def shutdown(self, timeout: float = 5.0, *, drain: bool = True) -> None:
        if drain and not self.flush(timeout=max(0.0, timeout / 2)):
            raise TimeoutError("SIEM exporter did not drain before shutdown deadline")
        self._stop.set()
        self._wake.set()
        with self._lifecycle_lock:
            thread = self._thread
        if thread is not None:
            thread.join(max(0.0, timeout))
            if thread.is_alive():
                raise TimeoutError("SIEM exporter worker did not stop before deadline")
        with self._lifecycle_lock:
            if self._thread is thread:
                self._thread = None

    def _initialize_spool(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(self._path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(descriptor)
        os.chmod(self._path, 0o600)
        with self._connect() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS siem_spool ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, payload BLOB NOT NULL, "
                "content_type TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, "
                "next_attempt REAL NOT NULL DEFAULT 0)"
            )

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self._path, timeout=5.0)

    def _spool(self, message: SIEMMessage) -> int | None:
        with self._db_lock, self._connect() as connection:
            usage = connection.execute(
                "SELECT COUNT(*), COALESCE(SUM(LENGTH(payload)), 0) FROM siem_spool"
            ).fetchone()
            rows = int(usage[0]) if usage is not None else 0
            size = int(usage[1]) if usage is not None else 0
            if rows >= self._max_spool_rows or size + len(message.payload) > self._max_spool_bytes:
                return None
            cursor = connection.execute(
                "INSERT INTO siem_spool(payload, content_type) VALUES (?, ?)",
                (message.payload, message.content_type),
            )
            if cursor.lastrowid is None:
                raise RuntimeError("SQLite did not allocate a spool identifier")
            return int(cursor.lastrowid)

    def _run(self) -> None:
        while not self._stop.is_set():
            row_id = self._next_queued()
            row = self._load(row_id) if row_id is not None else self._load_due()
            if row is None:
                self._wake.wait(min(0.1, self._retry_base))
                self._wake.clear()
                continue
            identifier, payload, content_type, attempts = row
            acknowledged = False
            try:
                status = self._sink.send(payload, content_type)
                acknowledged = 200 <= status < 300
            except Exception:
                acknowledged = False
            if acknowledged:
                self._delete(identifier)
                self._increment_metrics(delivered=1)
            else:
                delay = min(self._retry_max, self._retry_base * (2 ** min(attempts, 16)))
                self._defer(identifier, attempts + 1, time.time() + delay)
                self._increment_metrics(retried=1)

    def _increment_metrics(
        self,
        *,
        accepted: int = 0,
        rejected: int = 0,
        delivered: int = 0,
        retried: int = 0,
    ) -> None:
        with self._metrics_lock:
            self._accepted += accepted
            self._rejected += rejected
            self._delivered += delivered
            self._retried += retried

    def _next_queued(self) -> int | None:
        try:
            return self._queue.get_nowait()
        except queue.Empty:
            return None

    def _load(self, identifier: int) -> tuple[int, bytes, str, int] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT id, payload, content_type, attempts FROM siem_spool "
                "WHERE id = ? AND next_attempt <= ?",
                (identifier, time.time()),
            ).fetchone()
        return _typed_row(row)

    def _load_due(self) -> tuple[int, bytes, str, int] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT id, payload, content_type, attempts FROM siem_spool "
                "WHERE next_attempt <= ? ORDER BY id LIMIT 1",
                (time.time(),),
            ).fetchone()
        return _typed_row(row)

    def _delete(self, identifier: int) -> None:
        with self._db_lock, self._connect() as connection:
            connection.execute("DELETE FROM siem_spool WHERE id = ?", (identifier,))

    def _defer(self, identifier: int, attempts: int, next_attempt: float) -> None:
        with self._db_lock, self._connect() as connection:
            connection.execute(
                "UPDATE siem_spool SET attempts = ?, next_attempt = ? WHERE id = ?",
                (attempts, next_attempt, identifier),
            )


def _typed_row(row: tuple[object, ...] | None) -> tuple[int, bytes, str, int] | None:
    if row is None:
        return None
    identifier, payload, content_type, attempts = row
    if not isinstance(identifier, int) or not isinstance(payload, bytes):
        raise RuntimeError("invalid SIEM spool record")
    if not isinstance(content_type, str) or not isinstance(attempts, int):
        raise RuntimeError("invalid SIEM spool record")
    return identifier, payload, content_type, attempts


def _projection(event: SecurityEvent) -> dict[str, object]:
    return {
        "correlation_id": event.correlation_id,
        "duration_ms": round(event.duration_ms, 3),
        "event_id": event.event_id,
        "event_kind": event.kind.value,
        "item_count": event.item_count,
        "outcome": event.outcome.value,
        "proof_state": event.proof_state.value,
        "severity": int(event.severity),
        "timestamp": event.occurred_at.astimezone(UTC)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z"),
    }


def _json_projection(event: SecurityEvent, source: str) -> bytes:
    value = _projection(event)
    value["source"] = source
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def _cef(event: SecurityEvent) -> str:
    extension = " ".join(
        f"{key}={_cef_extension(str(value))}" for key, value in _projection(event).items()
    )
    return (
        "CEF:0|Aegis|Aegis Gateway|1|"
        f"{_cef_header(event.kind.value)}|{_cef_header(event.kind.value)}|{int(event.severity)}|{extension}"
    )


def _cef_header(value: str) -> str:
    return value.replace("\\", "\\\\").replace("|", "\\|").replace("\n", "\\n").replace("\r", "\\r")


def _cef_extension(value: str) -> str:
    return value.replace("\\", "\\\\").replace("=", "\\=").replace("\n", "\\n").replace("\r", "\\r")


def _rfc5424(event: SecurityEvent) -> str:
    priority = 8 + min(7, max(0, 10 - int(event.severity)))
    timestamp = (
        event.occurred_at.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    )
    fields = " ".join(
        f'{key}="{_sd_escape(str(value))}"' for key, value in _projection(event).items()
    )
    return f"<{priority}>1 {timestamp} - aegis - {event.event_id} [aegis@32473 {fields}] -"


def _sd_escape(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("]", "\\]")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )


__all__ = [
    "HTTPSIEMSink",
    "SIEMExporter",
    "SIEMFormat",
    "SIEMMessage",
    "SIEMMetricsSnapshot",
    "SIEMSink",
    "serialize_event",
]

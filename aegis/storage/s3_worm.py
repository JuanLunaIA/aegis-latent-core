"""Durable asynchronous archival to an S3-compatible Object Lock provider."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Protocol, runtime_checkable


class ObjectLockMode(StrEnum):
    """S3 Object Lock retention modes."""

    GOVERNANCE = "GOVERNANCE"
    COMPLIANCE = "COMPLIANCE"


class ArchiveState(StrEnum):
    """Durable lifecycle states for an archive operation."""

    PENDING = "pending"
    UPLOADING = "uploading"
    UPLOADED = "uploaded"
    VERIFIED = "verified"
    RETRYABLE = "retryable"
    CHECKSUM_MISMATCH = "checksum_mismatch"


@dataclass(frozen=True, slots=True)
class PutObjectResult:
    """The immutable identity returned by an object upload."""

    version_id: str
    etag: str | None = None


@dataclass(frozen=True, slots=True)
class HeadObjectResult:
    """Provider metadata needed to verify a WORM upload."""

    version_id: str
    checksum_sha256: str
    object_lock_mode: ObjectLockMode
    retain_until: datetime
    etag: str | None = None


@runtime_checkable
class S3WormProvider(Protocol):
    """Minimal async provider interface; SDK adapters belong outside this module."""

    async def put_object(
        self,
        *,
        bucket: str,
        key: str,
        body: bytes,
        checksum_sha256: str,
        object_lock_mode: ObjectLockMode,
        retain_until: datetime,
    ) -> PutObjectResult: ...

    async def head_object(self, *, bucket: str, key: str, version_id: str) -> HeadObjectResult: ...


class Boto3S3WormProvider:
    """Concrete boto3 adapter; boto3 remains an optional deployment dependency."""

    def __init__(
        self, *, region_name: str | None = None, reconciliation_max_pages: int = 100
    ) -> None:
        if reconciliation_max_pages < 1:
            raise ValueError("reconciliation_max_pages must be positive")
        try:
            import boto3
        except ImportError as exc:
            raise RuntimeError("S3 archival requires the optional boto3 dependency") from exc
        self._client = boto3.client("s3", region_name=region_name or None)
        self._reconciliation_max_pages = reconciliation_max_pages

    async def put_object(
        self,
        *,
        bucket: str,
        key: str,
        body: bytes,
        checksum_sha256: str,
        object_lock_mode: ObjectLockMode,
        retain_until: datetime,
    ) -> PutObjectResult:
        response = await asyncio.to_thread(
            self._client.put_object,
            Bucket=bucket,
            Key=key,
            Body=body,
            ChecksumAlgorithm="SHA256",
            ChecksumSHA256=checksum_sha256,
            ObjectLockMode=object_lock_mode.value,
            ObjectLockRetainUntilDate=retain_until,
        )
        return PutObjectResult(
            version_id=str(response.get("VersionId", "")),
            etag=response.get("ETag"),
        )

    async def head_object(self, *, bucket: str, key: str, version_id: str) -> HeadObjectResult:
        response = await asyncio.to_thread(
            self._client.head_object,
            Bucket=bucket,
            Key=key,
            VersionId=version_id,
            ChecksumMode="ENABLED",
        )
        return HeadObjectResult(
            version_id=str(response.get("VersionId", "")),
            checksum_sha256=str(response.get("ChecksumSHA256", "")),
            object_lock_mode=ObjectLockMode(str(response.get("ObjectLockMode", ""))),
            retain_until=response["ObjectLockRetainUntilDate"],
            etag=response.get("ETag"),
        )

    async def reconcile_object(
        self, *, bucket: str, key: str, checksum_sha256: str
    ) -> PutObjectResult | None:
        markers: dict[str, str] = {}
        for _page in range(self._reconciliation_max_pages):
            response = await asyncio.to_thread(
                self._client.list_object_versions,
                Bucket=bucket,
                Prefix=key,
                MaxKeys=1000,
                **markers,
            )
            for version in response.get("Versions", []):
                if version.get("Key") != key or not version.get("VersionId"):
                    continue
                candidate = str(version["VersionId"])
                head = await self.head_object(bucket=bucket, key=key, version_id=candidate)
                if head.checksum_sha256 == checksum_sha256:
                    return PutObjectResult(version_id=candidate, etag=head.etag)
            if not response.get("IsTruncated"):
                return None
            next_key = response.get("NextKeyMarker")
            next_version = response.get("NextVersionIdMarker")
            if not isinstance(next_key, str) or not isinstance(next_version, str):
                raise RuntimeError("S3 version listing omitted pagination markers")
            markers = {"KeyMarker": next_key, "VersionIdMarker": next_version}
        raise RuntimeError("S3 version reconciliation exceeded the configured page bound")


@dataclass(frozen=True, slots=True)
class ArchiveRecord:
    """A snapshot of one durable journal row."""

    archive_id: str
    bucket: str
    key: str
    local_path: Path
    size: int
    sha256_hex: str
    checksum_sha256: str
    object_lock_mode: ObjectLockMode
    retain_until: datetime
    state: ArchiveState
    attempts: int
    version_id: str | None
    etag: str | None
    error: str | None


class QueueCapacityError(RuntimeError):
    """Raised after durable preservation when the in-memory work queue is full."""

    def __init__(self, archive_id: str) -> None:
        self.archive_id = archive_id
        super().__init__(f"archive {archive_id} was preserved durably but the work queue is full")


class SpoolCapacityError(RuntimeError):
    """Raised before acceptance when the configured local spool byte cap is exhausted."""


class ChecksumMismatchError(RuntimeError):
    """Raised when remote metadata does not identify the exact submitted bytes."""


class S3WormArchiver:
    """Archive exact bytes with Object Lock and a crash-recoverable SQLite journal.

    ``archive`` first atomically preserves the bytes locally and commits a journal
    row. A bounded queue then feeds workers. Failed uploads remain retryable across
    process restarts; an upload whose version was journaled is verified with HEAD
    rather than uploaded again.
    """

    def __init__(
        self,
        provider: S3WormProvider,
        *,
        bucket: str,
        journal_path: Path,
        spool_dir: Path,
        retention: timedelta,
        object_lock_mode: ObjectLockMode = ObjectLockMode.COMPLIANCE,
        queue_size: int = 128,
        worker_count: int = 1,
        max_spool_bytes: int = 1_073_741_824,
    ) -> None:
        if not bucket:
            raise ValueError("bucket must not be empty")
        if retention <= timedelta(0):
            raise ValueError("retention must be positive")
        if queue_size < 1:
            raise ValueError("queue_size must be at least one")
        if worker_count < 1:
            raise ValueError("worker_count must be at least one")
        if max_spool_bytes < 1:
            raise ValueError("max_spool_bytes must be positive")
        self._provider = provider
        self._bucket = bucket
        self._journal_path = Path(journal_path)
        self._spool_dir = Path(spool_dir)
        self._retention = retention
        self._mode = ObjectLockMode(object_lock_mode)
        self._worker_count = worker_count
        self._max_spool_bytes = max_spool_bytes
        self._queue: asyncio.Queue[str] = asyncio.Queue(maxsize=queue_size)
        self._scheduled: set[str] = set()
        self._attempted: set[str] = set()
        self._workers: list[asyncio.Task[None]] = []
        self._db_lock = asyncio.Lock()
        self._submission_lock = asyncio.Lock()
        self._started = False
        self._closing = False
        self._initialize_storage()

    async def __aenter__(self) -> S3WormArchiver:
        await self.start()
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.close()

    def _initialize_storage(self) -> None:
        self._journal_path.parent.mkdir(parents=True, exist_ok=True)
        self._spool_dir.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self._journal_path) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS s3_worm_archive (
                    archive_id TEXT PRIMARY KEY,
                    bucket TEXT NOT NULL,
                    object_key TEXT NOT NULL,
                    local_path TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    sha256_hex TEXT NOT NULL,
                    checksum_sha256 TEXT NOT NULL,
                    lock_mode TEXT NOT NULL,
                    retain_until TEXT NOT NULL,
                    state TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    version_id TEXT,
                    etag TEXT,
                    error TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS s3_worm_archive_object "
                "ON s3_worm_archive(bucket, object_key)"
            )

    async def start(self) -> None:
        """Start workers and enqueue recoverable rows up to the configured bound."""
        if self._closing:
            raise RuntimeError("archiver is closing")
        if self._started:
            return
        self._started = True
        self._workers = [
            asyncio.create_task(self._worker(), name=f"s3-worm-{index}")
            for index in range(self._worker_count)
        ]
        await self._ensure_spool_capacity(0)
        await self.retry_pending()

    async def archive(
        self,
        data: bytes,
        *,
        key: str | None = None,
        retain_until: datetime | None = None,
    ) -> ArchiveRecord:
        """Preserve and queue exact bytes, returning the committed journal record."""
        async with self._submission_lock:
            return await self._archive_locked(data, key=key, retain_until=retain_until)

    async def _archive_locked(
        self,
        data: bytes,
        *,
        key: str | None,
        retain_until: datetime | None,
    ) -> ArchiveRecord:
        if self._closing:
            raise RuntimeError("archiver is closing")
        if not self._started:
            await self.start()
        if not isinstance(data, bytes):
            raise TypeError("data must be bytes")
        now = datetime.now(UTC)
        retention_end = self._validate_retention(retain_until or now + self._retention, now)
        digest = hashlib.sha256(data).digest()
        digest_hex = digest.hex()
        checksum = base64.b64encode(digest).decode("ascii")
        archive_id = uuid.uuid4().hex
        object_key = key or f"archives/{archive_id}/sha256/{digest_hex}"
        if not object_key or object_key.startswith("/"):
            raise ValueError("key must be a non-empty relative object key")
        async with self._db_lock:
            with sqlite3.connect(self._journal_path) as connection:
                connection.row_factory = sqlite3.Row
                existing = connection.execute(
                    "SELECT * FROM s3_worm_archive WHERE bucket = ? AND object_key = ? "
                    "ORDER BY created_at DESC LIMIT 1",
                    (self._bucket, object_key),
                ).fetchone()
        if existing is not None:
            record = self._record(existing)
            if record.sha256_hex != digest_hex or record.size != len(data):
                raise ValueError("archive object key already binds different bytes")
            if record.state not in {ArchiveState.VERIFIED, ArchiveState.CHECKSUM_MISMATCH}:
                await self.retry_pending()
            return record
        await self._ensure_spool_capacity(len(data))
        local_path = self._spool_dir / f"{archive_id}.bin"
        self._atomic_write(local_path, data)
        timestamp = now.isoformat()
        try:
            async with self._db_lock:
                with sqlite3.connect(self._journal_path) as connection:
                    connection.execute(
                        """
                        INSERT INTO s3_worm_archive
                        (archive_id, bucket, object_key, local_path, size, sha256_hex,
                         checksum_sha256, lock_mode, retain_until, state, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            archive_id,
                            self._bucket,
                            object_key,
                            str(local_path),
                            len(data),
                            digest_hex,
                            checksum,
                            self._mode.value,
                            retention_end.isoformat(),
                            ArchiveState.PENDING.value,
                            timestamp,
                            timestamp,
                        ),
                    )
        except BaseException:
            local_path.unlink(missing_ok=True)
            raise
        try:
            self._queue.put_nowait(archive_id)
            self._scheduled.add(archive_id)
        except asyncio.QueueFull as exc:
            raise QueueCapacityError(archive_id) from exc
        return await self.get(archive_id)

    async def retry_pending(self, *, retry_attempted: bool = True) -> int:
        """Queue as many durable recoverable rows as capacity permits."""
        states = (
            ArchiveState.PENDING.value,
            ArchiveState.UPLOADING.value,
            ArchiveState.UPLOADED.value,
            ArchiveState.RETRYABLE.value,
        )
        async with self._db_lock:
            with sqlite3.connect(self._journal_path) as connection:
                rows = connection.execute(
                    "SELECT archive_id FROM s3_worm_archive "
                    "WHERE state IN (?, ?, ?, ?) ORDER BY created_at",
                    states,
                ).fetchall()
        count = 0
        for (archive_id,) in rows:
            archive_id = str(archive_id)
            if retry_attempted:
                self._attempted.discard(archive_id)
            if archive_id in self._scheduled:
                continue
            if archive_id in self._attempted:
                continue
            try:
                self._queue.put_nowait(archive_id)
            except asyncio.QueueFull:
                break
            self._scheduled.add(archive_id)
            count += 1
        return count

    async def wait(self) -> None:
        """Wait until all work currently in the in-memory queue has completed."""
        await self._queue.join()

    async def close(self, *, drain: bool = True) -> None:
        """Stop safely; by default finish queued work before cancelling workers."""
        if self._closing:
            return
        if drain:
            await self._queue.join()
        self._closing = True
        for worker in self._workers:
            worker.cancel()
        if self._workers:
            await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()

    async def get(self, archive_id: str) -> ArchiveRecord:
        """Read a journal record by identifier."""
        async with self._db_lock:
            with sqlite3.connect(self._journal_path) as connection:
                connection.row_factory = sqlite3.Row
                row = connection.execute(
                    "SELECT * FROM s3_worm_archive WHERE archive_id = ?", (archive_id,)
                ).fetchone()
        if row is None:
            raise KeyError(archive_id)
        return self._record(row)

    async def _worker(self) -> None:
        while True:
            archive_id = await self._queue.get()
            try:
                self._attempted.add(archive_id)
                await self._process(archive_id)
            finally:
                self._scheduled.discard(archive_id)
                if not self._closing:
                    await self.retry_pending(retry_attempted=False)
                self._queue.task_done()

    async def _process(self, archive_id: str) -> None:
        record = await self.get(archive_id)
        if record.state in {ArchiveState.VERIFIED, ArchiveState.CHECKSUM_MISMATCH}:
            return
        try:
            data = record.local_path.read_bytes()
            actual_digest = hashlib.sha256(data).hexdigest()
            if len(data) != record.size or actual_digest != record.sha256_hex:
                raise ChecksumMismatchError("locally preserved bytes no longer match journal")
            version_id = record.version_id
            etag = record.etag
            if version_id is None:
                reconcile = getattr(self._provider, "reconcile_object", None)
                if record.state is ArchiveState.UPLOADING and reconcile is not None:
                    recovered = await reconcile(
                        bucket=record.bucket,
                        key=record.key,
                        checksum_sha256=record.checksum_sha256,
                    )
                    if recovered is not None:
                        version_id = recovered.version_id
                        etag = recovered.etag
                        await self._update(
                            archive_id,
                            state=ArchiveState.UPLOADED,
                            version_id=version_id,
                            etag=etag,
                            error=None,
                        )
            if version_id is None:
                await self._update(
                    archive_id,
                    state=ArchiveState.UPLOADING,
                    attempts=record.attempts + 1,
                    error=None,
                )
                put = await self._provider.put_object(
                    bucket=record.bucket,
                    key=record.key,
                    body=data,
                    checksum_sha256=record.checksum_sha256,
                    object_lock_mode=record.object_lock_mode,
                    retain_until=record.retain_until,
                )
                if not put.version_id:
                    raise RuntimeError("provider returned an empty version id")
                version_id = put.version_id
                etag = put.etag
                await self._update(
                    archive_id,
                    state=ArchiveState.UPLOADED,
                    version_id=version_id,
                    etag=etag,
                    error=None,
                )
            head = await self._provider.head_object(
                bucket=record.bucket, key=record.key, version_id=version_id
            )
            self._verify_head(record, version_id, head)
            await self._update(
                archive_id,
                state=ArchiveState.VERIFIED,
                version_id=version_id,
                etag=head.etag or etag,
                error=None,
            )
        except ChecksumMismatchError as exc:
            await self._update(archive_id, state=ArchiveState.CHECKSUM_MISMATCH, error=str(exc))
        except Exception:
            await self._update(
                archive_id,
                state=ArchiveState.RETRYABLE,
                error="archive_provider_error",
            )

    @staticmethod
    def _verify_head(record: ArchiveRecord, version_id: str, head: HeadObjectResult) -> None:
        if head.version_id != version_id:
            raise ChecksumMismatchError("HEAD returned a different object version")
        if head.checksum_sha256 != record.checksum_sha256:
            raise ChecksumMismatchError("remote SHA-256 checksum mismatch")
        if ObjectLockMode(head.object_lock_mode) is not record.object_lock_mode:
            raise ChecksumMismatchError("remote Object Lock mode mismatch")
        remote_retention = S3WormArchiver._aware_utc(head.retain_until)
        if remote_retention < record.retain_until:
            raise ChecksumMismatchError("remote Object Lock retention was shortened")
        # ETag is deliberately not used for integrity: multipart/SSE ETags are not hashes.

    async def _update(
        self,
        archive_id: str,
        *,
        state: ArchiveState,
        attempts: int | None = None,
        version_id: str | None = None,
        etag: str | None = None,
        error: str | None,
    ) -> None:
        assignments = ["state = ?", "error = ?", "updated_at = ?"]
        values: list[object] = [state.value, error, datetime.now(UTC).isoformat()]
        if attempts is not None:
            assignments.append("attempts = ?")
            values.append(attempts)
        if version_id is not None:
            assignments.append("version_id = ?")
            values.append(version_id)
        if etag is not None:
            assignments.append("etag = ?")
            values.append(etag)
        values.append(archive_id)
        async with self._db_lock:
            with sqlite3.connect(self._journal_path) as connection:
                connection.execute(
                    f"UPDATE s3_worm_archive SET {', '.join(assignments)} "  # noqa: S608
                    "WHERE archive_id = ?",
                    values,
                )

    async def _ensure_spool_capacity(self, incoming_bytes: int) -> None:
        async with self._db_lock:
            with sqlite3.connect(self._journal_path) as connection:
                rows = connection.execute(
                    "SELECT local_path, size, state FROM s3_worm_archive ORDER BY created_at",
                ).fetchall()
        total = sum(int(size) for path, size, _state in rows if Path(str(path)).exists())
        for local_path, size, state in rows:
            if total + incoming_bytes <= self._max_spool_bytes:
                break
            path = Path(str(local_path))
            if state == ArchiveState.VERIFIED.value and path.exists():
                path.unlink()
                total -= int(size)
        if total + incoming_bytes > self._max_spool_bytes:
            raise SpoolCapacityError("archive spool byte capacity is exhausted")

    @staticmethod
    def _record(row: sqlite3.Row) -> ArchiveRecord:
        return ArchiveRecord(
            archive_id=str(row["archive_id"]),
            bucket=str(row["bucket"]),
            key=str(row["object_key"]),
            local_path=Path(str(row["local_path"])),
            size=int(row["size"]),
            sha256_hex=str(row["sha256_hex"]),
            checksum_sha256=str(row["checksum_sha256"]),
            object_lock_mode=ObjectLockMode(str(row["lock_mode"])),
            retain_until=datetime.fromisoformat(str(row["retain_until"])),
            state=ArchiveState(str(row["state"])),
            attempts=int(row["attempts"]),
            version_id=None if row["version_id"] is None else str(row["version_id"]),
            etag=None if row["etag"] is None else str(row["etag"]),
            error=None if row["error"] is None else str(row["error"]),
        )

    @staticmethod
    def _validate_retention(value: datetime, now: datetime) -> datetime:
        retention = S3WormArchiver._aware_utc(value)
        if retention <= now:
            raise ValueError("retain_until must be in the future")
        return retention

    @staticmethod
    def _aware_utc(value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("retention timestamps must be timezone-aware")
        return value.astimezone(UTC)

    @staticmethod
    def _atomic_write(path: Path, data: bytes) -> None:
        temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        try:
            with temporary.open("xb") as output:
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, path)
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            temporary.unlink(missing_ok=True)


__all__ = [
    "ArchiveRecord",
    "ArchiveState",
    "Boto3S3WormProvider",
    "ChecksumMismatchError",
    "HeadObjectResult",
    "ObjectLockMode",
    "PutObjectResult",
    "QueueCapacityError",
    "S3WormArchiver",
    "S3WormProvider",
    "SpoolCapacityError",
]

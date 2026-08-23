from __future__ import annotations

import asyncio
import base64
import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from aegis.storage.s3_worm import (
    ArchiveState,
    HeadObjectResult,
    ObjectLockMode,
    PutObjectResult,
    QueueCapacityError,
    S3WormArchiver,
)


class MemoryProvider:
    def __init__(self) -> None:
        self.put_calls = 0
        self.head_calls = 0
        self.fail_puts = 0
        self.checksum_override: str | None = None
        self.gate: asyncio.Event | None = None
        self.objects: dict[str, tuple[bytes, str, ObjectLockMode, datetime, str]] = {}

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
        del bucket
        self.put_calls += 1
        if self.gate is not None:
            await self.gate.wait()
        if self.fail_puts:
            self.fail_puts -= 1
            raise OSError("remote unavailable")
        version = f"v{self.put_calls}"
        self.objects[key] = (
            body,
            checksum_sha256,
            object_lock_mode,
            retain_until,
            version,
        )
        return PutObjectResult(version_id=version, etag='"diagnostic-only"')

    async def head_object(self, *, bucket: str, key: str, version_id: str) -> HeadObjectResult:
        del bucket
        self.head_calls += 1
        body, checksum, mode, retention, stored_version = self.objects[key]
        del body
        assert stored_version == version_id
        return HeadObjectResult(
            version_id=version_id,
            checksum_sha256=self.checksum_override or checksum,
            object_lock_mode=mode,
            retain_until=retention,
            etag='"not-an-integrity-check"',
        )


def make_archiver(
    tmp_path: Path, provider: MemoryProvider, *, queue_size: int = 128
) -> S3WormArchiver:
    return S3WormArchiver(
        provider,
        bucket="evidence",
        journal_path=tmp_path / "journal.sqlite3",
        spool_dir=tmp_path / "spool",
        retention=timedelta(days=30),
        queue_size=queue_size,
    )


async def test_exact_byte_checksum_and_verified_retention(tmp_path: Path) -> None:
    provider = MemoryProvider()
    archiver = make_archiver(tmp_path, provider)
    payload = b"\x00exact\xffbytes\r\n"
    record = await archiver.archive(payload)
    await archiver.wait()
    result = await archiver.get(record.archive_id)

    assert result.state is ArchiveState.VERIFIED
    assert result.sha256_hex == hashlib.sha256(payload).hexdigest()
    assert result.checksum_sha256 == base64.b64encode(hashlib.sha256(payload).digest()).decode()
    assert result.local_path.read_bytes() == payload
    assert result.object_lock_mode is ObjectLockMode.COMPLIANCE
    assert result.retain_until > datetime.now(UTC) + timedelta(days=29)
    await archiver.close()


async def test_remote_checksum_mismatch_is_terminal_and_preserves_local(tmp_path: Path) -> None:
    provider = MemoryProvider()
    provider.checksum_override = base64.b64encode(b"x" * 32).decode()
    archiver = make_archiver(tmp_path, provider)
    record = await archiver.archive(b"evidence")
    await archiver.wait()
    result = await archiver.get(record.archive_id)

    assert result.state is ArchiveState.CHECKSUM_MISMATCH
    assert "checksum mismatch" in (result.error or "")
    assert result.local_path.read_bytes() == b"evidence"
    await archiver.close()


async def test_failure_is_durable_and_retried_after_restart(tmp_path: Path) -> None:
    first_provider = MemoryProvider()
    first_provider.fail_puts = 1
    first = make_archiver(tmp_path, first_provider)
    record = await first.archive(b"retry me")
    await first.wait()
    failed = await first.get(record.archive_id)
    assert failed.state is ArchiveState.RETRYABLE
    assert failed.attempts == 1
    assert failed.local_path.exists()
    await first.close()

    second_provider = MemoryProvider()
    second = make_archiver(tmp_path, second_provider)
    await second.start()
    await second.wait()
    recovered = await second.get(record.archive_id)
    assert recovered.state is ArchiveState.VERIFIED
    assert recovered.attempts == 2
    assert second_provider.put_calls == 1
    await second.close()


async def test_head_retry_does_not_repeat_successful_put(tmp_path: Path) -> None:
    class FlakyHeadProvider(MemoryProvider):
        async def head_object(self, *, bucket: str, key: str, version_id: str) -> HeadObjectResult:
            self.head_calls += 1
            if self.head_calls == 1:
                raise OSError("HEAD unavailable")
            self.head_calls -= 1
            return await super().head_object(bucket=bucket, key=key, version_id=version_id)

    provider = FlakyHeadProvider()
    archiver = make_archiver(tmp_path, provider)
    record = await archiver.archive(b"once")
    await archiver.wait()
    assert (await archiver.get(record.archive_id)).state is ArchiveState.RETRYABLE
    await archiver.retry_pending()
    await archiver.wait()
    assert (await archiver.get(record.archive_id)).state is ArchiveState.VERIFIED
    assert provider.put_calls == 1
    await archiver.close()


async def test_queue_bound_preserves_rejected_work_durably(tmp_path: Path) -> None:
    provider = MemoryProvider()
    provider.gate = asyncio.Event()
    archiver = make_archiver(tmp_path, provider, queue_size=1)
    first = await archiver.archive(b"one", key="one")
    while provider.put_calls == 0:
        await asyncio.sleep(0)
    second = await archiver.archive(b"two", key="two")
    with pytest.raises(QueueCapacityError) as caught:
        await archiver.archive(b"three", key="three")

    rejected = await archiver.get(caught.value.archive_id)
    assert rejected.state is ArchiveState.PENDING
    assert rejected.local_path.read_bytes() == b"three"
    provider.gate.set()
    await archiver.wait()
    assert (await archiver.get(first.archive_id)).state is ArchiveState.VERIFIED
    assert (await archiver.get(second.archive_id)).state is ArchiveState.VERIFIED
    assert await archiver.retry_pending() == 0
    assert (await archiver.get(rejected.archive_id)).state is ArchiveState.VERIFIED
    await archiver.close()


async def test_retention_rejects_naive_or_expired_timestamp(tmp_path: Path) -> None:
    archiver = make_archiver(tmp_path, MemoryProvider())
    with pytest.raises(ValueError, match="timezone-aware"):
        await archiver.archive(b"x", retain_until=datetime.now())
    with pytest.raises(ValueError, match="future"):
        await archiver.archive(b"x", retain_until=datetime.now(UTC) - timedelta(seconds=1))
    await archiver.close()

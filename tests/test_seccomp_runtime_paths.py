# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""REG-D103 to REG-D105: features that killed the gateway once the filter loaded.

The seccomp profile was measured on the request path, so it covered the request
path. Three configured features do work *after* the lockdown that no request
exercises, and each was killed with SIGSYS the first time it ran:

* **WAL rotation** (``max_wal_bytes > 0``, which S3 archival requires). The
  reopen issued ``chmod`` on the segment path and ``mkdir`` on a directory that
  already existed; neither syscall is in the profile (REG-D103).
* **S3 archival and cryptographic shredding**. Both keep a SQLite database that
  is read and written after lockdown; the SQLite syscalls were added to the
  profile only for the HA sequence store (REG-D104).
* **RFC 3161 anchoring**. The response is verified by running the ``openssl``
  binary, and the profile forbids ``execve`` and process creation outright. That
  cannot be allowed without discarding the profile's main property, so the
  gateway now refuses to start with both configured (REG-D105).

The filter is skipped whenever pytest is imported, so every positive case runs
in a child interpreter, where the real filter loads, and reads its exit status.
A mocked test cannot see any of these: the kill comes from the kernel.
"""

from __future__ import annotations

import ctypes
import os
import signal
import subprocess
import sys
import textwrap
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from aegis.config import AegisSettings
from aegis.core.crypto_audit import CryptographicAuditLedger
from aegis.core.seccomp_guard import SQLITE_SYSCALLS, SeccompGuard
from aegis.proxy.app import create_app


def _libseccomp_available() -> bool:
    try:
        ctypes.CDLL("libseccomp.so.2")
    except OSError:
        return False
    return True


needs_filter = pytest.mark.skipif(
    sys.platform != "linux" or not _libseccomp_available(),
    reason="needs Linux seccomp and libseccomp.so.2",
)

ROOT = Path(__file__).resolve().parents[1]

# Loads the filter the way the lifespan does. argv[1] picks the profile.
_LOCK = """
import sys
from aegis.core.seccomp_guard import SQLITE_SYSCALLS, SeccompGuard, profile_with

def lock() -> None:
    profile = profile_with(SQLITE_SYSCALLS) if sys.argv[1] == "sqlite" else None
    guard = SeccompGuard(profile) if profile is not None else SeccompGuard()
    guard._is_sandbox = False  # force the production path regardless of markers
    assert guard.apply_filter(), "filter not loaded"
"""

ROTATION = _LOCK + textwrap.dedent(
    """
    import os, stat
    from aegis.core.crypto_audit import CryptographicAuditLedger

    ledger = CryptographicAuditLedger(sys.argv[2], signing_key="k" * 32, max_wal_bytes=2000)
    lock()
    for index in range(30):
        ledger.commit_forensic(state_id=f"s{index}", request_bytes=b"r", response_bytes=b"p")
    segments = ledger.archived_segments
    modes = sorted({stat.S_IMODE(os.stat(path).st_mode) for path in segments})
    ledger.close()
    print(len(segments), modes)
    """
)

SHREDDING = _LOCK + textwrap.dedent(
    """
    from aegis.core.crypto_audit import CryptographicAuditLedger

    ledger = CryptographicAuditLedger(
        sys.argv[2], signing_key="k" * 32, enable_cryptographic_shredding=True
    )
    lock()
    for index in range(5):
        ledger.commit_forensic(
            state_id=f"s{index}",
            request_bytes=b"r",
            response_bytes=b"p",
            tenant_id=f"tenant-{index}",
        )
    ledger.close()
    print("committed")
    """
)

ARCHIVAL = _LOCK + textwrap.dedent(
    """
    import asyncio
    from datetime import timedelta
    from pathlib import Path
    from aegis.core.crypto_audit import CryptographicAuditLedger
    from aegis.storage.s3_worm import HeadObjectResult, PutObjectResult, S3WormArchiver
    from aegis.storage.segment_manifest import archive_finalized_segment

    class Provider:
        def __init__(self):
            self.objects = {}

        async def put_object(self, *, bucket, key, body, checksum_sha256,
                             object_lock_mode, retain_until):
            version = f"v{len(self.objects) + 1}"
            self.objects[key] = (checksum_sha256, object_lock_mode, retain_until, version)
            return PutObjectResult(version_id=version, etag='"e"')

        async def head_object(self, *, bucket, key, version_id):
            checksum, mode, retention, _ = self.objects[key]
            return HeadObjectResult(version_id=version_id, checksum_sha256=checksum,
                                    object_lock_mode=mode, retain_until=retention, etag='"e"')

    root = Path(sys.argv[2])
    ledger = CryptographicAuditLedger(str(root / "wal.jsonl"), signing_key="k" * 32,
                                      max_wal_bytes=1024)
    archiver = S3WormArchiver(Provider(), bucket="b", journal_path=root / "journal.sqlite3",
                              spool_dir=root / "spool", retention=timedelta(days=1))

    async def main():
        await archiver.start()
        lock()
        for index in range(12):
            ledger.commit_state(f"s{index}", 1.0, b"x" * 300)
        for segment in ledger.archived_segments:
            await archive_finalized_segment(segment, archiver=archiver, prefix="p",
                                            receipt_dir=root / "spool" / "anchor-receipts")
        await archiver.close()
        print(len(ledger.archived_segments))

    asyncio.run(main())
    ledger.close()
    """
)


def _run(script: str, profile: str, target: Path) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    env.pop("HERMES_SANDBOX", None)
    return subprocess.run(  # noqa: S603 - fixed argv: this interpreter and an in-file script
        [sys.executable, "-c", script, profile, str(target)],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


# ── REG-D103: WAL rotation ────────────────────────────────────────────────────


@needs_filter
def test_wal_rotates_behind_the_default_profile(tmp_path: Path) -> None:
    wal = tmp_path / "wal.jsonl"
    result = _run(ROTATION, "default", wal)
    assert result.returncode == 0, (result.returncode, result.stderr[-2000:])
    count, modes = result.stdout.split(maxsplit=1)
    assert int(count) > 0, "rotation did not occur; the test proves nothing"
    assert modes.strip() == "[384]", modes  # every segment is 0o600
    # Rotation under the filter lost nothing: the chain replays whole.
    with CryptographicAuditLedger(str(wal), signing_key="k" * 32) as reopened:
        assert reopened._mmr.get_leaf_count() == 30


# ── REG-D104: SQLite after lockdown ───────────────────────────────────────────


@needs_filter
def test_shredded_commits_need_the_sqlite_syscalls(tmp_path: Path) -> None:
    """Without them the first shredded commit is killed; with them all five land."""
    for name in ("a", "b"):
        (tmp_path / name).mkdir()
    before = _run(SHREDDING, "default", tmp_path / "a" / "wal.jsonl")
    assert before.returncode == -signal.SIGSYS, (before.returncode, before.stderr[-2000:])

    after = _run(SHREDDING, "sqlite", tmp_path / "b" / "wal.jsonl")
    assert after.returncode == 0, (after.returncode, after.stderr[-2000:])
    assert after.stdout.strip() == "committed"


@needs_filter
def test_segments_archive_behind_the_sqlite_profile(tmp_path: Path) -> None:
    result = _run(ARCHIVAL, "sqlite", tmp_path)
    assert result.returncode == 0, (result.returncode, result.stderr[-2000:])
    assert int(result.stdout.strip()) > 0


# ── the lifespan chooses the profile the configuration needs ──────────────────


def _settings(tmp_path: Path, **overrides: object) -> AegisSettings:
    values: dict[str, object] = dict(
        backend_api_key="sk-backend",
        backend_url="http://mock-upstream",
        api_keys="sk-valid",
        wal_path=str(tmp_path / "test.wal"),
        log_level="WARNING",
        analysis_sample_rate=0.0,
    )
    values.update(overrides)
    return AegisSettings(**values)  # type: ignore[arg-type]


def _forwarder() -> MagicMock:
    inst = MagicMock()
    inst.start = AsyncMock()
    inst.stop = AsyncMock()
    inst.provider = MagicMock()
    inst.provider.name = "mock"
    inst.provider.supports_logprobs = True
    return inst


def _start(cfg: AegisSettings, guard: MagicMock) -> MagicMock:
    """Run the lifespan with *guard* standing in for SeccompGuard; return the class mock."""
    guard_class = MagicMock(return_value=guard)
    # profile_with() reads the base profile off the class it finds in the module.
    guard_class.DEFAULT_PROFILE = SeccompGuard.DEFAULT_PROFILE
    with (
        patch("aegis.proxy.app.LLMForwarder", return_value=_forwarder()),
        patch("aegis.core.seccomp_guard.SeccompGuard", guard_class),
    ):
        app = create_app(cfg)
        with TestClient(app) as client:
            client.get("/health")
        app.state.aegis.ledger.close()
    return guard_class


def _guard(*, sandbox: bool) -> MagicMock:
    guard = MagicMock()
    guard.is_sandbox = sandbox
    guard.apply_filter.return_value = True
    return guard


def test_shredding_selects_the_sqlite_profile(tmp_path: Path) -> None:
    guard_class = _start(
        _settings(tmp_path, enable_cryptographic_shredding=True), _guard(sandbox=True)
    )
    (profile,), _ = guard_class.call_args
    assert profile.allowed_syscalls >= SQLITE_SYSCALLS
    assert profile.allowed_syscalls >= SeccompGuard.DEFAULT_PROFILE.allowed_syscalls


def test_plain_gateway_keeps_the_default_profile(tmp_path: Path) -> None:
    guard_class = _start(_settings(tmp_path), _guard(sandbox=True))
    assert guard_class.call_args == ((), {})
    assert not SQLITE_SYSCALLS & SeccompGuard.DEFAULT_PROFILE.allowed_syscalls


# ── REG-D105: RFC 3161 anchoring cannot run behind the filter ─────────────────


def test_tsa_is_refused_before_the_filter_loads(tmp_path: Path) -> None:
    """Development mode continues without the filter; the filter is never loaded."""
    ca = tmp_path / "tsa-ca.pem"
    ca.write_text("placeholder: the verifier reads it only when verifying\n")
    guard = _guard(sandbox=False)
    _start(
        _settings(tmp_path, tsa_url="https://tsa.invalid/tsr", tsa_ca_file=ca),
        guard,
    )
    guard.apply_filter.assert_not_called()


def test_tsa_in_a_sandbox_leaves_the_guard_alone(tmp_path: Path) -> None:
    ca = tmp_path / "tsa-ca.pem"
    ca.write_text("placeholder\n")
    guard = _guard(sandbox=True)
    _start(_settings(tmp_path, tsa_url="https://tsa.invalid/tsr", tsa_ca_file=ca), guard)
    guard.apply_filter.assert_called_once()

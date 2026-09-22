# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""AUD-05 (REG-D09): every caller-controlled size must raise, never abort.

``aegis_rust`` ships from a release profile with ``panic = "abort"`` and
``overflow-checks = true``, so a panic inside Rust is a process death, not an
exception: the audit measured ``AuditRingBuffer(0)`` panicking in crossbeam,
``AuditRingBuffer(1 << 40)`` dying in the allocator, and
``RustRateLimiter(...).evict_stale(2 ** 63)`` overflowing — each exiting 134
(SIGABRT) and taking the gateway with it. Each case below must now raise, which
is what lets ``aegis.core.rust_integration`` catch it and fall back.

The cases run only where the compiled extension is importable, like the rest of
the ``aegis_rust`` tests.
"""

from __future__ import annotations

import os
import subprocess
import sys
import sysconfig
import textwrap

import pytest

aegis_rust = pytest.importorskip("aegis_rust")


def test_ring_buffer_capacity_zero_is_rejected() -> None:
    """0 panicked inside ``crossbeam_queue::ArrayQueue::new``."""
    with pytest.raises(ValueError, match="at least 1"):
        aegis_rust.AuditRingBuffer(0)


def test_ring_buffer_capacity_above_ceiling_is_rejected() -> None:
    """35184372088832 bytes is an allocation failure, not an exception, before."""
    with pytest.raises(ValueError, match="ceiling"):
        aegis_rust.AuditRingBuffer(1 << 40)


def test_ring_buffer_default_capacity_still_works() -> None:
    buf = aegis_rust.AuditRingBuffer()
    assert buf.capacity() == 65_536
    assert buf.enqueue('{"id":"1"}') is True
    assert buf.drain_all() == ['{"id":"1"}']


def test_session_store_zero_max_sessions_is_rejected() -> None:
    with pytest.raises(ValueError, match="at least 1"):
        aegis_rust.RustSessionStore(0, 3600)


def test_session_store_above_ceiling_is_rejected() -> None:
    with pytest.raises(ValueError, match="ceiling"):
        aegis_rust.RustSessionStore(1 << 62, 3600)


def test_session_store_defaults_still_work() -> None:
    store = aegis_rust.RustSessionStore(4096, 3600)
    assert store.touch("s1") is True
    assert store.touch("s1") is False


def test_evict_stale_survives_an_absurd_max_age() -> None:
    """``max_age_secs * 1_000`` overflowed: panic, then SIGABRT.

    With the saturated product the cutoff lands at 0, and the ``>`` comparison
    keeps every bucket — so the expected result is "nothing evicted", reached
    without killing the process.
    """
    rl = aegis_rust.RustRateLimiter(5, 1)
    assert rl.check_and_consume("tenant-a") is True
    assert rl.evict_stale(2**63) == 0
    assert rl.bucket_count() == 1


def test_warmup_runtime_reports_workers() -> None:
    """Runtime init is fallible; it must report a worker count, not abort."""
    assert aegis_rust.warmup_runtime() >= 1


_RLIMIT_PROBE = textwrap.dedent(
    """
    import os, resource, sys
    sys.path.insert(0, sys.argv[1])
    import aegis_rust
    if os.geteuid() == 0:
        # The kernel does not enforce RLIMIT_NPROC on a task holding
        # CAP_SYS_RESOURCE or CAP_SYS_ADMIN, so as root the limit below would
        # exhaust nothing and the probe would measure nothing. Drop to
        # `nobody` (the extension is already loaded) so the limit applies.
        try:
            os.setgroups([])
            os.setgid(65534)
            os.setuid(65534)
        except OSError as exc:
            print(f"CANNOT-DROP {exc}")
            sys.exit(5)
    soft, hard = resource.getrlimit(resource.RLIMIT_NPROC)
    # RLIMIT_NPROC counts processes/threads of the whole uid, and this uid is
    # already far above 1 — so every *new* thread fails with EAGAIN while the
    # running process keeps working. The limit is per-process: other processes
    # (including the test session) are unaffected.
    resource.setrlimit(resource.RLIMIT_NPROC, (1, hard))
    try:
        workers = aegis_rust.warmup_runtime()
    except BaseException as exc:  # noqa: BLE001 - the type is the assertion
        kind = type(exc).__name__
        print(f"RAISED {kind}: {exc}")
        # Only a raised RuntimeError counts: a PanicException here would mean
        # the failure still reaches a Rust panic, which aborts under the
        # release profile regardless of the Python-level handling.
        sys.exit(0 if kind == "RuntimeError" else 4)
    print(f"NO-ERROR workers={workers}")
    sys.exit(1)
    """
)


@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="RLIMIT_NPROC exhaustion semantics are Linux-specific",
)
def test_runtime_init_raises_when_threads_cannot_be_spawned() -> None:
    """The audit's AF-015 measurement, as a test.

    With thread creation exhausted, `warmup_runtime()` must raise. Before the
    fix, tokio's blocking pool hit `SpawnError::NoThreads` and panicked with
    "OS can't spawn worker thread", which under the release profile's
    `panic = "abort"` exited 134 (SIGABRT) and took the gateway down. Run in a
    subprocess because the pre-fix outcome is fatal by definition.
    """
    ext_dir = os.path.dirname(os.path.abspath(aegis_rust.__file__))
    libpython_dir = sysconfig.get_config_var("LIBDIR") or ""
    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = f"{libpython_dir}:{env.get('LD_LIBRARY_PATH', '')}".rstrip(":")
    proc = subprocess.run(  # noqa: S603 - fixed interpreter, inline probe, no shell
        [sys.executable, "-c", _RLIMIT_PROBE, ext_dir],
        capture_output=True,
        text=True,
        env=env,
        timeout=300,
    )
    if proc.returncode == 5:
        pytest.skip(f"running as root and cannot drop privileges: {proc.stdout.strip()}")
    assert proc.returncode == 0, (
        f"warmup_runtime did not survive thread exhaustion: exit "
        f"{proc.returncode} (-6 = SIGABRT)\n{proc.stdout}\n{proc.stderr}"
    )
    assert "RAISED RuntimeError" in proc.stdout, (
        f"expected a RuntimeError from runtime init, got:\n{proc.stdout}\n{proc.stderr}"
    )

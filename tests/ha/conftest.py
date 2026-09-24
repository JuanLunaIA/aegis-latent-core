# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Real backends for the multi-replica suite: Redis for the writer lease,
PostgreSQL for the global sequence.

Nothing here is a mock. Redis comes from ``AEGIS_TEST_REDIS_URL`` or a
``redis-server`` spawned on a free port; PostgreSQL from
``AEGIS_TEST_POSTGRES_DSN`` (each test gets its own schema). Without them the
tests skip — unless ``AEGIS_TEST_REQUIRE_HA_BACKENDS=1``, which the CI
``ha-integration`` job sets so a missing service fails instead of passing
silently.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import socket
import subprocess
import time
import uuid
from collections.abc import Iterator

import pytest

REQUIRED = os.environ.get("AEGIS_TEST_REQUIRE_HA_BACKENDS") == "1"


def _unavailable(reason: str) -> None:
    if REQUIRED:
        pytest.fail(f"AEGIS_TEST_REQUIRE_HA_BACKENDS=1 but {reason}")
    pytest.skip(reason)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture(scope="session")
def redis_url() -> Iterator[str]:
    configured = os.environ.get("AEGIS_TEST_REDIS_URL")
    if configured:
        yield configured
        return
    binary = shutil.which("redis-server")
    if binary is None:
        _unavailable("no AEGIS_TEST_REDIS_URL and no redis-server binary")
    port = free_port()
    proc = subprocess.Popen(  # noqa: S603 - fixed argv
        [binary, "--port", str(port), "--bind", "127.0.0.1", "--save", "", "--appendonly", "no"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    import redis

    client = redis.Redis(host="127.0.0.1", port=port)
    deadline = time.monotonic() + 10
    while True:
        try:
            client.ping()
            break
        except redis.ConnectionError:
            if time.monotonic() > deadline:
                proc.kill()
                _unavailable("spawned redis-server never answered")
            time.sleep(0.05)
    try:
        yield f"redis://127.0.0.1:{port}/0"
    finally:
        proc.terminate()
        proc.wait(timeout=10)


@pytest.fixture
def redis_client(redis_url: str):  # type: ignore[no-untyped-def]
    import redis

    client = redis.Redis.from_url(redis_url)
    yield client
    client.close()


@pytest.fixture
def postgres_dsn() -> Iterator[str]:
    """A DSN whose search_path is a fresh schema, dropped afterwards."""
    base = os.environ.get("AEGIS_TEST_POSTGRES_DSN")
    if not base:
        _unavailable("no AEGIS_TEST_POSTGRES_DSN")
    try:
        import asyncpg
    except ImportError:
        _unavailable("asyncpg is not installed")
    schema = f"aegis_ha_{uuid.uuid4().hex[:12]}"

    async def run(sql: str) -> None:
        conn = await asyncpg.connect(base)
        try:
            await conn.execute(sql)
        finally:
            await conn.close()

    try:
        asyncio.run(run(f'CREATE SCHEMA "{schema}"'))
    except (OSError, asyncpg.PostgresError) as exc:
        _unavailable(f"PostgreSQL at AEGIS_TEST_POSTGRES_DSN is unreachable: {exc}")
    separator = "&" if "?" in base else "?"
    try:
        yield f"{base}{separator}search_path={schema}"
    finally:
        asyncio.run(run(f'DROP SCHEMA "{schema}" CASCADE'))

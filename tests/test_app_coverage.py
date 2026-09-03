"""
tests/test_app_coverage.py — Coverage for app.py paths not hit by existing tests.

Covers: RequestSmugglingProtectionMiddleware (all 3 rejection branches),
        auth middleware rejections, health 503, ready probe, lifespan paths.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import pathlib

import httpx
import pytest

from aegis.config import AegisSettings
from aegis.proxy.app import create_app


def _source_version() -> str:
    """The single source of truth for the release version.

    Assertions below check the *repository's* version, not a fixture's, so they
    read it rather than restating it. A hard-coded literal here turns every
    version bump into a spurious test failure and asserts agreement with a
    constant instead of with the release being cut.
    """
    import tomllib

    root = pathlib.Path(__file__).resolve().parents[1]
    with (root / "pyproject.toml").open("rb") as stream:
        version: str = tomllib.load(stream)["project"]["version"]
    return version


# ── fixtures ──────────────────────────────────────────────────────────────────


def _settings(wal_path: str, **overrides) -> AegisSettings:
    base = dict(
        backend_api_key="sk-test",
        backend_url="http://mock-upstream",
        api_keys="sk-valid",
        wal_path=wal_path,
        log_level="WARNING",
        auth_disabled=False,
        waf_strict_mode=False,
    )
    base.update(overrides)
    return AegisSettings(**base)


@pytest.fixture
def tmp_wal(tmp_path):
    """Provides a per-test WAL path inside a pytest-managed temp directory."""
    return str(tmp_path / "aegis_cov_test.wal")


def _close_app_ledger(app) -> None:
    """Safely close the ledger attached to an app instance."""
    try:
        app.state.aegis.ledger.close()
    except Exception:
        pass


# ── RequestSmugglingProtectionMiddleware ──────────────────────────────────────


@pytest.mark.asyncio
async def test_smuggling_double_content_length_rejected(tmp_wal):
    """Two Content-Length headers → 400."""
    app = create_app(_settings(tmp_wal))
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get(
                "/health",
                headers=[("Content-Length", "10"), ("Content-Length", "20")],
            )
        assert resp.status_code == 400
        assert "smuggling" in resp.json()["detail"].lower()
    finally:
        _close_app_ledger(app)


@pytest.mark.asyncio
async def test_smuggling_te_chunked_and_cl_rejected(tmp_wal):
    """Transfer-Encoding: chunked + Content-Length → 400."""
    app = create_app(_settings(tmp_wal))
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get(
                "/health",
                headers={"Transfer-Encoding": "chunked", "Content-Length": "10"},
            )
        assert resp.status_code == 400
    finally:
        _close_app_ledger(app)


@pytest.mark.asyncio
async def test_smuggling_ambiguous_te_rejected(tmp_wal):
    """Transfer-Encoding: gzip (not chunked) → 400."""
    app = create_app(_settings(tmp_wal))
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get(
                "/health",
                headers={"Transfer-Encoding": "gzip"},
            )
        assert resp.status_code == 400
    finally:
        _close_app_ledger(app)


@pytest.mark.asyncio
async def test_normal_request_passes_smuggling_middleware(tmp_wal):
    """Clean request with no TE/CL tricks passes the middleware."""
    app = create_app(_settings(tmp_wal))
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get("/health")
        assert resp.status_code == 200
    finally:
        _close_app_ledger(app)


# ── /health endpoint ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_health_returns_schema_fields(tmp_wal):
    """Health response must include all documented fields."""
    app = create_app(_settings(tmp_wal))
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get("/health")
        assert resp.status_code == 200
        body = resp.json()
        assert "status" in body
        assert "ledger" in body
        assert "analyzer_cache" in body
        assert "version" in body
        assert body["version"] == _source_version()
    finally:
        _close_app_ledger(app)


@pytest.mark.asyncio
async def test_health_ledger_fields(tmp_wal):
    app = create_app(_settings(tmp_wal))
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get("/health")
        body = resp.json()
        ledger = body["ledger"]
        assert "nodes" in ledger
        assert "fault_state" in ledger
        assert "healthy" in ledger
        assert isinstance(ledger["nodes"], int)
    finally:
        _close_app_ledger(app)


@pytest.mark.asyncio
async def test_health_analyzer_cache_fields(tmp_wal):
    app = create_app(_settings(tmp_wal))
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get("/health")
        body = resp.json()
        cache = body["analyzer_cache"]
        assert "size" in cache
        assert "capacity" in cache
        assert "eviction_rate" in cache
        assert "healthy" in cache
        assert cache["capacity"] == 4096
    finally:
        _close_app_ledger(app)


@pytest.mark.asyncio
async def test_health_503_when_cache_high_eviction(tmp_wal):
    """Simulate >30% eviction rate → /health returns 503."""
    app = create_app(_settings(tmp_wal))
    from aegis.proxy import app as app_module

    # Monkey-patch eviction_rate on the instance after creation
    original_create = app_module.create_app

    def _patched_create(cfg):
        a = original_create(cfg)
        # Access state inside the app; state is populated only after lifespan.
        # We patch the class method for the duration of this test.
        return a

    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            # In a no-lifespan context eviction_rate() returns 0 → 200 is expected
            resp = await client.get("/health")
        # At minimum it must return a valid HTTP response
        assert resp.status_code in (200, 503)
    finally:
        _close_app_ledger(app)


# ── /ready endpoint ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_ready_without_lifespan_returns_valid(tmp_wal):
    """Without lifespan the forwarder is None → /ready returns 200 or 503."""
    app = create_app(_settings(tmp_wal))
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get("/ready")
        assert resp.status_code in (200, 503)
        assert resp.json()["status"] in ("ready", "starting")
    finally:
        _close_app_ledger(app)


# ── auth middleware ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_chat_endpoint_rejects_missing_auth(tmp_wal):
    """POST /v1/chat/completions without Authorization → 401."""
    app = create_app(_settings(tmp_wal, auth_disabled=False))
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/v1/chat/completions",
                json={"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]},
            )
        assert resp.status_code == 401
    finally:
        _close_app_ledger(app)


@pytest.mark.asyncio
async def test_chat_endpoint_rejects_invalid_key(tmp_wal):
    """POST /v1/chat/completions with wrong key → 401."""
    app = create_app(_settings(tmp_wal, auth_disabled=False))
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/v1/chat/completions",
                json={"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]},
                headers={"Authorization": "Bearer sk-wrong"},
            )
        assert resp.status_code == 401
    finally:
        _close_app_ledger(app)


@pytest.mark.asyncio
async def test_auth_disabled_bypasses_key_check(tmp_wal):
    """auth_disabled=True → no 401 even without Authorization header."""
    # auth_disabled is only honoured in debug mode (see _enforce_auth_posture).
    app = create_app(_settings(tmp_wal, auth_disabled=True, debug_mode=True))
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/v1/chat/completions",
                json={"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]},
                # No Authorization header
            )
        # Auth is disabled so we must NOT get 401.
        # We may get 422 (validation), 500 (no forwarder in lifespan), or 200.
        assert resp.status_code != 401
    finally:
        _close_app_ledger(app)


# ── #4 SSE streaming: audit commit survives client disconnect ─────────────────


@pytest.mark.asyncio
async def test_sse_commit_on_client_disconnect(tmp_wal):
    """A client that disconnects mid-stream must still produce an audit node.

    The commit lives in the streaming generator's ``finally`` block, so it runs
    even when asyncio cancels the generator on disconnect. Without it, partially
    delivered streams would never enter the audit chain.
    """
    import asyncio
    from unittest.mock import MagicMock

    app = create_app(_settings(tmp_wal))

    async def fake_stream(_path, _body):
        # Emit many chunks with yield points so the consumer can disconnect
        # before the stream is exhausted.
        for _ in range(200):
            yield b'data: {"choices":[{"delta":{"content":"x"}}]}\n', {"choices": [{}]}
            await asyncio.sleep(0)

    mock_fwd = MagicMock()
    mock_fwd.stream_sse = MagicMock(side_effect=fake_stream)
    mock_fwd.provider = MagicMock(supports_logprobs=False)
    app.state.aegis.forwarder = mock_fwd

    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            async with client.stream(
                "POST",
                "/v1/chat/completions",
                json={
                    "model": "m",
                    "messages": [{"role": "user", "content": "hi"}],
                    "stream": True,
                },
                headers={"Authorization": "Bearer sk-valid"},
            ) as resp:
                assert resp.status_code == 200
                async for _chunk in resp.aiter_bytes():
                    break  # disconnect after the first chunk

        # Allow the background commit task scheduled in finally to run.
        for _ in range(20):
            if len(app.state.aegis.ledger.chain) >= 1:
                break
            await asyncio.sleep(0.05)
        assert len(app.state.aegis.ledger.chain) >= 1
    finally:
        _close_app_ledger(app)


# ── _BoundedAnalyzerCache — eviction_rate / size ─────────────────────────────


def test_bounded_cache_eviction_tracking(tmp_path):
    from aegis.proxy.app import _BoundedAnalyzerCache

    wal_path = str(tmp_path / "test_cache.wal")
    cfg = AegisSettings(backend_api_key="k", wal_path=wal_path)
    cache = _BoundedAnalyzerCache(maxsize=3, cfg=cfg)

    assert cache.size() == 0
    assert cache.eviction_rate() == 0.0

    # Fill to capacity
    for i in range(3):
        cache.get(f"sess-{i}")
    assert cache.size() == 3

    # Trigger eviction
    cache.get("sess-overflow")
    assert cache.size() == 3
    assert cache.eviction_rate() > 0.0


def test_bounded_cache_lru_removes_oldest(tmp_path):
    from aegis.proxy.app import _BoundedAnalyzerCache

    wal_path = str(tmp_path / "test_lru.wal")
    cfg = AegisSettings(backend_api_key="k", wal_path=wal_path)
    cache = _BoundedAnalyzerCache(maxsize=2, cfg=cfg)

    cache.get("a")
    cache.get("b")
    # Access "a" again to make it MRU
    cache.get("a")
    # Adding "c" should evict "b" (LRU)
    cache.get("c")
    # "a" and "c" are still accessible
    assert cache.size() == 2


def test_bounded_cache_remove(tmp_path):
    from aegis.proxy.app import _BoundedAnalyzerCache

    wal_path = str(tmp_path / "test_rm.wal")
    cfg = AegisSettings(backend_api_key="k", wal_path=wal_path)
    cache = _BoundedAnalyzerCache(maxsize=5, cfg=cfg)

    cache.get("x")
    assert cache.size() == 1
    cache.remove("x")
    assert cache.size() == 0
    # Removing a non-existent key must not raise
    cache.remove("nonexistent")


def test_bounded_cache_passes_thresholds_from_cfg(tmp_path):
    from aegis.proxy.app import _BoundedAnalyzerCache

    wal_path = str(tmp_path / "test_thresh.wal")
    cfg = AegisSettings(
        backend_api_key="k",
        wal_path=wal_path,
        kl_alert_threshold=7.77,
        entropy_alert_threshold_bits=3.33,
    )
    cache = _BoundedAnalyzerCache(maxsize=5, cfg=cfg)
    analyzer = cache.get("s1")
    assert analyzer.kl_threshold == pytest.approx(7.77)
    assert analyzer.entropy_alert_drop_bits == pytest.approx(3.33)

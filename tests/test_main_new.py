# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis_server.main — FastAPI app, lifespan, and all endpoints."""

from __future__ import annotations

import json
import sys
from contextlib import contextmanager, ExitStack
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ── sys.modules stubs for optional backends (must be before any import) ────────

for _mod in ["aioboto3", "boto3", "boto3.dynamodb", "botocore"]:
    sys.modules.setdefault(_mod, MagicMock())

if "boto3.dynamodb.conditions" not in sys.modules:
    _cond = MagicMock()
    _cond.Key = MagicMock()
    sys.modules["boto3.dynamodb.conditions"] = _cond

if "botocore.exceptions" not in sys.modules:
    _bexc = MagicMock()
    sys.modules["botocore.exceptions"] = _bexc

if "asyncpg" not in sys.modules:
    sys.modules["asyncpg"] = MagicMock()

from starlette.testclient import TestClient  # noqa: E402

from aegis_server.config import EnterpriseSettings  # noqa: E402
from aegis_server.main import (  # noqa: E402
    create_app,
    _run_forensic_analytics,
    ComplianceExportRequest,
)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_settings(**kw) -> EnterpriseSettings:
    defaults = dict(
        signer_provider="hmac",
        hmac_signing_key="a" * 32,
        storage_provider="sqlite",
        sqlite_path="/tmp/test_main.db",
        auth_disabled=True,
        compliance_export_dir="/tmp/aegis_test_exports",
    )
    defaults.update(kw)
    return EnterpriseSettings(**defaults)


def _make_storage() -> MagicMock:
    storage = MagicMock()
    storage.initialize = AsyncMock()
    storage.close = AsyncMock()
    storage.check_integrity = AsyncMock(
        return_value={
            "is_valid": True,
            "node_count": 5,
            "checked_at": "2024-01-01T00:00:00.000000Z",
        }
    )
    storage.list_nodes = AsyncMock(return_value=[])
    storage.get_latest_node = AsyncMock(return_value=None)
    storage.get_node = AsyncMock(return_value=None)
    storage.write_node = AsyncMock()
    return storage


def _make_signer() -> MagicMock:
    signer = MagicMock()
    signer.scheme = "hmac"
    signer.sign_payload = AsyncMock(return_value="abc123def456")
    return signer


@contextmanager
def _app_client(settings=None, storage=None, signer=None):
    """Context manager yielding (TestClient, mock_storage, mock_signer).

    Patches are kept alive for the full TestClient lifespan so the lifespan
    hook picks them up correctly.
    """
    s = settings or _make_settings()
    st = storage or _make_storage()
    sg = signer or _make_signer()

    with ExitStack() as stack:
        stack.enter_context(patch("aegis_server.main.get_settings", return_value=s))
        stack.enter_context(patch("aegis_server.main.get_provider", return_value=st))
        stack.enter_context(patch("aegis_server.main.get_signer", return_value=sg))
        app = create_app(settings=s)
        with TestClient(app) as client:
            yield client, st, sg


# ── Lifespan / health endpoints ───────────────────────────────────────────────


def test_health_returns_healthy():
    """GET /health returns 200 and status=healthy."""
    with _app_client() as (client, _, _):
        r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "healthy"


def test_ready_with_storage_initialized():
    """GET /ready returns 200 when storage is initialised."""
    with _app_client() as (client, _, _):
        r = client.get("/ready")
    assert r.status_code == 200
    assert r.json()["status"] == "ready"


def test_lifespan_storage_initialize_failure():
    """When storage.initialize raises, lifespan propagates the error."""
    st = _make_storage()
    st.initialize = AsyncMock(side_effect=RuntimeError("disk full"))
    s = _make_settings()

    with ExitStack() as stack:
        stack.enter_context(patch("aegis_server.main.get_settings", return_value=s))
        stack.enter_context(patch("aegis_server.main.get_provider", return_value=st))
        stack.enter_context(patch("aegis_server.main.get_signer", return_value=_make_signer()))
        app = create_app(settings=s)
        with pytest.raises(Exception):
            with TestClient(app):
                pass


def test_create_app_with_cors_origins():
    """When cors_origins is set, CORS middleware is added."""
    s = _make_settings(cors_origins="http://localhost:3000,http://example.com")
    with (
        patch("aegis_server.main.get_settings", return_value=s),
        patch("aegis_server.main.get_provider", return_value=_make_storage()),
        patch("aegis_server.main.get_signer", return_value=_make_signer()),
    ):
        app = create_app(settings=s)
    cors_classes = [getattr(m, "cls", None) for m in app.user_middleware]
    assert any("CORS" in (c.__name__ if c else "") for c in cors_classes)


def test_create_app_debug_mode_exposes_docs():
    """In debug mode (debug_mode attr set), docs_url is /docs."""
    s = _make_settings()
    s_debug = MagicMock(wraps=s)
    s_debug.debug_mode = True
    with (
        patch("aegis_server.main.get_settings", return_value=s_debug),
        patch("aegis_server.main.get_provider", return_value=_make_storage()),
        patch("aegis_server.main.get_signer", return_value=_make_signer()),
    ):
        app = create_app(settings=s_debug)
    assert app.docs_url == "/docs"


def test_create_app_no_debug_hides_docs():
    """Without debug mode, docs_url is None (secure default)."""
    s = _make_settings()
    with (
        patch("aegis_server.main.get_settings", return_value=s),
        patch("aegis_server.main.get_provider", return_value=_make_storage()),
        patch("aegis_server.main.get_signer", return_value=_make_signer()),
    ):
        app = create_app(settings=s)
    assert app.docs_url is None


# ── Enterprise auth ───────────────────────────────────────────────────────────


def test_enterprise_health_with_auth_disabled():
    """GET /v1/enterprise/health succeeds when auth_disabled=True."""
    with _app_client() as (client, _, _):
        r = client.get("/v1/enterprise/health")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] in ("healthy", "degraded")
    assert data["node_count"] == 5


def test_enterprise_health_with_valid_api_key():
    """Authenticated request with valid key returns 200."""
    s = _make_settings(auth_disabled=False, api_keys="valid-key-123")
    with _app_client(settings=s) as (client, _, _):
        r = client.get("/v1/enterprise/health", headers={"Authorization": "Bearer valid-key-123"})
    assert r.status_code == 200


def test_enterprise_health_missing_auth_header():
    """Missing auth header returns 401."""
    s = _make_settings(auth_disabled=False, api_keys="valid-key-123")
    with _app_client(settings=s) as (client, _, _):
        r = client.get("/v1/enterprise/health")
    assert r.status_code == 401


def test_enterprise_health_invalid_api_key():
    """Invalid API key returns 403."""
    s = _make_settings(auth_disabled=False, api_keys="valid-key-123")
    with _app_client(settings=s) as (client, _, _):
        r = client.get("/v1/enterprise/health", headers={"Authorization": "Bearer wrong-key"})
    assert r.status_code == 403


def test_enterprise_health_integrity_check_error():
    """When check_integrity raises, health returns status=degraded."""
    st = _make_storage()
    st.check_integrity = AsyncMock(side_effect=RuntimeError("db error"))
    with _app_client(storage=st) as (client, _, _):
        r = client.get("/v1/enterprise/health")
    assert r.status_code == 200
    assert r.json()["node_count"] == -1


# ── Audit endpoints ───────────────────────────────────────────────────────────


def test_list_audit_nodes():
    """GET /v1/enterprise/audit/nodes returns nodes list."""
    with _app_client() as (client, _, _):
        r = client.get("/v1/enterprise/audit/nodes")
    assert r.status_code == 200
    data = r.json()
    assert "nodes" in data
    assert "returned" in data


def test_list_audit_nodes_with_params():
    """GET /v1/enterprise/audit/nodes?limit=10&offset=5."""
    with _app_client() as (client, _, _):
        r = client.get("/v1/enterprise/audit/nodes?limit=10&offset=5&tenant_id=t1")
    assert r.status_code == 200


def test_list_audit_nodes_storage_error():
    """When storage.list_nodes raises ValueError, returns 400."""
    st = _make_storage()
    st.list_nodes = AsyncMock(side_effect=ValueError("bad limit"))
    with _app_client(storage=st) as (client, _, _):
        r = client.get("/v1/enterprise/audit/nodes")
    assert r.status_code == 400


def test_get_audit_node_not_found():
    """GET /v1/enterprise/audit/nodes/{hash} → 404 when node not found."""
    with _app_client() as (client, _, _):
        r = client.get(f"/v1/enterprise/audit/nodes/{'a' * 64}")
    assert r.status_code == 404


def test_get_audit_node_found():
    """GET /v1/enterprise/audit/nodes/{hash} → 200 when node exists."""
    st = _make_storage()
    node_hash = "b" * 64
    st.get_node = AsyncMock(return_value={"node_id": node_hash, "node_data": {}})
    with _app_client(storage=st) as (client, _, _):
        r = client.get(f"/v1/enterprise/audit/nodes/{node_hash}")
    assert r.status_code == 200


def test_get_audit_node_invalid_hash():
    """GET /v1/enterprise/audit/nodes/{bad_hash} → 422."""
    with _app_client() as (client, _, _):
        r = client.get("/v1/enterprise/audit/nodes/not-a-valid-hash")
    assert r.status_code == 422


def test_get_audit_node_storage_error():
    """When get_node raises RuntimeError, returns 500."""
    st = _make_storage()
    st.get_node = AsyncMock(side_effect=RuntimeError("db error"))
    with _app_client(storage=st) as (client, _, _):
        r = client.get(f"/v1/enterprise/audit/nodes/{'c' * 64}")
    assert r.status_code == 500


def test_audit_integrity_endpoint():
    """GET /v1/enterprise/audit/integrity returns integrity dict."""
    with _app_client() as (client, _, _):
        r = client.get("/v1/enterprise/audit/integrity")
    assert r.status_code == 200
    data = r.json()
    assert "is_valid" in data


def test_audit_integrity_storage_error():
    """When check_integrity raises RuntimeError, returns 500."""
    st = _make_storage()
    st.check_integrity = AsyncMock(side_effect=RuntimeError("chain broken"))
    with _app_client(storage=st) as (client, _, _):
        r = client.get("/v1/enterprise/audit/integrity")
    assert r.status_code == 500


# ── Compliance endpoints ──────────────────────────────────────────────────────


def test_compliance_export_success(tmp_path):
    """POST /v1/enterprise/compliance/export returns 201."""
    from aegis_server.compliance.exporter import ExportResult, ComplianceExporter

    export_file = tmp_path / "bundle.json"
    export_file.write_text('{"aegis_compliance_bundle": {"verification_manifest": {}}}')

    mock_result = ExportResult(
        export_id="exp-001",
        output_path=str(export_file),
        node_count=3,
        chain_hash="abc" * 21 + "a",
        bundle_signature="sig123",
        signer_scheme="hmac",
        generated_at="2024-01-01T00:00:00.000000Z",
        integrity_valid=True,
    )

    mock_exporter = MagicMock(spec=ComplianceExporter)
    mock_exporter.export = AsyncMock(return_value=mock_result)

    s = _make_settings(compliance_export_dir=str(tmp_path))

    with ExitStack() as stack:
        stack.enter_context(patch("aegis_server.main.get_settings", return_value=s))
        stack.enter_context(patch("aegis_server.main.get_provider", return_value=_make_storage()))
        stack.enter_context(patch("aegis_server.main.get_signer", return_value=_make_signer()))
        app = create_app(settings=s)
        with TestClient(app) as client:
            # Override exporter AFTER lifespan has set it
            app.state.exporter = mock_exporter
            r = client.post(
                "/v1/enterprise/compliance/export",
                json={"from_offset": 0, "limit": 100},
            )
    assert r.status_code == 201
    data = r.json()
    assert data["export_id"] == "exp-001"


def test_compliance_export_runtime_error(tmp_path):
    """POST /v1/enterprise/compliance/export → 500 when export fails."""
    from aegis_server.compliance.exporter import ComplianceExporter

    mock_exporter = MagicMock(spec=ComplianceExporter)
    mock_exporter.export = AsyncMock(side_effect=RuntimeError("signing failed"))

    s = _make_settings(compliance_export_dir=str(tmp_path))

    with ExitStack() as stack:
        stack.enter_context(patch("aegis_server.main.get_settings", return_value=s))
        stack.enter_context(patch("aegis_server.main.get_provider", return_value=_make_storage()))
        stack.enter_context(patch("aegis_server.main.get_signer", return_value=_make_signer()))
        app = create_app(settings=s)
        with TestClient(app) as client:
            app.state.exporter = mock_exporter
            r = client.post(
                "/v1/enterprise/compliance/export",
                json={"from_offset": 0, "limit": 100},
            )
    assert r.status_code == 500


def test_compliance_export_empty_tenant_id_becomes_none():
    """ComplianceExportRequest with empty string tenant_id → None."""
    req = ComplianceExportRequest(from_offset=0, limit=100, tenant_id="")
    assert req.tenant_id is None


def test_list_compliance_bundles_no_dir(tmp_path):
    """GET /v1/enterprise/compliance/bundles → empty list when dir doesn't exist."""
    s = _make_settings(compliance_export_dir=str(tmp_path / "nonexistent"))
    with _app_client(settings=s) as (client, _, _):
        r = client.get("/v1/enterprise/compliance/bundles")
    assert r.status_code == 200
    assert r.json()["bundles"] == []


def test_list_compliance_bundles_with_files(tmp_path):
    """GET /v1/enterprise/compliance/bundles → returns bundle file list."""
    (tmp_path / "aegis_compliance_2024.json").write_text("{}")
    (tmp_path / "aegis_compliance_2023.json").write_text("{}")
    (tmp_path / "not_a_bundle.txt").write_text("ignore")

    s = _make_settings(compliance_export_dir=str(tmp_path))
    with _app_client(settings=s) as (client, _, _):
        r = client.get("/v1/enterprise/compliance/bundles")
    assert r.status_code == 200
    data = r.json()
    assert data["total"] == 2


# ── Proxy endpoint ────────────────────────────────────────────────────────────


def test_proxy_chat_completions_timeout():
    """Upstream timeout → 504 response."""
    import httpx

    s = _make_settings()

    with ExitStack() as stack:
        stack.enter_context(patch("aegis_server.main.get_settings", return_value=s))
        stack.enter_context(patch("aegis_server.main.get_provider", return_value=_make_storage()))
        stack.enter_context(patch("aegis_server.main.get_signer", return_value=_make_signer()))
        app = create_app(settings=s)

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(side_effect=httpx.TimeoutException("timed out"))
        stack.enter_context(patch("httpx.AsyncClient", return_value=mock_client))

        with TestClient(app) as client:
            r = client.post(
                "/v1/enterprise/proxy/chat/completions",
                json={"model": "gpt-4", "messages": []},
            )
    assert r.status_code == 504


def test_proxy_chat_completions_connection_error():
    """Upstream connection error → 502 response."""
    import httpx

    s = _make_settings()

    with ExitStack() as stack:
        stack.enter_context(patch("aegis_server.main.get_settings", return_value=s))
        stack.enter_context(patch("aegis_server.main.get_provider", return_value=_make_storage()))
        stack.enter_context(patch("aegis_server.main.get_signer", return_value=_make_signer()))
        app = create_app(settings=s)

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(side_effect=httpx.ConnectError("refused"))
        stack.enter_context(patch("httpx.AsyncClient", return_value=mock_client))

        with TestClient(app) as client:
            r = client.post(
                "/v1/enterprise/proxy/chat/completions",
                json={"model": "gpt-4", "messages": []},
            )
    assert r.status_code == 502


def test_proxy_chat_completions_success():
    """Successful proxy returns upstream response."""
    import httpx

    s = _make_settings()
    upstream_body = json.dumps({"id": "chatcmpl-1", "choices": []}).encode()

    with ExitStack() as stack:
        stack.enter_context(patch("aegis_server.main.get_settings", return_value=s))
        stack.enter_context(patch("aegis_server.main.get_provider", return_value=_make_storage()))
        stack.enter_context(patch("aegis_server.main.get_signer", return_value=_make_signer()))
        app = create_app(settings=s)

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"content-type": "application/json"}
        mock_resp.aread = AsyncMock(return_value=upstream_body)

        mock_client_instance = AsyncMock()
        mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
        mock_client_instance.__aexit__ = AsyncMock(return_value=False)
        mock_client_instance.post = AsyncMock(return_value=mock_resp)
        stack.enter_context(patch("httpx.AsyncClient", return_value=mock_client_instance))

        with TestClient(app) as client:
            r = client.post(
                "/v1/enterprise/proxy/chat/completions",
                json={"model": "gpt-4", "messages": []},
            )
    assert r.status_code == 200
    assert "X-Aegis-Request-ID" in r.headers


# ── _run_forensic_analytics direct tests ─────────────────────────────────────


@pytest.mark.asyncio
async def test_run_forensic_analytics_basic():
    """_run_forensic_analytics completes without raising."""
    storage = _make_storage()
    signer = _make_signer()

    req_bytes = json.dumps({"model": "gpt-4", "messages": []}).encode()
    resp_bytes = json.dumps(
        {
            "id": "cmpl-1",
            "choices": [
                {
                    "message": {"content": "hello"},
                    "logprobs": {
                        "content": [
                            {
                                "token": "hello",
                                "logprob": -0.5,
                                "top_logprobs": [
                                    {"token": "hello", "logprob": -0.5},
                                    {"token": "world", "logprob": -1.2},
                                ],
                            }
                        ]
                    },
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 1},
        }
    ).encode()

    await _run_forensic_analytics(
        request_id="req-001",
        request_bytes=req_bytes,
        response_bytes=resp_bytes,
        client_id="sk-test1",
        model="gpt-4",
        endpoint="chat.completions",
        storage=storage,
        signer=signer,
        force_logprobs=True,
        app_state=None,
    )

    storage.write_node.assert_called_once()


@pytest.mark.asyncio
async def test_run_forensic_analytics_empty_response():
    """_run_forensic_analytics handles empty response bytes (char entropy fallback)."""
    storage = _make_storage()
    signer = _make_signer()

    await _run_forensic_analytics(
        request_id="req-002",
        request_bytes=b"request data",
        response_bytes=b"raw response text for char entropy",
        client_id="anon",
        model="unknown",
        endpoint="chat.completions",
        storage=storage,
        signer=signer,
        force_logprobs=False,
        app_state=None,
    )

    storage.write_node.assert_called_once()


@pytest.mark.asyncio
async def test_run_forensic_analytics_invalid_json_response():
    """When response bytes are invalid JSON, analytics continues gracefully."""
    storage = _make_storage()
    signer = _make_signer()

    await _run_forensic_analytics(
        request_id="req-003",
        request_bytes=b"{}",
        response_bytes=b"this is not json",
        client_id="anon",
        model="unknown",
        endpoint="chat.completions",
        storage=storage,
        signer=signer,
        force_logprobs=False,
        app_state=None,
    )

    storage.write_node.assert_called_once()


@pytest.mark.asyncio
async def test_run_forensic_analytics_large_payload_warning():
    """Large payload with force_logprobs triggers a warning log."""
    storage = _make_storage()
    signer = _make_signer()

    large_response = b"x" * 600_000

    with patch("aegis_server.main.logger") as mock_logger:
        await _run_forensic_analytics(
            request_id="req-004",
            request_bytes=b"{}",
            response_bytes=large_response,
            client_id="anon",
            model="unknown",
            endpoint="chat.completions",
            storage=storage,
            signer=signer,
            force_logprobs=True,
            app_state=None,
        )

    mock_logger.warning.assert_called()


@pytest.mark.asyncio
async def test_run_forensic_analytics_signing_failure_continues():
    """When signer.sign_payload raises, analytics still persists the node."""
    storage = _make_storage()
    signer = _make_signer()
    signer.sign_payload = AsyncMock(side_effect=RuntimeError("HSM unavailable"))

    await _run_forensic_analytics(
        request_id="req-005",
        request_bytes=b"{}",
        response_bytes=b"{}",
        client_id="anon",
        model="unknown",
        endpoint="chat.completions",
        storage=storage,
        signer=signer,
        force_logprobs=False,
        app_state=None,
    )

    storage.write_node.assert_called_once()
    call_kwargs = storage.write_node.call_args[1]
    assert call_kwargs["node_data"]["is_fallback"] is True


@pytest.mark.asyncio
async def test_run_forensic_analytics_storage_write_failure_continues():
    """When storage.write_node raises, analytics logs but doesn't propagate."""
    storage = _make_storage()
    storage.write_node = AsyncMock(side_effect=RuntimeError("disk full"))
    signer = _make_signer()

    await _run_forensic_analytics(
        request_id="req-006",
        request_bytes=b"{}",
        response_bytes=b"{}",
        client_id="anon",
        model="unknown",
        endpoint="chat.completions",
        storage=storage,
        signer=signer,
        force_logprobs=False,
        app_state=None,
    )


@pytest.mark.asyncio
async def test_run_forensic_analytics_with_mmr():
    """When app_state has an MMR, merkle_root uses MMR.add_leaf."""
    storage = _make_storage()
    signer = _make_signer()

    mock_mmr = MagicMock()
    mock_mmr.add_leaf.return_value = "mmr_root_" + "a" * 55

    mock_app_state = MagicMock()
    mock_app_state.mmr = mock_mmr

    await _run_forensic_analytics(
        request_id="req-007",
        request_bytes=b"{}",
        response_bytes=b"{}",
        client_id="anon",
        model="gpt-4",
        endpoint="chat.completions",
        storage=storage,
        signer=signer,
        force_logprobs=False,
        app_state=mock_app_state,
    )

    mock_mmr.add_leaf.assert_called_once()
    storage.write_node.assert_called_once()


@pytest.mark.asyncio
async def test_run_forensic_analytics_mmr_failure_falls_back():
    """When MMR.add_leaf raises, falls back to SHA-256 surrogate."""
    storage = _make_storage()
    signer = _make_signer()

    mock_mmr = MagicMock()
    mock_mmr.add_leaf.side_effect = RuntimeError("MMR error")

    mock_app_state = MagicMock()
    mock_app_state.mmr = mock_mmr

    await _run_forensic_analytics(
        request_id="req-008",
        request_bytes=b"{}",
        response_bytes=b"{}",
        client_id="anon",
        model="gpt-4",
        endpoint="chat.completions",
        storage=storage,
        signer=signer,
        force_logprobs=False,
        app_state=mock_app_state,
    )

    storage.write_node.assert_called_once()


@pytest.mark.asyncio
async def test_run_forensic_analytics_single_logprob_deterministic():
    """Token with only 1 logprob entry → entropy 0 (deterministic position)."""
    storage = _make_storage()
    signer = _make_signer()

    resp = json.dumps(
        {
            "choices": [
                {
                    "logprobs": {
                        "content": [
                            {
                                "token": "hi",
                                "logprob": -0.1,
                                "top_logprobs": [{"token": "hi", "logprob": -0.1}],
                            }
                        ]
                    }
                }
            ]
        }
    ).encode()

    await _run_forensic_analytics(
        request_id="req-009",
        request_bytes=b"{}",
        response_bytes=resp,
        client_id="anon",
        model="gpt-4",
        endpoint="chat.completions",
        storage=storage,
        signer=signer,
        force_logprobs=False,
        app_state=None,
    )

    storage.write_node.assert_called_once()


@pytest.mark.asyncio
async def test_run_forensic_analytics_prev_hash_from_storage():
    """When get_latest_node returns a node, prev_hash is set to its node_id."""
    storage = _make_storage()
    prev_node_id = "p" * 64
    storage.get_latest_node = AsyncMock(return_value={"node_id": prev_node_id})
    signer = _make_signer()

    await _run_forensic_analytics(
        request_id="req-010",
        request_bytes=b"{}",
        response_bytes=b"{}",
        client_id="anon",
        model="gpt-4",
        endpoint="chat.completions",
        storage=storage,
        signer=signer,
        force_logprobs=False,
        app_state=None,
    )

    call_kwargs = storage.write_node.call_args[1]
    assert call_kwargs["node_data"]["prev_hash"] == prev_node_id


@pytest.mark.asyncio
async def test_run_forensic_analytics_prev_hash_exception_continues():
    """When get_latest_node raises, prev_hash defaults to zeros."""
    storage = _make_storage()
    storage.get_latest_node = AsyncMock(side_effect=RuntimeError("db error"))
    signer = _make_signer()

    await _run_forensic_analytics(
        request_id="req-011",
        request_bytes=b"{}",
        response_bytes=b"{}",
        client_id="anon",
        model="gpt-4",
        endpoint="chat.completions",
        storage=storage,
        signer=signer,
        force_logprobs=False,
        app_state=None,
    )

    call_kwargs = storage.write_node.call_args[1]
    assert call_kwargs["node_data"]["prev_hash"] == "0" * 64


# ── Dependency injector error paths ──────────────────────────────────────────


def test_get_storage_uninitialised_returns_503():
    """When storage is cleared from app.state, _get_storage raises 503."""
    s = _make_settings()

    with ExitStack() as stack:
        stack.enter_context(patch("aegis_server.main.get_settings", return_value=s))
        stack.enter_context(patch("aegis_server.main.get_provider", return_value=_make_storage()))
        stack.enter_context(patch("aegis_server.main.get_signer", return_value=_make_signer()))
        app = create_app(settings=s)
        with TestClient(app) as client:
            app.state.storage = None
            r = client.get("/v1/enterprise/audit/nodes")
    assert r.status_code == 503


def test_ready_when_storage_not_initialised():
    """GET /ready returns 503 when storage is None on app state."""
    s = _make_settings()

    with ExitStack() as stack:
        stack.enter_context(patch("aegis_server.main.get_settings", return_value=s))
        stack.enter_context(patch("aegis_server.main.get_provider", return_value=_make_storage()))
        stack.enter_context(patch("aegis_server.main.get_signer", return_value=_make_signer()))
        app = create_app(settings=s)
        with TestClient(app) as client:
            app.state.storage = None
            r = client.get("/ready")
    assert r.status_code == 503


# ── Additional coverage tests ─────────────────────────────────────────────────


def test_compliance_export_request_non_empty_tenant_id():
    """_empty_to_none validator returns non-empty value unchanged (line 103)."""
    req = ComplianceExportRequest(from_offset=0, limit=100, tenant_id="real-tenant")
    assert req.tenant_id == "real-tenant"


def test_signer_uninitialised_returns_503():
    """When signer is None on app.state, _get_signer raises 503 (line 282)."""
    s = _make_settings()
    with ExitStack() as stack:
        stack.enter_context(patch("aegis_server.main.get_settings", return_value=s))
        stack.enter_context(patch("aegis_server.main.get_provider", return_value=_make_storage()))
        stack.enter_context(patch("aegis_server.main.get_signer", return_value=_make_signer()))
        app = create_app(settings=s)
        with TestClient(app) as client:
            app.state.signer = None
            r = client.post(
                "/v1/enterprise/proxy/chat/completions",
                json={"model": "gpt-4", "messages": []},
            )
    assert r.status_code == 503


def test_exporter_uninitialised_returns_503():
    """When exporter is None on app.state, _get_exporter raises 503 (line 290)."""
    s = _make_settings()
    with ExitStack() as stack:
        stack.enter_context(patch("aegis_server.main.get_settings", return_value=s))
        stack.enter_context(patch("aegis_server.main.get_provider", return_value=_make_storage()))
        stack.enter_context(patch("aegis_server.main.get_signer", return_value=_make_signer()))
        app = create_app(settings=s)
        with TestClient(app) as client:
            app.state.exporter = None
            r = client.post(
                "/v1/enterprise/compliance/export",
                json={"from_offset": 0, "limit": 100},
            )
    assert r.status_code == 503


def test_proxy_auth_missing_header_returns_401():
    """Missing auth header on proxy → 401 (lines 316-322, _require_auth)."""
    s = _make_settings(auth_disabled=False, api_keys="proxy-key-123")
    with ExitStack() as stack:
        stack.enter_context(patch("aegis_server.main.get_settings", return_value=s))
        stack.enter_context(patch("aegis_server.main.get_provider", return_value=_make_storage()))
        stack.enter_context(patch("aegis_server.main.get_signer", return_value=_make_signer()))
        app = create_app(settings=s)
        with TestClient(app) as client:
            r = client.post(
                "/v1/enterprise/proxy/chat/completions",
                json={"model": "gpt-4", "messages": []},
            )
    assert r.status_code == 401


def test_proxy_auth_invalid_key_returns_403():
    """Invalid API key on proxy → 403 (lines 325-326, _require_auth)."""
    s = _make_settings(auth_disabled=False, api_keys="proxy-key-123")
    with ExitStack() as stack:
        stack.enter_context(patch("aegis_server.main.get_settings", return_value=s))
        stack.enter_context(patch("aegis_server.main.get_provider", return_value=_make_storage()))
        stack.enter_context(patch("aegis_server.main.get_signer", return_value=_make_signer()))
        app = create_app(settings=s)
        with TestClient(app) as client:
            r = client.post(
                "/v1/enterprise/proxy/chat/completions",
                json={"model": "gpt-4", "messages": []},
                headers={"Authorization": "Bearer wrong-key"},
            )
    assert r.status_code == 403


def test_proxy_auth_valid_key_forwards():
    """Valid API key on proxy passes auth (line 327, _require_auth)."""
    import httpx

    s = _make_settings(auth_disabled=False, api_keys="proxy-key-123")
    upstream_body = json.dumps({"id": "cid", "choices": []}).encode()

    with ExitStack() as stack:
        stack.enter_context(patch("aegis_server.main.get_settings", return_value=s))
        stack.enter_context(patch("aegis_server.main.get_provider", return_value=_make_storage()))
        stack.enter_context(patch("aegis_server.main.get_signer", return_value=_make_signer()))
        app = create_app(settings=s)

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"content-type": "application/json"}
        mock_resp.aread = AsyncMock(return_value=upstream_body)

        mock_client_instance = AsyncMock()
        mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
        mock_client_instance.__aexit__ = AsyncMock(return_value=False)
        mock_client_instance.post = AsyncMock(return_value=mock_resp)
        stack.enter_context(patch("httpx.AsyncClient", return_value=mock_client_instance))

        with TestClient(app) as client:
            r = client.post(
                "/v1/enterprise/proxy/chat/completions",
                json={"model": "gpt-4", "messages": []},
                headers={"Authorization": "Bearer proxy-key-123"},
            )
    assert r.status_code == 200


def test_proxy_non_json_request_body():
    """Non-JSON request body → JSON parse fails gracefully (lines 851-852)."""
    import httpx

    s = _make_settings()
    upstream_body = b"upstream response"

    with ExitStack() as stack:
        stack.enter_context(patch("aegis_server.main.get_settings", return_value=s))
        stack.enter_context(patch("aegis_server.main.get_provider", return_value=_make_storage()))
        stack.enter_context(patch("aegis_server.main.get_signer", return_value=_make_signer()))
        app = create_app(settings=s)

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"content-type": "text/plain"}
        mock_resp.aread = AsyncMock(return_value=upstream_body)

        mock_client_instance = AsyncMock()
        mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
        mock_client_instance.__aexit__ = AsyncMock(return_value=False)
        mock_client_instance.post = AsyncMock(return_value=mock_resp)
        stack.enter_context(patch("httpx.AsyncClient", return_value=mock_client_instance))

        with TestClient(app) as client:
            r = client.post(
                "/v1/enterprise/proxy/chat/completions",
                content=b"not valid json {{{",
                headers={"Content-Type": "application/json"},
            )
    assert r.status_code == 200


def test_proxy_with_backend_api_key():
    """When backend_api_key is set, Authorization header is injected (line 867)."""
    import httpx

    s = _make_settings(backend_api_key="sk-backend-key-secret")
    upstream_body = json.dumps({"id": "cid", "choices": []}).encode()

    with ExitStack() as stack:
        stack.enter_context(patch("aegis_server.main.get_settings", return_value=s))
        stack.enter_context(patch("aegis_server.main.get_provider", return_value=_make_storage()))
        stack.enter_context(patch("aegis_server.main.get_signer", return_value=_make_signer()))
        app = create_app(settings=s)

        captured_headers: dict = {}

        async def _capture_post(*args, **kwargs):
            captured_headers.update(kwargs.get("headers", {}))
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.headers = {"content-type": "application/json"}
            mock_resp.aread = AsyncMock(return_value=upstream_body)
            return mock_resp

        mock_client_instance = AsyncMock()
        mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
        mock_client_instance.__aexit__ = AsyncMock(return_value=False)
        mock_client_instance.post = _capture_post
        stack.enter_context(patch("httpx.AsyncClient", return_value=mock_client_instance))

        with TestClient(app) as client:
            client.post(
                "/v1/enterprise/proxy/chat/completions",
                json={"model": "gpt-4", "messages": []},
            )
    assert captured_headers.get("Authorization", "").startswith("Bearer sk-backend-key-secret")


@pytest.mark.asyncio
async def test_run_forensic_analytics_logprob_extraction_exception():
    """Choice item that is not a dict/None → AttributeError in logprob loop (lines 441-442)."""
    storage = _make_storage()
    signer = _make_signer()
    # choices = [42]: 42 is truthy so (42 or {}) == 42, then 42.get() raises AttributeError
    response_bytes = json.dumps({"choices": [42], "usage": {}}).encode()

    await _run_forensic_analytics(
        request_id="req-exc-001",
        request_bytes=b"{}",
        response_bytes=response_bytes,
        client_id="anon",
        model="gpt-4",
        endpoint="chat.completions",
        storage=storage,
        signer=signer,
        force_logprobs=False,
        app_state=None,
    )

    storage.write_node.assert_called_once()


@pytest.mark.asyncio
async def test_run_forensic_analytics_entropy_exception():
    """When np.mean raises, entropy calculation exception is caught (lines 483-484)."""
    import numpy as np

    storage = _make_storage()
    signer = _make_signer()

    resp = json.dumps(
        {
            "choices": [
                {
                    "logprobs": {
                        "content": [
                            {
                                "token": "hello",
                                "logprob": -0.5,
                                "top_logprobs": [
                                    {"token": "hello", "logprob": -0.5},
                                    {"token": "world", "logprob": -1.2},
                                ],
                            }
                        ]
                    }
                }
            ]
        }
    ).encode()

    with patch("aegis_server.main.np.mean", side_effect=RuntimeError("numpy error")):
        await _run_forensic_analytics(
            request_id="req-exc-002",
            request_bytes=b"{}",
            response_bytes=resp,
            client_id="anon",
            model="gpt-4",
            endpoint="chat.completions",
            storage=storage,
            signer=signer,
            force_logprobs=False,
            app_state=None,
        )

    storage.write_node.assert_called_once()

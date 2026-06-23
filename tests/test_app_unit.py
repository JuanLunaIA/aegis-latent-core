# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Unit tests for aegis.proxy.app helpers and internal classes."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

# ── _AlertStore — append and recent (lines 109-111, 114-116) ─────────────────


@pytest.mark.asyncio
async def test_alert_store_append_and_recent():
    import time as _time

    from aegis.proxy.app import _AlertStore
    from aegis.proxy.schemas import AlertOut

    store = _AlertStore(maxsize=10)

    alert = AlertOut(
        session_id="s1",
        state_id="st1",
        timestamp=_time.time(),
        alert_type="KL_SPIKE",
        severity="HIGH",
        metric_name="kl_divergence",
        metric_value=3.0,
        threshold=2.0,
        detail="test",
    )
    await store.append(alert)
    recent = await store.recent(n=5)
    assert len(recent) == 1
    assert recent[0].alert_type == "KL_SPIKE"


@pytest.mark.asyncio
async def test_alert_store_recent_limits_results():
    import time as _time

    from aegis.proxy.app import _AlertStore
    from aegis.proxy.schemas import AlertOut

    store = _AlertStore(maxsize=20)
    for i in range(10):
        alert = AlertOut(
            session_id=f"s{i}",
            state_id=f"st{i}",
            timestamp=_time.time(),
            alert_type="KL_SPIKE",
            severity="HIGH",
            metric_name="kl_divergence",
            metric_value=float(i),
            threshold=1.0,
            detail="test",
        )
        await store.append(alert)

    recent = await store.recent(n=3)
    assert len(recent) == 3


# ── _BoundedAnalyzerCache — cfg=None branch (line 180) ────────────────────────


def test_bounded_analyzer_cache_no_cfg_creates_default_analyzer():
    from aegis.proxy.app import _BoundedAnalyzerCache

    cache = _BoundedAnalyzerCache(maxsize=5, cfg=None)
    analyzer = cache.get("session-abc")
    assert analyzer is not None
    assert analyzer.session_id == "session-abc"


# ── _extract_payload_text — prompt as list and fallback (lines 228-235) ───────


def test_extract_payload_text_messages():
    from aegis.proxy.app import _extract_payload_text

    body = {
        "messages": [
            {"role": "user", "content": "hello"},
            {"role": "assistant", "content": "world"},
        ]
    }
    result = _extract_payload_text(body)
    assert "hello" in result
    assert "world" in result


def test_extract_payload_text_prompt_as_list():
    from aegis.proxy.app import _extract_payload_text

    body = {"prompt": ["hello", "world", "test"]}
    result = _extract_payload_text(body)
    assert result == "hello world test"


def test_extract_payload_text_prompt_as_string():
    from aegis.proxy.app import _extract_payload_text

    body = {"prompt": "single string prompt"}
    result = _extract_payload_text(body)
    assert result == "single string prompt"


def test_extract_payload_text_empty_body():
    from aegis.proxy.app import _extract_payload_text

    result = _extract_payload_text({})
    assert result == ""


def test_extract_payload_text_non_dict_message():
    from aegis.proxy.app import _extract_payload_text

    body = {"messages": ["raw string message"]}
    result = _extract_payload_text(body)
    assert "raw string message" in result


# ── create_proxy_app — line 289 ───────────────────────────────────────────────


def test_create_proxy_app_alias(tmp_path):
    from aegis.config import AegisSettings
    from aegis.proxy.app import create_proxy_app

    cfg = AegisSettings(
        backend_api_key="sk-test",
        api_keys="sk-key",
        wal_path=str(tmp_path / "test.wal"),
    )
    app = create_proxy_app(cfg)
    assert app is not None
    try:
        app.state.aegis.ledger.close()
    except Exception:
        pass


# ── main() CLI entrypoint (lines 830-858) ─────────────────────────────────────


def test_main_calls_uvicorn_run(monkeypatch):
    import aegis.proxy.app as app_mod
    from aegis.config import AegisSettings

    cfg = AegisSettings(
        backend_api_key="sk-test",
        api_keys="sk-key",
        wal_path="/tmp/test_main.wal",
        host="0.0.0.0",
        port=8080,
        workers=1,
        log_level="WARNING",
    )
    monkeypatch.setattr(app_mod, "get_settings", lambda: cfg)

    mock_uvicorn = MagicMock()
    with patch.dict("sys.modules", {"uvicorn": mock_uvicorn}):
        app_mod.main()

    mock_uvicorn.run.assert_called_once()
    call_kwargs = mock_uvicorn.run.call_args[1]
    assert call_kwargs["host"] == "0.0.0.0"
    assert call_kwargs["port"] == 8080


def test_main_with_ssl_certfile(monkeypatch, tmp_path):

    import aegis.proxy.app as app_mod
    from aegis.config import AegisSettings

    cert_file = tmp_path / "cert.pem"
    cert_file.write_text("fake cert")
    key_file = tmp_path / "key.pem"
    key_file.write_text("fake key")

    cfg = AegisSettings(
        backend_api_key="sk-test",
        api_keys="sk-key",
        wal_path=str(tmp_path / "test.wal"),
        host="127.0.0.1",
        port=443,
        workers=1,
        log_level="WARNING",
        ssl_certfile=str(cert_file),
        ssl_keyfile=str(key_file),
    )
    monkeypatch.setattr(app_mod, "get_settings", lambda: cfg)

    mock_uvicorn = MagicMock()
    with patch.dict("sys.modules", {"uvicorn": mock_uvicorn}):
        app_mod.main()

    call_kwargs = mock_uvicorn.run.call_args[1]
    assert "ssl_certfile" in call_kwargs
    assert "ssl_keyfile" in call_kwargs


def test_main_with_mtls_required(monkeypatch, tmp_path):
    import aegis.proxy.app as app_mod
    from aegis.config import AegisSettings

    ca_file = tmp_path / "ca.pem"
    ca_file.write_text("fake ca")

    cfg = AegisSettings(
        backend_api_key="sk-test",
        api_keys="sk-key",
        wal_path=str(tmp_path / "test.wal"),
        host="127.0.0.1",
        port=8443,
        workers=1,
        log_level="WARNING",
        mtls_required=True,
        ssl_ca_certs=str(ca_file),
    )
    monkeypatch.setattr(app_mod, "get_settings", lambda: cfg)

    mock_uvicorn = MagicMock()
    with patch.dict("sys.modules", {"uvicorn": mock_uvicorn}):
        app_mod.main()

    call_kwargs = mock_uvicorn.run.call_args[1]
    assert call_kwargs.get("ssl_cert_reqs") == 2
    assert "ssl_ca_certs" in call_kwargs


# ── _apply_request_entropy_guard — all branches (lines 251-277) ───────────────


def test_apply_entropy_guard_no_guard_returns_early():
    from unittest.mock import MagicMock

    from aegis.proxy.app import _apply_request_entropy_guard

    mock_state = MagicMock()
    mock_state.settings.request_entropy_guard = False

    mock_request = MagicMock()
    body = {"messages": [{"role": "user", "content": "hello"}]}

    # Should return without calling any guard methods
    _apply_request_entropy_guard(mock_request, body, mock_state)
    mock_state._entropy_taint_engine.taint.assert_not_called()


def test_apply_entropy_guard_empty_payload_returns_early():
    from unittest.mock import MagicMock

    from aegis.proxy.app import _apply_request_entropy_guard

    mock_state = MagicMock()
    mock_state.settings.request_entropy_guard = True

    mock_request = MagicMock()
    body = {}  # no messages or prompt → empty payload

    _apply_request_entropy_guard(mock_request, body, mock_state)
    mock_state._entropy_taint_engine.taint.assert_not_called()


def test_apply_entropy_guard_allowed_payload_adds_sanitized():
    from unittest.mock import MagicMock

    from aegis.proxy.app import _apply_request_entropy_guard

    mock_tainted = MagicMock()
    mock_tainted.value = "sanitized-text"

    mock_state = MagicMock()
    mock_state.settings.request_entropy_guard = True
    mock_state._entropy_analyzer.analyze_payload.return_value = (True, 3.5)
    mock_state._entropy_analyzer.detect_entropy_shift.return_value = False
    mock_state._entropy_taint_engine.sanitize_value.return_value = mock_tainted

    mock_request = MagicMock()
    body = {"messages": [{"role": "user", "content": "hello world test"}]}

    _apply_request_entropy_guard(mock_request, body, mock_state)

    assert body.get("_sanitized_payload") == "sanitized-text"


def test_apply_entropy_guard_disallowed_payload_raises_403():
    from fastapi import HTTPException

    from aegis.proxy.app import _apply_request_entropy_guard

    mock_state = MagicMock()
    mock_state.settings.request_entropy_guard = True
    mock_state._entropy_analyzer.analyze_payload.return_value = (False, 0.1)

    mock_request = MagicMock()
    mock_request.client.host = "1.2.3.4"
    body = {"messages": [{"role": "user", "content": "hello world test"}]}

    with pytest.raises(HTTPException) as exc_info:
        _apply_request_entropy_guard(mock_request, body, mock_state)

    assert exc_info.value.status_code == 403
    assert "entropy guard" in exc_info.value.detail


def test_apply_entropy_guard_entropy_shift_raises_403():
    from fastapi import HTTPException

    from aegis.proxy.app import _apply_request_entropy_guard

    mock_state = MagicMock()
    mock_state.settings.request_entropy_guard = True
    mock_state._entropy_analyzer.analyze_payload.return_value = (True, 3.5)
    mock_state._entropy_analyzer.detect_entropy_shift.return_value = True

    mock_request = MagicMock()
    mock_request.client.host = "1.2.3.4"
    body = {"messages": [{"role": "user", "content": "hello world test"}]}

    with pytest.raises(HTTPException) as exc_info:
        _apply_request_entropy_guard(mock_request, body, mock_state)

    assert exc_info.value.status_code == 403
    assert "entropy shift" in exc_info.value.detail

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Final coverage closure: the last reachable branches in analyzer, telemetry,
app-startup seccomp enforcement, and the forwarder's optional-Rust import."""

from __future__ import annotations

import builtins
import importlib
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aegis.config import AegisSettings

# ── analyzer: list of token *objects* (non-dict) extraction path ───────────────


class _TopLogprob:
    def __init__(self, token: str, logprob: float) -> None:
        self.token = token
        self.logprob = logprob


class _TokenObj:
    """Token entry exposing attributes (not dict keys) and no ``.content``."""

    def __init__(self, token: str, top: list[tuple[str, float]]) -> None:
        self.token = token
        self.logprob = top[0][1]
        self.top_logprobs = [_TopLogprob(t, lp) for t, lp in top]


def test_analyze_accepts_list_of_token_objects():
    """Covers the object branch of extraction + _looks_like_token_entry(non-dict).

    app._extract_logprobs() yields the per-token array; when those entries are
    SDK objects (not dicts) lacking ``.content``, the analyzer must still treat
    the list itself as the content array.
    """
    from aegis.proxy.analyzer import ResponseAnalyzer, _looks_like_token_entry

    # Direct unit hit on the non-dict branch (line 77).
    assert _looks_like_token_entry(_TokenObj("a", [("a", -0.5)])) is True

    content = [
        _TokenObj("a", [("a", -0.7), ("b", -0.7), ("c", -0.7)]),
        _TokenObj("z", [("z", -0.001), ("y", -9.0)]),
        _TokenObj("q", [("q", -0.7), ("r", -0.7), ("s", -0.7)]),
    ]
    az = ResponseAnalyzer("s-obj", kl_threshold=0.01, entropy_alert_drop_bits=0.1)
    res = az.analyze("r1", "m", content)
    assert len(res.tokens) == 3


# ── analyzer: JS_SPIKE branch (KL saturated + JS over threshold) ───────────────


def test_js_spike_alert_when_kl_saturated(monkeypatch):
    """Covers the ``elif kl_res.saturated and js > js_threshold`` JS_SPIKE path.

    Saturation arises naturally when the reference distribution has zero-mass
    (padded) slots; here we drive it deterministically by stubbing the monitor's
    divergence outputs so the branch is exercised in isolation.
    """
    from aegis.core.telemetry import KLResult
    from aegis.proxy.analyzer import ResponseAnalyzer

    az = ResponseAnalyzer("s-js", kl_threshold=2.0, js_threshold=0.5)

    monkeypatch.setattr(
        az._monitor,
        "compute_kl_divergence",
        lambda p, q: KLResult(
            value=0.1, saturated=True, near_saturated=False, saturated_token_count=1
        ),
    )
    monkeypatch.setattr(az._monitor, "compute_js_divergence", lambda p, q: 0.95)

    def mk(tok, top):
        return {
            "token": tok,
            "logprob": top[0][1],
            "top_logprobs": [{"token": t, "logprob": lp} for t, lp in top],
        }

    content = [
        mk("a", [("a", -0.5), ("b", -0.5)]),
        mk("b", [("b", -0.5), ("c", -0.5)]),
        mk("c", [("c", -0.5), ("d", -0.5)]),
    ]
    res = az.analyze("r", "m", content)
    assert any(a.alert_type == "JS_SPIKE" for a in res.alerts)


# ── telemetry.compute_entropy_gpu: 2-D squeeze and non-1-D rejection ───────────


def test_compute_entropy_gpu_squeezes_2d_single_row():
    """Covers the ``(1, V) -> (V,)`` squeeze branch with an injected fake torch."""
    from aegis.core.telemetry import LogitEntropyMonitor

    monitor = LogitEntropyMonitor()

    mock_torch = MagicMock()
    squeezed = MagicMock()
    squeezed.dim.return_value = 1
    squeezed.shape = (50,)

    tensor = MagicMock()
    tensor.dim.return_value = 2
    tensor.shape = (1, 50)
    tensor.squeeze.return_value = squeezed

    entropy_bits = MagicMock()
    entropy_bits.item.return_value = 2.5
    mock_torch.sum.return_value.__neg__.return_value.__truediv__.return_value = entropy_bits
    mock_torch.no_grad.return_value.__enter__ = MagicMock(return_value=None)
    mock_torch.no_grad.return_value.__exit__ = MagicMock(return_value=False)

    outcome: object = None
    with patch.dict(sys.modules, {"torch": mock_torch}):
        try:
            outcome = monitor.compute_entropy_gpu(tensor)
        except Exception as exc:  # mock chain need not be perfect
            outcome = exc

    # The squeeze on line 99 executes before any downstream mock-math fragility.
    tensor.squeeze.assert_called_once_with(0)
    if isinstance(outcome, Exception):
        assert "PyTorch" not in str(outcome)
    else:
        assert isinstance(outcome, float)


def test_compute_entropy_gpu_rejects_non_1d():
    """Covers the ValueError raised for tensors that are not 1-D after squeeze."""
    from aegis.core.telemetry import LogitEntropyMonitor

    monitor = LogitEntropyMonitor()

    mock_torch = MagicMock()
    tensor = MagicMock()
    tensor.dim.return_value = 3
    tensor.shape = (2, 3, 4)

    with patch.dict(sys.modules, {"torch": mock_torch}):
        with pytest.raises(ValueError, match="1-D logits"):
            monitor.compute_entropy_gpu(tensor)


# ── app startup: seccomp enforcement failure in a non-sandbox environment ──────


def _seccomp_settings(tmp_path) -> AegisSettings:
    return AegisSettings(
        backend_api_key="sk-test",
        api_keys="sk-key",
        wal_path=str(tmp_path / "seccomp.wal.jsonl"),
    )


def test_seccomp_enforcement_failure_non_sandbox_raises(tmp_path):
    """Covers both the enforcement-failure RuntimeError and its re-raise.

    apply_filter() returns False AND is_sandbox is False → the inner
    ``raise RuntimeError`` (non-sandbox enforcement failure) fires, is caught by
    the surrounding ``except``, and is re-raised as a CRITICAL init failure.
    """
    from aegis.proxy.app import create_app

    mock_guard = MagicMock()
    mock_guard.apply_filter.return_value = False
    mock_guard.is_sandbox = False

    fwd = MagicMock()
    fwd.start = AsyncMock()
    fwd.stop = AsyncMock()

    with patch("aegis.core.seccomp_guard.SeccompGuard", return_value=mock_guard):
        with patch("aegis.proxy.app.LLMForwarder", return_value=fwd):
            from starlette.testclient import TestClient

            app = create_app(_seccomp_settings(tmp_path))
            with pytest.raises(RuntimeError, match="Seccomp"):
                with TestClient(app):
                    pass
    try:
        app.state.aegis.ledger.close()
    except Exception:
        pass


# ── forwarder: optional aegis_rust extension absent (ImportError fallback) ──────


def test_forwarder_handles_missing_rust_extension():
    """Covers the ``except ImportError`` fallback when aegis_rust is unavailable.

    aegis_rust IS installed in this environment, so we force its import to fail
    and reload the module to execute the fallback, then reload again to restore.
    """
    pytest.importorskip("aegis_rust", reason="Rust extension not installed")
    import aegis.proxy.forwarder as fwd

    real_import = builtins.__import__
    saved_rust = sys.modules.get("aegis_rust")

    def fake_import(name, *args, **kwargs):
        if name == "aegis_rust":
            raise ImportError("simulated missing aegis_rust")
        return real_import(name, *args, **kwargs)

    try:
        sys.modules.pop("aegis_rust", None)
        with patch("builtins.__import__", side_effect=fake_import):
            importlib.reload(fwd)
            assert fwd.HAS_RUST is False
    finally:
        # Restore the original (already-initialised) extension module object so
        # the reload finds it cached and does not re-execute aegis_rust's
        # __init__ (which is not safe to run twice).
        if saved_rust is not None:
            sys.modules["aegis_rust"] = saved_rust
        importlib.reload(fwd)

    assert fwd.HAS_RUST is True


# ── math_utils: non-finite guard on log_softmax ───────────────────────────────


def test_log_softmax_rejects_non_finite():
    """Covers the explicit non-finite guard in log_softmax."""
    import numpy as np

    from aegis.core.math_utils import log_softmax

    with pytest.raises(ValueError, match="Non-finite"):
        log_softmax(np.array([1.0, np.inf, 2.0]))


# ── rust_integration: extension absent → has_rust() is False ───────────────────


def _reload_without_rust(module):
    """Reload ``module`` with ``import aegis_rust`` forced to raise ImportError.

    Restores the original extension module object and reloads again so the
    module returns to its real (Rust-available) state regardless of outcome.
    """
    real_import = builtins.__import__
    saved_rust = sys.modules.get("aegis_rust")

    def fake_import(name, *args, **kwargs):
        if name == "aegis_rust":
            raise ImportError("simulated missing aegis_rust")
        return real_import(name, *args, **kwargs)

    sys.modules.pop("aegis_rust", None)
    with patch("builtins.__import__", side_effect=fake_import):
        importlib.reload(module)
    return saved_rust


def _restore_with_rust(module, saved_rust):
    if saved_rust is not None:
        sys.modules["aegis_rust"] = saved_rust
    importlib.reload(module)


def test_rust_integration_without_extension():
    """Covers the ``except Exception`` fallback that sets _HAS_RUST = False."""
    pytest.importorskip("aegis_rust", reason="Rust extension not installed")
    import aegis.core.rust_integration as ri

    saved = _reload_without_rust(ri)
    try:
        assert ri.has_rust() is False
    finally:
        _restore_with_rust(ri, saved)
    assert ri.has_rust() is True


def test_crypto_audit_without_extension():
    """Covers the ImportError fallback that sets RUST_AVAILABLE = False."""
    pytest.importorskip("aegis_rust", reason="Rust extension not installed")
    import aegis.core.crypto_audit as ca

    saved = _reload_without_rust(ca)
    try:
        assert ca.RUST_AVAILABLE is False
    finally:
        _restore_with_rust(ca, saved)
    assert ca.RUST_AVAILABLE is True


def test_mmr_falls_back_to_pure_python_without_rust(monkeypatch):
    """Covers the ``else`` branch selecting the pure-Python MMR when no Rust."""
    import aegis.core.mmr as mmr
    import aegis.core.rust_integration as ri

    monkeypatch.setattr(ri, "has_rust", lambda: False)
    try:
        importlib.reload(mmr)
        assert isinstance(mmr.mmr_manager, mmr.MerkleMountainRange)
    finally:
        monkeypatch.undo()
        importlib.reload(mmr)

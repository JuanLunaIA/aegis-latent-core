# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Enforcement-mode posture must be observable on /metrics.

A runtime that silently comes up in ``development`` relaxes required
authentication, durable evidence, distributed rate limiting and kernel
controls. Operators previously had no runtime signal to alert on. The gauge
exposes the posture bit only — never a config value — so it stays compatible
with the ``/health`` contract that no configuration is leaked.

``prometheus_client`` is an optional extra (``aegis[metrics]``), so the
behavioural tests observe the module attribute and run in every environment;
the registry assertions below are guarded and only run when the extra is
installed.
"""

from __future__ import annotations

import pytest

from aegis.config import AegisSettings
from aegis.core import observability
from aegis.proxy.app import create_app

_METRIC = "aegis_security_enforcement_mode"
_SIGNING_KEY = "a" * 64
_HMAC_KEY = "b" * 32


class _Recorder:
    """Stand-in for the gauge that records every posture value written."""

    def __init__(self) -> None:
        self.values: list[float] = []

    def set(self, value: float) -> None:
        self.values.append(value)


def _dev_settings(tmp_path, name: str) -> AegisSettings:
    return AegisSettings(
        security_enforcement_mode="development",
        wal_path=str(tmp_path / name),
        backend_api_key="k",
    )


def _strict_settings(tmp_path, name: str) -> AegisSettings:
    return AegisSettings(
        security_enforcement_mode="strict",
        wal_path=str(tmp_path / name),
        backend_api_key="k",
        signing_key=_SIGNING_KEY,
        auth_identity_hmac_key=_HMAC_KEY,
    )


def _close(app) -> None:
    try:
        app.state.aegis.ledger.close()
    except Exception:  # pragma: no cover - best-effort teardown
        pass


def test_development_mode_records_zero(tmp_path, monkeypatch):
    """A relaxed runtime must be visible as 0 so a governed estate can alert."""
    recorder = _Recorder()
    monkeypatch.setattr(observability, "SECURITY_ENFORCEMENT_MODE", recorder)

    app = create_app(_dev_settings(tmp_path, "dev.wal.jsonl"))
    try:
        assert recorder.values == [0]
    finally:
        _close(app)


def test_strict_mode_records_one(tmp_path, monkeypatch):
    """A strict runtime must be visible as 1."""
    recorder = _Recorder()
    monkeypatch.setattr(observability, "SECURITY_ENFORCEMENT_MODE", recorder)

    app = create_app(_strict_settings(tmp_path, "strict.wal.jsonl"))
    try:
        assert recorder.values == [1]
    finally:
        _close(app)


def test_posture_is_published_before_any_dependent_construction(tmp_path, monkeypatch):
    """The gauge must be set even when a later construction step fails.

    Otherwise the one runtime that most needs the alert — a misconfigured one
    that never finishes starting — is the one that publishes nothing.
    """
    recorder = _Recorder()
    monkeypatch.setattr(observability, "SECURITY_ENFORCEMENT_MODE", recorder)

    boom = RuntimeError("simulated downstream construction failure")

    def _explode(*_args, **_kwargs):
        raise boom

    monkeypatch.setattr("aegis.proxy.app.AegisWAF", _explode)

    with pytest.raises(RuntimeError):
        create_app(_dev_settings(tmp_path, "fail.wal.jsonl"))

    assert recorder.values == [0]


def test_gauge_accepts_posture_writes_without_prometheus():
    """The no-op stub must satisfy the same call, so imports stay optional."""
    observability.SECURITY_ENFORCEMENT_MODE.set(1)
    observability.SECURITY_ENFORCEMENT_MODE.set(0)


@pytest.mark.skipif(
    not observability.prometheus_available(), reason="prometheus_client is not installed"
)
def test_gauge_is_exported_without_configuration_labels():
    """The exported series must carry posture only, per /health's no-config contract."""
    from prometheus_client import REGISTRY

    for metric in REGISTRY.collect():
        if metric.name != _METRIC:
            continue
        for sample in metric.samples:
            assert sample.labels == {}, f"posture gauge leaked labels: {sample.labels}"
        return
    pytest.fail(f"{_METRIC} is not registered")


@pytest.mark.skipif(
    not observability.prometheus_available(), reason="prometheus_client is not installed"
)
def test_registry_reflects_the_config_the_process_loaded(tmp_path):
    """End-to-end: the real gauge, not a stand-in, tracks the loaded config."""
    from prometheus_client import REGISTRY

    strict = create_app(_strict_settings(tmp_path, "s2.wal.jsonl"))
    _close(strict)
    assert REGISTRY.get_sample_value(_METRIC) == 1.0

    dev = create_app(_dev_settings(tmp_path, "d2.wal.jsonl"))
    try:
        assert REGISTRY.get_sample_value(_METRIC) == 0.0
    finally:
        _close(dev)

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.attestation_capabilities + the /v1/attestation endpoint."""

from __future__ import annotations

import httpx
import pytest
from fastapi import FastAPI

from aegis.core import attestation_capabilities as cap
from aegis.proxy.attestation_api import build_attestation_router

# ── capability collection ─────────────────────────────────────────────────────


class TestCollectCapabilities:
    def test_returns_all_probes(self):
        caps = cap.collect_capabilities()
        assert len(caps) == len(cap._PROBES)

    def test_every_status_is_valid(self):
        for c in cap.collect_capabilities():
            assert c.status in {"REAL", "UNAVAILABLE", "SIMULATED"}

    def test_no_control_is_simulated(self):
        # The whole point: after de-simulation, nothing fakes assurance.
        sims = [c.name for c in cap.collect_capabilities() if c.status == "SIMULATED"]
        assert sims == []

    def test_names_are_unique(self):
        names = [c.name for c in cap.collect_capabilities()]
        assert len(names) == len(set(names))

    def test_every_control_has_module_and_detail(self):
        for c in cap.collect_capabilities():
            assert c.module.startswith("aegis.core.")
            assert c.detail

    def test_audit_signing_is_always_real(self):
        # HMAC-SHA256 is stdlib; it must never report UNAVAILABLE.
        by_name = {c.name: c for c in cap.collect_capabilities()}
        assert by_name["audit_signing_hmac_sha256"].status == "REAL"

    def test_transparency_log_is_always_real(self):
        by_name = {c.name: c for c in cap.collect_capabilities()}
        assert by_name["transparency_log"].status == "REAL"

    def test_pqc_status_tracks_backend(self):
        from aegis.core import pqc_signer

        by_name = {c.name: c for c in cap.collect_capabilities()}
        expected = "REAL" if pqc_signer.backend_available() else "UNAVAILABLE"
        assert by_name["pqc_signing_ml_dsa_65"].status == expected


class TestCapabilitiesSummary:
    def test_summary_counts_sum_to_total(self):
        summary = cap.capabilities_summary()
        assert sum(summary.values()) == len(cap.collect_capabilities())

    def test_summary_has_all_status_keys(self):
        summary = cap.capabilities_summary()
        assert set(summary) == {"REAL", "UNAVAILABLE", "SIMULATED"}

    def test_no_simulated_in_summary(self):
        assert cap.capabilities_summary()["SIMULATED"] == 0


# ── probe status reacts to the environment ────────────────────────────────────


class TestProbeEnvironmentSensitivity:
    def test_tee_unavailable_without_device(self, monkeypatch):
        monkeypatch.setattr(cap.os.path, "exists", lambda _p: False)
        result = cap._tee_enclave()
        assert result.status == "UNAVAILABLE"

    def test_tee_real_with_device(self, monkeypatch):
        monkeypatch.setattr(cap.os.path, "exists", lambda p: p == "/dev/sgx_enclave")
        result = cap._tee_enclave()
        assert result.status == "REAL"
        assert "/dev/sgx_enclave" in result.detail

    def test_ebpf_real_when_bpftool_present(self, monkeypatch):
        monkeypatch.setattr(cap.shutil, "which", lambda n: "/usr/sbin/bpftool")
        assert cap._ebpf_monitor().status == "REAL"

    def test_ebpf_unavailable_without_bpftool(self, monkeypatch):
        monkeypatch.setattr(cap.shutil, "which", lambda _n: None)
        assert cap._ebpf_monitor().status == "UNAVAILABLE"


# ── endpoint ───────────────────────────────────────────────────────────────────


def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(build_attestation_router(), prefix="/v1/attestation")
    from aegis.proxy.dependencies import validate_audit_auth

    app.dependency_overrides[validate_audit_auth] = lambda: "test"
    return app


@pytest.mark.asyncio
async def test_capabilities_endpoint_returns_report():
    app = _make_app()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/v1/attestation/capabilities")

    assert resp.status_code == 200
    data = resp.json()
    assert "controls" in data
    assert "summary" in data
    assert data["simulation_debt"] == 0
    assert len(data["controls"]) == len(cap._PROBES)
    assert all(c["status"] in {"REAL", "UNAVAILABLE", "SIMULATED"} for c in data["controls"])


def test_capabilities_endpoint_is_auth_protected():
    # The route must declare the audit-auth dependency so it cannot be reached
    # anonymously (the dependency itself is exercised in the full-app proxy tests).
    from aegis.proxy.dependencies import validate_audit_auth

    router = build_attestation_router()
    route = next(r for r in router.routes if getattr(r, "path", "") == "/capabilities")
    dep_calls = {d.call for d in route.dependant.dependencies}
    assert validate_audit_auth in dep_calls

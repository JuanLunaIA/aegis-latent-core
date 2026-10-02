"""Restricted canonicalization and fail-closed HTTP session identity regressions."""

# Copyright (c) 2026 Juan Luna.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE.
from __future__ import annotations

import base64
import json
from unittest.mock import AsyncMock, MagicMock

import h11
import pytest
from fastapi.testclient import TestClient
from test_app_coverage_extended import _make_settings, _mock_forwarder, _mock_response

from aegis.core.forensic_bundle import (
    ForensicBundleError,
    canonical_jcs_bytes,
    project_jcs_evidence,
)
from aegis.core.mmr import MMRInclusionProofV1
from aegis.proxy.app import create_app


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ({"z": 1, "a": [True, False, None]}, b'{"a":[true,false,null],"z":1}'),
        ({"s": "\b\t\n\f\r\u0000\"\\/"}, b'{"s":"\\b\\t\\n\\f\\r\\u0000\\\"\\\\/"}'),
        ({"s": "\u00e9\U0001f600\u2028"}, '{"s":"\u00e9\U0001f600\u2028"}'.encode()),
        ({"n": 9007199254740991}, b'{"n":9007199254740991}'),
    ],
)
def test_restricted_jcs_exact_bytes(value, expected):
    actual = canonical_jcs_bytes(value)
    print("JCS supported:", repr(value), actual.hex())
    assert actual == expected


@pytest.mark.parametrize(
    ("value", "error"),
    [
        ({"\u00e9": 1}, "ASCII"),
        ({"\U0001f600": 1, "\ue000": 2}, "ASCII"),
        ({"n": 1.0}, "unsupported"),
        ({"n": 9007199254740992}, "safe range"),
        ({"s": "\ud800"}, "Unicode scalar"),
        ({"n": float("nan")}, "unsupported"),
    ],
)
def test_restricted_jcs_domain_not_general_rfc8785(value, error):
    with pytest.raises(ForensicBundleError, match=error) as caught:
        canonical_jcs_bytes(value)
    print("JCS restricted rejection:", repr(value), str(caught.value))


def test_jcs_projection_is_a_different_document_not_float_canonicalization():
    actual = canonical_jcs_bytes(project_jcs_evidence({"n": 1.0}))
    assert actual == b'{"n":"1.0"}'
    assert actual != b'{"n":1}'
    composed = canonical_jcs_bytes({"s": "\u00e9"})
    decomposed = canonical_jcs_bytes({"s": "e\u0301"})
    assert composed != decomposed  # RFC 8785 does not normalize Unicode.
    print("JCS float projection:", actual.decode())


@pytest.fixture
def local_app(tmp_path, monkeypatch):
    # All interactions are in-process, synthetic, and network/host-change free.
    import socket

    def no_network(*args, **kwargs):
        raise AssertionError("network is prohibited for these probes")

    monkeypatch.setattr(socket.socket, "connect", no_network)
    monkeypatch.setattr(socket, "create_connection", no_network)
    monkeypatch.setattr(socket, "getaddrinfo", no_network)
    forwarder = _mock_forwarder()
    forwarder.forward_json = AsyncMock(return_value=_mock_response())
    monkeypatch.setattr("aegis.proxy.app.LLMForwarder", lambda *args, **kwargs: forwarder)
    guard = MagicMock(is_sandbox=True)
    guard.apply_filter.return_value = False
    monkeypatch.setattr("aegis.core.seccomp_guard.SeccompGuard", lambda *args: guard)
    monkeypatch.setattr("aegis.core.lsm_guard.LSMGuard", MagicMock())
    monkeypatch.setattr("aegis.consensus.runtime.start_gossip", AsyncMock(return_value=None))
    app = create_app(_make_settings(tmp_path))
    with TestClient(app, raise_server_exceptions=False) as client:
        yield app, client, forwarder


def _post(client, session):
    return client.post(
        "/v1/chat/completions",
        headers={"Authorization": "Bearer sk-valid"},
        json={"model": "synthetic", "messages": [{"role": "user", "content": "hi"}], "user": session},
    )


def test_ascii_session_preserves_proof_header_consistency(local_app):
    app, client, _ = local_app
    response = _post(client, "synthetic-session")
    assert response.status_code == 200
    assert response.headers["X-Aegis-Session-ID"] == "synthetic-session"
    encoded = response.headers["X-Aegis-MMR-Proof"]
    proof = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    assert response.headers["X-Aegis-MMR-Format"] == proof["version"]
    assert MMRInclusionProofV1.from_dict(proof).root == response.headers["X-Aegis-MMR-Root"]
    assert len(app.state.aegis.ledger.chain_snapshot()) == 1
    print("ASCII headers:", json.dumps(dict(response.headers), sort_keys=True))


@pytest.mark.parametrize("session", ["\u2603", "synthetic\r\nX-Synthetic: 1", ["unhashable"], "x" * 257])
def test_invalid_body_user_is_rejected_before_forwarding(local_app, session):
    app, client, forwarder = local_app
    response = _post(client, session)
    count = len(app.state.aegis.ledger.chain_snapshot())
    assert response.status_code == 422
    assert count == 1
    assert app.state.aegis.ledger.chain_snapshot()[0].status == "rejected"
    forwarder.forward_json.assert_not_awaited()


def test_valid_session_is_serializable_on_http1_wire(local_app):
    _, client, _ = local_app
    response = _post(client, "synthetic-valid")
    value = response.headers["X-Aegis-Session-ID"]
    assert response.status_code == 200
    h11.Response(status_code=200, headers=[(b"x-aegis-session-id", value.encode("ascii"))])

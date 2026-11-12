# Copyright (c) 2026 Juan Luna. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
# Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
"""Edge secret: 403 without the header, 404 for /metrics outside loopback."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from aegis.proxy.edge import EdgeSecretMiddleware, install_edge_middleware

SECRET = "s3cr3t-edge-value"


def make_app(secret: str = SECRET, header: str = "x-aegis-edge") -> FastAPI:
    app = FastAPI()
    app.add_middleware(EdgeSecretMiddleware, secret=secret, header=header)

    @app.get("/v1/x")
    def x() -> dict[str, bool]:
        return {"ok": True}

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/ready")
    def ready() -> dict[str, str]:
        return {"status": "ready"}

    @app.get("/metrics")
    def metrics() -> dict[str, bool]:
        return {"metrics": True}

    return app


def client(secret: str = SECRET, **kwargs: object) -> TestClient:
    return TestClient(make_app(secret), **kwargs)  # type: ignore[arg-type]


def test_blocks_without_header() -> None:
    assert client().get("/v1/x").status_code == 403


def test_allows_with_header() -> None:
    response = client().get("/v1/x", headers={"x-aegis-edge": SECRET})
    assert response.status_code == 200
    assert response.json() == {"ok": True}


def test_rejects_wrong_secret() -> None:
    assert client().get("/v1/x", headers={"x-aegis-edge": SECRET + "x"}).status_code == 403


def test_empty_secret_fails_closed() -> None:
    """A middleware built with an empty secret authenticates no request at all."""
    app = make_app(secret="")
    http = TestClient(app)
    assert http.get("/v1/x", headers={"x-aegis-edge": ""}).status_code == 403
    assert http.get("/v1/x").status_code == 403


def test_header_name_is_case_insensitive() -> None:
    assert client().get("/v1/x", headers={"X-Aegis-Edge": SECRET}).status_code == 200


def test_custom_header_name() -> None:
    http = TestClient(make_app(header="x-custom-edge"))
    assert http.get("/v1/x").status_code == 403
    assert http.get("/v1/x", headers={"x-custom-edge": SECRET}).status_code == 200


def test_health_exempt() -> None:
    assert client().get("/health").status_code == 200


def test_ready_exempt() -> None:
    assert client().get("/ready").status_code == 200


def test_metrics_not_public() -> None:
    assert client().get("/metrics").status_code == 404


def test_metrics_hidden_even_with_valid_secret_from_public_client() -> None:
    """The secret does not open /metrics: the route is loopback only."""
    response = client().get("/metrics", headers={"x-aegis-edge": SECRET})
    assert response.status_code == 404
    assert response.json() == {"detail": "not found"}


def test_metrics_served_to_loopback() -> None:
    http = TestClient(make_app(), client=("127.0.0.1", 50000))
    response = http.get("/metrics")
    assert response.status_code == 200
    assert response.json() == {"metrics": True}
    # And from the other loopback literal too.
    http_v6 = TestClient(make_app(), client=("::1", 50000))
    assert http_v6.get("/metrics").status_code == 200


def test_metrics_loopback_does_not_require_the_secret() -> None:
    http = TestClient(make_app(), client=("127.0.0.1", 50000))
    assert http.get("/metrics").status_code == 200
    assert http.get("/v1/x").status_code == 403


def test_forbidden_body_does_not_leak_the_secret() -> None:
    response = client().get("/v1/x", headers={"x-aegis-edge": "nope"})
    assert response.status_code == 403
    assert response.json() == {"detail": "edge authentication required"}
    assert SECRET not in response.text
    assert SECRET not in "".join(f"{k}:{v}" for k, v in response.headers.items())


def test_comparison_is_constant_time(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[bytes, bytes]] = []
    real = __import__("hmac").compare_digest

    def spy(left: bytes, right: bytes) -> bool:
        calls.append((left, right))
        return real(left, right)

    monkeypatch.setattr("aegis.proxy.edge.hmac.compare_digest", spy)
    assert client().get("/v1/x", headers={"x-aegis-edge": SECRET}).status_code == 200
    assert calls == [(SECRET.encode(), SECRET.encode())]


def test_install_helper_is_noop_without_secret() -> None:
    app = FastAPI()
    assert install_edge_middleware(app, "") is False
    assert install_edge_middleware(app, SECRET) is True

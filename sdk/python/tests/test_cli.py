# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""``aegis-sdk``: exit codes, output, and the audit client's refusals.

The exit codes are the interface a CI job scripts against, so each is pinned —
in particular that ``3`` (incomplete) is distinct from ``0``: a pipeline that
treats "nothing failed" as "verified" would accept an unauthenticated bundle.

The audit tests run a real HTTP server on loopback. The refusals are the point:
no key over plain HTTP to another host, no redirects (``urllib`` would re-send
``Authorization`` to the new location), no unbounded or non-JSON body.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from aegis_sdk import __version__
from aegis_sdk.audit import MAX_RESPONSE_BYTES, GatewayAuditError, audit_url, fetch_audit_status
from aegis_sdk.cli import EXIT_FAILED, EXIT_INCOMPLETE, EXIT_OK, EXIT_USAGE, main

SHARED = Path(__file__).parents[2] / "shared"
BUNDLE = str(SHARED / "forensic-bundle-v1.zip")
KEY = str(SHARED / "forensic-bundle-v1.pub.hex")


# ── verify ───────────────────────────────────────────────────────────────────


def test_verify_exits_zero_only_when_the_signature_verifies(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["verify", BUNDLE, "--public-key", KEY]) == EXIT_OK
    assert "RESULT: VERIFIED" in capsys.readouterr().out


def test_verify_without_a_key_exits_three_not_zero(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["verify", BUNDLE]) == EXIT_INCOMPLETE
    out = capsys.readouterr().out
    assert "RESULT: INCOMPLETE" in out
    assert "SKIP  manifest_signature" in out


def test_verify_exits_one_on_a_failed_check(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    broken = tmp_path / "broken.zip"
    broken.write_bytes(b"not a zip")
    assert main(["verify", str(broken)]) == EXIT_FAILED
    assert "FAIL  archive" in capsys.readouterr().out


def test_verify_json_report_is_machine_readable(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["verify", BUNDLE, "--public-key", KEY, "--json"]) == EXIT_OK
    report = json.loads(capsys.readouterr().out)
    assert report["result"] == "verified"
    assert {check["status"] for check in report["checks"]} <= {"pass", "skip"}


@pytest.mark.parametrize(
    "extra",
    [
        ["--public-key", "/nonexistent/key.pem"],
        ["--trusted-root", "not-hex"],
    ],
)
def test_verify_unusable_input_exits_two(
    extra: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["verify", BUNDLE, *extra]) == EXIT_USAGE
    assert capsys.readouterr().err.startswith("aegis-sdk verify:")


def test_verify_a_missing_bundle_exits_two(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["verify", "/nonexistent/bundle.zip"]) == EXIT_USAGE
    assert "cannot read bundle" in capsys.readouterr().err


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])
    assert exit_info.value.code == 0
    assert capsys.readouterr().out.strip() == f"aegis-sdk {__version__}"


# ── audit: a real loopback server ────────────────────────────────────────────


@dataclass
class _Gateway:
    """What the fake gateway answers, and what it was asked."""

    routes: dict[str, tuple[int, dict[str, str], bytes]] = field(default_factory=dict)
    seen: list[tuple[str, str | None]] = field(default_factory=list)
    url: str = ""

    def json(self, path: str, value: Any, status: int = 200) -> None:
        self.routes[path] = (
            status,
            {"Content-Type": "application/json"},
            json.dumps(value).encode(),
        )


@pytest.fixture
def gateway() -> Iterator[_Gateway]:
    state = _Gateway()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - http.server's naming
            state.seen.append((self.path, self.headers.get("Authorization")))
            status, headers, body = state.routes.get(self.path, (404, {}, b""))
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    state.url = f"http://127.0.0.1:{server.server_address[1]}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()


HEALTH = {"status": "ok", "node_count": 3, "signature_assurance": "SYMMETRIC_AUTHENTICATED"}


def test_audit_sends_the_key_from_the_environment_and_prints_sorted_json(
    gateway: _Gateway, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    gateway.json("/v1/audit/health", HEALTH)
    monkeypatch.setenv("AEGIS_AUDIT_API_KEY", "audit-key-for-test")
    assert main(["audit", gateway.url]) == EXIT_OK
    assert gateway.seen == [("/v1/audit/health", "Bearer audit-key-for-test")]
    out = capsys.readouterr().out
    assert json.loads(out)["health"] == HEALTH
    assert out == json.dumps(json.loads(out), sort_keys=True, indent=2) + "\n"


def test_audit_reads_a_custom_key_variable_and_sends_none_when_unset(
    gateway: _Gateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    gateway.json("/v1/audit/health", HEALTH)
    monkeypatch.delenv("AEGIS_AUDIT_API_KEY", raising=False)
    monkeypatch.setenv("OTHER_KEY", "k2")
    assert main(["audit", gateway.url, "--api-key-env", "OTHER_KEY"]) == EXIT_OK
    assert main(["audit", gateway.url]) == EXIT_OK
    assert [auth for _, auth in gateway.seen] == ["Bearer k2", None]


def test_audit_degraded_exits_one(gateway: _Gateway) -> None:
    gateway.json("/v1/audit/health", {**HEALTH, "status": "degraded"})
    assert main(["audit", gateway.url]) == EXIT_FAILED


def test_audit_integrity_is_opt_in_and_an_invalid_chain_exits_one(gateway: _Gateway) -> None:
    gateway.json("/v1/audit/health", HEALTH)
    gateway.json("/v1/audit/integrity", {"valid": False, "error_index": 2})
    assert main(["audit", gateway.url]) == EXIT_OK
    assert main(["audit", gateway.url, "--integrity"]) == EXIT_FAILED
    assert [path for path, _ in gateway.seen] == [
        "/v1/audit/health",
        "/v1/audit/health",
        "/v1/audit/integrity",
    ]


def test_audit_accepts_a_base_url_that_already_ends_in_v1(gateway: _Gateway) -> None:
    gateway.json("/v1/audit/health", HEALTH)
    assert main(["audit", f"{gateway.url}/v1/"]) == EXIT_OK


def test_audit_does_not_follow_a_redirect(
    gateway: _Gateway, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    gateway.routes["/v1/audit/health"] = (302, {"Location": "/elsewhere"}, b"")
    gateway.json("/elsewhere", HEALTH)
    monkeypatch.setenv("AEGIS_AUDIT_API_KEY", "must-not-travel")
    assert main(["audit", gateway.url]) == EXIT_USAGE
    assert "redirects are not followed" in capsys.readouterr().err
    assert [path for path, _ in gateway.seen] == ["/v1/audit/health"]


@pytest.mark.parametrize(
    ("status", "headers", "body", "message"),
    [
        (401, {}, b"", "HTTP 401"),
        (200, {"Content-Type": "text/html"}, b"<html>", "expected application/json"),
        (200, {"Content-Type": "application/json"}, b"[1, 2]", "not a JSON object"),
        (200, {"Content-Type": "application/json"}, b"{nope", "not JSON"),
        (
            200,
            {"Content-Type": "application/json"},
            b" " * (MAX_RESPONSE_BYTES + 1),
            "exceeds",
        ),
    ],
)
def test_audit_bad_answers_exit_two(
    gateway: _Gateway,
    capsys: pytest.CaptureFixture[str],
    status: int,
    headers: dict[str, str],
    body: bytes,
    message: str,
) -> None:
    gateway.routes["/v1/audit/health"] = (status, headers, body)
    assert main(["audit", gateway.url]) == EXIT_USAGE
    assert message in capsys.readouterr().err


def test_audit_refuses_a_key_over_plain_http_to_another_host(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("AEGIS_AUDIT_API_KEY", "secret")
    assert main(["audit", "http://gateway.example.invalid"]) == EXIT_USAGE
    assert "plain HTTP" in capsys.readouterr().err


def test_audit_unreachable_gateway_exits_two(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["audit", "http://127.0.0.1:9", "--timeout", "2"]) == EXIT_USAGE
    assert capsys.readouterr().err.startswith("aegis-sdk audit:")


@pytest.mark.parametrize(
    "url", ["ftp://gateway.example", "not a url", "https://user:pw@gateway.example"]
)
def test_audit_rejects_malformed_urls(url: str) -> None:
    assert main(["audit", url]) == EXIT_USAGE


def test_audit_rejects_a_non_positive_timeout() -> None:
    with pytest.raises(GatewayAuditError, match="timeout"):
        fetch_audit_status("https://gateway.example", api_key=None, timeout=0)


@pytest.mark.parametrize(
    ("base", "expected"),
    [
        ("https://gw.example", "https://gw.example/v1/audit/health"),
        ("https://gw.example/", "https://gw.example/v1/audit/health"),
        ("https://gw.example/v1", "https://gw.example/v1/audit/health"),
        ("https://gw.example/prefix", "https://gw.example/prefix/v1/audit/health"),
    ],
)
def test_audit_url(base: str, expected: str) -> None:
    assert audit_url(base, "health") == expected


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "[::1]"])
def test_a_key_over_http_to_loopback_is_allowed_to_try(host: str) -> None:
    with pytest.raises(GatewayAuditError) as refused:
        fetch_audit_status(f"http://{host}:9", api_key="k", timeout=1)
    assert "plain HTTP" not in str(refused.value)


def test_verify_refuses_an_oversized_key_file_without_reading_it_all(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    key = tmp_path / "huge.pem"
    key.write_bytes(b"A" * 5_000)
    assert main(["verify", BUNDLE, "--public-key", str(key)]) == EXIT_USAGE
    assert "too large" in capsys.readouterr().err


def test_verify_accepts_the_pem_form_operators_hand_out(tmp_path: Path) -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    raw = bytes.fromhex(Path(KEY).read_text().strip())
    pem = tmp_path / "operator.pub.pem"
    pem.write_bytes(
        Ed25519PublicKey.from_public_bytes(raw).public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    assert main(["verify", BUNDLE, "--public-key", str(pem)]) == EXIT_OK

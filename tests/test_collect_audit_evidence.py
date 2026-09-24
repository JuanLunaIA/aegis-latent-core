# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""The auditor's evidence collector reads, hashes and never leaks the audit key.

``scripts/collect_audit_evidence.py`` is what docs/compliance/AUDIT_READINESS.md
tells an assessor to run against a live gateway. A snapshot is only worth
handing on if three things hold. Every file is covered by ``SHA256SUMS``. The
observations match the responses they were read from. The ``audit:read`` key,
which comes from the environment, goes only to the named target: it must not
reach the output, argv, or the far end of a redirect.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
KEY = "sk-audit-collector-test-key-0123456789"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "collect_audit_evidence", ROOT / "scripts/collect_audit_evidence.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Registered first: its dataclass resolves annotations through sys.modules.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


collector = _load()

METRICS = (
    b"# HELP aegis_security_enforcement_mode Active enforcement mode\n"
    b"# TYPE aegis_security_enforcement_mode gauge\n"
    b"aegis_security_enforcement_mode 1.0\n"
)
INTEGRITY = {
    "valid": True,
    "error_index": None,
    "node_count": 4,
    "tail_hash": "ab" * 32,
    "signature_assurance": "SYMMETRIC_AUTHENTICATED",
    "scope": "retained-memory-window",
    "window_anchor_hash": "0" * 64,
    "full_history_retained": True,
}
CAPABILITIES = {
    "controls": [
        {"name": "seccomp_syscall_filter", "status": "REAL"},
        {"name": "tpm_pcr_root_of_trust", "status": "UNAVAILABLE"},
    ]
}


class _Gateway:
    """A stub gateway that records which headers reached which path."""

    def __init__(self, routes: dict[str, tuple[int, dict[str, str], bytes]]) -> None:
        self.seen: list[tuple[str, str | None]] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                outer.seen.append((self.path, self.headers.get("authorization")))
                status, headers, body = routes.get(self.path, (404, {}, b"{}"))
                self.send_response(status)
                for name, value in headers.items():
                    self.send_header(name, value)
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: Any) -> None:
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def _json_route(payload: object, status: int = 200) -> tuple[int, dict[str, str], bytes]:
    return status, {"content-type": "application/json"}, json.dumps(payload).encode()


def _healthy_routes() -> dict[str, tuple[int, dict[str, str], bytes]]:
    return {
        "/health": _json_route({"status": "healthy"}),
        "/ready": _json_route({"status": "ready"}),
        "/metrics": (200, {"content-type": "text/plain"}, METRICS),
        "/v1/audit/health": _json_route({"status": "ok", "node_count": 2}),
        "/v1/audit/integrity": _json_route(INTEGRITY),
        "/v1/attestation/capabilities": _json_route(CAPABILITIES),
    }


@pytest.fixture
def gateway() -> Iterator[_Gateway]:
    stub = _Gateway(_healthy_routes())
    yield stub
    stub.close()


def _all_bytes(directory: Path) -> bytes:
    return b"".join(p.read_bytes() for p in sorted(directory.rglob("*")) if p.is_file())


def test_a_snapshot_is_complete_hashed_and_observed(gateway: _Gateway, tmp_path: Path) -> None:
    out = tmp_path / "snap"
    assert collector.collect(gateway.url, out, KEY) == 0

    manifest = json.loads((out / "manifest.json").read_text())
    assert manifest["schema"] == "aegis-audit-evidence-snapshot-v1"
    assert manifest["target"] == gateway.url
    for probe in collector.PROBES:
        entry = manifest["requests"][probe.name]
        body = (out / entry["file"]).read_bytes()
        assert entry["status"] == 200
        assert entry["sha256"] == hashlib.sha256(body).hexdigest()
    assert manifest["observations"]["enforcement_mode"] == "strict"
    assert manifest["observations"]["integrity_valid"] is True
    assert manifest["observations"]["integrity_node_count"] == 4
    assert manifest["observations"]["controls"]["seccomp_syscall_filter"] == "REAL"
    assert manifest["observations"]["ready_status_code"] == 200

    listed = {}
    for line in (out / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split("  ", 1)
        listed[name] = digest
    files = {p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file()} - {"SHA256SUMS"}
    assert set(listed) == files, "every file, and only files that exist, is in SHA256SUMS"
    for name, digest in listed.items():
        assert hashlib.sha256((out / name).read_bytes()).hexdigest() == digest


def test_the_key_goes_only_to_audit_paths_and_never_into_the_snapshot(
    gateway: _Gateway, tmp_path: Path
) -> None:
    out = tmp_path / "snap"
    collector.collect(gateway.url, out, KEY)
    for path, authorization in gateway.seen:
        needs = path.startswith("/v1/")
        assert (authorization == f"Bearer {KEY}") is needs, (path, authorization)
    assert KEY.encode() not in _all_bytes(out)


def test_without_a_key_the_authenticated_probes_are_skipped_not_failed(
    gateway: _Gateway, tmp_path: Path
) -> None:
    out = tmp_path / "snap"
    assert collector.collect(gateway.url, out, None) == 0
    requests = json.loads((out / "manifest.json").read_text())["requests"]
    assert "skipped" in requests["audit_integrity"]
    assert requests["health"]["status"] == 200
    assert all(authorization is None for _, authorization in gateway.seen)


def test_a_redirect_is_recorded_and_never_followed_with_the_key(tmp_path: Path) -> None:
    elsewhere = _Gateway({"/v1/audit/integrity": _json_route(INTEGRITY)})
    routes = _healthy_routes()
    routes["/v1/audit/integrity"] = (
        302,
        {"location": f"{elsewhere.url}/v1/audit/integrity"},
        b"",
    )
    origin = _Gateway(routes)
    try:
        out = tmp_path / "snap"
        collector.collect(origin.url, out, KEY)
        manifest = json.loads((out / "manifest.json").read_text())
        assert manifest["requests"]["audit_integrity"]["status"] == 302
        assert elsewhere.seen == [], "the redirect target must never be contacted"
        assert "integrity_valid" not in manifest["observations"]
    finally:
        origin.close()
        elsewhere.close()


def test_an_unreachable_gateway_exits_1_and_still_writes_a_manifest(tmp_path: Path) -> None:
    stub = _Gateway({})
    url = stub.url
    stub.close()  # nothing listens on that port any more
    out = tmp_path / "snap"
    assert collector.collect(url, out, KEY, timeout=2) == 1
    requests = json.loads((out / "manifest.json").read_text())["requests"]
    assert "error" in requests["health"]


@pytest.mark.parametrize(
    "url",
    ["ftp://gateway", "https://user:pw@gateway", "https://gateway/?x=1", "gateway"],
)
def test_unusable_urls_are_refused_with_exit_2(url: str, tmp_path: Path) -> None:
    assert collector.main(["--url", url, "--out", str(tmp_path / "snap")]) == 2


def test_an_existing_snapshot_is_never_written_over(gateway: _Gateway, tmp_path: Path) -> None:
    out = tmp_path / "snap"
    out.mkdir()
    (out / "manifest.json").write_text("{}")
    assert collector.main(["--url", gateway.url, "--out", str(out)]) == 2
    assert (out / "manifest.json").read_text() == "{}"


def test_the_key_cannot_be_passed_on_the_command_line(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as exc:
        collector.main(["--url", "http://x", "--out", str(tmp_path), "--key", KEY])
    assert exc.value.code == 2


def test_attached_files_are_copied_and_covered(gateway: _Gateway, tmp_path: Path) -> None:
    verify = tmp_path / "ha_verify.json"
    verify.write_text('{"valid": true}\n')
    out = tmp_path / "snap"
    assert collector.collect(gateway.url, out, KEY, extra_files=(verify,)) == 0
    assert (out / "attached/ha_verify.json").read_text() == '{"valid": true}\n'
    assert "attached/ha_verify.json" in (out / "SHA256SUMS").read_text()

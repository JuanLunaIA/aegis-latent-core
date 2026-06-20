# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""
examples/demo.py — Aegis end-to-end reproducible demo.

Boots Aegis in-process (no real LLM provider: uses an in-process
OpenAI-compatible mock upstream), sends requests through the proxy, shows the
audit chain growing node by node, verifies cryptographic integrity, demonstrates
tamper-detection, and exports a sealed SOC2/HIPAA compliance bundle.

Everything runs in a single process, with no external network and no real
credentials, so an evaluator can run it and see the value in under one minute:

    pip install -e ".[storage-sqlite]"
    python -m examples.demo

What it proves (each step prints PASS/FAIL with the evidence):

    1. Proxy forwards OpenAI-format requests transparently.
    2. Every request appends exactly one signed node to the audit chain.
    3. verify_integrity() returns valid over the full chain.
    4. Mutating any node field breaks the chain → tamper detected at that index.
    5. The chain exports to a sealed compliance bundle whose signature
       re-verifies independently (ComplianceExporter.verify_bundle()).

Exit code is 0 only if every assertion holds.
"""

from __future__ import annotations

import asyncio
import secrets
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

import httpx
import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse

# ── Demo constants ────────────────────────────────────────────────────────────

_N_REQUESTS = 5
_PROXY_KEY = "demo-proxy-key"
_AUDIT_KEY = "demo-audit-readonly-key"
_TENANT = "demo-tenant"


# ── Presentation helpers ──────────────────────────────────────────────────────


def _hr() -> None:
    print("─" * 78)


def _step(n: int, title: str) -> None:
    print()
    _hr()
    print(f"  STEP {n} — {title}")
    _hr()


def _ok(msg: str) -> None:
    print(f"  [PASS] {msg}")


def _fail(msg: str) -> None:
    print(f"  [FAIL] {msg}")


def _free_port() -> int:
    """Return a free TCP port on loopback."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


# ── Upstream LLM mock (OpenAI-compatible with logprobs for entropy) ──────────


def _build_mock_upstream() -> FastAPI:
    """
    Minimal upstream that mimics OpenAI /v1/chat/completions, including
    `logprobs` so Aegis's entropy analyzer has a real signal (not just the
    character-level fallback).
    """
    app = FastAPI(title="mock-openai-upstream")

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/chat/completions")
    async def chat(body: dict[str, Any]) -> JSONResponse:
        content = "Aegis demo response: the audit chain is append-only."
        # Synthetic but well-formed logprobs (OpenAI top_logprobs format).
        token_logprobs = [
            {
                "token": tok,
                "logprob": -0.10 - 0.01 * i,
                "top_logprobs": [
                    {"token": tok, "logprob": -0.10 - 0.01 * i},
                    {"token": "_", "logprob": -2.5},
                ],
            }
            for i, tok in enumerate(content.split())
        ]
        return JSONResponse(
            {
                "id": "chatcmpl-demo",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": body.get("model", "gpt-4o-mini"),
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": content},
                        "logprobs": {"content": token_logprobs},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": 12,
                    "completion_tokens": len(token_logprobs),
                    "total_tokens": 12 + len(token_logprobs),
                },
            }
        )

    return app


# ── uvicorn servers in daemon threads (full lifespan) ────────────────────────


class _ThreadedServer:
    """
    Runs an ASGI app with uvicorn in a daemon thread, executing its full
    lifespan (unlike ASGITransport, which skips it). Required so the forwarder's
    httpx client and the ledger initialize exactly as in production.
    """

    def __init__(self, app: Any, port: int) -> None:
        cfg = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
        self._server = uvicorn.Server(cfg)
        self._thread = threading.Thread(target=self._server.run, daemon=True)

    def start(self, *, ready_timeout: float = 15.0) -> None:
        self._thread.start()
        deadline = time.monotonic() + ready_timeout
        while time.monotonic() < deadline:
            if self._server.started:
                return
            time.sleep(0.02)
        raise RuntimeError("uvicorn server did not start within timeout")

    def stop(self) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=5.0)


def _build_aegis_app(backend_port: int) -> FastAPI:
    """
    Build the Aegis proxy app pointed at the mock upstream. Configuration is
    injected via environment variables before AegisSettings is instantiated.
    """
    import os

    # Isolated WAL per run: avoids loading nodes from previous runs that were
    # signed with a different HMAC key, which would break chain verification.
    wal_path = Path(tempfile.mkdtemp(prefix="aegis_demo_wal_")) / "aegis.wal.jsonl"

    os.environ.update(
        {
            "AEGIS_PROVIDER": "openai",
            "AEGIS_BACKEND_URL": f"http://127.0.0.1:{backend_port}",
            "AEGIS_BACKEND_API_KEY": "",
            "AEGIS_WAL_PATH": str(wal_path),
            "AEGIS_API_KEYS": _PROXY_KEY,
            "AEGIS_AUDIT_API_KEYS": _AUDIT_KEY,
            # Dedicated HMAC key → legal_admissibility = "High".
            "AEGIS_SIGNING_KEY": secrets.token_hex(32),
            "AEGIS_DEBUG_MODE": "false",
            "AEGIS_FORCE_LOGPROBS": "true",
            # Demo runs in-process: declare sandbox to skip real seccomp/LSM
            # enforcement (production hardening that doesn't apply to an
            # ephemeral demo process).
            "HERMES_SANDBOX": "true",
        }
    )

    from aegis.config import AegisSettings
    from aegis.proxy.app import create_proxy_app

    return create_proxy_app(AegisSettings())


# ── Compliance export (uses the real ComplianceExporter engine) ───────────────


async def _export_compliance(chain: list[Any]) -> bool:
    """
    Maps the proxy's AuditNodes to a SQLite StorageProvider, produces an
    HMAC-sealed compliance bundle, then independently re-verifies it.

    {P} chain is non-empty; each node exposes node_hash/merkle_root/signature.
    {Q} returns True iff the bundle was written and its signature re-verifies.
    """
    import datetime

    from aegis_server.compliance.exporter import (
        ComplianceExporter,
        ExportParams,
    )
    from aegis_server.crypto.base import LocalHMACSigner
    from aegis_server.storage.sqlite_provider import SQLiteStorageProvider

    workdir = Path(tempfile.mkdtemp(prefix="aegis_demo_"))
    db_path = str(workdir / "audit.db")
    export_dir = str(workdir / "exports")

    storage = SQLiteStorageProvider(db_path)
    await storage.initialize()
    try:
        for node in chain:
            d = node.to_dict()
            ts_iso = (
                datetime.datetime.fromtimestamp(float(d["timestamp"]), tz=datetime.UTC)
                .isoformat()
                .replace("+00:00", "Z")
            )
            await storage.write_node(
                node_id=node.node_hash,
                timestamp=ts_iso,
                node_data=d,
                request_hash=d.get("request_hash", ""),
                response_hash=d.get("response_hash", ""),
                merkle_root=d.get("merkle_root", ""),
                signature=d.get("signature", ""),
                client_id=d.get("tenant_id", _TENANT) or _TENANT,
            )

        signer = LocalHMACSigner(secrets.token_hex(32))
        exporter = ComplianceExporter(storage=storage, signer=signer, export_dir=export_dir)
        result = await exporter.export(ExportParams(from_offset=0, limit=10_000, tenant_id=None))

        print(f"  bundle written : {result.output_path}")
        print(f"  node_count     : {result.node_count}")
        print(f"  chain_hash     : {result.chain_hash[:32]}…")
        print(f"  signer_scheme  : {result.signer_scheme}")
        print(f"  integrity      : {result.integrity_valid}")

        verification = await ComplianceExporter.verify_bundle(result.output_path, signer)
        signature_ok = bool(verification.get("signature_valid"))
        chain_hash_ok = bool(verification.get("chain_hash_match"))
        print(f"  re-verify sig  : {signature_ok}")
        print(f"  re-verify hash : {chain_hash_ok}")
        return (
            result.node_count == len(chain)
            and result.integrity_valid
            and signature_ok
            and chain_hash_ok
        )
    finally:
        await storage.close()


# ── Tamper-evidence (independent ledger — does not corrupt the exported chain) ─


def _demo_tamper_evidence() -> bool:
    """
    Shows that editing a single field of any node breaks verification. Uses a
    fresh ledger so it does not affect the chain exported in the previous step.
    """
    from aegis.core.crypto_audit import CryptographicAuditLedger

    workdir = Path(tempfile.mkdtemp(prefix="aegis_tamper_"))
    ledger = CryptographicAuditLedger(str(workdir / "wal.jsonl"), signing_key=secrets.token_hex(32))
    try:
        for i in range(3):
            ledger.commit_forensic(state_id=f"node-{i}", request_bytes=f"req-{i}".encode())

        ok_before, _ = ledger.verify_integrity()
        if not ok_before:
            _fail("chain did not verify before tampering")
            return False

        # Mutate state_id of node 1 → changes its node_hash → breaks the link.
        ledger.chain[1].state_id = "TAMPERED"
        ok_after, idx = ledger.verify_integrity()

        if (not ok_after) and idx == 1:
            _ok(f"verify_integrity() detected tampering at index={idx}")
            return True
        _fail(f"tampering was not detected as expected (ok={ok_after}, idx={idx})")
        return False
    finally:
        ledger.close()


# ── Orchestration ─────────────────────────────────────────────────────────────


def main() -> int:
    print()
    print("  AEGIS LATENT CORE — REPRODUCIBLE END-TO-END DEMO")
    print("  (in-process mock upstream · no external network · no real credentials)")

    backend_port = _free_port()
    proxy_port = _free_port()

    mock = _ThreadedServer(_build_mock_upstream(), backend_port)
    aegis_app = _build_aegis_app(backend_port)
    proxy = _ThreadedServer(aegis_app, proxy_port)

    results: list[bool] = []

    try:
        # ── STEP 1: boot Aegis + mock upstream ────────────────────────────
        _step(1, "Boot Aegis and the mock upstream")
        mock.start()
        proxy.start()
        base = f"http://127.0.0.1:{proxy_port}"
        with httpx.Client(timeout=10.0) as client:
            health = client.get(f"{base}/health")
            up = health.status_code == 200
            results.append(up)
            (_ok if up else _fail)(f"GET /health → {health.status_code}")

            # ── STEP 2: send requests and watch the chain grow ─────────────
            _step(2, "Send requests and observe the audit chain growing")
            for i in range(_N_REQUESTS):
                resp = client.post(
                    f"{base}/v1/chat/completions",
                    headers={"Authorization": f"Bearer {_PROXY_KEY}", "x-session-id": _TENANT},
                    json={
                        "model": "gpt-4o-mini",
                        "messages": [{"role": "user", "content": f"demo request #{i}"}],
                    },
                )
                count = _wait_for_node_count(client, base, expected=i + 1, timeout=10.0)
                line = f"request #{i} → HTTP {resp.status_code} · chain length = {count}"
                if resp.status_code == 200 and count == i + 1:
                    _ok(line)
                else:
                    _fail(line)
                    results.append(False)
            else:
                results.append(True)

            # ── STEP 3: verify chain integrity via the endpoint ───────────
            _step(3, "Verify cryptographic integrity of the chain")
            integ = client.get(
                f"{base}/v1/audit/integrity",
                headers={"Authorization": f"Bearer {_AUDIT_KEY}"},
            ).json()
            valid = bool(integ.get("valid"))
            results.append(valid)
            (_ok if valid else _fail)(
                f"GET /v1/audit/integrity → valid={valid} · node_count={integ.get('node_count')}"
            )

            # ── STEP 5 (export reads the in-memory chain from the proxy) ──
            chain = list(aegis_app.state.aegis.ledger.chain)

        # ── STEP 4: tamper-evidence ────────────────────────────────────────
        _step(4, "Demonstrate tamper-evidence (mutating a node breaks the chain)")
        results.append(_demo_tamper_evidence())

        # ── STEP 5: export compliance bundle ──────────────────────────────
        _step(5, "Export a sealed SOC2/HIPAA compliance bundle")
        results.append(asyncio.run(_export_compliance(chain)))

    finally:
        proxy.stop()
        mock.stop()

    # ── Summary ────────────────────────────────────────────────────────────
    print()
    _hr()
    passed = sum(1 for r in results if r)
    total = len(results)
    if passed == total:
        print(f"  RESULT: {passed}/{total} checks OK — demo successful.")
        _hr()
        return 0
    print(f"  RESULT: {passed}/{total} checks OK — failures detected.")
    _hr()
    return 1


def _wait_for_node_count(client: httpx.Client, base: str, *, expected: int, timeout: float) -> int:
    """
    Poll until the background commit has appended `expected` nodes.

    Loop invariant: the commit runs via asyncio.create_task AFTER the response
    is returned, so the node count is eventually consistent.
    """
    deadline = time.monotonic() + timeout
    last = -1
    while time.monotonic() < deadline:
        report = client.get(
            f"{base}/v1/audit/integrity",
            headers={"Authorization": f"Bearer {_AUDIT_KEY}"},
        ).json()
        last = int(report.get("node_count", 0))
        if last >= expected:
            return last
        time.sleep(0.05)
    return last


if __name__ == "__main__":
    sys.exit(main())

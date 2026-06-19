# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""
examples/demo.py — Aegis end-to-end reproducible demo.

Levanta Aegis en proceso (sin tocar ningún proveedor LLM real: usa un upstream
mock OpenAI-compatible), manda requests a través del proxy, muestra el audit
chain creciendo nodo a nodo, verifica la integridad criptográfica, demuestra la
detección de manipulación (tamper-evidence), y exporta un bundle de compliance
SOC2/HIPAA sellado y re-verificable.

Todo corre en un único proceso, sin red externa ni claves reales, para que un
evaluador pueda ejecutarlo y "ver" el valor en menos de un minuto:

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


# ── Helpers de presentación (prose en español, datos técnicos en inglés) ─────


def _hr() -> None:
    print("─" * 78)


def _step(n: int, title: str) -> None:
    print()
    _hr()
    print(f"  PASO {n} — {title}")
    _hr()


def _ok(msg: str) -> None:
    print(f"  [PASS] {msg}")


def _fail(msg: str) -> None:
    print(f"  [FAIL] {msg}")


def _free_port() -> int:
    """Reserva un puerto TCP libre en loopback y lo devuelve."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


# ── Upstream LLM mock (OpenAI-compatible, con logprobs para entropía) ────────


def _build_mock_upstream() -> FastAPI:
    """
    Upstream mínimo que imita la respuesta de /v1/chat/completions de OpenAI,
    incluyendo `logprobs` para que el analizador de entropía de Aegis tenga
    señal real que medir (no solo el fallback a nivel de carácter).
    """
    app = FastAPI(title="mock-openai-upstream")

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/chat/completions")
    async def chat(body: dict[str, Any]) -> JSONResponse:
        content = "Aegis demo response: the audit chain is append-only."
        # logprobs sintéticos pero bien formados (formato OpenAI top_logprobs).
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


# ── Arranque de servidores uvicorn en threads (lifespan real) ────────────────


class _ThreadedServer:
    """
    Corre una app ASGI con uvicorn en un thread daemon, ejecutando su lifespan
    completo (a diferencia de ASGITransport, que lo omite). Esencial para que el
    cliente httpx del forwarder y el ledger se inicialicen como en producción.
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
    Construye la app del proxy Aegis apuntada al upstream mock. La configuración
    se inyecta por variables de entorno antes de leer AegisSettings.
    """
    import os

    # WAL aislado por corrida: evita cargar nodos de ejecuciones previas (que
    # fueron firmados con OTRA clave HMAC y romperían la verificación de la cadena).
    wal_path = Path(tempfile.mkdtemp(prefix="aegis_demo_wal_")) / "aegis.wal.jsonl"

    os.environ.update(
        {
            "AEGIS_PROVIDER": "openai",
            "AEGIS_BACKEND_URL": f"http://127.0.0.1:{backend_port}",
            "AEGIS_BACKEND_API_KEY": "",
            "AEGIS_WAL_PATH": str(wal_path),
            "AEGIS_API_KEYS": _PROXY_KEY,
            "AEGIS_AUDIT_API_KEYS": _AUDIT_KEY,
            # Clave HMAC dedicada → legal_admissibility = "High".
            "AEGIS_SIGNING_KEY": secrets.token_hex(32),
            "AEGIS_DEBUG_MODE": "false",
            "AEGIS_FORCE_LOGPROBS": "true",
            # Esta demo corre in-process: declaramos el entorno como sandbox para
            # saltar la aplicación real de seccomp/LSM (hardening de producción que
            # no aplica a un proceso efímero de demostración).
            "HERMES_SANDBOX": "true",
        }
    )

    from aegis.config import AegisSettings
    from aegis.proxy.app import create_proxy_app

    return create_proxy_app(AegisSettings())


# ── Compliance export (usa el motor real ComplianceExporter) ─────────────────


async def _export_compliance(chain: list[Any]) -> bool:
    """
    Mapea los AuditNode del proxy a un StorageProvider SQLite y produce un bundle
    de compliance sellado con HMAC, luego lo re-verifica de forma independiente.

    {P} chain no vacío, cada nodo expone node_hash/merkle_root/signature.
    {Q} devuelve True sii el bundle se escribió y su firma re-verifica.
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


# ── Tamper-evidence (ledger independiente, no corrompe la cadena exportada) ──


def _demo_tamper_evidence() -> bool:
    """
    Demuestra que editar un solo campo de un nodo rompe la verificación. Usa un
    ledger fresco para no afectar la cadena que se exporta en el paso anterior.
    """
    from aegis.core.crypto_audit import CryptographicAuditLedger

    workdir = Path(tempfile.mkdtemp(prefix="aegis_tamper_"))
    ledger = CryptographicAuditLedger(str(workdir / "wal.jsonl"), signing_key=secrets.token_hex(32))
    try:
        for i in range(3):
            ledger.commit_forensic(state_id=f"node-{i}", request_bytes=f"req-{i}".encode())

        ok_before, _ = ledger.verify_integrity()
        if not ok_before:
            _fail("la cadena no verificó antes de manipularla")
            return False

        # Manipular el state_id del nodo 1 → cambia su node_hash → rompe el enlace.
        ledger.chain[1].state_id = "TAMPERED"
        ok_after, idx = ledger.verify_integrity()

        if (not ok_after) and idx == 1:
            _ok(f"verify_integrity() detectó la manipulación en index={idx}")
            return True
        _fail(f"la manipulación no se detectó como se esperaba (ok={ok_after}, idx={idx})")
        return False
    finally:
        ledger.close()


# ── Orquestación ──────────────────────────────────────────────────────────────


def main() -> int:
    print()
    print("  AEGIS LATENT CORE — DEMO REPRODUCIBLE END-TO-END")
    print("  (upstream mock en proceso · sin red externa · sin claves reales)")

    backend_port = _free_port()
    proxy_port = _free_port()

    mock = _ThreadedServer(_build_mock_upstream(), backend_port)
    aegis_app = _build_aegis_app(backend_port)
    proxy = _ThreadedServer(aegis_app, proxy_port)

    results: list[bool] = []

    try:
        # ── PASO 1: levantar Aegis + upstream ──────────────────────────────
        _step(1, "Levantar Aegis y el upstream mock")
        mock.start()
        proxy.start()
        base = f"http://127.0.0.1:{proxy_port}"
        with httpx.Client(timeout=10.0) as client:
            health = client.get(f"{base}/health")
            up = health.status_code == 200
            results.append(up)
            (_ok if up else _fail)(f"GET /health → {health.status_code}")

            # ── PASO 2: mandar requests y ver la cadena crecer ─────────────
            _step(2, "Mandar requests y observar el audit chain creciendo")
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

            # ── PASO 3: verificar integridad por el endpoint ───────────────
            _step(3, "Verificar la integridad criptográfica de la cadena")
            integ = client.get(
                f"{base}/v1/audit/integrity",
                headers={"Authorization": f"Bearer {_AUDIT_KEY}"},
            ).json()
            valid = bool(integ.get("valid"))
            results.append(valid)
            (_ok if valid else _fail)(
                f"GET /v1/audit/integrity → valid={valid} · node_count={integ.get('node_count')}"
            )

            # ── PASO 5 (export usa la cadena en memoria del proxy) ─────────
            chain = list(aegis_app.state.aegis.ledger.chain)

        # ── PASO 4: tamper-evidence ────────────────────────────────────────
        _step(4, "Demostrar tamper-evidence (manipular un nodo rompe la cadena)")
        results.append(_demo_tamper_evidence())

        # ── PASO 5: exportar compliance ────────────────────────────────────
        _step(5, "Exportar un bundle de compliance SOC2/HIPAA sellado")
        results.append(asyncio.run(_export_compliance(chain)))

    finally:
        proxy.stop()
        mock.stop()

    # ── Resumen ────────────────────────────────────────────────────────────
    print()
    _hr()
    passed = sum(1 for r in results if r)
    total = len(results)
    if passed == total:
        print(f"  RESULTADO: {passed}/{total} verificaciones OK — demo exitosa.")
        _hr()
        return 0
    print(f"  RESULTADO: {passed}/{total} verificaciones OK — hubo fallos.")
    _hr()
    return 1


def _wait_for_node_count(client: httpx.Client, base: str, *, expected: int, timeout: float) -> int:
    """
    Espera hasta que el commit en background haya agregado `expected` nodos.

    Invariante del loop: el commit corre vía asyncio.create_task DESPUÉS de
    devolver la respuesta, así que el conteo es eventualmente consistente.
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

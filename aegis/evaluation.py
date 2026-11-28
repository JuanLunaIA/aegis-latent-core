# Copyright (c) 2026 Juan Luna. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
"""Runnable, local GTM evaluation report.

This module exercises real mechanisms with synthetic local fixtures. It is not
customer acceptance, an independent root channel, or a production assessment.
Reports never contain raw corpus text or credentials.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import inspect
import json
import os
import tempfile
import time
import uuid
from collections.abc import AsyncIterator, Callable, Sequence
from contextlib import ExitStack
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
from fastapi import FastAPI
from starlette.testclient import TestClient

from aegis_server import __version__ as _source_version

Status = Literal["passed", "failed", "manual_required"]
CHECK_IDS = (
    "non_streaming_ordering",
    "independent_inclusion",
    "rejection_evidence",
    "evidence_failure",
    "streaming",
    "root_design",
    "redaction_measurement",
    "operations",
    "tenant_negative",
    "claim_review",
)
MANUAL_LIMIT = "Requires buyer-environment evidence and human review."
SENSITIVE_EXPECTATIONS = frozenset({"EMAIL", "SSN", "ACCOUNT", "PAN", "CVV", "TRACK_DATA"})


@dataclass
class CheckResult:
    id: str
    status: Status
    summary: str
    evidence: dict[str, Any] = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "status": self.status,
            "summary": self.summary,
            "evidence": self.evidence,
            "limitations": self.limitations,
        }


@dataclass
class EvaluationReport:
    evaluation_id: str
    workflow: str
    environment: dict[str, str]
    started_at: str
    completed_at: str
    checks: list[CheckResult]
    limitations: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": "aegis-evaluation/v1",
            "evaluation_id": self.evaluation_id,
            "workflow": self.workflow,
            "environment": self.environment,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "checks": [check.to_dict() for check in self.checks],
            "limitations": self.limitations,
        }


def canonical_report_bytes(report: EvaluationReport) -> bytes:
    """Canonical JSON used by the sidecar and by Cloud's independent hash."""
    return json.dumps(
        report.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _atomic_write(path: Path, body: bytes) -> None:
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        temporary.write_bytes(body)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def write_report(report: EvaluationReport, destination: Path) -> str:
    """Atomically write canonical JSON plus a SHA-256 sidecar; return the hash."""
    canonical = canonical_report_bytes(report)
    digest = hashlib.sha256(canonical).hexdigest()
    destination.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write(destination, canonical + b"\n")
    sidecar = destination.with_suffix(".sha256")
    _atomic_write(sidecar, f"{digest}  {destination.name}\n".encode("ascii"))
    return digest


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _settings() -> Any:
    from aegis_server.config import EnterpriseSettings

    workdir = tempfile.mkdtemp(prefix="aegis-evaluation-enterprise-")
    return EnterpriseSettings(
        signer_provider="hmac",
        hmac_signing_key="e" * 32,
        storage_provider="sqlite",
        sqlite_path=str(Path(workdir) / "audit.db"),
        auth_disabled=True,
        security_enforcement_mode="development",
        compliance_export_dir=str(Path(workdir) / "exports"),
    )


def _storage(*, write_error: Exception | None = None) -> MagicMock:
    storage = MagicMock()
    storage.initialize = AsyncMock()
    storage.close = AsyncMock()
    storage.check_integrity = AsyncMock(return_value={"is_valid": True, "node_count": 0})
    storage.list_nodes = AsyncMock(return_value=[])
    storage.get_latest_node = AsyncMock(return_value=None)
    storage.get_node = AsyncMock(return_value=None)
    storage.write_node = AsyncMock(side_effect=write_error)
    storage.write_node_atomic = AsyncMock(side_effect=write_error)
    return storage


def _signer() -> MagicMock:
    signer = MagicMock()
    signer.scheme = "hmac-sha256"
    signer.sign_payload = AsyncMock(return_value="a" * 64)
    return signer


async def _aiter(parts: list[bytes]) -> AsyncIterator[bytes]:
    for part in parts:
        yield part


class _StreamContext:
    def __init__(self, response: Any) -> None:
        self.response = response

    async def __aenter__(self) -> Any:
        return self.response

    async def __aexit__(self, *args: Any) -> bool:
        return False


def _enterprise_client(
    storage: MagicMock, *, upstream_response: Any = None, upstream_error: Exception | None = None
) -> tuple[ExitStack, TestClient]:
    settings = _settings()
    stack = ExitStack()
    stack.enter_context(patch("aegis_server.main.get_settings", return_value=settings))
    stack.enter_context(patch("aegis_server.main.get_provider", return_value=storage))
    stack.enter_context(patch("aegis_server.main.get_signer", return_value=_signer()))
    http_client = AsyncMock()
    http_client.__aenter__ = AsyncMock(return_value=http_client)
    http_client.__aexit__ = AsyncMock(return_value=False)
    if upstream_error is not None:
        http_client.stream = MagicMock(side_effect=upstream_error)
    else:
        http_client.stream = MagicMock(return_value=_StreamContext(upstream_response))
    stack.enter_context(patch("httpx.AsyncClient", return_value=http_client))
    from aegis_server.main import create_app

    return stack, TestClient(create_app(settings=settings))


def _non_streaming_ordering() -> tuple[bool, dict[str, Any]]:
    body = json.dumps({"id": "chatcmpl-evaluation", "choices": []}).encode()
    response = MagicMock(status_code=200, headers={"content-type": "application/json"})
    response.aiter_bytes = MagicMock(return_value=_aiter([body]))
    storage = _storage()
    stack, client = _enterprise_client(storage, upstream_response=response)
    with stack, client:
        result = client.post(
            "/v1/enterprise/proxy/chat/completions", json={"model": "gpt-4", "messages": []}
        )
    calls = storage.write_node_atomic.await_count
    evidence = {
        "http_status": result.status_code,
        "evidence_header": result.headers.get("X-Aegis-Evidence-Status"),
        "durable_writes": calls,
    }
    return result.status_code == 200 and calls == 1 and evidence["evidence_header"] == "durable", evidence


def _evidence_failure() -> tuple[bool, dict[str, Any]]:
    storage = _storage(write_error=RuntimeError("synthetic storage failure"))
    stack, client = _enterprise_client(storage, upstream_error=httpx.ConnectError("refused"))
    with stack, client:
        result = client.post(
            "/v1/enterprise/proxy/chat/completions", json={"model": "gpt-4", "messages": []}
        )
    evidence = {
        "http_status": result.status_code,
        "evidence_header": result.headers.get("X-Aegis-Evidence-Status"),
        "unevidenced_success_observed": result.status_code == 200,
    }
    return result.status_code == 503 and evidence["evidence_header"] == "unavailable", evidence


def _independent_inclusion() -> tuple[bool, dict[str, Any]]:
    from aegis.core.mmr import MerkleMountainRange

    leaves = [f"evaluation-leaf-{index}".encode() for index in range(5)]
    mmr = MerkleMountainRange()
    for leaf in leaves:
        mmr.add_leaf(leaf)
    proof = mmr.get_portable_inclusion_proof(2)
    root = mmr.get_root_hash()
    genuine = MerkleMountainRange.verify_portable_inclusion(leaves[2], proof, root)
    tampered = not MerkleMountainRange.verify_portable_inclusion(b"altered", proof, root)
    wrong_root = not MerkleMountainRange.verify_portable_inclusion(leaves[2], proof, "0" * 64)
    evidence = {
        "genuine": genuine,
        "tampered_rejected": tampered,
        "wrong_root_rejected": wrong_root,
        "algorithm": proof.algorithm,
        "second_operator": "not_evaluated",
        "independent_root_channel": "not_evaluated",
    }
    return genuine and tampered and wrong_root, evidence


def _rejection_evidence() -> tuple[bool, dict[str, Any]]:
    from aegis.core.crypto_audit import CryptographicAuditLedger

    with tempfile.TemporaryDirectory(prefix="aegis-evaluation-rejection-") as workdir:
        path = Path(workdir) / "wal.jsonl"
        with CryptographicAuditLedger(str(path), signing_key="r" * 32) as ledger:
            before = ledger.commit_forensic(state_id="before", request_bytes=b"ok")
            node = ledger.commit_rejection(
                request_bytes=b'{"prompt":"synthetic hostile input"}',
                rejection_code=403,
                reason_category="waf_block",
                tenant_id="tenant-a",
            )
            after = ledger.commit_forensic(state_id="after", request_bytes=b"ok")
            valid, error_index = ledger.verify_integrity()
        raw = path.read_bytes()
    chained = node.prev_hash == before.node_hash and after.prev_hash == node.node_hash
    evidence = {
        "status": node.status,
        "rejection_code": node.sampling_params.get("rejection_code"),
        "chain_linked": chained,
        "integrity_valid": valid,
        "integrity_error_index": error_index,
        "hostile_payload_stored": b"synthetic hostile input" in raw,
    }
    return node.status == "rejected" and chained and valid and not evidence["hostile_payload_stored"], evidence


def _sse_event(content: str) -> tuple[bytes, dict[str, Any]]:
    parsed = {"choices": [{"index": 0, "delta": {"content": content}}]}
    return b"data: " + json.dumps(parsed).encode() + b"\n\n", parsed


async def _streaming_success() -> dict[str, Any]:
    from aegis.proxy.streaming import BoundedStreamProxy, StreamEvidenceSummary

    release = asyncio.Event()
    started = asyncio.Event()
    summaries: list[StreamEvidenceSummary] = []

    async def upstream() -> AsyncIterator[tuple[bytes, Any]]:
        yield _sse_event("hello")
        yield b"data: [DONE]\n\n", None

    async def commit(summary: StreamEvidenceSummary) -> None:
        summaries.append(summary)
        started.set()
        await release.wait()

    proxy = BoundedStreamProxy(
        upstream(), terminal_commit=commit, max_response_bytes=4096,
        max_duration_seconds=2, max_event_bytes=1024, queue_max_items=2, queue_max_bytes=2048,
    )
    iterator = proxy.__aiter__()
    first = await anext(iterator)
    pending = asyncio.create_task(anext(iterator))
    await asyncio.wait_for(started.wait(), timeout=1)
    blocked_before_commit = not pending.done()
    release.set()
    done = await asyncio.wait_for(pending, timeout=1)
    expected = first + done
    return {
        "terminal_marker_after_commit": blocked_before_commit and done == b"data: [DONE]\n\n",
        "response_hash_matches": summaries[0].response_hash == hashlib.sha256(expected).hexdigest(),
        "terminal_outcome": summaries[0].terminal_outcome,
    }


async def _streaming_commit_failure() -> bool:
    from aegis.proxy.streaming import BoundedStreamProxy

    async def upstream() -> AsyncIterator[tuple[bytes, Any]]:
        yield _sse_event("hello")
        yield b"data: [DONE]", None

    async def fail_commit(_summary: Any) -> None:
        raise OSError("synthetic fsync failure")

    proxy = BoundedStreamProxy(
        upstream(), terminal_commit=fail_commit, max_response_bytes=4096,
        max_duration_seconds=2, max_event_bytes=1024, queue_max_items=2, queue_max_bytes=2048,
    )
    output = b"".join([part async for part in proxy])
    return b"hello" in output and b"[DONE]" not in output


async def _streaming() -> tuple[bool, dict[str, Any]]:
    success = await _streaming_success()
    withheld = await _streaming_commit_failure()
    evidence = {**success, "done_withheld_on_commit_failure": withheld}
    return all((success["terminal_marker_after_commit"], success["response_hash_matches"], withheld)), evidence


def measure_redaction(corpus: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """Measure declared labels over a bounded corpus without retaining its text."""
    from aegis.core.pci_detector import PCIScrubber
    from aegis.core.phi_deidentifier import PHIDeidentifier

    if len(corpus) > 100:
        raise ValueError("redaction corpus accepts at most 100 samples")
    phi = PHIDeidentifier()
    pci = PCIScrubber()
    rows: list[dict[str, Any]] = []
    for sample in corpus:
        identifier = sample.get("id")
        text = sample.get("text")
        expected = sample.get("expected", [])
        if not isinstance(identifier, str) or not identifier.strip():
            raise ValueError("sample id must be non-empty")
        if not isinstance(text, str) or len(text) > 10_000 or not isinstance(expected, list):
            raise ValueError("sample text must be a string of at most 10000 characters")
        expected_set = set(expected)
        if not expected_set.issubset(SENSITIVE_EXPECTATIONS):
            raise ValueError("sample declares an unsupported expectation")
        phi_result = phi.scrub(text)
        pci_result = pci.scan(text)
        counts = dict(phi_result.hits)
        for label, count in (("PAN", pci_result.pan_count), ("CVV", pci_result.cvv_count), ("TRACK_DATA", pci_result.track_count)):
            if count:
                counts[label] = count
        observed = set(counts)
        rows.append({
            "id": identifier[:80],
            "text_sha256": hashlib.sha256(text.encode()).hexdigest(),
            "expected": sorted(expected_set),
            "observed": sorted(observed),
            "misses": sorted(expected_set - observed),
            "unexpected": sorted(observed - expected_set),
            "hits": counts,
        })
    misses = sum(len(row["misses"]) for row in rows)
    return {"sample_count": len(rows), "miss_count": misses, "rows": rows}


def _redaction_outcome(corpus: Sequence[dict[str, Any]]) -> tuple[bool, dict[str, Any]]:
    evidence = measure_redaction(corpus)
    return evidence["miss_count"] == 0, evidence


def _default_corpus() -> list[dict[str, Any]]:
    return [
        {"id": "synthetic-contact", "text": "Email buyer@example.test and SSN 123-45-6789", "expected": ["EMAIL", "SSN"]},
        {"id": "synthetic-card", "text": "Card 4111 1111 1111 1111 CVV: 123", "expected": ["ACCOUNT", "PAN", "CVV"]},
    ]


async def _tenant_negative() -> tuple[bool, dict[str, Any]]:
    from aegis.auth.principal import Principal, Role
    from aegis.auth.scopes import SCOPE_AUDIT_READ
    from aegis.core.crypto_audit import CryptographicAuditLedger
    from aegis.proxy.audit_api import build_audit_router

    with tempfile.TemporaryDirectory(prefix="aegis-evaluation-tenant-") as workdir:
        ledger = CryptographicAuditLedger(str(Path(workdir) / "wal.jsonl"), signing_key="t" * 32)
        ledger.commit_forensic(state_id="a", request_bytes=b"a", tenant_id="tenant-a")
        other = ledger.commit_forensic(state_id="b", request_bytes=b"b", tenant_id="tenant-b")
        app = FastAPI()

        async def tenant_auth() -> Principal:
            return Principal(subject="auditor", tenant_id="tenant-a", roles=frozenset({Role.AUDIT_READER}), scopes=frozenset({SCOPE_AUDIT_READ}), auth_method="evaluation")

        app.include_router(build_audit_router(ledger, auth_dependency=tenant_auth), prefix="/v1/audit")

        async def request_all() -> dict[str, Any]:
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://evaluation") as client:
                listing = await client.get("/v1/audit/nodes")
                crossing = await client.get("/v1/audit/nodes", params={"tenant_id": "tenant-b"})
                direct = await client.get(f"/v1/audit/nodes/{other.node_hash}")
                tenants = await client.get("/v1/audit/tenants")
            return {"listing_status": listing.status_code, "listing_tenants": [row["tenant_id"] for row in listing.json()], "cross_tenant_status": crossing.status_code, "direct_cross_tenant_status": direct.status_code, "tenant_listing_status": tenants.status_code}

        evidence = await request_all()
        ledger.close()
    ok = evidence["listing_status"] == 200 and evidence["listing_tenants"] == ["tenant-a"] and evidence["cross_tenant_status"] == 403 and evidence["direct_cross_tenant_status"] == 404 and evidence["tenant_listing_status"] == 403
    return ok, evidence


async def _automatic(identifier: str, summary: str, function: Callable[[], Any], limitations: list[str] | None = None) -> CheckResult:
    try:
        outcome = function()
        if inspect.isawaitable(outcome):
            outcome = await outcome
        passed, evidence = outcome
        return CheckResult(identifier, "passed" if passed else "failed", summary, evidence, limitations or [])
    except Exception as exc:
        return CheckResult(identifier, "failed", summary, {"error_type": type(exc).__name__}, limitations or [])


def _manual(identifier: str, summary: str, evidence: dict[str, Any], limitation: str) -> CheckResult:
    return CheckResult(identifier, "manual_required", summary, evidence, [limitation])


async def run_evaluation(*, workflow: str, redaction_corpus: Sequence[dict[str, Any]] | None = None) -> EvaluationReport:
    """Run the local witness suite and return all ten GTM check results."""
    workflow = workflow.strip()
    if not 1 <= len(workflow) <= 120:
        raise ValueError("workflow must contain 1..120 characters")
    started_at = _utc_now()
    started = time.monotonic()
    corpus = list(redaction_corpus) if redaction_corpus is not None else _default_corpus()
    checks = [
        await _automatic("non_streaming_ordering", "Durable evidence precedes the local non-streaming response.", _non_streaming_ordering, ["Mock storage and upstream; target durability is not measured."]),
        await _automatic("independent_inclusion", "Portable inclusion accepts genuine data and rejects alteration and an unrelated root.", _independent_inclusion),
        await _automatic("rejection_evidence", "A rejection is signed, linked and replay-verified without storing the hostile payload.", _rejection_evidence),
        await _automatic("evidence_failure", "A synthetic storage failure refuses the governed response without a success claim.", _evidence_failure),
        await _automatic("streaming", "The terminal marker waits for commit and is withheld after commit failure.", _streaming),
        _manual("root_design", "Root distribution, retention, rotation and compromise handling need review.", {"documented": False}, MANUAL_LIMIT),
        await _automatic("redaction_measurement", "Declared labels are measured on a bounded synthetic corpus; raw text is excluded.", lambda: _redaction_outcome(corpus), ["Synthetic labels are not customer-corpus recall, Safe Harbor or universal redaction."]),
        _manual("operations", "Setup, operator time, failures, recovery, storage and retention need an operator log.", {"runner_elapsed_ms": round((time.monotonic() - started) * 1000, 3)}, MANUAL_LIMIT),
        await _automatic("tenant_negative", "The audit router rejects cross-tenant filters, direct reads and tenant enumeration.", _tenant_negative, ["Local ASGI tenant fixture; target identity and RLS still need acceptance."]),
        _manual("claim_review", "Every final claim needs linked evidence and explicit untested surfaces.", {"reviewed": False}, MANUAL_LIMIT),
    ]
    redaction = next(check for check in checks if check.id == "redaction_measurement")
    if redaction.status == "passed" and redaction.evidence.get("miss_count") != 0:
        redaction.status = "failed"
    inclusion = next(check for check in checks if check.id == "independent_inclusion")
    if inclusion.status == "passed":
        inclusion.status = "manual_required"
        inclusion.limitations = ["A second operator and independently held root are still required."]
    return EvaluationReport(
        evaluation_id=str(uuid.uuid4()), workflow=workflow,
        environment={"kind": "local-mock", "source_version": _source_version},
        started_at=started_at, completed_at=_utc_now(), checks=checks,
        limitations=["Local synthetic witness only; not buyer acceptance, certification, legal compliance or production readiness."],
    )


def _load_corpus(path: Path) -> list[dict[str, Any]]:
    if path.stat().st_size > 1_048_576:
        raise ValueError("redaction corpus exceeds 1 MiB")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, list):
        raise ValueError("redaction corpus must be a JSON array")
    return value


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workflow", default="local-proof")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--redaction-corpus", type=Path)
    args = parser.parse_args(argv)
    try:
        corpus = _load_corpus(args.redaction_corpus) if args.redaction_corpus else None
        report = asyncio.run(run_evaluation(workflow=args.workflow, redaction_corpus=corpus))
        digest = write_report(report, args.output)
    except Exception as exc:
        print(f"EVALUATION ERROR {type(exc).__name__}", flush=True)
        return 1
    failed = sum(check.status == "failed" for check in report.checks)
    manual = sum(check.status == "manual_required" for check in report.checks)
    print(f"EVALUATION WRITTEN {args.output}")
    print(f"SHA256 {digest}")
    print(f"CHECKS {len(report.checks)} FAILED {failed} MANUAL_REQUIRED {manual}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())

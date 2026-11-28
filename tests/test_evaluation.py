# Copyright (c) 2026 Juan Luna. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from aegis.evaluation import (
    CHECK_IDS,
    canonical_report_bytes,
    measure_redaction,
    run_evaluation,
    write_report,
)


async def test_local_report_covers_ten_gtm_checks_without_inventing_acceptance() -> None:
    report = await run_evaluation(workflow="contract-test")
    document = report.to_dict()

    assert document["format"] == "aegis-evaluation/v1"
    assert document["workflow"] == "contract-test"
    assert tuple(check["id"] for check in document["checks"]) == CHECK_IDS
    checks = {check["id"]: check for check in document["checks"]}

    for identifier in (
        "non_streaming_ordering",
        "rejection_evidence",
        "evidence_failure",
        "streaming",
        "redaction_measurement",
        "tenant_negative",
    ):
        assert checks[identifier]["status"] == "passed", identifier
    for identifier in (
        "independent_inclusion",
        "root_design",
        "operations",
        "claim_review",
    ):
        assert checks[identifier]["status"] == "manual_required", identifier

    inclusion = checks["independent_inclusion"]["evidence"]
    assert inclusion["genuine"] is True
    assert inclusion["tampered_rejected"] is True
    assert inclusion["wrong_root_rejected"] is True
    assert checks["streaming"]["evidence"]["done_withheld_on_commit_failure"] is True
    assert checks["tenant_negative"]["evidence"]["cross_tenant_status"] == 403
    assert checks["tenant_negative"]["evidence"]["direct_cross_tenant_status"] == 404


async def test_report_is_deterministic_and_never_contains_raw_corpus_text() -> None:
    corpus = [
        {
            "id": "synthetic-email",
            "text": "Contact buyer@example.test and SSN 123-45-6789",
            "expected": ["EMAIL", "SSN"],
        }
    ]
    report = await run_evaluation(workflow="privacy-test", redaction_corpus=corpus)
    raw = canonical_report_bytes(report)

    assert raw == canonical_report_bytes(report)
    assert b"buyer@example.test" not in raw
    assert b"123-45-6789" not in raw
    assert b"synthetic-email" in raw
    measurement = next(
        check for check in report.checks if check.id == "redaction_measurement"
    )
    row = measurement.evidence["rows"][0]
    assert row["misses"] == []
    assert row["observed"] == ["EMAIL", "SSN"]
    assert row["text_sha256"] == hashlib.sha256(corpus[0]["text"].encode()).hexdigest()


async def test_report_file_and_sidecar_bind_the_exact_canonical_bytes(tmp_path: Path) -> None:
    report = await run_evaluation(workflow="write-test")
    destination = tmp_path / "report.json"

    digest = write_report(report, destination)

    body = destination.read_bytes()
    assert body.endswith(b"\n")
    assert hashlib.sha256(body[:-1]).hexdigest() == digest
    assert destination.with_suffix(".sha256").read_text() == f"{digest}  report.json\n"
    parsed = json.loads(body)
    assert len(parsed["checks"]) == 10


def test_redaction_measurement_rejects_unbounded_or_malformed_corpus() -> None:
    with pytest.raises(ValueError, match="at most"):
        measure_redaction([{"id": str(i), "text": "x", "expected": []} for i in range(101)])
    with pytest.raises(ValueError, match="unsupported"):
        measure_redaction([{"id": "bad", "text": "x", "expected": ["NAME"]}])
    with pytest.raises(ValueError, match="non-empty"):
        measure_redaction([{"id": "", "text": "x", "expected": []}])

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import json
import os
from pathlib import Path

from aegis.core.crypto_audit import CryptographicAuditLedger
from aegis.proxy.waf import AegisWAF

ROOT = Path(__file__).resolve().parents[1]


def _body(case: dict):
    if isinstance(case.get("body"), dict):
        return case["body"]
    return {"messages": [{"role": "user", "content": str(case.get("text", ""))}]}


def test_waf_pinned_corpus_has_no_critical_bypass_or_benign_false_positive():
    corpus = json.loads((ROOT / "tests/data/waf_corpus_v1.json").read_text(encoding="utf-8"))
    waf = AegisWAF(strict_mode=True)
    malicious_bypasses = []
    benign_false_positives = []
    for case in corpus["cases"]:
        observed_block = not waf.inspect_payload(_body(case)).allowed
        if case["expected"] == "block" and not observed_block:
            malicious_bypasses.append(case["id"])
        if case["expected"] == "allow" and observed_block:
            benign_false_positives.append(case["id"])
    assert malicious_bypasses == []
    assert benign_false_positives == []


def test_ledger_fsync_injection_preserves_durable_commit_and_integrity(tmp_path):
    fsync_calls: list[int] = []

    def recording_fsync(fd: int) -> None:
        os.fsync(fd)
        fsync_calls.append(fd)

    ledger = CryptographicAuditLedger(
        persistence_path=str(tmp_path / "audit.wal.jsonl"),
        signing_key="s" * 64,
        fsync_fn=recording_fsync,
    )
    try:
        node = ledger.commit_state(
            state_id="fault-injection-1",
            entropy=0.0,
            payload=b"bounded-fsync-test",
        )
        valid, index = ledger.verify_integrity()
        assert node.state_id == "fault-injection-1"
        assert valid is True
        assert index is None
        assert fsync_calls
    finally:
        ledger.close()

    assert (tmp_path / "audit.wal.jsonl").read_text(encoding="utf-8").count(
        "fault-injection-1"
    ) == 1

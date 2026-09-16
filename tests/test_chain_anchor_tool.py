"""
tests/test_chain_anchor_tool.py — ending a v1 chain without rewriting it.

The audit asked for a "v1 -> v2 migration tool" that exports v1 leaves and
rebuilds the MMR under v2. That is not achievable in the sense the phrase
implies: a root *is* its construction, so recomputing old leaves under v2
produces a root that no verifier ever witnessed and breaks every proof already
issued against the v1 root.

`tools/anchor_v1_chain_into_v2.py` does the achievable thing instead — it
records where the v1 chain ended so a verifier can order the two chains — and
these tests pin the property that makes it safe: **the v1 WAL is not touched**.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from aegis.core.crypto_audit import CryptographicAuditLedger

_SPEC = importlib.util.spec_from_file_location(
    "anchor_tool", Path(__file__).resolve().parents[1] / "tools" / "anchor_v1_chain_into_v2.py"
)
assert _SPEC is not None
assert _SPEC.loader is not None
anchor_tool = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(anchor_tool)


def _chain(path: Path, scheme: str, count: int = 3) -> None:
    ledger = CryptographicAuditLedger(
        str(path), signing_key="anchor-test-key", mmr_hash_scheme=scheme
    )
    for index in range(count):
        ledger.commit_forensic(state_id=f"req-{index}", request_bytes=f"payload-{index}".encode())
    ledger.close()


def test_anchor_records_the_v1_terminal_root(tmp_path: Path) -> None:
    v1 = tmp_path / "v1.jsonl"
    _chain(v1, "v1-asciihex")
    before = v1.read_bytes()

    statement = anchor_tool.build_anchor(
        v1_wal=v1, v2_wal=None, operator="examiner", reason="ending v1"
    )

    assert statement["schema"] == "aegis-chain-anchor-v1"
    assert statement["v1_chain"]["mmr_leaf_count"] == 3
    assert len(statement["v1_chain"]["terminal_merkle_root"]) == 64
    assert v1.read_bytes() == before, "the v1 WAL must not be modified"


def test_anchor_links_both_chains_when_the_v2_wal_exists(tmp_path: Path) -> None:
    v1, v2 = tmp_path / "v1.jsonl", tmp_path / "v2.jsonl"
    _chain(v1, "v1-asciihex")
    _chain(v2, "v2-binary-domain-separated")

    statement = anchor_tool.build_anchor(
        v1_wal=v1, v2_wal=v2, operator="examiner", reason="cutover"
    )
    assert statement["v2_chain"]["mmr_proof_version"] == "aegis-mmr-inclusion-v2"
    # Two independent chains must not share an accumulator root.
    assert (
        statement["v1_chain"]["terminal_merkle_root"]
        != statement["v2_chain"]["genesis_merkle_root"]
    )


def test_the_statement_digest_covers_the_statement(tmp_path: Path) -> None:
    v1 = tmp_path / "v1.jsonl"
    _chain(v1, "v1-asciihex")
    statement = anchor_tool.build_anchor(
        v1_wal=v1, v2_wal=None, operator="examiner", reason="ending v1"
    )
    recorded = statement.pop("statement_sha256")
    body = json.dumps(statement, sort_keys=True, separators=(",", ":")).encode()
    assert recorded == hashlib.sha256(body).hexdigest()


def test_anchoring_a_v2_chain_is_refused(tmp_path: Path) -> None:
    """There is nothing to end; refusing beats emitting a meaningless record."""
    v2 = tmp_path / "v2.jsonl"
    _chain(v2, "v2-binary-domain-separated")
    with pytest.raises(SystemExit, match="not a v1 chain"):
        anchor_tool.build_anchor(v1_wal=v2, v2_wal=None, operator="examiner", reason="oops")


def test_the_statement_states_what_it_does_not_establish(tmp_path: Path) -> None:
    """The boundaries travel with the artifact, not only in the tool's docs."""
    v1 = tmp_path / "v1.jsonl"
    _chain(v1, "v1-asciihex")
    boundaries = " ".join(
        anchor_tool.build_anchor(v1_wal=v1, v2_wal=None, operator="examiner", reason="ending v1")[
            "boundaries"
        ]
    )
    assert "not modified, migrated, or recomputed" in boundaries
    assert "exact leaf payload" in boundaries
    assert "only as trustworthy as the key" in boundaries


def test_an_empty_or_missing_wal_is_refused(tmp_path: Path) -> None:
    with pytest.raises(SystemExit, match="no WAL at"):
        anchor_tool.build_anchor(
            v1_wal=tmp_path / "absent.jsonl", v2_wal=None, operator="e", reason="r"
        )
    empty = tmp_path / "empty.jsonl"
    empty.write_text("", encoding="utf-8")
    with pytest.raises(SystemExit, match="contains no records"):
        anchor_tool.build_anchor(v1_wal=empty, v2_wal=None, operator="e", reason="r")

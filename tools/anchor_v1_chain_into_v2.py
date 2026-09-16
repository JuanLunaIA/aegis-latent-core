#!/usr/bin/env python3
"""Cross-sign a v1 MMR chain's terminal root into a new v2 chain's genesis.

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

**This is not a migration, and the difference is not pedantic.** An audit asked
for a tool that exports v1 leaves and rebuilds them under v2. That cannot be
done and have the result mean anything: an MMR root *is* the construction that
produced it, so recomputing old leaves under v2 yields a root that commits to
the same data under different rules. Every inclusion proof ever issued against
the v1 root would stop verifying, and the new root would attest to a history no
verifier ever witnessed. A tool that did this would destroy evidence while
appearing to preserve it.

What is achievable, and what this does, is an **anchoring statement**: a record
that says "v2 chain X begins where v1 chain Y ended", signed by the operator,
so a verifier holding proofs against either root can establish their order
without either chain being rewritten.

After running this:

* the v1 chain stays exactly as it was and stays verifiable under v1, forever;
* the v2 chain starts fresh, with the v1 terminal root recorded in its first
  commit;
* the anchoring statement links them, and is only as trustworthy as the key
  that signed it.

**The verifier-side rule this implies** (`CLM-064`): a v1 inclusion proof still
requires the exact v1 leaf payload, because v1 derives interior nodes without
domain separation and a crafted leaf can therefore collide with an interior
node. Anchoring does not repair that property — it bounds how much history is
exposed to it by ending the v1 chain.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ANCHOR_SCHEMA = "aegis-chain-anchor-v1"


def _read_terminal_node(wal_path: Path) -> dict[str, Any]:
    """Return the last complete JSONL record, or raise."""
    if not wal_path.is_file():
        raise SystemExit(f"error: no WAL at {wal_path}")
    terminal: dict[str, Any] | None = None
    line_number = 0
    with wal_path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):  # noqa: B007
            stripped = line.strip()
            if not stripped:
                continue
            try:
                terminal = json.loads(stripped)
            except json.JSONDecodeError as exc:
                # A truncated tail is the normal shape of a crash, so say which
                # line rather than failing opaquely.
                raise SystemExit(
                    f"error: {wal_path} line {line_number} is not valid JSON: {exc}"
                ) from exc
    if terminal is None:
        raise SystemExit(f"error: {wal_path} contains no records")
    return terminal


def _scheme_of(record: dict[str, Any]) -> str:
    """Return the MMR proof version a WAL record was written under."""
    proof = record.get("mmr_proof")
    if isinstance(proof, dict):
        version = proof.get("version")
        if isinstance(version, str) and version:
            return version
    # A record with no proof predates portable proofs; v1 is the only
    # construction that existed then, so naming it is accurate rather than a
    # guess -- but say where it came from.
    return "aegis-mmr-inclusion-v1"


def build_anchor(
    *,
    v1_wal: Path,
    v2_wal: Path | None,
    operator: str,
    reason: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Build the anchoring statement. Pure: performs no writes."""
    v1_terminal = _read_terminal_node(v1_wal)
    # The scheme is not a top-level WAL field: it is carried by the proof's
    # `version`/`algorithm` pair, which is the value a verifier actually acts on.
    scheme = _scheme_of(v1_terminal)
    if not scheme.startswith("aegis-mmr-inclusion-v1"):
        raise SystemExit(
            f"error: {v1_wal} records proof version {scheme!r}, not a v1 chain. "
            "Anchoring is for ending a v1 chain; there is nothing to anchor here."
        )

    statement: dict[str, Any] = {
        "schema": ANCHOR_SCHEMA,
        "created_at": (now or datetime.now(UTC)).isoformat().replace("+00:00", "Z"),
        "operator": operator.strip(),
        "reason": reason.strip(),
        "v1_chain": {
            "wal": str(v1_wal),
            # The WAL stores the chain link and the accumulator root; the node
            # hash itself is derived on read, so it is not quoted here as if it
            # had been recorded.
            "terminal_prev_hash": v1_terminal.get("prev_hash", ""),
            "terminal_merkle_root": v1_terminal.get("merkle_root", ""),
            "terminal_state_id": v1_terminal.get("state_id", ""),
            "mmr_leaf_count": v1_terminal.get("mmr_leaf_count", 0),
            "mmr_proof_version": scheme,
        },
        "boundaries": [
            "The v1 chain is not modified, migrated, or recomputed by this statement.",
            "v1 inclusion proofs remain verifiable under v1 and only under v1.",
            "A v1 proof still requires the exact leaf payload; v1 lacks domain "
            "separation, so a crafted leaf can collide with an interior node.",
            "This statement is only as trustworthy as the key that signs it; "
            "unsigned, it is an assertion by whoever produced the file.",
            "No time, custody, or external anchoring is established here.",
        ],
    }
    if v2_wal is not None:
        v2_first = _read_first_node(v2_wal)
        statement["v2_chain"] = {
            "wal": str(v2_wal),
            "genesis_prev_hash": v2_first.get("prev_hash", ""),
            "genesis_merkle_root": v2_first.get("merkle_root", ""),
            "genesis_state_id": v2_first.get("state_id", ""),
            "mmr_proof_version": _scheme_of(v2_first),
        }
    body = json.dumps(statement, sort_keys=True, separators=(",", ":")).encode()
    statement["statement_sha256"] = hashlib.sha256(body).hexdigest()
    return statement


def _read_first_node(wal_path: Path) -> dict[str, Any]:
    if not wal_path.is_file():
        raise SystemExit(f"error: no WAL at {wal_path}")
    with wal_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                return json.loads(line)  # type: ignore[no-any-return]
    raise SystemExit(f"error: {wal_path} contains no records")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Cross-sign a v1 chain's terminal root into a v2 chain's genesis. "
            "This does NOT migrate leaves: an MMR root is its construction, so "
            "recomputing v1 leaves under v2 would invalidate every issued proof."
        )
    )
    parser.add_argument("--v1-wal", type=Path, required=True, help="the closing v1 WAL")
    parser.add_argument("--v2-wal", type=Path, help="the new v2 WAL, if already started")
    parser.add_argument("--operator", required=True, help="who is making this statement")
    parser.add_argument("--reason", required=True, help="why the chain is being ended")
    parser.add_argument("--output", type=Path, help="write JSON here instead of stdout")
    args = parser.parse_args(argv)

    if not args.operator.strip() or not args.reason.strip():
        raise SystemExit("error: --operator and --reason must be non-empty")

    statement = build_anchor(
        v1_wal=args.v1_wal,
        v2_wal=args.v2_wal,
        operator=args.operator,
        reason=args.reason,
    )
    rendered = json.dumps(statement, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
        print(f"anchoring statement written to {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(rendered)
    print(
        "NOTE: this statement is unsigned. Sign it with the operator key your "
        "verifiers already hold, or it asserts nothing they can check.",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Verify an Aegis evidence record without trusting the gateway that made it.

Needs only the SDK (``pip install aegis-latent-sdk``). No network call is made.

    python prove_it.py verify RECORD.json TRUSTED_ROOT
    python prove_it.py --demo

``verify`` exits 0 only if the disclosed record is included under ``TRUSTED_ROOT``.
``--demo`` checks three shipped cases: one genuine record that must be included,
one altered record that must not, and the genuine record against a root that was
not obtained independently, which must not. It exits 0 only if all three behave
as stated.

A pass establishes inclusion under the root you supplied and nothing else. The
root must reach you by a path the discloser does not control.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from aegis_sdk.proof import AegisProofError, InclusionProof, verify_inclusion

HERE = Path(__file__).resolve().parent
UNRELATED_ROOT = "0" * 64


def _leaf_bytes(body: dict[str, Any]) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def verify_file(record_path: Path, trusted_root: str) -> bool:
    """Return True iff the record in *record_path* is included under *trusted_root*."""
    record = json.loads(record_path.read_text(encoding="utf-8"))
    try:
        proof = InclusionProof.from_mapping(record["mmr_proof"])
        included = bool(verify_inclusion(_leaf_bytes(record["record"]), proof, trusted_root))
    except (AegisProofError, KeyError, TypeError):
        print("proof malformed")
        print("NOT INCLUDED")
        return False
    print(f"leaf {proof.leaf_index} of {proof.leaf_count}  scheme={proof.version}")
    print("INCLUDED" if included else "NOT INCLUDED")
    return included


def run_demo() -> int:
    root = (HERE / "TRUSTED_ROOT.txt").read_text(encoding="utf-8").strip()
    cases = (
        ("1. genuine record, root it belongs to", "record.json", root, True),
        ("2. one altered field in the record", "record_tampered.json", root, False),
        ("3. genuine record, root you did not obtain", "record.json", UNRELATED_ROOT, False),
    )
    failures = 0
    for label, name, trusted, expected in cases:
        print(f"\n{label} (must be {'INCLUDED' if expected else 'NOT INCLUDED'})")
        actual = verify_file(HERE / name, trusted)
        if actual != expected:
            print("UNEXPECTED RESULT")
            failures += 1
    print(f"\n{'all 3 cases behaved as required' if not failures else f'{failures} case(s) wrong'}")
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--demo", action="store_true", help="run the three shipped cases")
    sub = parser.add_subparsers(dest="command")
    verify = sub.add_parser("verify", help="verify one record against a trusted root")
    verify.add_argument("record", type=Path)
    verify.add_argument("trusted_root")
    args = parser.parse_args(argv)
    if args.demo:
        return run_demo()
    if args.command == "verify":
        return 0 if verify_file(args.record, args.trusted_root) else 1
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())

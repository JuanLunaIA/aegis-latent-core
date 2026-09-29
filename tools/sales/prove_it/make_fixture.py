# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Regenerate the synthetic fixtures that ``prove_it.py --demo`` verifies.

The three records are generated, not captured from a running gateway. They exist
so that anyone can watch the verifier accept one record and reject two forgeries
without standing up a gateway. Run from a checkout::

    python tools/sales/prove_it/make_fixture.py            # rewrite in place
    python tools/sales/prove_it/make_fixture.py --check    # exit 1 if they differ

The output is deterministic: no clock, no randomness, no keys.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from aegis.core.mmr import HASH_SCHEME_V2, MerkleMountainRange

HERE = Path(__file__).resolve().parent
SCHEMA = "aegis-sales-demo-record-v1"
TARGET_INDEX = 2


def canonical(body: dict[str, Any]) -> bytes:
    """The exact bytes that become the MMR leaf."""
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _bodies() -> list[dict[str, Any]]:
    bodies: list[dict[str, Any]] = []
    for index in range(3):
        bodies.append(
            {
                "decision": "allowed",
                "model": "demo-model",
                "prompt_sha256": hashlib.sha256(f"demo prompt {index}".encode()).hexdigest(),
                "request_id": f"demo-req-{index:04d}",
                "response_sha256": hashlib.sha256(f"demo response {index}".encode()).hexdigest(),
                "tenant": "demo-tenant",
            }
        )
    return bodies


def build() -> dict[str, str]:
    """Return ``{filename: text}`` for every fixture file."""
    bodies = _bodies()
    mmr = MerkleMountainRange(hash_scheme=HASH_SCHEME_V2)
    for body in bodies:
        mmr.add_leaf(canonical(body))
    root = mmr.get_root_hash()
    proof = json.loads(json.dumps(mmr.get_portable_inclusion_proof(TARGET_INDEX).to_dict()))

    genuine = {"schema": SCHEMA, "synthetic_fixture": True, "record": bodies[TARGET_INDEX]}
    genuine["mmr_proof"] = proof
    tampered = json.loads(json.dumps(genuine))
    digest = tampered["record"]["response_sha256"]
    tampered["record"]["response_sha256"] = digest[:-1] + ("0" if digest[-1] != "0" else "1")

    def dump(value: dict[str, Any]) -> str:
        return json.dumps(value, indent=2, sort_keys=True) + "\n"

    return {
        "record.json": dump(genuine),
        "record_tampered.json": dump(tampered),
        "TRUSTED_ROOT.txt": root + "\n",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="fail if committed files differ")
    args = parser.parse_args()
    status = 0
    for name, text in build().items():
        path = HERE / name
        if args.check:
            if not path.exists() or path.read_text(encoding="utf-8") != text:
                print(f"DIFFERS {name}")
                status = 1
        else:
            path.write_text(text, encoding="utf-8")
            print(f"wrote {name}")
    return status


if __name__ == "__main__":
    sys.exit(main())

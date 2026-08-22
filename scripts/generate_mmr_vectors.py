# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import json
from pathlib import Path

from aegis.core.mmr import MerkleMountainRange

COUNTS = (1, 2, 3, 4, 5, 7, 8, 15, 16, 33)
OUTPUT = Path("sdk/shared/mmr-inclusion-v1.json")


def build_vectors() -> dict[str, object]:
    cases: list[dict[str, object]] = []
    for leaf_count in COUNTS:
        leaves = [f"leaf-{index}".encode() for index in range(leaf_count)]
        mmr = MerkleMountainRange()
        for leaf in leaves:
            mmr.add_leaf(leaf)
        cases.append(
            {
                "leaf_count": leaf_count,
                "leaves_hex": [leaf.hex() for leaf in leaves],
                "proofs": [
                    mmr.get_portable_inclusion_proof(index).to_dict() for index in range(leaf_count)
                ],
                "root": mmr.get_root_hash(),
            }
        )
    return {
        "format": "aegis-mmr-vector-set-v1",
        "algorithm": "sha256-asciihex",
        "cases": cases,
    }


def main() -> None:
    payload = json.dumps(build_vectors(), sort_keys=True, separators=(",", ":")) + "\n"
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(payload, encoding="utf-8")


if __name__ == "__main__":
    main()

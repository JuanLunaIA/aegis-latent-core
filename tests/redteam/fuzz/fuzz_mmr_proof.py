#!/usr/bin/env python3
# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Coverage-guided fuzzing of portable inclusion-proof verification.

    python tests/redteam/fuzz/fuzz_mmr_proof.py -atheris_runs=200000

This is the boundary where fully attacker-controlled structured data meets a
cryptographic verifier. A reviewer receives a proof from the party making the
claim and checks it against a root obtained elsewhere; every field except that
root is chosen by whoever wants the proof to verify.

Two properties, and the second is the one that matters:

1. **Verification never raises.** A malformed proof must return ``False``. An
   exception escaping into a verifier's loop is a denial of service against
   the auditor, and an exception caught too broadly upstream becomes an
   accidental "valid".

2. **Verification never returns ``True`` for a proof the fuzzer built.** The
   fuzzer does not know a preimage of the trusted root. Any input it can
   construct that verifies is a forgery, and therefore a critical finding.

Structured mutation matters here: random bytes are rejected by the JSON parser
long before reaching the cryptographic checks. So the harness starts from a
*genuine* proof and lets the fuzzer perturb individual fields, which is what
reaches the index arithmetic and the peak-structure validation.

`atheris` is a development-only dependency and is deliberately absent from
`requirements.lock`; this harness is not imported by the test suite.
"""

from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports():
    from aegis.core.mmr import MerkleMountainRange, MMRInclusionProofV1

#: Several peak structures: one perfect tree, and shapes with two and three
#: mountains, where index confusion lives.
_TREES: dict[int, tuple[MerkleMountainRange, list[bytes], str]] = {}
for _count in (1, 4, 5, 7, 8, 11):
    _mmr = MerkleMountainRange()
    _leaves = [f"evidence-node-{i}".encode() for i in range(_count)]
    for _leaf in _leaves:
        _mmr.add_leaf(_leaf)
    _TREES[_count] = (_mmr, _leaves, _mmr.get_root_hash())

_SIZES = sorted(_TREES)


def test_one_input(data: bytes) -> None:
    provider = atheris.FuzzedDataProvider(data)

    mmr, leaves, root = _TREES[_SIZES[provider.ConsumeIntInRange(0, len(_SIZES) - 1)]]
    leaf_index = provider.ConsumeIntInRange(0, len(leaves) - 1)
    payload = mmr.get_portable_inclusion_proof(leaf_index).to_dict()

    # Perturb a field the attacker controls on the wire.
    keys = sorted(payload)
    key = keys[provider.ConsumeIntInRange(0, len(keys) - 1)]
    choice = provider.ConsumeIntInRange(0, 3)
    if choice == 0:
        payload[key] = provider.ConsumeUnicodeNoSurrogates(64)
    elif choice == 1:
        payload[key] = provider.ConsumeIntInRange(-(2**40), 2**40)
    elif choice == 2:
        payload[key] = None
    else:
        payload.pop(key, None)

    try:
        proof = MMRInclusionProofV1.from_dict(payload)
    except (TypeError, ValueError, KeyError, AttributeError):
        # Refusing to deserialise a malformed proof is a correct outcome.
        return

    leaf = leaves[provider.ConsumeIntInRange(0, len(leaves) - 1)]
    try:
        verified = MerkleMountainRange.verify_portable_inclusion(leaf, proof, root)
    except (TypeError, ValueError, AttributeError, IndexError, KeyError) as exc:
        raise AssertionError(
            f"verification raised {exc!r} instead of returning False for {payload!r}"
        ) from exc

    if verified and leaf is not leaves[leaf_index]:
        raise AssertionError(
            f"a proof for leaf {leaf_index} verified against a different leaf: {payload!r}"
        )


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()

# Fuzzing campaigns — 4.3.0 source baseline

Harnesses live in `tests/redteam/fuzz/`. Both use `atheris` (libFuzzer for
Python), which is a development-only dependency and is deliberately absent from
`requirements.lock`.

## Runs recorded here

| harness | target | executions | new crashes | corpus |
| --- | --- | --- | --- | --- |
| `fuzz_phi_deidentifier.py` | `aegis/core/phi_deidentifier.py` | 100,000 | 0 | `phi_corpus/` |
| `fuzz_mmr_proof.py` | `aegis/core/mmr.py` portable proof verification | 200,000 | 0 (after the fix below) | `mmr_corpus/` |

Commands, reproducible as run:

```bash
python tests/redteam/fuzz/fuzz_phi_deidentifier.py \
    -atheris_runs=100000 -max_len=512 evidence/fuzz/4.3.0/phi_corpus
python tests/redteam/fuzz/fuzz_mmr_proof.py \
    -atheris_runs=200000 -max_len=256 evidence/fuzz/4.3.0/mmr_corpus
```

## Finding: type confusion in inclusion-proof verification

The first `fuzz_mmr_proof.py` run crashed after roughly 12,000 executions:

```
AssertionError: verification raised
TypeError("'>' not supported between instances of 'int' and 'str'")
instead of returning False for
{'version': 'aegis-mmr-inclusion-v1', 'algorithm': 'sha256-asciihex',
 'leaf_index': 0, 'leaf_count': '', 'peak_index': 0, ...}
```

`MMRInclusionProofV1.from_dict` validated that the field *set* matched the
schema but not that the integer fields held integers, so a proof carrying
`"leaf_count": ""` reached the range comparison in
`verify_portable_inclusion_hash` and raised instead of returning `False`.

Impact: a malformed proof — fully attacker-controlled data at the one boundary
where a third party supplies input to a verifier — raised an exception into the
caller. For an auditor verifying proofs in a loop that is a denial of service;
where an exception is caught too broadly one frame up it can become an
accidental "valid".

Fixed in `aegis/core/mmr.py` at both layers: `from_dict` now rejects a
non-integer `leaf_index`, `leaf_count` or `peak_index` (excluding `bool`, which
is an `int` subclass), and the verifier type-checks defensively so a proof
built directly or through `dataclasses.replace` also fails closed.

Regression tests: `TestTypeConfusionOnTheWire` in
`tests/redteam/test_mmr_proof_forgery.py`, including the exact input the fuzzer
produced. Re-running the harness for 200,000 executions afterwards found no
further crashes.

## Boundary

A campaign that finds no crash establishes that these harnesses, at these
execution counts, on this corpus, found none. It is not a proof of absence of
defects, and neither run reached saturation — the mission brief asked for
campaigns run to saturation, and these were bounded by session time instead.
The execution counts above are what was actually run.

`cargo-fuzz` was **not** run: it is not installed, and the environment's proxy
returns 403 for the GitHub releases API, so it could not be fetched. The Rust
WAL parser, MMR verifier and canonicalizer are therefore **not** covered by any
fuzzing recorded here.

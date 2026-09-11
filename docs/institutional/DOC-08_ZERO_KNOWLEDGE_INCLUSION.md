# DOC-08 — Zero-Knowledge Inclusion Proof: Construction and Epistemic Boundary

**Document ID:** `DOC-08`
**Source boundary:** checked-out source metadata is synchronized at `v4.3.0`; it does not prove external tag, release, registry, OCI, deployment, or acceptance state
**Canonical language:** US English
**Review method:** construction review against `aegis/core/mmr.py` and the circuit source; no third-party cryptographic audit has been performed
**Normative claim control:** [`docs/CLAIMS_MATRIX.md`](../CLAIMS_MATRIX.md)
**Human-review owner:** Release owner and qualified cryptographic reviewer

## 1. What the proof attests

**The proof attests that the ledger contains a record asserting a WAF pass. It
does not re-execute the WAF, does not attest that the WAF is correct, and does
not attest semantic correctness, model safety, or upstream provider behavior.**

That sentence is the whole of the claim. Everything below either explains how
the construction achieves exactly that, or names something a reader might
otherwise assume it achieves and states that it does not.

## 2. Construction

The circuit proves one statement:

> There exists a leaf `L`, and an inclusion path for `L`, such that `L` is
> included in the Merkle Mountain Range under public root `R`, and `L` carries a
> gateway signature over content asserting `waf_verdict = passed`.

Public inputs: the MMR root `R` and the gateway's public key. Private witness:
the leaf preimage and its inclusion path. The verdict is read from signed leaf
*content*; the WAF's matching automaton is **not** executed inside the circuit.

**Why the verdict is attested rather than recomputed.** Proving
`WAF_Check(Prompt) == Passed` in-circuit means executing Aho-Corasick over the
prompt as arithmetic constraints. The constraint count scales with prompt length
times automaton size, which is orders of magnitude beyond an inclusion path of
`O(log n)` hashes. The honest construction attests the recorded verdict and says
so; the alternative would be a proof whose cost is unbounded in the input and
whose claim is still only as good as the WAF that produced the verdict.

## 3. Trust model

Transparent setup, no trusted setup, no toxic waste: there is no ceremony whose
compromise would allow forged proofs. This is why the proving system was chosen.

Verification requires a root obtained **independently of the gateway that served
the proof**, exactly as `CLM-044` requires for the non-zero-knowledge MMR proof.
A proof verified against a root supplied by the same gateway establishes internal
consistency only. The zero-knowledge property changes what the *leaf* discloses;
it does not change where the *root* must come from.

## 4. What this does not establish

- **Not WAF correctness.** A leaf asserting `waf_verdict = passed` proves the
  ledger recorded that assertion. If the WAF was misconfigured, had a coverage
  gap, or was bypassed before the record was written, the proof is still valid
  and still says nothing about it.
- **Not prompt safety.** No statement is made about what the prompt contained,
  only that a record about it exists under `R`.
- **Not model or provider behavior.** Nothing upstream of the gateway is in
  scope.
- **Not identity, time, custody, consensus, non-membership, or external
  anchoring.** The same exclusions `CLM-044` states for MMR inclusion apply
  unchanged; zero-knowledge removes leaf disclosure and adds nothing else.
- **Not a substitute for the disclosed-leaf proof.** `CLM-044` remains the
  mechanism for a verifier who is entitled to see the leaf.
- **Not audited.** No third party has reviewed the circuit or the proving
  system's integration.

## 5. Status

`ROADMAP` until the circuit, the PyO3 binding `aegis.crypto.generate_zk_proof()`
and the background worker exist and are tested. Setup, proving and verification
cost and proof size are **unmeasured**: no figure may be quoted for them until a
reproducible artifact records one on a named workload and host. The existing
`aegis/core/zk_proof.py` remains a non-real stub (`HAS_ZK_NATIVE = False`,
`CLM-019`) and is not this construction.

---

## 6. Addenda from implementation

Sections 1 through 5 are the reviewed and approved statement of the boundary and
are reproduced above unchanged. This section records what building the circuit
established, and it only ever **narrows** the claim — nothing here widens §1.

### 6.1 Two departures from §2, both narrowing

§2 was written before the circuit existed and describes it accurately in
substance. Two details differ in the implementation and both reduce what is
claimed:

- **The gateway public key is not a public input, and no signature is verified
  in-circuit.** §2 lists it; `aegis_rust_v2/src/zk_mmr.rs` does not implement it.
  Verifying an ML-DSA or Ed25519 signature inside R1CS is a large circuit in its
  own right, and it would add nothing here: inclusion under `R` already requires
  the leaf to be one the gateway committed, because the gateway is what builds
  the tree that `R` summarizes. The only public input is `R`. Read §2's sentence
  as describing the *record* the circuit reaches, not an in-circuit signature
  check.
- **The verdict is a circuit constant, not a witnessed field.** The hashed
  preimage is `0x00 ‖ prefix ‖ ,"waf_verdict":"passed"}`, where the suffix is
  compiled in. A leaf recording `blocked`, or recording no verdict, therefore has
  no satisfying witness at all rather than being checked and rejected. This is
  strictly stronger than a checked field and is what
  `tests/test_zk_native_surface.py` and the Rust unit tests exercise.

### 6.2 The proof shape is public

A verifier must build the same R1CS shape to obtain a verifier key, so three
numbers travel with every proof and are **not** hidden by the zero-knowledge
property:

| Disclosed | What it reveals |
| --- | --- |
| Leaf prefix length | The canonical leaf's byte length, which varies with request and response preview size |
| Path depth | The height of the mountain containing the leaf |
| Peak count | `popcount(leaf_count)`, which bounds the ledger's size |

The leaf's **contents**, its **position**, and every **other leaf** remain
undisclosed. The leaf index in particular is not bound: the circuit leaves the
path's direction bits free, which is safe only because v2's domain separation
(`0x00` leaf tag, `0x01` node tag) makes an interior node's digest unusable as a
leaf. The peak index is likewise not disclosed — the circuit compares the walk
against every peak rather than an indexed one.

A reader who is entitled to none of the leaf's content but is handed the shape
learns roughly how large the request was and roughly how large the ledger is.
That is a real disclosure and deployments that care must treat it as one.

### 6.3 Leaf length is the binding constraint on feasibility

Circuit cost is dominated by the leaf-hash term, which is linear in leaf length.
`_DEFAULT_MAX_FORENSIC_BYTES` is `65_536`, and previews are hex-encoded, so a
**default-configured gateway writes leaves whose proofs would need on the order
of 10⁸ constraints.** That is not provable at any practical cost.

The construction is therefore usable only where `max_forensic_bytes` is small or
zero. This is a configuration boundary, not a tuning note: an operator who wants
zero-knowledge inclusion proofs must decide to shrink or drop forensic previews,
and that trades away the preview evidence those bytes exist to carry. Nothing in
the gateway currently makes that trade automatically, and nothing warns when a
configuration puts proofs out of reach.

### 6.4 The proving system does not refuse an unsatisfiable witness

Measured, and material to any integration: given a witness that does not satisfy
the constraints, `spartan2`'s prover returns `Ok` with a proof object rather than
an error. The object is inert — it verifies against neither the honest root nor
any other, which is what soundness requires — but a caller who treats a
successful `prove` as evidence would ship bytes whose worthlessness only a third
party discovers.

`aegis_rust_v2/src/zk_mmr.rs::prove` therefore verifies its own output before
returning, and that is why it requires the verifier key. Integrators calling the
proving system directly must do the same.

### 6.5 A verifier key from the prover establishes nothing

For the same reason §3 requires an independently obtained root, the verifier key
must be one the verifier derived themselves. Key derivation is deterministic in
the shape alone, which is what makes this possible — asserted by
`key_derivation_is_a_function_of_the_shape_alone` in
`aegis_rust_v2/tests/zk_mmr_end_to_end.rs`, where a key from a second,
independent `setup` verifies a proof made under the first.

Derivation is not free. For the shapes measured, the verifier key is tens of
megabytes and takes seconds to build, against a proof of roughly 84–110 KB. The
asymmetry is the Hyrax commitment's, not this circuit's, and it means a verifier
pays a per-shape cost that a proof-size figure does not reveal.

### 6.6 Status, restated

§5 names `aegis.crypto.generate_zk_proof()` as the binding, and that path now
resolves: `aegis/core/zk_native.py` wraps the extension and `aegis.crypto`
re-exports it alongside `verify_zk_proof`, `zk_verifier_key`, `has_zk_native` and
`split_passed_leaf`. The facade deliberately carries **two** zero-knowledge
surfaces that must not be blurred — `ZKProver`/`ZKVerifier` remain the `CLM-019`
stubs, and these functions are this construction. The wrapper imports the
extension lazily, so a pure-Python checkout still imports `aegis.crypto`, and it
refuses rather than simulating on every path where a proof cannot be produced.

Still `ROADMAP`, and §5's prohibition on quoting cost figures still holds for
public claims. Cost has now been *observed* — `aegis_rust_v2/tests/zk_mmr_cost.rs`
prints a curve on demand — but an `#[ignore]`d harness run on one developer host
is not a reproducible artifact for a named workload, so no figure from it appears
in `docs/CLAIMS_MATRIX.md` and none may be quoted externally. What has changed
since §5 was written is that the circuit, the binding and the tests now exist;
the **background worker does not**, and no gateway request path calls any of
this.

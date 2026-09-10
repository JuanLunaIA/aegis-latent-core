# Changelog

All notable changes to **Aegis Latent Core** are documented in this file.

**Last verified:** 2026-09-08 UTC
**Release baseline:** `v4.3.0`, fourteen synchronized anchors — **a candidate, not a release. Nothing is published for `4.3.0`** — no tag, GitHub Release, PyPI or npm artifact, or OCI image exists for it. Source metadata does not establish external lifecycle state, which requires independent readback. There is no `4.2.0`; the number was skipped deliberately and no artifact was ever published under it.
**Most recent published release (readback 2026-09-04):** `v4.1.2` signed annotated tag at `860f14177d94c194e5ae7156017d6fa74264e429`, GitHub Release with 31 assets, PyPI `aegis-latent-core` `4.1.2`, PyPI `aegis-latent-sdk` `4.1.2`, npm `aegis-latent-sdk` `4.1.2`, GHCR gateway image `sha256:b3f6aadc…f80710` and dashboard image `sha256:27e1bbc2…d92398`
**Historical GitHub baseline:** `v4.0.1`, a lightweight tag targeting `6469904380218584ae0b5221334bc9a46500f5ba`
**Immutable source baseline:** `fdace8844568eb788216740b2cb5daf187d99d3b` (fourteen `4.0.0` anchors)
**Source release target:** `v4.3.0` (fourteen synchronized `4.3.0` anchors; tag, release, registry, image, signature, and attestation state remain external readback facts, none of which exist yet for `4.3.0` — recorded in `docs/RELEASE_STATUS.md` §1.0)
**Documentation verification baseline:** Public claims remain controlled by `docs/CLAIMS_MATRIX.md`; framework references are contribution mappings, not certifications.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — the WAF verdict is now recorded where a proof can reach it

Groundwork for the zero-knowledge inclusion proof, and a correction to an
epistemic gap that existed independently of it.

**The outcome was real but unrecorded.** A blocked request raises before the
durable commit, so a committed node already *implied* the WAF had allowed it.
An implication is not evidence: nothing in the record said so, and nothing could
prove it. `commit_forensic` now accepts `waf_verdict`, the proxy passes `passed`
at the durable commit, and the value lands in two places that matter — the bytes
the MMR commits to (`build_merkle_leaf`) and the node signature
(`_build_signed_payload`).

Putting it in the **leaf** is the part that makes it provable. A signature binds
the verdict to a node, but the tree would know nothing about it; a statement
about the verdict can only be proved against a root if the verdict is inside the
bytes that root commits to.

**Additive, and that is asserted as bytes.** The field is omitted from the leaf
and from the signed payload whenever it is empty, so a node without a verdict
produces byte-identical output to everything written before the field existed.
The test pins the legacy envelope literally rather than recomputing it, since a
test that recomputes with the code under test follows that code wherever it
drifts.

**No SDK wire boundary.** Both SDKs reconstruct exactly one envelope — the A2A
receipt — and the A2A path records no verdict, so those bytes are unchanged and
every published SDK keeps verifying every A2A receipt. Forensic leaves, which
may now carry a verdict, are not reconstructed by any SDK: inclusion is verified
from a leaf *hash*.

**Tampering fails closed in both directions, with no version flag to keep in
step.** Verification rebuilds the payload from the node's own stored verdict, so
blanking a recorded verdict rebuilds four fields where five were signed, and
forging one onto a node that never had it rebuilds five where four were signed.
Both mismatch. The vocabulary is closed and delimiter-free, which is load-bearing
rather than tidy: the payload is `"|".join(...)`, so an unconstrained verdict
would be a serialisation ambiguity rather than merely an unknown label.

Recorded as `CLM-088`. **It records that the WAF allowed the request. It does
not establish that the WAF is correct**, and it is not itself a proof — it is
what makes one possible.

### Added — the evidence commit is now traced, and the `pqc` extra carries only what it uses

Two owner decisions from the tracing and PQC verification passes.

**`aegis.wal.commit`.** The span fabric had `aegis.waf.check` and
`aegis.forward` wired and nothing at all on the durable commit. For an evidence
product that was the wrong operation to leave dark: it is the one the gateway
exists to perform, and the one whose latency an operator most needs attributed.
The span wraps the whole durability gate, `fsync` included. It is entered on the
event loop while the work runs on a worker thread, which is deliberate — it
measures the caller's wait, which is the latency a durability gate actually
imposes.

Attributes stay content-free, the same rule metric labels follow: no payload, no
tenant, no subject value. A span is as exportable as a metric. `tests/
test_wal_commit_span.py` drives a real governed request through the ASGI app
with a stubbed upstream and asserts the span by **observing** it rather than by
reading the source; one test asserts the content-free property directly. Teeth
checked by deleting the span — five of eight tests fail, and restoring returns
to green.

The unwired W3C facade in `aegis/telemetry/otel.py` stays unwired and is now
marked `[ROADMAP]` for propagation in `docs/security/SECURITY_CONTROLS.md`.
Every gateway trace is still a new root; nothing here changes that, and the
control row says so rather than leaving a reader to find out.

**`oqs-python` removed from the `pqc` extra.** Nothing in this tree imports it.
It was declared alongside the library the code does import, so the extra
installed an unused liboqs binding; with `kyber-py` now declared, keeping it
would leave supply-chain surface in a security-relevant extra for no capability.
The `pqc` extra installs `kyber-py` only.

### Fixed — the `pqc` extra installed the wrong library, so the feature was never on

`aegis/core/mlkem_session.py` imports `kyber_py.kyber.Kyber1024` behind a
try/except and tells the operator to `pip install kyber-py`. The `pqc` extra
declared `oqs-python` instead — a different library that **no module in this
tree imports**. `kyber-py` was declared nowhere: not in `pyproject.toml`, not in
`requirements.txt`, not in the lock.

So `pip install aegis-latent-core[pqc]` installed something unused and left the
post-quantum backend switched off, and `backend_available()` returned `False` on
a tree that had been asked for exactly that capability.

The failure was silent in both directions. The import guard turned a missing
dependency into a graceful degradation rather than an error, and **thirty-two
tests covering those paths skipped instead of failing** — the suite stayed green
while the cryptographic code it reports on was never executed. Installing
`kyber-py` moves the suite from 6 748 passed / 58 skipped to 6 780 passed / 26
skipped.

`kyber-py` is now declared in the `pqc` extra, so the extra enables the feature
it advertises, and in `dev`, so CI executes those thirty-two tests instead of
skipping them. `tests/test_optional_backend_declarations.py` binds the extra to
the import — it reads `pyproject.toml`, needs none of the optional packages
installed, and fails if the two drift apart again. Its teeth were checked by
reverting the extra and observing two tests fail.

With the backend present, a real two-party exchange was driven end to end: an
initiator and a responder independently derive the **same** 32-byte secret.

Recorded as `CLM-087`, scoped deliberately to the **KEM primitive**.

**It is not TLS.** There is no TLS listener, no `SSLContext`, and no cipher-suite
or named-group negotiation in that module — it is an application-layer exchange
between two parties that already have a channel, and the gateway's ingress TLS
is terminated by the customer, outside this repository. The parameter set is
**ML-KEM-1024**, not the TLS hybrid group `X25519MLKEM768`, which the module
docstring cites only as an analogy for the composition. The post-quantum half is
pure Python, so no constant-time, side-channel or FIPS-validation property is
claimed. The register entry blocks each of those phrasings by name.

**`oqs-python` is left in place and flagged rather than removed.** Nothing in
this tree imports it, so it appears to be dead weight in an extra whose name
implies it is the post-quantum backend; dropping a declared dependency changes
what a consumer's install resolves to, which is the owner's call rather than a
side effect of fixing a different defect.

### Fixed — a security-control row that cited the wrong tracing module

A verification pass over the tracing surface found that this repository has
**two** of them, and that the control table pointed at the wrong one.

`aegis/core/observability.py` holds the real OpenTelemetry integration. It is
wired: `setup_otel()` is called from the gateway lifespan, and `record_span()
wraps exactly two operations — `aegis.waf.check` and `aegis.forward`. It is
optional, no-oping when the `otel` extra is absent.

`aegis/telemetry/otel.py` is **not OpenTelemetry**. It imports nothing from the
OTel SDK; it is a pure standard-library facade implementing W3C `traceparent`
and `tracestate` parsing and injection behind an attribute allowlist. It is
complete and tested, and **nothing in the request path uses it** — the only
references outside its own module are its package re-export and its test.

`docs/security/SECURITY_CONTROLS.md` cited that second module as the evidence
for "OpenTelemetry tracing", and described it as having an optional dependency,
which it does not have. Three errors in one row: wrong module, wrong technology,
wrong dependency story. The row now cites `observability.py` and states what is
actually wired; a second row records the W3C facade as present but unwired, so a
reader does not mistake one for the other.

Two limits are now written down rather than left to be discovered:

- **Two spans are wired, and the evidence commit path carries none.** The
  `SpanName` enum in the unwired module declares four intended spans —
  `aegis.gateway.request`, `aegis.policy.evaluate`, `aegis.proof.verify`,
  `aegis.siem.export` — and not one of those names is in use.
- **There is no W3C trace-context propagation on the wired path.** No propagator
  is registered, and no `traceparent` is extracted from an incoming request or
  injected into an upstream one, so a caller's trace does not continue through
  the gateway: every gateway trace is a new root. The unwired module is exactly
  the code that would fix this, which is why leaving both in the tree without
  saying so was the hazard.

No claim changed, because no claim covered this. `README.md` already lists the
span model under "Not built. No dates.", and `ENTERPRISE_READINESS.md` already
says "Partial; hooks exist, a tested model does not". Both were accurate; the
security-control row was the outlier.

### Added — attestation backends that refuse, and a replay that cannot escape a test

`aegis/core/tee_manager.py` already carried the hard part: a verifier protocol,
an exact `AttestationPolicy`, and a fail-closed evaluator that compares nonce
and report data with `hmac.compare_digest`. What it had no implementations of
was the protocol itself, so a deployment had a seam and nothing to put in it.

`aegis/core/tee_backends.py` adds three. `NitroBackend` and `SevSnpBackend`
refuse in every case, and refuse in two distinguishable ways on purpose: no
device node means the workload is not running on the platform it believes it is,
while a present device node means the platform is right and the vendor verifier
is the missing piece. Neither reads a COSE_Sign1 document, an SNP report, a
certificate chain or a TCB version, because no such verifier is integrated —
device presence is discovery evidence, which is the position
`TEEManager.initialize_enclave` already took.

`RecordedAttestationBackend` replays a captured document so the policy path can
be exercised without hardware. It authenticates nothing: it ignores the evidence
bytes entirely and returns a fixture.

**It needs no guard rail, because the existing evaluator already defeats it.** A
recorded document carries the nonce and issue time it was captured with, both
frozen, while production issues a fresh random nonce per challenge and reads a
real clock. So the replay fails `compare_digest` on the nonce and fails the
`max_age` bound. It can satisfy policy only when the caller supplies the very
nonce it was recorded against *and* pins the clock to the recording — which is
to say, in a test. Two tests assert exactly that, one per rejection. The
`bind_nonce` option deliberately defeats the freshness check, and exists only so
that policy-field rejection (a wrong measurement, a stale TCB status) can be
tested without the nonce check masking which field did the rejecting.

Protocol conformance is checked by mypy rather than assumed: each backend
inherits `AttestationVerifier` explicitly rather than satisfying it
structurally. `TEEManager` accepts the protocol structurally either way, but
naming it as a base makes mypy reject a drifted `verify` signature at build
time — otherwise the drift surfaces at runtime in a deployment that has the
hardware, which is the most expensive place to find it. The check was confirmed
to have teeth by drifting a signature and observing mypy reject it.

**No attestation is performed anywhere in this tree and none is claimed.**
Recorded as `CLM-086`, whose register entry blocks "hardware-attested",
"confidential computing", "runs in a TEE", and the specific trap of reading a
passing test as a verified quote.

### Added — the three verification gates that were missing, and the test-suite bug one of them exposed

A release-tooling audit listed seven gates as absent from CI. Four were already
there and passing, which today's run proves: `lean` and TLA+ are installed from
pinned revisions by the `Formal Verification (Z3, Lean, TLC)` job, `z3` comes
from the distribution package in the same job, and `syft` backs `Generate SBOM`.
They were missing from a *development container*, not from CI. Three were
genuinely absent and are added here.

**`pytest -n auto` — and it did not work.** Enabling xdist made the whole suite
abort before a single test ran: `Different tests were collected between gw3 and
gw1`. The cause is a real defect that only parallel collection exposes.
`tests/auth/test_mtls_v4.py::test_rejects_certificate_outside_validity_window`
is parametrized over **freshly generated X.509 certificates**, so pytest derived
each test id from the PEM bytes — which differ in every process. Every worker
collected a different set of ids and xdist refused to proceed. Naming the two
cases (`not_yet_valid`, `already_expired`) fixes the ids across processes, and
replaces a 2 KB base64 blob in the test name with the case it covers. The suite
now runs in **47.7 s instead of 118.9 s**, which is the difference between a
gate a contributor runs before pushing and one they skip.

**Miri, on a pinned nightly, over the digest buffer.** Miri executes real Rust
and reports undefined behaviour — invalid aliasing, uninitialised reads,
out-of-bounds arithmetic — that compiles and passes ordinary tests. It runs
`tests/block_buffer_panic_safety.rs`, covering the `block-buffer` cursor beneath
every SHA-256 and HMAC call on the evidence path, where a torn cursor is a
*wrong digest* rather than a crash.

Nightly is not a preference. Miri ships only as a nightly component and
`rustup component add miri` against stable fails outright, so the audit's
"install `cargo miri` on the stable toolchain" has no implementation; the date
is pinned instead so a nightly regression cannot turn the gate red by surprise.
The scope is one target rather than `--lib`, for three measured reasons recorded
in `docs/formal/FORMAL_VERIFICATION_LIMITS.md`: Miri cannot execute foreign
functions and the default build links PQClean C; it does not service `mmap`, so
the WAL is unreachable under it; and `--lib` drags tokio, reqwest and vendored
OpenSSL through Miri's own compilation, which had not finished after fifteen
minutes locally. Recorded as `CLM-085`.

**`slsa-verifier`, installed and executed.** Generating an attestation and
verifying one are different capabilities and only the first was present. The
verifier is installed on every run of the SBOM job — not only at release, since
a verifier that first appears at release time is one nobody has tested — and a
version check proves the binary executes.

### Fixed — a jitter gate that measured the runner, not the code

Turning on `-n auto` also surfaced a second latent defect, and this one only
parallel *execution* could expose.
`tests/test_determinism.py::TestSpawnBackgroundDeterminism::test_spawn_background_jitter_sigma`
asserted σ < 100µs on wall-clock dispatch jitter and failed at **σ = 189.66µs on
Python 3.12 while 3.11 and 3.13 passed the same commit** — the signature of a
host property, not a code property.

Four sibling checks in that same file already carry
`skipif(CI == "true")` on the identical quantity, with reasons that name this
exact failure ("shared CI runners have unbounded scheduling variance",
"multi-millisecond scheduling outliers (observed 90ms)"). This one had no such
guard and passed only because a serial suite left the runner idle. It was a
latent flake, and parallelism made it reliable rather than causing it.

Fourteen runs of the dispatch loop — six idle, eight under a parallel suite —
show why σ cannot be the instrument: the median held within ±2% (4.39–4.56µs)
and the interquartile range stayed under 1.05µs, while **σ swung eightfold
(1.23–9.82µs) even on the idle machine**, landing within a ninth of the single
largest sample in every run. One preemption sets it; 189.66µs is one ~1.9ms
preemption in 100 samples. A coefficient-of-variation bound would have flaked
for the same reason, since CV inherits σ's outlier sensitivity.

The property is now asserted twice rather than weakened. Median and IQR — both
outlier-resistant — are bounded at 100µs and run everywhere including CI; the
absolute σ bound keeps the IEC 62443 framing and is guarded exactly as its four
siblings are. The robust pair is deliberately coarser and is documented as such:
it catches a wrapper that becomes uniformly slow or broadly dispersed, not a
small change in tail shape. Its teeth were verified by injecting a 250µs
synchronous block into `_spawn_background`, which it caught at a median of
375.02µs.

### Fixed — `CLM-023` contradicted `CLM-054`

`CLM-023` stated the tree has "no cargo-fuzz workspace or Kani harness".
`CLM-054` documents the Kani harnesses, and `cargo kani` verifies five of them.
The cargo-fuzz half was accurate and stands; the Kani half was false and is
corrected.


### Fixed — four documentation statements that contradicted the code or each other

A conflict audit put ten alleged contradictions to the corpus. Six of them were
already correct and are recorded here so nobody re-opens them: the wiring status
of `GrammarFrontierAutomaton` (wired, on by default) and `CryptoShredder`
(wired, off by default) is stated accurately in `ARCHITECTURE.md`; the two
benchmark runs are already delineated, and no document pairs the 10,000-request
count with the 836 ms latency; `AEGIS_MMR_HASH_SCHEME` is already documented as
defaulting to `auto` in both places; pre-admission rejection nodes are already
specified in `CLM-060`; "the gateway ships from source only" already appears
nowhere except in the register of forbidden phrasings; and the fourteen version
anchors already agree — at `4.3.0`.

Four statements were genuinely wrong, two of which the audit did not name:

- **npm SDK version.** `README.md` contradicted *itself*: its release banner
  recorded the 2026-09-04 readback of npm `aegis-latent-sdk` `4.1.2`, while a
  later section said npm "still carries `4.0.0`". Corrected there and in
  `SUPPORT_MODEL.md` and `PROCUREMENT_CHECKLIST.md`. `BUYER_GUIDE_US.md` also
  says `4.0.0`, and is left alone: it describes the historical `v4.0.x`
  baseline, where that was the observation.
- **WAL corruption semantics.** `AUDIT_ENDPOINTS.md`, `SECURITY_CONTROLS.md`
  and `CONTROL_TO_EVIDENCE_MATRIX.md` still said commits remain permitted after
  `wal_corrupt` and that the request path does not check the fault state.
  `_require_intact_ledger` has refused all three governed endpoints with `503`
  since 2026-09-03.
- **`DOC-01` disagreed with itself.** Its Table 2 had been corrected and says so
  explicitly; two later rows — falsification test `DOC01-FALS-007` and risk
  `DOC01-RISK-003` — still described the superseded fail-open behaviour.
  `DOC01-RISK-003` is now the risk that actually remains: corruption that replay
  parses successfully raises no fault, so the ingress guard never fires.
- **`FAQ_TECHNICAL.md` said there is no gossip transport.** There is one now,
  and the gateway starts it. Rewritten to say what did *not* change, which is
  the part that matters: the mesh reconciles the CRDT accumulator, not the
  ledger.


### Added — an ML-DSA backend seam, and a measurement that corrects two of our own conclusions

`pqcrypto-mldsa`, `pqcrypto-traits` and `pqcrypto-internals` carry
`RUSTSEC-2026-0166`, `-0162` and `-0163` because upstream PQClean was archived.
None is a defect; all three are unmaintained-status notices with no fixed
version. `aegis_rust_v2/src/pqc_trait.rs` makes reacting to one cheap:
`PostQuantumSigner` states the ML-DSA-65 contract in FIPS 204 byte encodings —
bytes rather than types, because the two candidate crates model keys with
incompatible type systems and the wire format is both what they agree on and
what Aegis persists. `pqc.rs` now names only the selected backend, so the PyO3
class, its methods and the exported FFI symbols are identical either way.

Both backends are optional dependencies, so the swap genuinely *removes* the C
stack rather than shadowing it: under `--no-default-features --features
pure-rust-pqc` the dependency tree contains `ml-dsa` and none of
`pqcrypto-mldsa`, `pqcrypto-traits`, `pqcrypto-internals` or `paste`.

It does not strand evidence, and that is measured rather than assumed. The
`cross_backend` tests (`cargo test --features pqc-compat-tests`) assert that
`ml-dsa` verifies a PQClean signature, that PQClean verifies an `ml-dsa`
signature, and that `ml-dsa` derives the **same** public key from the persisted
4032-byte expanded secret — so nodes already in a WAL stay verifiable, a
rollback stays open, and the durable signing identity survives without
re-keying.

**The default is unchanged, and that is the measurement's verdict.** On this
repository's hardware, both signing arms hedged: verify 45,961 → 65,805 ns
(1.43x), sign 135,443 → 650,361 ns (**4.80x**). Signing is per-commit work on
the evidence path, so 4.8x is a real cost to pay against an advisory that
reports no defect. The swap is a flag an operator takes deliberately.

Two things we had written down turned out to be wrong, and both are corrected
in place rather than quietly dropped:

- `pqc.rs` said closing the `verify` timing gap "requires a verifier that does
  not exit early — an upstream change in `pqcrypto-mldsa` or a different
  implementation". A different implementation now measures at the **same**
  `p = 0.0000` with a **larger** class delta. The proposed remedy does not work.
- More usefully, it explains why. When two independent implementations of one
  specification give the same result, the effect belongs to the experiment. The
  `verify` experiment's classes are one repeated signature versus 1024 varying
  ones, **all valid** — two sets of *public* inputs — and **ML-DSA verification
  consumes no secret**: public key, public message, public signature. A timing
  difference across public inputs discloses nothing they did not already
  disclose. Signing, which does touch the secret key, meets the non-detection
  threshold on both backends (`p = 0.8399` and `p = 0.8828`).

No constant-time claim is made or lifted for either backend; the release gate in
`docs/security/PQC_CONSTANT_TIME.md` stands closed. Recorded as `CLM-084`, with
the roadmap in `docs/security/DEPENDENCY_RISK_REGISTER.md`.

Also fixed: `cargo fmt --check` was failing on four pre-existing diffs in
`aegis_rust_v2/src/crdt_mmr.rs`, unrelated to this change and unrelated to any
behaviour. Reformatted so the gate passes.


### Added — the gateway now starts the gossip mesh, and receipts can be checked across replicas

`GossipDaemon` existed and converged, but nothing started it: enabling
`AEGIS_GOSSIP_ENABLED` configured a mesh that never ran. `aegis/consensus/runtime.py`
closes that. The gateway's lifespan now starts both halves — the daemon that
reaches out to peers on a timer, and an mTLS listener on its own port that lets
peers reach in — and stops them on shutdown, daemon first so a peer's in-flight
round does not log a failure that is only shutdown.

Placed **before** the seccomp filter, deliberately: reading the three PEM files
needs `openat` and binding the listener needs a socket the filter is about to
forbid, so starting it afterwards fails looking like a TLS fault. Two settings
are new, `AEGIS_GOSSIP_BIND_HOST` and `AEGIS_GOSSIP_BIND_PORT`, and the Helm
chart now renders them so the listener, the `containerPort` and the port the
peer list is written against cannot drift apart.

Misconfiguration is loud rather than silent. Each of the three PEM settings is
checked by name before TLS sees it, a missing native `CausalMmr` is a startup
failure rather than a Python stand-in that would compute roots no other replica
agrees with, and the listener is waited on via `server.started` rather than a
connect probe — the kernel accepts into the backlog as soon as the socket is
bound, so a probe cannot tell "serving" from "bound but never scheduled". Under
strict enforcement a failure to start is fatal; otherwise it is an error log and
the gateway continues without the mesh. It is never skipped quietly: a replica
asked to join a mesh that did not join looks healthy while diverging from every
peer.

`aegis.core.a2a.verify_cluster_receipt` is the verifier-side half. A cluster has
no single root — each replica keeps its own single-writer WAL and its own
accumulator — so it searches a supplied set of per-replica **ledger** roots and
returns the name of the replica whose root verifies the receipt, which is where
an auditor goes for the surrounding evidence. Two boundaries are stated in the
code and in `CLM-083` because both are easy to get wrong: a match is *one
replica's word, not the cluster's* — replicas do not attest to each other's
ledgers, so this is not a quorum and not corroboration — and the roots are
**ledger** roots, not gossip roots, since the mesh reconciles a different
structure whose root cannot verify a receipt at all.

Recorded as `CLM-083`; `CLM-080` updated to say the mesh is started by the
gateway rather than merely importable.


### Changed — concurrent WAL commits now share one `fsync` (group commit)

A commit did not return until its record was `fsync`ed, and that `fsync` was
issued **inside the ledger lock**, one per record. So concurrent commits did not
merely each pay for a device round trip — they paid for them *in series*. Under
32 concurrent writers, measured on this repository's own filesystem, that was
p99 55.5 ms and 1,065 commits/s.

`aegis/core/group_commit.py` coalesces them. An `fsync` makes everything already
written to the descriptor durable, not just the caller's own record, so one call
can retire a whole burst. Records are written and ordered under the ledger lock;
the lock is then released, and one waiter issues a single `fsync` covering every
record written while it was in flight. Same workload after: **p99 24.8 ms,
1,536 commits/s, and 66 `fsync` calls in place of 400** — reproducible with
`tools/benchmarks/run_group_commit.py`.

No artificial delay is used, and that is deliberate. Batching does not need a
timer: while the syncer is inside its `fsync`, later writers pile up behind it,
and the next syncer retires all of them. A fixed linger would tax the
uncontended path — the common case — to help a case that already batches on its
own, so `AEGIS_COMMIT_BATCH_TIMEOUT_MS` is only ever paid when another committer
is already waiting. `AEGIS_COMMIT_BATCH_MAX_SIZE` bounds that wait; it cannot
bound what an `fsync` covers, because `fsync` is not scopable to part of a file.

Two properties changed and both are stated rather than glossed:

- **A node enters the in-memory chain before its batch is synced.** It has to:
  the next committer reads the tip to link against it. Nothing observes the node
  in the meantime, because the commit call has not returned, and a crash in that
  window loses the in-memory chain too — replay rebuilds a shorter, internally
  consistent chain from the WAL. The previous invariant, "each node is fsynced
  before the in-memory chain is updated", no longer holds and has been corrected
  wherever it was written down.
- **A batch is durable together or not at all.** A failed `fsync` raises
  `WalDurabilityError` to *every* commit waiting on it and latches
  `wal_persist_failed`, which `_require_intact_ledger` already reads to answer
  503 and stop extending the chain. Individual nodes are deliberately not
  unwound: later nodes have already linked against them, so there is no single
  node whose removal leaves a consistent chain. The engine stays latched after
  the disk recovers, because a descriptor that lost a write may have lost it
  silently.

WAL rotation and `close()` both `fsync` before replacing or releasing the
descriptor, which makes pending records durable as a side effect; both now tell
the engine so, and — where they previously swallowed the error — report a failed
`fsync` to it instead, so waiters fail closed rather than being released against
a write that never landed.

Recorded as `CLM-082`. `CLM-059` was widened: `wal_persist_failed` is now also
reachable from a durability failure at commit time, not only from startup
replay.


### Fixed — concurrent appends forked the enterprise storage chain (P0)

The analytics path read the chain tip, then built and **signed** the node — an
await that may reach an HSM — and only then wrote. Two background tasks
therefore read the same tip and both appended against it. Measured on SQLite
before the fix: ten concurrent appends produced **ten nodes all naming one
predecessor**. A hash chain with two successors at a point has no single
history, and an integrity sweep over either branch passes, so this is not a
corruption to be detected later; it is a state the store must not reach.

Two layers, and neither is redundant:

- `write_node_atomic(..., expected_prev_hash)` appends **only if the tip is
  still what the caller read**, and raises `ConcurrentChainMutationError`
  otherwise, writing nothing. `prev_hash` also moves out of the `node_data`
  JSON into a column with a uniqueness constraint, which makes a fork
  *unrepresentable* rather than merely detectable — in a linear chain no two
  nodes share a predecessor, so the constraint is exactly the invariant. It
  covers what a compare-and-append alone cannot: on an empty table there is no
  row to lock, so two genesis writers would otherwise both commit.
- A process-wide lock spans the whole read-tip → sign → append sequence, which
  is what keeps this process's MMR consistent with what it writes. It does
  nothing across workers or hosts; the storage guard is the only thing that
  does.

**What this does not fix.** An append refused because *another process* moved
the tip is reported and lost, not retried. A retry would have to re-add an MMR
leaf, and this process's MMR is a separate accumulator from the shared chain,
so a second leaf for one request would leave the two disagreeing. Reconciling
them needs the MMR and the store to commit together, which they do not. And a
store that forked before the constraint existed now refuses to initialise,
naming the duplicate — repairing it means choosing which branch is the record,
which no rule here can decide.

Only the SQLite path is verified. The PostgreSQL (`FOR UPDATE`
compare-and-append plus a unique partial index) and DynamoDB
(`TransactWriteItems` against a tip item) implementations are written against
their documented primitives but were not executed: `asyncpg`, a PostgreSQL
server and a DynamoDB endpoint are all absent here. `CLM-081` records that.


### Fixed — a gossip round that failed said nothing about why

`GossipDaemon.run_round` logged `failed (%s)` with the exception alone. Several
of the exceptions that reach there carry no message, so an operator saw
`round with peer replica-1 failed ()` and learned nothing — and a reproducible
fault looked like an unexplained one. The log now carries the exception type,
which is what actually distinguishes a refused certificate from a timeout from
a rejected state.


### Added — cross-replica reconciliation, off by default

- **`CausalMmr` has a transport.** The join-semilattice was implemented and
  tested but nothing ran it: there was no way to move a replica's leaf set
  between processes, so the convergence it promised was reachable only from a
  single test that held both replicas in one interpreter.

  `aegis/consensus/` supplies the missing half — a peer set, a schedule, and
  anti-entropy over mutual TLS. Each round compares roots first, so a converged
  cluster exchanges one 32-byte digest per peer per interval; only a mismatch
  triggers a state exchange, which moves leaves in both directions at once.
  There is no log to be at the end of and no leader to be behind: a replica
  that misses any number of rounds catches up completely on its next
  successful one.

  The wire format is new Rust (`encode_state`/`decode_state`). Its decoder is
  the part that faces a peer who may not be friendly, so it is canonical
  (clock entries must ascend, or one state would have many encodings),
  bounded (a leaf count is checked against a ceiling *and* against the bytes
  actually present, because a trusted length prefix is an out-of-memory
  primitive), and total — every truncation returns an error rather than
  panicking, which matters behind a PyO3 boundary where an unwind aborts the
  interpreter rather than raising. The sender's own replica id is deliberately
  absent from the wire: it would break canonicality, and it would put a
  forgeable claim of identity beside the authenticated one the certificate
  already establishes.

  **Verification is not optional and there is no flag to disable it.** A peer
  supplies leaves that enter every replica's accumulator, so authenticating
  peers is the entire security boundary. Convergence is asserted over three
  replicas on real loopback TLS sockets with `CERT_REQUIRED` in both
  directions, through a simulated partition and heal; a client presenting no
  certificate, or one from another CA, is refused at the handshake.

  **What it does not do.** It reconciles the CRDT accumulator, *not* the
  ledger: each replica's WAL stays its own chain and nothing about a receipt,
  root or inclusion proof changes (`CLM-012` unchanged). It is not consensus,
  not Byzantine fault tolerance and not a total order — `join` reconciles
  replicas that disagree about ordering, not replicas that lie, and a replica
  contributing fabricated leaves has them merged like any other. There is no
  membership protocol; the peer list is static configuration.

  Rendered onto the existing StatefulSet rather than a DaemonSet. A DaemonSet
  has no `volumeClaimTemplates` and so cannot give each replica its own WAL
  claim — the single-writer property the chart is built around — while the
  StatefulSet plus its headless Service already provides what a mesh needs and
  a DaemonSet does not: a stable per-replica DNS name a certificate can be
  issued for.

### Added — cryptographic erasure on the ledger commit path, off by default

- **`CryptographicAuditLedger` can seal what it commits.** `CryptoShredder`
  existed and was tested but nothing called it, so the property it was written
  for — erase a subject without moving the tree — was unavailable to any
  deployment. With `AEGIS_ENABLE_CRYPTOGRAPHIC_SHREDDING=true` the ledger now
  encrypts each leaf under a per-subject AES-256-GCM key and commits
  `SHA-256(0x00 || nonce || ciphertext)` in its place; `crypto_shred(subject_id)`
  destroys that key, and `open_sealed_leaf(node)` reads a node back while the key
  still exists.

  The mechanism is that the commitment is computable from the ciphertext alone.
  A verifier who cannot read a leaf can still recompute what the tree committed
  to, so **destroying the key invalidates no proof**: `tests/test_crypto_shredder_integration.py`
  asserts on a live ledger that after erasure the inclusion proof still verifies,
  the plaintext no longer opens, the root is unchanged, `verify_integrity()`
  still passes, and another subject's records are still readable.

  **Off by default, and not a runtime toggle.** Sealing changes what the MMR
  commits to, so it cannot be enabled for a chain that already holds records —
  adopting it means starting a new chain, the same rule the hash scheme follows.
  An unchanged deployment commits payload digests exactly as before, and
  `crypto_shred()` on such a ledger raises rather than returning a false
  success, so a retention job cannot mistake a no-op for an erasure.

  Three costs an operator owns. The WAL carries ciphertext, so its growth tracks
  payload size. The key vault (`<wal_path>.shredder.db` by default) becomes the
  only mutable component in an append-only design: lose it and every plaintext
  is gone at once, restore it from a pre-erasure backup and every erasure through
  it is undone. And a shredded node **keeps its request and response digests**,
  so erasure removes the ability to read a payload, not the ability to confirm a
  guess about it. `CLM-068` states what may be claimed; no regulatory conclusion
  follows from any of it.

### Changed — documentation that described three components as unwired

`4.3.0` wires the grammar frontier (on by default), the v2 hash scheme (on for
new chains) and the shredder (off by default). The claims matrix rows for the
first two were updated when they landed, but the descriptive corpus still told
readers that the streaming path uses `StreamingDeidentifier` alone, that v2 "is
not the default", and that the shredder "is not wired in" — statements that were
true when written and are now false. Corrected across `ARCHITECTURE.md`,
`DECISIONS.md`, `PII_REDACTION_BOUNDARIES.md`, `DATA_RETENTION.md`,
`MMR_PROOF_V1.md`, `FAQ_TECHNICAL.md`, `ROADMAP.md`, `PLATFORM_OPERATOR_GUIDE.md`,
`BACKUP_RESTORE.md`, `DOC-02`, `DOC-03`, `DOC-05`, `CLAIM_EVIDENCE_GRAPH.md`,
`UNSUPPORTED_CLAIMS.md` and `CLAIMS_MATRIX.md`.

Wiring narrows nothing these documents bound. `UC-037` still blocks every
erasure conclusion and gains one: "Aegis erases on request" is now also
forbidden, because the default build does not. The blocked-wording row for
`CLM-064`–`CLM-068` gains "the grammar frontier replaced the de-identifier" (it
runs *after* it, and replacing it would have dropped eighteen detectors) and
requires "for new chains" wherever v2 is called enabled.

### Fixed — three defects that each failed quietly

- **Importing the proxy module took the WAL's exclusive lock (P0).**
  `aegis/proxy/app.py` ended with `app = create_app()`, and constructing the app
  opens the WAL and claims its single-writer lock. So *importing the module for
  any reason at all* claimed it, and the documented factory `create_proxy_app()`
  then failed with `WalWriterConflictError` against a writer that was the
  importing process itself. Anything that imported the module without wanting a
  running gateway paid the same price: a test collector, a CLI reading a
  version, a worker importing one helper.

  The attribute is now lazy (PEP 562 module `__getattr__`), so the app is built
  on first *access* rather than on import. `uvicorn.run("aegis.proxy.app:app")`
  and `from aegis.proxy.app import app` both resolve through it, so the ASGI
  entry point is unchanged, and repeated access still returns one app.

- **Every commit signed under a throwaway post-quantum key (P1).**
  When the Rust extension was present and no HSM was configured, `_sign` called
  `generate_pqc_keypair()` **on every commit** and discarded the private half
  immediately. Each node was signed by a different one-shot identity that nobody
  holds — which attributes nothing, links nothing, and cannot be checked against
  any published key, while being recorded under the `pqc-ml-dsa` scheme label as
  though it could. It also put an ML-DSA keygen on the commit path.

  The tier now signs under a persistent identity, configured by
  `AEGIS_PQC_IDENTITY_PATH` and created on first use (written `0600`; it holds
  the raw ML-DSA-65 private key and needs the custody any signing secret does).

  Two ways that identity could still stop attributing anything, both raised in
  review and both fixed here. **An identity provisioned elsewhere is checked
  rather than trusted**: one whose mode lets group or other read it is refused,
  and signing falls through to HMAC rather than claiming ML-DSA under a key the
  whole host can read. It is refused rather than silently `chmod`-ed, because
  tightening the mode does not un-expose a key that has already been readable
  and would hide the provisioning mistake. And **publication is now
  create-if-absent rather than replace**: two processes pointed at one absent
  path both find it missing and both generate a keypair — ML-DSA keygen holds
  that window open — so the one that published second used to overwrite the
  first's file while continuing to sign under its own discarded key. Measured
  before the fix, six concurrent processes produced up to four distinct signing
  keys, with every one of them signing under a key that was not the one left on
  disk; a shared temporary filename also let one process consume another's file
  mid-write and drop silently to HMAC. The bytes now go to a per-process
  temporary and are linked into place, so the loser adopts the winner's identity
  instead of orphaning its own nodes.
  **With no identity configured the tier is skipped and signing falls through to
  HMAC-SHA256**, rather than minting a key per signature. That changes the
  recorded `signature_scheme` for deployments that had the Rust extension and no
  HSM — from `pqc-ml-dsa` to `hmac-sha256` — which is a weaker claim and a true
  one, where the old label was a stronger claim than the evidence supported.

- **New chains defaulted to the MMR construction v2 exists to replace (P1).**
  `mmr_hash_scheme` defaulted to `v1-asciihex`, which admits the leaf/interior
  type confusion documented in `aegis/core/mmr.py`. The default is now `auto`:
  a **new** chain starts on `v2-binary-domain-separated`, and an **existing**
  chain reopens under whatever scheme its WAL recorded. Pinning a scheme
  explicitly stays fail-closed — a WAL written under the other one is still
  refused with `mmr_scheme_mismatch`.

  `auto` rather than a plain v2 default is the point: the scheme decides every
  root a chain has recorded, so defaulting to v2 outright would refuse to open
  every chain already in the field, turning an upgrade into an outage.

### Fixed — v2 defects the new default exposed

Moving new chains to v2 surfaced four places that computed or compared digests
under the v1 construction regardless of the proof in hand. Each was latent: v1
was the only scheme any ledger used, so none could fire.

- **`aegis/core/a2a.py`** hardcoded the v1 leaf digest, so a receipt issued by a
  v2 ledger could not be verified at all. The digest now follows the version the
  receipt's own proof declares, which is self-describing — a verifier reads it
  off the receipt rather than having to know how the issuer was configured.
- **Both SDK verifiers** (`sdk/python`, `sdk/typescript`) had the same hardcoded
  v1 leaf digest and are fixed the same way.
- **`verify_portable_inclusion_hash`** required the trusted root in hex, but a
  v2 proof *transports* its root as unpadded base64url — so a caller passing the
  root straight from the proof document it received, which is the obvious thing
  to do, was rejected. Both encodings are now accepted and normalised; this is
  not a relaxation, since both decode to the same 32 bytes and anything that is
  neither still fails.
- **The `X-Aegis-MMR-Format` response header** was the literal string
  `aegis-mmr-inclusion-v1`. It now reports the version of the proof actually
  served: the header tells a client which construction to verify under, so
  advertising v1 while serving a v2 proof sent it to the wrong leaf digest.

**Wire compatibility.** A receipt from a v2 chain cannot be verified by an SDK
build that predates these fixes, including the published `4.1.2` packages. Both
in-repo SDKs are fixed, but gateway and SDKs must move together; a v2 gateway in
front of older clients breaks receipt verification.

### Fixed

- **A ledger configured for MMR v2 would have recorded a leaf digest that
  disagreed with its own accumulator.** `crypto_audit.py` computed the digest it
  stores on each committed node as `sha256(leaf)` in three places — the v1
  construction, hardcoded — while the accumulator appended
  `sha256(0x00 || leaf)` under v2. Replay rebuilt a different root from the
  recorded digests and the integrity check reported an intact chain corrupt.
  Nothing shipped could reach it, because until this release no ledger could
  select v2; it would have fired the moment one did. The digest now comes from
  `MerkleMountainRange.leaf_digest`, which applies the accumulator's own scheme.

### Added

- **The audit ledger can select the domain-separated MMR construction.**
  `CryptographicAuditLedger(mmr_hash_scheme=…)` and `AEGIS_MMR_HASH_SCHEME`
  accept `v2-binary-domain-separated`, which applies the RFC 6962 §2.1 domain
  tags — `0x00` on leaves, `0x01` on interior nodes, `0x02` on the bagged root —
  and hashes raw digests rather than their hex text. **The default stays v1**,
  so no existing deployment changes.

  v2 has existed in `aegis/core/mmr.py` and both SDK verifiers since `4.3.0`,
  wired to nothing, and the module recorded two blockers. Both are now cleared.
  `aegis_rust_v2/src/mmr.rs` implemented v1 only, so an accelerated deployment
  running Python v2 would have disagreed with the Rust root on every leaf; it
  now implements both under the same scheme names, and
  `tests/test_mmr_v2_migration.py` asserts the two accumulators agree across a
  37-leaf rollover under each. The Rust constructor still defaults to v1 and
  refuses an unrecognised scheme name rather than falling back.

  **There is no in-place migration, and there cannot be one.** The scheme
  decides every root a chain has recorded, and a root cannot be recomputed under
  a different construction without rewriting the history it commits to. So a
  scheme belongs to a chain: the ledger reads the proof version its WAL recorded
  and refuses to open it under a different one, reporting fault state
  `mmr_scheme_mismatch` before replay rather than replaying to a different root
  and reporting intact evidence as corrupt. Selecting v2 means starting a new
  chain; existing v1 chains stay verifiable under v1.

  What this establishes is leaf/interior-node type distinctness and nothing
  further. The v1 weakness is that a leaf whose payload is the concatenated hex
  of two child digests hashes identically to the node over those children — the
  Rust and Python tests both demonstrate the collision under v1 and its absence
  under v2. It is not a break of SHA-256, and it does not let anyone forge a
  proof against a root they do not control.

### Changed

- **The grammar-frontier automaton now runs on the governed streaming path.**
  It was implemented and tested at `4.3.0` but wired to nothing, so it changed
  no runtime behaviour. It is now composed with the Safe Harbor de-identifier
  in `aegis/core/stream_redactor.py`, selected by `AEGIS_STREAMING_ENGINE`,
  which defaults to `grammar_frontier`.

  **Composed, not substituted.** The automaton declares four rules; the Safe
  Harbor set declares twenty. Replacing one with the other would have taken
  `EMAIL`, `ADDRESS`, `MRN`, `URL`, `TRACK_DATA`, `CVV` and the
  Luhn-and-brand-validated `PAN` — eighteen detectors in all — off the evidence
  path in exchange for two new ones. Both stages run instead, de-identifier
  first, so the path gains `INSTR_OVERRIDE` and `SYS_LEAK` matching without
  losing anything.

  **Response redaction off means off.** With both PHI and PCI detector families
  disabled the de-identifier is a pass-through that withholds nothing, and the
  frontier stage does not run either. Adding it there would have turned "no
  redaction" into "some redaction plus a 28-character holdback" — changing both
  the bytes a deployment emits and when it emits them — for an operator who
  asked for neither.

  **Two effects to know about where redaction is on.** Output bytes change for
  streams containing instruction-override or system-prompt-disclosure phrasing:
  that text is now replaced. And the per-stream holdback grows by the
  28-character frontier, so `R_max` rises by 112 bytes; the composite reports
  the summed window, so the ceiling added in `CLM-078` still covers everything
  the stream retains. Setting `AEGIS_STREAMING_ENGINE=deidentifier` restores the
  previous behaviour exactly.

  Measured overhead is +10 to +12 µs per chunk at p50 and +3.8 to +22.7 µs at
  p99 across five runs of `benchmarks/bench_streaming_engine.py`, against the
  5 ms p99 budget the change was held to. The p99 figure sits at the harness's
  noise floor — earlier runs at the same sample size measured the new stage as
  *faster*, which it cannot be — so it is recorded as "too small for this
  harness to separate from variance" rather than as a number. Artifacts and
  that boundary are in `evidence/streaming-engine/4.3.0/`.

## [4.3.0] — unreleased source target

**Nothing is published for `4.3.0`.** There is no tag, GitHub Release, PyPI or
npm artifact, and no OCI image. This section records what the source tree
contains at fourteen synchronized `4.3.0` anchors; it is not a release
announcement, and the date of any future release is not set here. See
`docs/RELEASE_STATUS.md` §1.0.

**`4.2.0` does not exist.** The number was skipped deliberately when the source
line moved from `4.1.2` to `4.3.0`. No `4.2.0` artifact was ever built or
published, so its absence from any registry is expected rather than a
withdrawal.

### Security

- **`vitest` upgraded to 4.1.11 in `sdk/typescript`** (`GHSA-82fw-gwwq-j7x9` /
  `CVE-2026-84373`). `@vitest/mocker` registered a redirect mock's target path
  without checking it against the dev server's file-serving allowlist, so a
  client that could reach Vite's unauthenticated HMR socket could read
  arbitrary local files. Affected 2.1.0 up to 4.1.11; the SDK pinned 3.2.7. The
  dashboard was already on 4.1.11 but its lock file carried a stale copy of the
  SDK's metadata, so both locks were refreshed. `npm ci` reproduces both trees.
  This was the only advisory affecting a pinned version anywhere in the
  repository. `tests/security/test_dependency_containment.py` fails the build
  if either project's declared version or resolved lock entries fall back
  behind the fix.

- **Quadratic ReDoS in the PHI de-identifier's `EMAIL` pattern, found and
  fixed.** The unbounded local-part class matched separator-dense runs such as
  `1-1-1-…` in full at every start position, then backtracked the length of the
  run before advancing one character. Measured at 2.0 s for 16 KB and 12.29 s
  for 40 KB — a clean 4× per doubling. Model output is attacker-influenced text
  on the evidence path, so this was one request per stalled worker. Bounding
  each run at the limits RFC 5321 already imposes (64 octets local part, 255
  domain, 63 final label) makes the scan linear: the same 40 KB input now takes
  73.8 ms, and 80 KB takes 152 ms. No deliverable address is rejected by the
  bound, and every existing detection test passes unchanged.

- **Type confusion in portable inclusion-proof verification, found by fuzzing
  and fixed.** `MMRInclusionProofV1.from_dict` checked that the field *set*
  matched the schema but not that the integer fields held integers, so a proof
  carrying `"leaf_count": ""` reached the range comparison in
  `verify_portable_inclusion_hash` and raised `TypeError` instead of returning
  `False`. A verifier that throws on hostile input is a denial of service
  against the auditor running it, and an exception caught too broadly one frame
  up becomes an accidental "valid". Fixed at both layers: `from_dict` refuses a
  non-integer `leaf_index`, `leaf_count` or `peak_index` (excluding `bool`,
  which is an `int` subclass), and the verifier type-checks defensively so a
  proof built directly or through `dataclasses.replace` also fails closed.

- **Rust digest stack migrated to `sha2` 0.11 / `hmac` 0.13**, removing
  `block-buffer 0.10.4` from the tree. Hash output is unchanged byte for byte,
  asserted against published external vectors rather than against the
  implementation's own prior output: FIPS 180-4 for SHA-256 (including the
  56-byte case that straddles a block boundary) and RFC 4231 for HMAC-SHA-256,
  comparing full digests rather than prefixes. The tests this replaced compared
  a six-character prefix and compared `hmac_sign` with itself, which holds for
  any deterministic function including a wrong one. Verified with 49 Rust
  tests, 106 Python MMR parity tests under `AEGIS_REQUIRE_RUST=1`, and a clean
  Miri run over the digest tests including a caught-panic case.

  **This remediates a real advisory.** Row `0.31` of the scanner report flags
  `block-buffer 0.10.4` at CVSS 6.3 with an **empty CVE ID field** — which is
  why an OSV query returns nothing, and why this entry previously recorded that
  no primary source existed. A caught panic could leave an `EagerBuffer` or
  `ReadBuffer` cursor violating its invariant, after which `get_pos()` reaches
  `unreachable_unchecked`; the crate sat under every SHA-256 and HMAC call on
  the evidence path via `digest 0.10`. Upstream fixed it with a `ResetGuard`
  whose `Drop` restores the invariant during unwind.

- **Both published `block-buffer` proofs ported and run under Miri.**
  `aegis_rust_v2/tests/block_buffer_panic_safety.rs` reproduces the advisory's
  own two tests — a panic inside `compress`, a panic inside `gen_block` — and
  adds a third for a panic inside `read_fn` that neither proof covers. All
  three pass under `cargo +nightly miri test` against the `block-buffer 0.12.1`
  this crate links, so the remediation is demonstrated rather than inferred
  from a version number. `block-buffer` is added as a dev-dependency for this,
  pinned to the version Cargo already resolves so the test cannot exercise a
  second copy.

  The two buffer types do not share a cursor invariant — `EagerBuffer` requires
  `pos < block_size`, `ReadBuffer` requires `1 <= pos <= block_size` — and
  asserting the former on the latter produces a test that fails against correct
  behaviour. Both are asserted separately.

### Added

- **Public-surface compatibility suite (`tests/compat/`).** Asserts that the
  console entry points, HTTP routes, top-level Python exports and `aegis_rust`
  FFI names present at the published `v4.1.2` tag are still present. Every
  expected value was read out of the tag with `git show v4.1.2:<path>` rather
  than restated, and the assertions run one way — anything that existed then
  must exist now, additions are fine — so a new endpoint does not train anyone
  to edit the expectation. `v4.1.2` is the baseline because it is the most
  recent published release: there is no `4.2.0` at any surface, so there is no
  `4.2.0` contract to compare against. It pins names, routes and call shapes
  only; response bodies and persisted-evidence compatibility are covered
  elsewhere, and the SDKs version independently.

- **The retained-byte ceiling is computed in code (`aegis/core/stream_bounds.py`).**
  `R_max = 4W + Q + E + P` was declared in `specs/aegis_stream_buffer.smt2` and
  restated in prose, but nothing computed it, so the two could drift without a
  failure anywhere. `StreamRetentionBounds` now holds the expression and the
  spec's declared parameter ranges in one place, and `tests/test_stream_bounds.py`
  parses the ranges back out of the `.smt2` file rather than hardcoding both
  sides. `BoundedStreamProxy` gained `bounds` and `retained_bytes_ceiling`
  accessors; they are **reporting only** and change no admission decision, so
  no stream the previous release admitted is refused now.

  This does not upgrade what the Z3 run establishes. That check remains
  arithmetic consistency over declared ranges, not a refinement proof of the
  proxy or of process memory, and `R_max` remains a per-stream ceiling —
  aggregate memory still scales with concurrent admitted streams.

- **Scanner report ingest (`scripts/triage/parse_socket_report.py`).**
  Converts a Socket.dev PDF export into normalized JSON committed under
  `evidence/dependency-scan/`, so a scan is diffable rather than a binary
  nobody can review. It undoes the layout wrapping that splits package names
  and paths mid-token, recognizes both the dependency-alerts and threat-feed
  layouts, and exits non-zero on any row it cannot parse — a silent drop would
  break the guarantee that every row is accounted for. The 2026-09-09 report's
  **100 rows parsed with zero failures**, as did the 30 rows of the threat-feed
  sample.

- **Deterministic dependency triage (`scripts/triage/dependency_triage.py`).**
  Reads every dependency the repository locks across all five lock files,
  queries OSV per pinned version, and assigns each component to exactly one of
  six action buckets under a fixed precedence. The advisory snapshot is pinned
  to `docs/security/advisory_snapshot.json` so classification is reproducible
  offline and records the date the advisory set was observed. Advisories with
  no fixed version are routed to the maintenance bucket rather than the CVE
  bucket — they have no bump available, and filing them as CVEs makes the gate
  unsatisfiable. `--scan-export` merges a CSV or JSON scanner export and reports
  rows naming packages the repository does not lock rather than dropping them.

- **Licence inventory (`scripts/license/license_scan.py`).** Reads declared
  licences from installed `.dist-info` metadata, crate manifests under
  `CARGO_HOME`, and npm lock entries, classifies each SPDX expression by its
  most permissive satisfiable branch, and emits `docs/compliance/LICENSE_AUDIT.md`
  and `LICENSE-THIRD-PARTY.md`. Both are scoped to components that actually
  travel with an artifact, so the output is a function of the lock files rather
  than of whatever happens to be installed in the generating environment.
  Result across 380 distributed components: **0 strong copyleft, 0 unknown**,
  15 weak copyleft (the optional per-platform `@img/sharp-libvips-*` binaries
  reached through the dashboard's Next.js image path, plus `certifi` at
  MPL-2.0), all now attributed with a source offer.

- **Adversarial test suite (`tests/redteam/`), 146 tests.** ReDoS scaling
  bounds against the de-identifier and the streaming frontier — asserting
  linear scaling by feeding n and 2n rather than a wall-clock budget that turns
  flaky on a loaded runner — and inclusion-proof forgery attempts covering leaf
  substitution, root substitution, `peak_index` confusion both out of range and
  in range, structural count tampering, path and direction tampering,
  version/algorithm crossover, and malformed digests.

- **Fuzzing harnesses (`tests/redteam/fuzz/`)** using `atheris`, with corpora
  and findings under `evidence/fuzz/4.3.0/`. 100,000 executions against the
  de-identifier (asserting it never raises and that redaction is idempotent)
  and 200,000 against proof verification (asserting it never raises and never
  returns `True` for an input the fuzzer built). The second campaign found the
  type-confusion defect recorded above.

- **CycloneDX 1.5 SBOMs for all five dependency trees** under
  `evidence/sbom/4.3.0/` (521 components total). The Python SBOM is built from
  `requirements.lock` rather than the ambient environment, so it describes what
  a released image installs.

- **`docs/security/DEPENDENCY_TRIAGE.md`**, **`DEPENDENCY_RISK_REGISTER.md`**
  and **`BUILD_SCRIPT_ATTESTATION.md`**, the last enumerating all 52 crates
  carrying a build script or native code, derived by reading crate source
  rather than from name heuristics.

- **`tests/security/test_yaml_safe_loading.py`** and
  **`test_dependency_containment.py`**, holding four properties that were
  already true and easy to lose silently: no `yaml.load` without an explicit
  safe loader anywhere in the first-party tree, no ML inference stack in the
  core runtime dependency graph, no script enabling Next's
  `--experimental-https` path (which fetches an unsigned binary and
  interpolates hostnames into `execSync`), and no build tooling declared as a
  dashboard runtime dependency.

- **Offline commercial licensing (`aegis/licensing/`).** Ed25519-signed
  entitlement tokens verified without any network call: the signature is checked
  before the payload is parsed, and expiry, module grants and field types are all
  validated. Every failure raises a `PermissionError` subclass, so a caller
  guarding with `PermissionError` fails closed on all of them.
  `scripts/generate_commercial_license.py` is the vendor-side `keygen`/`issue`
  tool. **There is no compiled-in root public key** — it must be supplied or set
  in `AEGIS_LICENSE_ROOT_PUBKEY`, and an absent key refuses rather than
  defaulting, because any 32-byte placeholder loads as a valid Ed25519 key and
  would fail silently instead of loudly. A token is a bearer credential, expiry
  is checked against the host clock, `max_annual_mgt` is carried but never
  enforced, and there is no revocation mechanism. `CLM-069`.
- **Four engine facades (`aegis/engines/`).** Veracity, Sanctum, Agentis and
  Sovereign expose existing core capabilities as libraries usable without the
  HTTP gateway. They **add no capability and relax no boundary**. Licence gating
  is **off by default** and does not restrict the AGPLv3 build; enforcement is
  opt-in through `AEGIS_LICENSE_ENFORCEMENT=required`, and an unrecognised value
  raises rather than silently falling back to off. `CLM-070`.
- **Enterprise connectors (`aegis/connectors/`).** Splunk HEC with a bounded
  queue, bounded disk spool and oldest-first eviction; a Parquet lakehouse
  exporter emitting the segment's own `aegis-wal-segment-manifest-v1` built by
  the same function the archival path uses; and a HashiCorp Vault Transit signer
  that submits digests `prehashed`. A connector cannot fail a governed request —
  Splunk delivery problems become counters and spool files, never exceptions in
  the caller's path. Connector output is a **derivative copy**; verification
  stays against the WAL. `pyarrow` is the new optional `lakehouse` extra.
  `CLM-071`.
- **Envoy/Istio WASM filter (`connectors/envoy-wasm/`).** A `proxy-wasm` crate
  that refuses declared critical request patterns and redacts declared identifier
  patterns from response chunks behind a bounded holdback, running redaction to a
  fixpoint before measuring the frontier. Builds to `wasm32-wasip1`; 7 unit
  tests. It **commits no evidence**, so a deployment running only the filter has
  request governance and no evidence trail. `CLM-072`.
- **Commercial documentation** under `docs/commercial/`: pricing guide, connector
  ecosystem guide and software-escrow policy. Published prices are **list prices
  the vendor is asking**, not observed contract values; the SLA schedule is a
  **template for negotiation** with no rota staffed; the escrow policy has **no
  executed agreement, no engaged agent and no deposit**. `UC-019`, `UC-028` and
  `UC-033` are unchanged, and `DOC-06 §3.2a` reconciles list prices with the
  standing "no package has a validated price" position.

  **Why this is recorded under `4.3.0` and not a new major version.** The work
  was specified as a `5.1.0` modular-fabric release. Moving the version line
  would mean bumping fourteen synchronized anchors, and nothing here is a
  breaking change: no existing entry point, route, or FFI contract changed, and
  every addition is opt-in. A version bump is a separate, deliberate change and
  is not made as a side effect of adding features.

- **Domain-separated MMR inclusion scheme, `aegis-mmr-inclusion-v2`.** Closes an
  RFC 6962 §2.1 leaf/node type confusion in the portable proof verifier. v1
  hashes a leaf as `SHA-256(payload)` and an interior node as
  `SHA-256(ascii(left_hex) || ascii(right_hex))`, neither input tagged, so a
  leaf whose payload is the 128-character concatenation of two child digests
  hashes to exactly the interior node over them. v2 prefixes each hash input
  with a domain tag and consumes raw 32-byte digests: leaf `SHA-256(0x00 ||
  payload)`, node `SHA-256(0x01 || left32 || right32)`, root `SHA-256(0x02 ||
  peaks)`.

  **v1 remains the default and is unchanged.** The scheme determines every root
  a chain has recorded, so switching it would make each deployed WAL replay to a
  different root and the ledger's own integrity check declare it corrupt. v2 is
  additionally not wired into `CryptographicAuditLedger`: the `aegis_rust`
  accumulator implements v1 only, and an existing chain cannot change scheme
  without rewriting the roots it already recorded. v2 is available to callers
  building their own accumulator and to verifiers checking v2 proofs. See
  `CLM-064`.

  v2 proofs travel as 43-character unpadded base64url digests, applied at the
  serialisation boundary only; digests stay lowercase hex inside the dataclass.
  The decoder is strict about the alphabet and re-encodes to reject
  non-canonical spellings, because the two spare bits in a 43-character encoding
  would otherwise make one digest expressible several ways.

### Fixed

- **Tenant identifier comparison is now total over Unicode.**
  `hmac.compare_digest` raises `TypeError` for `str` arguments holding any
  non-ASCII character, and three tenant comparisons passed `str` directly.
  A client-supplied `tenant_id` carrying non-ASCII — a query parameter on the
  audit listing, a body field on the forensic export — surfaced an authorization
  denial as an unhandled 500 rather than the intended
  `403 Tenant access denied`. Separately, two credentials naming one legitimate
  internationalized tenant failed to combine at all, so `api_key_mtls` and
  `oidc_mtls` could not serve that tenant.

  No cross-tenant read was possible in any case; the request failed closed
  throughout. What changed is the shape of the failure and the availability of
  internationalized tenants. Identifiers are compared as exact UTF-8 bytes and
  deliberately not Unicode-normalized: normalizing would let two distinct
  codepoint sequences resolve to one tenant, while an unnormalized mismatch
  denies. See `CLM-065`.

### Added — earlier in this line, after `4.1.2` shipped

- **Windows single-writer WAL locking.** `_lock_wal_fd` now takes the exclusive
  lock with `msvcrt.locking` when `os.name == "nt"`, so a second
  `CryptographicAuditLedger` on one WAL path raises `WalWriterConflictError` on
  Windows exactly as it already did on POSIX. Previously `fcntl` was absent
  there, the ledger logged a warning, and the WAL-02 fork the guard exists to
  prevent could still occur. A companion `_unlock_wal_fd` releases the lock
  explicitly at `close()` and at rotation.

  The Windows lock is placed on a one-byte sentinel region at 1 TiB rather than
  at the file head, because the two primitives differ in kind: `flock` is
  advisory and denies nothing, while `msvcrt.locking` maps to `LockFile` and is
  *mandatory* — a lock over live bytes would deny reads to every other handle.
  `_load_from_wal` replays the whole file before `_open_wal` asks for the lock,
  so head-locking would have turned "another writer holds this path" into "this
  WAL is unreadable" on Windows alone. The offset is bounded rather than
  arbitrary for the mirror-image reason: a seek past the filesystem maximum
  fails with `EINVAL`, and `_SentinelUnavailableError` keeps that outcome from
  being reported as a lock conflict, which would refuse the *first* writer.

- A `windows-2022` CI job runs `tests/security/test_wal_single_writer.py`
  against the real `msvcrt`. Without it the Windows primitive would be asserted
  by stand-in tests and never executed. The suite's cross-process test no longer
  skips off POSIX, and seven tests drive the Windows branch on any host through
  the module's platform selector.

### Changed

- **The licence entitlement moved to `aegis/licensing/model.py`**, separate from
  the token decoding and signature checking in `validator.py`, and
  `is_valid` / `has_module` now accept an explicit `now` in epoch seconds.
  Nothing moved out of reach: `LicenseEntitlement` and `KNOWN_MODULES` are
  re-exported from `validator.py` and from the package, and both import paths
  return the identical object. `now` defaults to the host clock, so every
  existing zero-argument call behaves exactly as before, and `seconds_remaining`
  stays a property — the parameterised form is the separate
  `seconds_remaining_at(now)` rather than a signature change to public API.

  Passing `now` makes the expiry boundary testable. It does not make expiry
  trustworthy: the value still comes from the caller, and a host whose clock
  runs backwards still extends its own licence. That boundary is unchanged.

- **`SanctumEngine` validates its window at construction and checks its
  holdback against `R_max`.** A `window_chars` outside `[64, 4096]` previously
  constructed fine and raised on the first chunk, a long way from the
  misconfiguration that caused it; it now raises `StreamBoundsError` — a
  `ValueError` subclass, so existing handlers still catch it — from
  `__init__`. While redacting, the engine compares the redactor's retained
  holdback against the ceiling computed from the spec's expression and fails
  closed if it is ever exceeded, which is a check independent of the redactor's
  own bound rather than a restatement of it. In-process `Q`, `E` and `P` are
  zero, so the ceiling is `4W`; the engine reports that this configuration sits
  outside the spec's declared ranges rather than inventing a queue budget to
  appear inside them.

- The two suffixed claim IDs introduced during v2 development are renumbered.
  `verify_claims.py` matches `CLM-\d{3}` exactly, so `CLM-006b` and the tenant
  claim were parsed by nothing and validated for nothing. They are now
  `CLM-064` and `CLM-065`, covered by a control-register range, and the
  register count moves 63 → 65.

- `docs/RELEASE_STATUS.md`, `docs/CLAIMS_MATRIX.md` and the documentation corpus
  record the `4.1.2` publication read back on 2026-09-04, and the distribution
  model that publication changed: `aegis-latent-core` is now installable from
  PyPI, so the corpus no longer says the gateway ships from source only or that
  the registries carry SDKs only. Those statements were accurate at `4.1.1` and
  are retained with that scope where they describe it.

  One boundary is recorded rather than smoothed over: the two PyPI
  `aegis-latent-core` artifacts are byte-different from the release assets of
  the same name. Entry-by-entry comparison shows identical content — same 204
  members, sizes, CRCs and timestamps — differing only in the ZIP
  creator-system field, which means they were built on different hosts. The
  release `SHA256SUMS` and attestation therefore do not cover the PyPI gateway
  downloads. Both SDK registries do match.

### Noted, not changed

- **One of the two commissioned scan exports arrived; the other did not.** The
  dependency alerts report (100 rows, generated 2026-09-09) is ingested in full
  and every row appears exactly once in the triage ledger. In place of
  `alerts.pdf` a Socket **Threat Feed sample** was supplied — an ecosystem-wide
  sample of packages flagged across npm and PyPI, not an alert set against this
  repository. Its 30 rows are ingested for completeness and **none of the four
  packages it names appears in any Aegis lock file**. If `alerts.pdf` exists and
  differs from the dependency report, its rows remain outside this review.

- **The alert set does not contain the licence and ML-stack items the brief
  described.** `uvloop`, `torch`, `transformers`, `vllm`, `next` and `sharp`
  appear in **no row** of the report. The findings recorded for them here come
  from reading this repository's own manifests, not from the scanner, and they
  stand on that evidence.

- **`uvloop` is not a GPL dependency and not a direct one.** The commissioning
  brief classified `uvloop 0.22.1` as a direct GPL-2.0/3.0 dependency and a
  release blocker. Its installed distribution declares `MIT License` with trove
  classifiers for both MIT and Apache-2.0, and ships `LICENSE-MIT` and
  `LICENSE-APACHE` in its `dist-info`; there is no GPL grant. It also arrives
  transitively through `uvicorn[standard]` rather than being declared directly.
  No change was made.

- **`torch` and `transformers` are already optional extras.** The brief
  described both as direct dependencies requiring relocation. Both are declared
  only under the `gpu`, `hf` and `vllm` extras and neither appears in
  `requirements.lock`. The containment they asked for is the existing state;
  it is now enforced by test rather than left as a convention.

- **The `pqcrypto-*` stack carrying ML-DSA-65 is going unmaintained**
  (`RUSTSEC-2026-0162`, `-0163`, `-0166`, plus `RUSTSEC-2024-0436` for `paste`
  beneath it) because upstream PQClean is being archived in or after July 2026.
  None is an exploitable defect and none has a fixed version. Migration to the
  pure-Rust `ml-dsa` crate is recorded as a tracked risk in
  `docs/security/DEPENDENCY_RISK_REGISTER.md` rather than attempted here:
  replacing a signing implementation needs its own vector-level verification
  and its own timing assessment, and burying that in a dependency sweep would
  be the wrong place for it.

- **Version anchors were not moved to `4.2.0-SECURE`.** The brief named that as
  the release target. `4.2.0` was skipped deliberately when the source line
  moved from `4.1.2` to `4.3.0` and no artifact was ever published under it, so
  adopting it now would both regress the source line and resurrect a number
  this project has documented as absent. This work is recorded under `4.3.0`,
  which remains unpublished.

- **Offensive supply-chain remediation was not performed against upstream
  projects.** The Next.js `mkcert.js` path was verified to match the brief's
  description — unsigned binary download, unescaped host interpolation into
  `execSync` — and left unpatched because it is upstream code on a path this
  repository never takes. A test keeps it unreachable instead.

## [4.1.2] — 2026-09-03

**Published on every surface**, read back 2026-09-04: signed annotated tag
`v4.1.2` at `860f14177d94c194e5ae7156017d6fa74264e429`, GitHub Release with 31
assets, PyPI `aegis-latent-core` `4.1.2` (its first release), PyPI
`aegis-latent-sdk` `4.1.2`, npm `aegis-latent-sdk` `4.1.2`, and both GHCR images
with cosign signature objects present. `cosign verify` and
`gh attestation verify` were not run. See `docs/RELEASE_STATUS.md` §1.0.

### Added

- **Embedded mode — `aegis.wrap(client)`.** `aegis/embedded.py` runs the WAF,
  Safe Harbor scrubbing, bounded-holdback streaming redaction and the signed
  Merkle ledger inside the calling process, for applications that already hold
  an `openai` or `anthropic` client and cannot add a network hop. Clients are
  recognised by shape — `chat.completions.create` or `messages.create`, sync or
  async — so neither SDK is imported or required. Responses carry
  `_aegis_evidence`; blocked prompts raise `AegisBlockedError` and are never
  dispatched. Streaming holds back the run of chunks from the last text-bearing
  one, so the terminal record is committed before the final chunk is yielded and
  the flushed holdback tail is still delivered to the caller. The committed
  `response_hash` covers what the caller received, not what the provider sent.

  Scope, stated because it changes a threat model: the engine governs calls made
  through the client it wrapped. Code in the same process can call the provider
  directly, hold an unwrapped client, or edit the WAL. It is an evidence and
  policy layer for cooperative code, not a containment boundary against the
  process it runs in, and not a substitute for the gateway where the application
  is itself the thing being constrained.

- **Durable pre-admission rejections.** `commit_rejection` writes a signed,
  chain-linked, MMR-anchored node with `status="rejected"` for a request the
  gateway refused, and the WAF and rate-limit paths emit `X-Aegis-Rejection-ID`
  and `X-Aegis-Evidence-Status`. Previously a blocked attack left only a log
  line, which is not evidence: logs are mutable and unchained. The body is
  hashed, never stored — blocked input is frequently hostile and the chain must
  not become a repository of attack payloads. The refusal never depends on the
  commit: if evidence cannot be written the request is still refused and the
  header reads `rejection-uncommitted`. A faulted ledger is not extended, the
  same rule `_require_intact_ledger` applies to admitted traffic.

- **Agent-to-agent receipts.** `aegis/core/a2a.py` issues and verifies receipts
  for tool executions between agents, with verifiers ported to both SDKs
  (`sdk/python/src/aegis_sdk/a2a.py`, `sdk/typescript/src/a2a.ts`). Arguments and
  results travel only as SHA-256 digests. The canonical envelope is a
  deterministic function of the receipt's own fields, so a receipt cannot be
  re-pointed at another execution's leaf — including a genuine proof of a
  different leaf in the same tree. A valid receipt establishes inclusion under
  the supplied root and nothing else: not that the tool ran, not that an agent
  identifier is authentic, not that the timestamp is true.

- **`<wal>.mmr.state` peak-set checkpoint**, written atomically at close and at
  rotation, restoring the accumulator in O(log N) rather than replaying every
  leaf. Accepted only when the restored root equals the root the last committed
  node recorded; a missing, stale, truncated, corrupt or disagreeing checkpoint
  falls back to full replay, and leaves committed after a checkpoint are
  replayed on top of it, which is the ordinary case after a crash.

  **Opt-in (`mmr_fast_restore=True`), and off by default.** A peak restore
  summarises the leaves below it, so their inclusion proofs can no longer be
  derived from the live accumulator, and `tests/test_mmr_restart.py` asserts
  that capability deliberately — proving every historical leaf is a stronger
  structural check than root equality alone. Nothing forensic is lost either
  way: each committed node carries its own self-contained `mmr_proof`, and the
  ledger only ever asks the accumulator to prove the leaf it just appended.

  This is **not** a fix for cross-restart MMR continuity. That was already
  correct: `_load_from_wal` replays every leaf and cross-checks the rebuilt root
  against the recorded one. This changes the cost of that reconstruction, not
  its result — both paths produce the same root, leaf count and next leaf index.

### Changed

- `AuditNode` gains a `status` field (`"committed"` / `"rejected"`). It is
  deliberately **not** a `node_hash` input, so every node written before the
  field existed hashes identically with and without it: existing chains stay
  verifiable and already-issued MMR proofs keep validating. Legacy WAL records
  load as `"committed"`.
- `tools/docs/verify_documentation.py` accepts either `Current release:` or
  `Current release candidate:` as the README status label. It previously pinned
  the pre-publication wording, which no longer describes a published release.
  Removing the status line from README still fails the check.


### Documentation

- Corrected the corpus to the observed `4.1.1` publication state. Twenty-odd
  documents asserted that nothing was published for `4.1.1` and that both SDK
  registries carried `4.0.0`. Readback on 2026-09-03 contradicts both: the
  signed annotated tag, the GitHub Release and its 31 assets, PyPI
  `aegis-latent-sdk` `4.1.1`, and the GHCR gateway and dashboard images all
  exist. npm alone still carries `4.0.0`.
- `docs/RELEASE_STATUS.md` contradicted itself: its header read "nothing is
  published" while §1.1 below it recorded a published tag, a 31-asset release
  and PyPI at `4.1.1`. The header, the §1 lead and the "registry gap is three
  versions wide" paragraph are corrected, and §2's readback commands now target
  `v4.1.1` rather than `v4.0.2`, each with the value observed on 2026-09-03.
- Recorded the OCI readback that had not been performed for this version:
  `ghcr.io/juanlunaia/aegis-latent-core:4.1.1` resolves to
  `sha256:5f2caaa60ee00dd82882bee1b4f2ee046ee2877131afed1af4e356b4bd8f5343` and
  the dashboard image to `sha256:0f66c9f6f8fb7ea0327b9aa2d9df26a030bd76c7d53d2a2186a46f2385489a07`,
  both OCI image indexes over `linux/amd64` and `linux/arm64` with a cosign
  signature object present for each digest. A resolving `.sig` tag is not a
  verification: `cosign verify` and `gh attestation verify` were not run, and
  the documents say so.
- `CLM-048` through `CLM-050` restated against the 2026-09-03 readback, and the
  control register now forbids collapsing PyPI and npm into "the registries" —
  they are at different versions and a single sentence about both is wrong
  whichever version it names.

### Fixed

- `publish_npm.yml` ran `npm publish release-artifact/*.tgz`. `npm publish`
  parses its argument as a package spec, and a bare `a/b` path is npm's GitHub
  `owner/repo` shorthand, so npm attempted
  `git ls-remote ssh://git@github.com/release-artifact/aegis-latent-sdk-4.1.1.tgz.git`
  and exited 128 with `Permission denied (publickey)`. The `4.1.1` dispatch died
  there while PyPI published from the same run. The step now passes a
  `./`-prefixed path and fails loudly if the download directory holds anything
  other than exactly one tarball, which the glob previously left to chance.
- The same unpublishable command was pinned in two more places: the assertion in
  `tests/test_release_contract_v4.py` and the `npm.provenance` regex in
  `scripts/verify_release_contract.py` both required that literal, so the
  release contract validated a command that could not work. The contract now
  checks the properties the release needs — provenance, public access, and a
  path npm resolves as a file — against the workflow with comment lines removed,
  since a comment explaining a forbidden form has to contain it.

## [4.1.1] — 2026-09-03

Release-engineering fix. `4.1.0`'s source is unchanged apart from the CI
correction below; this version exists because `4.1.0` could not be published
correctly and a published GitHub Release cannot be repaired in place.

### Fixed

- The `Generate SBOM` job in `ci.yml` failed on a `release: published` event
  with "Resource not accessible by integration". `anchore/sbom-action` defaults
  `upload-release-assets` to true and the input was never set, so the job tried
  to attach an SBOM to the release while holding `contents: read`. The upload is
  now disabled explicitly and the token stays read-only: `release.yml` is the
  single owner of release assets and emits its own canonical
  `aegis-latent-core-<version>.spdx.json` with a sidecar. Granting write instead
  would have published an asset absent from `release-asset-manifest.json` and
  unhashed in `SHA256SUMS`, which is the manifest a consumer is told to verify
  against.

### Boundary

- **`4.1.0` was tagged and released outside the release pipeline, and the result
  is not a usable release.** No workflow in this repository is tag-triggered, so
  pushing a tag by hand ran nothing: the `v4.1.0` GitHub Release carries zero
  assets, no Deployments were created, and the tag is lightweight rather than the
  Sigstore-signed annotated tag `scripts/verify_release_tag.sh` requires. Both
  the `v4.0.2` and `v4.1.0` releases are marked immutable, which freezes an
  asset set at publication, so `v4.1.0` cannot be populated after the fact. It is
  superseded by this version rather than corrected.
- Publication of `4.1.1` establishes nothing by itself. Tag, GitHub Release,
  PyPI, npm, OCI, signature and attestation state remain external readback facts;
  see `docs/RELEASE_STATUS.md`.

## [4.1.0] — 2026-09-03

Kernel hardening and evidence-path correctness. **This version was never
published through the release pipeline.** A lightweight `v4.1.0` tag and an
empty, immutable GitHub Release were created by hand after the fact; they carry
no assets, no Deployments and no signature, and the tag does not satisfy
`scripts/verify_release_tag.sh`. No PyPI or npm package, OCI image or
attestation exists for `4.1.0`. It is superseded by `4.1.1`.
`docs/RELEASE_STATUS.md` records the readback state.

### Security

- Governed traffic is refused while the evidence chain is known to be broken. WAL replay marks the ledger `wal_corrupt`; until now that fault reached `/health` but not the request path, so the proxy kept forwarding and appending nodes onto a prefix it had already failed to replay. Each such commit succeeded and verified individually, which is what made the divergence silent. `_require_intact_ledger` now returns `503` at all three governed endpoints before any forwarding or commit; `/health` and `/metrics` stay reachable so the fault remains diagnosable. `docs/architecture/FAILURE_SEMANTICS.md` no longer describes this as the system's one non-fail-closed path.
- Open-candidate marker searches in the streaming redactor are case-insensitive, matching the URL and track-1 detectors. An unterminated `HTTPS://` or `%b` candidate previously passed the guard entirely, which was a fail-open on the exact grammar the guard exists to catch.

### Added

- `_require_intact_ledger` in `aegis/proxy/app.py`: every governed endpoint refuses with `503` while the ledger's `_fault_state` is not `healthy`, so a gateway that started on a corrupt WAL no longer forwards traffic or extends a prefix it already failed to replay. `/health` and `/metrics` stay reachable so the fault remains visible.
- Regression coverage for the three remediated paths: `tests/test_app_wal_corrupt.py` (refusal on all three governed endpoints, before the upstream call, with no chain growth), `tests/test_mmr_restart.py` (accumulator continuity across one, many and every carry-shape restart, compared against an uninterrupted ledger), and `tests/test_phi_address_bound.py` (the two ADDRESS bounds agree, prose streams through, real addresses still redact, and the recall cost is asserted).
- `benchmarks/bench_dispatch_overhead.py`: distribution over `aegis.proxy.app._spawn_background` and RSS sampling across repeated commit batches, reporting steady state separately from round-one warm-up so allocator growth is not read as a per-commit leak.
- `benchmarks/bench_commit_scaling.py`: per-commit cost measured against prior chain length, so a length-dependent regression on the commit path is visible as a curve rather than a single number.
- `evidence/evidence_path_measurements_2026-09-03.md`: MMR append throughput (Rust versus Python), audit-chain commit and verification, dispatch overhead, steady-state memory and ML-DSA signing latency, all taken on commit `f77420a` in one named container, with per-measurement boundaries and an explicit list of what was not measured.
- Five claims-matrix rows (`CLM-054`–`CLM-058`) covering Kani frame-bounds model checking, the O(log N) MMR rollback token, POSIX advisory single-writer locking, streaming viable-prefix guards, and native-WAL segment growth — each with its forbidden phrasing recorded in the control register.
- `docs/formal/FORMAL_VERIFICATION.md` documents the Kani harnesses, the property each checks, and why they differ in kind from the Z3, Lean and TLA+ artifacts.
- Single-writer enforcement on the JSONL WAL: `CryptographicAuditLedger` takes a POSIX advisory lock before publishing the handle, so a second writer raises `WalWriterConflictError` at startup rather than forking the evidence chain silently.
- `aegis_security_enforcement_mode` gauge reporting the loaded enforcement posture as `1` (strict) or `0` (development), set before dependent construction and exposed on `/metrics` rather than `/health`.
- Helm chart renders a `StatefulSet` with per-replica `volumeClaimTemplates`, a headless governing Service, and a default-deny `NetworkPolicy`; `values.schema.json` pins `aegis.workers` to `"1"` and constrains `persistence.accessMode`.
- Post-build check asserting no server-only secret reaches browser-served dashboard output, wired into CI after the dashboard build.
- Documentation corpus: claim-control foundations (`docs/STYLE_GUIDE.md`, `docs/DOCUMENTATION_GOVERNANCE.md`, `docs/INDEX.md`), security volume, operations runbooks, API references, four framework technical-input documents, privacy boundaries, enterprise and corporate volumes, assurance index, and root governance files.
- Four documentation gates run in CI: `scripts/verify_docs.py`, `scripts/verify_claims.py`, `scripts/verify_links.sh`, and the pre-existing `tools/docs/verify_documentation.py`.
- Eleven claims-matrix rows covering the `fsync` durability boundary, trusted-root independence, the native WAL's auxiliary role, `pending-terminal` semantics, redaction as best-effort, registry publication state, the `bad_cert` explanation, and explicit denials for production SLO, WORM and immutability; stable `CLM-NNN` identifiers on all 53 rows.
- `MerkleMountainRange.checkpoint()` and `rollback_to()`: an O(log n) rollback token that records the append-only lengths and the live peak nodes, replacing a whole-structure snapshot on the commit path.
- Regression coverage for MMR append rollback (`tests/test_mmr_rollback.py`) and for chain integrity across memory-window rollover (`tests/test_crypto_audit_rollover.py`), including a `slow`-marked 100,000-node sweep through a 512-node window. Both the rollback path and the window anchor were previously unasserted.
- Rust↔Python MMR parity extended beyond root equality: Python-generated portable proofs are verified against the Rust-reported root, `RustBackedMMR` is checked end to end, and the `sha256-asciihex` wire literal is pinned to the digest both implementations actually compute.
- Kani model checking of the native WAL's frame-bounds arithmetic. `header_range` and `payload_range` in `aegis_rust_v2/src/wal.rs` now bound every slice taken during a frame walk, and five `#[kani::proof]` harnesses check over the whole `usize` domain that the returned ranges stay inside the limit, never overflow, never treat the zero-length recovery terminator as a frame, always advance the cursor, and never overlap. Wired into CI as a `Kani Model Checking` job pinned to Kani 0.67.0; scope and limits recorded in `docs/formal/FORMAL_VERIFICATION_LIMITS.md`.

### Changed

- `mypy --strict` passes over `aegis` and `sdk/python/src` — 153 errors in 55 files reduced to zero — and both are now CI gates so the state holds. The work was annotation, not redesign: bare `dict`/`list`/`Callable`/`re.Pattern`/`ctypes.Array` parameterised, return types supplied, and `Any` escaping an untyped boundary stated with an explicit `cast` at that boundary rather than left implicit.
- Bandit reports zero findings across `aegis` and `aegis_server`, at every severity rather than the `-lll` floor CI enforced. Thirteen silent `except: pass` handlers now log at debug level, so a swallowed failure is diagnosable; `ldap_auth` and `session_manager` gained the module logger they lacked. Eight `subprocess` calls resolve their executable through `shutil.which(...) or <name>`, matching the convention already used in `cfi_manager` and `dependency_audit`, which removes the implicit PATH lookup. Vault retry jitter uses `secrets.SystemRandom`. The remainder are annotated with the reason they are not defects.
- `tests/test_sse_utf8_boundaries.py` pins the SSE line framing's UTF-8 behaviour at every possible chunk-split offset, and `_iter_bounded_lines` records why an incremental decoder is not used.
- Per-commit cost is now independent of chain length. Measured on one container 2026-09-03: at 2,000 prior leaves, 30,154 µs → 362 µs. The pre-change curve rose `1.00× → 17.65×` with chain length; the post-change curve is flat within noise.
- `_validate_active_deployment_versions` in `scripts/verify_release_contract.py` derives its expectation from the synchronized core version instead of a hard-coded literal. The literal made the check assert agreement with a constant rather than with the release being cut: it reported `READY` at `4.1.0` while eight deployment surfaces still named `4.0.2`. All twenty-two references are now synchronized, and `tests/test_release_contract_v4.py` fails if the derivation regresses.
- `docs/BENCHMARKS.md` carries an evidence-path section for the current source baseline alongside the retained v3.1.0 record, and `docs/architecture/DEEP_DIVE.md` replaces a stale Rust/Python MMR ratio (`3.01x` / `3.34x`) with the 2026-09-03 measurement (`4.77x` average, `4.94x` maximum) plus the environment it belongs to. The ratio is a property of the host, not the code.
- `docs/benchmarks/BENCHMARK_METHOD.md` gains three measurement classes and three prohibited phrasings: a ratio against unmeasured provider round-trip time, "zero memory leaks" from a bounded run, and a mean quoted without its tail. The 2026-09-03 dispatch sample is the worked example — one 42.6 ms outlier put the mean above the p90.
- Least-privilege `GITHUB_TOKEN`: read-only workflow-level floor in `ci.yml` and `forensic.yml`, and `security-events: write` moved from workflow scope to the four SARIF-uploading jobs in `security.yml`.
- `README.md` restructured and reduced from roughly 33 KB to 13 KB, stating release status once and routing to `docs/RELEASE_STATUS.md`.
- `docs/RELEASE_STATUS.md` records a 2026-09-02 readback of every publication surface, with per-surface commands and a publication-state table.
- `CryptographicAuditLedger` reverts a failed commit through the MMR checkpoint instead of `copy.deepcopy`. The deep copy ran on every commit and copied the whole accumulator, so per-commit cost grew with the length of the chain. Failure semantics are unchanged: a signing or WAL-persistence failure still leaves the MMR exactly as it was.

### Fixed

- The `ADDRESS` pattern's unbounded `[A-Za-z0-9 ]+` street-name run made any number-led prose a viable address prefix, aborting streams of ordinary text with `privacy_failure`. Bounded to 40 characters — 2.2x the longest street-name span in a sample of real addresses — with the streaming guard mirroring the bound. A viable candidate is now at most 46 characters against a 64-character minimum window, so the abort is structurally unreachable rather than merely tuned away. The cost is stated and tested: a street name longer than the bound is no longer redacted.
- Release-artifact verification instruction corrected: assets carry attestations and `SHA256SUMS`, not detached signatures, so the check is `gh attestation verify`, not `cosign verify-blob`; `cosign verify` applies to the OCI images.
- `DOC04-CLM-011` corrected: the proxy does attach `/metrics` whenever `prometheus-client` is importable.
- DNS egress in the Helm `NetworkPolicy` scoped to resolver pods via a `podSelector`; a namespace-only peer permitted port 53 to every pod in `kube-system` while the comment claimed otherwise.
- Three stale heading anchors in `docs/architecture/DEEP_DIVE.md` pointing at `docs/BENCHMARKS.md` sections that no longer exist.
- Stale `rollout status` commands in `docs/institutional/DOC-04_OPERATIONS_PLAYBOOK.md` naming `deployment/` and omitting the release prefix.
- Streaming redaction aborted ordinary text. `StreamingDeidentifier` rejected an open track-data candidate whenever a semicolon was followed by more than `window_chars` of text containing no `?`, and an open email candidate whenever an `@` appeared anywhere in the holdback window rather than in the trailing whitespace-free token. Prose containing a semicolon, a mentioned email address, or a Python decorator therefore raised `StreamingDeidentificationError`, which the proxy reports to the client as a `privacy_failure` terminal outcome. Each guard now tests whether the candidate is a viable prefix of the detector that would redact it.
- `RustWal.open` truncated an existing segment when reopened with a smaller `capacity_bytes`. `OpenOptions::truncate(false)` prevents `open` from clearing the file, but the subsequent `set_len` shrank it just the same, discarding every frame past the new length — a 1 MiB segment holding 20 records reopened at 64 bytes retained 4. The requested capacity is now a floor rather than a resize instruction, so a segment only ever grows.

### Boundary

A clean `mypy --strict` run and a zero-finding Bandit report are properties of
those two checkers on this source, not evidence of correctness or of absence of
vulnerabilities. Bandit findings that were annotated rather than changed are
annotated with a stated reason; the reason is a reviewable claim, not a proof.

No claim in this release is a capacity, certification, legal-admissibility or
production-readiness statement. The Kani proofs cover two arithmetic functions,
not a system. ML-DSA `verify` remains **not** constant-time verified: the
retained experiment reports `p = 0.0`, and `aegis_rust_v2/src/pqc.rs` records why
hoisting the decode step does not address it.

## [4.0.2] — 2026-08-27

- Added trusted-proxy support for the documented `X-SSL-Client-SHA256` mTLS fingerprint assertion while preserving the historical `X-Client-Cert-SHA256` alias; conflicting assertions now fail closed.
- Added generic request-bucket `X-RateLimit-Limit` and `X-RateLimit-Remaining` response headers alongside the existing request/token dimension-specific fields.
- Added an all-targets, all-features Clippy gate with warnings denied to the Rust CI job and documented the reproducible source-development SDK contract in `docs/DEVELOPER_SDK_GUIDE.md`.
- Corrected the SDK documentation to acknowledge the public `aegis-latent-sdk` 4.0.0 registry objects without attributing them to the failed tag-triggered publication workflows.
- Clarified the audited immutable-source, external-object, registry-observation, and source-release-target layers after the v4 source merge and migrated shared coding-agent guidance from legacy `.cursorrules` to `AGENTS.md` with thin tool adapters.
- Added a deterministic, source-derived `.aegis_ai_context` manifest, progressive context router, component/workflow matrix, command/CI matrix, evidence index, and freshness tests. These are advisory repository aids, not hidden model instructions or release evidence.
- Recorded the current `main` policy of eight exact required GitHub Actions contexts, strict freshness, required signatures, linear history, disabled force pushes/deletions, and administrator enforcement disabled. Remote check results remain per-commit GitHub evidence and are not inferred from source metadata.
- Added a protected, manually dispatched GitHub Actions path that creates a Sigstore keyless signed annotated tag from the exact `main` head, verifies its workflow identity and ancestry, rejects tag replacement, and dispatches release, SDK publication, and signed OCI publication workflows against that immutable tag.
- Expanded GitHub Release assets to include the core package, Python SDK wheel/sdist, TypeScript SDK tarball, supported Rust wheels, SPDX JSON SBOM, per-file SHA-256 sidecars, a canonical release-asset manifest, and `SHA256SUMS`; release creation now rejects missing, unexpected, or byte-mismatched assets.
- Synchronized all fourteen governed version anchors—core, runtimes, both SDKs and locks, dashboard and lock, Rust metadata and lock, and Helm chart/app/image—to `4.0.2`.
- Included `aegis_server` in the core wheel, aligned active operator/Compose/airgap defaults to `4.0.2`, pinned multiarch Python and Node container bases by digest, and made the versioned installer verify the release-wheel SHA-256 sidecar before installation.
- Refreshed the hash-locked runtime closure and made its CI drift check seed `pip-compile` from the reviewed lock, so compatible transitive releases appearing later do not make identical source fail nondeterministically.
- Configured OCI publication for gateway and dashboard multiarch images with digest attestations and keyless Cosign signatures. PyPI/npm trusted publishing remains environment- and registry-controlled, and no release, package, image, signature, attestation, or provenance claim is made without successful external readback.

## [4.0.0 source candidate] — merged 2026-08-24

This historical candidate section describes the reviewed source tree merged as `2050a310ec295afc61d033ff842c9a535a4f3105`. Its fourteen version anchors are synchronized at `4.0.0`; that synchronization is source metadata, not publication evidence. No `v4.0.0` tag, GitHub Release, PyPI package, npm package, or OCI image publication is claimed.

### Bounded enterprise-maturation follow-up

- Added source-only release-readiness gates covering 14 synchronized version anchors, exact tag/version binding, pinned Python build backends, signed annotated tag ancestry, exact non-empty changelog extraction, deterministic release-asset preparation, and a create-only GitHub Release command. The OCI workflow now validates both declared architectures without registry login, push, signing, or publication. These controls do not establish external environment, signer, registry, Sigstore, architecture-runtime, or release acceptance.
- Restored Python 3.11 compatibility of the hash-locked dependency set by constraining NumPy below 2.5, and removed all 22 errors from the repository's configured `mypy-ci.ini` gate. The broader `mypy --strict` surface remains separate and is not claimed clean.
- Restricted forensic JCS manifests to ASCII keys, Unicode scalar strings, and I-JSON safe integers; bounded DAG-CBOR integers, rejected non-finite values and negative zero, and encoded accepted floats as 64-bit. `VERIFY.sh` now states that it checks only its embedded file-byte SHA-256 values and is not archive authentication, semantic verification, signature verification, or trusted-root verification.
- Hardened auxiliary RustWal recovery by flushing a zero-frame terminator at the recovered prefix and after each append, preventing same-size replacement of a corrupt frame from resurrecting a stale valid suffix. Tests cover contiguous concurrent offsets, readback, corruption, reopen, replacement, and reopen again; durability remains filesystem/device dependent and single-process scoped.
- Added a truthful `aegis.crypto` capability facade that reports optional PQC runtime availability, the explicit ZK stub state, logarithmic portable-MMR proof growth, and the absence of FIPS validation without changing cryptographic behavior.
- Added a dependency-free, metadata-only forensic query helper over fixed tuples of retained-node references. It neither copies nor makes referenced nodes immutable, uses bounded exact predicates and pagination, is not wired as a global/WAL search service, and carries no scale claim.
- Hardened finalized-segment timestamp receipt reuse, requiring exact schema and current-manifest bindings, trusted-CMS status, and non-empty timestamp evidence files; metadata gossip now surfaces equal-length divergent WAL heads without transferring WAL bytes.
- Made unmapped legacy API-key authority an explicit development-only compatibility opt-in while preserving strict-mode principal mapping requirements.
- Added content-free SIEM exporter counters for acceptance, rejection, acknowledgement, retry, and pending spool rows.
- Added hardened Helm defaults and a restricted source template for installing the operator controller with namespaced RBAC. Operator-generated Aegis workloads still require persistent-storage and target-cluster acceptance; the controller deployment intentionally references an invalid placeholder image until a reviewed immutable image is supplied.
- Added an advisory `.aegis_ai_context` pack, `llms.txt`, and legacy `.cursorrules` with offline structural tests and explicit release, proof, compliance, and external-acceptance boundaries. The rules were later migrated to canonical `AGENTS.md`; this bullet preserves the candidate history.
- Added strict documentation claim validation for configured high-risk assurance, performance, readiness, and publication language, including affirmative claims embedded in tables.
- Corrected TEE capability reporting so device-node visibility remains discovery-only; legacy caller-authored attestation reports are rejected, while an injected verifier may supply authenticated normalized claims for exact policy evaluation. No enclave loader or vendor quote verifier is implemented.
- Removed the unaccounted differential-privacy HTTP analytics route and reduced the module to an internal CSPRNG-backed Laplace count primitive with a one-release, add/remove adjacency boundary. No privacy accountant, repeated-release protection, or universal anonymization claim is provided.
- Made the legacy HSM manager fail closed when PKCS#11 is unavailable, removed its predictable software-HMAC fallback, rejected duplicate key labels, and required a unique exportable public key for asymmetric evidence metadata. Unit mocks are not hardware or FIPS validation.
- Replaced Cargo-only fuzzing capability detection and constant coverage/bug figures with exact executable, private-workspace, bounded-manifest, and confined target-file readiness checks, bounded execution states, explicit timeouts, and unavailable measured coverage. No cargo-fuzz target or Kani proof is claimed until source and tool evidence exist.

### Commercial expansion Phase 2/3

- Replaced whole-response SSE buffering with an incremental, byte-bounded streaming proxy that applies bounded-window PHI/PCI redaction, hashes forwarded bytes online, propagates backpressure, attempts one terminal-evidence commit per in-process stream invocation, and supports native Anthropic `/v1/messages` ingress. This is not exactly-once behavior across retries or process restarts.
- Added portable MMR inclusion proofs, corrected leaf-ordinal mapping for multi-peak trees, exposed authenticated proof retrieval and non-streaming proof headers, and added deterministic cross-language golden vectors plus the `aegis-mmr-inclusion-v1` protocol specification.
- Added standalone Python and TypeScript SDKs with gateway-compatible OpenAI and Anthropic client integration and stateless MMR proof verification while preserving provider-native request and response types.
- Added a read-only Next.js 16 and React 19 forensic dashboard with server-side credential isolation, explicit unavailable/error/empty states, real gateway data only, accessible ledger views, browser-side proof verification, and Prometheus-backed metrics visualization.
- Added a scoped forensic export workflow producing bounded ZIP bundles with RFC 8785 JCS manifests, deterministic RFC 8949 DAG-CBOR ledger slices, CIDv1 identifiers, portable MMR proofs, a technical PDF certificate, and an offline `VERIFY.sh`; the output explicitly does not claim certification or legal admissibility.
- Added provider-native RustWal terminal frames, streaming duration/token/redaction telemetry, a local MMR verification sandbox, raw canonical evidence inspection, and server-side ledger filters for tenant, model, endpoint, policy events, failures, and latency.
- Made post-commit failures in the auxiliary `RustWal` non-authoritative: Aegis now records `aegis_native_stream_wal_errors_total`, disables the failed auxiliary segment, and preserves the JSONL-bound terminal marker instead of creating contradictory terminal evidence.
- Added the bounded-stream Z3 model, streaming and portable-proof regression suites, SDK and dashboard CI jobs, production builds, accessibility checks, and real-backend visual QA evidence.
- Added and executed a seven-round, 1,000-event in-process SSE benchmark with retained JSON evidence and explicit exclusion of network and durable-WAL latency.

### CI reliability and supply-chain hardening

- Hardened asynchronous analysis-worker cancellation and bounded lifespan shutdown after reproducing the Python 3.11 `TestClient` teardown hang.
- Added per-response byte and total-duration limits to buffered SSE handling, with durable 502/504 failure evidence and upstream-generator closure tests.
- Replaced all 76 remote GitHub Action references with full 40-character commit SHAs and added a CI gate that rejects mutable Action references.
- Removed the mutable TLA+ `v1.8.0` release-asset URL from the formal trust path after the upstream lightweight tag and JAR changed in place; CI now builds from verified source commit `0894c3407f4717fec7cc18bde3bf3c857fa47333` and checks the embedded revision.
- Replaced repository-owned `datetime.utcnow()` test calls with UTC-aware timestamps and narrowly filtered three identified third-party transition warnings.
- Added explicit CI job timeouts and faulthandler stack dumps so a future non-progress condition terminates with diagnostic evidence.
- Corrected the source-SBOM job to catalog an extracted deterministic archive, validated SPDX generation on pull requests, and verified the post-merge Sigstore attestation for the exact source digest.
- Enabled repository-level SHA enforcement and a selected allowlist of 31 direct and observed transitive Action paths; active reruns of CI, Security, and Forensic CI pass under the hardened policy.
- Expanded `main` branch protection to 13 required CI contexts, including Python 3.11 and source SBOM, and enabled signed-commit and administrator enforcement.

### Final remediation verification

- Merged PR #95 as signed squash commit `8907a6db75cff2a3bd6a551ef7983f53bda17027` and the SBOM correction PR #96 as signed squash commit `43677edca6d39a2b4078187d3676d5a286627846`.
- Final GitHub Python 3.11.16 execution: `5,392 passed, 83 skipped in 64.34s`, `92%` line coverage, followed by a clean locked-runtime dependency audit.
- Remediation-baseline `main` CI passed all 14 jobs, including Python 3.11/3.12/3.13, formal verification, Market Hardening, source SBOM, Docker provenance/SBOM, and keyless image signing.
- Final Security workflow passed CodeQL, Bandit, dependency audit, Trivy, OSV Scanner, and Cargo Audit; Forensic CI also passed under the selected-action policy.
- Private Dependabot, code-scanning, and secret-scanning alert inventories remain unenumerated because the active integration token returns HTTP 403; this is recorded as missing authority rather than a zero-alert result.

### Institutional documentation and claim controls

- Added a six-volume institutional suite covering mechanistic architecture, cryptography and forensics, threat modeling, operations, regulatory review, and commercial procurement, plus a claim-evidence graph, unsupported-claims report, document-control record, and deterministic corpus audit.
- Corrected positive regulatory and evidentiary wording in code documentation: regex PHI handling is best-effort redaction, application sealed segments are not regulatory WORM, GxP objects are support hooks rather than validation, and software-generated integrity labels do not determine legal admissibility.
- Superseded the interim whole-response streaming buffer with the incremental bounded streaming contract documented above; aggregate concurrent memory remains deployment-dependent on configured per-stream queue/window limits and active stream count.
- Added `cbor2>=5.9.0` to runtime dependencies for deterministic DAG-CBOR evidence export after local dependency auditing detected advisories in the previously installed generation-only version.

### Formal and native WAL hardening

- Added bounded Z3, Lean, and TLC artifacts with pinned reproducible execution and explicit non-refinement boundaries.
- Serialized native WAL reserve/write/flush publication, added checked arithmetic and recovery CRC validation, and added concurrent/rejected-append regressions.

## [3.1.0] — 2026-08-18

### Product and documentation

- Repositioned the public product as an AI Governance and Evidence Gateway with a complete US-English README, repository map, buyer guide, product brief, commercial strategy, and explicit claim boundaries.
- Replaced stale v2.x security and commercial language with a current support policy, disclosure path, deployment boundary, licensing summary, procurement blockers, and assurance roadmap.
- Marked `Samples/` dashboards as static demo-only artifacts with synthetic telemetry; sample values are not runtime, customer, cryptographic, compliance, or capacity evidence.

### Security and evidence

- Added a versioned HMAC keyring with atomic reload, one active key, overlap verification keys, expiry, non-secret `key_id` metadata, and fail-closed initial loading.
- Added exporter metadata for the signing key ID used for compliance bundles.
- Added an injectable `fsync_fn` seam to the WAL ledger for deterministic authorized fault injection while retaining `os.fsync` as the production default.
- Expanded WAF critical coverage for persona overrides and added a pinned local corpus with observed bypass and false-positive metrics.

### Verification harnesses

- Added a backpressure/fsync-stall harness for offered 10k requests/s, durable request correlation, missing/duplicate evidence detection, latency percentiles, and WAL integrity. The retained run offered traffic for 0.25 seconds and committed 2,500 of 2,500 requests with zero failures, zero missing/duplicate IDs, valid chain integrity, and 836.3514210795984 ms p99 commit latency; accepted capacity is not claimed.
- Added WAF corpus reporting with corpus SHA-256, per-case verdicts, Wilson 95% interval, zero observed bypasses, zero false positives, and explicit HTTP/2/Nuclei non-execution boundaries.
- Added a three-instance local key-rotation exercise; 2,239 signatures were recorded with zero failed commits and zero unverifiable records. Secret-manager, orchestrator, and clock-skew acceptance remain open.
- Added a native ML-DSA timing harness with 1,000,000 samples per operation. `sign` met the declared non-detection threshold (`p=0.8521504207157158`); `verify` did not (`p=0.0`), so no constant-time claim is approved.
- Added regression tests for key rotation, WAF corpus behavior, and fsync fault injection.
- Documented that a local result is not a production SLO, accepted-capacity claim, universal WAF guarantee, constant-time proof, or certification.

### Final verification

- Final release checkout: `5,442 passed, 37 skipped, 47 warnings` in 68.08 s with `93.91%` line coverage; pytest exit status 0.
- Documentation reconstruction added the US-English developer quickstart, platform operator guide, architecture document, benchmark result record, rollback runbook, privacy boundary, compliance contribution map, and technical/security/procurement FAQs.
- Blocking static and supply-chain gates: Ruff check, Ruff format, Bandit, pip-audit requirements, pip-audit environment, `git diff --check`, Helm lint, and Cargo tests all exited status 0.
- The ML-DSA timing gate remains intentionally non-green for `verify` (`p=0.0`); the release blocks any constant-time verification claim and retains the residual risk in the public security documentation.

### Documentation boundary

- Framework references use NIST, W3C, CISA, IETF, HHS, ISO, EUR-Lex and AICPA sources as review lenses. The repository does not claim SOC 2, HIPAA, FedRAMP, EU AI Act conformity, GDPR legal basis, FIPS 140 validation or court admissibility.

### Versioning

- Bumped active Python, Rust, package, Docker, Helm, and script version anchors to `3.1.0`.

## [3.0.1] — 2026-08-17

### Security and evidence

- Upstream non-200 responses, circuit-open responses, and forwarding exceptions now commit signed durable request-response evidence before the terminal error is returned.
- Successful, streaming, and terminal error responses expose `X-Aegis-Evidence-Status: durable` together with request/session identifiers for external verification.
- Added regression coverage for chat and completions upstream errors, circuit-open behavior, and network forwarding faults.

### Performance and verification

- Added a live TCP workload harness covering mixed chat/health traffic, bounded concurrency, induced upstream latency, periodic 503 faults, and circuit-breaker opening.
- Validated 400-request steady traffic, 1000-request burst traffic, periodic 503 faults, and ten-request breaker opening against the local checkout with zero missing evidence-status headers in the valid runs.
- Bumped the Python package, Python entrypoints, Helm chart, Docker metadata, Rust crate, and maturin package to `3.0.1`.

### Verification

- Final checkout gate: `5374 passed, 80 skipped, 47 warnings`; Ruff lint/format, Bandit, pip-audit, and Helm lint exited with status 0.
- Coverage gate: `93%` line coverage measured by `pytest-cov`; residual warnings remain documented telemetry.

## 3.0.0 — 2026-08-14

This is a historical changelog entry; no corresponding public GitHub Release or tag is currently available.

### Security and evidence

- Production mode is now explicitly `strict` by default and rejects missing authentication, durable evidence, strong signing, request bounds, required kernel controls, or distributed rate limiting.
- Redis rate-limit failures raise `RateLimitBackendUnavailable` and are rejected at the HTTP boundary instead of failing open.
- Non-sandbox Seccomp failures raise; LSM exposes a fail-closed assertion for strict startup.
- The forensic ledger accepts `require_strong_signing` and rejects the ephemeral Ed25519 fallback when enabled. The proxy persists and fsyncs request/response evidence before returning a successful governed response.

### Performance and concurrency

- Response analysis is dispatched through a bounded worker queue and is no longer executed synchronously on the client-visible request path.
- Per-session analyzer state is serialized to prevent races in baseline, EMA, and previous-logit state.
- Streaming responses are bounded and committed before SSE emission.

### Configuration and supply chain

- Backend URLs and air-gap allowlist entries reject unsupported schemes, userinfo, malformed ports, and non-canonical entries.
- Enterprise lifespan uses the injected settings instance consistently.
- `cryptography` is constrained to `>=50.0.0,<51.0.0`; `requirements.lock` pins `50.0.0` with official PyPI hashes to remediate the audited `CVE-2026-69247` / `PYSEC-2026-3552` affected range.
- README, `.env.example`, and `DEPLOYMENT_GUIDE.md` now describe implemented behavior and residual risk instead of certification claims.

### Verification

- Isolated Python 3.12 baseline: `5373 passed, 80 skipped, 47 warnings in 24.17s`.


## [2.4.1] — 2026-06-24

### Summary

Commercial deployment release. Closes all remaining P0 security-theater items
identified in the 2026-06-24 roadmap audit; ships the complete cross-platform
abi3 wheel matrix; upgrades Helm chart to v2.4.1; introduces the enterprise
multi-vertical Docker Compose; and restructures COMMERCIAL.md with concrete
SLA tiers and AGPL §13 enforcement mechanics.

**Audit baseline at release:** 5,451 tests · 5 skipped · 95.18% branch
coverage · `ruff`/`mypy`/`bandit` clean · `cargo test` 26 passing · pyo3 0.29
/ `edition = "2021"` · 8-target abi3 wheel matrix (manylinux2014 + musllinux ×
x86_64/aarch64/armv7, macOS Intel/ARM, Windows MSVC) · all simulation-debt
entries driven to zero (`tests/test_no_simulation_markers.py` asserts 0).

### Security

- **De-simulated `CFIManager`** (ROADMAP P0.2). `aegis/core/cfi_manager.py`
  previously hardcoded `is_cfi_enabled = True  # Simulation result`, always
  returning a positive CFI attestation regardless of the binary under inspection.
  Rewritten with three real ELF detection tiers: LLVM CFI (`__cfi_check` /
  `__cfi_prototype` symbols via `pyelftools`), GCC/LLVM unwind tables
  (`.eh_frame` / `.eh_frame_hdr` sections), and Intel CET IBT + Shadow Stack
  (`GNU_PROPERTY_X86_FEATURE_1_AND` in `.note.gnu.property`). Falls back to
  `readelf`/`nm` subprocess if `pyelftools` is not installed. 18 tests including
  KAT against the real Rust `.so` binary and malformed-file edge cases
  (`tests/test_cfi_manager.py`).

- **De-simulated `MTEGuard`** (ROADMAP P0.2). `aegis/core/mte_guard.py`
  previously fabricated ARM MTE support on every platform (`self._hardware_support
  = True`) and simulated `PR_SET_TAGGED_ADDR_CTRL` success without issuing the
  syscall. Rewritten with real `/proc/cpuinfo` `mte` flag parsing, `AT_HWCAP2`
  bit 18 (`HWCAP2_MTE`) auxiliary-vector check, and a real `prctl(55, 1)` call
  via `ctypes.CDLL("libc.so.6")`. Returns `False` on x86/non-ARM hosts. 14 tests
  cover the no-hardware path and monkeypatched hardware paths; 2 ARM integration
  tests skip cleanly on CI (`tests/test_mte_guard.py`).

- **De-simulated `DependencyAuditor`** (ROADMAP P0.4). `aegis/core/dependency_audit.py`
  previously calculated `SHA-256(f"{name}_{version}_AUDITED")` as the audit hash
  and re-computed the exact same string for verification — always passing. Replaced
  with a real `pip-audit -f json` invocation (`DependencyAuditor.scan()` returning
  `VulnerabilityFinding` dataclasses) and real `importlib.metadata` RECORD hash
  verification using URL-safe base64 (PEP 658). `DependencyInternalizer.verify_supply_chain()`
  now delegates to both. 24 tests including tamper detection and real certifi hash
  match (`tests/test_dependency_audit.py`). Also registered `slow` pytest mark.

- **De-simulated `XDPDynamicSegmenter`** (ROADMAP P0.3). `aegis/core/xdp_dynamic_segmentation.py`
  previously added IPs only to an in-memory Python `set` and logged
  `# Simulation: eBPF_map_update(...DROP)` — no packet was ever dropped at the
  kernel level. Replaced with `_FirewallBackend` that auto-detects nftables (`nft`)
  → iptables → NONE and issues real kernel rules (`nft add/delete element` or
  `iptables -I/-D INPUT -s <ip> -j DROP`). `block_ip_immediately()` returns `True`
  only when a kernel rule is installed; the application-layer-only fallback path logs
  an explicit "APPLICATION-LAYER ONLY" advisory. 27 tests cover backend detection,
  idempotency, kernel failure fallback, and zone blackhole/active transitions
  (`tests/test_xdp_dynamic_segmentation.py`).

- **Hardened `DependencyAuditor` against B607 partial-path subprocess start**.
  `pip-audit` is now resolved via `shutil.which()` in `__init__`; a `DependencyAuditorError`
  is raised immediately if the tool is absent — no partial-path fallback. `subprocess.run`
  annotated `# noqa: S603`. Test updated to patch `shutil.which`.

- **De-simulated `sandbox_l1.py`** (ROADMAP P0.2). Previously skipped the
  entire rule-addition step ("we simulate the rule addition") and called
  `seccomp_load` with zero allowlist rules and `SCMP_ACT_KILL` — any loaded
  filter would have immediately killed the process. Rewritten with real
  `seccomp_syscall_resolve_name` + `seccomp_rule_add` calls via ctypes for
  every syscall in the allowlist; default action changed to
  `SCMP_ACT_ERRNO(EPERM)` (safe); `apply_filter()` returns `True` only when
  `seccomp_load()` succeeds; `build_filter_without_loading()` validates the
  filter safely in tests. 18 tests including real subprocess filter load and
  mocked-library failure paths (`tests/test_sandbox_l1.py`).

- **De-simulated `panic_mode.py`** (ROADMAP P0.2). `_zeroize_critical_memory` previously only
  logged "Zeroizing..." and "complete" with a `# Simulation` comment and no actual write.
  Replaced with real `ctypes.memset` over registered ``bytearray``/``memoryview`` buffers;
  ``register_sensitive_buffer()`` added so callers can enlist secret-bearing buffers.
  `_isolate_network` previously only logged with `# Simulation: calls XDPDynamicSegmenter...`.
  Replaced with real subprocess calls to `nft add rule ... drop` or `iptables -P INPUT/OUTPUT/FORWARD DROP`;
  returns `False` and logs a CRITICAL advisory when no kernel firewall tool is available.

- **De-simulated `root_ca_gateway.py`** (ROADMAP P0.2). `import_signed_certificate`
  had a `# Simulation of decoding the physical transfer` comment despite doing real
  JSON decoding. Comment removed. `fetch_certificate(request_id)` previously ignored
  the `request_id` parameter ("In a real system, we would match the request_id");
  now iterates `_inbound_buffer` and matches by `cert.ca_serial == request_id`.

- **De-simulated `memory.py`** (ROADMAP P0.2). `HardenedMemoryManager.initialize_hardened_allocator`
  previously set `_allocator_type = "mimalloc"` via a "Simulation mode" comment
  even when neither `libmimalloc.so` nor `libhardened_malloc.so` appeared in
  `/proc/self/maps`. Now logs a warning and sets `_allocator_type = "standard"`
  honestly when no hardened allocator is detected.

- **De-simulated `memory_invariants.py`** (ROADMAP P0.2). Previously computed
  golden hashes from a `f"STATE_{start}_{end}"` string (always matching itself,
  never detecting any modification). Rewritten with `_read_range()` reading the
  actual bytes from the process's own virtual address space via `/proc/self/mem`,
  and `_hash_range()` computing real SHA-256 digests. `register_invariant()`
  returns `False` when the range is unreadable. `verify_invariants()` re-reads
  each range and detects real modifications; unmapped pages after registration
  are logged as CRITICAL. 16 tests including real ctypes buffer tampering
  detection, unmapped-address handling, and mock-based unreadable-after-register
  coverage (`tests/test_memory_invariants.py`).

- `tests/test_no_simulation_markers.py` — `KNOWN_SIMULATION_DEBT` shrunk from
  23 → 16 as `cfi_manager.py`, `mte_guard.py`, `dependency_audit.py`,
  `xdp_dynamic_segmentation.py`, `sandbox_l1.py`, `memory.py`, and
  `memory_invariants.py` are removed. Debt-count assertion updated to `== 16`.

- **Removed two fake post-quantum modules that manufactured false cryptographic
  assurance** (ROADMAP P0.1). `aegis/core/pqc.py` advertised "ML-DSA (Dilithium)"
  signatures but computed HMAC-SHA512 padded with random bytes; `aegis/core/
  pqc_provider.py` was a SHAKE-256 "simulation" whose `verify()` accepted **any**
  128-byte signature regardless of message. Both are deleted.

### Added

- `aegis/core/pqc_signer.py` — the single real `PQCSigner` over genuine ML-DSA-65
  (FIPS 204) via the Rust `pqcrypto-mldsa` backend: real keypair (pk 1952 / sk
  4032 / sig 3309 bytes), `sign`/`verify`, honest `backend` reporting (never a
  simulation label), `require_real` mode, and no simulated fallback. 20 KAT-style
  tests prove forgery, tamper, wrong-key, and truncation rejection
  (`tests/test_pqc_signer.py`).

### Changed

- `aegis/core/pqc_tls.py` rewritten as a **real** hybrid post-quantum key
  exchange: X25519 ECDH (`cryptography`) composed with ML-KEM-1024
  (`aegis.core.mlkem_session`) via `HKDF-SHA256`, TLS-1.3-style initiator/
  responder protocol. The previous module's "X25519" and "Kyber" secrets were
  both `sha256(priv ‖ pub)` — not a Diffie-Hellman and not post-quantum. The new
  module refuses to downgrade to classical-only when ML-KEM is unavailable. 14
  tests prove key agreement and tamper-breaks-agreement (`tests/test_pqc_tls.py`).
- `aegis/core/artifact_signing.py` rewritten with two honestly-labelled **real**
  schemes — `HMAC_SHA512` and real `ML_DSA_65` (via `PQCSigner`) — fixing a
  comment that labelled HMAC as ML-DSA and a verify path that re-signed instead
  of doing asymmetric verification with the published public key. 10 tests
  (`tests/test_artifact_signing.py`).
- `tests/test_no_simulation_markers.py` — a **ratchet** CI guard: no new `aegis/`
  module may introduce a `# SIMULATION` marker, and de-simulated modules must be
  removed from the 23-entry `KNOWN_SIMULATION_DEBT` allowlist (shrink-only).

### Fixed

- `tests/test_determinism.py::test_no_outlier_exceeds_500us` now skips on shared
  CI runners (`HERMES_SANDBOX`/`CI`), where multi-tenant kernel-scheduler
  preemption produces millisecond-scale dispatch outliers unrelated to the code
  under test (a 90 ms outlier was observed). The hard <500 µs bound remains
  enforced on dedicated CPU-isolated hardware.

## [2.4.1] - 2026-06-24

Release-hardening and capability-expansion release. Twenty roadmap controls were
implemented and tested across all five target domains (Defense, Healthcare,
Industrial, Enterprise HA, Forensics), advancing the roadmap scorecard to
151/193 (~78%). All 4,575 tests pass (3 skipped) at 94.79% coverage.

### Added

**Defense & Government (Domain 1)**
- ML-KEM-1024 (FIPS 203) session-key bootstrap (`aegis/core/mlkem_session.py`).
- Cross-domain solution (CDS) guard with classification-domain transfer
  sanitization (`aegis/core/cds_guard.py`).
- Offline license validation — HMAC-SHA256 over canonical JSON, no phone-home,
  enforced key separation (`aegis/core/offline_license.py`).
- Pinned CA bundle for air-gapped signature verification, SHA-256 DER
  fingerprints, no runtime CA fetch (`aegis/core/pinned_ca_bundle.py`).
- LSM confinement guard — AppArmor/SELinux detection and advisory enforcement
  (`aegis/core/lsm_guard.py`, `deploy/apparmor/aegis.profile`).
- Hardware-bound session tokens (TPM 2.0 / software backends, HMAC-SHA256
  binding) (`aegis/core/hardware_token.py`).
- Rust build hardening — full RELRO, noexecstack, embedded size profile
  (`aegis_rust_v2/.cargo/config.toml`).
- **Fully air-gapped Docker image** — `deploy/docker/Dockerfile.airgap` with
  sha256-pinned base, `pip install --no-index --find-links /wheels`, vendored
  wheel workflow (`scripts/vendor_wheels.sh`), and `make docker-airgap`.

**Healthcare & Life Sciences (Domain 2)**
- GxP Installation/Operational Qualification (IQ/OQ) protocols with JSON evidence
  artifacts (`tools/qualification/iq_checks.py`, `oq_checks.py`).

**Industrial Automation & OT (Domain 3)**
- Real-time scheduling via `sched_setscheduler` (FIFO/RR/DEADLINE)
  (`aegis/core/rt_scheduler.py`).
- CPU affinity pinning via `sched_setaffinity` (`aegis/core/cpu_affinity.py`).
- Gossip-protocol WAL synchronization for disconnected edge nodes
  (`aegis/core/gossip_wal_sync.py`).
- CRDT audit-node ordering with vector clocks for deterministic distributed
  ordering (`aegis/core/crdt_ordering.py`).

**Enterprise Hyperscale & HA (Domain 4)**
- Raft consensus state machine (Ongaro & Ousterhout 2014) — leader election,
  log replication, SHA-256 entry-hash tamper detection (`aegis/core/raft_consensus.py`).
- Split-brain prevention via monotonic fencing tokens (Kleppmann 2016),
  gating every WAL write (`aegis/core/split_brain.py`).
- Kubernetes operator — `AegisProxy` CRD + kopf controller
  (`deploy/k8s/aegis-operator/`).

**Advanced Forensics & WAF (Domain 5)**
- Semantic similarity clustering of jailbreak families (SimHash + Hamming)
  (`aegis/core/semantic_sim_clustering.py`).
- Token-split reassembly WAF detector for boundary-split attack patterns
  (`aegis/core/token_split_detector.py`).
- Court-ready forensic PDF report with SHA-256 seal, no external PDF dependency
  (`aegis/core/forensic_pdf_report.py`).
- Anonymized threat-intelligence sharing with STIX 2.1 indicator export
  (`aegis/core/ti_sharing.py`).

**Tooling & Benchmarks**
- New `benchmarks/bench_crypto_audit.py` — measures HMAC signing, durable
  `commit_forensic()`, and `verify_integrity()` throughput (documented as
  Claim 4 in `docs/BENCHMARKS.md`).

### Changed

- Bumped version to 2.4.1 across `pyproject.toml`, `aegis`, `aegis_server`,
  Docker images, README, and deployment guide.
- README test evidence and badges refreshed to 4,575 passing tests.

### Fixed

- **Rust extension test linking:** `aegis_rust_v2/Cargo.toml` had
  `default = ["extension-module"]`, which made `cargo test` omit the libpython
  link and fail with undefined `Py*` symbols. Changed to `default = []`;
  maturin still enables `pyo3/extension-module` via `[tool.maturin] features`,
  so production wheels are unaffected. (`cargo test --release` → 23 passed.)
- **Version drift:** `aegis_server.__version__` and the standard
  `deploy/docker/Dockerfile` were stale at 2.3.0; the `aegis_server` `/health`
  and `/ready` endpoints now report the correct release version.
- **Forensic tool environment bug:** `tools/forensic/forensic_checks.py` invoked
  `cargo test` with an empty environment (no `PATH`), which prevented the Rust
  toolchain from resolving; it now inherits the process environment.
- Resolved 30 lint findings across recently added consensus, qualification, and
  test modules (import ordering, unused imports, `StrEnum` migration, ambiguous
  identifiers); full repository is now `ruff` lint- and format-clean.
- Skipped a flaky concurrent-load scheduling-jitter test on shared CI runners
  (`tests/test_determinism.py`), which require dedicated real-time hosts.

### Security

- `aegis_server.crypto` previously imported `hvac` eagerly at package level,
  breaking the HMAC-only compliance-export path on installs without the optional
  `vault` extra; `VaultSigner` is now lazy-imported. (Carried from 2.4.0.)

## [2.4.0] - 2026-06-21

### Added

- Broad roadmap expansion across Defense, Healthcare, Industrial, Enterprise,
  and Forensics domains (SCIM 2.0, RBAC/ABAC zero-trust, LDAP/AD, WORM ledger,
  RAG injection scanning, SLO burn-rate alerting, DFIR export formats, and more).

### Fixed

- `aegis_server.crypto` eagerly imported `hvac` at package level, breaking the
  HMAC-only compliance export path on installs without the optional `vault`
  extra; `VaultSigner` is now lazy-imported. *(Severity: Low)*

## 2.3.0 - 2026-06

This is a historical changelog entry; no corresponding public GitHub Release or tag is currently available.

### Fixed

- mTLS settings were defined in `AegisSettings` but never applied to the uvicorn
  listener or the upstream `httpx` client. *(Severity: High)*
- `ResponseAnalyzer` thresholds were hardcoded, ignoring `AegisSettings`;
  alerting could not be tuned at runtime. *(Severity: Medium)*

## [2.2.0] - 2026-05

### Fixed

- Audit chain signing key was derived from the first sorted API key; unannounced
  rotation silently invalidated the chain. *(Severity: High)*
- `/docs` and `/redoc` were exposed unconditionally in all deployment modes.
  *(Severity: Medium)*
- `prev_hash` always pointed to the genesis node due to a wrong `ORDER BY`
  direction in `list_nodes()`. *(Severity: Critical)*
- Concurrent `BackgroundTask` writes could fork the audit chain (no chain lock).
  *(Severity: Critical)*

[3.0.1]: https://github.com/JuanLunaIA/aegis-latent-core/releases/tag/v3.0.1
[2.4.1]: https://github.com/JuanLunaIA/aegis-latent-core/releases/tag/v2.4.1
[2.4.0]: https://github.com/JuanLunaIA/aegis-latent-core/releases/tag/v2.4.0
[2.2.0]: https://github.com/JuanLunaIA/aegis-latent-core/releases/tag/v2.2.0

## Related documents

- [`README.md`](README.md)
- [`docs/CLAIMS_MATRIX.md`](docs/CLAIMS_MATRIX.md)
- [`docs/benchmarks/BENCHMARK_RESULTS.md`](docs/benchmarks/BENCHMARK_RESULTS.md)
- [`docs/SECURITY_ASSURANCE_ROADMAP.md`](docs/SECURITY_ASSURANCE_ROADMAP.md)
- [`SECURITY.md`](SECURITY.md)

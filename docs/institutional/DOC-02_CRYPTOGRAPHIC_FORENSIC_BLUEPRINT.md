# DOC-02: Zero-Trust Post-Quantum Cryptographic and Forensic Blueprint

**Document ID:** DOC-02
**Title:** Zero-Trust Post-Quantum Cryptographic and Forensic Blueprint
**Language:** US English
**Repository audit revision:** `c1c1bb706ceebfa33dfe32c051e913a063c5d357`
**Review date:** 2026-08-20
**Claim-control authority:** `docs/CLAIMS_MATRIX.md:1-67`
**Human-review owner:** Security Architecture Owner, with the specialist owners named in the claim register

## 1. Purpose and claim discipline

This blueprint defines the cryptographic and forensic controls that are directly evidenced in the repository. It covers the SHA-256 Merkle Mountain Range (MMR), SHA-256, BLAKE3, HMAC-SHA256, file-keyring rotation, ML-DSA-65, ML-KEM-1024 and the X25519/ML-KEM hybrid exchange, RFC 3161 timestamp requests, canonical serialization, forensic evidence packages, export audit logs, and DFIR export containers.

The governing rule is **verify the evidence, not the label**. Algorithm identifiers, comments, generated narratives, configuration values, and format names are not proof of deployment properties. In particular, this document does not claim FIPS 140 validation, constant-time behavior, third-party non-repudiation, production ML-KEM support, or legal admissibility. Those conclusions require evidence outside the audited implementation or are expressly constrained by `docs/CLAIMS_MATRIX.md:36-39,48-49`.

The stable status vocabulary is inherited from the claims matrix:

| Status | Meaning in this document |
|---|---|
| `IMPLEMENTED` | The cited production path implements the stated behavior and cited tests exercise that behavior. |
| `MEASURED` | A named execution artifact or current focused run records the result within its stated environment and workload. |
| `CONFIGURATION-DEPENDENT` | The behavior exists only when the named backend, secret, endpoint, trust material, or deployment control is present. |
| `ROADMAP` | The repository does not provide sufficient evidence for the broader capability. |
| `LEGAL-REVIEW-REQUIRED` | Technical records exist, but a qualified legal and forensic review is required before a legal conclusion. |

## 2. Audit basis and evidence hierarchy

The review read production code, tests, existing operational documentation, the claims matrix, formal records, and retained evidence JSON. Pasted or generated prose was treated as untrusted source material. The evidence hierarchy for this blueprint is: executable production code; directly associated tests; retained execution artifacts with declared boundaries; formal records within their finite models; and explanatory documentation. A statement in a docstring or generated report is not promoted when the implementation establishes a narrower result.

The focused current-worktree test run used the repository virtual environment and covered the in-scope MMR, keyring, HMAC, ML-DSA, ML-KEM, hybrid KEM, RFC 3161, safe serialization, export log, forensic report, DFIR, and ISO-style evidence modules. It recorded **451 passed and 32 skipped in 4.00 seconds**. Skips preserve backend and environment boundaries; they are not passes. The retained release manifest reports a different historical source revision, `20fa011f64bff3582f6be8a6b12735ac2430ec7e`, and broader historical suites in `evidence/execution_2026-08-20/manifest.json:1`. Consequently, that manifest is corroborating historical evidence, not a measurement of the audit revision named above.

The formal record is also bounded. `docs/formal/FORMAL_VERIFICATION.md:14-18` lists the exact formulas and finite state spaces, while `docs/formal/FORMAL_VERIFICATION.md:44-46` states that there is no machine-checked implementation-to-model refinement mapping. The formal artifacts therefore do not prove the cryptographic implementations, key custody, filesystem power-loss semantics, or forensic admissibility.

## 3. Operational boundary and trust model

The blueprint assumes that every external component may fail or be misconfigured: the Rust extension may be absent; the ML-KEM package may be absent; a keyring update may be malformed; a timestamp authority may be unreachable or untrusted; a report caller may supply an unverified integrity status; and an operator may apply an inappropriate legal-status override. The application must expose these conditions rather than convert them into stronger claims.

| Boundary | In scope | Explicitly outside the evidenced boundary |
|---|---|---|
| Cryptographic primitives | Calls and data transformations visible in the cited Python and Rust source | FIPS 140 module validation, hardware isolation, side-channel resistance, entropy-source certification |
| MMR | In-process append, SHA-256 root construction, inclusion checks, prefix-peak reconstruction, Python/Rust root parity tests | A standardized MMR wire format, domain-separated hashing, independent consistency-proof verification, distributed global ordering |
| HMAC and keyring | HMAC-SHA256, key IDs, local file snapshot reload, overlap verification, expiry, permission check | HSM custody, distributed secret propagation, multi-region rotation, secure deletion, filesystem atomicity across network mounts |
| ML-DSA-65 | Native backend key generation, signing, verification, key reload when the extension is installed | Constant-time behavior, FIPS 140 validation, universal platform availability, legal non-repudiation |
| ML-KEM and hybrid exchange | Optional in-process key generation, encapsulation, decapsulation, X25519 plus ML-KEM combination | Production protocol integration, peer authentication, transcript binding, certificate validation, replay protection, deployment support |
| RFC 3161 | DER request construction, HTTP submission, response extraction, package-imprint recomputation, minimal token structure check | TSA certificate-chain validation, token signature validation, revocation status, trusted time conclusion |
| Forensic export | Canonical JSON hashing, package/report seals, custody fields, export-log HMAC, PKCS#7/E01 byte construction | Legal admissibility, examiner qualification, evidence-handling policy compliance, long-term signature validation, tool certification |

## 4. Cryptographic construction inventory

| Component | Implemented primitive and representation | Production locator | Test locator | Boundary |
|---|---|---|---|---|
| Python MMR | SHA-256 leaves; SHA-256 over concatenated lowercase hexadecimal child hashes; root is SHA-256 over height-descending peak hex strings | `aegis/core/mmr.py:40-90` | `tests/test_mmr.py:16-46`; `tests/test_mmr_properties.py:40-175` | No domain prefix or binary hash concatenation is implemented. |
| Rust MMR | Same SHA-256 and hex-string concatenation scheme | `aegis_rust_v2/src/mmr.rs:18-25,60-115` | `tests/test_mmr_parity.py:42-64`; Rust unit test at `aegis_rust_v2/src/mmr.rs:119-130` | Python/Rust parity test is skipped if the extension is unavailable. |
| Content hashes | SHA-256 of request and response bytes | `aegis/core/forensic.py:27-29`; use at `aegis/core/crypto_audit.py:365-366` | `tests/test_forensic.py:60-61,133`; `tests/test_forensic_builders.py:45-56` | Digest detects changed bytes when compared with a trusted reference; it does not establish origin. |
| Audit HMAC | HMAC-SHA256 over the signed audit payload | `aegis/core/crypto_audit.py:184-218,492-504` | `tests/test_local_hmac_signer.py:79-151` | Symmetric authentication; not third-party non-repudiation or PQ resistance. |
| Rotating HMAC | Versioned local keyring; one active key; verify-state overlap; expiration | `aegis_server/crypto/keyring.py:74-290` | `tests/test_keyring_rotation.py:33-162` | Secret-manager and multi-replica delivery are not implemented by this class. |
| BLAKE3 | Native unkeyed and keyed BLAKE3 helper functions; keyed form requires 32 bytes | `aegis_rust_v2/src/hasher.rs:20-50`; `aegis_rust_v2/src/ledger.rs:33-49` | `aegis_rust_v2/src/hasher.rs:84-97`; `aegis_rust_v2/src/ledger.rs:51-75` | No audited caller connects these helpers to the Python MMR or forensic export path. |
| ML-DSA-65 | Native `pqcrypto-mldsa` keypair, detached sign, and detached verify | `aegis_rust_v2/src/pqc.rs:19-77`; wrapper at `aegis/core/pqc_signer.py:91-237` | `aegis_rust_v2/src/pqc.rs:80-119`; `tests/test_pqc_signer.py:32-247` | Available only when `aegis_rust` is importable. No simulated signature is accepted. |
| ML-KEM-1024 | Optional `kyber_py.kyber.Kyber1024` key generation, encapsulation, and decapsulation | `aegis/core/mlkem_session.py:24-49,87-151` | `tests/test_mlkem_session.py:23-176` | Tests skip when `kyber-py` is absent; package is not declared in the project PQ extra. |
| Hybrid KEM | X25519 and ML-KEM-1024 shared secrets concatenated into HKDF-SHA256, 32-byte output, fixed info string | `aegis/core/pqc_tls.py:35-46,110-122,128-204` | `tests/test_pqc_tls.py:31-158` | Standalone exchange helper, not an integrated authenticated TLS handshake. |
| RFC 3161 imprint | SHA-256 over sorted compact JSON; DER SHA-256 MessageImprint and nonce request | `aegis/core/rfc3161_timestamper.py:52-186,370-448,512-515` | `tests/test_rfc3161_timestamper.py:113-153,382-445,509-528` | Verification does not validate TSA signature or certificate chain. |

## 5. Implementation-matched mathematical definitions

The definitions in this section deliberately reproduce the implementation rather than a generalized or standardized alternative.

Let `H(x)` be SHA-256 with a lowercase hexadecimal output when the result is used by the MMR. For leaf bytes `d_i`, the Python and Rust MMR compute:

\[
L_i = \operatorname{hex}(\operatorname{SHA256}(d_i)).
\]

When two peaks of equal height are merged, their **hexadecimal text**, not the decoded 32-byte digests, is concatenated and UTF-8 encoded:

\[
P = \operatorname{hex}(\operatorname{SHA256}(\operatorname{UTF8}(L \mathbin{\|} R))).
\]

For peaks ordered by descending height, `p_1, …, p_k`, the current root is:

\[
R = \operatorname{hex}(\operatorname{SHA256}(\operatorname{UTF8}(p_1 \mathbin{\|} \cdots \mathbin{\|} p_k))).
\]

The empty root is 64 ASCII zero characters, not `SHA-256` of an empty byte string. These equations match `aegis/core/mmr.py:40-90` and `aegis_rust_v2/src/mmr.rs:18-25,60-115`. There is no leaf/node domain-separation prefix in this MMR implementation. The domain-separated Merkle aggregation recorded in `evidence/execution_2026-08-20/manifest.json:1` describes the execution-manifest builder and must not be substituted for the MMR formula.

For the HMAC paths, with secret key `K` and payload bytes `M`, the implementation uses:

\[
T = \operatorname{HMAC\text{-}SHA256}(K, M).
\]

The audit helper emits lowercase hexadecimal text and verifies with `hmac.compare_digest` at `aegis/core/crypto_audit.py:206-218`. The safe-serialization helper emits raw 32-byte tags and verifies with `hmac.compare_digest` at `aegis/core/safe_serialization.py:58-107`. This describes comparison API usage only; it is not a claim that the entire operation, runtime, backend, or calling path is constant-time.

The hybrid helper derives its 32-byte output as:

\[
S = \operatorname{HKDF\text{-}SHA256}(X \mathbin{\|} Q,\; \text{salt}=\varnothing,\; \text{info}=\texttt{AEGIS-HYBRID-X25519-MLKEM1024-v1}),
\]

where `X` is the X25519 shared secret and `Q` is the ML-KEM-1024 shared secret. This matches `aegis/core/pqc_tls.py:35-46,115-122`. The helper does not hash a complete protocol transcript or authenticate either peer.

For canonical package imprints and seals, the common implementation pattern is:

\[
C(o)=\operatorname{UTF8}(\operatorname{JSON}(o,\;\text{sort\_keys}=\text{true},\;\text{separators}=(\texttt{,},\texttt{:}))),
\]

followed by `SHA-256(C(o))`. This exact pattern appears in `aegis/core/rfc3161_timestamper.py:480-515`, `aegis/core/forensic_pdf_report.py:109-119`, `aegis/core/iso27037_evidence.py:305-331`, and `aegis/core/dfir_export.py:478-479`. It is deterministic for the accepted Python object and serializer behavior, but it is not presented as RFC 8785 JSON Canonicalization Scheme.

## 6. MMR audit findings

`MerkleMountainRange.add_leaf` hashes raw leaf bytes, merges equal-height rightmost peaks, and stores parent/child relations at `aegis/core/mmr.py:40-77`. `get_root_hash` sorts peaks by height descending and hashes their concatenated text at `aegis/core/mmr.py:79-90`. The Rust implementation mirrors those transformations at `aegis_rust_v2/src/mmr.rs:60-115`.

Inclusion verification recomputes the sibling path, checks that the result equals one of the object’s current peaks, then recomputes the root from **the verifier object’s complete current peak set** at `aegis/core/mmr.py:119-149`. Therefore a caller must verify against an MMR instance representing the claimed state. The proof list alone is not a self-contained commitment to all other peaks.

The method named `get_consistency_proof` reconstructs old peak hashes and returns them at `aegis/core/mmr.py:151-224`. If the supplied old root differs from the reconstruction, the method logs a warning but still returns a proof (`aegis/core/mmr.py:209-224`). If reconstruction raises, it falls back to current peaks (`aegis/core/mmr.py:202-207`). No separate production verifier for these returned consistency data is present. Accordingly, this blueprint describes **prefix-peak reconstruction data**, not a complete independently verified consistency-proof protocol.

The hybrid Rust wrapper returns the Rust root while using a Python replica for proofs at `aegis/core/mmr.py:285-318`. Root parity is thus a required invariant. `tests/test_mmr_parity.py:42-64` checks selected leaf counts when the extension is importable, and the module explicitly skips otherwise at `tests/test_mmr_parity.py:27-39`.

## 7. SHA-256, BLAKE3, and HMAC boundaries

SHA-256 is the active content-binding digest in the audited Python MMR, audit node request/response hashes, report seals, ISO-style evidence package seals, DFIR export metadata, and RFC 3161 imprints. This does not imply that one canonical byte representation is shared by every subsystem. Each consumer’s serialization must be preserved with its evidence.

BLAKE3 is implemented in the Rust extension as unkeyed and keyed helper functions. The keyed APIs enforce an exactly 32-byte key (`aegis_rust_v2/src/hasher.rs:27-50`; `aegis_rust_v2/src/ledger.rs:40-49`). The Python integration wrapper returns `None` when Rust is absent or the call fails (`aegis/core/rust_integration.py:204-224`). Repository call-site search found definitions and wrappers but no in-scope production caller that makes BLAKE3 the MMR, audit-ledger, or forensic-export commitment. Claims that the audited MMR “uses BLAKE3” are therefore blocked.

HMAC-SHA256 is symmetric. Possession of the verification secret also permits tag generation, so HMAC can authenticate data within a controlled trust domain but does not by itself establish third-party non-repudiation. The claims matrix preserves this limitation at `docs/CLAIMS_MATRIX.md:36`.

## 8. Keyring rotation blueprint

`RotatingHMACSigner` loads a version-1 JSON keyring, requires a regular file with no group/other permission bits, validates key IDs and minimum 32-byte UTF-8 secrets, permits only `active` and `verify` states, and requires exactly one active key (`aegis_server/crypto/keyring.py:74-235`). Reload compares modification time, size, and inode; a malformed reload retains the previous valid snapshot, while an invalid initial load blocks construction (`aegis_server/crypto/keyring.py:147-190`).

Signing uses the active record and returns its non-secret key ID. Verification evaluates unexpired active or verify records using HMAC-SHA256 and `hmac.compare_digest` (`aegis_server/crypto/keyring.py:237-290`). Tests cover active and overlap verification, invalid-update retention, reload without restart, expired-key rejection, invalid initial schema, and owner-only permissions at `tests/test_keyring_rotation.py:33-162`.

The retained `evidence/execution_2026-08-20/key_rotation_report.json:1-24` records 2,033 records across three independent local signer instances, both old and new key IDs, zero failed commits, zero unverifiable records, and mode `0o600`. Its own boundary states `LOCAL_ONLY` and excludes Kubernetes, secret-manager propagation, clock skew, and orchestrator restart. The operator sequence and release gates are specified in `docs/operations/KEY_ROTATION_RUNBOOK.md:16-65`. A production rotation must not be approved from the local artifact alone.

Operationally, key creation and custody belong to an approved secret manager; only the versioned file snapshot crosses into this signer. The deployment owner must atomically install a complete file, maintain an overlap window long enough for historical verification, observe the active key ID, reject any secret in logs, and roll back to the previous valid snapshot if any committed record becomes unverifiable. Distributed propagation and deletion require separate evidence.

## 9. ML-DSA-65 boundary

The Rust backend uses `pqcrypto_mldsa::mldsa65` to generate a keypair, create detached signatures, reconstruct keypairs from bytes, and verify detached signatures (`aegis_rust_v2/src/pqc.rs:19-77`). The Python wrapper reports `ml-dsa-65-rust` only when the backend exists, raises `PQCUnavailableError` rather than returning a simulated signature, and returns `False` on unavailable or malformed verification paths (`aegis/core/pqc_signer.py:91-237`). Tests assert the 1,952-byte public key, 4,032-byte private key, 3,309-byte signature, round-trip verification, tamper rejection, wrong-key rejection, malformed input rejection, and persistent-identity reload at `tests/test_pqc_signer.py:39-247`.

This is `CONFIGURATION-DEPENDENT`, consistent with `docs/CLAIMS_MATRIX.md:39`. The implementation does not evidence FIPS 140 validation. Referring to ML-DSA-65 or FIPS 204 parameter sizes does not convert the loaded software module into a validated cryptographic module. It also does not evidence constant-time behavior; `docs/CLAIMS_MATRIX.md:49` explicitly keeps that claim at `ROADMAP` because the retained verification timing failed the declared threshold. Finally, public-key verification is not by itself legal non-repudiation: identity proofing, certificate policy, private-key custody, revocation, trusted time, and procedural evidence remain external.

## 10. ML-KEM and hybrid KEM boundary

`MLKEMSessionBootstrap` optionally imports `Kyber1024` from `kyber_py`, declares ML-KEM-1024 byte sizes, validates input sizes, and exposes key generation, encapsulation, decapsulation, and a local full exchange (`aegis/core/mlkem_session.py:24-49,87-151`). Its tests are module-skipped if the backend is unavailable (`tests/test_mlkem_session.py:23-176`). The project’s `pqc` extra names `oqs-python`, not `kyber-py`, at `pyproject.toml:81-83`, so the audited dependency declaration does not establish that this backend is installed by an ordinary PQC installation.

`HybridPQCExchange` refuses a classical-only downgrade when ML-KEM is unavailable, combines an ephemeral X25519 secret with an ML-KEM secret via the implementation-matched HKDF formula, and tests two-party agreement, independent sessions, changed-secret behavior after tampering, and selected length validation (`aegis/core/pqc_tls.py:128-204`; `tests/test_pqc_tls.py:31-158`).

These modules establish an optional cryptographic helper, not production ML-KEM support. There is no cited integration into the proxy transport, no authenticated peer identity, no certificate path, no full transcript binding, no negotiation state machine, and no production deployment artifact. `pqc_verified=True` is a local result field assigned after the helper operations; it is not an independent attestation. Production support remains `ROADMAP` until a pinned backend, protocol specification, dependency and supply-chain policy, authenticated integration, interoperability suite, downgrade tests, lifecycle operations, and target-deployment evidence are approved.

## 11. RFC 3161 timestamping boundary

`RFC3161Timestamper.stamp` computes a SHA-256 imprint over compact sorted-key JSON, constructs a DER request with a random or supplied nonce, sends it to the configured TSA URL, accepts PKI status 0 or 1, extracts the token, and adds the token, TSA URL, and imprint to a copy of the package (`aegis/core/rfc3161_timestamper.py:370-448`). The HTTP client enforces a timeout but accepts the configured URL scheme and uses the environment trust behavior of `httpx` or `urllib` (`aegis/core/rfc3161_timestamper.py:519-542`).

The local `verify` method removes RFC 3161 fields, recomputes the imprint, and checks only that the token parses as a DER SEQUENCE (`aegis/core/rfc3161_timestamper.py:450-510`). Its own comment states that PKI trust requires the TSA certificate chain at `aegis/core/rfc3161_timestamper.py:492-495`. It does not validate the CMS signature, TSA certificate chain, extended key usage, policy OID, nonce inside signed token content, revocation status, or trusted current time. A successful return therefore means **local structural and imprint consistency**, not a validated trusted timestamp.

Deployment approval requires a qualified PKI owner to pin or approve the TSA endpoint, require protected transport as policy dictates, validate response content and CMS signature with an approved trust store, check certificate purpose and revocation policy, correlate the nonce, preserve the full token, and test failure and renewal behavior. Until that exists, trusted-time claims remain `ROADMAP`.

## 12. Canonical serialization and forensic export

The repository has multiple serialization paths. They must not be conflated:

| Path | Serialization and protection | Exact locator | Important limitation |
|---|---|---|---|
| Safe JSON persistence | Indented JSON through `json.dump` | `aegis/core/safe_serialization.py:110-121` | This is safe interchange relative to pickle, but it is not canonical JSON and has no atomic replacement in this function. |
| Signed pickle artifact | HMAC-SHA256 over raw bytes before restricted loading | `aegis/core/safe_serialization.py:58-107,141-170,247-306` | HMAC authenticity depends on secret custody; restricted unpickling narrows but does not make arbitrary pickle a preferred interchange format. |
| Forensic report seal | SHA-256 of compact sorted-key JSON excluding `integrity_seal` | `aegis/core/forensic_pdf_report.py:99-119` | Unkeyed digest; caller supplies integrity and legal-status strings. |
| ISO-style evidence package seal | SHA-256 of compact sorted-key JSON excluding `integrity_seal`, compared with `hmac.compare_digest` | `aegis/core/iso27037_evidence.py:286-335` | Comparison API does not make the seal keyed or prove provenance. |
| Export audit log | Compact sorted-key JSON HMAC-SHA256 per entry; append-only file; index verification | `aegis/core/export_audit_log.py:105-157,200-311` | No hash link between entries; verification detects index mismatch and bad HMAC but does not by itself detect deletion of a valid tail without an external expected count. |
| PKCS#7 export | Canonical JSON, SHA-256 metadata, CMS SignedData generated with an ephemeral self-signed certificate | `aegis/core/dfir_export.py:130-185,382-425,478-479` | Self-signed export identity is not an external trust anchor or long-term validation service. |
| E01 export | Canonical JSON in a constructed EWF-like container; compatibility MD5 plus SHA-256 metadata | `aegis/core/dfir_export.py:259-356,427-475` | Format construction and signature bytes do not establish forensic-tool interoperability or legal admissibility. MD5 is labeled compatibility-only. |

The forensic report builder accepts `integrity_status` and `legal_admissibility` arguments and defaults them to `UNCHECKED` and `Conditional` (`aegis/core/forensic_pdf_report.py:184-235`). A report seal binds those values but does not validate their truth. Tests correctly demonstrate that a changed field changes or invalidates a seal (`tests/test_forensic_pdf_report.py:296-319`), while separate tests demonstrate that caller-selected admissibility strings are retained (`tests/test_forensic_pdf_report.py:349-397`).

The ISO-style evidence builder snapshots the ledger, calls `verify_integrity`, copies node and custody metadata, allows an explicit legal-admissibility override, then computes an unkeyed SHA-256 seal (`aegis/core/iso27037_evidence.py:343-459`). Tests cover tampering, deterministic sealing of an unchanged object, JSON round-trip, custody re-sealing, and override coverage at `tests/test_iso27037_evidence.py:413-501,580-626,716-883`. These are useful technical controls. They do not authorize the override, establish examiner competence, or determine admissibility under any jurisdiction.

## 13. Controlled claim register

Each material claim has a stable ID, an approved status, exact evidence, assumptions, a falsification criterion, an operational boundary, and a human-review owner.

| Claim ID | Material claim | Status | Exact code, test, or evidence locator | Assumptions | Falsification criterion | Operational boundary | Human-review owner |
|---|---|---|---|---|---|---|---|
| DOC02-CRY-001 | The Python MMR implements the SHA-256 and hex-text construction defined in Section 5. | `IMPLEMENTED` | `aegis/core/mmr.py:40-90`; `tests/test_mmr.py:16-46`; `tests/test_mmr_properties.py:40-175` | Input bytes and ordered append sequence are preserved. | A cited test fails, or code changes leaf, merge, peak order, encoding, or empty-root behavior. | One in-process MMR state. | Cryptography Review Owner |
| DOC02-CRY-002 | The Rust MMR is intended to produce the same roots as Python for tested sequences. | `CONFIGURATION-DEPENDENT` | `aegis_rust_v2/src/mmr.rs:18-115`; `tests/test_mmr_parity.py:27-64` | Compatible native extension is built and imported. | Any parity assertion fails for the same leaf sequence. | Selected test counts; no universal cross-version proof. | Rust Cryptography Owner |
| DOC02-CRY-003 | MMR inclusion verification requires the verifier object’s current peak set and is not a proof-only verifier. | `IMPLEMENTED` | `aegis/core/mmr.py:119-149` | The object reflects the claimed MMR state. | A reviewed code change validates all peaks solely from a self-contained proof. | Current Python object state. | Cryptography Review Owner |
| DOC02-CRY-004 | Returned consistency data reconstruct old peaks but do not constitute a fail-closed independently verified consistency-proof protocol. | `IMPLEMENTED` | `aegis/core/mmr.py:151-224`; tests at `tests/test_mmr_branch.py:58-132` | Internal node history is available. | A production verifier rejects old-root mismatch and validates append-only extension from self-contained proof data. | Prefix reconstruction in one MMR instance. | Cryptography Review Owner |
| DOC02-CRY-005 | SHA-256 is the active digest for the audited MMR and forensic commitments. | `IMPLEMENTED` | `aegis/core/mmr.py:44-90`; `aegis/core/forensic.py:27-29`; `aegis/core/forensic_pdf_report.py:109-119`; `aegis/core/iso27037_evidence.py:305-331` | Exact subsystem serialization is retained. | Any cited path changes algorithms or representations without claim update. | Listed paths only. | Security Architecture Owner |
| DOC02-CRY-006 | Native BLAKE3 and keyed-BLAKE3 helpers exist, but they are not evidenced as the audited MMR or forensic commitment. | `IMPLEMENTED` | `aegis_rust_v2/src/hasher.rs:20-50`; `aegis_rust_v2/src/ledger.rs:33-49`; wrappers `aegis/core/rust_integration.py:204-224` | Source-call search remains accurate. | A reviewed production caller routes the relevant commitment through BLAKE3 and tests prove the path. | Native helper API only. | Rust Cryptography Owner |
| DOC02-CRY-007 | Audit and serialization HMAC paths use HMAC-SHA256 and reject mismatched tags. | `IMPLEMENTED` | `aegis/core/crypto_audit.py:206-218,492-504`; `aegis/core/safe_serialization.py:58-107`; `tests/test_local_hmac_signer.py:79-151` | Key remains secret and payload bytes are stable. | Correct-key/correct-payload verification fails or altered payload/tag is accepted. | Symmetric trust domain. | Application Security Owner |
| DOC02-CRY-008 | HMAC does not provide third-party non-repudiation or post-quantum signing. | `CONFIGURATION-DEPENDENT` | Claim control `docs/CLAIMS_MATRIX.md:36` | Verifier and signer share secret capability. | An approved asymmetric identity, custody, revocation, and external verification design replaces the symmetric path. | HMAC paths only. | PKI and Legal Review Owners |
| DOC02-CRY-009 | The file-backed signer reloads a valid versioned keyring without restart and retains the prior valid snapshot after a malformed reload. | `IMPLEMENTED` | `aegis_server/crypto/keyring.py:147-235`; `tests/test_keyring_rotation.py:71-98` | Local regular file semantics and polling occur. | Invalid update replaces the good snapshot, or valid update cannot become active without restart. | Single process and local file. | Key Management Owner |
| DOC02-CRY-010 | The keyring supports active signing, overlap verification, expiry, and key-ID metadata. | `IMPLEMENTED` | `aegis_server/crypto/keyring.py:237-290`; `tests/test_keyring_rotation.py:41-68,100-130` | Clock and expiry input are trustworthy enough for policy. | Expired verify key is accepted, active key ID is wrong, or overlap signatures fail inside the window. | One loaded snapshot per signer. | Key Management Owner |
| DOC02-CRY-011 | The retained rotation exercise observed 2,033 local records, both key IDs, and zero failed or unverifiable records. | `MEASURED` | `evidence/execution_2026-08-20/key_rotation_report.json:1-24` | Artifact corresponds to its stated historical source and harness. | Artifact integrity fails or rerun under identical boundary contradicts result. | Three independent local instances for 0.5 seconds; no orchestrator or secret manager. | Release Evidence Owner |
| DOC02-CRY-012 | Production distributed zero-downtime rotation is not yet evidenced. | `ROADMAP` | `docs/operations/KEY_ROTATION_RUNBOOK.md:51-65`; evidence boundary at `evidence/execution_2026-08-20/key_rotation_report.json:6-7,23` | Production means actual secret-manager and replica lifecycle paths. | A target deployment passes the runbook gate with restart, delay, rollback, clock, custody, and correlation evidence. | Distributed deployment. | Platform Security Owner |
| DOC02-PQC-001 | ML-DSA-65 signing and verification are available when the native Rust backend is installed. | `CONFIGURATION-DEPENDENT` | `aegis/core/pqc_signer.py:91-237`; `aegis_rust_v2/src/pqc.rs:19-77`; `tests/test_pqc_signer.py:32-247` | Compatible `aegis_rust` module is present. | Backend round-trip, tamper, wrong-key, or reload test fails. | Supported native build only. | Post-Quantum Cryptography Owner |
| DOC02-PQC-002 | The ML-DSA wrapper fails closed rather than returning simulated signatures. | `IMPLEMENTED` | `aegis/core/pqc_signer.py:91-107,200-237`; `tests/test_pqc_signer.py:65-88,180-190,242-247` | Caller does not replace exceptions with acceptance. | Unavailable backend produces a signature or accepts verification. | Python wrapper boundary. | Application Security Owner |
| DOC02-PQC-003 | FIPS 140 validation of the ML-DSA implementation is not evidenced. | `ROADMAP` | Limitation control `docs/CLAIMS_MATRIX.md:39` | Validation requires an applicable module certificate and operating-environment evidence. | Approved validation evidence directly covers the shipped module and configuration. | All deployments. | Compliance Cryptography Owner |
| DOC02-PQC-004 | Constant-time ML-DSA behavior is not approved. | `ROADMAP` | `docs/CLAIMS_MATRIX.md:49`; `docs/formal/FORMAL_VERIFICATION.md:44-46` | Timing evidence does not prove constant-time behavior. | A qualified review approves implementation and platform evidence under a declared leakage model. | Signing and verification implementations. | Side-Channel Review Owner |
| DOC02-PQC-005 | Optional ML-KEM-1024 operations and the X25519/ML-KEM hybrid helper are implemented in source. | `CONFIGURATION-DEPENDENT` | `aegis/core/mlkem_session.py:24-151`; `aegis/core/pqc_tls.py:110-204`; tests `tests/test_mlkem_session.py:23-176`, `tests/test_pqc_tls.py:31-158` | `kyber-py` and compatible `cryptography` are installed. | Backend tests fail or helper silently downgrades. | In-process helper; no transport integration. | Post-Quantum Cryptography Owner |
| DOC02-PQC-006 | Production ML-KEM or hybrid-TLS support is not evidenced. | `ROADMAP` | Dependency boundary `pyproject.toml:81-83`; source boundaries above | Production support requires authenticated protocol and deployment evidence. | Approved integration, dependency pinning, interoperability, downgrade, lifecycle, and target-deployment gates pass. | Network protocol and production deployment. | Security Architecture Owner |
| DOC02-TSP-001 | RFC 3161 stamping builds and submits a SHA-256 imprint request and stores the returned token on status 0 or 1. | `CONFIGURATION-DEPENDENT` | `aegis/core/rfc3161_timestamper.py:370-448,519-542`; `tests/test_rfc3161_timestamper.py:382-445` | Configured TSA endpoint is reachable and returns parseable data. | Request encoding, status handling, imprint, or token extraction test fails. | Client request and response extraction. | PKI Operations Owner |
| DOC02-TSP-002 | Local RFC 3161 verification checks package imprint and minimal DER structure but not TSA PKI trust. | `IMPLEMENTED` | `aegis/core/rfc3161_timestamper.py:450-510`; tests `tests/test_rfc3161_timestamper.py:462-503` | Stored package fields are supplied to verifier. | Code validates CMS signature and certificate chain under an approved trust policy. | Structural consistency only. | PKI Review Owner |
| DOC02-TSP-003 | A trusted RFC 3161 timestamp conclusion is not yet supported by the local verifier. | `ROADMAP` | Explicit limitation `aegis/core/rfc3161_timestamper.py:492-495` | Trusted timestamp requires TSA signature and trust-chain validation. | Full token, nonce, policy, EKU, revocation, and chain validation pass approved tests. | Legal and long-term validation use. | PKI and Legal Review Owners |
| DOC02-SER-001 | Forensic seals and RFC 3161 imprints use compact sorted-key JSON, not RFC 8785 JCS. | `IMPLEMENTED` | `aegis/core/forensic_pdf_report.py:109-119`; `aegis/core/iso27037_evidence.py:305-331`; `aegis/core/rfc3161_timestamper.py:480-515`; `aegis/core/dfir_export.py:478-479` | Python JSON types are serializable and behavior is stable. | Serializer changes or formal JCS implementation replaces it. | Listed Python objects and runtime. | Data Format Owner |
| DOC02-SER-002 | `safe_dump_json` is non-canonical human-readable persistence. | `IMPLEMENTED` | `aegis/core/safe_serialization.py:110-121`; tests `tests/test_safe_serialization.py` and `tests/test_safe_serialization_new.py` | Filesystem write completes. | Function adds a canonicalization and atomic-write contract with tests. | Local file output. | Application Security Owner |
| DOC02-FOR-001 | Forensic report and ISO-style package seals detect post-generation field changes when compared with a trusted original seal. | `IMPLEMENTED` | `aegis/core/forensic_pdf_report.py:99-119`; `aegis/core/iso27037_evidence.py:305-335`; tests `tests/test_forensic_pdf_report.py:296-319`, `tests/test_iso27037_evidence.py:413-501` | Original seal is trusted and all relevant fields are serialized. | Changed covered field verifies under unchanged seal. | Unkeyed integrity comparison, not provenance. | Digital Forensics Owner |
| DOC02-FOR-002 | Export audit entries are individually HMAC-authenticated and index-checked. | `IMPLEMENTED` | `aegis/core/export_audit_log.py:105-157,265-311`; `tests/test_export_audit_log.py:176-210,253-298` | Signing key remains secret and expected log boundary is known. | Altered covered field or wrong key is accepted. | One local log file; no tail-deletion guarantee without external count. | Audit Operations Owner |
| DOC02-FOR-003 | PKCS#7 and E01 byte exports are implemented with canonical JSON content hashes. | `IMPLEMENTED` | `aegis/core/dfir_export.py:130-185,259-356,382-479`; `tests/test_dfir_export.py:196-245,271-334` | Evidence is JSON-serializable and cryptography backend is available for PKCS#7. | Export or content-hash tests fail. | Byte construction and metadata only. | Digital Forensics Engineering Owner |
| DOC02-FOR-004 | Forensic-tool interoperability for generated E01 and long-term PKCS#7 trust are not established. | `ROADMAP` | Current implementation `aegis/core/dfir_export.py:130-185,259-356` | External tools and trust services define acceptance. | Pinned independent-tool matrix and long-term validation profile pass. | External DFIR ecosystem. | Digital Forensics Owner |
| DOC02-FOR-005 | Legal admissibility cannot be concluded from a seal, selected status string, ISO label, RFC 3161 field, PKCS#7 envelope, or E01 signature. | `LEGAL-REVIEW-REQUIRED` | Caller-controlled fields `aegis/core/forensic_pdf_report.py:184-235`; override `aegis/core/iso27037_evidence.py:343-459`; claim control `docs/CLAIMS_MATRIX.md:48` | Jurisdiction, procedure, custody, examiner, and authenticity evidence matter. | Qualified counsel and examiner approve a case-specific record under applicable rules. | Every intended legal use. | Legal Counsel and Qualified Forensic Examiner |
| DOC02-EVD-001 | The focused current-worktree suite recorded 451 passed and 32 skipped. | `MEASURED` | Command covered the in-scope test files listed in Section 2; executed 2026-08-20 under repository `.venv` | The worktree and virtual environment are the audited local state. | Reproduction at the same revision contradicts result or hidden test selection is found. | Local test environment; skips are not passes. | Release Evidence Owner |

## 14. Release gates and falsification workflow

A release consuming these controls must satisfy all applicable gates below. Any failure blocks the affected claim rather than being converted into a warning.

| Gate | Required evidence | Kill criterion | Owner |
|---|---|---|---|
| MMR compatibility | Python tests plus Rust parity when Rust-backed roots are enabled | Any root divergence, accepted altered leaf, or unreviewed formula change | Cryptography Review Owner |
| HMAC key custody | Approved secret source, no secret in logs, minimum key policy, verification replay | Any unsigned or unverifiable committed record; any exposed secret | Key Management Owner |
| Rotation | Runbook-correlated records across actual replicas and secret-manager path | Any invalid snapshot activation, failed valid-window commit, wrong key ID, unverifiable overlap record, or required restart contrary to claim | Platform Security Owner |
| ML-DSA | Native capability probe, key-custody design, round-trip and tamper tests | Backend unavailable when required, malformed identity accepted, or claim exceeds matrix | Post-Quantum Cryptography Owner |
| ML-KEM/hybrid | Approved backend and protocol design, peer authentication, transcript and downgrade tests | Silent classical downgrade, unauthenticated deployment, missing dependency provenance, or helper represented as production TLS | Security Architecture Owner |
| RFC 3161 | Approved TSA, CMS and certificate validation, nonce/policy/revocation checks | Structural-only verification represented as trusted time | PKI Review Owner |
| Forensic package | Recomputed chain integrity, preserved original bytes and metadata, seal verification, custody review | Caller-supplied `VERIFIED` or admissibility status accepted without independent review | Digital Forensics Owner |
| Legal use | Jurisdiction-specific counsel and qualified-examiner sign-off | “Admissible,” “court-ready,” or non-repudiation claim based solely on application output | Legal Counsel |

Falsification is continuous. Per `docs/CLAIMS_MATRIX.md:61-63`, a claim is blocked when its source locator changes, its named regression fails, its boundary changes without rerun, a prerequisite is absent, an independent reviewer finds a contradiction, or customer-facing language exceeds the controlled wording. Every source change affecting a formula, serialization, key lifecycle, trust decision, or export representation requires an updated locator and specialist review.

## 15. Residual risks and priority actions

The highest cryptographic risk is **semantic overstatement across subsystem boundaries**: BLAKE3 helper availability can be mistaken for BLAKE3-backed MMR operation; ML-DSA algorithm implementation can be mistaken for validated or side-channel-reviewed deployment; and optional ML-KEM helpers can be mistaken for authenticated production transport. Capability reporting must expose the active backend and exact scheme rather than a generic “post-quantum enabled” flag.

The highest MMR risk is that consistency-proof behavior is permissive: old-root mismatch is logged rather than rejected, and reconstruction failure falls back to current peaks. If independently consumable append-only proofs are required, the protocol needs explicit proof encoding, domain and representation versioning, a fail-closed verifier, adversarial vectors, and cross-language conformance tests.

The highest timestamp risk is that local RFC 3161 verification can return valid after only imprint equality and a top-level DER sequence check. That result must be labeled structural consistency until complete CMS and TSA trust validation is implemented.

The highest forensic risk is that unkeyed seals bind caller-selected status fields. A digest proves equality to a trusted digest, not the truth of “VERIFIED,” “Admissible,” or any generated narrative. Export workflows must recompute chain integrity, preserve the original source and expected boundary, identify the operator, and require legal review for legal use.

The highest operational key risk is the gap between a local file-state machine and distributed secret delivery. The retained key-rotation artifact is useful local evidence, but secret-manager propagation, independent replica lifecycle, clock skew, restart/replay, secure deletion, and rollback remain deployment responsibilities.

## 16. Approval statement

This blueprint approves only the claims marked `IMPLEMENTED`, `MEASURED`, or `CONFIGURATION-DEPENDENT` within their stated assumptions and boundaries. `ROADMAP` items are not capabilities available for representation as production guarantees. `LEGAL-REVIEW-REQUIRED` items must be reviewed by qualified counsel and a qualified forensic examiner for the intended jurisdiction and matter.

No part of this document asserts FIPS 140 validation, whole-path constant-time behavior, third-party non-repudiation, production ML-KEM support, or legal admissibility.

## 17. Review sign-off

| Review role | Required decision |
|---|---|
| Security Architecture Owner | Confirms subsystem boundaries, capability reporting, and claim status. |
| Cryptography Review Owner | Confirms MMR equations, hash representations, HMAC use, and proof semantics. |
| Post-Quantum Cryptography Owner | Confirms backend identity, ML-DSA and ML-KEM boundaries, and no downgrade. |
| Key Management Owner | Confirms secret custody, overlap, expiry, rotation, rollback, and destruction policy. |
| PKI Review Owner | Confirms TSA trust, token signature validation, certificate policy, and revocation behavior. |
| Digital Forensics Owner | Confirms export reproducibility, interoperability evidence, custody procedures, and examiner workflow. |
| Legal Counsel | Confirms that any legal characterization is case-specific and does not rely solely on technical labels. |
| Release Evidence Owner | Confirms revision, test selection, skips, artifact provenance, and reproducibility record. |

**Document end.**

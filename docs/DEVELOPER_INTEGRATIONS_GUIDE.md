# Aegis Enterprise Integrations Guide

**Status:** `UNRELEASED` implementation candidate on the post-`v3.1.0` development line  
**Claim boundary:** Source support and tests do not prove target-environment availability, regulatory retention, identity-provider correctness, legal admissibility, trusted publishing, or production readiness.

## 1. Security model

Aegis binds every governed request to an immutable `Principal` containing a subject, tenant, approved roles, exact scopes, authentication method, and opaque credential identifier. The gateway derives tenant and rate-limit identity from verified credentials. `X-Aegis-Tenant-ID`, session headers, and provider `user` fields are not identity sources. Session values remain correlation inputs only.

| Authentication mode | Required configuration | Trust boundary |
|---|---|---|
| `api_key` | API keys; in strict mode, `auth_identity_hmac_key` and a SHA-256-keyed `api_key_principals_json` mapping | Constant-time key match plus server-side tenant/scope mapping |
| `oidc` | HTTPS issuer, exact audience, pinned HTTPS JWKS URL, explicit algorithms, PyJWT extra | JWT signature and exact claims; deployment owns IdP, TLS, key rotation, and revocation policy |
| `mtls` | Fingerprint and SAN allowlists; direct verified TLS state or allowlisted immediate proxy | Current source implements explicit leaf pinning, validity, SAN, and unique tenant binding; it is not a general PKI path/revocation engine |
| `api_key_mtls` / `oidc_mtls` | Both corresponding configurations | Both factors must authenticate and bind the same tenant |

Built-in roles grant only the following scopes: `admin` grants all declared scopes; `proxy_user` grants `proxy:completions`; `auditor` grants `audit:read`, `audit:export`, and `audit:analytics`; `audit_reader` grants `audit:read`. Audit records and proofs are tenant-confined for non-admin principals, while tenant inventory is admin-only.

## 2. Distributed request and token quotas

The v4 candidate uses atomic request and generated-token buckets keyed by a SHA-256 pseudonym of authenticated tenant and credential identity. Session and tenant headers cannot reset these buckets. Redis mode executes one Lua transaction over both buckets and uses Redis `TIME`, avoiding host-clock disagreement. Memory mode is process-local and is not a distributed enforcement claim.

The gateway reserves the configured output maximum before forwarding. Non-streaming responses refund only when the authenticated upstream returns a valid provider usage count. Streaming retains the reservation because terminal event counting is not treated as authoritative billing telemetry. Responses expose request/token limit and remaining headers; 429 responses add finite `Retry-After` when a reset can be computed.

## 3. Finalized WAL archival and timestamps

Only rotated JSONL WAL segments are eligible for asynchronous archival. Active WAL files are never uploaded. For each finalized segment, Aegis constructs an `aegis-wal-segment-manifest-v1` document containing the exact file SHA-256, byte size, terminal chain hash, MMR root, MMR leaf count, and local finalization time. These fields are distinct domains and must not be conflated.

When S3 archival is enabled, the adapter sends `ChecksumSHA256`, requests Object Lock retention, records the returned version ID, and verifies checksum, lock mode, and retention with `HeadObject`. ETag is diagnostic only. Local spool bytes and the SQLite journal remain authoritative when upload is unavailable. A successful source-level test does not prove the target bucket has versioning/Object Lock enabled, that the operator cannot delete retained versions, or that a retention regime satisfies any regulation.

RFC 3161 anchoring is optional and occurs only after the segment and manifest are remotely verified. The gateway persists the full request and response, checks nonce and message imprint, and requires OpenSSL verification against an explicitly configured CA file. A returned TSA response with failed CMS trust is not an accepted anchor. The deployment remains responsible for TSA selection, certificate lifecycle, revocation policy, policy OID acceptance, network egress, and retention of verification material.

Required variables include `AEGIS_S3_ARCHIVE_ENABLED`, `AEGIS_S3_ARCHIVE_BUCKET`, `AEGIS_S3_ARCHIVE_REGION`, spool/journal paths, retention settings, and—when anchoring is enabled—`AEGIS_TSA_URL` plus `AEGIS_TSA_CA_FILE`. Install `aegis-latent-core[storage-s3]` for boto3.

## 4. Privacy-safe telemetry and SIEM

Security events use a closed schema with enumerated event kind, outcome, proof state, severity, counts, duration, and a UUID/trace/digest correlation identifier. Prompt text, response text, token text, embeddings, node content, raw tenant/session identifiers, signer names, and exception strings are not fields. SIEM formats are CEF, RFC 5424, Splunk JSON, and Datadog JSON.

The SQLite SIEM spool has configurable row and byte caps and rejects new events at quota. Its file is mode `0600`. Queue saturation does not discard an already spooled event. HTTPS transport disables redirects and has a finite timeout. Operators must monitor rejected submissions, pending rows, disk capacity, sink errors, and shutdown timeouts. The source does not establish downstream SIEM retention, delivery SLOs, or incident-response effectiveness.

## 5. SDK framework adapters

The Python SDK includes optional LangChain and LlamaIndex callback adapters. They submit only correlation/proof metadata and verify portable MMR inclusion proofs against an independently supplied trusted root. A valid inclusion proof establishes inclusion relative to that root; it does not establish external immutability, authorship, global order, or legal provenance. Framework compatibility remains bounded to the dependency versions and integration tests named by the package metadata.

## 6. Publishing and OCI boundaries

The PyPI and npm workflows build and test exact SDK artifacts, require a signed annotated `v*` tag, require the peeled tag commit to be reachable from `origin/main`, pass artifacts by commit-specific names, and grant OIDC only in environment-gated publish jobs. Publication also requires repository variable `AEGIS_TRUSTED_PUBLISHING_ENABLED=true`. Leaving the variable unset keeps publication disabled.

External setup is mandatory: configure protected immutable tag rules, signing-key trust, GitHub environments and reviewers, PyPI/npm trusted-publisher identities bound to the exact workflow and environment, package ownership, and registry policy. The repository cannot prove those controls. The dashboard image accepts credentials only at runtime; credentials are not Docker build arguments.

No `v4.0.0` version bump, tag, registry publication, GitHub Release, WORM certification, SLSA level, legal-admissibility statement, or production-readiness assertion is authorized by this candidate alone.

## 7. External acceptance checklist

| Gate | Required evidence | Current repository status |
|---|---|---|
| Identity | IdP issuer/audience/JWKS policy, rotation and revocation exercise, tenant mapping review | External acceptance required |
| mTLS | TLS terminator strips inbound forwarding headers and supplies verified client identity; leaf-pin lifecycle tested | External acceptance required |
| Redis | Atomic Lua behavior, outage handling, latency, eviction, and capacity on target topology | External acceptance required |
| S3 | Versioning/Object Lock enabled at creation, retention/legal-hold permissions tested, restore/reconciliation exercised | External acceptance required |
| TSA | Approved HTTPS TSA, CA/revocation/policy configuration, timestamp renewal and offline verification | External acceptance required |
| SIEM/OTel | Endpoint authentication, egress policy, spool capacity, downstream parsing, outage and recovery drill | External acceptance required |
| Registries | Trusted-publisher binding, environment protection, signed-tag policy, package ownership | External acceptance required |
| OCI | Execute and verify the candidate multi-architecture gateway/dashboard build, SBOM, provenance, keyless signatures, architecture smoke tests, and rollback in target GHCR | External acceptance required |
| Release | Full CI/security/formal/docs/dependency gates plus required human/domain approvals | Not yet accepted |

## 8. Falsification criteria

The identity claim is falsified if changing a caller tenant/session header changes the authenticated tenant or quota key. Atomic quota behavior is falsified if one dimension is charged after a denied combined decision. Archive verification is falsified if a checksum, version, lock mode, or retention mismatch reaches `verified`. Timestamp trust is falsified if an untrusted CMS response returns a successful anchor. Privacy projection is falsified if sentinel prompt, response, tenant, secret, or exception text enters an exported event. Publishing provenance is falsified if a lightweight/unsigned tag or a commit outside `origin/main` reaches an OIDC publish step.

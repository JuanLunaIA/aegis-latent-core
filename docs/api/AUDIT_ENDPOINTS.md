# Audit Endpoints

**Audience:** developers integrating against the audit surface, security reviewers.
**Scope:** the `/v1/audit` and `/v1/attestation` endpoints, their scopes, and what each response does and does not establish.
**Boundary:** these endpoints report what one gateway process retains. They do not establish global ordering, external immutability, or independent trust. A response from a gateway is not independent evidence about that gateway. See [Boundaries](../BOUNDARIES.md).

---

## 1. Authentication and scopes

All audit endpoints require an authenticated principal carrying the right scope.

| Scope | Grants |
| --- | --- |
| `audit:read` | Reading health, integrity, nodes, evidence, proofs, tenants |
| `audit:export` | Producing a forensic bundle |

Configure audit keys with `AEGIS_AUDIT_API_KEYS`. When unset, the proxy API keys apply. Treat `audit:export` as a sensitive-data-export permission and grant it separately from `audit:read`.

```
Authorization: Bearer <audit-key>
```

**Tenant visibility.** A principal sees records for its own tenant. Filtering is applied server-side. This is logical isolation within one process, not a boundary equivalent to separate deployments — an operator with filesystem access reads every tenant's records regardless.

## 2. Endpoints

| Method | Path | Scope | Purpose |
| --- | --- | --- | --- |
| `GET` | `/v1/audit/health` | `audit:read` | Ledger health and fault state |
| `GET` | `/v1/audit/integrity` | `audit:read` | Verify the retained chain |
| `GET` | `/v1/audit/nodes` | `audit:read` | List retained nodes |
| `GET` | `/v1/audit/nodes/{node_hash}` | `audit:read` | One node by hash |
| `GET` | `/v1/audit/nodes/{node_hash}/evidence` | `audit:read` | Raw evidence for a node |
| `GET` | `/v1/audit/proofs/{state_id}` | `audit:read` | MMR inclusion proof |
| `GET` | `/v1/audit/tenants` | `audit:read` | Tenants visible to the principal |
| `GET` | `/v1/audit/export/part11` | `audit:read` | Part 11-oriented record projection |
| `POST` | `/v1/audit/forensics/export` | `audit:export` | Bounded evidence bundle |
| `GET` | `/v1/attestation/capabilities` | — | Machine-readable capability report |

### 2.1 Health

```bash
curl -sH "Authorization: Bearer $AUDIT_KEY" localhost:8080/v1/audit/health
```

Reports node count and fault state. **`wal_corrupt` here means replay stopped at a malformed line during startup.** Read this carefully: subsequent commits remain permitted, and the request path does not check the fault state before committing. A degraded health response is a signal to investigate, not a guarantee that the gateway has stopped accepting work.

### 2.2 Integrity

```bash
curl -sH "Authorization: Bearer $AUDIT_KEY" localhost:8080/v1/audit/integrity
```

Runs `verify_integrity()` over the retained chain and reports validity, node count, scope, and whether full history is retained.

**Read `full_history_retained` before quoting the result.** The in-memory chain is a bounded deque governed by `AEGIS_MAX_MEMORY_NODES`. Once it has rolled over, a `valid: true` response covers the retained window only. It is not a statement about records evicted from memory, and presenting it as whole-history verification would be wrong.

### 2.3 Nodes

```bash
curl -sH "Authorization: Bearer $AUDIT_KEY" \
  "localhost:8080/v1/audit/nodes?limit=50&offset=0"
```

Offset pagination over the retained window. **It is not snapshot-stable under concurrent appends or eviction**: a record can shift index between two pages. For a consistent set, export a bundle instead.

Optional signature verification per node is available; it costs a signing operation per node, so it is off by default.

### 2.4 Node evidence

```bash
curl -sH "Authorization: Bearer $AUDIT_KEY" \
  localhost:8080/v1/audit/nodes/<node_hash>/evidence
```

Returns the raw evidence payload for one node. This is the most sensitive read on the surface — it returns governed content, subject to whatever redaction was configured when the record was written. Redaction is best-effort pattern matching; see [PII Redaction Boundaries](../privacy/PII_REDACTION_BOUNDARIES.md).

### 2.5 Proofs

```bash
curl -sH "Authorization: Bearer $AUDIT_KEY" \
  localhost:8080/v1/audit/proofs/<state_id>
```

Returns an `aegis-mmr-inclusion-v1` proof. Verify it with an SDK verifier against a root you obtained **independently of this gateway**.

Verifying a proof against a root returned by the same gateway that produced the proof establishes internal consistency and nothing more. Schema and verification rules: [MMR Proof v1](MMR_PROOF_V1.md).

For a stream, no proof exists until the terminal summary commits. Before then, evidence status reads `pending-terminal`.

### 2.6 Tenants

Lists tenants visible to the calling principal. Not a directory of all tenants in the system.

### 2.7 Part 11 export

Projects retained records into a record-oriented shape. **The endpoint name refers to the shape of the projection, not to a compliance determination.** Whether any deployment satisfies 21 CFR Part 11 is a determination for you and your assessor, and depends on organisational controls this software does not implement. See [Compliance Mapping](../compliance/COMPLIANCE_MAPPING.md).

### 2.8 Forensic export

`POST /v1/audit/forensics/export` produces a bounded ZIP. Full contents, verification path and limits: [Forensic Export](FORENSIC_EXPORT.md).

### 2.9 Attestation capabilities

```bash
curl -s localhost:8080/v1/attestation/capabilities
```

Reports which cryptographic capabilities are implemented, optional-runtime, stubbed, or require external validation. Use it to check what a given deployment actually has rather than what the documentation says is possible — a build without the Rust extension has no ML-DSA regardless of the docs.

## 3. Operational endpoints

| Path | Auth | Purpose |
| --- | --- | --- |
| `/health` | None | Liveness. Carries no configuration values by contract. |
| `/ready` | None | Readiness. |
| `/metrics` | None | Prometheus exposition, registered only when `prometheus-client` is installed. |

`/health` deliberately leaks no configuration. Enforcement posture is on `/metrics` as `aegis_security_enforcement_mode`, not on `/health`.

## 4. Error responses

| Status | Means |
| --- | --- |
| `401` | No credential, or an unrecognised one |
| `403` | Authenticated, but missing the required scope |
| `404` | Node, proof, or state not in the retained window — which is not the same as never having existed |
| `422` | Malformed request; export rejects empty or unbounded requests |
| `503` | A required backend is unavailable; the gateway fails closed rather than serving unevidenced |

**`404` is ambiguous by design and worth understanding.** A record evicted from the retained window and a record that never existed both return `404`. Distinguishing them needs archived segments, not this API.

## 5. What these endpoints do not establish

- **Not independent evidence.** Every response comes from the gateway being assessed.
- **Not global ordering.** One process, one chain. Other replicas have their own.
- **Not completeness.** Responses cover the retained window.
- **Not external immutability.** The chain detects tampering on read; it does not prevent it.
- **Not custody or authorship.** Nothing here establishes who caused a record to exist.
- **Not a compliance determination.** Endpoint names describing regulatory shapes describe shapes.

---

**Related:** [MMR Proof v1](MMR_PROOF_V1.md) · [Forensic Export](FORENSIC_EXPORT.md) · [Integrations Guide](../DEVELOPER_INTEGRATIONS_GUIDE.md) · [Security Controls](../security/SECURITY_CONTROLS.md) · [Boundaries](../BOUNDARIES.md)

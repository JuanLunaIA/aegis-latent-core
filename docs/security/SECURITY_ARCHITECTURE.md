# Security Architecture

**Audience:** security reviewers, architects, platform engineers.
**Scope:** how the controls in [Security Controls](SECURITY_CONTROLS.md) compose across trust boundaries, and where each boundary's assumptions come from.
**Boundary:** this describes the architecture of the checked-out source. It does not establish that any deployment implements it correctly. See [Boundaries](../BOUNDARIES.md).

---

## 1. Position in the system

The gateway is an interception point. It sits between an application and a model provider and is the only component that sees both the governed request and the governed response before the caller does.

```
   caller                gateway                       upstream
     │                      │                             │
     │  request ───────────►│                             │
     │                 ┌────┴─────┐                       │
     │                 │  admit   │  auth, scope, bounds  │
     │                 │  policy  │  WAF, rate limit      │
     │                 └────┬─────┘                       │
     │                      │  forward ──────────────────►│
     │                      │◄──────────────────  response│
     │                 ┌────┴─────┐                       │
     │                 │ redact   │  PHI / PCI scrubbing  │
     │                 │ commit   │  sign → write → fsync │
     │                 └────┬─────┘                       │
     │◄── response ─────────│   (only after commit)       │
```

The ordering is the security property. Everything else is support for it: **for an admitted non-streaming call, the evidence record is durable before the caller can observe the response.** A design that returned first and committed later would make the evidence optional, and an optional evidence record is not evidence.

## 2. Trust boundaries

Six boundaries, ordered by how much a reviewer should care.

| # | Boundary | What crosses it | Assumption |
| --- | --- | --- | --- |
| B1 | Caller → gateway | Credentials, prompts, headers | Everything is hostile. The principal is derived from the credential, never from a header. |
| B2 | Gateway → upstream provider | Governed request, backend key | The provider is a third party outside the evidence boundary. Data sent is gone. |
| B3 | Gateway → WAL storage | Signed evidence nodes | Exactly one writer per path. Storage acknowledges `fsync` truthfully. |
| B4 | Gateway → Redis | Rate-limit and session state | Redis holds no signing keys and no payload content. |
| B5 | Gateway → audit consumer | Nodes, proofs, forensic bundles | The consumer is authenticated and scoped, but is not trusted to supply its own trusted root. |
| B6 | Operator → host | Filesystem, process, keys | The operator is trusted. This is the largest residual assumption in the design. |

**B6 is the one that constrains every claim in this project.** An operator with root can alter a WAL file, replace a signing key, or restart the process with a different configuration. No control in this repository prevents that. The chain detects tampering on read; it does not prevent it. Statements about immutability, custody, and non-repudiation all terminate at this boundary.

## 3. Layered controls

Controls compose in a specific order, and the order matters more than the individual controls.

**Admission (before any upstream cost is incurred).** Authentication resolves a principal. Scope gates the endpoint. Body bounds reject oversized input. The WAF evaluates patterns and session-cumulative signals. Rate limiting applies per authenticated tenant. A request rejected here produces a rejection record, not a governed evidence record — the distinction matters when reconciling counts.

**Forwarding.** The egress guard constrains the endpoint form. The circuit breaker protects the gateway from a failing upstream. The backend credential crosses B2 and is never returned to the caller.

**Evidence (before the caller observes anything).** Redaction runs over the payload. The node is built, signed, written, flushed, and `fsync`-ed under a per-path lock. Only then does the response return.

**Streaming is the same discipline with different mechanics.** Events are emitted incrementally through a byte-accounted bounded queue, so the caller sees output before the record exists. The reconciliation is that the stream reports `pending-terminal` throughout, and the terminal marker is withheld until the terminal summary commits. A commit failure suppresses the marker, so a caller never sees a completed stream without a durable record.

## 4. Fail-closed posture

The design prefers refusing to serving unevidenced traffic. Concretely:

| Condition | Behaviour |
| --- | --- |
| Second writer opens an in-use WAL path | Startup raises `WalWriterConflictError` |
| Strict mode without a signing key or HSM | Startup refuses |
| Strict mode with debug, auth disabled, or non-Redis limiting | Startup refuses |
| Strict mode with a configured but unavailable PKCS#11 backend | Startup refuses rather than falling back |
| Rate-limit backend unreachable | Requests fail with 503 |
| Terminal commit fails mid-stream | Terminal marker withheld |
| Analysis queue full | Enrichment rejected; the governed call still completes |

The last row is the deliberate exception: enrichment is optional, so its loss degrades analysis rather than evidence.

## 5. Where strict mode changes the architecture

Strict mode is not a hardening flag layered on top; it removes fallbacks that exist for local evaluation.

`validate_runtime_invariants()` refuses to bind sockets when debug mode is on, authentication is disabled, durable evidence is not required, the rate-limit backend is not Redis, no signing key or PKCS#11 library is configured, `mtls_required` lacks a CA bundle, or the identity HMAC key is under 32 bytes.

A deployment running in development mode has a materially different security architecture from one running in strict mode. `aegis_security_enforcement_mode` exists so that difference is observable at runtime rather than inferred from configuration files.

## 6. Cryptographic composition

| Layer | Primitive | Provides | Does not provide |
| --- | --- | --- | --- |
| Node linkage | SHA-256 over canonical fields | Tamper detection on read | Prevention of tampering |
| Node signature | HMAC-SHA256, or PKCS#11, or ML-DSA-65 | Authenticity relative to key custody | Third-party non-repudiation, for HMAC |
| Inclusion proof | MMR over hexadecimal peak bagging | Membership under a given root | Confidentiality, time, custody, non-membership |
| Anchoring | RFC 3161, S3 Object Lock | Optional external reference points | Guaranteed external immutability |

No primitive is hand-rolled. Hashing and HMAC come from Python's `hashlib`/`hmac`, asymmetric operations from `cryptography`, and native post-quantum signing from the Rust extension.

The composition has a deliberate asymmetry worth naming: **the proof is only as independent as the root you check it against.** Verifying a proof using a root fetched from the same gateway that produced the proof establishes internal consistency and nothing more. Independent trust requires obtaining the root through a separate channel.

## 7. Multi-instance architecture

Each gateway process owns one WAL path and produces one independently verifiable chain. There is no cross-process ordering, no distributed lock, and no consensus.

The Helm chart expresses this as a `StatefulSet` with one volume claim per replica. Scaling out adds independent chains; it does not extend a single chain. A customer requiring one global timeline needs a centralized writer or a reviewed merge process, neither of which exists today. See [DOC-01 §8](../institutional/DOC-01_ENTERPRISE_ARCHITECTURE.md).

## 8. What the architecture deliberately does not attempt

- **Preventing operator tampering.** Detection only. See B6.
- **Protecting data already sent upstream.** Redaction protects the record, not the provider.
- **Guaranteeing model behaviour.** The gateway governs the transaction, not the model's outputs.
- **Replacing network security.** The egress guard is application-layer. Network policy, firewalls and namespaces are yours.
- **Being a compliance product.** It produces technical inputs. Determinations are made by you and your assessor.

---

**Related:** [Security Controls](SECURITY_CONTROLS.md) · [Threat Model](THREAT_MODEL.md) · [Failure Semantics](../architecture/FAILURE_SEMANTICS.md) · [Architecture](../architecture/ARCHITECTURE.md) · [DOC-01](../institutional/DOC-01_ENTERPRISE_ARCHITECTURE.md)

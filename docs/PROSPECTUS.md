<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
-->

# Aegis Latent Core v2.4.1 — Product Prospectus

**Printable executive brief · Licensing sales deck · Technical overview**

*Prepared: June 2026 · Audience: C-Suite, CISOs, VCs, Principal Engineers, Compliance Officers*

---

## Executive Summary

Aegis Latent Core is an OpenAI-compatible governance proxy for LLM inference.
It sits between any client application and any LLM provider, applies
authentication, threat detection, and rate limiting on the request path, and
commits a SHA-256 hash-chained, post-quantum-signed, tamper-evident audit
record of every inference — without adding measurable latency to the client.

**The three-sentence pitch:**

Every AI Act regulator, HIPAA auditor, FedRAMP authorizer, and opposing
counsel in an AI-related litigation will eventually ask the same question:
*"Can you prove what your AI system received and produced, and prove the
record was not altered after the fact?"*

Standard application logs cannot answer this question cryptographically.
Aegis can.

---

## Part I — Why Aegis Was Born

### The Regulatory Cliff

Between 2024 and 2026, four major regulatory frameworks came into force that
directly govern AI systems handling sensitive decisions:

| Framework | Jurisdiction | Key AI Obligation | In Force |
|-----------|-------------|-------------------|----------|
| EU AI Act (2024/1689) | EU / EEA | Tamper-evident audit trail for high-risk AI systems (Art. 12–13) | Aug 2024 |
| NIST AI RMF 1.0 | US Federal | AI governance, traceability, documentation | Jan 2023 |
| DoD CDAO AI Policy | US DoD | Responsible AI principles, inference accountability | Nov 2022 |
| ISO/IEC 42001:2023 | Global | AI management system certification | Dec 2023 |

At the same time, existing regulations were being actively applied to AI
systems for the first time:

- **HIPAA §164.312(b)** was applied to AI diagnostic tools — requiring
  audit controls over every ePHI inference.
- **SEC Rule 17a-4** was extended to AI-generated financial communications
  — requiring WORM-compliant electronic records.
- **Daubert (Fed. R. Evid. 702)** was invoked in AI-generated evidence
  cases — requiring independently verifiable cryptographic proofs.

The infrastructure gap was identical across every vertical: organizations
were deploying LLMs without any tamper-evident record of what the model
received or returned. Standard application logs are mutable, unsigned, and
inadmissible as cryptographic proof. The forensic layer did not exist.

**Aegis was built to be that layer.**

### The Technical Gap

A forensic audit system for LLM inference must satisfy five properties
simultaneously:

1. **Zero I/O wait on the client path** — adding audit overhead to LLM
   calls (which already cost 100ms–3s) is commercially unacceptable.
2. **Tamper-evident records** — any post-hoc modification must be detectable
   by any party with the public key, without access to the live system.
3. **Post-quantum durability** — records signed today must remain
   cryptographically valid for 30+ year retention requirements under
   "harvest now, decrypt later" threat models.
4. **Zero application changes** — enterprises cannot afford to refactor
   every LLM integration point; the audit layer must be transparent.
5. **Multi-provider** — any organization running OpenAI, Anthropic, Gemini,
   Azure OpenAI, vLLM, or Ollama must be covered by the same infrastructure.

No existing solution satisfied all five. Aegis was engineered from the
ground up to satisfy all five simultaneously.

---

## Part II — The Four Architectural Pillars

### Pillar 1 — Two-Path Execution (Zero Forensic Latency)

```
Client → Auth → WAF → Rate Limit → Forward → ← Response to client
                                              ↓
                                   [Background task dispatched]
                                   ResponseAnalyzer → CryptographicAuditLedger → WAL
```

The hot path (client-visible) is: authenticate, inspect, rate-limit, forward,
return response. After `return JSONResponse(...)` sends the response to the
client, `asyncio.create_task()` dispatches the forensic audit work. The client
has already received its response; the audit commit runs in background.

**Measured overhead:** `_spawn_background()` scheduling = 2.70 µs p50,
12.90 µs p99 (measured 2026-06-25 on Intel Xeon @ 2.80 GHz, 5,000 iterations).
The client sees no I/O wait from the audit system.

### Pillar 2 — Merkle Mountain Range Hash Chain

Every inference becomes one audit node. Node construction:

```
node[i].hash = SHA-256(
    node[i-1].hash          ← chain linkage (ordering is authenticated)
  ‖ state_id               ← unique per-inference identifier
  ‖ SHA-256(request_bytes) ← what the model received
  ‖ SHA-256(response_bytes)← what the model returned
  ‖ timestamp
  ‖ tenant_id
)
```

**Chain invariant:** modifying node `i` changes its hash, which changes node
`i+1`'s hash (because `prev_hash` is the first input), which cascades to
every subsequent node. `verify_integrity()` sweeps the entire chain in O(N)
time and reports the exact index of the first tampered node.

The **Merkle Mountain Range** (MMR) adds a logarithmic proof layer: an
auditor can prove that node #10,000 existed in the chain at time T by
verifying only log₂(N) hashes — without replaying the full ledger. This
makes multi-year WORM-compliant exports tractable at scale.

**Measured throughput:** 9,310 durable commits/second (fsync per node on
spinning/NVMe storage mix, measured 2026-06-25). Offline verification sweeps
at 88,350 nodes/second.

### Pillar 3 — Post-Quantum Cryptographic Signatures (FIPS 204)

Each audit node carries two independent signatures:

| Layer | Algorithm | Purpose | Standard |
|-------|----------|---------|---------|
| **HMAC-SHA256** | Symmetric, keyed | Fast per-node signing; constant-time verify | NIST FIPS 198-1 |
| **ML-DSA-65** | Lattice-based, asymmetric | 30-year post-quantum durability | NIST FIPS 204 (Aug 2024) |

ML-DSA-65 (formerly Dilithium) uses the mathematical hardness of the Module
Learning With Errors (M-LWE) problem — believed hard for both classical and
quantum computers under current models. Key sizes: public key 1,952 bytes,
secret key 4,032 bytes, signature 3,309 bytes.

This dual-signing architecture means:
- **Today:** HMAC-SHA256 is fast enough for 9,310+ commits/second.
- **In 30 years:** when HMAC keys may be compromised, the ML-DSA-65
  public key and signature on each node still proves authenticity.
- **"Harvest now, decrypt later":** an adversary intercepting today's
  WAL file cannot forge signatures even with a future quantum computer,
  because ML-DSA-65 is post-quantum secure by construction.

### Pillar 4 — Memory-Mapped Write-Ahead Log (WAL)

The forensic record is persisted to a memory-mapped, CRC32-framed,
fsync-on-every-write WAL file. Properties:

| Property | Implementation | Why It Matters |
|---------|---------------|---------------|
| **Crash consistency** | fsync per node | No node is "in flight" across a crash |
| **Access control** | `os.chmod(path, 0o600)` at creation | WAL readable only by process owner |
| **CRC32 framing** | Per-frame checksum | `read_all()` stops at first corrupt frame; in-memory chain intact |
| **Append-only** | `mode='a'` | Physical WORM storage can enforce non-rewriteability |
| **Fault detection** | `fault_state` field in `/health` | Operators are alerted before compliance gap occurs |

The WAL is separate from the in-memory chain. An operator can archive,
rotate, and ship WAL files to cold storage independently, then re-verify
them offline with the signing key.

---

## Part III — Live Threat Detection (10 Engines)

Aegis inspects every inference request before it reaches the upstream model:

| Engine | Detection Category | Response |
|--------|-------------------|---------|
| `AegisWAF` | Prompt injection, jailbreak patterns (Aho-Corasick SIMD + regex) | 403 BLOCK |
| `YARAEngine` | Obfuscation, multi-turn jailbreak sequences | 403 BLOCK |
| `AdversarialSuffixDetector` | GCG / AutoDAN gradient-suffix attacks | 403 BLOCK |
| `ClassifiedMarkerDetector` | DoD/IC SCI/SAP classification banners in prompts | 403 BLOCK |
| `RAGInjectionScanner` | Indirect injection in retrieved content | 403 BLOCK |
| `ManyShotDetector` | Many-shot jailbreak example flooding | 403 BLOCK |
| `OTProtocolScanner` | MODBUS/DNP3/OPC-UA SCADA command injection | 403 BLOCK |
| `IOCCorrelator` | SimHash correlation against seeded threat IOCs | 403 BLOCK |
| Malware signatures | EICAR + common shell/exploit IOCs | 403 BLOCK |
| Secret leak engine | PEM keys, AWS/OpenAI/GitHub/Slack tokens, credit cards | 403 BLOCK |

WAF bypass resistance: NFKC normalization is applied to all text before
pattern matching, stripping Unicode homoglyphs (Cyrillic `о` → `o`),
zero-width characters (U+200B/C/D/E/F, U+00AD, U+FEFF), and other
canonicalization attacks. Verified by `pytest tests/test_waf*.py`.

---

## Part IV — The Threat Mitigation Boundary

### What Aegis Defends Against

- **Prompt injection / jailbreak:** WAF blocks known patterns; 10 engines in series.
- **Post-hoc audit log tampering:** SHA-256 hash chain; any modification is detected.
- **API credential abuse:** `hmac.compare_digest()` for all key comparisons (timing-attack-resistant).
- **Unicode homoglyph WAF evasion:** NFKC normalization applied before all pattern matching.
- **Per-tenant rate-limit abuse:** CAS token bucket or Redis GCRA per tenant.
- **Malware / EICAR in prompts:** signature engine blocks before forwarding to model.
- **Credential leaks in prompts:** pattern engine blocks PEM/API keys/CC numbers.
- **SCADA/OT command injection:** OTProtocolScanner blocks MODBUS/DNP3/OPC-UA.
- **HTTP request smuggling:** `RequestSmugglingProtectionMiddleware` rejects ambiguous headers.

### What Aegis Does NOT Address

| Non-Goal | Reason |
|---------|--------|
| **Content safety / harmful content filtering** | Aegis blocks known injection patterns; it does not classify arbitrary harmful content. Use a dedicated content safety layer for this. |
| **Upstream provider integrity** | Aegis cannot observe what a provider does with forwarded data after it leaves the proxy boundary. |
| **Compromised Aegis process** | If process memory or the signing key is extracted by a host-level attacker, an attacker can forge signatures. |
| **High availability / clustering** | Single-node design; no built-in WAL replication or consensus. Operators must handle HA at the infrastructure layer (load balancer + multiple instances). |
| **Post-quantum transport security** | ML-DSA-65 covers the audit record only. Transport to upstream uses standard TLS (not post-quantum). |
| **Model behavior / bias** | Aegis records what the model said; it does not evaluate whether the model's output was correct, biased, or harmful. |
| **Novel prompt injections not in the WAF ruleset** | Novel patterns not yet in the Aho-Corasick / regex set will pass through. Rule updates are shipped in patch releases. |

---

## Part V — Compliance Framework Alignment

| Framework | Control Family | Aegis Mechanism |
|-----------|---------------|----------------|
| **NIST SP 800-53 Rev 5** | AU-2, AU-3, AU-9, AU-10, AU-11 | SHA-256 hash chain, HMAC signatures, WAL 0o600, MMR proof, sealed compliance bundles |
| **FIPS 140-3 / CNSSP-15** | Approved algorithm use | ML-DSA-65 (FIPS 204), HMAC-SHA256, BLAKE3, SHA-384 |
| **FedRAMP High** | AC-2, IA-2, IA-5, SC-8, SC-13, AU-9 | mTLS/CAC-PIV, RBAC+ABAC, LDAP/AD, SCIM 2.0, post-quantum signing |
| **DoD IL5/IL6** | Compartmentalization, need-to-know | Bell-LaPadula ABAC, `ClassifiedMarkerDetector`, SCADA injection detection |
| **HIPAA §164.312(b)** | Audit controls | Every inference logged with tamper-evident chain; sealed bundle export |
| **SOC 2 Type II (CC6/CC7)** | Logical access, change management | Per-key auth, RBAC, WAF, rate limiting, integrity verification endpoint |
| **IEC 62443-3-3** | SR 6.2 audit logging | OTProtocolScanner (MODBUS/DNP3/OPC-UA), audit trail |
| **ISO/IEC 42001** | AI governance | Tamper-evident inference logs, detection engines, compliance bundle export |
| **GDPR Art. 5(2)** | Accountability | Per-tenant SHA-256 pseudonymization, scoped sealed exports |
| **SEC Rule 17a-4** | WORM electronic records | Append-only WAL; WORM-capable storage backend required from operator |
| **21 CFR Part 11** | Electronic records, signatures | Signed audit nodes with UTC timestamps; sealed PKCS#7 CMS exports |
| **Daubert (FRE 702)** | Admissibility of scientific evidence | PKCS#7 CMS SignedData, EWF/E01 forensic images, chain-of-custody metadata |

---

## Part VI — Deployment Architecture (5-Minute Install)

### Drop-In Integration (Zero Application Changes)

```python
# Before Aegis:
client = openai.OpenAI(api_key="sk-...")

# After Aegis (the only change required):
client = openai.OpenAI(
    api_key="sk-aegis-your-proxy-key",
    base_url="http://aegis:8080/v1",   # ← one line changed
)
```

### Docker Compose (Simplest)

```bash
cp .env.example .env && $EDITOR .env  # Set API keys
docker compose -f deploy/docker/docker-compose.yml up -d
curl -sf http://localhost:8080/health   # → {"status":"healthy"}
```

### Enterprise Docker Compose (Production-Hardened)

```bash
cp config/presets/<your-vertical>.env .env && $EDITOR .env
docker compose -f deploy/docker/docker-compose.enterprise.yml up -d
```

Includes: TLS Redis, Aegis compliance exporter, Prometheus, non-root
execution, read-only filesystem, capability drop.

### Kubernetes (Helm)

```bash
helm install aegis deploy/helm/ \
  --set aegis.backendUrl=https://api.openai.com \
  --set aegis.existingSecret=aegis-keys
```

Includes: PodDisruptionBudget, TopologySpreadConstraints (multi-AZ),
HPA, Prometheus SLO alerting, signed SBOM per release.

### Compliance Preset Selection

| Vertical | Preset File | Key Settings Activated |
|---------|------------|----------------------|
| FinReg (SEC/FINRA/MiFID II) | `config/presets/finreg.env` | WORM labels, mTLS, tight KL threshold |
| Healthcare (HIPAA/21 CFR) | `config/presets/healthcare.env` | PHI de-identification, BAA note |
| FedRAMP / DoD IL5 | `config/presets/fedramp.env` | Bell-LaPadula ABAC, mTLS, classified markers, seccomp |
| Forensic / Judicial | `config/presets/judicial.env` | Large memory chain, PKCS#7 / EWF/E01 export |
| Engineering | `config/presets/engineering.env` | Max throughput, relaxed thresholds, uvloop |
| Scientific | `config/presets/scientific.env` | logprobs required, determinism docs |
| SMB / General | `config/presets/smb.env` | SQLite WAL, asyncio rate limiter, no TLS required |

---

## Part VII — Pricing & Licensing Tiers

Aegis is dual-licensed: **AGPLv3** (open-source, network-use disclosure
required) and a **Commercial License** (eliminates all copyleft obligations).

See [`COMMERCIAL.md`](../COMMERCIAL.md) for the full terms. Summary:

| Tier | Who It Serves | Annual Investment | SLA |
|------|-------------|-------------------|-----|
| **Evaluation** | PoC, sandbox, non-production | Free | Best-effort email |
| **Startup** | Single-org, < 1M req/mo | $9,900 | 72h security patches |
| **Self-Serve Enterprise** | Mid-market, automated compliance exports | $29,900 | 48h critical CVE; doc portal; no direct-access SLA |
| **Premium Sovereign** | Gov/DoD, air-gapped, mission-critical | $150,000+ | P1: 4h ack; direct founder; quarterly briefing |
| **OEM / Embedded** | Redistribution, white-label | Negotiated | Per MSA |

### The AGPL Forcing Function

AGPL §13 requires organizations that modify and operate Aegis over a network
to make their complete corresponding source available to network users — including
proprietary prompt engineering, custom WAF rules, and internal configuration.
Organizations that cannot meet this obligation must obtain a commercial license.
There is no third path.

### Procurement

Email: **juan.c.luna04@gmail.com**

Include: company name, deployment model (SaaS/on-prem/air-gap), request
volume, vertical, compliance frameworks in scope, desired tier, and
procurement vehicle (direct / GSA / OTA / SEWP V).

---

## Part VIII — Verified Performance (2026-06-25)

All numbers are from actual execution on the development host. No numbers
are invented. See [`docs/BENCHMARKS.md`](BENCHMARKS.md) for full methodology.

**Hardware:** Intel Xeon @ 2.80 GHz · 4 cores · Linux 6.18 x86_64

| Metric | Measured Value |
|--------|---------------|
| `_spawn_background()` scheduling (p50) | **2.70 µs** |
| `_spawn_background()` scheduling (p99) | **12.90 µs** |
| WAF+HTTP round-trip — WITH background (p50) | **0.654 ms** |
| WAF+HTTP round-trip — WITHOUT background (p50) | **0.614 ms** |
| Δp50 (forensic scheduling overhead) | **+39.75 µs** (Cohen's d = 0.39, small effect) |
| Audit commit throughput (fsync per node) | **9,310 nodes/s** |
| HMAC-SHA256 signing (crypto-only) | **242,600 ops/s** (4.1 µs/op) |
| Chain verification sweep | **88,350 nodes/s** (11.3 µs/node) |
| Test suite | **5,451 passed · 5 skipped** |
| Branch coverage | **95.18%** |
| Simulation debt | **0 modules** |

---

## Part IX — Contact & Next Steps

**To start a commercial evaluation:**

1. Email `juan.c.luna04@gmail.com` with your company name, vertical, and
   desired tier.
2. Receive evaluation license key (valid 30 days, 10,000 node cap).
3. Deploy in 5 minutes: `bash scripts/install_aegis.sh --dir /opt/aegis`
4. Run self-serve diagnostics: `python tools/forensic/diagnose_aegis.py`
5. Integration validation: `python scripts/integration_test_mock.py --sweep`

**Technical documentation:**

| Document | Audience | Link |
|---------|---------|------|
| Architecture Deep Dive | Principal Engineers | [`docs/architecture/DEEP_DIVE.md`](architecture/DEEP_DIVE.md) |
| Threat Model | Security Teams | [`docs/security/THREAT_MODEL.md`](security/THREAT_MODEL.md) |
| Scaling Guide | SRE / Platform | [`docs/performance/SCALING_GUIDE.md`](performance/SCALING_GUIDE.md) |
| Benchmarks | Performance Engineers | [`docs/BENCHMARKS.md`](BENCHMARKS.md) |
| Roadmap | Stakeholders | [`docs/ROADMAP.md`](ROADMAP.md) |
| Commercial Terms | Legal / Finance | [`COMMERCIAL.md`](../COMMERCIAL.md) |

---

*Aegis Latent Core v2.4.1 · Copyright © 2026 Juan Luna. All rights reserved.*
*AGPLv3 open-source · Commercial licenses available — see COMMERCIAL.md*

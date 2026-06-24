
# Security Policy

## Supported Versions

| Version | Supported          |
| :------ | :----------------- |
| 2.4.x   | ✅ Active           |
| 2.3.x   | ⚠️ Security patches only |
| 2.2.x   | ⚠️ Security patches only |
| 2.1.x   | ❌ End of life      |
| 2.0.x   | ❌ End of life      |
| < 2.0   | ❌ End of life      |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Use [GitHub Security Advisories](https://github.com/JuanLunaIA/aegis-latent-core/security/advisories/new) on the **JuanLunaIA/aegis-latent-core** repository. For sensitive disclosures, contact the maintainer through GitHub private channels.

### Response Timeline

| Milestone              | Target           |
| :--------------------- | :--------------- |
| Acknowledgment         | 48 hours         |
| Severity assessment    | 5 business days  |
| Mitigation or plan     | 14 days (critical: 7 days) |
| Public disclosure      | After patch ships |

We follow coordinated disclosure. Reports may be credited in the changelog unless the reporter requests anonymity.

---

## Deployment Security Checklist

### Authentication

- Always set `AEGIS_API_KEYS` in production. Never set `AEGIS_AUTH_DISABLED=true` outside local development.
- Use a high-entropy signing key: `python -c 'import secrets; print(secrets.token_hex(32))'` and store the output in `AEGIS_SIGNING_KEY`. An empty or missing signing key causes audit nodes to fall back to ephemeral Ed25519 keys, reducing legal admissibility to `"Compromised"`.
- Restrict audit API access with separate `AEGIS_AUDIT_API_KEYS` (read-only principals should not share keys with write paths).

### TLS / mTLS (v2.3.0+)

- Enable TLS termination at the Aegis layer for any deployment that does not place it behind a TLS-terminating proxy:
  ```env
  AEGIS_SSL_CERTFILE=/etc/certs/server.crt
  AEGIS_SSL_KEYFILE=/etc/certs/server.key
  ```
- To enforce mutual TLS (require a client certificate from callers):
  ```env
  AEGIS_MTLS_REQUIRED=true
  AEGIS_SSL_CA_CERTS=/etc/certs/client-ca.crt
  ```
- To use a custom CA bundle when connecting to an upstream LLM provider:
  ```env
  AEGIS_SSL_CA_CERTS=/etc/certs/upstream-ca.crt
  ```
  If `AEGIS_MTLS_REQUIRED=true` but `AEGIS_SSL_CERTFILE` and `AEGIS_SSL_KEYFILE` are not set, Aegis logs a `WARNING` and proceeds without a client certificate.

### Secrets Management

- Never commit `.env`, PEM files, or any `*.wal.jsonl` file containing real audit data to version control.
- Rotate `AEGIS_SIGNING_KEY` using a documented key-rotation procedure; an unannounced rotation will break the HMAC chain. Document the rotation event in your chain-of-custody notes.
- Use `AEGIS_DEBUG_MODE=false` (default) in all non-development environments. Debug mode exposes `/docs`, `/redoc`, and `/openapi.json`.

### LSM Hardening (v2.3.0+)

As of v2.3.0, the LSM guard runs in **advisory mode**: missing AppArmor or SELinux profiles emit a `WARNING` but do not crash the server. For hardened deployments requiring hard LSM enforcement:

1. Load an AppArmor or SELinux profile before starting Aegis.
2. Verify confinement externally: `aa-status` (AppArmor) or `getenforce` (SELinux).
3. Use a process supervisor or init system that fails the unit on non-zero exit if enforcement is mandatory for your threat model.

### Entropy & WAF Tuning

- Tune `AEGIS_ENTROPY_ALERT_THRESHOLD_BITS` to match your model's expected entropy range before deploying alerting integrations.
- In high-security environments, set `AEGIS_WAF_STRICT_MODE=true`. In strict mode, the WAF applies hard blocks on critical injection patterns regardless of score threshold.
- KL divergence and Jensen-Shannon divergence thresholds (`AEGIS_KL_ALERT_THRESHOLD`, `AEGIS_JS_ALERT_THRESHOLD`) are now respected at runtime via `AegisSettings` (fixed in v2.3.0); verify your values if upgrading from v2.2.0.

### Network Exposure

- Bind to `127.0.0.1` or a private interface unless a load balancer or ingress controller handles public-facing TLS termination.
- Restrict `/v1/audit/*` endpoints to trusted internal networks or require `AEGIS_AUDIT_API_KEYS`.
- The visualizer server (`tools/visualizer/`) is a local development tool. Never expose it to public networks.

---

## Simulated vs. Real Controls

Aegis ships **no simulated security controls**. A 2026-06-24 full-tree audit found
~20% of `aegis/core` modules returning success without performing the advertised
function (fake PQC signatures, hardcoded enclave measurements, randomly-generated
"telemetry", etc.). Every one has since been replaced with a real implementation
or an honest, hardware-gated stub that **fails closed** when its dependency is
absent — never fabricating assurance. This is enforced two ways:

- **Regression ratchet** — `tests/test_no_simulation_markers.py` fails CI if any
  `aegis/` module reintroduces a simulation marker (`KNOWN_SIMULATION_DEBT` is
  empty and the test asserts the count stays `0`).
- **Live capability report** — `GET /v1/attestation/capabilities` (behind audit
  auth) reports each control's status in the running deployment as `REAL`,
  `UNAVAILABLE`, or `SIMULATED`, with a `simulation_debt` count that must be `0`.

Many controls depend on hardware or external tooling. Where that dependency is
absent, the control reports `UNAVAILABLE` and refuses to run — it does **not**
silently degrade to a fake. The matrix below shows each control, its dependency,
and what it does when the dependency is missing.

| Control | Module | Requires | When dependency absent |
| :------ | :----- | :------- | :--------------------- |
| ML-DSA-65 signing | `pqc_signer` | Rust `aegis_rust` ext | `UNAVAILABLE`; `sign()` raises (no fake signature) |
| Audit signing (HMAC-SHA256) | `crypto_audit` | stdlib | always `REAL` |
| Hybrid PQC TLS (X25519+ML-KEM) | `pqc_tls` | `cryptography` + ML-KEM | refuses classical-only downgrade |
| Seccomp syscall filter | `sandbox_l1` | libseccomp | `UNAVAILABLE`; filter not loaded |
| TPM PCR root-of-trust | `tpm` | tpm2-tools + TPM device | labelled **software** PCR (not a hardware RoT) |
| Trusted-boot attestation | `boot_attestation` | signed vendor manifest + TPM | manifest signature always verified; live PCR check needs a TPM |
| Hardware-bound session tokens | `hardware_token` | TPM device + tpm2-tools | software HMAC binding (no PCR seal) when TPM/tools absent |
| TEE enclave attestation | `tee_manager` / `enclave_provider` | SGX/SEV/TDX device | `UNAVAILABLE`; operations raise |
| eBPF runtime monitor | `ebpf_monitor` | `bpftool` + CAP_BPF | probes stay inactive; no fabricated telemetry |
| DPDK kernel-bypass datapath | `dpdk_engine` | hugepages + dpdk-devbind | `UNAVAILABLE`; no packets (no fake packets) |
| Dynamic firewall segmentation | `xdp_dynamic_segmentation` | nftables/iptables | application-layer only (no kernel drop) |
| CFI binary inspection | `cfi_manager` | pyelftools / readelf | `UNAVAILABLE` |
| MTE detection | `mte_guard` | ARM MTE hardware | honest `False` on x86/non-ARM |
| Fuzzing harness | `fuzzing_harness` | `cargo` + cargo-fuzz | `UNAVAILABLE` (no fake clean run) |
| Dependency CVE audit | `dependency_audit` | `pip-audit` | raises (no fake clean result) |
| Reproducible-build verify | `build_reproducibility` | `cargo` | raises (no fake match) |
| Transparency log | `transparency_log` | stdlib (JSONL) | always `REAL` |
| Public root anchoring | `blockchain_anchor` | configured anchor backend (RFC3161/OTS) | `publish_root` fails closed — never fabricates a tx/proof |

> The `zk_proof` audit-inclusion proof is still an honest stub (it sets
> `is_stub == True` and does not claim ZK soundness); integrating a real proving
> system is tracked in `docs/ROADMAP.md` (DX-Forensic).

---

## Known Security-Relevant Fixes

| Version | Fix | Severity |
| :------ | :-- | :------- |
| 2.4.0 | `aegis_server.crypto` eagerly imported `hvac` at package level, breaking the HMAC-only compliance export path on installs without the optional `vault` extra; `VaultSigner` is now lazy-imported | Low |
| 2.3.0 | mTLS settings were defined in `AegisSettings` but never applied to the uvicorn listener or the upstream `httpx` client | High |
| 2.3.0 | `ResponseAnalyzer` thresholds were hardcoded, ignoring `AegisSettings`; alerting could not be tuned at runtime | Medium |
| 2.2.0 | Audit chain signing key derived from the first sorted API key; unannounced rotation silently invalidated the chain | High |
| 2.2.0 | `/docs` and `/redoc` exposed unconditionally in all deployment modes | Medium |
| 2.2.0 | `prev_hash` always pointed to the genesis node due to wrong `ORDER BY` direction in `list_nodes()` | Critical |
| 2.2.0 | Concurrent `BackgroundTask` writes could fork the audit chain (no chain lock) | Critical |

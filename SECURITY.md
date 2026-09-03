# Security Policy — Aegis Latent Core 4.0.x

This policy defines the vulnerability-reporting path, support boundary, production security baseline, runtime evidence rules and release security gates. It is for security researchers, customers, maintainers and operators. It is not a contractual SLA, certification, legal opinion or guarantee of future remediation.

**Last verified:** 2026-08-27 UTC
**Release baseline:** current source/release candidate
**Current candidate/source line:** `4.1.1` with fourteen synchronized anchors; supported as the current source line without asserting external publication
**Historical external baseline:** signed annotated `v4.0.2` tag at `a6eb58dcc03f8b638c8f3e35f0300f5443a926ca`, with GitHub Release and GHCR gateway/dashboard images read back on 2026-09-02; before it, lightweight `v4.0.1` at `6469904380218584ae0b5221334bc9a46500f5ba` with failed tag workflows; PyPI/npm observed at `4.0.0` without attributed provenance
**Private reporting path:** GitHub Private Vulnerability Reporting

## Scope and support posture

Aegis Latent Core is security-sensitive infrastructure. The repository provides defensive controls and evidence paths; it does not certify a deployment, replace customer security governance, or establish legal admissibility.

| Version line | Support status |
|---|---|
| `4.1.x` | Current candidate and supported source line (`4.1.1`); nothing is published for it. Support does not assert an external `v4.1.1` tag, release, or package publication. |
| `4.0.x` | Most recently published line (`v4.0.2` tag, GitHub Release and GHCR images). SDK registries remain at `4.0.0`. |
| `3.1.x` | Historical v3.1.0 market-hardening line; fixes remain subject to the project's actual operating capacity and supported-version policy. |
| `3.0.x` | Published v3.0.1 baseline. Upgrade to the candidate line for new hardening; security fixes remain subject to the project’s actual operating capacity. |
| `<3.0.0` | Historical releases. Upgrade before requesting support; no default security-fix commitment is made. |

The current supported source line is `4.1.x`, with candidate `4.1.1` and fourteen synchronized anchors. External `v4.1.1` publication is not claimed until tag, release, and registry readback succeeds; no such readback has been performed, because nothing has been published for `4.1.1`. The most recent published line is `4.0.x`: the signed annotated tag `v4.0.2` targets `a6eb58dcc03f8b638c8f3e35f0300f5443a926ca`, and its GitHub Release and GHCR images were read back on 2026-09-02. The previous public GitHub baseline is lightweight tag `v4.0.1` targeting `6469904380218584ae0b5221334bc9a46500f5ba`; its tag workflows failed, while PyPI/npm were separately observed at `4.0.0` without attributed provenance. Release support must be evaluated from published artifacts, while source behavior must be evaluated from the named commit, tests, and deployment prerequisites.

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.** Use [GitHub Private Vulnerability Reporting](https://github.com/JuanLunaIA/aegis-latent-core/security/advisories/new) when available. If that path is unavailable, use the maintainer contact shown in the repository profile and include only the minimum reproduction data required for triage. Do not send credentials, customer data, live targets, or secrets.

Please include the affected release or commit, deployment boundary, prerequisites, reproducible steps in an authorized environment, impact, and any safe mitigation. Reports may be credited in release notes unless anonymity is requested.

The following are target response objectives for coordinated disclosure, not a contractual SLA until a support agreement names an accountable operations owner:

| Milestone | Target |
|---|---|
| Acknowledgment | 2 business days |
| Initial severity assessment | 5 business days |
| Mitigation or remediation plan | 14 days; 7 days for confirmed critical impact where a safe mitigation exists |
| Public disclosure | After a fix or coordinated disclosure decision |

## Dependency and supply-chain policy

The repository uses pinned dependency resolution, an SBOM, vulnerability scans, and release provenance. CI should block on known critical/high vulnerabilities when a fix is available and must record justified exceptions when upstream remediation does not yet exist. Each exception requires an owner, rationale, compensating control, review date, and removal condition.

Release reviewers should verify `requirements.lock`, `Cargo.lock`, the SPDX SBOM, action references, container base images, and the release asset manifest. A clean scan is evidence about the scanned dependency set at a point in time; it is not a perpetual absence-of-vulnerability guarantee.

## Production security baseline

Strict mode is the production-oriented posture. It requires authentication, durable evidence, strong signing, bounded request bodies, distributed rate limiting, durable storage, and the configured kernel controls. Development or sandbox modes must be explicit and must not be used as production evidence.

The minimum deployment controls are:

```env
AEGIS_SECURITY_ENFORCEMENT_MODE=strict
AEGIS_API_KEYS=<secret-manager-managed-value>
AEGIS_REQUIRE_DURABLE_EVIDENCE=true
AEGIS_REQUIRE_DISTRIBUTED_LIMITER=true
AEGIS_RATE_LIMIT_BACKEND=redis
AEGIS_REDIS_URL=rediss://redis.internal:6380/0
AEGIS_REQUIRE_LSM=true
AEGIS_REQUIRE_SECCOMP=true
AEGIS_MAX_REQUEST_BODY_BYTES=1048576
AEGIS_DEBUG_MODE=false
```

Use a secret manager or approved HSM/Vault integration. Never commit `.env` files, PEM files, bearer tokens, provider credentials, raw WAL records, or customer payloads. Restrict WAL and keyring files to the service owner and preserve them read-only during incident handling.

## Signing and key rotation

HMAC-SHA256 is symmetric and classical. It is suitable only when the deployment accepts shared-secret verification and has a documented custody model. For key rotation, use [`docs/operations/KEY_ROTATION_RUNBOOK.md`](docs/operations/KEY_ROTATION_RUNBOOK.md) and the versioned keyring implementation. The keyring uses one active key, historical verify keys with explicit expiry, atomic reload, and non-secret `key_id` metadata. A malformed replacement must leave the prior valid snapshot active or fail closed; it must never produce an unsigned record.

The native ML-DSA-65 path is available only when the real Rust extension is present. It does not silently return a simulated signature. Native availability is not a claim of constant-time execution, FIPS 140 validation, or legal admissibility. The timing assessment boundary is documented in [`docs/security/PQC_CONSTANT_TIME.md`](docs/security/PQC_CONSTANT_TIME.md).

## Network and ingress boundary

Terminate TLS at a controlled ingress or at Aegis and document which component owns HTTP/2 parsing and normalization. Use mTLS where the customer threat model requires caller certificates. Configure upstream TLS validation and egress allowlists. Application-layer endpoint validation does not replace firewall policy, network namespaces, Kubernetes NetworkPolicy, cloud IAM, or provider-side controls.

The WAF operates at the application boundary. The pinned local corpus and its limitations are documented in [`docs/security/WAF_TESTING.md`](docs/security/WAF_TESTING.md). HTTP/2 fragmentation and ingress parser differential tests remain a separate acceptance requirement.

## Runtime evidence and sample material

Aegis runtime evidence must come from live control paths, test fixtures, or retained benchmark artifacts. `Samples/01-overview.html` is a static dashboard demo and may contain synthetic display values to illustrate layout and interaction. Its values, hashes, counts, provider names, and timestamps must never be presented as production telemetry, customer activity, cryptographic proof, or release evidence.

The repository’s real-vs-unavailable contract is fail-closed for security-sensitive capabilities. When a dependency such as native ML-DSA, Seccomp, an HSM, a TPM, or an external audit tool is absent, the capability must report unavailable or refuse the operation. A demo sample is not an exception to this rule because it is not on the governed runtime path.

## Security-relevant release gates

A release is blocked when a governed accepted response lacks durable evidence in the declared scope, chain verification fails, a critical WAF corpus case bypasses, a valid rotation loses or invalidates a record, a security scan fails without a reviewed exception, a runtime control is absent in strict mode, or public documentation overstates the evidence. Release artifacts must include tests, SBOM, provenance, hashes, rollback instructions, and residual risks.

## Security assurance roadmap

The external-assurance sequence is maintained in [`docs/SECURITY_ASSURANCE_ROADMAP.md`](docs/SECURITY_ASSURANCE_ROADMAP.md). It separates repository evidence from independent code review, penetration testing, crypto review, disaster-recovery evidence, customer pilot results, and certification or attestation work owned by qualified external parties.

## License and disclosure caveat

The project is licensed under [`LICENSE`](LICENSE) and [`COMMERCIAL.md`](COMMERCIAL.md). License interpretation, contractual remedies, regulatory obligations and legal strategy require counsel in the applicable jurisdiction.

## Related documents

- [`README.md`](README.md)
- [`docs/CLAIMS_MATRIX.md`](docs/CLAIMS_MATRIX.md)
- [`docs/security/THREAT_MODEL.md`](docs/security/THREAT_MODEL.md)
- [`docs/security/WAF_TESTING.md`](docs/security/WAF_TESTING.md)
- [`docs/security/PQC_CONSTANT_TIME.md`](docs/security/PQC_CONSTANT_TIME.md)
- [`docs/operations/ROLLBACK_RUNBOOK.md`](docs/operations/ROLLBACK_RUNBOOK.md)
- [`COMMERCIAL.md`](COMMERCIAL.md)

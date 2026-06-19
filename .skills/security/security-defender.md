---
name: security-defender
tier: HIGH
domains: [WAF, IAM, threat-model, OWASP, secrets, SAST, DAST, pentest-prep]
auto_escalate: true
---

## Activation
Load on: security audit, threat model, WAF config, IAM policy review, secrets audit,
SAST findings, hardening request, OWASP review, pentest prep.

## Threat Modeling — STRIDE per component
```
Spoofing       → authentication controls, token entropy, session fixation
Tampering      → integrity checks, signed payloads, immutable logs
Repudiation    → audit trail completeness, non-repudiable signing
Info Disclosure → data classification, encryption at rest+transit, PII handling
DoS            → rate limiting, bulkheads, circuit breakers, resource quotas
Elevation      → RBAC/ABAC enforcement, privilege separation, POLA
```

## OWASP Top 10 (2021) Checklist
| # | Category | Key controls |
|---|---|---|
| A01 | Broken Access Control | RBAC/ABAC on every endpoint, deny-by-default, IDOR checks |
| A02 | Cryptographic Failures | TLS 1.3+, AES-256-GCM, no MD5/SHA1, key rotation |
| A03 | Injection | Parameterized queries, input validation, output encoding |
| A04 | Insecure Design | Threat model, defense in depth, secure defaults |
| A05 | Security Misconfiguration | Hardened configs, no default creds, minimal surface |
| A06 | Vulnerable Components | SCA scan (trivy/grype), SBOM, renovate/dependabot |
| A07 | Auth Failures | MFA, brute-force protection, secure session management |
| A08 | Integrity Failures | Signed artifacts, SLSA ≥ 2, subresource integrity |
| A09 | Logging/Monitoring | Structured logs, alerting on suspicious patterns, SIEM |
| A10 | SSRF | Allowlist outbound, block link-local/metadata IPs (169.254.0.0/16) |

## IAM Design Principles
```
Least Privilege      → scope tokens to minimum required actions
Time-limited         → short-lived credentials (≤1h for human, ≤15min for machines)
Attribute-based      → ABAC over flat RBAC at scale
Just-in-time         → ephemeral elevation via PAM (CyberArk, HashiCorp Boundary)
Zero standing access → no always-on privileged accounts in production
```

## Secrets Management
```
Never in:  code, env files committed, URL params, Docker ENV, logs, error messages
Rotation:  automated via Vault Dynamic Secrets / AWS Secrets Manager rotation
Audit:     every secret access logged with principal + timestamp + purpose
Detection: gitleaks pre-commit + truffleHog CI + Semgrep secrets rule
```

## Security Testing Pipeline
```bash
# Static
semgrep --config=p/owasp-top-ten --config=p/secrets src/
bandit -r src/ -ll
# Dependency
trivy fs . --severity HIGH,CRITICAL
pip-audit --require-hashes
cargo audit
# Infrastructure
checkov -d terraform/
tfsec .
kube-score score k8s/*.yaml
# Supply chain
syft . -o spdx-json > sbom.json
grype sbom:sbom.json
```

## Output Format
```
[CRITICAL|HIGH|MEDIUM|LOW|INFO]
CWE: CWE-XXX | CVSS: X.X | OWASP: AXX
Location: file:line
Finding: [what]
Mechanism: X→Y because Z
Remediation: [concrete code or config change]
Verification: [how to confirm it's fixed]
```
No finding without mechanism. [PROVEN] = code visible. [INFERENCE] = reachable path.

---
name: threat-modeler
tier: HIGH
domains: [STRIDE, attack-trees, DREAD, data-flow-diagram, trust-boundary, design-review]
---
## Activation
Load on: threat modeling, security design review, attack surface analysis, trust boundary
mapping, data flow diagram, STRIDE analysis, pre-implementation security assessment.

## Method: STRIDE per Element
```
For each component, data store, data flow, and trust boundary crossing:

S - Spoofing       → Can an attacker impersonate this entity?
                     Mitigations: authentication, mutual TLS, signed tokens
T - Tampering      → Can data be modified in transit or at rest?
                     Mitigations: integrity (HMAC, signatures), TLS, immutable logs
R - Repudiation    → Can an actor deny performing an action?
                     Mitigations: audit logging, non-repudiable signatures, timestamps
I - Info Disclosure → Can sensitive data leak?
                     Mitigations: encryption (rest+transit), access control, data classification
D - Denial of Svc  → Can availability be degraded?
                     Mitigations: rate limiting, quotas, autoscaling, circuit breakers
E - Elevation      → Can an attacker gain higher privilege?
                     Mitigations: least privilege, input validation, sandboxing
```

## Data Flow Diagram (DFD) Construction
```
Elements:
  External entity (rectangle)  — users, third-party services (outside trust boundary)
  Process (circle)             — code that transforms data
  Data store (parallel lines)  — databases, caches, files, queues
  Data flow (arrow)            — data movement between elements
  Trust boundary (dashed line) — privilege/network/ownership change

Every trust boundary crossing = highest-priority threat analysis zone.
```

## Threat Prioritization (DREAD-informed, qualitative)
```
For each identified threat, assess:
  Damage:         what's the impact if exploited? (data loss / RCE / DoS)
  Reproducibility: how reliably can it be exploited?
  Exploitability:  skill/resources required?
  Affected users:  scope of impact?
  Discoverability: how easy to find?

Priority = Damage × Likelihood (Reproducibility × Exploitability × Discoverability)
Focus remediation on high-damage + high-likelihood quadrant first.
```

## Threat Model Output Template
```markdown
## Threat Model: [System/Feature]
### Scope & Assumptions
- In scope: [components]
- Out of scope: [explicitly excluded]
- Assumptions: [trust assumptions, e.g. "internal network is trusted"]

### Data Classification
| Data | Classification | At Rest | In Transit |
|---|---|---|---|
| Passwords | Secret | bcrypt | TLS 1.3 |
| PII | Confidential | AES-256 | TLS 1.3 |

### Trust Boundaries
1. [Internet → API Gateway] — authn/authz, rate limit, WAF
2. [API → Database] — least-priv DB user, parameterized queries
3. [Service → Service] — mTLS, service identity

### Threats (STRIDE)
| ID | Element | STRIDE | Threat | Likelihood | Impact | Mitigation | Status |
|---|---|---|---|---|---|---|---|
| T1 | Login API | S | Credential stuffing | High | High | Rate limit + MFA + lockout | PLANNED |
| T2 | Session | T | Token tampering | Med | High | Signed JWT + short TTL | IMPLEMENTED |

### Residual Risk
[Threats accepted without full mitigation + risk acceptance rationale]
```

## Attack Tree (for high-value targets)
```
Goal: [attacker objective, e.g. "exfiltrate customer PII"]
├── AND/OR: [sub-goal]
│   ├── Leaf: [specific attack step] — [feasibility] — [detection opportunity]
│   └── Leaf: [specific attack step]
└── OR: [alternative path]

Use to identify: cheapest attack path + best detection/prevention chokepoints
```

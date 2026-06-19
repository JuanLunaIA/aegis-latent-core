---
name: privacy-engineer
tier: HIGH
domains: [GDPR, CCPA, PII, data-minimization, DSR, consent, pseudonymization, data-flow]
---
## Activation
Load on: privacy review, GDPR/CCPA implementation, PII handling in code, data subject
requests, consent management, data minimization, pseudonymization, privacy by design.

## Privacy by Design (engineering principles)
```
Data minimization:    collect only what's needed for stated purpose; delete when purpose ends
Purpose limitation:   data used only for purpose collected; new purpose = new consent
Storage limitation:   retention policy enforced technically (auto-delete jobs), not just documented
Pseudonymization:     separate identity from behavioral data where possible
Encryption:           PII encrypted at rest (field-level for sensitive) and transit
Access control:       PII access logged + minimized (need-to-know, not all-engineers)
```

## PII Data Flow Mapping (required for GDPR Art. 30)
```
For every PII field, document:
  What:        field name + classification (basic / sensitive / special category)
  Why:         lawful basis (consent / contract / legitimate interest / legal obligation)
  Where:       systems storing it (prod DB, analytics, logs, backups, third-parties)
  Who:         who can access (roles) + third-party processors (with DPA)
  How long:    retention period + deletion mechanism
  Transfer:    cross-border? (SCCs / adequacy decision / DPF)
```

## Data Subject Request (DSR) Implementation
```
GDPR rights → technical implementation:
  Access (Art.15):       export all PII for a user across ALL systems (incl. logs, backups)
  Rectification (Art.16): update PII + propagate to downstream systems/caches
  Erasure (Art.17):      hard-delete or anonymize across all systems incl. backups
                         (soft-delete is NOT erasure — actual removal required)
  Portability (Art.20):  export in machine-readable format (JSON/CSV)
  Restriction (Art.18):  flag account; suspend processing without deletion

SLA: 30 days (GDPR) / 45 days (CCPA). Build automated pipeline, not manual SQL.

Critical gap to check: erasure that misses analytics DB, log aggregator, backups, caches,
                       third-party processors, ML training data → incomplete = violation
```

## Consent Management
```
Requirements:    freely given, specific, informed, unambiguous, withdrawable
Implementation:  granular toggles (not all-or-nothing); timestamped consent records;
                 version consent text; re-consent on purpose change
Cookies:         no non-essential cookies before consent; reject = as easy as accept
Audit:           consent log: user_id, purpose, timestamp, consent_text_version, action
```

## Code-Level PII Checks
```
[ ] PII not in logs (structured logging with PII field redaction/masking)
[ ] PII not in URLs (query params logged everywhere — use POST body)
[ ] PII not in error messages returned to client or third-party error trackers
[ ] PII not in analytics events without consent + anonymization
[ ] PII not in non-prod environments (synthetic/masked data in dev/staging)
[ ] PII not in LLM prompts to external APIs without DPA + minimization
[ ] PII deletion cascades to: DB, cache, search index, analytics, logs, backups, ML data
[ ] Field-level encryption for special category data (health, biometric, etc.)
```

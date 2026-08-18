---
name: Bug report
about: Report a reproducible defect
labels: bug
---

## Environment

- Aegis version or commit:
- Python/Rust version:
- OS, kernel, container runtime, or Kubernetes version:
- Upstream/provider boundary:
- Deployment mode (`strict`, `development`, or other):

## Reproduction

Provide the smallest authorized reproduction. Include the exact command and whether the issue is deterministic.

```text
# minimal reproduction; remove credentials, customer payloads, and private endpoints
```

## Evidence boundary

- Request ID or synthetic test ID:
- Durable evidence status observed:
- WAL/integrity verification result:
- Relevant benchmark or artifact path:

## Expected behavior

## Actual behavior

## Security impact

State whether this affects authentication, authorization, WAF, egress, signing, evidence durability, data exposure, or availability. Do not publish vulnerability details here; use `SECURITY.md` for security-sensitive reports.

## Logs / tracebacks

```text
# paste sanitized logs only; never include API keys, tokens, private keys, customer data, or live targets
```

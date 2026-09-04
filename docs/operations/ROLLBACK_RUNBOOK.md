# Rollback Runbook — Aegis Latent Core v4.1.2 Source Baseline

This runbook is for release operators and incident commanders who must stop or revert an Aegis deployment without destroying evidence continuity. It covers decision gates, preservation, rollback execution, verification, and escalation. It does not replace the customer's incident-response, legal-hold, disaster-recovery, or change-management process.

**Last verified:** 2026-08-27 UTC
**Release baseline:** four-layer truth model
**Source baseline/release target:** `v4.1.2` with 14 synchronized anchors; source metadata does not establish external lifecycle state; the `v4.1.2` tag, GitHub Release, PyPI, npm, OCI digest and signature objects were read back on 2026-09-04 and are recorded in `docs/RELEASE_STATUS.md` §1.0; `cosign verify` and `gh attestation verify` were not run
**Immutable comparison source:** `fdace8844568eb788216740b2cb5daf187d99d3b` with `4.0.0` anchors
**Previous public GitHub Release:** `v4.0.1` lightweight tag targeting `6469904380218584ae0b5221334bc9a46500f5ba`
**Observed registries:** PyPI/npm `4.0.0`, without workflow provenance attribution
**Historical evidence baseline:** retained `v3.1.0` evidence remains historical and is not a `v4.1.2` result
**Audience:** Release operators, SRE and incident commanders
**Related policy:** [`SECURITY.md`](../../SECURITY.md)

## Rollback principles

Rollback is a controlled state transition. Preserve the original WAL bytes, release metadata, key IDs, configuration snapshot, logs, metrics and operator actions before changing the runtime. A rollback that restores availability but loses the evidence chain is not a successful rollback.

| Principle | Required behavior |
|---|---|
| Preserve | Copy or snapshot original evidence read-only before mutation |
| Identify | Record current image digest, tag, commit, configuration version and signer key ID |
| Bound | Declare blast radius, affected replicas, time window and customer impact |
| Revert | Use a previously verified image digest and compatible schema |
| Verify | Run integrity, health, readiness and governed-request checks after rollback |
| Escalate | Notify security, privacy/legal and release owners when evidence or data handling is affected |

## Kill criteria

Initiate a controlled rollback or traffic stop when any of the following is observed:

1. A governed successful response lacks a verifiable durable evidence record in the declared scope.
2. `verify_integrity()` fails for an active or newly restored evidence segment.
3. A required signer becomes unavailable, uses an unauthorized fallback, or loses key overlap during rotation.
4. A critical WAF corpus case bypasses or a benign corpus case is newly blocked without approved change.
5. Strict startup detects missing Seccomp, LSM/AppArmor/SELinux, authentication, Redis or durable-storage prerequisites.
6. WAL synchronization or storage errors create an unbounded queue or evidence timeout.
7. A release artifact cannot be matched to its tag, commit, image digest or provenance record.
8. A security incident creates credible risk of key, prompt, response or customer-identifier exposure.

A rollback is not mandatory for every upstream error. If the failure is isolated to a provider outage and the Aegis evidence path remains correct, follow the upstream circuit and incident procedure instead.

## Pre-change capture

Before changing traffic or containers, record the following in the incident system:

```text
UTC start time:
Incident ID:
Operator and reviewer:
Current image digest:
Current git tag and commit:
Configuration version/hash:
WAL path and segment list:
Signer scheme and key_id:
Affected replicas:
Observed evidence status:
Observed queue and fsync latency:
Reason for rollback:
```

Preserve the active WAL and associated metadata read-only. If a filesystem snapshot is available, use a snapshot that preserves bytes, ownership, timestamps and access metadata. Do not expose the snapshot to untrusted analysis tooling.

## Safe traffic action

Use the customer's approved ingress or service-control mechanism to stop new governed traffic or drain replicas. Do not bypass authentication, durable evidence, signer policy or strict startup checks to keep traffic moving.

If the active process cannot drain without losing in-flight evidence, preserve request IDs and treat those operations as failed until their evidence status is independently verified. Do not reconstruct a successful response from application logs alone.

## Select the rollback artifact

Select the last release that satisfies all of the following:

| Check | Evidence |
|---|---|
| Source identity | Signed tag, commit and release notes |
| Runtime artifact | Image digest or wheel hash |
| Supply chain | Lockfile, SBOM, vulnerability and license results |
| Schema compatibility | WAL reader and exporter compatibility review |
| Security posture | Release-gate record and known residual risks |
| Operational fit | Configuration and migration compatibility |

A tag name without a digest or commit is not sufficient for a forensic rollback record.

## Execute the rollback

Use the deployment platform's reviewed rollback command. The following is a pattern, not a universal command:

```bash
# Replace IMAGE_DIGEST with the reviewed immutable digest.
export IMAGE_DIGEST='sha256:<reviewed-digest>'

# Apply through the approved deployment system, then record the resulting revision.
# Do not use an unreviewed mutable tag in the production path.
```

After the old revision is running, keep the preserved WAL read-only and direct the restored process to a new or explicitly approved active path only when the schema and chain-continuity review permits it. A rollback must not silently append to a copy whose provenance is unknown.

## Post-rollback verification

Run the following checks against the restored environment:

```bash
pytest -q tests/test_p0_release_gates.py
pytest -q tests/test_enterprise_durable_evidence.py
python -m compileall -q aegis aegis_server
```

Then perform an authorized disposable governed request and verify:

| Observable | Required result |
|---|---|
| Authentication | Accepted only through the configured identity path |
| Request ID | Present in response and structured telemetry |
| Evidence status | Durable before governed success |
| WAL record | Present, signed and linked to the expected predecessor |
| Integrity | `verify_integrity()` passes for the active scope |
| Signer | Expected scheme and key ID are observed |
| Upstream error path | Fails according to the documented durable-error contract |
| Readiness | Reports only after required dependencies are available |

## Key and evidence continuity

If the rollback crosses a signer or keyring version, verify overlap keys before accepting old records. A key ID identifies metadata; it is not proof of secret custody. If overlap cannot be verified, stop governed traffic and escalate to the security owner.

If the rollback crosses a WAL schema or exporter version, do not rewrite evidence to fit the new schema without retaining the original bytes and transformation record. Exported bundles must preserve their original integrity metadata and verification path.

## Closeout

The incident commander closes the rollback only after the evidence chain, provider path, signer, storage, telemetry and customer impact are reviewed. Record root cause, contributing conditions, false positives, missing telemetry, remediation owner, regression test and next release gate.

A rollback can restore service while leaving the root cause unresolved. Do not mark the incident fixed until the release owner records the corrective action and its verification artifact.

## Related documents

- [`DEPLOYMENT_GUIDE.md`](../../DEPLOYMENT_GUIDE.md)
- [`docs/PLATFORM_OPERATOR_GUIDE.md`](../PLATFORM_OPERATOR_GUIDE.md)
- [`docs/operations/BACKPRESSURE_RUNBOOK.md`](BACKPRESSURE_RUNBOOK.md)
- [`docs/operations/KEY_ROTATION_RUNBOOK.md`](KEY_ROTATION_RUNBOOK.md)
- [`docs/CLAIMS_MATRIX.md`](../CLAIMS_MATRIX.md)
- [`SECURITY.md`](../../SECURITY.md)

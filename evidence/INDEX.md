# Evidence Index

**Last verified:** 2026-08-25 UTC
**Release baseline:** two-baseline model
**Source baseline:** merged v4 source state identified by the post-merge audit
**Distribution baseline:** published `v3.1.0` artifacts and their preserved historical evidence
**Status:** repository evidence catalog; not a publication, compliance, production-readiness, or acceptance record

This index distinguishes historical observations from current source-state evidence. An artifact remains evidence of what its own scope and date measured even when a later record supersedes it for current-state identification. Supersession does not rewrite old results.

## Current source-state chain

| Date | Record | Status | Supersession relationship | Integrity |
|---|---|---|---|---|
| 2026-08-24 | [`v4_release_readiness_no_go_2026-08-24.md`](v4_release_readiness_no_go_2026-08-24.md) | Historical pre-candidate no-go; source anchors were still at the prior state described there. | Superseded for current source-state identification by the candidate gate, then the post-merge audit. Retained for its executed checks and blockers. | [`v4_release_readiness_no_go_2026-08-24.sha256`](v4_release_readiness_no_go_2026-08-24.sha256); [`verify_v4_release_readiness_evidence.sh`](verify_v4_release_readiness_evidence.sh) |
| 2026-08-24 | [`pasted_content_5_execution_no_go_2026-08-24.md`](pasted_content_5_execution_no_go_2026-08-24.md) | Historical governance execution record and no-go. | Complementary governance record; superseded by later records only for current source/repository state. | [`pasted_content_5_execution_no_go_2026-08-24.sha256`](pasted_content_5_execution_no_go_2026-08-24.sha256); [`verify_pasted_content_5_evidence.sh`](verify_pasted_content_5_evidence.sh) |
| 2026-08-24 | [`v4_0_0_release_candidate_gate_2026-08-24.md`](v4_0_0_release_candidate_gate_2026-08-24.md) | Historical source-candidate go with tag and multi-registry publication blocked. | Supersedes the pre-candidate record for candidate source state; superseded by the post-merge audit for merged source state. | [`v4_0_0_release_candidate_gate_2026-08-24.sha256`](v4_0_0_release_candidate_gate_2026-08-24.sha256); [`verify_v4_0_0_release_candidate_gate.sh`](verify_v4_0_0_release_candidate_gate.sh) |
| 2026-08-25 | [`v4_0_0_post_merge_release_readiness_2026-08-25.md`](v4_0_0_post_merge_release_readiness_2026-08-25.md) | **Current source-state record:** source merge verified; production release no-go. | Supersedes earlier v4 readiness records only for merged-tree identification and repository observations as of its audit. | [`v4_0_0_post_merge_release_readiness_2026-08-25.sha256`](v4_0_0_post_merge_release_readiness_2026-08-25.sha256); [`verify_v4_0_0_post_merge_release_readiness.sh`](verify_v4_0_0_post_merge_release_readiness.sh) |
| 2026-08-25 | [`pasted_content_6_execution_no_go_2026-08-25.md`](pasted_content_6_execution_no_go_2026-08-25.md) | Historical pre-publication gate: source preflight and local builds passed; signed tag and production publication were no-go at observation time. | Superseded by the pasted7 record only for the later existence of public release/package objects; its signed-tag, workflow and quality-gate findings remain historical evidence. | [`pasted_content_6_execution_no_go_2026-08-25.sha256`](pasted_content_6_execution_no_go_2026-08-25.sha256); [`verify_pasted_content_6_evidence.sh`](verify_pasted_content_6_evidence.sh) |
| 2026-08-25 | [`pasted_content_7_readme_overhaul_2026-08-25.md`](pasted_content_7_readme_overhaul_2026-08-25.md) | **Current public-state and README record:** GitHub Release label `v4.0.1`, source/package version `4.0.0`, and verified documentation overhaul. | Supersedes earlier records only for public object existence; records the lightweight-tag and failed tag-workflow discrepancies without changing the source baseline. | [`pasted_content_7_readme_overhaul_2026-08-25.sha256`](pasted_content_7_readme_overhaul_2026-08-25.sha256); [`verify_pasted_content_7_evidence.sh`](verify_pasted_content_7_evidence.sh) |

The post-merge record is the current locator for the v4 **source baseline**. Its `4.0.0` anchors are source metadata, not proof of a signed tag, GitHub Release, PyPI/npm/OCI artifact, deployed service, or target acceptance.

## Preserved v3.1.0-era evidence

| Date | Collection | Preserved scope | Current status |
|---|---|---|---|
| 2026-08-20 | [`execution_2026-08-20/`](execution_2026-08-20/) | Historical WAF, backpressure, key-rotation, timing, security, test, and manifest outputs used by the v3.1.0-era review. | Historical and not superseded as observations. Results must retain their named workload, source, environment, denominator, and limitations; they are not v4 measurements. |
| 2026-08-20 | [`github_status_baseline_2026-08-20/`](github_status_baseline_2026-08-20/) | Repository/API status snapshots. | Historical point-in-time state; later repository settings and runs supersede it for current GitHub state. |
| 2026-08-20 | [`documentation_audit_2026-08-20/`](documentation_audit_2026-08-20/) | Documentation corpus audit outputs. | Historical audit input; later documentation audits supersede it for current prose, not for the recorded findings. |
| 2026-08-21 | [`remediation_2026-08-21/`](remediation_2026-08-21/) | Remediation reports, test/formal logs, supply-chain assessment, and manifests. | Historical v3.1.0-era remediation evidence; preserved unchanged and not applied to v4 without rerun. |
| 2026-08-21 onward | [`github_status_post_pr95/`](github_status_post_pr95/) | Pull-request and GitHub status/security snapshots after PR #95. | Historical point-in-time API evidence; inaccessible endpoints in those records must not be represented as clean. |
| 2026-08-22 | [`documentation_audit_2026-08-22/`](documentation_audit_2026-08-22/) | Later documentation audit, summaries, and source register. | Supersedes the 2026-08-20 audit for its reviewed corpus, while both remain historical records. |

## Additional bounded source artifacts

| Artifact | Date/status | Boundary |
|---|---|---|
| [`commercial_phase2_streaming_benchmark.json`](commercial_phase2_streaming_benchmark.json) | Post-v3.1.0 local source benchmark | Bounded local workload; excludes network and durable-WAL latency and is not production capacity. |
| [`commercial_phase2_dashboard_qa.md`](commercial_phase2_dashboard_qa.md) | Post-v3.1.0 local dashboard QA | Local source/UI review; not deployment availability, customer telemetry, accessibility certification, or acceptance. |
| [`apex_workstreams_9_11_gate_2026-08-24.md`](apex_workstreams_9_11_gate_2026-08-24.md) | 2026-08-24 source gate record | Retains its own stated scope and limitations; not registry publication or external assurance. |
| [`commit_scaling_measurement_2026-09-03.md`](commit_scaling_measurement_2026-09-03.md) | 2026-09-03 in-process microbenchmark of the ledger commit path | One container, one date. Excludes network, provider, and (by default) durable-write cost; establishes the shape of the per-commit cost curve, not throughput capacity or any service level. |
| [`evidence_path_measurements_2026-09-03.md`](evidence_path_measurements_2026-09-03.md) | 2026-09-03 in-process benchmarks of the evidence path on commit `f77420a` | One container, four shared unpinned CPUs, one date. Excludes network, provider and concurrency. Records the shape and ordering of costs, not throughput capacity or any service level. Z3, Lean and TLC rows are marked NOT-EXECUTED because that tooling is absent from the container. |

## Integrity sidecars and manifests

| Path | Protects or identifies | Verification boundary |
|---|---|---|
| `evidence/*.sha256` beside the six v4/governance Markdown records | Exact bytes of the adjacent named Markdown file | Run the adjacent `verify_*.sh` or `sha256sum -c` from `evidence/`. A digest proves byte identity only, not truth or approval. |
| [`execution_2026-08-20/manifest.sha256`](execution_2026-08-20/manifest.sha256), [`manifest.cbor`](execution_2026-08-20/manifest.cbor), [`manifest.cid`](execution_2026-08-20/manifest.cid) | Historical execution manifest representations | Preserve together with the referenced files and original canonicalization rules. |
| [`remediation_2026-08-21/remediation_manifest.sha256`](remediation_2026-08-21/remediation_manifest.sha256), [`remediation_manifest.cbor`](remediation_2026-08-21/remediation_manifest.cbor), [`remediation_manifest.cid`](remediation_2026-08-21/remediation_manifest.cid) | Historical remediation manifest representations | Byte/provenance identifiers within the original record's scope; not current-state certification. |
| [`remediation_2026-08-21/native_wheel.sha256`](remediation_2026-08-21/native_wheel.sha256) | Historical locally built v3.1.0 native wheel named in that sidecar | Does not prove the wheel is currently available from a registry or accepted on another platform. |

Quick sidecar verification:

```bash
cd evidence
./verify_v4_release_readiness_evidence.sh
./verify_pasted_content_5_evidence.sh
./verify_v4_0_0_release_candidate_gate.sh
./verify_v4_0_0_post_merge_release_readiness.sh
./verify_pasted_content_6_evidence.sh
./verify_pasted_content_7_evidence.sh
```

## Publication and acceptance boundary

Evidence in this directory may support technical review, but no file here by itself establishes or authorizes a v4 tag, GitHub Release, package or image publication, registry ownership, production deployment, operational SLO, compliance status, certification, legal admissibility, customer acceptance, or independent assurance. External APIs that returned forbidden, unavailable, or incomplete results remain unknown rather than clean. Local builds, tests, hashes, signatures, and bounded benchmarks must not be promoted beyond their recorded scope.

## Preservation rules

Do not edit historical reports to make them describe a newer baseline. Add a new dated artifact, retain raw output and environment details, link the prior record, state whether it is complemented or superseded, and add an integrity sidecar when the evidence process requires one. If a current-state record conflicts with an older point-in-time snapshot, use the newer record for current state and preserve the older record as history.

## Related documents

- [`docs/README.md`](../docs/README.md)
- [`docs/CLAIMS_MATRIX.md`](../docs/CLAIMS_MATRIX.md)
- [`docs/ROADMAP.md`](../docs/ROADMAP.md)
- [`docs/institutional/DOCUMENT_CONTROL.md`](../docs/institutional/DOCUMENT_CONTROL.md)

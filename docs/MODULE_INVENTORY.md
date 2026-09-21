# Module inventory

Every file under the six source roots, with what it is, what reaches it, what tests it, and who owns it. Generated — edit `scripts/generate_module_inventory.py`, not this file. Currency is enforced by `tests/test_module_inventory_current.py`.

`python scripts/generate_module_inventory.py` — 300 files.

## What the status column means

| Status | Meaning |
|---|---|
| `reachable` | For `aegis/`, `aegis_server/`, `integrations/`: reached from a documented entrypoint by `scripts/verify_import_reachability.py`. For `aegis_rust_v2/src`: reached by the transitive `mod` graph from `lib.rs`. |
| `roadmap-omit` | Listed in `[tool.coverage.run] omit` as roadmap / platform-specific: a declared status, cross-checked by the reachability gate. |
| `allowlisted` | Declared in `scripts/import_reachability_allowlist.txt` — a disclosure, not a classification, and a worklist rather than a verdict. |
| `referenced` | For `scripts/` and `tools/`: named by a CI workflow, the Makefile, or a tracked document. Nothing imports a console script, so being named by something that runs or documents it is what makes it live. |
| `unreferenced` | For `scripts/` and `tools/`: named by no workflow, Makefile target or tracked document. Not a defect by itself — but it is the set to prune or wire, and the currency test fails if this set changes without the inventory being regenerated. |
| `orphan` | A Python module no entrypoint reaches and no registry declares, or an `.rs` file no `mod` reaches. The reachability gate fails on Python orphans; the Rust list here is the only place they are reported. |
| `n/a` | A data file inside a source root (`.md`, `.json`, …). |

## Coverage and ownership

- **Navigation coverage:** 68 of 300 files (23%) are named in a navigation source (`llms.txt`, `docs/REPOSITORY_MAP.md`, `AGENTS.md`, `README.md`, `SECURITY.md`, `docs/architecture/ARCHITECTURE.md`, and `.aegis_ai_context/`). The rest are reachable from these tables alone, which is the point of the inventory.
- **Status counts:** `allowlisted` 77, `n/a` 1, `reachable` 128, `referenced` 43, `roadmap-omit` 34, `unreferenced` 17.
- **Ownership:** resolved from `.github/CODEOWNERS` by longest path prefix. `@JuanLunaIA` 300 files. This is a single accountable owner, as CODEOWNERS itself states, not a staffed review team — per-module maintainers cannot be named until one exists, so no row invents one.

Tests are the test files that import the module directly, capped at 4 per row; the count is exact, the list is not exhaustive.

## Open roadmap tickets, owner and unblock path

Every open roadmap ticket, its owner, and the ticket's own `Proposed solution` quoted as the unblock path. A ticket with no such line is shown as such rather than given one.

| Ticket | Priority | Owner | Unblock path |
|---|---|---|---|
| `AUD-26` | P3 | @JuanLunaIA | Re-label harness output as host-specific observations; commit a retained report or mark the figures historical; remove/replace '[PROVEN]' and 'zero latency' phrasings; decide the fate of UC-015/UC-016 (produce or keep retracted). |
| `AUD-27` | P3 | @JuanLunaIA | Split `_sign` into scheme selection + signing, build the payload with the selected scheme appended (same additive/conditional pattern as `waf_verdict`), gate the change on a trail-version bump so v1/v2 chains keep verifying, and add a tamper test asserting a label rewrite breaks the signature for every verifiable scheme. No `node_hash` change is required. |
| `AUD-28` | P3 | @JuanLunaIA | Spool the frozen summary (a small append-only spool file next to the WAL) before the handoff acknowledges, and commit pending spool entries on the next startup before serving traffic; keep the in-memory path as the fast case and expose spool depth as a metric. |
| `AUD-29` | P3 | @JuanLunaIA | Decide the canonical type-check scope once: add `scripts/` and `tools/` to a mypy job (start with `--strict` on the two directories that already pass, and stage the remainder), annotate `_split_row`'s locals, and add the directory list to the same gate that `AUD-18` reconciles for the formatter. |
| `AUD-30` | P3 | @JuanLunaIA | Narrow the trigger to version-shaped tokens (`v4(?:\.[0-9]+)*`, `4\.0(?:\.0)?`, `version 4`) and keep a test for the intended catch (`tests/test_documentation_verifier.py:56` already asserts "Aegis v4.0.0 has been published and released." must fail). Do not relax the prohibition itself. |
| `AUD-35` | P2 | @JuanLunaIA | decide per control — either wire it (source `siem_url` from `webhook_url` when empty, feed `rate_limit_window` into the limiter, construct `LDAPAuthenticator`, construct `CACPIVAuth`) with a test per wired path, or delete the knob and its operator-facing copies. The gate (`tests/test_config_surface_inert_fields.py`) enforces that whichever is chosen, the section and the allowlist agree. |
| `AUD-36` | P2 | @JuanLunaIA | decide per module. Wire: a governed admission-path hook for the detector with an explicit configuration flag, a documented verdict destination, and rewritten `CLM-103`/`CLM-104` rows with measured evidence; or retire: delete the module, its tests and its allowlist entry, and mark the corresponding claim row withdrawn. Either branch removes the allowlist entry, which is the point — an allowlisted compliance module is a liability in every audit it appears in. |
| `AUD-37` | P3 | @JuanLunaIA | do these as **content reviews, not date bumps.** For each document: re-read it against the 5.0.0 tree, verify its cited paths resolve (the same check `REG-D23` ran on `REPOSITORY_MAP.md` and `docs/README.md`, 22 and 16 targets, 0 missing), correct what is stale, and date the line with what was checked. A date shortened without that pass is exactly the failure mode `REG-D23` closed on the other side of the corpus. The two claim-ledger rows should go first: they are already known to mislead. |

## Files

| Path | Kind | Purpose | Status | Tests | Owner |
|---|---|---|---|---|---|
| `aegis/__init__.py` | package | Aegis Latent Core — forensic evidence gateway for LLM inference pipelines. | reachable | `tests/compat/test_public_api_compat.py`, `tests/test_embedded_mode.py`, `tests/test_forensic_pdf_report.py` | @JuanLunaIA |
| `aegis/anchoring/__init__.py` | package | External evidence anchoring integrations. | reachable | — | @JuanLunaIA |
| `aegis/anchoring/rfc3161.py` | module | RFC 3161 timestamp anchoring with explicit transport and trust boundaries. | reachable | `tests/anchoring/test_rfc3161.py`, `tests/storage/test_segment_manifest.py` | @JuanLunaIA |
| `aegis/auth/__init__.py` | package | API key authentication for the Aegis proxy. | reachable | — | @JuanLunaIA |
| `aegis/auth/abac.py` | module | aegis.auth.abac — Attribute-Based Access Control for IL5/IL6 compartmentalization. | allowlisted | `tests/test_abac.py` | @JuanLunaIA |
| `aegis/auth/apikey.py` | module | aegis.auth.apikey — Constant-time API key authentication for FastAPI. | reachable | `tests/test_apikey_new.py`, `tests/test_enterprise_auth.py` | @JuanLunaIA |
| `aegis/auth/ldap_auth.py` | module | aegis.auth.ldap_auth — LDAP/Active Directory multi-factor identity assertion. | allowlisted | `tests/test_ldap_auth.py` | @JuanLunaIA |
| `aegis/auth/mtls.py` | module | mTLS client-certificate verification at direct and trusted-proxy boundaries. | reachable | `tests/auth/test_mtls_v4.py`, `tests/security/test_tenant_isolation.py` | @JuanLunaIA |
| `aegis/auth/oidc.py` | module | OIDC access-token verification without network or global-cache side effects. | reachable | `tests/auth/test_oidc_rbac.py` | @JuanLunaIA |
| `aegis/auth/principal.py` | module | Immutable authenticated-principal model shared by enterprise auth mechanisms. | reachable | `tests/auth/test_oidc_rbac.py`, `tests/security/test_tenant_isolation.py`, `tests/test_audit_api_new.py`, `tests/test_audit_read_snapshot.py`, … (+2 more)` | @JuanLunaIA |
| `aegis/auth/rbac.py` | module | aegis.auth.rbac — Role-Based Access Control with NIST SP 800-207 Zero Trust. | allowlisted | `tests/test_rbac.py`, `tests/test_scim.py` | @JuanLunaIA |
| `aegis/auth/scim.py` | module | aegis.auth.scim — SCIM 2.0 provisioning/deprovisioning lifecycle. | allowlisted | `tests/test_scim.py` | @JuanLunaIA |
| `aegis/auth/scopes.py` | module | aegis.auth.scopes — HIPAA minimum-necessary API key scope enforcement. | reachable | `tests/test_api_key_scopes.py`, `tests/test_audit_api_new.py`, `tests/test_audit_read_snapshot.py`, `tests/test_dependencies_identity_helpers.py`, … (+3 more)` | @JuanLunaIA |
| `aegis/config.py` | module | aegis.config — Centralized configuration via environment variables. | reachable | `tests/compat/test_public_api_compat.py`, `tests/security/test_enforcement_mode_metric.py`, `tests/security/test_stream_admission_metric.py`, `tests/test_apikey_new.py`, … (+36 more)` | @JuanLunaIA |
| `aegis/connectors/__init__.py` | package | Connectors that carry Aegis evidence into systems an enterprise already runs. | allowlisted | — | @JuanLunaIA |
| `aegis/connectors/lakehouse/__init__.py` | package | — | allowlisted | — | @JuanLunaIA |
| `aegis/connectors/lakehouse/parquet_exporter.py` | module | Convert a finalized JSONL WAL segment into Parquet for a lakehouse. | allowlisted | `tests/connectors/test_parquet_exporter.py` | @JuanLunaIA |
| `aegis/connectors/siem/__init__.py` | package | — | allowlisted | — | @JuanLunaIA |
| `aegis/connectors/siem/splunk_hec.py` | module | Splunk HTTP Event Collector client with bounded buffering and disk spooling. | allowlisted | `tests/connectors/test_splunk_hec.py` | @JuanLunaIA |
| `aegis/connectors/vault/__init__.py` | package | — | allowlisted | — | @JuanLunaIA |
| `aegis/connectors/vault/transit_signer.py` | module | Sign audit-node hashes with HashiCorp Vault's Transit secrets engine. | allowlisted | `tests/connectors/test_vault_transit.py` | @JuanLunaIA |
| `aegis/consensus/__init__.py` | package | Cross-replica reconciliation over the Causal-Merkle CRDT. | reachable | `tests/consensus/test_gossip_settings.py`, `tests/test_gossip_runtime_lifecycle.py` | @JuanLunaIA |
| `aegis/consensus/gossip.py` | module | Anti-entropy gossip over the Causal-Merkle CRDT. | reachable | `tests/consensus/test_gossip_convergence.py`, `tests/consensus/test_gossip_settings.py` | @JuanLunaIA |
| `aegis/consensus/runtime.py` | module | aegis.consensus.runtime — start and stop the gossip mesh alongside the gateway. | reachable | `tests/consensus/test_gossip_runtime.py`, `tests/test_gossip_runtime_lifecycle.py` | @JuanLunaIA |
| `aegis/consensus/transport.py` | module | The wire for gossip: mutual-TLS HTTP, and the endpoint that answers it. | reachable | `tests/consensus/test_gossip_convergence.py` | @JuanLunaIA |
| `aegis/core/__init__.py` | package | aegis.core — Mathematical and cryptographic telemetry primitives. | reachable | `tests/compat/test_public_api_compat.py`, `tests/engines/test_modular_engines.py`, `tests/security/test_enforcement_mode_metric.py`, `tests/security/test_stream_admission_metric.py`, … (+16 more)` | @JuanLunaIA |
| `aegis/core/a2a.py` | module | aegis.core.a2a — receipts for agent-to-agent tool execution. | reachable | `tests/test_a2a_protocol.py`, `tests/test_waf_verdict_schema.py` | @JuanLunaIA |
| `aegis/core/adversarial_filter.py` | module | aegis.core.adversarial_filter — Advanced Adversarial AI Guard. | reachable | `tests/test_waf_layer2_normalization.py` | @JuanLunaIA |
| `aegis/core/adversarial_suffix_detector.py` | module | aegis.core.adversarial_suffix_detector — GCG/AutoDAN adversarial suffix detection. | allowlisted | `tests/test_adversarial_suffix_detector.py` | @JuanLunaIA |
| `aegis/core/ae_keyword_detector.py` | module | aegis.core.ae_keyword_detector — Adverse Event keyword detection aligned to MedDRA. | allowlisted | `tests/test_ae_keyword_detector.py` | @JuanLunaIA |
| `aegis/core/anchoring.py` | module | aegis.core.anchoring — external root anchoring orchestration. | roadmap-omit | `tests/test_blockchain_anchor.py` | @JuanLunaIA |
| `aegis/core/archival_bundle.py` | module | aegis.core.archival_bundle — algorithm-agile evidence bundle for 30-year retention. | allowlisted | `tests/test_archival_bundle.py` | @JuanLunaIA |
| `aegis/core/artifact_signing.py` | module | aegis.core.artifact_signing — sign & verify deployment artifacts (supply-chain | allowlisted | `tests/test_artifact_signing.py` | @JuanLunaIA |
| `aegis/core/atlas_tactic_mapper.py` | module | aegis.core.atlas_tactic_mapper — MITRE ATLAS tactic mapping for WAF hits. | allowlisted | `tests/test_atlas_tactic_mapper.py` | @JuanLunaIA |
| `aegis/core/attestation_capabilities.py` | module | aegis.core.attestation_capabilities — honest per-control capability matrix. | reachable | — | @JuanLunaIA |
| `aegis/core/audit_node.proto` | other | — | n/a | — | @JuanLunaIA |
| `aegis/core/audit_node_encryptor.py` | module | aegis.core.audit_node_encryptor — AES-256-GCM envelope encryption for IL6 audit nodes. | allowlisted | `tests/test_audit_node_encryptor.py` | @JuanLunaIA |
| `aegis/core/audit_node_pb2.py` | module | Generated protocol buffer code. | roadmap-omit | — | @JuanLunaIA |
| `aegis/core/blockchain_anchor.py` | module | aegis.core.blockchain_anchor — external root anchoring (pluggable backend). | reachable | `tests/test_blockchain_anchor.py` | @JuanLunaIA |
| `aegis/core/boot_attestation.py` | module | aegis.core.boot_attestation — Trusted Boot Verification. | roadmap-omit | `tests/test_boot_attestation.py` | @JuanLunaIA |
| `aegis/core/boot_guard.py` | module | aegis.core.boot_guard — Orchestrates the Measured Boot process. | roadmap-omit | — | @JuanLunaIA |
| `aegis/core/build_hardener.py` | module | aegis.core.build_hardener — Binary Hardening Orchestrator. | roadmap-omit | — | @JuanLunaIA |
| `aegis/core/build_reproducibility.py` | module | aegis.core.build_reproducibility — Bit-for-Bit Reproducible Build System. | roadmap-omit | `tests/test_build_reproducibility.py` | @JuanLunaIA |
| `aegis/core/cac_piv.py` | module | aegis.core.cac_piv — DoD CAC / GSA PIV client certificate verification. | allowlisted | `tests/test_cac_piv.py` | @JuanLunaIA |
| `aegis/core/cds_guard.py` | module | aegis.core.cds_guard — Domain 1.1 cross-domain solution guard. | allowlisted | `tests/test_cds_guard.py` | @JuanLunaIA |
| `aegis/core/cfi_manager.py` | module | aegis.core.cfi_manager — Control Flow Integrity (CFI) Verification. | roadmap-omit | `tests/test_cfi_manager.py` | @JuanLunaIA |
| `aegis/core/cgroups_quota.py` | module | aegis.core.cgroups_quota — cgroups v2 memory and CPU quota enforcement. | allowlisted | `tests/test_cgroups_quota.py` | @JuanLunaIA |
| `aegis/core/circuit_breaker.py` | module | aegis.core.circuit_breaker — Thread-safe upstream circuit breaker. | reachable | `tests/test_app_coverage_extended.py`, `tests/test_chaos.py`, `tests/test_circuit_breaker.py`, `tests/test_circuit_breaker_new.py`, … (+1 more)` | @JuanLunaIA |
| `aegis/core/classified_marker_detector.py` | module | aegis.core.classified_marker_detector — Pre-forwarding classified-data blocking. | allowlisted | `tests/test_classified_marker_detector.py` | @JuanLunaIA |
| `aegis/core/clinical_claim_detector.py` | module | aegis.core.clinical_claim_detector — de-novo clinical claim detection. | allowlisted | `tests/test_clinical_claim_detector.py` | @JuanLunaIA |
| `aegis/core/clock_integrity.py` | module | aegis.core.clock_integrity — System clock integrity assertion. | allowlisted | `tests/test_clock_integrity.py` | @JuanLunaIA |
| `aegis/core/cnsa_negotiation.py` | module | aegis.core.cnsa_negotiation — NSA Suite B / CNSA 2.0 algorithm negotiation. | allowlisted | `tests/test_cnsa_negotiation.py` | @JuanLunaIA |
| `aegis/core/codeql_config.py` | module | aegis.core.codeql_config — CodeQL Query Integration for CI/CD. | roadmap-omit | `tests/test_codeql_config.py` | @JuanLunaIA |
| `aegis/core/conversation_graph.py` | module | aegis.core.conversation_graph — Conversation graph crescendo analysis. | allowlisted | `tests/test_conversation_graph.py` | @JuanLunaIA |
| `aegis/core/cpu_affinity.py` | module | aegis.core.cpu_affinity — Domain 3.2 CPU pinning via sched_setaffinity. | allowlisted | `tests/test_cpu_affinity.py` | @JuanLunaIA |
| `aegis/core/crdt_ordering.py` | module | aegis.core.crdt_ordering — Domain 3.3 CRDT for distributed audit node ordering. | allowlisted | `tests/test_crdt_ordering.py` | @JuanLunaIA |
| `aegis/core/cross_session_correlator.py` | module | aegis.core.cross_session_correlator — Cross-session coordinated attack detection. | allowlisted | `tests/test_cross_session_correlator.py`, `tests/test_ioc_correlator.py`, `tests/test_semantic_sim_clustering.py` | @JuanLunaIA |
| `aegis/core/crypto_audit.py` | module | aegis.core.crypto_audit — Cryptographic audit ledger with a Merkle-linked evidence chain. | reachable | `tests/connectors/test_parquet_exporter.py`, `tests/security/test_wal_single_writer.py`, `tests/storage/test_segment_manifest.py`, `tests/test_a2a_protocol.py`, … (+45 more)` | @JuanLunaIA |
| `aegis/core/crypto_shredder.py` | module | Cryptographic erasure for an append-only ledger. | reachable | `tests/engines/test_modular_engines.py`, `tests/test_crypto_shredder.py`, `tests/test_crypto_shredder_integration.py`, `tests/test_shredded_digest_confirmability.py` | @JuanLunaIA |
| `aegis/core/custody_transfer.py` | module | aegis.core.custody_transfer — ISO/IEC 27037 custody transfer protocol. | allowlisted | `tests/test_custody_transfer.py` | @JuanLunaIA |
| `aegis/core/decode_pipeline.py` | module | aegis.core.decode_pipeline — Iterative multi-layer decode pipeline for WAF evasion resistance. | allowlisted | `tests/test_decode_pipeline.py` | @JuanLunaIA |
| `aegis/core/dependency_audit.py` | module | aegis.core.dependency_audit — Supply-chain vulnerability auditing. | roadmap-omit | `tests/test_dependency_audit.py` | @JuanLunaIA |
| `aegis/core/dfir_export.py` | module | aegis.core.dfir_export — DFIR-compatible evidence bundle export formats. | allowlisted | `tests/test_dfir_export.py` | @JuanLunaIA |
| `aegis/core/dosage_hallucination.py` | module | aegis.core.dosage_hallucination — drug dosage hallucination detection. | allowlisted | `tests/test_dosage_hallucination.py` | @JuanLunaIA |
| `aegis/core/dp_analytics.py` | module | Internal, non-published Laplace mechanism for one bounded count release. | allowlisted | `tests/test_dp_analytics.py` | @JuanLunaIA |
| `aegis/core/dpdk_engine.py` | module | aegis.core.dpdk_engine — Data Plane Development Kit (DPDK) Implementation. | roadmap-omit | `tests/test_hardware_modules.py` | @JuanLunaIA |
| `aegis/core/ebpf_monitor.py` | module | aegis.core.ebpf_monitor — eBPF-based Real-time Observability. | roadmap-omit | `tests/test_hardware_modules.py` | @JuanLunaIA |
| `aegis/core/enclave_provider.py` | module | aegis.core.enclave_provider — Hardware Enclave Integration (SGX/SEV). | roadmap-omit | `tests/test_hardware_modules.py` | @JuanLunaIA |
| `aegis/core/entropy_analysis.py` | module | aegis.core.entropy_analysis — Shannon entropy and drift monitoring for LLM payloads. | reachable | — | @JuanLunaIA |
| `aegis/core/export_audit_log.py` | module | aegis.core.export_audit_log — Tamper-evident compliance export audit log. | allowlisted | `tests/test_export_audit_log.py` | @JuanLunaIA |
| `aegis/core/forensic.py` | module | aegis.core.forensic — Forensic record builders for the audit ledger. | reachable | `tests/test_forensic.py`, `tests/test_forensic_builders.py`, `tests/test_part11_annotation_binding.py`, `tests/test_pre_admission_rejection.py`, … (+2 more)` | @JuanLunaIA |
| `aegis/core/forensic_bundle.py` | module | Bounded forensic bundle construction for authenticated audit exports. | reachable | `tests/test_audit_api_new.py`, `tests/test_forensic_bundle.py`, `tests/test_forensic_bundle_manifest_signature.py` | @JuanLunaIA |
| `aegis/core/forensic_pdf_report.py` | module | aegis.core.forensic_pdf_report — structured forensic report generator. | allowlisted | `tests/test_forensic_pdf_report.py` | @JuanLunaIA |
| `aegis/core/forensic_sealing.py` | module | aegis.core.forensic_sealing — Quantum-Resistant Evidence Sealing. | roadmap-omit | `tests/test_forensic_sealing.py` | @JuanLunaIA |
| `aegis/core/formal_proofs.py` | module | aegis.core.formal_proofs — Empirical checks for statements proved elsewhere. | roadmap-omit | — | @JuanLunaIA |
| `aegis/core/formal_specs.py` | module | aegis.core.formal_specs — Formal Specifications and TLA+ Mappings. | roadmap-omit | — | @JuanLunaIA |
| `aegis/core/fuzzing_harness.py` | module | Evidence-based cargo-fuzz orchestration for declared Rust fuzz targets. | reachable | `tests/test_fuzzing_harness.py` | @JuanLunaIA |
| `aegis/core/gossip_wal_sync.py` | module | aegis.core.gossip_wal_sync — SWIM-inspired gossip WAL sync. | allowlisted | `tests/test_gossip_wal_sync.py` | @JuanLunaIA |
| `aegis/core/group_commit.py` | module | aegis.core.group_commit — coalesce concurrent WAL commits into one fsync. | reachable | `tests/test_coalesced_commit.py` | @JuanLunaIA |
| `aegis/core/gxp_qualification.py` | module | aegis.core.gxp_qualification — GxP-oriented qualification support hooks. | allowlisted | `tests/test_gxp_qualification.py` | @JuanLunaIA |
| `aegis/core/hardware_token.py` | module | aegis.core.hardware_token — Domain 1.2 hardware-bound session tokens. | allowlisted | `tests/test_hardware_token.py` | @JuanLunaIA |
| `aegis/core/hl7_fhir_phi_detector.py` | module | aegis.core.hl7_fhir_phi_detector — HL7 v2 / FHIR structured PHI detection. | allowlisted | `tests/test_hl7_fhir_phi_detector.py` | @JuanLunaIA |
| `aegis/core/homoglyph_normalizer.py` | module | aegis.core.homoglyph_normalizer — Homoglyph normalization beyond NFKC. | reachable | `tests/test_homoglyph_normalizer.py` | @JuanLunaIA |
| `aegis/core/hsm.py` | module | aegis.core.hsm — Hardware Security Module (HSM) / PKCS#11 signing backend. | reachable | `tests/test_hsm.py` | @JuanLunaIA |
| `aegis/core/icd_snomed_detector.py` | module | aegis.core.icd_snomed_detector — ICD-11 / SNOMED-CT ontology-aware anomaly detection. | allowlisted | `tests/test_icd_snomed_detector.py` | @JuanLunaIA |
| `aegis/core/identity.py` | module | aegis.core.identity — SPIFFE/SPIRE Identity Integration. | roadmap-omit | `tests/test_identity_mtls.py` | @JuanLunaIA |
| `aegis/core/intermittent_connectivity.py` | module | aegis.core.intermittent_connectivity — WAL backpressure monitor for disconnected ops. | allowlisted | `tests/test_intermittent_connectivity.py` | @JuanLunaIA |
| `aegis/core/ioc_correlator.py` | module | aegis.core.ioc_correlator — IOC correlation against known threat actor TTPs. | allowlisted | `tests/test_ioc_correlator.py` | @JuanLunaIA |
| `aegis/core/iso27037_evidence.py` | module | aegis.core.iso27037_evidence — ISO/IEC 27037-oriented evidence packages. | allowlisted | `tests/test_iso27037_evidence.py` | @JuanLunaIA |
| `aegis/core/kernel_hardener.py` | module | aegis.core.kernel_hardener — Kernel-Level Security Enforcement. | roadmap-omit | — | @JuanLunaIA |
| `aegis/core/leak_detector.py` | module | aegis.core.leak_detector — Data Exfiltration Detection via Entropy. | reachable | `tests/test_leak_detector_new.py` | @JuanLunaIA |
| `aegis/core/lsm_guard.py` | module | aegis.core.lsm_guard — Domain 1.5 Linux Security Module confinement guard. | reachable | `tests/test_lsm_guard.py`, `tests/test_lsm_guard_new.py`, `tests/test_lsm_guard_process_label.py`, `tests/test_misc_gaps.py` | @JuanLunaIA |
| `aegis/core/manyshot_detector.py` | module | aegis.core.manyshot_detector — Many-shot jailbreak detection. | allowlisted | `tests/test_manyshot_detector.py` | @JuanLunaIA |
| `aegis/core/market_abuse_detector.py` | module | aegis.core.market_abuse_detector — MAR / MiFID II market-abuse pattern detection. | allowlisted | `tests/test_market_abuse_detector.py` | @JuanLunaIA |
| `aegis/core/math_utils.py` | module | math_utils.py — Numerically Stable & Cryptographically Deterministic Layer | reachable | `tests/test_core.py`, `tests/test_coverage_final.py`, `tests/test_misc_gaps.py` | @JuanLunaIA |
| `aegis/core/memory.py` | module | aegis.core.memory — Hardened Memory Management. | roadmap-omit | `tests/test_property_based.py` | @JuanLunaIA |
| `aegis/core/memory_invariants.py` | module | aegis.core.memory_invariants — Real-time memory invariant verification. | roadmap-omit | `tests/test_memory_invariants.py` | @JuanLunaIA |
| `aegis/core/mifid_record_keeper.py` | module | aegis.core.mifid_record_keeper — MiFID II / Dodd-Frank communication records. | allowlisted | `tests/test_mifid_record_keeper.py` | @JuanLunaIA |
| `aegis/core/mlkem_session.py` | module | aegis.core.mlkem_session — FIPS 203 ML-KEM (Kyber-1024) session key bootstrap. | reachable | `tests/crypto/test_capabilities.py`, `tests/test_mlkem_session.py` | @JuanLunaIA |
| `aegis/core/mmr.py` | module | aegis.core.mmr — Merkle Mountain Ranges (MMR). | reachable | `tests/compat/test_public_api_compat.py`, `tests/crypto/test_capabilities.py`, `tests/redteam/fuzz/fuzz_mmr_proof.py`, `tests/redteam/test_mmr_proof_forgery.py`, … (+20 more)` | @JuanLunaIA |
| `aegis/core/model_decision_explainer.py` | module | aegis.core.model_decision_explainer — Basel-aligned model-decision explainability. | allowlisted | `tests/test_model_decision_explainer.py` | @JuanLunaIA |
| `aegis/core/model_risk_governance.py` | module | aegis.core.model_risk_governance — SOX ICFR + SR 11-7 model risk governance. | allowlisted | `tests/test_model_risk_governance.py` | @JuanLunaIA |
| `aegis/core/moe_monitor.py` | module | — | allowlisted | `tests/test_core.py`, `tests/test_misc_gaps.py`, `tests/test_stealth_attack.py`, `tests/test_zero_day_defense.py` | @JuanLunaIA |
| `aegis/core/mte_guard.py` | module | aegis.core.mte_guard — Memory Tagging Extension (MTE) Guard. | roadmap-omit | `tests/test_mte_guard.py` | @JuanLunaIA |
| `aegis/core/network_isolation.py` | module | aegis.core.network_isolation — XDP/eBPF Network Hardening. | roadmap-omit | — | @JuanLunaIA |
| `aegis/core/normalization.py` | module | aegis.core.normalization — Canonical normalization of inputs. | reachable | — | @JuanLunaIA |
| `aegis/core/observability.py` | module | aegis.core.observability — Prometheus metrics and OpenTelemetry span helpers. | reachable | `tests/test_chaos.py`, `tests/test_misc_gaps.py`, `tests/test_observability.py`, `tests/test_observability_new.py` | @JuanLunaIA |
| `aegis/core/offline_license.py` | module | aegis.core.offline_license — Domain 1.3 offline license validation. | allowlisted | `tests/test_offline_license.py` | @JuanLunaIA |
| `aegis/core/operator_seal.py` | module | aegis.core.operator_seal — HSM-signed operator attestation gate for bundle export. | allowlisted | `tests/test_operator_seal.py` | @JuanLunaIA |
| `aegis/core/ot_protocol_scanner.py` | module | aegis.core.ot_protocol_scanner — SCADA/OT protocol command injection detection. | allowlisted | `tests/test_ot_protocol_scanner.py` | @JuanLunaIA |
| `aegis/core/panic_mode.py` | module | aegis.core.panic_mode — Logical self-destruct (panic-mode). | roadmap-omit | — | @JuanLunaIA |
| `aegis/core/pci_detector.py` | module | aegis.core.pci_detector — PCI-DSS v4.0 cardholder-data detection & masking. | reachable | `tests/test_pci_detector.py` | @JuanLunaIA |
| `aegis/core/phi_deidentifier.py` | module | Best-effort PHI identifier redaction using deterministic regex patterns. | reachable | `tests/redteam/fuzz/fuzz_phi_deidentifier.py`, `tests/redteam/test_redos_bounds.py`, `tests/test_phi_address_bound.py`, `tests/test_phi_audit_trail.py`, … (+3 more)` | @JuanLunaIA |
| `aegis/core/phi_encryption.py` | module | aegis.core.phi_encryption — AES-256-GCM field-level encryption for PHI payloads. | allowlisted | `tests/test_phi_encryption.py` | @JuanLunaIA |
| `aegis/core/pii_confidence.py` | module | aegis.core.pii_confidence — PII confidence scoring per response with block/flag/log actions. | allowlisted | `tests/test_pii_confidence.py` | @JuanLunaIA |
| `aegis/core/pinned_ca_bundle.py` | module | aegis.core.pinned_ca_bundle — Domain 1.3 air-gapped certificate chain verification. | allowlisted | `tests/test_pinned_ca_bundle.py` | @JuanLunaIA |
| `aegis/core/pqc_signer.py` | module | aegis.core.pqc_signer — the single, real post-quantum signer (ML-DSA-65 / FIPS 204). | reachable | `tests/crypto/test_capabilities.py`, `tests/engines/test_modular_engines.py`, `tests/test_artifact_signing.py`, `tests/test_boot_attestation.py`, … (+1 more)` | @JuanLunaIA |
| `aegis/core/pqc_tls.py` | module | aegis.core.pqc_tls — real hybrid post-quantum key exchange (X25519 + ML-KEM-1024). | reachable | `tests/test_pqc_tls.py` | @JuanLunaIA |
| `aegis/core/process_hardening.py` | module | aegis.core.process_hardening — prctl-based process privilege hardening. | allowlisted | `tests/test_process_hardening.py` | @JuanLunaIA |
| `aegis/core/raft_consensus.py` | module | aegis.core.raft_consensus — Domain 4.1 Raft consensus state machine. | allowlisted | `tests/test_raft_consensus.py` | @JuanLunaIA |
| `aegis/core/rag_injection_scanner.py` | module | aegis.core.rag_injection_scanner — RAG-aware prompt injection scanner. | reachable | `tests/test_rag_injection_scanner.py` | @JuanLunaIA |
| `aegis/core/ratelimiter.py` | module | aegis.core.ratelimiter — Rate limiting with Redis (distributed) or in-memory fallback. | reachable | `tests/test_chaos.py`, `tests/test_p0_release_gates.py`, `tests/test_ratelimiter_new.py` | @JuanLunaIA |
| `aegis/core/readonly_rootfs.py` | module | aegis.core.readonly_rootfs — read-only rootfs detection and writable-path redirection. | allowlisted | `tests/test_readonly_rootfs.py` | @JuanLunaIA |
| `aegis/core/red_team_framework.py` | module | aegis.core.red_team_framework — Automated Adversarial Testing. | roadmap-omit | `tests/test_red_team_framework.py` | @JuanLunaIA |
| `aegis/core/rfc3161_cms.py` | module | CMS (RFC 5652) signature verification for RFC 3161 timestamp tokens. | reachable | `tests/test_rfc3161_cms_verification.py` | @JuanLunaIA |
| `aegis/core/rfc3161_timestamper.py` | module | aegis.core.rfc3161_timestamper — RFC 3161 trusted timestamp integration. | reachable | `tests/test_rfc3161_timestamper.py` | @JuanLunaIA |
| `aegis/core/root_ca_gateway.py` | module | aegis.core.root_ca_gateway — Air-Gapped Root CA Gateway. | roadmap-omit | — | @JuanLunaIA |
| `aegis/core/rt_scheduler.py` | module | aegis.core.rt_scheduler — Domain 3.2 real-time scheduling policy manager. | allowlisted | `tests/test_rt_scheduler.py` | @JuanLunaIA |
| `aegis/core/rust_integration.py` | module | Tier-4 Rust acceleration bridge for Aegis Latent Core. | reachable | `tests/test_coverage_final.py`, `tests/test_rust_integration_new.py` | @JuanLunaIA |
| `aegis/core/safe_serialization.py` | module | Safe helpers for serialization and deserialization. | allowlisted | `tests/test_misc_gaps.py`, `tests/test_safe_serialization.py`, `tests/test_safe_serialization_failclosed.py`, `tests/test_safe_serialization_new.py` | @JuanLunaIA |
| `aegis/core/sandbox.py` | module | aegis.core.sandbox — System-level hardening and sandbox enforcement. | roadmap-omit | `tests/test_sandbox.py` | @JuanLunaIA |
| `aegis/core/sandbox_l1.py` | module | aegis.core.sandbox_l1 — L1 Seccomp-BPF sandbox via libseccomp C API. | reachable | `tests/test_sandbox_l1.py` | @JuanLunaIA |
| `aegis/core/seccomp_guard.py` | module | aegis.core.seccomp_guard — Secure Computing (Seccomp-BPF) Enforcement. | reachable | `tests/test_seccomp_extended.py`, `tests/test_seccomp_guard_new.py`, `tests/test_seccomp_new.py` | @JuanLunaIA |
| `aegis/core/secrets.py` | module | aegis.core.secrets — Integration with HashiCorp Vault for dynamic secret management. | reachable | `tests/test_vault_manager.py` | @JuanLunaIA |
| `aegis/core/secure_runtime.py` | module | Fail-closed coordinator for optional TPM and TEE evidence backends. | roadmap-omit | — | @JuanLunaIA |
| `aegis/core/semantic_defense.py` | module | aegis.core.semantic_defense — Semantic Drift and Adversarial AI Detection. | roadmap-omit | — | @JuanLunaIA |
| `aegis/core/semantic_sim_clustering.py` | module | aegis.core.semantic_sim_clustering — Domain 5.1 semantic similarity clustering. | allowlisted | `tests/test_semantic_sim_clustering.py` | @JuanLunaIA |
| `aegis/core/session_manager.py` | module | session_manager.py - Session Lifecycle & Isolation Layer (Tier-4 Rust acceleration) | reachable | `tests/test_session_manager_new.py` | @JuanLunaIA |
| `aegis/core/slo_alerting.py` | module | aegis.core.slo_alerting — SLO burn-rate alert rule generation. | allowlisted | `tests/test_slo_alerting.py` | @JuanLunaIA |
| `aegis/core/split_brain.py` | module | aegis.core.split_brain — Domain 4.1 split-brain prevention via fencing tokens. | allowlisted | `tests/test_split_brain.py` | @JuanLunaIA |
| `aegis/core/state_snapshotter.py` | module | aegis.core.state_snapshotter — in-memory state snapshotting & rollback. | roadmap-omit | `tests/test_state_snapshotter.py` | @JuanLunaIA |
| `aegis/core/stix_taxii_ingestor.py` | module | aegis.core.stix_taxii_ingestor — STIX 2.1 / TAXII 2.1 threat feed ingestion. | allowlisted | `tests/test_stix_taxii_ingestor.py` | @JuanLunaIA |
| `aegis/core/stream_bounds.py` | module | The per-stream retained-byte ceiling, in one place. | reachable | `tests/engines/test_modular_engines.py`, `tests/test_stream_bounds.py`, `tests/test_streaming_safety_engine_integration.py` | @JuanLunaIA |
| `aegis/core/stream_redactor.py` | module | Composition of the two streaming redactors, and the choice between them. | reachable | `tests/test_streaming_safety_engine_integration.py` | @JuanLunaIA |
| `aegis/core/streaming_deidentifier.py` | module | Bounded incremental PHI/PCI redaction for streamed text. | reachable | `tests/test_phi_address_bound.py`, `tests/test_proxy_streaming.py`, `tests/test_streaming_safety_engine_integration.py` | @JuanLunaIA |
| `aegis/core/streaming_safety_engine.py` | module | Grammar-frontier automaton for streaming redaction. | reachable | `tests/redteam/test_redos_bounds.py`, `tests/test_streaming_safety_engine.py`, `tests/test_streaming_safety_engine_integration.py` | @JuanLunaIA |
| `aegis/core/taint_analysis.py` | module | aegis.core.taint_analysis — Dynamic Taint Analysis for LLM Request Pipelines. | reachable | — | @JuanLunaIA |
| `aegis/core/tee_backends.py` | module | Concrete :class:`~aegis.core.tee_manager.AttestationVerifier` backends. | allowlisted | `tests/test_tee_backends.py` | @JuanLunaIA |
| `aegis/core/tee_manager.py` | module | Fail-closed TEE discovery and attestation-policy boundary. | allowlisted | `tests/test_hardware_modules.py`, `tests/test_tee_backends.py` | @JuanLunaIA |
| `aegis/core/telemetry.py` | module | telemetry.py - Advanced Information-Theoretic Signal Analysis Layer | reachable | `tests/test_core.py`, `tests/test_coverage_final.py`, `tests/test_production_stresses.py`, `tests/test_red_team.py`, … (+4 more)` | @JuanLunaIA |
| `aegis/core/ti_sharing.py` | module | aegis.core.ti_sharing — Domain 5.4 anonymized threat intelligence sharing. | allowlisted | `tests/test_ti_sharing.py` | @JuanLunaIA |
| `aegis/core/timing_defense.py` | module | aegis.core.timing_defense — Side-Channel Timing Mitigation. | allowlisted | `tests/test_misc_gaps.py`, `tests/test_property_based.py`, `tests/test_timing_defense_new.py` | @JuanLunaIA |
| `aegis/core/token_split_detector.py` | module | aegis.core.token_split_detector — Domain 5.2 token-split reassembly attack detection. | allowlisted | `tests/test_token_split_detector.py` | @JuanLunaIA |
| `aegis/core/tpm.py` | module | aegis.core.tpm — Trusted Platform Module (TPM 2.0) Interface. | roadmap-omit | `tests/test_tpm.py` | @JuanLunaIA |
| `aegis/core/transparency_log.py` | module | aegis.core.transparency_log — Binary Transparency Log. | roadmap-omit | `tests/test_transparency_log.py` | @JuanLunaIA |
| `aegis/core/transport_hardener.py` | module | aegis.core.transport_hardener — Transport Layer Security Enforcement. | roadmap-omit | — | @JuanLunaIA |
| `aegis/core/tsa_provider.py` | module | aegis.core.tsa_provider — RFC 3161 Timestamping Authority Provider. | roadmap-omit | `tests/test_tsa_provider.py` | @JuanLunaIA |
| `aegis/core/waf_fuzzing.py` | module | aegis.core.waf_fuzzing — Differential fuzzing harness for WAF bypass detection. | allowlisted | `tests/test_waf_hypothesis.py` | @JuanLunaIA |
| `aegis/core/waf_hot_reload.py` | module | aegis.core.waf_hot_reload — WAF pattern hot-reload without process restart. | reachable | `tests/test_waf_hot_reload.py` | @JuanLunaIA |
| `aegis/core/waf_session.py` | module | aegis.core.waf_session — Multi-turn behavioral WAF session state machine. | reachable | `tests/test_waf_session.py` | @JuanLunaIA |
| `aegis/core/wal_backup.py` | module | aegis.core.wal_backup — WAL backup and restore with integrity re-verification. | allowlisted | `tests/test_wal_backup.py`, `tests/test_wal_backup_atomic_restore.py` | @JuanLunaIA |
| `aegis/core/witness_cosign.py` | module | aegis.core.witness_cosign — m-of-n threshold co-signing for bundle export. | allowlisted | `tests/test_witness_cosign.py` | @JuanLunaIA |
| `aegis/core/worm_ledger.py` | module | aegis.core.worm_ledger — application-level sealed-segment enforcement. | allowlisted | `tests/test_worm_ledger.py`, `tests/test_worm_ledger_bounds.py` | @JuanLunaIA |
| `aegis/core/worm_storage.py` | module | aegis.core.worm_storage — Hardware WORM (Write Once Read Many) Interface. | roadmap-omit | — | @JuanLunaIA |
| `aegis/core/xdp_dynamic_segmentation.py` | module | aegis.core.xdp_dynamic_segmentation — Dynamic network micro-segmentation. | reachable | `tests/test_xdp_dynamic_segmentation.py` | @JuanLunaIA |
| `aegis/core/yara_engine.py` | module | aegis.core.yara_engine — Pure-Python YARA rule engine for adversarial prompt detection. | allowlisted | `tests/test_yara_engine.py` | @JuanLunaIA |
| `aegis/core/zk_native.py` | module | Python entry point for the zero-knowledge inclusion proof. | reachable | `tests/test_zk_native_surface.py` | @JuanLunaIA |
| `aegis/core/zk_proof.py` | module | aegis.core.zk_proof — Domain 4.2 ZK-SNARK/STARK proof stubs. | reachable | `tests/crypto/test_capabilities.py`, `tests/test_zk_native_surface.py`, `tests/test_zk_proof.py` | @JuanLunaIA |
| `aegis/crypto/__init__.py` | package | Truthful facade for the cryptographic APIs that Aegis currently exposes. | reachable | `tests/crypto/test_capabilities.py`, `tests/test_zk_native_surface.py` | @JuanLunaIA |
| `aegis/crypto/capabilities.py` | module | Machine-readable, conservative capability reporting for :mod:`aegis.crypto`. | reachable | `tests/crypto/test_capabilities.py` | @JuanLunaIA |
| `aegis/embedded.py` | module | aegis.embedded — in-process evidence engine for applications that hold the | reachable | `tests/test_embedded_mode.py` | @JuanLunaIA |
| `aegis/engines/__init__.py` | package | Decoupled engine facades over capabilities that already exist in the core. | reachable | `tests/compat/test_public_api_compat.py`, `tests/engines/test_modular_engines.py` | @JuanLunaIA |
| `aegis/engines/agentis.py` | module | Agentis engine — receipts for agent-to-agent tool execution. | reachable | `tests/engines/test_modular_engines.py` | @JuanLunaIA |
| `aegis/engines/sanctum.py` | module | Sanctum engine — streaming de-identification and request scanning. | reachable | `tests/compat/test_public_api_compat.py` | @JuanLunaIA |
| `aegis/engines/sovereign.py` | module | Sovereign vault — post-quantum signing and hardware-backed key custody. | reachable | — | @JuanLunaIA |
| `aegis/engines/veracity.py` | module | Veracity engine — evidence commitment and inclusion proofs, without the proxy. | reachable | — | @JuanLunaIA |
| `aegis/forensics/__init__.py` | package | Dependency-free forensic query primitives. | reachable | `tests/forensics/test_search.py` | @JuanLunaIA |
| `aegis/forensics/search.py` | module | Typed metadata-only search over retained audit-node snapshots. | reachable | — | @JuanLunaIA |
| `aegis/licensing/__init__.py` | package | Offline verification of commercial license tokens. | reachable | `tests/compat/test_public_api_compat.py`, `tests/licensing/test_license_model.py` | @JuanLunaIA |
| `aegis/licensing/model.py` | module | The licence data model, separated from the code that verifies signatures. | reachable | `tests/licensing/test_license_model.py` | @JuanLunaIA |
| `aegis/licensing/validator.py` | module | Offline commercial license verification. | reachable | `tests/compat/test_public_api_compat.py`, `tests/engines/test_modular_engines.py`, `tests/licensing/test_license_validator.py` | @JuanLunaIA |
| `aegis/providers/__init__.py` | package | aegis.providers — Multi-provider adapter registry. | reachable | `tests/test_providers.py` | @JuanLunaIA |
| `aegis/providers/anthropic_provider.py` | module | aegis.providers.anthropic_provider — Anthropic Claude adapter. | reachable | `tests/test_forwarder_deep.py`, `tests/test_forwarder_extra.py`, `tests/test_forwarder_new.py`, `tests/test_forwarder_sse_framing.py`, … (+2 more)` | @JuanLunaIA |
| `aegis/providers/base.py` | module | aegis.providers.base — Abstract provider adapter interface. | reachable | `tests/test_provider_contracts.py` | @JuanLunaIA |
| `aegis/providers/gemini_provider.py` | module | aegis.providers.gemini_provider — Google Gemini adapter. | reachable | `tests/test_provider_contracts.py`, `tests/test_providers.py` | @JuanLunaIA |
| `aegis/providers/openai_provider.py` | module | aegis.providers.openai_provider — Passthrough adapter for OpenAI and any | reachable | `tests/test_forwarder_deep.py`, `tests/test_provider_contracts.py`, `tests/test_providers.py` | @JuanLunaIA |
| `aegis/proxy/__init__.py` | package | FastAPI proxy, WAF, and audit REST endpoints. | reachable | `tests/test_analyzer_deep.py`, `tests/test_app_coverage.py`, `tests/test_app_coverage_extended.py`, `tests/test_forwarder_extra.py` | @JuanLunaIA |
| `aegis/proxy/analyzer.py` | module | aegis.proxy.analyzer — Entropy analysis on OpenAI logprobs payloads. | reachable | `tests/test_analyzer_deep.py`, `tests/test_coverage_final.py`, `tests/test_misc_gaps.py`, `tests/test_observability.py` | @JuanLunaIA |
| `aegis/proxy/app.py` | module | — | reachable | `tests/compat/test_public_api_compat.py`, `tests/security/test_enforcement_mode_metric.py`, `tests/security/test_stream_admission_metric.py`, `tests/test_app_coverage.py`, … (+21 more)` | @JuanLunaIA |
| `aegis/proxy/attestation_api.py` | module | aegis.proxy.attestation_api — honest per-control capability reporting. | reachable | `tests/test_attestation_capabilities.py` | @JuanLunaIA |
| `aegis/proxy/audit_api.py` | module | aegis.proxy.audit_api — Read-only REST endpoints for the Merkle audit chain. | reachable | `tests/test_audit_api_new.py`, `tests/test_audit_read_snapshot.py` | @JuanLunaIA |
| `aegis/proxy/body_limits.py` | module | Streaming request-body limits, installed by both HTTP surfaces. | reachable | `tests/test_enterprise_body_limits.py` | @JuanLunaIA |
| `aegis/proxy/dependencies.py` | module | Principal-first FastAPI authentication and authorization dependencies. | reachable | `tests/auth/test_oidc_rbac.py`, `tests/security/test_tenant_isolation.py`, `tests/test_attestation_capabilities.py`, `tests/test_audit_api_new.py`, … (+2 more)` | @JuanLunaIA |
| `aegis/proxy/dmz_middleware.py` | module | aegis.proxy.dmz_middleware — DMZ-mode source-IP allowlist middleware. | reachable | `tests/test_dmz_middleware.py` | @JuanLunaIA |
| `aegis/proxy/egress_guard.py` | module | aegis.proxy.egress_guard — Application-layer egress enforcement for air-gapped zones. | reachable | `tests/test_egress_guard.py` | @JuanLunaIA |
| `aegis/proxy/forwarder.py` | module | aegis.proxy.forwarder — Provider-aware async HTTP forwarding. | reachable | `tests/test_chaos.py`, `tests/test_coverage_final.py`, `tests/test_egress_guard.py`, `tests/test_forwarder_deep.py`, … (+7 more)` | @JuanLunaIA |
| `aegis/proxy/mtls.py` | module | aegis.proxy.mtls — Mutual TLS and SPIFFE Identity Validation. | roadmap-omit | `tests/test_cac_piv.py` | @JuanLunaIA |
| `aegis/proxy/rate_limiter.py` | module | Tenant/credential-scoped request and generated-token rate limiting. | reachable | `tests/proxy/test_token_rate_limiter.py`, `tests/test_rate_limiter_reservation.py` | @JuanLunaIA |
| `aegis/proxy/schemas.py` | module | aegis.proxy.schemas — OpenAI-compatible Pydantic v2 request/response models. | reachable | `tests/test_analyzer_deep.py`, `tests/test_app_unit.py`, `tests/test_misc_gaps.py` | @JuanLunaIA |
| `aegis/proxy/streaming.py` | module | Bounded, cancellation-owned SSE proxy sessions. | reachable | `tests/engines/test_modular_engines.py`, `tests/security/test_stream_admission_metric.py`, `tests/test_forwarder_sse_framing.py`, `tests/test_proxy_streaming.py`, … (+3 more)` | @JuanLunaIA |
| `aegis/proxy/waf.py` | module | aegis.proxy.waf — Web Application Firewall for LLM Payloads. | reachable | `tests/test_market_hardening_gates.py`, `tests/test_waf_hardening.py`, `tests/test_waf_hot_reload.py`, `tests/test_waf_hypothesis.py`, … (+2 more)` | @JuanLunaIA |
| `aegis/storage/__init__.py` | package | Production storage integrations. | reachable | — | @JuanLunaIA |
| `aegis/storage/s3_worm.py` | module | Durable asynchronous archival to an S3-compatible Object Lock provider. | reachable | `tests/storage/test_s3_worm.py`, `tests/storage/test_segment_manifest.py` | @JuanLunaIA |
| `aegis/storage/segment_manifest.py` | module | Versioned manifests for finalized JSONL WAL segments. | reachable | `tests/connectors/test_parquet_exporter.py`, `tests/storage/test_segment_manifest.py` | @JuanLunaIA |
| `aegis/telemetry/__init__.py` | package | Privacy-preserving telemetry and SIEM export primitives. | reachable | — | @JuanLunaIA |
| `aegis/telemetry/events.py` | module | Closed-schema, content-free telemetry events. | reachable | `tests/telemetry/test_otel_siem.py` | @JuanLunaIA |
| `aegis/telemetry/otel.py` | module | Small typed tracing facade with strict W3C propagation and no content capture. | reachable | `tests/telemetry/test_otel_siem.py` | @JuanLunaIA |
| `aegis/telemetry/siem.py` | module | Durable content-free SIEM projections and asynchronous delivery. | reachable | `tests/telemetry/test_otel_siem.py` | @JuanLunaIA |
| `aegis_rust_v2/src/audit.rs` | rust source | Lock-free MPSC ring buffer for audit events. | reachable | — | @JuanLunaIA |
| `aegis_rust_v2/src/crdt_mmr.rs` | rust source | Causal-Merkle CRDT — a join-semilattice over domain-separated Merkle | reachable | — | @JuanLunaIA |
| `aegis_rust_v2/src/forwarder.rs` | rust source | Tier-4 async HTTP forwarder. | reachable | — | @JuanLunaIA |
| `aegis_rust_v2/src/hasher.rs` | rust source | BLAKE3 hashing — ~4 GB/s SIMD vs ~350 MB/s for Python hashlib.sha256. | reachable | — | @JuanLunaIA |
| `aegis_rust_v2/src/ledger.rs` | rust source | Cryptographic primitives: SHA-256, HMAC-SHA256, BLAKE3. | reachable | — | @JuanLunaIA |
| `aegis_rust_v2/src/lib.rs` | rust source | `aegis_rust` — Tier-4 PyO3 extension module. | reachable | — | @JuanLunaIA |
| `aegis_rust_v2/src/mmr.rs` | rust source | — | reachable | — | @JuanLunaIA |
| `aegis_rust_v2/src/pqc.rs` | rust source | ML-DSA-65 as Python sees it. | reachable | — | @JuanLunaIA |
| `aegis_rust_v2/src/pqc_trait.rs` | rust source | The ML-DSA-65 boundary, behind one trait, so the backend can be replaced. | reachable | — | @JuanLunaIA |
| `aegis_rust_v2/src/rate_limit.rs` | rust source | Lock-free token-bucket rate limiter. | reachable | — | @JuanLunaIA |
| `aegis_rust_v2/src/session.rs` | rust source | Lock-free concurrent session store backed by DashMap. | reachable | — | @JuanLunaIA |
| `aegis_rust_v2/src/waf.rs` | rust source | Tier-4 WAF: Aho-Corasick SIMD multi-pattern matcher replacing Python `re`. | reachable | — | @JuanLunaIA |
| `aegis_rust_v2/src/wal.rs` | rust source | Memory-mapped Write-Ahead Log for audit nodes. | reachable | — | @JuanLunaIA |
| `aegis_rust_v2/src/zk_bindings.rs` | rust source | Python surface for the zero-knowledge inclusion proof. | reachable | — | @JuanLunaIA |
| `aegis_rust_v2/src/zk_mmr.rs` | rust source | Zero-knowledge inclusion proof for a leaf whose recorded WAF verdict is | reachable | — | @JuanLunaIA |
| `aegis_server/__init__.py` | package | aegis_server — Enterprise-grade LLM inference governance layer. | reachable | — | @JuanLunaIA |
| `aegis_server/compliance/__init__.py` | package | aegis_server.compliance — SOC2 Type II / HIPAA audit export sub-package. | reachable | — | @JuanLunaIA |
| `aegis_server/compliance/exporter.py` | module | aegis_server.compliance.exporter — SOC 2 Type II / HIPAA evidence export engine. | reachable | `tests/test_compliance_additional.py`, `tests/test_compliance_exporter_new.py`, `tests/test_main_new.py` | @JuanLunaIA |
| `aegis_server/config.py` | module | aegis_server.config — Enterprise configuration via environment variables. | reachable | `tests/test_config_surface_inert_fields.py`, `tests/test_enterprise_body_limits.py`, `tests/test_enterprise_config_new.py`, `tests/test_enterprise_durable_evidence.py`, … (+4 more)` | @JuanLunaIA |
| `aegis_server/crypto/__init__.py` | package | aegis_server.crypto — Pluggable async signing provider layer. | reachable | `tests/test_server_factory.py`, `tests/test_zz_server_factory_additional.py` | @JuanLunaIA |
| `aegis_server/crypto/base.py` | module | aegis_server.crypto.base — Signing provider interface and HMAC-SHA256 fallback. | reachable | `tests/test_compliance_additional.py`, `tests/test_compliance_exporter_new.py`, `tests/test_local_hmac_signer.py` | @JuanLunaIA |
| `aegis_server/crypto/keyring.py` | module | Versioned HMAC keyring with atomic, fail-closed configuration reload. | reachable | `tests/test_keyring_rotation.py` | @JuanLunaIA |
| `aegis_server/crypto/vault_signer.py` | module | aegis_server.crypto.vault_signer — HashiCorp Vault Transit Engine signing provider. | reachable | `tests/test_vault_signer_new.py`, `tests/test_zz_server_factory_additional.py` | @JuanLunaIA |
| `aegis_server/main.py` | module | aegis_server.main — Enterprise FastAPI application entry point. | reachable | `tests/test_enterprise_body_limits.py`, `tests/test_enterprise_durable_evidence.py`, `tests/test_error_response_hygiene.py`, `tests/test_main_new.py` | @JuanLunaIA |
| `aegis_server/storage/__init__.py` | package | aegis_server.storage — Pluggable async audit node persistence layer. | reachable | `tests/test_security_fixes.py`, `tests/test_server_factory.py`, `tests/test_zz_server_factory_additional.py` | @JuanLunaIA |
| `aegis_server/storage/base.py` | module | aegis_server.storage.base — Abstract storage provider interface and shared data models. | reachable | `tests/storage/test_chain_fork_prevention.py`, `tests/test_dynamodb_concurrent_append_race.py`, `tests/test_postgres_concurrent_append_race.py`, `tests/test_storage_base_new.py` | @JuanLunaIA |
| `aegis_server/storage/dynamodb_provider.py` | module | aegis_server.storage.dynamodb_provider — AWS DynamoDB audit node persistence. | reachable | `tests/test_dynamodb_concurrent_append_race.py`, `tests/test_dynamodb_provider_new.py`, `tests/test_zz_dynamodb_additional.py`, `tests/test_zz_server_factory_additional.py` | @JuanLunaIA |
| `aegis_server/storage/postgres_provider.py` | module | aegis_server.storage.postgres_provider — PostgreSQL audit node persistence. | reachable | `tests/test_postgres_concurrent_append_race.py`, `tests/test_postgres_provider_new.py`, `tests/test_zz_server_factory_additional.py` | @JuanLunaIA |
| `aegis_server/storage/sqlite_provider.py` | module | aegis_server.storage.sqlite_provider — SQLite audit node persistence. | reachable | `tests/storage/test_chain_fork_prevention.py`, `tests/test_server_factory.py`, `tests/test_sqlite_additional.py`, `tests/test_sqlite_provider_new.py` | @JuanLunaIA |
| `integrations/__init__.py` | package | — | allowlisted | — | @JuanLunaIA |
| `integrations/huggingface_plugin.py` | module | integrations.huggingface_plugin — HuggingFace Transformers hook for Aegis. | allowlisted | — | @JuanLunaIA |
| `integrations/vllm_plugin.py` | module | integrations.vllm_plugin — vLLM forward hook for full logit + MoE gate extraction. | allowlisted | — | @JuanLunaIA |
| `scripts/apply_license_headers.py` | module | Apply copyright + AGPLv3 / Commercial dual-license headers to source files. | referenced | — | @JuanLunaIA |
| `scripts/audit_documentation_corpus.py` | module | Create a deterministic inventory and documentation-integrity audit. | referenced | — | @JuanLunaIA |
| `scripts/build_embedded.sh` | shell script | Build Aegis Rust extension with embedded profile (minimized for edge/OT deployment) | unreferenced | — | @JuanLunaIA |
| `scripts/build_execution_manifest.py` | module | Build the 2026-08-20 execution provenance envelope. | unreferenced | — | @JuanLunaIA |
| `scripts/build_remediation_manifest.py` | module | Build the 2026-08-21 remediation provenance envelope. | unreferenced | — | @JuanLunaIA |
| `scripts/build_rust.sh` | shell script | Reproducible helper to build aegis_rust_v2 using maturin in an isolated venv. | unreferenced | — | @JuanLunaIA |
| `scripts/collect_github_security_status.sh` | shell script | — | unreferenced | — | @JuanLunaIA |
| `scripts/create_github_release.py` | module | Create one GitHub Release through a create-only, integrity-checked gh CLI surface. | referenced | — | @JuanLunaIA |
| `scripts/extract_release_notes.py` | module | Extract one exact, non-empty stable-version section from CHANGELOG.md. | referenced | — | @JuanLunaIA |
| `scripts/generate_ai_context_manifest.py` | module | Generate the deterministic manifest for the advisory AI context pack. | referenced | — | @JuanLunaIA |
| `scripts/generate_commercial_license.py` | module | Vendor tool: mint and sign a commercial license token. | referenced | — | @JuanLunaIA |
| `scripts/generate_license_key.py` | module | generate_license_key.py — HMAC-SHA256 license key generator for Aegis v4.1.0. | unreferenced | — | @JuanLunaIA |
| `scripts/generate_mmr_vectors.py` | module | — | referenced | — | @JuanLunaIA |
| `scripts/generate_module_inventory.py` | module | Generate ``docs/MODULE_INVENTORY.md`` — the per-file inventory AUD-25 asked for. | referenced | — | @JuanLunaIA |
| `scripts/generate_sbom.sh` | shell script | Aegis Latent Core — SBOM Generation Script | unreferenced | — | @JuanLunaIA |
| `scripts/import_reachability_allowlist.txt` | text/data | — | referenced | — | @JuanLunaIA |
| `scripts/install_aegis.sh` | shell script | install_aegis.sh — Zero-touch POSIX installer for Aegis Latent Core v5.0.1 | unreferenced | — | @JuanLunaIA |
| `scripts/install_gitsign.sh` | shell script | — | referenced | — | @JuanLunaIA |
| `scripts/integration_test_mock.py` | module | integration_test_mock.py — comprehensive local verification harness for Aegis v4.1.0. | unreferenced | — | @JuanLunaIA |
| `scripts/license/license_scan.py` | module | License inventory and copyleft reconciliation across all three ecosystems. | referenced | — | @JuanLunaIA |
| `scripts/prepare_release_assets.py` | module | Flatten release payloads and generate a deterministic integrity envelope. | referenced | — | @JuanLunaIA |
| `scripts/regenerate_protobuf.sh` | shell script | Regenerate aegis/core/audit_node_pb2.py from aegis/core/audit_node.proto. | referenced | — | @JuanLunaIA |
| `scripts/smoke_test.sh` | shell script | Quick smoke test against a running AEGIS instance (default port 8080). | referenced | — | @JuanLunaIA |
| `scripts/triage/dependency_triage.py` | module | Deterministic dependency triage across the Python, Rust and npm trees. | referenced | — | @JuanLunaIA |
| `scripts/triage/parse_socket_report.py` | module | Normalize a Socket.dev PDF report into machine-readable alert rows. | referenced | — | @JuanLunaIA |
| `scripts/vendor_wheels.sh` | shell script | vendor_wheels.sh — Pre-download all Python wheels for the air-gapped build. | referenced | — | @JuanLunaIA |
| `scripts/verify_ai_context_manifest.py` | module | Verify the deterministic manifest for the advisory AI context pack. | referenced | — | @JuanLunaIA |
| `scripts/verify_claims.py` | module | Claim-control consistency checks for ``docs/CLAIMS_MATRIX.md``. | referenced | — | @JuanLunaIA |
| `scripts/verify_docs.py` | module | Structural verification for the documentation corpus. | referenced | — | @JuanLunaIA |
| `scripts/verify_formal_artifacts.sh` | shell script | — | referenced | — | @JuanLunaIA |
| `scripts/verify_github_action_pins.py` | module | Fail when a remote GitHub Action is not pinned to a full commit SHA. | referenced | — | @JuanLunaIA |
| `scripts/verify_import_reachability.py` | module | Verify every internal module is either reachable or declared roadmap. | referenced | — | @JuanLunaIA |
| `scripts/verify_links.sh` | shell script | Relative-link and heading-anchor checking across the Markdown corpus. | referenced | — | @JuanLunaIA |
| `scripts/verify_release_contract.py` | module | Validate source-only release metadata and workflow contracts. | referenced | — | @JuanLunaIA |
| `scripts/verify_release_readback.py` | module | Read a published release back from every external surface it claims (REG-028). | referenced | — | @JuanLunaIA |
| `scripts/verify_release_tag.sh` | shell script | — | referenced | — | @JuanLunaIA |
| `tools/anchor_v1_chain_into_v2.py` | module | Cross-sign a v1 MMR chain's terminal root into a new v2 chain's genesis. | referenced | — | @JuanLunaIA |
| `tools/benchmarks/run_backpressure_stall.py` | module | — | referenced | — | @JuanLunaIA |
| `tools/benchmarks/run_group_commit.py` | module | Measure what coalescing the WAL fsync does to commit latency and throughput. | referenced | — | @JuanLunaIA |
| `tools/benchmarks/run_key_rotation.py` | module | — | referenced | — | @JuanLunaIA |
| `tools/benchmarks/run_pqc_timing.py` | module | — | referenced | — | @JuanLunaIA |
| `tools/docs/verify_documentation.py` | module | Validate the Aegis documentation contract without external dependencies. | referenced | — | @JuanLunaIA |
| `tools/forensic/diagnose_aegis.py` | module | diagnose_aegis.py — Self-service diagnostic tool for Aegis Latent Core. | unreferenced | — | @JuanLunaIA |
| `tools/forensic/forensic_checks.py` | module | Run repository forensic checks: pattern search, unsafe API usage, basic Python syntax checks | referenced | — | @JuanLunaIA |
| `tools/forensic/report.json` | text/data | — | referenced | — | @JuanLunaIA |
| `tools/forensic/triage_unsafe.py` | module | Triage unsafe API usage and generate remediation suggestions. | unreferenced | — | @JuanLunaIA |
| `tools/forensic/unsafe_remediation.md` | text/data | — | unreferenced | — | @JuanLunaIA |
| `tools/qualification/__init__.py` | package | GxP qualification scripts — IQ/OQ evidence generation. | referenced | — | @JuanLunaIA |
| `tools/qualification/iq_checks.py` | module | Installation Qualification (IQ) protocol — verifies Aegis is installed per specification. | unreferenced | — | @JuanLunaIA |
| `tools/qualification/oq_checks.py` | module | Operational Qualification (OQ) protocol — verifies Aegis operates per specification. | unreferenced | — | @JuanLunaIA |
| `tools/security/run_waf_corpus.py` | module | — | referenced | — | @JuanLunaIA |
| `tools/visualizer/README.md` | text/data | — | referenced | — | @JuanLunaIA |
| `tools/visualizer/app.py` | module | — | referenced | — | @JuanLunaIA |
| `tools/visualizer/generate_samples.py` | module | Generate the `Samples/` gallery: copies of the live dashboard (static/index.html) | referenced | — | @JuanLunaIA |
| `tools/visualizer/generate_summary.py` | module | Generate a JSON summary of the repository: files, Python functions/classes, Rust functions, counts and an optional test_results snapshot. | unreferenced | — | @JuanLunaIA |
| `tools/visualizer/requirements.txt` | text/data | — | referenced | — | @JuanLunaIA |
| `tools/visualizer/static/index.html` | other | — | referenced | — | @JuanLunaIA |
| `tools/visualizer/test_results.json` | text/data | — | unreferenced | — | @JuanLunaIA |
| `tools/visualizer/threat_lab.py` | module | tools.visualizer.threat_lab — live multi-engine threat scanning for the dashboard. | unreferenced | — | @JuanLunaIA |
| `tools/wal_repair.py` | module | Truncate a torn trailing line from a JSONL evidence WAL, under explicit consent. | referenced | — | @JuanLunaIA |


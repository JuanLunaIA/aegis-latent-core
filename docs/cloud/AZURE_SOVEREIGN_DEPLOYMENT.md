# Aegis v6.0.0 Sovereign Azure Architecture & Cloud Deployment Guide

## Overview

Aegis v6.0.0 "Sovereign Azure" enforces a 5-plane decoupled architecture deployed on Azure Sovereign Cloud / Government topology:

1. **Ingress Plane:** Native Rust gateway (`tokio`, `s2n-tls`) terminating TLS 1.3 with hybrid post-quantum key exchange (`X25519MLKEM768`).
2. **Data Plane:** Token emission path providing sub-10ms Time-To-First-Token (TTFT) with headers `X-Aegis-Evidence-ID: <uuid>` and `X-Aegis-Evidence-Status: pending-anchoring`.
3. **Evidence Plane:** Bounded non-blocking lock-free shadow pipeline consuming SHA-256 rolling digests and WAL frames.
4. **Trust Anchor Plane:** Azure Confidential VMs (AMD SEV-SNP node pools) paired with vNet-peered Thales Luna Network HSM (FW 7.9+, PKCS#11) for ML-DSA-65 hardware-attested signatures.
5. **WORM Anchor Plane:** Azure Blob Storage Immutable (Legal Hold + Time-Based Retention Policy) for tamper-proof archival.

---

## Azure Key Vault Post-Quantum Cryptography (PQC) Status

> **CRITICAL EPISTEMIC NOTICE:**
> The current state of native ML-DSA / PQC support in Azure Key Vault (AKV) is `[UNKNOWN]`.
> Aegis MUST NOT rely on AKV for post-quantum non-repudiation signing.
> Hardware-rooted ML-DSA-65 signing is strictly anchored to the vNet-attached Thales Luna HSM via PKCS#11.

---

## FedRAMP Moderate / High Pathway (NIST SP 800-53 Rev. 5 Controls)

| NIST Control | Control Title | Aegis Sovereign Azure Implementation |
| :--- | :--- | :--- |
| **AU-9** | Protection of Audit Information | Azure Blob Storage Immutable WORM + Tier C OpenRaft linearizable Merkle chain. |
| **SC-12** | Cryptographic Key Establishment | Hybrid PQC Key Exchange (`X25519MLKEM768`) via `s2n-tls` native ingress. |
| **SC-13** | Cryptographic Protection | Hardware-rooted ML-DSA-65 signing via Thales Luna HSM (PKCS#11). |
| **SC-28** | Protection of Information at Rest | AMD SEV-SNP confidential memory encryption + AES-256-GCM HKDF per-tenant keys. |
| **SI-7** | Software, Firmware, and Information Integrity | Continuous Merkle Mountain Range (MMR) root verification and single-writer WAL locks. |

---

## Secondary Cloud-Native Fallback: AWS Nitro Enclaves

For multi-cloud or AWS deployments, the Trust Anchor Plane falls back to AWS Nitro Enclaves connected over `vsock` with KMS attestation.

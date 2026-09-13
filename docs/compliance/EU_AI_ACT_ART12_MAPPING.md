# EU AI Act Article 12 Compliance Mapping

## Regulatory Mandate Mapping

| EU AI Act Article 12 Requirement | Technical Specification | Aegis v6.0.0 Sovereign Architecture | Verification Status |
| :--- | :--- | :--- | :--- |
| **Art. 12(1) Logging Capabilities** | Automatic recording of events throughout high-risk AI system lifecycle. | Bounded non-blocking shadow pipeline recording prompt/completion digests in WAL. | `[ESTABLISHED]` |
| **Art. 12(2) Traceability & Integrity** | Traceability of AI system functioning across operational lifespan. | OpenRaft linearizable Merkle chain guaranteeing exact total ordering. | `[ESTABLISHED]` |
| **Art. 12(3) Post-Market Monitoring** | In-flight telemetry and threat detection logging. | Real-time WAF normalization, PHI/PCI scrubbing, and SIEM CEF export. | `[ESTABLISHED]` |
| **Art. 12(4) Non-Repudiation** | Hardware-rooted identity attribution. | Thales Luna HSM PKCS#11 / ML-DSA-65 post-quantum signing. | `[ESTABLISHED]` |

## Notes
Azure Key Vault PQC capability remains `[UNKNOWN]`; hardware non-repudiation relies on vNet-peered Thales Luna HSM.

<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
-->

# Aegis — Cross-Domain Compliance Mapping (v2.4.1)

> **Purpose.** Map each regulated industry vertical to the *specific, implemented*
> Aegis controls that support it, with a direct pointer to the source code that
> provides the control and the configuration toggle that enables it.
>
> **Honesty contract.** This document follows the same epistemic policy as
> [`docs/audit/CLAIMS_VERIFICATION.md`](../audit/CLAIMS_VERIFICATION.md). Every
> row is labelled:
>
> | Marker | Meaning |
> |---|---|
> | `[PROVEN]` | Implemented in code, covered by tests, verifiable from the cited file. |
> | `[PARTIAL]` | Implemented for the stated scope, with an explicit documented boundary; not a full control by itself. |
>
> Aegis is an **AI gateway / control plane**, not a turnkey compliance product.
> It supplies *technical, tamper-evident audit and data-handling controls* on the
> LLM request/response path. It does **not** discharge an organisation's full
> regulatory obligation. Every section below states the boundary explicitly under
> **"Customer responsibility."**

---

## How to read this document

Each vertical lists:

1. **Regulatory anchor** — the rule(s) the controls speak to.
2. **What Aegis provides** — the implemented control, its source file, and the
   environment toggle that enables it.
3. **Customer responsibility** — what the deploying organisation must still own.
   These boundaries are deliberate, not omissions.

Configuration is via environment variables read by
[`aegis/config.py`](../../aegis/config.py). All cryptographic signing uses
`AEGIS_SIGNING_KEY` (HMAC-SHA256) or the Rust ML-DSA-65 path; the signing key is
kept strictly separate from upstream API keys and from `AEGIS_PHI_MASTER_KEY`.

---

## 1. Finance & Banking — `DX-Finance`

**Regulatory anchor:** SEC Rule 17a-4(b), FINRA Rule 4511, MiFID II Art. 16(6)/25(1),
Dodd-Frank §727 / CFTC Rule 45.2.

| Control | Status | Evidence |
|---|---|---|
| WORM (Write-Once Read-Many) sealing of WAL segments — app-level `WORMViolationError` on any mutate, plus OS-level `0o400` read-only bits | `[PROVEN]` | [`aegis/core/worm_ledger.py`](../../aegis/core/worm_ledger.py) — `WORMEnforcer.seal()` / `enforce_immutability()` / `delete_node()` |
| SEC 17a-4 retention-period attestation bundle (3-yr accessible / 6-yr total), HMAC-SHA256 sealed per-segment and bundle-level | `[PROVEN]` | `WORMEnforcer.attest()`, `SEC_17A4_BROKER_DEALER`, `WORMAttestationBundle.verify_bundle_hmac()` |
| MiFID II / Dodd-Frank communication record-keeping (5-yr+), content-hash-only records to minimise personal-data exposure | `[PROVEN]` | [`aegis/core/mifid_record_keeper.py`](../../aegis/core/mifid_record_keeper.py) — `MiFIDRecordKeeper.record_communication()` |
| PCI-DSS v4.0 cardholder-data masking on the request/response path (PAN → last-4 per §3.4, CVV/track fully redacted) | `[PROVEN]` | `aegis/config.py` `AEGIS_PCI_SCRUB`; `aegis.core.pci_detector` |
| Tamper-evident Merkle audit chain for every order/advice interaction | `[PROVEN]` | [`aegis/core/crypto_audit.py`](../../aegis/core/crypto_audit.py); `GET /v1/audit/integrity` |

**What Aegis provides.** A non-rewriteable ledger of LLM-mediated financial
communications. Once `WORMEnforcer.seal()` is called on a closed WAL segment, the
segment cannot be altered in-process (raises `WORMViolationError`) or by a
non-root OS actor (`0o400`). `attest()` produces a regulator-submittable bundle
carrying the retention deadlines and an HMAC over each seal sentinel.

**Customer responsibility.**
- **Storage substrate.** App + OS WORM is defence-in-depth, *not* SEC-grade
  non-erasable media on its own. The `WORMEnforcer` docstring is explicit: a root
  actor can still bypass `0o400`. For 17a-4(f) you must place the sealed WAL on
  WORM-capable hardware/object-lock storage (e.g. S3 Object Lock in compliance
  mode, or `chattr +i` + immutable backups) and operate the designated-third-party
  (D3P) access process.
- **Retention scheduling & legal hold.** Aegis computes `purge_eligible_at`; your
  retention system must enforce it.
- **Surveillance/supervision** of the *content* of advice is out of scope — Aegis
  records and seals; it does not adjudicate suitability.

---

## 2. Healthcare & Life Sciences — `DX-Healthcare`

**Regulatory anchor:** HIPAA Security Rule 45 CFR §164.312(b) (audit controls),
HIPAA Privacy Rule 45 CFR §164.514(b) (Safe Harbor de-identification),
NIST SP 800-188.

| Control | Status | Evidence |
|---|---|---|
| §164.312(b) audit controls — cryptographically sealed SOC2/HIPAA export bundle (SHA-256 canonical chain hash + signer-scheme signature, offline re-verifiable) | `[PROVEN]` | [`aegis_server/compliance/exporter.py`](../../aegis_server/compliance/exporter.py) — `ComplianceExporter.export()` / `verify_bundle()` |
| §164.514(b) Safe Harbor de-identification — 18 HIPAA identifier categories scrubbed on both request and response, regex (no NLP model required) | `[PROVEN]` | [`aegis/core/phi_deidentifier.py`](../../aegis/core/phi_deidentifier.py); `AEGIS_PHI_DEIDENTIFY` |
| Structure-aware PHI redaction for HL7 v2 (segment+field, e.g. PID-5/PID-19) and FHIR R4/R5 (resourceType + JSON path) | `[PROVEN]` | [`aegis/core/hl7_fhir_phi_detector.py`](../../aegis/core/hl7_fhir_phi_detector.py) — `HL7FHIRPHIDetector.scrub()` |
| PHI payload encryption at rest — AES-256-GCM under a per-tenant HKDF-SHA256 DEK, master key held separately from the signing key | `[PROVEN]` | `aegis/config.py` `AEGIS_PHI_MASTER_KEY`; `aegis.core.audit_node_encryptor` |
| Differentially-private aggregate analytics (ε-DP Laplace) so published stats cannot re-identify a session | `[PROVEN]` | [`aegis/proxy/audit_api.py`](../../aegis/proxy/audit_api.py) `GET /v1/audit/analytics/dp`; `aegis.core.dp_analytics` |

**What Aegis provides.** A §164.312(b)-aligned audit trail with tamper-evidence,
plus inline Safe Harbor scrubbing that removes PHI from prompts *before* they
reach a third-party LLM and from completions *before* they return to the client.
`AEGIS_PHI_MASTER_KEY` is required (and must differ from `AEGIS_SIGNING_KEY`) when
de-identification is enabled in a HIPAA deployment.

**Customer responsibility.**
- **BAA & covered-entity obligations.** Aegis is a technical safeguard; you remain
  the covered entity / business associate and must execute BAAs with your LLM
  provider where applicable.
- **Safe Harbor completeness.** Regex Safe Harbor catches the 18 enumerated
  categories; free-text clinical narrative may carry residual identifiers that
  pattern matching cannot guarantee to remove. For Expert Determination
  (§164.514(b)(1)) you must engage a qualified statistician. The HL7/FHIR scrubber
  redacts *mapped* fields only — bespoke extensions need mapping additions.
- **Administrative & physical safeguards** (§164.308/§164.310) are out of scope.

---

## 3. Government & Defense — `DX-Gov`

**Regulatory anchor:** DoD CC SRG IL5/IL6, DoDI 8520.02 (CAC), NIST SP 800-73-4
(PIV/PIV-I), GSA FPKI, FedRAMP High (technical control families AU/AC/SC).

| Control | Status | Evidence |
|---|---|---|
| DoD CAC / GSA PIV client-certificate identity — policy-OID gate + Client-Auth EKU, EDIPI (CAC) / UUID (PIV-I) extraction from the mTLS cert | `[PROVEN]` | [`aegis/core/cac_piv.py`](../../aegis/core/cac_piv.py); `AEGIS_CAC_PIV_REQUIRED` |
| Air-gapped egress containment — deny-all outbound except an explicit allow-list plus the configured upstream backend | `[PROVEN]` | `aegis/config.py` `AEGIS_AIRGAP_MODE` / `AEGIS_AIRGAP_ALLOWED_HOSTS`; `aegis.proxy.egress_guard` |
| Air-gapped container image (no network base layers) | `[PROVEN]` | [`deploy/docker/Dockerfile.airgap`](../../deploy/docker/Dockerfile.airgap) |
| Kernel-level containment — seccomp syscall filter + AppArmor profile | `[PARTIAL]` | [`deploy/apparmor/aegis.profile`](../../deploy/apparmor/aegis.profile); `deploy/network-isolation.yaml` |
| Military classification-marker detection (e.g. spillage of classified banners into prompts) | `[PROVEN]` | [`aegis/core/classified_marker_detector.py`](../../aegis/core/classified_marker_detector.py) |
| Post-quantum signing (FIPS 204 ML-DSA-65) on audit nodes | `[PARTIAL]` | Rust `aegis_rust` ML-DSA path; Ed25519 fallback marks bundle `legal_admissibility="Compromised"` (see [`CLAIMS_VERIFICATION.md`](../audit/CLAIMS_VERIFICATION.md) row L3) |
| mTLS / TLS termination with client-cert verification | `[PARTIAL]` | `AEGIS_MTLS_REQUIRED`, `AEGIS_SSL_CA_CERTS`; per-request client-cert *identity assertion in auth* is the boundary (see L2) |

**What Aegis provides.** An air-gappable gateway that can require hardware-token
(CAC/PIV) identity at the TLS edge, refuse all egress outside a sealed allow-list,
and run under a restrictive AppArmor/seccomp profile suitable for IL5/IL6
compartmentalisation.

**Customer responsibility.**
- **ATO / authorisation boundary.** FedRAMP High and IL5/IL6 are *accreditation*
  programmes. Aegis supplies specific technical controls (AU/AC/SC family
  building blocks); the System Security Plan, continuous monitoring, personnel,
  and physical controls remain yours.
- **CAC/PIV chain validation.** `AEGIS_CAC_PIV_REQUIRED` validates the policy OID
  and EKU; you must supply a trusted `AEGIS_SSL_CA_CERTS` bundle and operate CRL/OCSP
  revocation checking at your TLS terminator.
- **`[PARTIAL]` items** are scoped exactly as the linked CLAIMS rows state — do not
  represent the Ed25519 fallback as PQC, or the AppArmor profile as a full MAC
  policy without your own SELinux/AppArmor enforcement testing on the target host.

---

## 4. Forensic & Judicial — `DX-Forensic`

**Regulatory anchor:** ISO/IEC 27037:2012 (digital evidence), Daubert /
Fed. R. Evid. 702 (admissibility), 21 CFR Part 11 §11.50 (e-signature records).

| Control | Status | Evidence |
|---|---|---|
| ISO/IEC 27037 evidence package — chain-of-custody manifest, acquisition metadata, SHA-256 hash declaration, evidence nodes, integrity seal; offline `verify_seal()` | `[PROVEN]` | [`aegis/core/iso27037_evidence.py`](../../aegis/core/iso27037_evidence.py) — `build_evidence_package()` |
| Per-bundle legal-admissibility classification (Admissible / Conditional / Compromised) with justification, sealed | `[PROVEN]` | `iso27037_evidence.py` — `LegalAdmissibility` |
| 21 CFR Part 11 §11.50 e-signature export — signer name, signature meaning, timestamp + cryptographic binding to the chain | `[PROVEN]` | [`aegis/proxy/audit_api.py`](../../aegis/proxy/audit_api.py) `GET /v1/audit/export/part11`; `crypto_audit.export_part11_signatures()` |
| Forensic PDF report & DFIR export | `[PROVEN]` | [`aegis/core/forensic_pdf_report.py`](../../aegis/core/forensic_pdf_report.py), [`aegis/core/dfir_export.py`](../../aegis/core/dfir_export.py) |
| Trusted timestamping (RFC 3161 TSA) and external anchoring | `[PARTIAL]` | [`aegis/core/tsa_provider.py`](../../aegis/core/tsa_provider.py), [`aegis/core/anchoring.py`](../../aegis/core/anchoring.py) — require an external TSA/anchor endpoint to be configured |

**What Aegis provides.** Self-contained, offline-verifiable evidence packages: the
`integrity_seal` is a SHA-256 over the canonical serialisation of every other
field, so a third party with only the JSON file and `verify_seal()` can confirm
the package was not altered post-export — the property an expert needs to satisfy
Daubert authenticity and reliability prongs.

**Customer responsibility.**
- **EWF/E01 disk imaging.** Aegis seals the *audit-chain* evidence (LLM
  interaction records), not raw-media forensic disk images. EWF/E01 acquisition of
  host media is performed with dedicated forensic imagers (FTK Imager, `ewfacquire`)
  and is **out of scope** for this gateway.
- **PKCS#7/CMS SignedData.** The native bundle signature is HMAC-SHA256 or ML-DSA;
  if your court process specifically demands a CMS detached signature, wrap the
  exported bundle with your PKI's CMS signer — Aegis does not emit CMS containers.
- **Custody discipline.** The chain-of-custody manifest records what you log into
  it; the integrity of operator identities depends on your access controls.

---

## 5. Pharma / GxP Computerised Systems

**Regulatory anchor:** EU GMP Annex 11, GAMP 5 (2nd ed.), 21 CFR Part 11,
21 CFR Part 211.

| Control | Status | Evidence |
|---|---|---|
| Change control + version-gated deployment gate (refuses deploy without an approved change record for the exact version) | `[PROVEN]` | [`aegis/core/gxp_qualification.py`](../../aegis/core/gxp_qualification.py) — `ChangeControlRegistry`, `DeploymentGate` |
| Requirement → Design → Test → Evidence traceability matrix (GAMP 5 RTM) | `[PROVEN]` | `RequirementTraceMatrix` |
| Performance Qualification sign-off, HMAC-SHA256 signed by approver | `[PROVEN]` | `PerformanceQualification`, `VendorQualificationPackage` |
| Audit-trail lock-out (records cannot be altered/deleted after commitment) | `[PROVEN]` | `worm_ledger.py` `enforce_immutability()` cites Annex 11 §5 / NIST AU-9 |

**Customer responsibility.** GAMP 5 validation is a *lifecycle process*. Aegis
supplies code-tractable artefacts (change control, RTM, PQ sign-off) that slot into
a supplier-qualification dossier; URS authorship, IQ/OQ execution on your
infrastructure, and QA approval remain yours.

---

## 6. Cross-cutting: SOC 2 Type II / ISO 27001

| Control | Status | Evidence |
|---|---|---|
| SOC2 CC6.1 / CC7.2 + ISO 27001 A.12.4 — sealed audit-trail export with completeness + tamper evidence | `[PROVEN]` | [`aegis_server/compliance/exporter.py`](../../aegis_server/compliance/exporter.py) |
| Full-chain integrity sweep on demand | `[PROVEN]` | `GET /v1/audit/integrity` |

The same `ComplianceExporter` bundle serves SOC2, HIPAA §164.312(b), and ISO 27001
A.12.4 — it is a general tamper-evident audit-evidence package, re-verifiable
offline via `ComplianceExporter.verify_bundle()`.

---

## 7. SMBs / PyMEs — zero-configuration default path

The defaults in `aegis/config.py` are safe-by-default for a single-node
deployment: a local file WAL written `0o600`, `auth_disabled` permitted **only**
when `debug_mode=True`, and no compliance toggle forced on. A small business runs
the stock [`deploy/docker/docker-compose.yml`](../../deploy/docker/docker-compose.yml)
and gets a working, audited gateway without touching any of the regime-specific
flags above. Enabling a vertical is purely additive — set the env vars named in
the relevant section.

---

## Boundary summary (what Aegis is *not*)

Aegis does not, and does not claim to:

- adjudicate the **correctness, bias, or safety of upstream model outputs**;
- protect against a **compromised host** with root (OS WORM is defence-in-depth,
  not a hardware guarantee);
- substitute for **accreditation/authorisation programmes** (FedRAMP ATO, SOC 2
  attestation, GxP validation) — it supplies *technical evidence*, auditors and
  assessors render the opinion;
- emit **CMS/PKCS#7 containers or EWF/E01 disk images** natively;
- discharge **administrative, physical, or personnel** safeguards.

Every claim above maps to a cited file. If a control you need is not listed here
with a `[PROVEN]` or scoped `[PARTIAL]` marker, treat it as **not provided** until
it appears in this matrix.

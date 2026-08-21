# DOC-06: Commercial Strategy, C-Suite Buyer Dossier, and Procurement Package

**Document ID:** DOC-06
**Language:** US English
**Purpose:** Controlled commercial and procurement dossier
**Claim-control authority:** [`docs/CLAIMS_MATRIX.md`](../CLAIMS_MATRIX.md)
**Commercial status:** Community evaluation is available under the repository license; a bounded pilot is a proposed buying motion; production commercial terms are contract-dependent; sovereign, OEM, independent assurance, global ordering, multi-region high availability, and contractual service levels remain roadmap or legal-review items.

## 1. Executive decision brief

Aegis is positioned in the repository as an **OpenAI-compatible AI Governance and Evidence Gateway**. Its defensible present-tense proposition is narrow: it can place an application-layer control point between a client and configured model providers, apply request controls, and create durable, verifiable evidence under declared deployment conditions. The repository does not establish that Aegis is production-ready for a buyer, achieves a return on investment, supports a particular transaction rate in production, meets an availability target, has customers, offers round-the-clock support, or holds a security or regulatory certification.

The recommended buying decision is therefore **evaluate, then pilot, then contract**, rather than purchase based on a generalized compliance or performance claim. A buyer should first reproduce repository evidence, then test a named workload in the buyer's target ingress, storage, identity, secret-management, provider, network, backup, and recovery environment. Production authorization must remain gated on security, privacy, legal, operational, and commercial review.

> **Controlled value statement:** Route governed AI traffic through a provider-independent gateway and evaluate whether the resulting policy and evidence boundary reduces the buyer's verification gap under the buyer's own deployment and organizational controls.

The phrase “provider-independent” describes the gateway boundary and adapter intent; it does not mean provider behavior, safety, availability, or contractual terms are interchangeable. The phrases “compliant,” “certified,” “court-admissible,” “quantum-safe,” “constant-time,” “zero latency,” “unlimited throughput,” “24/7,” and “production-ready” are not authorized without a named artifact, scope, qualified reviewer, executed contract where applicable, and falsification condition.

## 2. Source-control and interpretation rules

This package synthesizes repository materials, production code, focused tests, formal records, and machine-readable evidence. Repository prose, samples, pasted text, generated output, and third-party framework references were treated as **untrusted inputs** until reconciled with code, tests, evidence boundaries, and the normative claims matrix. Static material under `Samples/` is illustrative and is not customer, runtime, capacity, or cryptographic evidence.

The following precedence applies if materials conflict:

| Priority | Source | Procurement use |
|---|---|---|
| 1 | Executed agreement and applicable law | Governs purchased rights, obligations, warranty, liability, support, data terms, and legal conclusions. No such agreement is supplied by the repository. |
| 2 | `LICENSE`, `NOTICE`, and counsel-approved commercial terms | Governs open-source and negotiated licensing boundaries. `COMMERCIAL.md` is explanatory, not a substitute for license text or counsel. |
| 3 | `docs/CLAIMS_MATRIX.md` | Normative public-language control for product, performance, security, assurance, and commercial claims. |
| 4 | Production code, focused tests, and retained evidence JSON | Establishes implemented behavior or measured results only within the exact exercised boundary. |
| 5 | Architecture, operations, privacy, compliance, FAQ, commercial, prospectus, and roadmap documents | Supplies design intent, operating assumptions, buyer context, open work, and review gates. |
| 6 | Samples, marketing summaries, and unexecuted plans | Context only; never proof of production behavior, adoption, customer outcome, or contractual capacity. |

A claim is blocked if its named source changes materially, its regression or measurement fails, its workload changes without rerun, a deployment prerequisite is absent, a reviewer identifies a contradiction, or customer-facing language becomes stronger than [`docs/CLAIMS_MATRIX.md`](../CLAIMS_MATRIX.md). Roadmap and legal-review claims are not current product promises.

## 3. Commercial strategy

### 3.1 Initial buyer profile and problem

The documented initial profile is a private-deployment B2B SaaS, fintech, or regulated-enterprise platform/security team operating multiple model providers. The buyer problem is not simply model access. It is the difficulty of proving which policy, route, evidence commit, error path, and operational control applied to a particular AI request across provider and deployment boundaries.

This profile is a **commercial hypothesis**, not evidence of market adoption. The repository contains no validated customer list, testimonials, paid-pilot results, market-share evidence, or validated willingness-to-pay data. The commercial sequence should seek falsifiable evidence of buyer need before expanding the product or support promise.

### 3.2 Packaging and promise boundary

| Package | Commercial stage | Included or evaluable scope | Explicit exclusions and gates |
|---|---|---|---|
| Community / OSS | **Current** | Repository source, tests, documentation, and self-hosted evaluation under the AGPLv3 file in `LICENSE`. | No support, SLA, availability, warranty, indemnity, production-readiness, certification, or commercial-license promise is created by this package. License interpretation requires counsel. |
| Team / Pilot | **Pilot proposal** | Time-bounded evaluation of a declared workload; evidence replay; bounded architecture and deployment review; agreed acceptance report. | Scope, staffing, support hours, environments, data handling, success criteria, fees, expenses, and exit terms require a written order. No price or service level is asserted here. |
| Production | **Production-contract-dependent** | Commercial self-hosted rights, deployment guidance, updates, and support only to the extent stated in an executed agreement. | Blocked until accountable operations, security/privacy acceptance, data terms, support model, key custody, rollback ownership, target evidence, legal terms, and order economics are approved. |
| Enterprise | **Production-contract-dependent** | Potential multiple-environment rights, security review cooperation, architecture assistance, and negotiated response targets. | No response target, coverage window, maintenance term, escalation commitment, or service credit exists unless staffed, measured, and executed in contract. |
| Sovereign / OEM | **Roadmap** | Potential air-gapped, redistribution, embedded, escrow, dedicated-assurance, or special-custody terms. | Not a default current offer. Requires capacity, export/sanctions review where applicable, intellectual-property review, separate economics, security architecture, and executed terms. |

No package has a validated price in this document. Existing commercial materials describe pricing only as hypotheses pending buyer interviews, comparable quotes, cost-to-serve modeling, and a paid pilot. Any quote must identify its assumptions and must not convert a benchmark into a capacity or SLA promise.

### 3.3 Commercial validation plan

A disciplined commercial cycle should capture the buyer's present control gap, the cost and risk of the existing process, the evidence required by internal reviewers, the target deployment constraints, and whether a bounded pilot changes an actual approval or operating decision. Evidence of interest is not evidence of willingness to pay; a meeting, repository star, download, or unpaid technical exercise must not be reported as a customer or validated demand.

The commercial owner should record the following without pre-populated values:

| Validation field | Required record | Falsification or stop condition |
|---|---|---|
| Buyer problem | Named workflow, current control/evidence gap, accountable owner, and consequence of the gap | No accountable owner, no decision affected, or problem is adequately solved by an existing control |
| Buying authority | Economic buyer, technical approver, security/privacy/legal reviewers, procurement process, and budget path | No identified approval path or authority to run the pilot |
| Pilot willingness | Written scope, access to target-like environment, buyer operators, test data classification, and acceptance criteria | Buyer will not supply the environment, owner, evidence, or decision date needed to evaluate |
| Price validation | Buyer reaction to an actual scoped quote and its assumptions | Interest exists only at an economically unsupportable or unscoped commitment |
| Conversion evidence | Executed paid pilot or production order with stated scope | No executed order; do not count verbal intent as booked revenue or a customer reference |
| Outcome evidence | Before/after method approved by buyer, with confounders and measurement boundary | Method cannot isolate the claimed outcome or buyer declines publication/usage rights |

## 4. C-suite buyer dossier

### 4.1 Decision roles and questions

| Role | Decision question | Evidence to request | Decision boundary |
|---|---|---|---|
| Chief Executive Officer / business sponsor | Does this solve a material governance or evidence problem without creating an unsupported enterprise commitment? | Named use case, accountable owner, pilot decision, risk register, commercial assumptions, and exit criteria | No ROI, adoption, strategic moat, or customer-validation claim is established by the repository. |
| Chief Information Officer / platform executive | Can the gateway fit the target application, provider, identity, network, storage, and operating model? | Architecture, target topology, dependency inventory, rollback exercise, capacity test, supported-version proposal, and ownership map | Integration feasibility and production suitability are configuration-dependent and must be tested in the buyer environment. |
| Chief Information Security Officer | Does the control/evidence boundary improve detection and verification without overstating protection? | Threat model, source revision, focused tests, WAF artifact, backpressure artifact, key-rotation artifact, SBOM, dependency records, ingress tests, secret-manager acceptance, and independent-review plan | WAF coverage is bounded; host root, provider compromise, signing-key theft, HTTP/2 parser differentials, and volumetric DDoS remain outside current evidence. |
| Chief Risk, Compliance, or Audit Executive | Can the evidence support selected control tests and audit requests? | Claims matrix, control mapping, data lineage, retention decision, evidence verifier, population/completeness test, chain-of-custody process, and reviewer qualifications | Technical evidence may contribute to an assessment; it is not a certification, audit opinion, authorization, conformity assessment, or legal conclusion. |
| General Counsel / Privacy Officer | Are licensing, data role, retention, transfers, evidence use, and liability terms acceptable? | `LICENSE`, `NOTICE`, `COMMERCIAL.md`, data-flow inventory, data categories, controller/processor roles, retention/deletion design, subprocessors/providers, geography, DPA terms, and evidentiary-use statement | AGPL effect, commercial rights, privacy obligations, admissibility, warranty, indemnity, and regulatory applicability require counsel. |
| Chief Financial Officer / procurement sponsor | Are scope, unit drivers, support burden, risk allocation, and exit costs understood? | Assumption-based quote, cost-to-serve worksheet, payment and renewal terms, deployment responsibilities, support staffing, usage drivers, dependencies, termination assistance, and liability proposal | No validated price, savings, payback period, total cost, margin, or ROI is available from the repository. |
| SRE / operations owner | Does failure behavior match the service's reliability and evidence-completeness requirements? | Storage-stall test, failure injection, rate-limiter outage behavior, monitoring specification, backup/restore exercise, incident runbook, rollback owner, and customer workload measurement | Local tests do not establish a production SLO, availability level, recovery objective, or target storage durability. |

### 4.2 Executive recommendation template

The executive sponsor should approve only a **bounded evaluation** when the buyer has a material evidence/control gap, a named target workload, a target-like environment, accountable technical and risk owners, acceptable data classification, and an agreed decision to be made from pilot results. The sponsor should decline or defer when the business case depends on an unverified certification, guaranteed throughput, unstaffed support commitment, legal admissibility, universal jailbreak prevention, global evidence ordering, or a production-readiness representation.

## 5. Buyer discovery and diligence questions

### 5.1 Business and governance

1. Which approval, audit, incident, or model-governance decision is impaired by the current evidence gap?
2. Who owns that decision, and what evidence would change it?
3. Which AI applications, providers, tenants, and data classes are in scope?
4. Is the requirement policy enforcement, evidence durability, provider routing, investigation support, or a combination?
5. What is explicitly out of scope for the first evaluation?
6. Does the buyer require a certification, authorization, auditor opinion, legal determination, or independent assessment that the repository does not supply?
7. What event would cause the buyer to stop the pilot or reject production adoption?

### 5.2 Architecture and operations

1. What are the ingress, protocol, authentication, authorization, model-provider, DNS, TLS, egress, and network-policy boundaries?
2. How many environments, replicas, workers, regions, and tenancy boundaries are proposed?
3. What are the request-size, streaming, tool-use, provider-error, timeout, concurrency, and retry profiles?
4. Which storage system will hold evidence, and what durability, immutability, backup, restore, retention, and deletion controls apply?
5. Is Redis required for the proposed topology, and what failure policy is acceptable?
6. Which secret manager, key custodian, rotation process, signer, and verification authority will be used?
7. Who owns deployment, monitoring, incident response, change control, rollback, and evidence export?
8. Which runtime controls, kernel capabilities, container profile, and read-only paths are required?

### 5.3 Security, privacy, and legal

1. Will raw prompts or responses be retained, or only hashes and metadata under the selected path?
2. What personal, regulated, confidential, privileged, export-controlled, or classified data may transit the gateway?
3. What are the lawful basis, minimization, residency, transfer, access, deletion, legal hold, and data-subject requirements?
4. What security review, penetration testing, vulnerability disclosure, incident notification, and remediation evidence is required?
5. Does the buyer require HTTP/2 ingress differential testing, external WAF testing, HSM/Vault integration, or independent cryptographic review?
6. What open-source use, network-use, modification, redistribution, embedded use, source-availability, escrow, and third-party-license obligations require counsel review?
7. Will evidence be used in litigation, employment, regulated decisions, or law-enforcement processes requiring a qualified chain-of-custody and admissibility analysis?

### 5.4 Commercial and procurement

1. Which legal entity will contract, in which geography, and under whose paper?
2. Which environments, deployment rights, updates, architecture work, questionnaire work, training, and implementation activities are requested?
3. What support window, severity taxonomy, response objective, restoration objective, escalation path, maintenance window, supported-version policy, and exclusions are requested?
4. What request, concurrency, retention, storage, provider, replica, region, and environment drivers should inform the quote?
5. Which security, privacy, insurance, accessibility, business-continuity, subcontractor, export, and audit terms are mandatory?
6. Who pays cloud, provider, storage, observability, backup, secret-manager, independent-assessment, travel, and tax costs?
7. What are the pilot conversion, renewal, termination, data return/deletion, source access, transition, and rollback requirements?

## 6. Evaluation and pilot plan

### 6.1 Phase gates

| Phase | Buyer and supplier activity | Required output | Exit gate |
|---|---|---|---|
| 0. Claim and license review | Freeze source revision; inspect license, notice, claims matrix, architecture, threat model, privacy, roadmap, and machine evidence. | Review record listing accepted, rejected, and open claims; counsel identifies license questions. | No stronger language than the claims matrix; no unresolved license blocker for evaluation. |
| 1. Local reproducibility | Install from the pinned source, run focused tests, verify evidence JSON and WAL integrity, and record environment. | Reproduction log with commands, versions, outcomes, and deviations. | Failed or non-reproducible gates are investigated; no artifact is silently waived. |
| 2. Target design | Define workload, data classification, topology, ingress, egress, identity, provider, storage, secrets, keys, retention, observability, backup, and rollback. | Signed evaluation plan and responsibility matrix. | Security, privacy, and operations owners accept the test boundary. |
| 3. Controlled pilot | Execute correlation, provider-error, limiter-failure, WAF, storage-stall, key-rotation, backup/restore, rollback, and target capacity tests. | Pilot report containing offered and accepted traffic, rejected traffic, latency distribution, evidence completeness, failures, environment, and residual risks. | Every acceptance criterion has evidence; exceptions have owners and explicit disposition. |
| 4. Independent and legal review | Perform risk-tier-appropriate security review; complete privacy, open-source, data, evidentiary, and contract analysis. | Review reports and contract issue list. | No critical unresolved finding; required counsel and security approvals are recorded. |
| 5. Production decision | Price the actual topology and support model; define service boundaries, incident operations, supported versions, rollout, kill criteria, and rollback. | Executed agreement, production design, runbooks, acceptance record, and accountable owners. | Production is authorized only by buyer governance and executed terms. |

### 6.2 Minimum pilot acceptance matrix

Targets must be populated by the buyer and supplier before execution. This package intentionally supplies no fabricated thresholds.

| Test | Method and record | Acceptance criterion to define | Mandatory failure disclosure |
|---|---|---|---|
| Request/evidence correlation | Send uniquely identified accepted, rejected, streaming, non-streaming, and upstream-error requests; reconcile responses to durable evidence. | Required completeness, uniqueness, integrity, and response-header behavior for the named workload | Missing, duplicate, unverifiable, or uncorrelated evidence; paths not exercised |
| Storage stall and recovery | Inject target-representative storage latency, errors, exhaustion, restart, replay, and recovery. | Permitted blocking/rejection behavior, durability, recovery time, and operator alerting | Silent evidence loss, corrupt chain, unbounded backlog, or undocumented recovery action |
| Distributed rate-limit failure | Interrupt the configured backend and observe policy. | Fail-closed or other expressly approved behavior for each route | Any silent fail-open behavior or unobserved dependency failure |
| WAF and normalization | Run the pinned corpus plus buyer-authorized application and ingress cases. | Corpus, severity, bypass, false-positive, protocol, and business-impact thresholds | Untested protocols, evasions, false positives, downstream abuse, or changed normalization |
| Key rotation and custody | Rotate through the actual secret manager and replica topology, including delayed replica, malformed update, restart, replay, overlap, and expiry. | No unauthorized signing, required verification continuity, observable failures, and approved custody | Local-only substitution, unverifiable records, secret exposure, clock/propagation issue, or failed rollback |
| Provider and egress behavior | Exercise allowlisted providers, DNS/TLS failures, timeouts, retries, circuit state, and disallowed endpoints. | Approved endpoint and failure semantics | Provider-specific behavior, untested protocol translation, or network control not enforced |
| Backup, restore, and rollback | Restore evidence and configuration; roll software backward while preserving verifier and custody requirements. | Buyer-defined integrity, recovery, retention, and rollback objectives | Data loss, verifier incompatibility, missing key material, or undocumented manual repair |
| Capacity and latency | Run the target request mix with actual upstream or explicitly bounded substitute, storage, WAF, streaming, rate limit, evidence commit, and failure paths. | Buyer-defined accepted load, rejection policy, latency/error distributions, saturation, and recovery | Offered load presented as accepted capacity; microbenchmark presented as end-to-end performance |
| Privacy and retention | Trace data fields, transient processing, evidence records, exports, logs, backups, deletion, legal hold, and access. | Approved data inventory and control operation | Raw or derived data outside inventory; deletion/chain conflict; unauthorized access or transfer |
| Operational readiness | Exercise monitoring, paging, incident, disclosure, change, maintenance, rollback, and escalation with named operators. | Buyer-approved staffing and operating model | Unowned alert, unstaffed commitment, absent runbook, or unsupported-version ambiguity |

### 6.3 Kill criteria

The pilot should stop or remain non-production when evidence is silently lost, the chain cannot be verified, a strict dependency fails open contrary to policy, secrets are exposed, the target data use lacks legal basis or approval, a critical security finding lacks an accepted treatment, rollback cannot preserve required evidence, support obligations cannot be staffed, licensing cannot be resolved, or customer-facing claims exceed their artifacts.

## 7. Evidence request checklist

| Evidence request | Current repository locator | Current disposition | Buyer follow-up |
|---|---|---|---|
| Normative claim controls | `docs/CLAIMS_MATRIX.md` | Available; controls wording and boundaries | Diff against proposal, order form, security answers, and sales material |
| Source and focused regression tests | `aegis/`; `aegis_server/`; `tests/test_p0_release_gates.py`; `tests/test_market_hardening_gates.py` | Available; focused run on 2026-08-20 returned 7 passed | Re-run from pinned source in buyer-approved build environment; retain complete output |
| Production request/evidence lifecycle | `aegis/proxy/app.py`; `aegis/core/crypto_audit.py` | Implemented code paths; deployment behavior remains conditional | Trace all buyer-required accepted, rejected, error, and streaming paths |
| WAF source, corpus, and result | `aegis/proxy/waf.py`; `tests/data/waf_corpus_v1.json`; `evidence/execution_2026-08-20/waf_corpus_report.json` | Local application-layer result; 23 cases; HTTP/2 and Nuclei execution explicitly absent | Run authorized buyer corpus and actual ingress/protocol tests |
| Storage-stall result | `tools/benchmarks/run_backpressure_stall.py`; `evidence/execution_2026-08-20/backpressure_stall_report.json`; corresponding WAL JSONL | Local injected seam; 2,500 offered and durable records in the in-tree run; no missing/duplicate IDs; valid chain; not production capacity | Repeat on target storage and topology with failure and recovery cases |
| Key-rotation result | `aegis_server/crypto/keyring.py`; `tools/benchmarks/run_key_rotation.py`; `evidence/execution_2026-08-20/key_rotation_report.json` | Three independent local signer instances; zero failed commits and zero unverifiable records; no Kubernetes or secret-manager claim | Execute actual secret-manager, replica, restart, overlap, expiry, and rollback test |
| Release evidence manifest | `evidence/execution_2026-08-20/manifest.json`; `.sha256`, `.cbor`, and `.cid` companions | Available for the named execution bundle | Verify files independently and retain buyer custody record |
| Formal-method record | `docs/formal/FORMAL_VERIFICATION.md`; formal specifications referenced there | Bounded formal records; not whole-system proof | Confirm model, properties, tool versions, scope, and applicability to deployed code |
| Architecture and threat model | `docs/architecture/ARCHITECTURE.md`; `docs/security/THREAT_MODEL.md` | Available with explicit trust and non-defense boundaries | Threat-model the buyer topology and data classes |
| Privacy and retention | `docs/privacy/DATA_RETENTION.md` | Guidance, not buyer-specific legal approval | Produce buyer-specific data inventory, retention/deletion statement, and DPA analysis |
| Compliance mappings | `docs/compliance/COMPLIANCE_MAPPING.md` | Contribution mapping only | Have qualified assessor determine applicability, control design, and operating effectiveness |
| Dependency and supply chain | `requirements.lock`; release SBOM/provenance references in documentation | Repository inputs exist; procurement must verify exact release artifacts | Request pinned SBOM, scan results, provenance, signatures, exceptions, base image, and license review |
| Deployment and rollback | `DEPLOYMENT_GUIDE.md`; `docs/operations/ROLLBACK_RUNBOOK.md` | Guidance, not target acceptance | Execute on intended runtime, storage, backup, ingress, and secret manager |
| Security assurance | `docs/SECURITY_ASSURANCE_ROADMAP.md`; `SECURITY.md` | Independent assurance remains an open commercial gate | Obtain the review required for buyer risk tier and contract |
| Service and support schedule | No executed schedule in repository | Not available as a current commitment | Require staffed hours, severity, response/restoration objectives, escalation, maintenance, exclusions, and supported versions in contract |
| Customer references and outcomes | No repository evidence | Not available | Do not imply references, deployment count, savings, or ROI; request consented references only if they later exist |

**Evidence discrepancy control:** [`docs/CLAIMS_MATRIX.md`](../CLAIMS_MATRIX.md) describes a separate 10,000-record backpressure result and points to `backpressure_stall_10k_report.json`, while the in-tree execution artifact at `evidence/execution_2026-08-20/backpressure_stall_report.json` records 2,500 offered and durable requests. This package uses the in-tree artifact's exact values and does not treat the separately described release artifact as present. Procurement should request and verify the exact artifact behind any 10,000-record statement before relying on it.

## 8. Objection handling under claim control

| Objection or request | Controlled response | Evidence or next step | Prohibited shortcut |
|---|---|---|---|
| “Is this production-ready?” | Production suitability is not established repository-wide. It depends on target acceptance, accountable operations, assurance, and contract. | Complete the phased pilot and production gates in this package. | Calling a passed local release gate “production-ready” |
| “Will this make us compliant?” | Aegis may contribute technical controls and evidence to selected objectives; the buyer's full system and organization require qualified assessment. | Map the exact use case, control owner, evidence population, legal role, and assessor criteria. | “SOC 2 compliant,” “HIPAA compliant,” “FedRAMP-ready,” or equivalent |
| “Is the evidence court-admissible?” | Integrity and provenance inputs may support a broader evidentiary record; admissibility is jurisdiction- and procedure-specific. | Counsel defines acquisition, custody, authentication, relevance, reliability, testimony, and preservation. | Guaranteeing admissibility or non-repudiation from an HMAC record |
| “Does the WAF stop prompt injection?” | The WAF implements bounded normalization and pattern controls. The pinned local corpus is not universal coverage. | Run buyer-authorized corpus, ingress, protocol, tool-use, and business-logic tests. | Universal prevention, bypass-rate, or HTTP/2 coverage claims |
| “Can it sustain 10k requests per second?” | The repository has local offered-load evidence, not a target production capacity result. | Run end-to-end target workload and report offered, accepted, rejected, latency, errors, saturation, and recovery. | Treating offered load, a dispatch microbenchmark, or a local injected seam as capacity |
| “Is it quantum-safe or constant-time?” | No universal quantum-safe or constant-time claim is approved. The retained timing record described in repository documentation failed the declared verify threshold. | Qualified cryptographic review and a passing, bounded measurement for the selected implementation and platform. | Inferring constant-time behavior from algorithm name or one passing operation |
| “Do you provide 24/7 support or an SLA?” | No current repository commitment exists. Any support or service level must be staffed, scoped, measured, and executed. | Negotiate hours, severity, response/restoration objectives, escalation, maintenance, exclusions, credits, and supported versions. | Inferring coverage from package name or annual pricing hypothesis |
| “Can we use it without releasing our changes?” | The repository is under AGPLv3; the effect on the buyer's network use, modifications, combination, distribution, and source obligations requires counsel. Separate commercial terms may be negotiated only in writing. | Open-source counsel reviews the architecture and intended use; contract states commercial rights. | Treating `COMMERCIAL.md` as a license grant or legal opinion |
| “Do you have customer references and proven ROI?” | The repository supplies neither. | Use a buyer-owned pilot method; seek consent before any future reference or publication. | Inventing logos, adoption, savings, payback, conversion, or testimonials |
| “Is multi-region HA and global ordering included?” | The claims matrix marks cross-replica global ordering and multi-region HA as roadmap. | Design and measure the required topology; define consistency, recovery, failover, and evidence semantics. | Describing independently verifiable per-replica evidence as globally ordered |

## 9. Licensing and intellectual-property boundaries

The repository's `LICENSE` file contains the GNU Affero General Public License version 3. `COMMERCIAL.md` states an AGPLv3 plus commercial-licensing model, but also states that commercial use requires a separate written agreement and that the summary creates no warranty or waiver. Procurement and supplier personnel must not interpret the summary as granting commercial rights.

Counsel should review at least the following before a pilot beyond internal evaluation or any production use:

| Legal issue | Required determination | Owner / gate |
|---|---|---|
| AGPL network-use and source obligations | Effect of the buyer's deployment, modifications, user interaction, distribution, and combination with other software | Buyer open-source counsel; **legal approval required** |
| Commercial license scope | Entities, affiliates, environments, users, providers, source access, modification, redistribution, embedding, OEM, air-gapped use, and term | Supplier and buyer counsel; executed agreement required |
| Third-party components | License inventory, notices, copyleft compatibility, base images, dependencies, and distribution obligations | Open-source program owner and counsel |
| Intellectual-property rights | Ownership of existing code, buyer configuration, integrations, feedback, pilot deliverables, and modifications | Executed agreement required |
| Warranty, indemnity, liability, insurance | Express warranties, disclaimers, IP/security/data indemnities, caps, exclusions, and insurance evidence | Executive and counsel approval required |
| Export, sanctions, and restricted environments | Parties, geography, encryption, end use, government restrictions, and sovereign/OEM implications | Trade counsel when applicable |
| Exit and continuity | Termination, transition, data return/deletion, source availability, escrow, verifier continuity, and key custody | Contract and operational acceptance required |

Nothing in this package is legal advice, a license interpretation, or a promise that commercial terms will be available on a requested schedule.

## 10. Security, privacy, and legal review gates

Production approval must be denied until each applicable gate has a named human approver and retained decision record.

| Gate | Minimum evidence | Approval owner | Blocking conditions |
|---|---|---|---|
| Claim integrity | Proposal and contract claims diffed to `docs/CLAIMS_MATRIX.md`; exceptions have artifact, scope, owner, and falsification test | Product assurance owner | Stronger unsupported language, missing artifact, or unresolved source/evidence conflict |
| Architecture security | Buyer-topology threat model; ingress, egress, identity, provider, storage, runtime, and trust boundaries reviewed | Buyer security architecture owner | Critical untreated risk or untested required boundary |
| Application security | Focused tests, dependency review, authorized security testing, vulnerability process, remediation disposition | Buyer CISO delegate and supplier security owner | Critical finding, absent disclosure path, or unacceptable exception |
| Cryptography and key custody | Signer selection, secret manager, key roles, rotation, overlap, expiry, recovery, verifier independence, and module claims reviewed | Cryptography/key-management owner | Unsupported constant-time, FIPS, PQC, non-repudiation, or custody claim |
| Privacy and data protection | Data inventory, legal role, lawful basis, minimization, retention/deletion, residency/transfers, access, incident, DPA, and provider terms | Privacy officer and counsel | Unapproved regulated data, absent legal basis, or unresolved deletion/chain requirement |
| Compliance and assurance | Applicable framework objectives, customer responsibility matrix, evidence population, assessor requirements, and independent review | Risk/compliance owner | Certification or authorization treated as inherited from repository controls |
| Reliability and recovery | Target capacity, dependency failures, monitoring, backup/restore, incident, rollback, recovery objectives, and on-call ownership | SRE/operations executive | Silent evidence loss, unowned operations, failed restore/rollback, or unstaffed service promise |
| Licensing and contract | AGPL analysis, commercial grant, third-party review, warranty, liability, indemnity, audit, security, data, support, and exit terms | Buyer and supplier counsel | Unresolved rights, unacceptable risk allocation, or absent executed agreement |
| Evidentiary use | Intended use, custody, preservation, verifier, authentication, testimony, legal hold, and jurisdiction analyzed | Litigation/regulatory counsel when applicable | “Court-admissible” or equivalent conclusion without jurisdiction-specific legal basis |
| Production authorization | All prior gates closed; residual risk accepted; rollout and kill criteria approved | Buyer accountable executive | Any blocking gate open |

## 11. Cost-to-serve and quote input schedule

No monetary values, margins, ROI, or validated package prices are supplied. A quote should be built from observable drivers and named assumptions rather than a generic tier label.

| Cost driver | Input to collect | Evidence/source | Allocation question |
|---|---|---|---|
| Deployment engineering | Topology, environments, replicas, regions, ingress, container/runtime, IaC, provider adapters, and customer change process | Target design and work breakdown | Included, buyer-owned, supplier professional service, or third party? |
| Workload | Offered and accepted requests, concurrency, request/response sizes, streaming duration, model/provider mix, retries, and error profile | Buyer traces or bounded synthetic method | Which metric controls scope or overage, if any? |
| Evidence storage | Record size, write rate, retention, replication, immutability, backup, restore, archive, legal hold, and egress | Target storage design | Who purchases and operates storage and backup? |
| Security and assurance | Questionnaire volume, architecture review, testing, SBOM/provenance work, remediation, independent assessment, and recurring review | Procurement requirements | One-time, recurring, pass-through, or excluded? |
| Key and secret operations | Secret manager, HSM where required, key ceremony, rotation frequency, custodians, recovery, and audit | Key-management design | Buyer or supplier custody; cloud and hardware costs? |
| Support | Coverage window, expected ticket/incident volume, severity mix, response/restoration objectives, escalation, language, and geography | Staffed support plan | Dedicated capacity, pooled capacity, or not offered? |
| Reliability engineering | Monitoring, dashboards, alerting, capacity tests, incident exercises, backup/restore, rollback, maintenance, and release qualification | Operations plan | Included in product, service, or buyer operations? |
| Legal and privacy | Negotiation complexity, DPA, subprocessor/provider review, open-source review, export review, audit rights, and evidence preservation | Counsel issue list | Standard terms, paid review, or unsupported term? |
| Training and enablement | Operators, developers, auditors, security reviewers, sessions, materials, and refresh cadence | Enablement plan | Included quantity and additional-work mechanism? |
| Release maintenance | Supported versions, compatibility matrix, security patches, upgrade assistance, end-of-support, and backport policy | Product and support plan | Which versions and duration are contractually supported? |
| Incident and disclosure | Notification workflow, forensic support, evidence export, communications, exercises, and post-incident review | Incident operating model | Included effort, severity-based effort, or separately scoped? |
| Commercial overhead and risk | Procurement cycle, insurance, payment terms, tax, currency, liability, service credits, subcontractors, and termination assistance | Proposed contract | Is the resulting risk economically supportable and approved? |

A defensible quote must state the legal entity, term, package stage, environments, scope, assumptions, customer responsibilities, supplier responsibilities, exclusions, third-party costs, support schedule, acceptance method, change control, payment terms, renewal, termination, and validity period. A quote must not promise capacity, response, restoration, availability, certification, or outcome without the corresponding staffed and measured schedule.

## 12. Procurement schedule and contract exhibits

| Exhibit or schedule | Required content | Current repository status |
|---|---|---|
| Order form / statement of work | Stage, scope, environments, deliverables, milestones, acceptance, price, expenses, payment, dependencies, and change control | Must be created for the transaction |
| License schedule | Commercial grant or AGPL acknowledgement, entities, deployment rights, modifications, restrictions, source/access terms, and third-party notices | Requires counsel and execution |
| Security schedule | Control responsibilities, vulnerability handling, testing rights, incident notice, remediation, audit evidence, and exclusions | Requires buyer-specific negotiation |
| Data processing schedule | Roles, purposes, data categories, providers/subprocessors, geography, transfers, security measures, retention/deletion, return, and incident terms | Requires buyer-specific legal review |
| Support schedule | Hours, channels, severity, response/restoration objectives, escalation, maintenance, supported versions, exclusions, and service-credit rules | No current repository commitment |
| Service-level schedule | Availability definition, measurement point, exclusions, dependencies, capacity assumptions, error budget, reporting, and remedies | Not available without measured target design and staffed operations |
| Implementation responsibility matrix | Ingress, identity, network, provider, storage, secrets, keys, runtime, monitoring, backup, restore, rollback, and incident ownership | Must be completed during target design |
| Acceptance plan | Tests, environment, workload, evidence, thresholds, exceptions, approvers, and retest procedure | Framework supplied in Section 6; values must be agreed |
| Business continuity and exit | Backup/restore, continuity, termination, transition, data return/deletion, evidence verification, source/escrow if negotiated, and key continuity | Requires operational and legal design |
| Claim and assurance schedule | Approved claims, artifacts, boundaries, falsification criteria, independent reports, and usage rights | Claim register supplied below; transaction-specific claims require review |

## 13. Controlled material claim register

The stable identifiers below are local to DOC-06. Status values are restricted to **IMPLEMENTED**, **MEASURED**, **CONFIGURATION-DEPENDENT**, **ROADMAP**, and **LEGAL-REVIEW-REQUIRED**. “Human-review owner” names an accountable role, not an assertion that a person currently occupies it.

| Claim ID | Material claim | Status | Exact repository locator | Assumptions | Falsification criteria | Operational boundary | Human-review owner |
|---|---|---|---|---|---|---|---|
| DOC06-CLM-001 | The repository implements an OpenAI-compatible proxy lifecycle with request controls and evidence handling paths. | IMPLEMENTED | `aegis/proxy/app.py`; `docs/architecture/ARCHITECTURE.md`; `tests/test_p0_release_gates.py` | Deployed code matches reviewed source; configured routes exercise those paths. | Required route bypasses the lifecycle, source/test behavior diverges, or focused gates fail. | Application process only; not proof of ingress, provider, network, storage, or production operation. | Product engineering owner |
| DOC06-CLM-002 | The canonical ledger code persists chained, signed records to a WAL and verifies integrity under its implemented verifier. | IMPLEMENTED | `aegis/core/crypto_audit.py`; `tests/test_market_hardening_gates.py:37-63`; `docs/CLAIMS_MATRIX.md` durable-evidence row | Configured signer and writable durable path are available; verifier uses matching scheme/key material. | Commit returns success without required persistence, tampering/reordering verifies, or regression fails. | Local ledger semantics; privileged-host compromise and external immutability are outside the application boundary. | Security engineering owner |
| DOC06-CLM-003 | The in-tree storage-stall run recorded 2,500 offered and durable records, zero failures, zero missing/duplicate IDs, and a valid chain under a 2 ms injected fsync delay. | MEASURED | `evidence/execution_2026-08-20/backpressure_stall_report.json`; `evidence/execution_2026-08-20/backpressure_stall_report.wal.jsonl`; `tools/benchmarks/run_backpressure_stall.py` | Artifact is authentic and interpreted with its environment, duration, worker, and seam metadata. | Independent verification does not reproduce the artifact fields or chain, or artifact integrity fails. | Local injected seam at offered 10,000 requests/s for 0.25 seconds; not accepted production capacity, target storage, availability, or SLO. | Performance assurance owner |
| DOC06-CLM-004 | The focused P0 and market-hardening test files passed 7 tests in the current workspace execution on 2026-08-20. | MEASURED | `tests/test_p0_release_gates.py`; `tests/test_market_hardening_gates.py`; execution command `.venv/bin/python -m pytest -q tests/test_p0_release_gates.py tests/test_market_hardening_gates.py` | Workspace and virtual environment correspond to the reviewed checkout. | Re-run fails or source/dependency/environment change invalidates applicability. | Focused tests only; not the full suite, external assessment, target acceptance, or production history. | Release assurance owner |
| DOC06-CLM-005 | Strict ledger configuration rejects an ephemeral fallback, and the distributed rate-limit test exercises fail-closed behavior. | IMPLEMENTED | `tests/test_p0_release_gates.py:31-63`; `aegis/core/ratelimiter.py` | Strict mode and distributed backend are selected as tested. | Strict configuration accepts the prohibited fallback or distributed failure silently allows traffic. | Named configuration and test path; ongoing dependency health and all routes remain deployment-dependent. | Platform security owner |
| DOC06-CLM-006 | The WAF implements application-layer inspection and the in-tree 23-case pinned corpus passed its declared local gate. | MEASURED | `aegis/proxy/waf.py`; `tests/data/waf_corpus_v1.json`; `tests/test_market_hardening_gates.py:22-35`; `evidence/execution_2026-08-20/waf_corpus_report.json` | Exact corpus, strict configuration, normalization path, and local environment match the artifact. | A pinned expected case produces a prohibited bypass/false positive or the retained artifact is invalid. | 23 local application-layer cases only; no universal prompt-injection claim, HTTP/2 ingress test, Nuclei execution, model-behavior coverage, or downstream business-logic guarantee. | Application security owner |
| DOC06-CLM-007 | The versioned HMAC keyring implements one active key, verification keys, atomic validated reload, overlap/expiry checks, and retention of the previous valid snapshot after an invalid reload. | IMPLEMENTED | `aegis_server/crypto/keyring.py:78-241`; keyring tests referenced in `docs/ROADMAP.md:72-79` | File permissions, clocks, key strength, process access, and operator/secret-manager writes satisfy checks. | Invalid snapshot replaces a valid snapshot, secret material is logged, wrong key signs, or overlap/expiry behavior fails. | Process/file-backed keyring implementation; not HSM, secret-manager orchestration, or distributed convergence evidence. | Key-management owner |
| DOC06-CLM-008 | The in-tree key-rotation run observed old and new key IDs across three independent local signer instances with zero failed commits and zero unverifiable records. | MEASURED | `evidence/execution_2026-08-20/key_rotation_report.json`; `tools/benchmarks/run_key_rotation.py` | Artifact corresponds to the reviewed harness and local file-backed keyring. | Artifact verification fails, records become unverifiable, or claimed counts do not match the report. | Local-only; three process replicas, secret-manager propagation, clock skew, orchestrator restart, and target deployment were not executed. | Key-management assurance owner |
| DOC06-CLM-009 | Egress endpoint validation and allowlisting are implemented at the application layer. | IMPLEMENTED | `aegis/proxy/egress_guard.py`; `docs/security/THREAT_MODEL.md` egress discussion | Air-gap/allowlist mode and configured upstream are correct; DNS/TLS/network controls are separately enforced. | Disallowed endpoint passes the implemented validator under the declared mode or tests fail. | Not a firewall, Kubernetes NetworkPolicy, DNS security control, TLS proof, or provider assurance. | Network security owner |
| DOC06-CLM-010 | Whether Aegis provides durable evidence for a buyer workload is configuration-dependent. | CONFIGURATION-DEPENDENT | `aegis/core/crypto_audit.py`; `DEPLOYMENT_GUIDE.md`; `docs/operations/BACKPRESSURE_RUNBOOK.md`; `docs/privacy/DATA_RETENTION.md` | Target storage, signer, permissions, retention, backups, monitoring, and recovery are correctly configured and operated. | Target replay shows missing, duplicate, corrupt, unverifiable, or silently dropped required records. | Buyer deployment, workload, and retention boundary only after acceptance testing. | Buyer SRE and security owners |
| DOC06-CLM-011 | A controlled pilot can evaluate a named workload, but pilot services, support, fees, and deliverables exist only in a written scope. | CONFIGURATION-DEPENDENT | `docs/BUYER_GUIDE_US.md:39-47`; `docs/COMMERCIAL_STRATEGY_US.md`; `docs/FAQ_PROCUREMENT.md:66-68` | Parties agree scope, environment, staffing, data handling, acceptance, and commercial terms. | No executed pilot scope or required target access exists, or acceptance cannot be measured. | Time-bounded evaluation; not production authorization or a customer outcome claim. | Commercial owner and buyer sponsor |
| DOC06-CLM-012 | Production commercial deployment and enterprise support are contract-dependent and are not current repository promises. | LEGAL-REVIEW-REQUIRED | `COMMERCIAL.md`; `docs/FAQ_PROCUREMENT.md:27-48`; `docs/ROADMAP.md:104-112`; `docs/CLAIMS_MATRIX.md` enterprise-support row | Accountable operations, legal capacity, measured target, and executed schedules exist. | Sales material or operations represent production terms, SLA, support coverage, or assurance absent staffing and executed agreement. | Exact contracted entities, topology, term, support schedule, and exclusions only. | Executive sponsor, support owner, and counsel |
| DOC06-CLM-013 | Repository pricing is not market-validated, and this package provides no binding price or ROI. | ROADMAP | `docs/COMMERCIAL_STRATEGY_US.md`; `docs/FAQ_PROCUREMENT.md:27-40`; `docs/ROADMAP.md:106-110`; `docs/CLAIMS_MATRIX.md` pricing row | Future validation uses buyer interviews, cost-to-serve modeling, comparable quotes, and paid-pilot evidence. | A claim of validated price, margin, ROI, savings, or payback is made without the named evidence and method. | Commercial hypothesis only; no offer, quote, valuation, or financial forecast. | Commercial finance owner |
| DOC06-CLM-014 | The repository does not establish a production SLO, availability commitment, round-the-clock support, customer references, or independent assurance. | ROADMAP | `docs/FAQ_PROCUREMENT.md:42-60`; `docs/ROADMAP.md:98-112`; `docs/CLAIMS_MATRIX.md` enterprise-support row | None of these properties is inferred from code, local tests, package names, or repository publication. | A corresponding staffed contract, customer-consented artifact, or independent report is produced and claim controls are updated; until then, any positive claim is blocked. | Repository-wide negative boundary; transaction terms may differ only by executed evidence and agreement. | Product assurance and legal owners |
| DOC06-CLM-015 | Cross-replica global audit ordering and multi-region high availability are not established current capabilities. | ROADMAP | `docs/CLAIMS_MATRIX.md` global-ordering row; `docs/ROADMAP.md:96-102`; `docs/architecture/ARCHITECTURE.md` topology boundaries | Per-replica evidence is not represented as global ordering. | A target design implements and verifies ordering, failover, consistency, recovery, and evidence semantics, followed by claim-matrix review. | Current repository topology boundary; target centralized writer or future architecture requires separate proof. | Architecture owner |
| DOC06-CLM-016 | No universal constant-time, quantum-safe, FIPS-validation, or non-repudiation claim is approved. | ROADMAP | `docs/security/PQC_CONSTANT_TIME.md`; `docs/FAQ_SECURITY.md`; `docs/ROADMAP.md:81-86`; `docs/CLAIMS_MATRIX.md` ML-DSA row | Algorithm specification, implementation path, timing behavior, module validation, custody, and legal effect are treated separately. | Qualified evidence and review establish a narrower claim and the claim matrix is updated; current verify measurement remains a blocker for constant-time wording. | Named implementation, build, platform, signer, verifier, custody, and experiment only. | Cryptography assurance owner |
| DOC06-CLM-017 | Aegis technical controls may contribute evidence to selected governance, privacy, security, retention, and policy workflows, but they do not establish compliance. | LEGAL-REVIEW-REQUIRED | `docs/compliance/COMPLIANCE_MAPPING.md`; `docs/privacy/DATA_RETENTION.md`; `docs/CLAIMS_MATRIX.md` compliance row | Buyer defines role, system boundary, data, controls, operators, evidence population, and applicable law/framework. | Customer-facing material says “compliant,” “certified,” “authorized,” or equivalent without authoritative assessment. | Technical component contribution only; not SOC 2 opinion, HIPAA determination, FedRAMP authorization, EU AI Act conformity, GDPR legal basis, or FIPS 140 validation. | Compliance owner and counsel |
| DOC06-CLM-018 | Evidentiary exports do not establish court admissibility by themselves. | LEGAL-REVIEW-REQUIRED | `docs/FAQ_PROCUREMENT.md:62-64`; `docs/FAQ_SECURITY.md`; `docs/compliance/COMPLIANCE_MAPPING.md` wording controls | Acquisition, custody, authentication, relevance, reliability, preservation, testimony, and procedure are handled for the jurisdiction and matter. | Counsel or a competent tribunal reaches a matter-specific conclusion based on the full record; generic product wording remains unauthorized. | Matter- and jurisdiction-specific legal process. | Litigation/regulatory counsel |
| DOC06-CLM-019 | The repository is distributed under AGPLv3, while any commercial rights require separate written terms. | LEGAL-REVIEW-REQUIRED | `LICENSE`; `COMMERCIAL.md`; `NOTICE` | Copyright ownership and commercial authority are confirmed; buyer counsel reviews intended use. | License files change, commercial authority is not established, or executed terms conflict with the summary. | Exact source revision, parties, deployment, modifications, distribution, and commercial grant. | Open-source and commercial counsel |
| DOC06-CLM-020 | Sovereign, OEM, redistribution, embedded, escrow, and dedicated-assurance packaging is not a default current offer. | ROADMAP | `docs/FAQ_PROCUREMENT.md:30-36`; `docs/COMMERCIAL_STRATEGY_US.md`; `docs/ROADMAP.md:104-112` | Future capacity, legal review, security architecture, assurance, and unit economics are established. | A staffed, approved, and executed offer exists and claim controls are updated; until then, a present-tense offer is blocked. | Future/custom packaging only. | Executive commercial owner and counsel |

## 14. Decision record and sign-off

A procurement recommendation should identify one of four outcomes: **decline**, **local evaluation only**, **controlled pilot**, or **production under executed contract**. It should not record “approved” without specifying the exact stage and boundary.

| Decision field | Required entry |
|---|---|
| Source revision and evidence bundle | Exact source reference and retained artifact inventory |
| Intended use and exclusions | Named applications, providers, users, data, environments, and excluded decisions |
| Approved claim set | DOC-06 claim IDs and any narrower transaction-specific claims |
| Pilot or production acceptance | Test report, exceptions, residual risks, and approvers |
| Security approval | Named approver, date, conditions, and retained review locator |
| Privacy/legal approval | Named approver, data role, license disposition, contract disposition, and conditions |
| Operations approval | Owners for monitoring, incident, backup/restore, key custody, release, rollback, and support |
| Commercial approval | Executed scope, quote assumptions, costs, payment, renewal, termination, and risk allocation |
| Kill and re-review triggers | Evidence loss, control failure, material topology/data change, major finding, claim drift, contract change, or unsupported version |

## 15. Residual risk summary

The principal procurement risks are **claim drift**, incomplete target-deployment evidence, lack of independent assurance, unvalidated pricing and cost-to-serve, absence of a repository-wide production SLO or staffed support commitment, unresolved AGPL/commercial terms, configuration-sensitive evidence durability, bounded WAF coverage, unverified real secret-manager orchestration, no established multi-region global ordering, and legal uncertainty around compliance and evidentiary use. These risks do not make evaluation impossible; they define why a controlled pilot and explicit review gates are necessary.

## 16. Repository references

The primary sources for this package are `README.md`, `COMMERCIAL.md`, `LICENSE`, `NOTICE`, `SECURITY.md`, `DEPLOYMENT_GUIDE.md`, `docs/COMMERCIAL_STRATEGY_US.md`, `docs/BUYER_GUIDE_US.md`, `docs/PRODUCT_BRIEF_US.md`, `docs/FAQ_PROCUREMENT.md`, `docs/FAQ_SECURITY.md`, `docs/FAQ_TECHNICAL.md`, `docs/PROSPECTUS.md`, `docs/ROADMAP.md`, `docs/CLAIMS_MATRIX.md`, `docs/architecture/ADR-001-AI-GOVERNANCE-EVIDENCE-GATEWAY.md`, `docs/architecture/ARCHITECTURE.md`, `docs/formal/FORMAL_VERIFICATION.md`, `docs/privacy/DATA_RETENTION.md`, `docs/compliance/COMPLIANCE_MAPPING.md`, `docs/security/THREAT_MODEL.md`, `docs/security/PQC_CONSTANT_TIME.md`, `docs/operations/BACKPRESSURE_RUNBOOK.md`, `docs/operations/KEY_ROTATION_RUNBOOK.md`, `docs/operations/ROLLBACK_RUNBOOK.md`, the production and test paths named in the claim register, and JSON artifacts under `evidence/execution_2026-08-20/`.

This document is a procurement-control artifact, not an executed offer, warranty, legal opinion, certification, security assessment, customer reference, service-level commitment, or production authorization.

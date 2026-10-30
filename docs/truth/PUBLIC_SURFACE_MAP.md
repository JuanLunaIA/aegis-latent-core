# Public surface map

One row per surface that a customer, investor, auditor, or agent can read. A
surface with no canonical source does not get to publish the claim.

**Last verified:** 2026-10-30 UTC
**Current release:** `v5.0.3`, published 2026-10-30; PyPI gateway `5.0.3`
**Last published release:** `v5.0.3` (2026-10-30), read back on GitHub Release,
both PyPI distributions, npm SDK and GHCR.

| Surface | Path / URL | Audience | Claims it makes | Canonical source | Owner | Gate |
| --- | --- | --- | --- | --- | --- | --- |
| GitHub README | `README.md` | developers, buyers | category, install path, boundaries, licence | `docs/CLAIMS_MATRIX.md`, `docs/RELEASE_STATUS.md` | release owner | `test_documentation_currency.py`, `test_release_readback_script.py` |
| Repository instructions | `AGENTS.md`, `CLAUDE.md`, `GEMINI.md` | agents, contributors | source baseline, release state, forbidden claims | `docs/RELEASE_STATUS.md`, this map | maintainer | `test_ai_context.py`, `test_documentation_currency.py` |
| Website home | `aegisweb/src/routes/index.tsx` | buyers | category, licence, deployment model, outcomes | `aegisweb/src/data/facts.ts` | web owner | `npm run audit` |
| Website pricing | `aegisweb/src/routes/precios.tsx`, `src/data/sections/pricing.ts` | buyers | quote-only model, evaluation, plan limits | `aegisweb/src/data/facts.ts`, `aegis-cloud/app/migrations/0011_pricing_truth.sql` | product owner | `test_pricing_consistency.py` |
| Website trust page | `aegisweb/src/routes/confianza.tsx` | security reviewers | what is proven, what is not, evidence commands | `docs/assurance/ASSURANCE_STATUS.md` | security owner | `npm run audit`, `audit-claims.mjs` |
| Website source/provenance | `aegisweb/src/routes/confianza/fuente.tsx` | verifiers | artifact digests, cosign identity, repository identity | PyPI JSON + GHCR manifest + GitHub Release readback | release owner | `scripts/audit-claims.mjs`, readback log |
| Website legal pages | `aegisweb/src/routes/terminos.tsx`, `privacidad.tsx` | buyers, counsel | terms, privacy, subprocessors, refunds | `docs/legal/*`, `aegisweb/src/data/legal.ts` | owner + counsel | counsel sign-off record |
| Website docs | `aegisweb/src/routes/docs/**` | evaluators | configuration, limits, operations | code, `docs/BOUNDARIES.md` | docs owner | `npm run audit` |
| Public repository docs | `docs/**` | developers, auditors | architecture, guarantees, limits, release state | code + `docs/CLAIMS_MATRIX.md` | maintainer | `Documentation Gates`, `Documentation index is current` |
| GitHub release page | `github.com/JuanLunaIA/aegis-latent-core/releases/tag/v5.0.3` | downloaders | version, assets, checksums, signature | release readback (`SHA256SUMS`, cosign, attestation) | release owner | `scripts/verify_release_readback.py` |
| PyPI gateway | `pypi.org/project/aegis-latent-core/5.0.3/` | Python users | wheel, version, licence metadata | PyPI JSON API | release owner | readback §1.0e |
| PyPI SDK | `pypi.org/project/aegis-latent-sdk/5.0.3/` | Python integrators | SDK version, licence | PyPI JSON API | release owner | readback §1.0e |
| npm SDK | `npmjs.com/package/aegis-latent-sdk/v/5.0.3` | TypeScript integrators | SDK version, licence | npm registry JSON | release owner | readback §1.0e |
| GHCR image | `ghcr.io/juanlunaia/aegis-latent-core:5.0.3` | operators | image digest, signature, provenance | OCI registry manifest + cosign | release owner | readback §1.0e |
| Investor pack | `investor_packs/**` (frozen historical); current pack is generated in the private workspace, not this repository | investors | metrics, market, pricing, use of funds | rebuild manifest + source data; no public facts file | founder | rebuild diff / manifest exit 0 |
| Data room | `docs/raise/DATA_ROOM_INDEX.md` | investors | company, metrics, risk, evidence | manifest tool | founder | `manifest` exit 0 |
| Impact / TechCamp | owner workspace (not in the public repository) | judges, accelerators | problem, theory of change, budget | owner source pack + dated public statistics | founder | source check before use |
| Status page | `status.aegislatent.com` (planned; not live) | customers | availability and incidents | CloudWatch + synthetic checks | operations owner | incident log; **not** a current surface until deployed |
| Security questionnaire | `docs/enterprise/VENDOR_SECURITY_QUESTIONNAIRE.md` | buyers | controls, evidence, gaps | `ASSURANCE_STATUS` + control matrix | security owner | counsel/security review |

## Withdrawn surfaces

These are intentionally absent. If a future page needs one of these claims, it
must first add evidence to `docs/assurance/ASSURANCE_STATUS.md` and
`docs/commercial/CLAIM_LEDGER.md`.

| Claim | Why it is withdrawn | Where the truth lives |
| --- | --- | --- |
| SOC 2 Type II | no audit, no report, no auditor | `ASSURANCE_STATUS.md` |
| ISO/IEC 27001 or 42001 | no certificate, no certification body | `ASSURANCE_STATUS.md` |
| HIPAA / BAA | no BAA, no covered-entity review | `ASSURANCE_STATUS.md` |
| FedRAMP / IL5 / IL6 | no authorization, no 3PAO | `ASSURANCE_STATUS.md` |
| PCI DSS | no assessment, no QSA | `ASSURANCE_STATUS.md` |
| EU AI Act "compliant" | no conformity assessment; regulation applies by role and date | `docs/legal/COUNSEL_QUESTIONS.md` |
| CSRD "compliant" | Aegis is not a European undertaking in scope; no assurance | `docs/impact/` |
| 99.99% SLA / 24/7 staffed support | no staffed on-call, no signed SLA | `docs/enterprise/SUPPORT_MODEL.md` |
| "Open source" / AGPLv3 for 5.0.3 | 5.0.3 is source-available under the Aegis Commercial License 1.0 | `LICENSE`, `COMMERCIAL.md` |
| Free forever plan | no permanent free tier exists | `aegisweb/src/routes/precios.tsx` |

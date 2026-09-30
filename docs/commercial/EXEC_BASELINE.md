# Commercialization Execution Baseline (Mission Order XVI, Phase 0)

**Date of readback:** 2026-09-29. **Source commit:** `8e4c2313cae54d50de9d0f9808db6f7c7f99e776` (`main`). **Scope:** this file records what was re-run and observed. It is a baseline for the sales work, not a product capability claim; `docs/CLAIMS_MATRIX.md` remains the only source of those.

Tags: **V** = read back from a primary source or retained artifact today. **M** = model assumption from the investor engine (seed 42). **H** = hypothesis, not yet tested. Every number below carries one.

## 1. Gate table

| # | Gate | Expected | Observed (2026-09-29) | Tag | Status |
|---|---|---|---|---|---|
| G1 | Engine rerun, English (`--out`) vs committed | byte-identical | 6 PNG, `model_tables.md`, `model_outputs.json` identical; `SHA256SUMS` ok | V | GREEN |
| G2 | Engine rerun, Spanish (`--lang es`) vs committed | byte-identical | identical; `model_outputs.json` identical across languages; `SHA256SUMS` ok | V | GREEN |
| G3 | `scripts/verify_claims.py` | 112 claims, 0 findings | 112 claims, 0 findings | V | GREEN |
| G4 | `pytest -n auto -q` (8 workers, this host) | 7,550 passed, 41 skipped, 0 failed | 7,576 passed, 43 skipped, **1 failed** | V | YELLOW, see §2 |
| G5 | CI on `main` at `8e4c231` | green | CI, Security, Forensic CI, Validate Python package: all `success` | V | GREEN |
| G6 | Tag `v5.0.1` | signed annotated tag | tag object `b590a7f4…` → commit `46db6c0c…`; CMS signature block present | V | GREEN (signature not cryptographically verified here, see G10) |
| G7 | GitHub Release checksums | 15 of 15 | `SHA256SUMS` sweep 15 of 15 `OK`; release has 31 assets | V | GREEN |
| G8 | PyPI `aegis-latent-core` 5.0.1 | present | wheel `c5e3ec35…`, sdist `cf431cf9…`; both equal the release-asset digests | V | GREEN |
| G9 | PyPI / npm SDK 5.0.1 | present | PyPI `aegis-latent-sdk` wheel `7d5b0c90…`, sdist `9cae15cb…`; npm `aegis-latent-sdk` 5.0.1, integrity `sha512-94X5kw5P…`, attestations object present | V | GREEN |
| G10 | Signature and provenance verification | `cosign verify`, `gitsign verify-tag`, `gh attestation verify` | **NOT_EXECUTED**: none of the three tools is installed in this environment. Not claimed. | V | NOT_EXECUTED |
| G11 | GHCR digests | gateway `sha256:2d22023e…`, dashboard `sha256:a05b41c5…` | manifest digests read back equal to both | V | GREEN (digest only; no signature check, see G10) |
| G12 | Azure price file (`deploy/azure/phase0/00_query_prices.sh`) | `prices_verified_2026-09-16.json` | **NOT_EXECUTED**: the script does not exist in the repository (`deploy/azure/phase0/` holds `budget.bicep` and `phase0_guardrails.sh` only) | V | NOT_EXECUTED |

**Gate verdict:** no gate is red. One is yellow (G4) and two are NOT_EXECUTED (G10, G12). None of them blocks Phase 1; each is carried forward in §5.

*(Amended 2026-09-30: **G12 executed.** `deploy/azure/phase0/00_query_prices.sh` now exists. It is read-only: one unauthenticated GET per meter to the Azure Retail Prices API, with no login and nothing created or spent. It wrote `evidence/benchmarks/azure/prices_verified_2026-09-30.json` (fetched 2026-09-30T21:36:41Z, V). The four prices the investor engine tags VERIFIED all read back **MATCH**: Key Vault HSM Pool Standard B1 at 3.20 USD/h, Standard_D4s_v5 Linux at 0.192 USD/h and Blob Hot LRS first tier at 0.0208 USD/GB-month, all eastus; and B2als v2 Linux in chilecentral at 0.0526 USD/h. The meter ids returned equal the ones the engine cites. A P4 LRS 32 GiB Premium SSD disk in chilecentral, 6.736598 USD/month, is recorded for context only. The file is dated 2026-09-30, not the 2026-09-16 the plan named. `tests/test_azure_price_readback.py` keeps the script's expected values equal to both engines' and turns a moved price into exit 3. The table row above is left as observed on 2026-09-29. G12 is now GREEN; G10 remains NOT_EXECUTED.)*

## 2. G4 detail

- The single failure is `tests/test_determinism.py::TestIEC62443Determinism::test_no_outlier_exceeds_500us`: one dispatch event took 594.7 µs against a 500 µs bound (V).
- The test's own docstring says it is meaningful only on dedicated CPU-isolated hardware and is skipped on shared CI runners. This host ran eight parallel workers.
- Run alone, the file `tests/test_determinism.py` passed 12 of 12 on three consecutive runs (V).
- Root cause is scheduler contention under parallel load, not a code change. CI on `main` at the same commit is green (G5). This is a diagnosis of one observed failure, not a claim that the test can never fail.
- Count drift: 7,576 / 43 here versus 7,550 / 41 expected. The suite grew, and skip counts depend on the host (earlier CI runs showed 7,445 to 7,570 passed by job). Treat 7,550 / 41 as a historical figure and cite the observed line above.

## 3. Data-room index (D10.1) against the repository

**EXISTS** (each path was checked on disk):

| Document | Path |
|---|---|
| Release record and readback transcript | `docs/RELEASE_STATUS.md`; `evidence/v5_0_1_release_readback_2026-09-24.md` |
| Claims register and refused claims | `docs/CLAIMS_MATRIX.md`; `docs/institutional/UNSUPPORTED_CLAIMS.md` |
| Defect registry and founder-only actions | `docs/REGISTRY.md`; `docs/REGISTRY_HUMAN_PACK.md` |
| Security policy and threat model | `SECURITY.md`; `docs/security/THREAT_MODEL.md` |
| SBOM and third-party licences | release asset `aegis-latent-core-5.0.1.spdx.json`; `LICENSE-THIRD-PARTY.md` |
| Audit-readiness package and control mappings | `docs/compliance/AUDIT_READINESS.md`; `docs/compliance/COMPLIANCE_MAPPING.md` |
| Maintainer handbook | `docs/MAINTAINER_HANDBOOK.md` |
| Licences and pricing hypotheses | `LICENSE`; `COMMERCIAL.md`; `docs/commercial/ENTERPRISE_PRICING_GUIDE.md` |
| Benchmarks | `evidence/benchmarks/benchmarks_5.0.1_2026-09-24.json`; `docs/BENCHMARKS.md` |
| Financial engine and outputs | `investor_packs/*/engine|motor/aegis_financial_engine.py` and `data|datos/` |
| Azure phase-0 script and budget Bicep | `deploy/azure/phase0/phase0_guardrails.sh`; `deploy/azure/phase0/budget.bicep` (not run end to end, so no budget alert has fired) |

**MISSING-HUMAN** (prepared signature-ready by the agent only in later phases; the owner acts):

| Document | REG-H / milestone | Owner | Target date (M) |
|---|---|---|---|
| Certificate of incorporation (Delaware parent) | REG-H09, M1 | Founder + counsel | 2027-01-31 |
| IP assignment, founder to company | REG-H09, M1 | Founder + counsel | 2027-01-31 |
| Cap table and any prior SAFEs or notes | none | Founder to confirm none exist | before first SAFE |
| Penetration-test report | REG-H01, M4, M6 | Founder, then maintainer | SOW 2027-03-31; report 2027-06-30 |
| SOC 2 report | REG-H02, M7, M11 | Founder + auditor | engaged 2027-08-31; issued 2027-12-31 |
| Escrow agreement | REG-H03, M9 | Founder | 2027-03-31 |
| Customer contracts, LOIs, executed commercial licence | REG-H06, M5, M8, M10 | Founder | 2027-05-31 to 2027-09-30 |
| Buyer interview notes | REG-H06, M2 | Founder | 2027-01-31 |
| Legal opinions: licence, AI-authorship copyright, MiFID/MAR inputs | REG-H04, REG-H10, M1 | Counsel | 2027-01-31 |
| Trademark registration | none | Founder | not scheduled |
| Financial statements and tax filings | none (no company yet) | Founder | after M1 |
| Cyber and E&O insurance | none | Founder | not scheduled |
| Founder's own monthly Azure burn, verified | REG-H07 | Founder | not scheduled |
| Employment or contractor agreements | M3 | Founder | 2027-02-28 |

**MISSING-AGENT** (fix now): none. Every row the agent can produce already exists.

## 4. Seed-42 tag census

Engine inputs (`model_outputs.json`, identical in EN and ES): 50 inputs, **V 14 / M 32 / H 4**. The two committed packs each carry their own per-deliverable census; this file adds none of its own model figures.

## 5. Open conflicts and carried items

| # | Item | State | Effect |
|---|---|---|---|
| C-1 | Founder's own monthly Azure burn ($17.54 / $44.77) | remains **M**, unmeasured. *(Amended 2026-09-30: `00_query_prices.sh` now exists and ran, see G12; it verifies list prices only. The owner's burn composition still needs the owner's own Cost Management export, so C-1 stays M.)* | State "unmeasured, MODEL" on every burn slide. |
| C-2 | `paginaaegis.html` (Phase 1 site input) | not in the repository | Phase 1 must either receive the file from the owner or build the sales surface from the repo. |
| C-3 | Audit corpus (AEG1 67.5/100, AEG2/L11 51/100, strategic audit, teardown notes) | not present as files; only summarised inside the investor packs | Not consumed. Those scores stay unverified until the source files are supplied. |
| C-4 | Signature and attestation verification (G10) | tools absent here | Phase 4 assurance work must not describe signatures as verified by this session. |
| C-5 | G4 timing test under parallel load | see §2 | Run it serially when quoting a "0 failed" figure. |
| C-6 | PyPI `aegis-latent-core` 5.0.1 artifacts now equal the release assets byte for byte | observed today (V); differs from the older note for the previously published 4.1.2 build | `SHA256SUMS` therefore also covers the PyPI gateway downloads at 5.0.1; the older caveat applies to 4.1.2 only. |

## 6. Kill criteria (D10.3)

No kill trigger has data yet: zero interviews, zero pilots and zero outbound touches have occurred. State: **not evaluable, no trigger fired** (V). Triggers become executable in Phase 3.

## 7. Phases unlocked

Phase 0 gates: none red. The owner instruction **"AVANZA FASE 1"** is the only remaining condition for **C1 (SALES_SURFACE)**. Phases C2 to C7 stay locked behind their predecessors and their own owner instruction.

## 8. What this baseline does not claim

No certification, legal compliance, court admissibility, production readiness or capacity, external assurance, or customer traction. The `v5.0.1` tag, release, registries and image digests were read back today; their signatures and attestations were not verified in this session.

## 9. Reproduce

```bash
python scripts/verify_claims.py
python -m pytest -n auto -q
python -m pytest tests/test_determinism.py -q
git ls-remote --tags origin 'v5.0.1*'
# release checksums: download the 15 files listed in SHA256SUMS from the v5.0.1 release, then
sha256sum -c SHA256SUMS
for pkg in aegis-latent-core aegis-latent-sdk; do
  curl -s "https://pypi.org/pypi/$pkg/5.0.1/json" \
    | python -c "import sys,json;[print(f['digests']['sha256'],f['filename'],f['url']) for f in json.load(sys.stdin)['urls']]"
done
# download each URL printed above, run sha256sum on it, and compare with the digest shown and the SHA256SUMS line
curl -s https://registry.npmjs.org/aegis-latent-sdk/5.0.1
```

Engine identity (G1, G2). Use a venv with the versions in `investor_packs/aegis_investor_pack_en/engine/requirements.txt` (numpy 2.4.6, matplotlib 3.11.2, Python 3.11):

```bash
cd investor_packs/aegis_investor_pack_en
sha256sum -c SHA256SUMS
python engine/aegis_financial_engine.py --out ./rebuild
cmp rebuild/model_tables.md data/model_tables.md
cmp rebuild/model_outputs.json data/model_outputs.json
for f in img/*.png; do cmp "$f" "rebuild/$(basename "$f")"; done
cd ../paquete_inversor_aegis_es
sha256sum -c SHA256SUMS
python motor/aegis_financial_engine.py --out ./reconstruccion --lang es
cmp reconstruccion/model_tables.md datos/model_tables.md
cmp reconstruccion/model_outputs.json datos/model_outputs.json
for f in img/*.png; do cmp "$f" "reconstruccion/$(basename "$f")"; done
cmp ../aegis_investor_pack_en/data/model_outputs.json datos/model_outputs.json
```

Delete the `rebuild/` and `reconstruccion/` folders afterwards; they are not to be committed.

WAITING FOR OWNER: AVANZA FASE 1

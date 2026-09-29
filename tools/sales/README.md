<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
-->

# Verification-first sales surface

**Audience:** whoever shows Aegis Latent Core to a buyer, and the buyer's engineer who wants to falsify what they were shown.
**Scope:** the assets that let a stranger check the central claim in minutes: a verifier kit, two static pages, a data-room index, a copy lint and an end-to-end demo. Read 2026-09-29 (Mission XVI, Phase 1).
**Boundary:** every asset here carries the command that reproduces it. None of it is evidence about a customer deployment, and none of it changes what `docs/CLAIMS_MATRIX.md` allows anyone to say.

## What is here

| Asset | Path | Reproduce |
| --- | --- | --- |
| Verifier and three-case demo | [`prove_it/prove_it.py`](prove_it/prove_it.py) | `pip install aegis-latent-sdk && python tools/sales/prove_it/prove_it.py --demo` |
| Synthetic fixtures | [`prove_it/`](prove_it/) (`record.json`, `record_tampered.json`, `TRUSTED_ROOT.txt`) | `python tools/sales/prove_it/make_fixture.py --check` |
| Landing page and data room | [`../../site/`](../../site/) | `python tools/sales/build_site.py --check` |
| Data-room source rows | [`data_room.json`](data_room.json) | `python tools/sales/build_site.py` (fails if a listed path is missing) |
| Banned-word lint | [`../../scripts/lint_sales_copy.py`](../../scripts/lint_sales_copy.py) | `python scripts/lint_sales_copy.py` |
| End-to-end demo tenant | [`../../examples/demo.py`](../../examples/demo.py) | `python -m examples.demo` |

## The verifier kit

`prove_it.py` needs only the SDK. It makes no network call. `--demo` verifies three shipped cases and exits 0 only if all three behave as required:

1. a genuine record against the root it belongs to: must be `INCLUDED`;
2. the same record with one field altered: must be `NOT INCLUDED`;
3. the genuine record against a root you did not obtain: must be `NOT INCLUDED`.

The records are generated, not captured from a running gateway, and each says `"synthetic_fixture": true`. To verify a record from a real gateway, use `prove_it.py verify RECORD.json TRUSTED_ROOT` with a root that reached you by a path the discloser does not control. A pass establishes inclusion under that root and nothing else; the full list of what it does not establish is in [Prove It Yourself](../../docs/PROVE_IT.md) §5 and on the landing page.

## The demo tenant

`examples/demo.py` boots the gateway and a mock upstream in one process, sends five requests, verifies the chain, shows a tamper being detected and exports a sealed bundle. It had been failing five of nine checks on `main`: the default enforcement mode is strict, API keys need a tenant, role and scope mapping, and each request commits two nodes (the request and its `:analysis` record). It now declares development mode, builds the mapping with `build_api_key_principals` and expects two nodes per request. `tests/test_sales_surface.py` runs it, so it cannot rot unnoticed again. It is a development-mode demonstration, not a statement about a strict deployment.

## Measured page quality

Lighthouse 12.8.2, headless Chromium, run against the pages served locally on 2026-09-29. The scores describe these two static pages on one machine, not a hosted site.

| Page | Performance | Accessibility | Best practices | SEO |
| --- | --- | --- | --- | --- |
| `site/index.html` | 100 | 100 | 96 | 100 |
| `site/data-room.html` | 100 | 100 | 96 | 100 |

Reproduce:

```bash
(cd site && python3 -m http.server 8765 &)
npm install lighthouse@12
CHROME_PATH=/path/to/chrome npx lighthouse http://127.0.0.1:8765/index.html \
  --chrome-flags="--headless=new --no-sandbox" \
  --only-categories=performance,accessibility,best-practices,seo
```

The pages load no script, font or image from another host. They are not deployed anywhere: publishing them is an owner action.

## Copy discipline

`scripts/lint_sales_copy.py` rejects `guaranteed`, `unbreakable`, `certified`, `100%` and `military-grade` in the sales surface unless the same sentence negates or quotes the word. It reads text only; whether the remaining sentences are true is decided by `scripts/verify_claims.py` and `tools/docs/verify_documentation.py`. The test suite runs it, so the check runs in CI.

## What this phase does not do

It does not publish the site, send anything to a prospect, or claim a customer, a certification or a capacity. The site input the mission expected (`paginaaegis.html`) is not in the repository, so the pages were built from repository facts instead.

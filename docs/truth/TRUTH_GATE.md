# Truth gate — 2026-10-29

> **Historical snapshot.** `5.0.3` was published on 2026-10-30 after this gate
> ran. The identity table below is preserved as the state it audited; the
> current publication record is `docs/RELEASE_STATUS.md` §1.0e.

**TRUTH GATE: PASS**

This record freezes the state of the public-claim gate before any commercial
surface, release asset, or investor document is produced. It is a snapshot, not
a permanent guarantee: the commands below must be rerun after any public-copy
change.

## Identity

| Item | Value |
| --- | --- |
| Date (UTC) | 2026-10-29 |
| Website commit | `aegisweb` `4c446d6` (`main`) |
| Core repository commit | `aegis-latent-core` `3061f92` (branch `docs/align-control-baselines`) |
| Published release inspected | `v5.0.2` (2026-10-01) |
| Source target inspected | `v5.0.3` (published 2026-10-30, after this snapshot) |
| Local preview | `http://127.0.0.1:4176`, built from the website commit above |

## Commands and real output

Run from `aegisweb/` unless stated otherwise.

| Command | Result |
| --- | --- |
| `npm run audit:claims` | `audit-claims: PASS — 0 finding(s)` |
| `node scripts/audit-site.mjs http://127.0.0.1:4176` | `OK: 30 paths × 13 locales verified.` |
| `node scripts/audit-content.mjs http://127.0.0.1:4176` | `rutas con cuerpo español: 0/27`; `combinaciones ruta×idioma afectadas: 0/324` |
| `node scripts/audit-links.mjs http://127.0.0.1:4176` | `links: 80 pages visited, 80 answered, 0 broken` |
| `node scripts/audit-headers.mjs http://127.0.0.1:4176` | `headers: 3 paths, 0 failure(s)` |
| `node scripts/axe-audit.mjs http://127.0.0.1:4176` | `OK: no serious or critical violations` (color-contrast skipped in jsdom; see `brand/check_a11y.py`) |
| `npm run verify:i18n` | `i18n check: PASS (367 keys × 13 locales)` |
| `npm run typecheck` | exit 0 |
| `npm run build` | exit 0 (run before this record; no source change since) |
| `cd aegis-latent-core && .venv/bin/python -m pytest tests/test_documentation_currency.py tests/test_ai_context.py tests/test_license_policy.py -q` | `37 passed` |
| `cd aegis-latent-core && .venv/bin/python tools/docs/build_index.py` | `156 pages, 22 directory groups, 1465 relative links, 0 broken` |

The production site was also read back after deploy: `https://aegislatent.com/`
and `https://aegislatent.com/precios` returned `200`, and neither contained
`AGPLv3`, `gratis`, `free`, `247+`, `99.99`, `Código abierto` or the old terms
date `2026-10-21`.

## Allowlisted exceptions

| Exception | Why it exists | Owner | Expiry |
| --- | --- | --- | --- |
| `aegisweb/src/data/sections/pricing.ts` is not scanned by `audit-claims.mjs` | The route imports a small subset of `PRICING_COPY`; the file still contains unused legacy plan/FAQ strings that mention unbacked features. The rendered surface is quote-only and is scanned. | web owner | 2026-11-30 |
| `README.md`, `NOTICE`, `COMMERCIAL.md`, `docs/CLAIMS_MATRIX.md` may name the historical licence | These are the licence-boundary documents that must say what `5.0.2` shipped with. They are not a claim that `5.0.3` is under that licence. | release owner | no expiry; scoped to the boundary docs |
| `investor_packs/**`, `evidence/**`, `site/**` are not rewritten | Historical artifacts keep the text they shipped with; they are not current claims. They must not be linked as current evidence. | founder | no expiry |
| Social profiles and third-party listings are not repository-controlled | They must be updated from this map before any campaign; the repository cannot gate them. | founder | 2026-11-15 |

No other exception is allowed. An exception without an owner and an expiry is a
finding, not an exception.

## Freeze rule

No new public surface — page, README section, release note, registry metadata,
pitch deck, data-room page, social profile, sales email, or investor document —
may ship a claim unless it has a row in
[`PUBLIC_SURFACE_MAP.md`](PUBLIC_SURFACE_MAP.md) naming its canonical source,
owner, and gate. A claim that cannot name a source is removed, not softened.

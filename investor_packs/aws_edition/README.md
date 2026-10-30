# AWS edition — investor HTML

Two self-contained HTML documents, English and Spanish, for a first or second
meeting. They are the current investor edition for hosting and release facts;
the 30 September 2026 packs in the parent directory remain as historical source
and are not rewritten.

| File | What it is |
| --- | --- |
| `aegis-aws-edition-en.html` | English edition, embedded fonts, no external asset |
| `aegis-aws-edition-es.html` | Spanish edition, same layout and data |
| `aegis-one-page-en.pdf` / `aegis-one-page-es.pdf` | A4 one-page sheets, copied from `../one_page/out/` |
| `aws_facts.json` | Release and AWS readback of 2026-10-30 |
| `build.py` | Reproducible generator; reads `docs/investor/facts.json`, the model and this file |

## Check

```bash
cd investor_packs/aws_edition
python3 build.py --check
sha256sum -c SHA256SUMS
```

`--check` renders both documents in memory and exits non-zero if any token is
unresolved or either file is stale. The checksum list covers the two HTML files,
both PDFs, the readback and the generator.

## Rebuild

```bash
python3 build.py
sha256sum aegis-aws-edition-*.html *.pdf aws_facts.json build.py > SHA256SUMS
```

The HTML embeds Geist and Instrument Serif as base64 WOFF2, so it opens offline
and prints to A4 without a network request. The page is responsive down to
390 px; print CSS keeps each section from breaking across pages.

## What the figures mean

- Release figures come from `aws_facts.json`, which records the 2026-10-30
  publication readback.
- Surface counts, pricing and test counts come from `docs/investor/facts.json`.
- The plan ladder, tranches, burn and use of funds come from
  `aegis_investor_pack_en/data/model_outputs.json`.
- The AWS p50 and throughput come from `docs/SCALABILITY.md`; the gate count
  comes from `orch/reports/integration/section12-reproduction.md`.
- The gateway distribution on PyPI is at 5.0.2; the SDKs and OCI images are at
  5.0.3. The document states that split without turning it into a headline.

# AWS edition — investor HTML

Two self-contained HTML documents, English and Spanish, for a first or second
meeting. They are the current investor edition for hosting and release facts;
the 30 September 2026 packs in the parent directory remain as historical source
and are not rewritten.

The rendered HTML, the A4 sheets and the handoff ZIP live in `out/`. That
directory is ignored on purpose: `AGENTS.md` forbids committing generated
artifacts. The generator and every input it needs are committed.

| Path | What it is |
| --- | --- |
| `out/aegis-aws-edition-en.html` | English edition, embedded fonts, no external asset |
| `out/aegis-aws-edition-es.html` | Spanish edition, same layout and data |
| `out/aegis-one-page-en.pdf` / `out/aegis-one-page-es.pdf` | A4 one-page sheets, copied from `../one_page/out/` |
| `aws_facts.json` | Release and AWS readback of 2026-10-30 |
| `data/investor_facts.json` | Snapshot of the surface, pricing and test facts used by the edition |
| `assets/*.woff2` | Geist and Instrument Serif, SIL OFL 1.1, embedded as base64 |
| `build.py` | Reproducible generator; resolves every input inside this checkout |

## Check

```bash
cd investor_packs/aws_edition
python3 build.py --check
cd out && sha256sum -c SHA256SUMS
```

`--check` renders both documents in memory and exits non-zero if any token is
unresolved or either file is stale. The checksum list covers the two HTML files,
both PDFs, the readback and the generator.

## Rebuild

```bash
cd investor_packs/aws_edition
python3 build.py
cd out
sha256sum aegis-aws-edition-*.html aegis-one-page-*.pdf ../aws_facts.json ../build.py > SHA256SUMS
zip -X -q aegis-aws-edition.zip aegis-aws-edition-*.html aegis-one-page-*.pdf ../README.md
```

The HTML embeds the two fonts as base64 WOFF2, so it opens offline and prints to
A4 without a network request. The page is responsive down to 390 px; print CSS
keeps each section from breaking across pages.

## What the figures mean

- Release figures come from `aws_facts.json`, which records the 2026-10-30
  publication readback.
- Surface counts, pricing and test counts come from
  `data/investor_facts.json`.
- The plan ladder, tranches, burn and use of funds come from
  `aegis_investor_pack_en/data/model_outputs.json`.
- The AWS p50, p95, rate and answer counts are in `aws_facts.json` under
  `throughput`; the clean-tree gate count is under `gates`.
- The gateway distribution on PyPI, both SDKs and both OCI images are at 5.0.3. The document lists each surface without turning the version into a headline.

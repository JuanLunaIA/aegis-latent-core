# Investor packs

The current AWS edition, two historical editions of the seed pack, one financial
model, and a one-page sheet for a first meeting.

| Path | What it is |
| --- | --- |
| `aws_edition/` | **Current:** self-contained AWS edition in English and Spanish, with the A4 sheets and the 2026-10-30 readback |
| `aegis_investor_pack_en/` | 30 September 2026 edition: the pack, six charts, the engine, model outputs, the A4 one-pager. Historical source |
| `paquete_inversor_aegis_es/` | Spanish edition of the same, with peso amounts in parentheses. Historical source |
| `one_page/` | Source of the A4 sheet: copy with tokens, the builder, the two PDFs and their checksums |

The packs share one financial engine and one `model_outputs.json`; the one-page
sheet reads the repository's measured facts and the model, never a retyped number.

## Check

```bash
cd aegis_investor_pack_en && sha256sum -c SHA256SUMS
cd ../paquete_inversor_aegis_es && sha256sum -c SHA256SUMS
cd ../one_page && python3 build.py --check
cd ../aws_edition && python3 build.py --check
```

The AWS edition is the one to send for a first meeting. The older packs remain
for their financial model and chart source, not for hosting or release figures.

## Rebuild the one-pager

```bash
cd one_page && python3 build.py
```

It renders both PDFs with headless Chromium and then verifies them with poppler:
one page, A4 (595 x 842 pt), the expected text present and no unembedded font.

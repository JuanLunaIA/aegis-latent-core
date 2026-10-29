# Investor packs

Two editions of the seed pack, one financial model, and a one-page sheet for a
first meeting.

| Path | What it is |
| --- | --- |
| `aegis_investor_pack_en/` | English edition: the pack, six charts, the engine, model outputs, the A4 one-pager |
| `paquete_inversor_aegis_es/` | Spanish edition of the same, with peso amounts in parentheses |
| `one_page/` | Source of the A4 sheet: copy with tokens, the builder, the two PDFs and their checksums |

The packs share one financial engine and one `model_outputs.json`; the one-page
sheet reads the repository's measured facts and the model, never a retyped number.

## Check

```bash
cd aegis_investor_pack_en && sha256sum -c SHA256SUMS
cd ../paquete_inversor_aegis_es && sha256sum -c SHA256SUMS
cd ../one_page && python3 build.py --check
```

## Rebuild the one-pager

```bash
cd one_page && python3 build.py
```

It renders both PDFs with headless Chromium and then verifies them with poppler:
one page, A4 (595 x 842 pt), the expected text present and no unembedded font.

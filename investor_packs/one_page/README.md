# One-page investor sheet

Two A4 PDFs, English and Spanish, for a first meeting. One page each, no appendix.

| File | What it is |
| --- | --- |
| `out/aegis-one-page-en.pdf` | A4, one page, 595 x 842 pt |
| `out/aegis-one-page-es.pdf` | Same sheet in Spanish, with Spanish number formatting |
| `out/*.html` | The rendered source, kept so a defect can be traced to markup |
| `out/SHA256SUMS` | Checksums of the four files above |
| `facts.json` | Copy with `{tokens}` instead of figures |
| `build.py` | Resolves the tokens, renders, and verifies the PDF |

## Nothing on the sheet is typed

`facts.json` contains no numbers: each one is `{p50}`, `{cost}`, `{team}` and so
on. `build.py` fills them from files a gate already maintains:

| Figure | Read from |
| --- | --- |
| Routes, migrations, locales, tests | `docs/investor/facts.json` |
| Latency and throughput | `docs/SCALABILITY.md`, section 7 (AWS, not the laptop) |
| Unit cost | `docs/COST_MODEL.md` |
| Gate count and duration | `orch/reports/integration/section12-reproduction.md`, last run |
| Raise, tranches, runway, margins | `aegis_investor_pack_en/data/model_outputs.json` |

A token that cannot be resolved stops the build. A number that moves in the
repository moves on the sheet or fails the build; it cannot go stale quietly.

## Build

```bash
python3 build.py
```

It renders each locale with headless Chromium at A4 and then verifies the result
with poppler: exactly one page, 595 x 842 points, the wordmark, the limits heading
and the footer present, no template token left, and every font embedded. If any of
those fail, the build exits non-zero.

```bash
python3 build.py --check
```

`--check` re-verifies the committed PDFs and their checksums without rebuilding.

## Editing the copy

Edit `facts.json`. Keep the tokens; do not paste figures. If a sentence needs a
new number, add it to `metrics()` with the file it comes from, then use the token.

## Why the sheet says what it does not claim

The last block names the missing certifications, the absent paying customers, the
single-AZ database and the restore drill nobody has run. An investor sheet that
only lists strengths is a brochure; this one is a measurement, and the limits are
part of it.

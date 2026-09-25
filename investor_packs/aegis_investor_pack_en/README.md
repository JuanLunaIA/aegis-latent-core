# Aegis Latent Core: Seed Investor Pack (English)

**Date created:** 25 September 2026 (2026-09-25)

This folder is the English edition of the Mission Order XV investor pack: deliverables D1–D10 and the one-screen ask. A separate folder, `paquete_inversor_aegis_es/`, holds the Rioplatense Spanish edition, with peso amounts in parentheses. Both editions come from the same engine and the same numbers.

## Contents

| Path | What it is |
|---|---|
| `aegis_investor_pack.html` | The pack. Open it in a browser. |
| `img/` | The six charts, produced by the engine and nothing else |
| `engine/aegis_financial_engine.py` | The single script behind every table, chart and model figure |
| `engine/requirements.txt` | The library versions that produced these files |
| `data/model_tables.md` | Every model table, as the engine wrote it |
| `data/model_outputs.json` | Every model output and every tagged input (VERIFIED, MODEL, HYPOTHESIS) |
| `SHA256SUMS` | Checksums of every other file in this folder |

A private online copy of the page is at <https://claude.ai/artifact/1RTrGhJgXiwG2fkseDruL1>. Only its owner can open it until it is shared from the page's Share menu.

## Check and reproduce

```bash
sha256sum -c SHA256SUMS

python3 -m venv .venv && . .venv/bin/activate
pip install -r engine/requirements.txt
python engine/aegis_financial_engine.py --out ./rebuild
cmp rebuild/model_tables.md data/model_tables.md
for f in img/*.png; do cmp "$f" "rebuild/$(basename "$f")"; done
```

With numpy 2.4.6, matplotlib 3.11.2 and Python 3.11, the engine reproduced every file in `img/` and `data/` byte for byte. Other library versions can move chart pixels, but the numbers stay the same.

## Reading notes

- **Tags.** Every figure carries a tag. VERIFIED means read back from a primary source or a retained artifact. MODEL means an assumption stated inline. HYPOTHESIS means untested, with the validating experiment named in D10. Each deliverable ends with a count of its tags.
- **Chart rules.** The engine is the only chart source: matplotlib with the Agg backend and seed 42.
- **Offline.** The page loads its fonts from Google Fonts and draws its two diagrams with Mermaid from jsDelivr. Without a network connection, the fonts fall back to system fonts and the diagrams appear as their source text.
- **What this pack does not claim.** No certification, legal compliance, court admissibility, production readiness or capacity, or external assurance. The conflict log in D10.4 records every supplied input that was corrected or downgraded.
- **Engine change on 2026-09-25.** A `--lang es` switch and one input, `fx_ars_per_usd`, were added for the Spanish edition. The English charts and tables were checked byte-identical to the versions before the change.
- **Handling.** These are fundraising materials, committed to the `aegis-latent-core` repository at the owner's request on 2026-09-25. They are not product documentation; `docs/CLAIMS_MATRIX.md` remains the only source of product capability claims.

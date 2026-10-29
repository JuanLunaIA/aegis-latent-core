#!/usr/bin/env python3
"""Refresh the two investor packs: dated banner, one-page link, checksums.

The financial model inside the packs is dated September and is left as it is;
what changed is the product evidence. The banner says exactly that instead of
rewriting history, and points at the A4 sheet built from today's measurements.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

HERE = Path(__file__).resolve().parent
ONE = HERE / "one_page/out"

BANNERS = {
    "en": """<section id="update-2026-10-29" style="max-width:1080px;margin:24px auto 0;padding:18px 22px;border:1px solid #21569f;border-left:6px solid #21569f;background:#eef3fb;font-family:'IBM Plex Sans',system-ui,sans-serif;color:#121820;">
  <div style="font:600 11px/1 'IBM Plex Mono',monospace;letter-spacing:.14em;text-transform:uppercase;color:#21569f;">Update · 29 October 2026</div>
  <p style="margin:10px 0 8px;font-size:15px;line-height:1.55;">The financial model in this pack is unchanged since 30 September. The product evidence is new: the control plane runs on AWS with a verified email round trip (201 → 200 → 201), 50 requests per second at p50 19.7 ms, 17/17 gates on a clean tree, and a unit cost of $19.47 per million requests.</p>
  <p style="margin:0;font-size:14px;line-height:1.55;">The one-page A4 sheet carries those figures with the file each one comes from: <a href="aegis-one-page-en.pdf" style="color:#21569f;font-weight:600;">aegis-one-page-en.pdf</a> · <a href="../one_page/out/aegis-one-page-es.pdf" style="color:#21569f;">edición en español</a></p>
</section>
""",
    "es": """<section id="actualizacion-2026-10-29" style="max-width:1080px;margin:24px auto 0;padding:18px 22px;border:1px solid #21569f;border-left:6px solid #21569f;background:#eef3fb;font-family:'IBM Plex Sans',system-ui,sans-serif;color:#121820;">
  <div style="font:600 11px/1 'IBM Plex Mono',monospace;letter-spacing:.14em;text-transform:uppercase;color:#21569f;">Actualización · 29 de octubre de 2026</div>
  <p style="margin:10px 0 8px;font-size:15px;line-height:1.55;">El modelo financiero de este paquete no cambió desde el 30 de septiembre. La evidencia de producto es nueva: el plano de control corre en AWS con verificación de correo comprobada (201 → 200 → 201), 50 peticiones por segundo con p50 de 19,7 ms, 17/17 gates sobre árbol limpio y un costo unitario de USD 19,47 por millón de peticiones.</p>
  <p style="margin:0;font-size:14px;line-height:1.55;">La hoja A4 de una página lleva esas cifras con el archivo del que sale cada una: <a href="aegis-one-page-es.pdf" style="color:#21569f;font-weight:600;">aegis-one-page-es.pdf</a> · <a href="../one_page/out/aegis-one-page-en.pdf" style="color:#21569f;">English edition</a></p>
</section>
""",
}

PACKS = {
    "en": HERE / "aegis_investor_pack_en",
    "es": HERE / "paquete_inversor_aegis_es",
}

README_SECTION = {
    "en": """
## Update, 29 October 2026

The financial model is unchanged since 30 September 2026. The product evidence is
new: the control plane runs on AWS with a verified email round trip, a measured
50 requests per second at p50 19.7 ms, 17/17 gates on a clean tree and a unit cost
of $19.47 per million requests.

The one-page A4 sheet for a first meeting is `aegis-one-page-en.pdf` in this
folder, built from the same measurements by `../one_page/build.py`. Its Spanish
counterpart is `../one_page/out/aegis-one-page-es.pdf`.
""",
    "es": """
## Actualización, 29 de octubre de 2026

El modelo financiero no cambió desde el 30 de septiembre de 2026. La evidencia de
producto es nueva: el plano de control corre en AWS con verificación de correo
comprobada, 50 peticiones por segundo medidas con p50 de 19,7 ms, 17/17 gates
sobre árbol limpio y un costo unitario de USD 19,47 por millón de peticiones.

La hoja A4 de una página para una primera reunión es `aegis-one-page-es.pdf` en
esta carpeta, construida con las mismas mediciones por `../one_page/build.py`. Su
contraparte en inglés es `../one_page/out/aegis-one-page-en.pdf`.
""",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rewrite_sums(folder: Path) -> int:
    lines = []
    for path in sorted(folder.rglob("*")):
        if not path.is_file() or path.name == "SHA256SUMS":
            continue
        lines.append(f"{sha256(path)}  {path.relative_to(folder).as_posix()}")
    (folder / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return len(lines)


def main() -> int:
    facts = json.loads((HERE / "one_page/facts.json").read_text(encoding="utf-8"))
    for locale, folder in PACKS.items():
        html_path = next(folder.glob("*.html"))
        html = html_path.read_text(encoding="utf-8")
        if 'id="update-2026-10-29"' in html or 'id="actualizacion-2026-10-29"' in html:
            marker = 'id="update-2026-10-29"' if locale == "en" else 'id="actualizacion-2026-10-29"'
            start = html.index(f"<section {marker}")
            end = html.index("</section>", start) + len("</section>\n")
            html = html[:start] + BANNERS[locale] + html[end:]
        else:
            html = html.replace("<body>", "<body>\n" + BANNERS[locale], 1)
        html_path.write_text(html, encoding="utf-8")

        readme = folder / "README.md"
        body = readme.read_text(encoding="utf-8")
        if "## Update, 29 October 2026" not in body and "## Actualización, 29 de octubre de 2026" not in body:
            body = body.rstrip() + "\n" + README_SECTION[locale]
        body = body.replace("**Updated:** 30 September 2026 (2026-09-30), twice; see sections U and U2 of the page.",
                            "**Updated:** 29 October 2026 (2026-10-29): evidence update and one-page A4 sheet; the financial model is unchanged since 30 September 2026.")
        body = body.replace("**Actualizado:** 30 de septiembre de 2026 (2026-09-30), dos veces; ver secciones U y U2 de la página.",
                            "**Actualizado:** 29 de octubre de 2026 (2026-10-29): actualización de evidencia y hoja A4 de una página; el modelo financiero no cambió desde el 30 de septiembre de 2026.")
        readme.write_text(body, encoding="utf-8")

        shutil.copy2(ONE / f"aegis-one-page-{locale}.pdf", folder / f"aegis-one-page-{locale}.pdf")
        count = rewrite_sums(folder)
        print(f"{folder.name}: banner, readme, PDF and {count} checksums")

    summary = """# Investor packs

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
"""
    (HERE / "README.md").write_text(summary, encoding="utf-8")
    print("investor_packs/README.md written")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

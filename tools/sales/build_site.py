# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Build the static verification-first sales pages under ``site/``.

    python tools/sales/build_site.py            # write site/index.html, site/data-room.html
    python tools/sales/build_site.py --check    # exit 1 if the committed pages differ

Every figure on the pages is read here from a retained artifact or produced by
running the verifier, then printed with a tag: V means read back from a primary
source or artifact on the date shown. The pages load no script, font or image
from any other host.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SITE = ROOT / "site"
DATA_ROOM = Path(__file__).resolve().parent / "data_room.json"
BENCH = ROOT / "evidence" / "benchmarks" / "benchmarks_5.0.1_2026-09-24.json"
BLOB = "https://github.com/JuanLunaIA/aegis-latent-core/blob/main/"
READBACK = "2026-09-29"

CSS = """
:root{--bg:#fff;--fg:#14171a;--mute:#4a5560;--line:#d5dbe1;--card:#f5f7f9;--acc:#0b5cad;--v:#0a6b3a;--code:#101418;--codefg:#e8edf2}
@media(prefers-color-scheme:dark){:root{--bg:#0f1317;--fg:#e6ebf0;--mute:#a9b4bf;--line:#2b343d;--card:#171d23;--acc:#7db8f5;--v:#56d08b;--code:#080b0e;--codefg:#e8edf2}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.6 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main,header,footer{max-width:60rem;margin:0 auto;padding:0 1rem}
header{padding-top:2rem}
nav a{margin-right:1rem}
a{color:var(--acc)}
h1{font-size:1.9rem;line-height:1.25;margin:1.5rem 0 .5rem}
h2{font-size:1.3rem;margin:2.2rem 0 .6rem}
p.lede{font-size:1.1rem;color:var(--mute)}
pre{background:var(--code);color:var(--codefg);padding:1rem;overflow-x:auto;border-radius:.4rem;font:.85rem/1.5 ui-monospace,SFMono-Regular,Menlo,monospace}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.9em}
table{border-collapse:collapse;width:100%;font-size:.95rem}
th,td{border-bottom:1px solid var(--line);padding:.5rem .6rem;text-align:left;vertical-align:top}
th{background:var(--card)}
.chip{display:inline-block;border:1px solid var(--v);color:var(--v);border-radius:.6rem;padding:0 .35rem;font-size:.75rem;margin-left:.25rem}
.note{background:var(--card);border-left:4px solid var(--acc);padding:.6rem 1rem;margin:1rem 0}
footer{color:var(--mute);font-size:.85rem;padding-bottom:3rem;margin-top:3rem;border-top:1px solid var(--line)}
@media(max-width:40rem){th,td{padding:.4rem .3rem}}
"""

NOT_ESTABLISHED = (
    (
        "That the AI response was correct, safe or appropriate",
        "The record commits to what was sent and returned, not to its quality.",
    ),
    (
        "That the request passed a security boundary",
        "The WAF is bounded pattern detection, not an injection boundary (UC-042).",
    ),
    (
        "Who produced the record",
        "With the default HMAC-SHA256 chain any key holder can forge. It authenticates a key, not a party (UC-041, CLM-090).",
    ),
    (
        "That the timestamp is accurate",
        "It is the issuer's unattested clock unless an RFC 3161 token is attached.",
    ),
    (
        "That the record set is complete",
        "An inclusion proof says nothing about what is absent. There is no non-membership proof.",
    ),
    (
        "That the record is admissible",
        "Admissibility is a judicial determination this software does not create (UC-022, UC-034).",
    ),
    (
        "That the operator could not delete records",
        "Tampering is detected, not prevented. An operator with filesystem access can destroy the chain; you would see the break.",
    ),
)

NOT_CLAIMED = (
    "Certification of any kind, or that one is in progress.",
    "Legal compliance, or that any regulation is satisfied.",
    "Court admissibility.",
    "Production readiness or production capacity.",
    "External assurance: no independent penetration test or SOC 2 report exists yet (REG-H01, REG-H02).",
    "Customer traction: no paying customer or signed pilot exists yet.",
)


def _chip(title: str) -> str:
    return f'<span class="chip" title="{html.escape(title)}">V</span>'


def _sdk_env() -> dict[str, str]:
    """The environment for the verifier, with the in-repo SDK importable.

    A buyer runs ``pip install aegis-latent-sdk``; a checkout that has not
    installed it still has the same source under ``sdk/python/src``.
    """
    env = dict(os.environ)
    src = str(ROOT / "sdk" / "python" / "src")
    env["PYTHONPATH"] = os.pathsep.join(filter(None, [src, env.get("PYTHONPATH", "")]))
    return env


def _demo_output() -> str:
    """Run the shipped verifier demo and return its exact output."""
    proc = subprocess.run(  # noqa: S603  # nosec B603 - argv is this interpreter and a fixed in-repo script, shell=False
        [sys.executable, str(ROOT / "tools/sales/prove_it/prove_it.py"), "--demo"],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
        env=_sdk_env(),
    )
    if proc.returncode != 0:
        raise SystemExit(f"prove_it --demo failed:\n{proc.stdout}\n{proc.stderr}")
    return proc.stdout.strip()


def _page(title: str, description: str, body: str, reproduce: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title>
<meta name="description" content="{html.escape(description)}">
<style>{CSS}</style>
</head>
<body>
<header>
<nav aria-label="Primary"><a href="index.html">Verify</a><a href="data-room.html">Data room</a><a href="{BLOB}docs/CLAIMS_MATRIX.md">Claims</a><a href="{BLOB}COMMERCIAL.md">Licensing</a></nav>
</header>
<main>
{body}
</main>
<footer>
<p>Rebuild this page: <code>{html.escape(reproduce)}</code></p>
<p>Source: <a href="https://github.com/JuanLunaIA/aegis-latent-core">github.com/JuanLunaIA/aegis-latent-core</a>. Licence: AGPLv3 or commercial.</p>
</footer>
</body>
</html>
"""


def build_index() -> str:
    bench = json.loads(BENCH.read_text(encoding="utf-8"))["commit_latency"]
    demo = html.escape(_demo_output())
    rows_not = "\n".join(
        f"<tr><td>{html.escape(a)}</td><td>{html.escape(b)}</td></tr>" for a, b in NOT_ESTABLISHED
    )
    not_claimed = "\n".join(f"<li>{html.escape(item)}</li>" for item in NOT_CLAIMED)
    body = f"""
<h1>Check an AI evidence record without trusting us</h1>
<p class="lede">Aegis Latent Core commits a signed, hash-linked record of every governed AI call before the response reaches the caller, and issues a portable proof that a third party verifies without trusting the gateway, the vendor or the operator.</p>

<h2>Verify it in three commands</h2>
<pre>pip install aegis-latent-sdk
git clone https://github.com/JuanLunaIA/aegis-latent-core
python aegis-latent-core/tools/sales/prove_it/prove_it.py --demo</pre>
<p>The verifier makes no network call. It accepts one genuine record and rejects two forgeries. This is the exact output of that command{_chip("Produced by running the command when this page was built")}:</p>
<pre>{demo}</pre>
<p class="note">The three records are generated fixtures, not captured from a running gateway. The third case matters most: a proof checks only against a root you obtained by a path the discloser does not control.</p>

<h2>What a passing check does not establish</h2>
<table>
<thead><tr><th>It does not establish</th><th>Because</th></tr></thead>
<tbody>
{rows_not}
</tbody>
</table>

<h2>Facts you can re-read</h2>
<table>
<thead><tr><th>Fact</th><th>Value</th><th>Reproduce</th></tr></thead>
<tbody>
<tr><td>Latest release</td><td>v5.0.1, published 2026-09-24{_chip("Read back 2026-09-24")}</td><td><code>git ls-remote --tags origin 'v5.0.1*'</code></td></tr>
<tr><td>PyPI gateway <code>aegis-latent-core</code></td><td>5.0.1, published 2026-09-26{_chip("Read back " + READBACK)}</td><td><code>curl -s https://pypi.org/pypi/aegis-latent-core/json</code></td></tr>
<tr><td>Commit latency, p50 / p99</td><td>{bench["p50_ms"]:.3f} ms / {bench["p99_ms"]:.3f} ms{_chip("Retained artifact evidence/benchmarks/benchmarks_5.0.1_2026-09-24.json")}</td><td><code>python scripts/run_benchmarks_5.0.1.py --json</code></td></tr>
<tr><td>Claims register</td><td>Every public claim has a locator and a boundary{_chip("Checked by a gate in CI")}</td><td><code>python scripts/verify_claims.py</code></td></tr>
</tbody>
</table>
<p>The latency figures come from one shared, unpinned four-CPU container with a real write-ahead-log <code>fsync</code> per commit. They are not a capacity claim. Re-run the harness in your own environment before planning against them.</p>

<h2>What we do not claim</h2>
<ul>
{not_claimed}
</ul>
<p>The full list of refused claims is in the <a href="{BLOB}docs/institutional/UNSUPPORTED_CLAIMS.md">Unsupported Claims register</a>. What exists and what is still missing is on the <a href="data-room.html">data room</a> page.</p>
"""
    return _page(
        "Aegis Latent Core: verify it yourself",
        "Verify a tamper-evident AI evidence record with no call to the vendor, and see exactly what a pass does not prove.",
        body,
        "python tools/sales/build_site.py",
    )


def build_data_room() -> str:
    data = json.loads(DATA_ROOM.read_text(encoding="utf-8"))
    exists: list[str] = []
    missing: list[str] = []
    for row in data["rows"]:
        if row["status"] == "exists":
            links = []
            for rel in row["paths"]:
                if not (ROOT / rel).exists():
                    raise SystemExit(f"data room row lists a path that does not exist: {rel}")
                links.append(
                    f'<a href="{BLOB}{html.escape(rel)}"><code>{html.escape(rel)}</code></a>'
                )
            exists.append(
                f"<tr><td>{html.escape(row['doc'])}</td><td>{'<br>'.join(links)}</td></tr>"
            )
        else:
            missing.append(
                f"<tr><td>{html.escape(row['doc'])}</td><td>{html.escape(row['reg'])}</td>"
                f"<td>{html.escape(row['owner'])}</td><td>{html.escape(row['target'])}</td></tr>"
            )
    body = f"""
<h1>Data room: what exists and what does not</h1>
<p class="lede">Read back {html.escape(data["as_of"])}. Every link below points at a file that existed in the repository when this page was built. Rows that are missing are listed with the owner and a target date, not hidden.</p>

<h2>Available now</h2>
<table>
<thead><tr><th>Document</th><th>Location</th></tr></thead>
<tbody>
{chr(10).join(exists)}
</tbody>
</table>

<h2>Not yet available</h2>
<p>These need a person outside the software to act: counsel, an auditor, a signatory or a customer. Target dates are plans, not commitments.</p>
<table>
<thead><tr><th>Document</th><th>Register item</th><th>Owner</th><th>Target</th></tr></thead>
<tbody>
{chr(10).join(missing)}
</tbody>
</table>
<p class="note">Source of this list: <a href="{BLOB}{html.escape(data["source"].split(" section")[0])}"><code>{html.escape(data["source"])}</code></a>.</p>
"""
    return _page(
        "Aegis Latent Core data room",
        "The documents that exist for Aegis Latent Core, and the ones that are still missing, with owners and target dates.",
        body,
        "python tools/sales/build_site.py",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="fail if committed pages differ")
    args = parser.parse_args()
    pages = {"index.html": build_index(), "data-room.html": build_data_room()}
    status = 0
    SITE.mkdir(exist_ok=True)
    for name, text in pages.items():
        path = SITE / name
        if args.check:
            if not path.exists() or path.read_text(encoding="utf-8") != text:
                print(f"DIFFERS site/{name}")
                status = 1
        else:
            path.write_text(text, encoding="utf-8")
            print(f"wrote site/{name}")
    return status


if __name__ == "__main__":
    sys.exit(main())

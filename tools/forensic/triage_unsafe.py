#!/usr/bin/env python3
"""
Triage unsafe API usage and generate remediation suggestions.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent / "unsafe_remediation.md"
PATTERNS = {
    "exec_call": re.compile(r"\bexec\s*\("),
    "eval_call": re.compile(r"\beval\s*\("),
    # Note: safe_pickle_load from aegis.core.safe_serialization is acceptable
    # This pattern flags direct pickle.load usage without safety wrappers
    "pickle_load": re.compile(r"(?<!safe_)pickle\.load\b"),
    "subprocess_popen": re.compile(r"subprocess\.Popen"),
    "os_system": re.compile(r"os\.system\("),
}

hits = []
for p in sorted(ROOT.rglob("*.py")):
    try:
        text = p.read_text(encoding="utf-8")
    except Exception:  # noqa: S112 — best-effort scan; unreadable files are skipped
        continue
    for key, pat in PATTERNS.items():
        for m in pat.finditer(text):
            line_no = text[: m.start()].count("\n") + 1
            line = (
                text.splitlines()[line_no - 1].strip()
                if line_no - 1 < len(text.splitlines())
                else ""
            )
            hits.append((key, str(p.relative_to(ROOT)), line_no, line))

md = [
    "# Unsafe API Triage",
    "",
    "This report lists occurrences of risky APIs and suggested remediation steps.",
    "",
]
if not hits:
    md.append("No occurrences found.")
else:
    for key in PATTERNS:
        md.append(f"## {key}")
        md.append("")
        for h in [x for x in hits if x[0] == key]:
            md.append(f"- {h[1]}:{h[2]} — `{h[3]}`")
        md.append("")
    md.append("### Suggested remediations")
    md.append("")
    md.append(
        "- Replace `pickle.load` with `json` or a signed artifact workflow. If using pickle, use "
        "`aegis.core.safe_serialization.safe_pickle_load` which provides:\n"
        "  - HMAC signature verification\n"
        "  - Restricted type whitelisting\n"
        "  - Post-load validation\n"
        "  - Comprehensive logging\n"
        "  Consider migrating to safer formats like JSON, MessagePack, or protocol buffers."
    )
    md.append(
        "- Replace `exec`/`eval` with explicit parsers or remove dynamic execution. If unavoidable, create a sandboxed subprocess with strict input validation."
    )
    md.append(
        "- Replace `os.system`/`subprocess.Popen` with higher-level API (`subprocess.run`) and avoid shell=True; prefer job queue for external commands."
    )
    md.append(
        "- Add unit tests that verify invalid inputs do not reach these code paths and add Bandit checks."
    )

OUT.write_text("\n".join(md), encoding="utf-8")
print(f"Wrote {OUT}")

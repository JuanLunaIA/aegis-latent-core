#!/usr/bin/env python3
"""
Triage unsafe API usage and generate remediation suggestions.
"""

# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from pathlib import Path
import re
ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent / "unsafe_remediation.md"
PATTERNS = {
    "exec_call": re.compile(r"\bexec\s*\("),
    "eval_call": re.compile(r"\beval\s*\("),
    "pickle_load": re.compile(r"\bpickle\.load\b"),
    "subprocess_popen": re.compile(r"subprocess\.Popen"),
    "os_system": re.compile(r"os\.system\("),
}

hits = []
for p in sorted(ROOT.rglob("*.py")):
    try:
        text = p.read_text(encoding='utf-8')
    except Exception:
        continue
    for key, pat in PATTERNS.items():
        for m in pat.finditer(text):
            line_no = text[:m.start()].count("\n") + 1
            line = text.splitlines()[line_no-1].strip() if line_no-1 < len(text.splitlines()) else ''
            hits.append((key, str(p.relative_to(ROOT)), line_no, line))

md = ["# Unsafe API Triage", "", "This report lists occurrences of risky APIs and suggested remediation steps.", ""]
if not hits:
    md.append("No occurrences found.")
else:
    for key in PATTERNS:
        md.append(f"## {key}")
        md.append("")
        for h in [x for x in hits if x[0]==key]:
            md.append(f"- {h[1]}:{h[2]} — `{h[3]}`")
        md.append("")
    md.append("### Suggested remediations")
    md.append("")
    md.append("- Replace `pickle.load` with `json` or a signed artifact workflow. If using pickle, restrict allowed types and verify HMAC signature before loading.")
    md.append("- Replace `exec`/`eval` with explicit parsers or remove dynamic execution. If unavoidable, create a sandboxed subprocess with strict input validation.")
    md.append("- Replace `os.system`/`subprocess.Popen` with higher-level API (`subprocess.run`) and avoid shell=True; prefer job queue for external commands.")
    md.append("- Add unit tests that verify invalid inputs do not reach these code paths and add Bandit checks.")

OUT.write_text("\n".join(md), encoding='utf-8')
print(f"Wrote {OUT}")

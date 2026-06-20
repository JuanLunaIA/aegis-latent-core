#!/usr/bin/env python3
"""
Generate a JSON summary of the repository: files, Python functions/classes, Rust functions, counts and an optional test_results snapshot.
Intended for the lightweight visualizer dashboard.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations
import ast
import json
import os
import re
from pathlib import Path
ROOT = Path.cwd()
def analyze_python_file(path: Path):
    try:
        src = path.read_text(encoding='utf-8')
        tree = ast.parse(src)
    except Exception as e:
        return {"error": str(e)}
    funcs = []
    classes = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            funcs.append(node.name)
        elif isinstance(node, ast.AsyncFunctionDef):
            funcs.append(node.name + " (async)")
        elif isinstance(node, ast.ClassDef):
            classes.append(node.name)
    return {"functions": funcs, "classes": classes}


def analyze_rust_file(path: Path):
    try:
        text = path.read_text(encoding='utf-8')
    except Exception as e:
        return {"error": str(e)}
    fn_pattern = re.compile(r"(?m)^\s*(pub\s+)?fn\s+([a-zA-Z0-9_]+)")
    fns = [m.group(2) for m in fn_pattern.finditer(text)]
    return {"functions": fns}


def git_head(root: Path):
    try:
        import subprocess
        out = subprocess.check_output(["git","rev-parse","--short","HEAD"], cwd=root, text=True).strip()
        return out
    except Exception:
        return None


def generate_summary_dict():
    result = {"project": ROOT.name, "python": {}, "rust": {}, "counts": {}}

    py_files = [p for p in ROOT.rglob("*.py") if ".venv" not in p.parts and ".git" not in p.parts]
    rs_files = [p for p in ROOT.rglob("*.rs") if ".venv" not in p.parts and ".git" not in p.parts]

    result["counts"]["python_files"] = len(py_files)
    result["counts"]["rust_files"] = len(rs_files)

    for p in sorted(py_files):
        rel = str(p.relative_to(ROOT))
        result["python"][rel] = analyze_python_file(p)

    for p in sorted(rs_files):
        rel = str(p.relative_to(ROOT))
        result["rust"][rel] = analyze_rust_file(p)

    result["git_head"] = git_head(ROOT)

    # include test results snapshot if present
    tr = ROOT / "tools" / "visualizer" / "test_results.json"
    if tr.exists():
        try:
            result["test_results"] = json.loads(tr.read_text(encoding='utf-8'))
        except Exception as e:
            result["test_results"] = {"error": str(e)}
    else:
        result["test_results"] = "not available"

    return result

def main():
    print(json.dumps(generate_summary_dict(), indent=2))

if __name__ == '__main__':
    main()

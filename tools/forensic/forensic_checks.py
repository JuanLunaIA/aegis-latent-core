#!/usr/bin/env python3
"""
Run repository forensic checks: pattern search, unsafe API usage, basic Python syntax checks
and attempt to compile the Rust extension capturing errors. Outputs a JSON report.
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REPORT = Path(__file__).resolve().parent / "report.json"

PATTERNS = {
    "openai_key_like": re.compile(r"sk-[A-Za-z0-9]{10,}", re.I),
    "password": re.compile(r"password", re.I),
    "private_key": re.compile(r"private_key", re.I),
    "secret_word": re.compile(r"\bsecret\b", re.I),
    "api_key_upper": re.compile(r"API_KEY"),
    "todo": re.compile(r"\bTODO\b"),
    "fixme": re.compile(r"\bFIXME\b"),
    "exec_call": re.compile(r"\bexec\s*\("),
    "eval_call": re.compile(r"\beval\s*\("),
    "subprocess_popen": re.compile(r"subprocess\.Popen"),
    "os_system": re.compile(r"os\.system\("),
    "pickle_load": re.compile(r"pickle\.load\("),
}


def search_files():
    hits = {k: [] for k in PATTERNS}
    exclude_dirs = {".git", "target", ".venv", "__pycache__", ".pytest_cache"}
    for p in ROOT.rglob("*.*"):
        # Skip files inside excluded directories
        if any(p.is_relative_to(ROOT / d) for d in exclude_dirs):
            continue
        if p.is_file() and p.suffix not in (".pyc", ".pyo"):
            try:
                text = p.read_text(encoding='utf-8', errors='ignore')
            except Exception:
                continue
            for k, pat in PATTERNS.items():
                if pat.search(text):
                    hits[k].append(str(p.relative_to(ROOT)))
    return hits


def python_syntax_check():
    errors = []
    for p in ROOT.rglob("*.py"):
        try:
            subprocess.check_output(['python','-m','py_compile', str(p)])
        except subprocess.CalledProcessError as e:
            errors.append({'file': str(p.relative_to(ROOT)), 'error': e.output.decode(errors='ignore')})
    return errors


def rust_build_attempt():
    """Attempt to build or test the Rust extension, but fail fast when toolchain is missing.

    This function prefers quick local diagnostics: it first checks for cargo and a
    system C compiler (cc/gcc/clang) and returns a concise status when these are
    missing to avoid long blocking compilations on developer machines.
    """
    rust_dir = ROOT / 'aegis_rust_v2'
    if not rust_dir.exists():
        return {'status': 'missing', 'detail': 'aegis_rust_v2 not found'}

    import shutil

    cargo = shutil.which('cargo')
    cc = shutil.which('cc') or shutil.which('gcc') or shutil.which('clang')

    if cargo is None:
        return {'status': 'skipped', 'detail': 'cargo not found in PATH'}
    if cc is None:
        return {'status': 'skipped', 'detail': 'C compiler not found (cc/gcc/clang). Install build-essential or equivalent.'}

    try:
        env = dict(**dict())
        env.update({'PYO3_USE_ABI3_FORWARD_COMPATIBILITY': '1'})
        proc = subprocess.run(
            ['cargo', 'test', '--lib', '--manifest-path', str(rust_dir / 'Cargo.toml')],
            capture_output=True,
            text=True,
            env=env,
            timeout=600,
        )
        return {'status': 'done', 'returncode': proc.returncode, 'stdout': proc.stdout[:10000], 'stderr': proc.stderr[:10000]}
    except subprocess.TimeoutExpired:
        return {'status': 'error', 'detail': 'cargo test timed out'}
    except Exception as e:
        return {'status': 'error', 'detail': str(e)}


def main():
    report = {}
    report['patterns'] = search_files()
    report['python_syntax'] = python_syntax_check()
    report['rust_build'] = rust_build_attempt()
    report['notes'] = [
        'This report is a snapshot. Review rust_build.stderr for linker errors (missing libpython-dev or ABI mismatch).',
        'Files listed under exec_call, eval_call, pickle_load may need security review for untrusted input handling.'
    ]
    REPORT.write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(f"Wrote report to {REPORT}")


if __name__ == '__main__':
    main()

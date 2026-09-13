#!/usr/bin/env python3
# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""AST-based import reachability verifier for aegis/core/ modules."""

from __future__ import annotations

import ast
import os
import sys
from pathlib import Path


def get_imports_from_file(filepath: Path) -> set[str]:
    """Parse a python file and return all imported module names."""
    imports = set()
    try:
        content = filepath.read_text(encoding="utf-8")
        tree = ast.parse(content, filename=str(filepath))
    except Exception:
        return imports

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module)
                for alias in node.names:
                    imports.add(f"{node.module}.{alias.name}")
    return imports


def build_call_graph(root_dir: Path) -> dict[str, set[str]]:
    """Build module dependency graph mapping module_name -> set of imported module_names."""
    graph: dict[str, set[str]] = {}
    for py_file in root_dir.glob("**/*.py"):
        if "__pycache__" in py_file.parts:
            continue
        rel_parts = py_file.relative_to(root_dir).with_suffix("").parts
        mod_name = ".".join(rel_parts)
        if mod_name.endswith(".__init__"):
            mod_name = mod_name[:-9]
        graph[mod_name] = get_imports_from_file(py_file)
    return graph


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    aegis_dir = repo_root / "aegis"

    if not aegis_dir.exists():
        print(f"Error: {aegis_dir} not found.", file=sys.stderr)
        return 1

    graph = build_call_graph(repo_root)

    # Known entrypoints
    entrypoints = {
        "aegis.proxy.app",
        "aegis.proxy.streaming",
        "aegis.proxy.waf",
        "aegis.proxy.forwarder",
        "aegis.proxy.dependencies",
        "aegis.proxy.audit_api",
        "aegis.proxy.attestation_api",
        "aegis.core.crypto_audit",
        "aegis.core.mmr",
        "aegis.core.group_commit",
        "aegis.core.pqc_signer",
        "aegis.core.stream_bounds",
        "aegis.core.stream_redactor",
        "aegis.core.forensic",
        "aegis.core.waf_session",
    }

    visited: set[str] = set()
    queue = list(entrypoints)

    while queue:
        curr = queue.pop(0)
        if curr in visited:
            continue
        visited.add(curr)

        # Find direct imports or sub-modules
        for imported in graph.get(curr, set()):
            if imported.startswith("aegis.") and imported not in visited:
                queue.append(imported)
            # Handle package level imports
            parts = imported.split(".")
            for i in range(1, len(parts) + 1):
                parent_mod = ".".join(parts[:i])
                if parent_mod.startswith("aegis.") and parent_mod not in visited:
                    queue.append(parent_mod)

    core_dir = aegis_dir / "core"
    core_modules = set()
    for py_file in core_dir.glob("*.py"):
        if py_file.name == "__init__.py":
            continue
        mod_name = f"aegis.core.{py_file.stem}"
        core_modules.add(mod_name)

    unreachable = core_modules - visited
    print(f"Total aegis/core/ modules: {len(core_modules)}")
    print(f"Reachable modules: {len(core_modules - unreachable)}")

    if unreachable:
        print(f"Notice: Found {len(unreachable)} isolated/auxiliary modules in aegis/core/:")
        for mod in sorted(unreachable):
            print(f"  - {mod}")

    print("AST import reachability verification complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

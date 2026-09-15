#!/usr/bin/env python3
"""Verify every internal module is either reachable or declared roadmap.

Builds the real static import graph, by AST, starting from this
repository's actual entrypoints:

* ``aegis`` — the top-level package ``__init__.py``, which is the public
  surface for the embedded engine (``from aegis import wrap``; see
  ``aegis/embedded.py``, documented in README.md and SECURITY.md).
* ``aegis.proxy.app`` — ``main()`` is the target of both the ``aegis`` and
  ``aegis-server`` console scripts (``pyproject.toml`` ``[project.scripts]``).
* ``aegis_server.main`` — ``main()`` is invoked directly (``python -m
  aegis_server.main``) by ``deploy/docker/docker-compose.enterprise.yml``
  and is a distinct reachable path from the console scripts above, per the
  finding recorded as ``CLM-092`` in ``docs/CLAIMS_MATRIX.md``.
* ``aegis.engines`` — a second, real, documented embedding surface: "a thin,
  importable surface over modules under ``aegis.core`` ... used without
  running the HTTP gateway" (``aegis/engines/__init__.py``'s own docstring).
  Its four facades reach a distinct set of ``aegis.core`` modules from the
  proxy path (e.g. ``pqc_tls``, ``hsm``) and are not roadmap just because the
  gateway itself never imports them.
* ``aegis.crypto`` — the public crypto SDK surface (``CLM-089``, ``CLM-019``):
  ML-KEM sessions, MMR, PQC signing/TLS, the real ZK bindings and the stub,
  and the capability report. Reached only by a caller importing it directly,
  never by the gateway.
* ``aegis.forensics`` — the public forensics-search surface
  (``aegis/forensics/__init__.py``), same pattern.

Every ``.py`` file under ``aegis/``, ``aegis_server/`` and ``integrations/``
(excluding ``tests/`` and ``__pycache__/``) must be either reached by that
graph, or explicitly declared in one of two registries:

* ``pyproject.toml``'s ``[tool.coverage.run]`` ``omit`` list — the existing,
  already-governed "roadmap / platform-specific, not required for proxy
  runtime" registry. A roadmap entry that *has become* reachable is a
  finding: either the roadmap list is stale, or a module the runtime does
  not require has been wired into a real path without anyone updating its
  status.
* ``scripts/import_reachability_allowlist.txt`` — a disclosure list, not a
  classification, populated from this script's own first real run. See its
  header for what "declared" does and does not mean here.

An undeclared orphan (importable by nothing real, on neither list) is the
finding this gate exists to catch: either it is new dead code, or the
entrypoint graph above is stale and needs updating.

Known blind spot, stated rather than hidden: this is static AST analysis.
It does not see ``importlib.import_module`` with a computed string, string
based plugin loading, or any other dynamic import.  A grep of the
production tree (``aegis/``, ``aegis_server/``, excluding ``tests/``) found
no such calls against internal modules at the time this script was written;
if one is added later without updating this script, it will be invisible
here.  Treat a clean run as "no *statically visible* orphan", not as an
exhaustive reachability proof.

Exit codes: 0 clean, 1 findings, 2 the check could not run.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import argparse
import ast
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

PACKAGE_ROOTS = ("aegis", "aegis_server", "integrations")

ENTRYPOINT_MODULES = (
    "aegis",
    "aegis.proxy.app",
    "aegis_server.main",
    "aegis.engines",
    "aegis.crypto",
    "aegis.forensics",
)

EXCLUDE_DIR_NAMES = {"__pycache__", "tests"}


@dataclass(frozen=True)
class Finding:
    code: str
    message: str


@dataclass(frozen=True)
class ModuleInfo:
    path: Path
    is_package: bool


def _module_name_for(path: Path, root: Path) -> str:
    rel = path.relative_to(root).with_suffix("")
    parts = list(rel.parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _discover_modules(root: Path) -> dict[str, ModuleInfo]:
    modules: dict[str, ModuleInfo] = {}
    for pkg in PACKAGE_ROOTS:
        pkg_dir = root / pkg
        if not pkg_dir.is_dir():
            continue
        for path in sorted(pkg_dir.rglob("*.py")):
            if any(part in EXCLUDE_DIR_NAMES for part in path.parts):
                continue
            name = _module_name_for(path, root)
            modules[name] = ModuleInfo(path=path, is_package=path.name == "__init__.py")
    return modules


def _own_package(module: str, info: ModuleInfo) -> str:
    if info.is_package:
        return module
    if "." not in module:
        return ""
    return module.rsplit(".", 1)[0]


def _resolve_relative(module: str, info: ModuleInfo, level: int, target: str | None) -> str:
    base = _own_package(module, info)
    # level=1 means "the module's own package"; each further level strips
    # one more trailing component, mirroring importlib._bootstrap._resolve_name.
    strip = level - 1
    parts = base.split(".") if base else []
    if strip:
        parts = parts[:-strip] if strip <= len(parts) else []
    base = ".".join(parts)
    if target:
        return f"{base}.{target}" if base else target
    return base


def _imports_in(path: Path) -> list[tuple[int | None, str | None, tuple[str, ...]]]:
    """Return (level, dotted_module, imported_names) triples.

    ``imported_names`` matters because ``from aegis.core import pqc_tls`` and
    ``from aegis.core.pqc_tls import Foo`` both reach the ``pqc_tls`` module,
    but only the second spells it in ``dotted_module``; the first spells the
    submodule as one of the imported names, so the caller must also try
    ``dotted_module + "." + name`` as a candidate.
    """
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (SyntaxError, UnicodeDecodeError) as exc:
        raise RuntimeError(f"could not parse {path}: {exc}") from exc
    found: list[tuple[int | None, str | None, tuple[str, ...]]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.append((None, alias.name, ()))
        elif isinstance(node, ast.ImportFrom):
            names = tuple(alias.name for alias in node.names if alias.name != "*")
            found.append((node.level or None, node.module, names))
    return found


def _reachable_set(
    modules: dict[str, ModuleInfo], entrypoints: tuple[str, ...]
) -> tuple[set[str], list[Finding]]:
    findings: list[Finding] = []
    reached: set[str] = set()
    queue = [m for m in entrypoints if m in modules]
    missing_entry = [m for m in entrypoints if m not in modules]
    for name in missing_entry:
        findings.append(Finding("reachability.missing-entrypoint", name))

    while queue:
        current = queue.pop()
        if current in reached:
            continue
        reached.add(current)
        # importing a submodule also executes every ancestor package __init__
        parts = current.split(".")
        for i in range(1, len(parts)):
            ancestor = ".".join(parts[:i])
            if ancestor in modules and ancestor not in reached:
                queue.append(ancestor)

        info = modules.get(current)
        if info is None:
            continue
        for level, target, names in _imports_in(info.path):
            if level is None:
                if target is None:
                    continue
                base = target
            else:
                base = _resolve_relative(current, info, level, target)

            # Two distinct shapes reach a submodule: `from aegis.core.hsm
            # import Foo` spells it in the module path itself, while `from
            # aegis.core import pqc_tls` spells it as an imported name off
            # the package. Try the module path first (also covers `import
            # aegis.core.hsm` and plain `from . import name` where name is
            # itself a submodule), then each `base.name` candidate.
            candidates = [base] if base else []
            candidates.extend(f"{base}.{name}" if base else name for name in names)

            for candidate in candidates:
                candidate_parts = candidate.split(".") if candidate else []
                # walk from the longest dotted prefix down, so a package-level
                # re-export doesn't hide the real file behind it.
                resolved = None
                for i in range(len(candidate_parts), 0, -1):
                    prefix = ".".join(candidate_parts[:i])
                    if prefix in modules:
                        resolved = prefix
                        break
                if resolved and resolved not in reached:
                    queue.append(resolved)

    return reached, findings


def _roadmap_modules(root: Path) -> set[str]:
    pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    omit = pyproject.get("tool", {}).get("coverage", {}).get("run", {}).get("omit", [])
    result = set()
    for entry in omit:
        if not entry.endswith(".py") or entry.startswith("tests/"):
            continue
        result.add(entry[: -len(".py")].replace("/", "."))
    return result


def _allowlisted_modules(root: Path) -> set[str]:
    path = root / "scripts" / "import_reachability_allowlist.txt"
    if not path.exists():
        return set()
    result = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        result.add(line)
    return result


def run(root: Path) -> tuple[bool, list[Finding], dict[str, object]]:
    modules = _discover_modules(root)
    reached, findings = _reachable_set(modules, ENTRYPOINT_MODULES)
    roadmap = _roadmap_modules(root)
    allowlisted = _allowlisted_modules(root)

    unreached = set(modules) - reached
    undeclared_orphans = sorted(unreached - roadmap - allowlisted)
    stale_roadmap_entries = sorted(roadmap & reached)
    roadmap_not_found = sorted(m for m in roadmap if m not in modules)
    stale_allowlist_entries = sorted(allowlisted & reached)
    allowlist_not_found = sorted(m for m in allowlisted if m not in modules)

    for name in undeclared_orphans:
        findings.append(
            Finding(
                "reachability.undeclared-orphan",
                f"{name} is not reachable from any real entrypoint and is not "
                "declared in pyproject.toml's [tool.coverage.run] omit list; "
                "declare it as roadmap or delete it",
            )
        )
    for name in stale_roadmap_entries:
        findings.append(
            Finding(
                "reachability.stale-roadmap-entry",
                f"{name} is declared roadmap in pyproject.toml but is now reachable "
                "from a real entrypoint; update its status or the omit list",
            )
        )
    for name in roadmap_not_found:
        findings.append(
            Finding(
                "reachability.roadmap-entry-not-found",
                f"{name} is declared roadmap in pyproject.toml but no such file exists",
            )
        )
    for name in stale_allowlist_entries:
        findings.append(
            Finding(
                "reachability.stale-allowlist-entry",
                f"{name} is on the reachability allowlist but is now reachable from a "
                "real entrypoint; remove it from "
                "scripts/import_reachability_allowlist.txt",
            )
        )
    for name in allowlist_not_found:
        findings.append(
            Finding(
                "reachability.allowlist-entry-not-found",
                f"{name} is on the reachability allowlist but no such file exists",
            )
        )

    summary = {
        "modules_discovered": len(modules),
        "reached": len(reached),
        "declared_roadmap": len(roadmap),
        "allowlisted": len(allowlisted),
        "undeclared_orphans": undeclared_orphans,
        "stale_roadmap_entries": stale_roadmap_entries,
        "roadmap_entries_not_found": roadmap_not_found,
        "stale_allowlist_entries": stale_allowlist_entries,
        "allowlist_entries_not_found": allowlist_not_found,
    }
    return not findings, findings, summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    args = parser.parse_args()
    root = args.root.resolve()

    try:
        ok, findings, summary = run(root)
    except RuntimeError as exc:
        print(f"verify_import_reachability: could not run: {exc}", file=sys.stderr)
        return 2

    print(
        f"modules discovered: {summary['modules_discovered']}  "
        f"reached: {summary['reached']}  "
        f"declared roadmap: {summary['declared_roadmap']}  "
        f"allowlisted: {summary['allowlisted']}"
    )
    for finding in findings:
        print(f"[{finding.code}] {finding.message}")

    if ok:
        print("verify_import_reachability: PASS — no undeclared orphans, no stale roadmap entries")
        return 0
    print(f"verify_import_reachability: FAIL — {len(findings)} finding(s)", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

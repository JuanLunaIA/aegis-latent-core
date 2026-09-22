#!/usr/bin/env python3
"""Generate ``docs/MODULE_INVENTORY.md`` — the per-file inventory AUD-25 asked for.

The finding was that no artifact answered "what is this file, is it live, what
tests it, who owns it" for the tree, that the import-reachability gate covered
only ``.py`` under three roots, and that navigation named a minority of files.
This script answers it from the authorities that already exist rather than from
a hand-written list:

* **Import status** for ``aegis/``, ``aegis_server/`` and ``integrations/`` comes
  from ``scripts/verify_import_reachability.py`` itself (imported and called, not
  re-implemented), so a module is ``reachable`` / ``roadmap-omit`` /
  ``allowlisted`` / ``orphan`` exactly as that gate measures it.
* **Rust status** is the transitive ``mod`` graph from ``aegis_rust_v2/src/lib.rs``;
  an ``.rs`` file no ``mod`` declaration reaches is an orphan.
* **Script status** for ``scripts/`` and ``tools/`` is "named by something that
  runs or documents it" — a CI workflow, the Makefile, or a tracked ``.md``/``.txt``
  — which is what makes a script live rather than an import edge (nothing imports
  a console script).
* **Ownership** comes from ``.github/CODEOWNERS``, resolved by longest path
  prefix, including the single ``*`` owner.

Output is deterministic (sorted by path, no timestamps), so the currency test can
assert byte-equality: ``tests/test_module_inventory_current.py``.

Run: ``python scripts/generate_module_inventory.py`` (``--check`` verifies only).
"""

# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import argparse
import ast
import importlib.util
import re
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "docs" / "MODULE_INVENTORY.md"

#: The roots the inventory covers. `aegis_rust_v2/src` is a source root, so the
#: Rust crate is classified here even though no Python import edge can reach it.
SOURCE_ROOTS = ("aegis", "aegis_server", "integrations", "scripts", "tools", "aegis_rust_v2/src")

#: Files whose text defines "named in navigation". `REPOSITORY_MAP.md` names these
#: itself as the repository's navigation aids (`.aegis_ai_context/` and `llms.txt`),
#: plus the documents a new contributor is sent to first.
NAVIGATION_SOURCES = (
    "llms.txt",
    "docs/REPOSITORY_MAP.md",
    "AGENTS.md",
    "README.md",
    "SECURITY.md",
    "docs/architecture/ARCHITECTURE.md",
)

#: Text scanned for a script's name — anything that runs it or documents it.
REFERENCE_SOURCES = (".github/workflows", "Makefile", "docs", "AGENTS.md", "llms.txt", "README.md")

SKIP_DIR_NAMES = {"__pycache__", ".pytest_cache"}


@dataclass(frozen=True)
class Entry:
    path: str
    kind: str
    purpose: str
    status: str
    tests: str
    owner: str


def _python_root_module(path: Path) -> str | None:
    """The dotted module name for a file under a package root, else None."""
    rel = path.relative_to(ROOT)
    for root in ("aegis", "aegis_server", "integrations"):
        if rel.parts[0] != root:
            continue
        parts = list(rel.parts)
        if parts[-1] == "__init__.py":
            parts = parts[:-1]
        else:
            parts[-1] = parts[-1][:-3]
        return ".".join(parts) if parts else None
    return None


def _reachability() -> tuple[set[str], set[str], set[str]]:
    """Reuse the gate's own measurement: (reachable, roadmap-omit, allowlisted)."""
    spec = importlib.util.spec_from_file_location(
        "verify_import_reachability", ROOT / "scripts" / "verify_import_reachability.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    modules = module._discover_modules(ROOT)
    reachable, _findings = module._reachable_set(modules, module.ENTRYPOINT_MODULES)
    roadmap: set[str] = set(module._roadmap_modules(ROOT))
    allowlisted: set[str] = set(module._allowlisted_modules(ROOT))
    return set(reachable), roadmap, allowlisted


def _rust_modules() -> set[str]:
    """Every `.rs` file the transitive `mod` graph from lib.rs reaches, by name."""
    src = ROOT / "aegis_rust_v2" / "src"
    seen: set[Path] = set()
    pending = [src / "lib.rs"]
    while pending:
        current = pending.pop()
        if current in seen or not current.exists():
            continue
        seen.add(current)
        text = current.read_text(encoding="utf-8")
        for name in re.findall(r"^\s*(?:pub(?:\([^)]*\))? )?mod (\w+)\s*;", text, re.MULTILINE):
            pending.append(current.parent / f"{name}.rs")
            pending.append(current.parent / name / "mod.rs")
    return {str(p.relative_to(ROOT)) for p in seen}


def _navigation_text() -> str:
    text = ""
    for rel in NAVIGATION_SOURCES:
        path = ROOT / rel
        if path.exists():
            text += path.read_text(encoding="utf-8", errors="replace")
    for path in sorted((ROOT / ".aegis_ai_context").rglob("*")):
        if path.is_file():
            text += path.read_text(encoding="utf-8", errors="replace")
    return text


def _reference_text() -> str:
    text = ""
    for rel in REFERENCE_SOURCES:
        path = ROOT / rel
        if path.is_dir():
            for child in sorted(path.rglob("*")):
                if child.is_file() and child.suffix in {".yml", ".yaml", ".md", ".txt"}:
                    # Never let this inventory count as a reference: it names every
                    # file under the roots, so including it would mark every script
                    # "referenced" by the table that reports the status.
                    if child == OUTPUT:
                        continue
                    text += child.read_text(encoding="utf-8", errors="replace")
        elif path.is_file():
            text += path.read_text(encoding="utf-8", errors="replace")
    return text


def _owners() -> tuple[list[tuple[str, str]], str]:
    """CODEOWNERS as (pattern, owner) pairs plus the catch-all owner."""
    patterns: list[tuple[str, str]] = []
    catch_all = ""
    for line in (ROOT / ".github" / "CODEOWNERS").read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        if parts[0] == "*":
            catch_all = parts[1]
            continue
        patterns.append((parts[0].lstrip("/"), parts[1]))
    return patterns, catch_all


def _owner_for(path: str, patterns: list[tuple[str, str]], catch_all: str) -> str:
    best: tuple[int, str] | None = None
    for prefix, owner in patterns:
        if path == prefix or path.startswith(prefix.rstrip("/") + "/"):
            if best is None or len(prefix) > best[0]:
                best = (len(prefix), owner)
    return best[1] if best else catch_all


def _test_map() -> dict[str, set[str]]:
    """module dotted name -> test files that import it, from one AST pass."""
    mapping: dict[str, set[str]] = {}
    owners = [ROOT / "tests"]
    owners += [p for p in (ROOT / "sdk").glob("*/tests") if p.is_dir()]
    owners += [p for p in (ROOT / "dashboard").glob("tests") if p.is_dir()]
    for base in owners:
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*.py")):
            if SKIP_DIR_NAMES & set(path.parts):
                continue
            try:
                tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                names: list[str] = []
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                    names = [node.module]
                for name in names:
                    if name.split(".")[0] in {"aegis", "aegis_server", "integrations"}:
                        mapping.setdefault(name, set()).add(str(path.relative_to(ROOT)))
    return mapping


def _open_tickets() -> list[tuple[str, str, str]]:
    """Open roadmap tickets as (ticket, priority, unblock path).

    The unblock path is the ticket's own ``Proposed solution`` text — quoted, not
    re-derived, so the inventory cannot drift from the roadmap about what would
    unblock a row.
    """
    text = (ROOT / "docs" / "ROADMAP.md").read_text(encoding="utf-8")
    tickets: list[tuple[str, str, str]] = []
    for match in re.finditer(
        r"^- \[ \] \*\*(.+?)\*\*(.*?)(?=^- \[ \] \*\*|^## |\Z)", text, re.MULTILINE | re.DOTALL
    ):
        heading, body = match.group(1), match.group(2)
        name = heading.split(" — ", 1)[0].strip()
        priority = ""
        if "[" in name and "]" in name:
            priority = name[name.index("[") + 1 : name.index("]")]
            name = name[: name.index("[")].strip()
        solution = ""
        found = re.search(r"Proposed solution[^:]*:\*?\*?\s*(.+)", body)
        if found:
            solution = " ".join(found.group(1).split())
        tickets.append((name, priority, solution))
    return tickets


def _purpose(path: Path) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    if path.suffix == ".py" or path.name == "Makefile":
        try:
            doc = ast.get_docstring(ast.parse(text))
        except SyntaxError:
            doc = None
        first = (doc or "").strip().splitlines()
        return first[0].strip() if first else ""
    if path.suffix == ".rs":
        for line in text.splitlines():
            if line.startswith("//!"):
                return line[3:].strip()
        return ""
    if path.suffix == ".sh":
        # Skip the shebang and the licence header every script carries, or the
        # "purpose" of every shell script is the same copyright line.
        skip = ("Copyright (c)", "Licensed under", "Proprietary Commercial", "See LICENSE")
        for line in text.splitlines():
            if line.startswith("#") and not line.startswith("#!"):
                candidate = line.lstrip("# ").strip()
                if candidate and not any(s in candidate for s in skip):
                    return candidate
        return ""
    return ""


def _kind(path: Path) -> str:
    if path.suffix == ".py":
        return "package" if path.name == "__init__.py" else "module"
    if path.suffix == ".rs":
        return "rust source"
    if path.suffix == ".sh":
        return "shell script"
    if path.suffix in {".md", ".txt", ".json", ".toml", ".lock"}:
        return "text/data"
    return "other"


def _escape(text: str) -> str:
    return text.replace("|", "\\|").strip()


#: Test files listed per row before the cell is abbreviated. The full set is one
#: grep away (`grep -rl 'import <module>' tests/`); the table's job is to say
#: whether a module is covered and by roughly what, not to be a second index.
TESTS_PER_ROW = 4


def _tests_cell(value: str) -> str:
    if value == "—":
        return "—"
    found = value.split(", ")
    shown = found[:TESTS_PER_ROW]
    cell = "`, `".join(shown)
    if len(found) > TESTS_PER_ROW:
        cell += f"`, … (+{len(found) - TESTS_PER_ROW} more)"
    return "`" + cell + "`"


def build() -> str:
    reachable, roadmap, allowlisted = _reachability()
    rust = _rust_modules()
    nav = _navigation_text()
    refs = _reference_text()
    patterns, catch_all = _owners()
    tests = _test_map()

    files: list[Path] = []
    for root in SOURCE_ROOTS:
        base = ROOT / root
        for path in sorted(base.rglob("*")):
            if path.is_dir() or SKIP_DIR_NAMES & set(path.parts):
                continue
            files.append(path)
    files.sort(key=lambda p: str(p.relative_to(ROOT)))

    entries: list[Entry] = []
    for path in files:
        rel = str(path.relative_to(ROOT))
        module = _python_root_module(path) if path.suffix == ".py" else None
        if module is not None:
            if module in reachable:
                status = "reachable"
            elif module in roadmap:
                status = "roadmap-omit"
            elif module in allowlisted:
                status = "allowlisted"
            else:
                status = "orphan"
        elif path.suffix == ".rs":
            status = "reachable" if rel in rust else "orphan"
        elif rel.startswith(("scripts/", "tools/")):
            status = "referenced" if path.name in refs else "unreferenced"
        else:
            status = "n/a"
        found = sorted(tests.get(module, set())) if module else []
        entries.append(
            Entry(
                path=rel,
                kind=_kind(path),
                purpose=_escape(_purpose(path)),
                status=status,
                tests=", ".join(found) if found else "—",
                owner=_owner_for(rel, patterns, catch_all),
            )
        )

    named = [e for e in entries if Path(e.path).name in nav or e.path in nav]
    lines: list[str] = []
    lines.append("# Module inventory")
    lines.append("")
    lines.append(
        "Every file under the six source roots, with what it is, what reaches it, what "
        "tests it, and who owns it. Generated — edit `scripts/generate_module_inventory.py`, "
        "not this file. Currency is enforced by `tests/test_module_inventory_current.py`."
    )
    lines.append("")
    lines.append(f"`python scripts/generate_module_inventory.py` — {len(entries)} files.")
    lines.append("")
    lines.append("## What the status column means")
    lines.append("")
    lines.append("| Status | Meaning |")
    lines.append("|---|---|")
    lines.append(
        "| `reachable` | For `aegis/`, `aegis_server/`, `integrations/`: reached from a documented "
        "entrypoint by `scripts/verify_import_reachability.py`. For `aegis_rust_v2/src`: reached by "
        "the transitive `mod` graph from `lib.rs`. |"
    )
    lines.append(
        "| `roadmap-omit` | Listed in `[tool.coverage.run] omit` as roadmap / platform-specific: a "
        "declared status, cross-checked by the reachability gate. |"
    )
    lines.append(
        "| `allowlisted` | Declared in `scripts/import_reachability_allowlist.txt` — a disclosure, "
        "not a classification, and a worklist rather than a verdict. |"
    )
    lines.append(
        "| `referenced` | For `scripts/` and `tools/`: named by a CI workflow, the Makefile, or a "
        "tracked document. Nothing imports a console script, so being named by something that runs "
        "or documents it is what makes it live. |"
    )
    lines.append(
        "| `unreferenced` | For `scripts/` and `tools/`: named by no workflow, Makefile target or "
        "tracked document. Not a defect by itself — but it is the set to prune or wire, and the "
        "currency test fails if this set changes without the inventory being regenerated. |"
    )
    lines.append(
        "| `orphan` | A Python module no entrypoint reaches and no registry declares, or an `.rs` "
        "file no `mod` reaches. The reachability gate fails on Python orphans; the Rust list here "
        "is the only place they are reported. |"
    )
    lines.append("| `n/a` | A data file inside a source root (`.md`, `.json`, …). |")
    lines.append("")
    lines.append("## Coverage and ownership")
    lines.append("")
    lines.append(
        f"- **Navigation coverage:** {len(named)} of {len(entries)} files "
        f"({100 * len(named) / len(entries):.0f}%) are named in a navigation source "
        f"(`{'`, `'.join(NAVIGATION_SOURCES)}`, and `.aegis_ai_context/`). The rest are reachable "
        "from these tables alone, which is the point of the inventory."
    )
    counts: dict[str, int] = {}
    for entry in entries:
        counts[entry.status] = counts.get(entry.status, 0) + 1
    lines.append(
        "- **Status counts:** "
        + ", ".join(f"`{status}` {counts[status]}" for status in sorted(counts))
        + "."
    )
    owners: dict[str, int] = {}
    for entry in entries:
        owners[entry.owner] = owners.get(entry.owner, 0) + 1
    lines.append(
        "- **Ownership:** resolved from `.github/CODEOWNERS` by longest path prefix. "
        + ", ".join(f"`{owner}` {count} files" for owner, count in sorted(owners.items()))
        + ". This is a single accountable owner, as CODEOWNERS itself states, not a staffed "
        "review team — per-module maintainers cannot be named until one exists, so no row "
        "invents one."
    )
    lines.append("")
    lines.append(
        f"Tests are the test files that import the module directly, capped at {TESTS_PER_ROW} per row; "
        "the count is exact, the list is not exhaustive."
    )
    lines.append("")
    lines.append("## Open roadmap tickets, owner and unblock path")
    lines.append("")
    lines.append(
        "Every open roadmap ticket, its owner, and the ticket's own `Proposed solution` "
        "quoted as the unblock path. A ticket with no such line is shown as such rather "
        "than given one."
    )
    lines.append("")
    lines.append("| Ticket | Priority | Owner | Unblock path |")
    lines.append("|---|---|---|---|")
    for name, priority, solution in _open_tickets():
        lines.append(
            f"| `{name}` | {priority or '—'} | {catch_all} | "
            f"{_escape(solution) if solution else '*(none stated in the ticket)*'} |"
        )
    lines.append("")
    lines.append("## Files")
    lines.append("")
    lines.append("| Path | Kind | Purpose | Status | Tests | Owner |")
    lines.append("|---|---|---|---|---|---|")
    for entry in entries:
        lines.append(
            f"| `{entry.path}` | {entry.kind} | {entry.purpose or '—'} | {entry.status} | "
            f"{_tests_cell(entry.tests)} | {entry.owner} |"
        )
    lines.append("")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify without writing")
    args = parser.parse_args()
    rendered = build()
    if args.check:
        current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.exists() else ""
        if current != rendered:
            print("docs/MODULE_INVENTORY.md is stale — run scripts/generate_module_inventory.py")
            return 1
        print("docs/MODULE_INVENTORY.md is current")
        return 0
    OUTPUT.write_text(rendered, encoding="utf-8")
    print(f"wrote {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

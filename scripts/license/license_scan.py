#!/usr/bin/env python3
# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""License inventory and copyleft reconciliation across all three ecosystems.

Aegis is offered under AGPLv3 **or** a proprietary commercial licence. That
dual offer is what makes this a release gate rather than paperwork: a component
whose terms are satisfied by the AGPL tier can still be undistributable under
the proprietary tier, and the second failure is invisible from the first.

    python scripts/license/license_scan.py --write

Where the licence text comes from
---------------------------------

Every identifier here is read from an artifact on disk, never from a lookup
table in this file:

- **PyPI** — the installed ``.dist-info`` metadata (``License-Expression``,
  ``License``, or the ``License ::`` trove classifiers) for each distribution
  in the active environment.
- **crates.io** — the ``license`` field of each crate's own ``Cargo.toml``, as
  unpacked under ``CARGO_HOME/registry/src``.
- **npm** — the ``license`` field npm records per package in the lockfile.

A component whose licence cannot be read is reported as ``UNKNOWN`` and fails
the gate. Guessing an identifier is the one outcome worse than not having one,
because it produces a clean report that is wrong.

Classification
--------------

``PERMISSIVE``      MIT, Apache-2.0, BSD, ISC, Unlicense, Zlib, CC0 — no
                    reciprocal obligation on the combined work.
``WEAK_COPYLEFT``   LGPL, MPL, EPL — reciprocal for the component itself.
                    Compatible with a proprietary distribution when the
                    component is dynamically linked and attributed, which is a
                    question about linkage this script reports rather than
                    decides.
``STRONG_COPYLEFT`` GPL, AGPL — reciprocal for the combined work. Blocking in
                    the proprietary tier unless the component is not
                    distributed with it at all.
``UNKNOWN``         no readable identifier; blocking until resolved.

What this does not establish
----------------------------

This is an inventory and a consistency check, not legal advice and not a
compliance certification. It reports the identifiers upstream projects
declare. It does not verify that a declared identifier matches the licence
text in the package, it does not resolve licence compatibility questions that
turn on how a work is combined, and no output here is an opinion on whether
any particular distribution is lawful. Counsel owns that judgement.

Exit codes: 0 clean, 1 unresolved blocking findings, 2 the check could not run.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tomllib
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]

AUDIT_PATH: Final[str] = "docs/compliance/LICENSE_AUDIT.md"
ATTRIBUTION_PATH: Final[str] = "LICENSE-THIRD-PARTY.md"

PERMISSIVE: Final[str] = "PERMISSIVE"
WEAK_COPYLEFT: Final[str] = "WEAK_COPYLEFT"
STRONG_COPYLEFT: Final[str] = "STRONG_COPYLEFT"
UNKNOWN: Final[str] = "UNKNOWN"

CLASS_ORDER: Final[tuple[str, ...]] = (STRONG_COPYLEFT, WEAK_COPYLEFT, UNKNOWN, PERMISSIVE)
BLOCKING_CLASSES: Final[frozenset[str]] = frozenset({STRONG_COPYLEFT, UNKNOWN})

_PERMISSIVE_TOKENS: Final[tuple[str, ...]] = (
    "MIT",
    "APACHE",
    "BSD",
    "ISC",
    "UNLICENSE",
    "ZLIB",
    "CC0",
    "0BSD",
    "PYTHON-2.0",
    "PSF",
    "BOOST",
    "BSL-1.0",
    "WTFPL",
    "OPENSSL",
    # Unicode-3.0 covers the ICU crates: permissive, attribution only.
    "UNICODE",
    # Blue Oak Model License, a plain-language permissive licence.
    "BLUEOAK",
    # Creative Commons attribution licences appear on data-only packages such
    # as browser-compatibility tables. Attribution, no reciprocity.
    "CC-BY-",
)
_WEAK_TOKENS: Final[tuple[str, ...]] = ("LGPL", "MPL", "EPL", "CDDL")
_STRONG_TOKENS: Final[tuple[str, ...]] = ("AGPL", "GPL")

#: This repository's own packages. They carry the project's dual licence by
#: design and are not third-party components to reconcile. Compared after
#: normalisation, because the same package is `aegis_rust` to Cargo and
#: `aegis-rust` to PyPI.
FIRST_PARTY: Final[frozenset[str]] = frozenset(
    {"aegis-latent-core", "aegis-latent-sdk", "aegis-rust", "aegis-audit-dashboard"}
)


def _normalise(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).strip().lower()


def _is_first_party(name: str) -> bool:
    return _normalise(name) in FIRST_PARTY


@dataclass(frozen=True, slots=True)
class LicensedComponent:
    name: str
    version: str
    ecosystem: str
    expression: str
    classification: str
    source: str
    shipped_with: str

    @property
    def blocking(self) -> bool:
        return self.classification in BLOCKING_CLASSES


def classify_expression(expression: str) -> str:
    """Classify an SPDX expression by its most permissive satisfiable branch.

    ``MIT OR GPL-3.0`` is permissive: a distributor may take the MIT branch.
    ``MIT AND GPL-3.0`` is strong copyleft: both apply. Splitting on ``OR``
    first and requiring every ``AND`` term is what encodes that difference,
    and getting it backwards is how a dual-licensed component gets reported as
    a blocker it is not.
    """

    text = expression.strip()
    if not text:
        return UNKNOWN
    upper = text.upper()

    branches = [b.strip(" ()") for b in re.split(r"\s+OR\s+", upper) if b.strip(" ()")]
    if not branches:
        return UNKNOWN

    branch_classes: list[str] = []
    for branch in branches:
        # `WITH <exception>` only ever grants additional permission on top of
        # the licence to its left — `Apache-2.0 WITH LLVM-exception` is no more
        # restrictive than Apache-2.0. Splitting on it the way `AND` is split
        # would classify the exception as an unrecognised licence and report a
        # permissive crate as unknown.
        branch = re.split(r"\s+WITH\s+", branch)[0]
        terms = [t.strip(" ()") for t in re.split(r"\s+AND\s+", branch) if t.strip(" ()")]
        term_classes = [_classify_term(term) for term in terms]
        if UNKNOWN in term_classes:
            branch_classes.append(UNKNOWN)
        elif STRONG_COPYLEFT in term_classes:
            branch_classes.append(STRONG_COPYLEFT)
        elif WEAK_COPYLEFT in term_classes:
            branch_classes.append(WEAK_COPYLEFT)
        else:
            branch_classes.append(PERMISSIVE)

    for preferred in (PERMISSIVE, WEAK_COPYLEFT, STRONG_COPYLEFT):
        if preferred in branch_classes:
            return preferred
    return UNKNOWN


def _classify_term(term: str) -> str:
    # LGPL contains "GPL" as a substring, so weak copyleft has to be tested
    # before strong or every LGPL component reports as a release blocker.
    if any(token in term for token in _WEAK_TOKENS):
        return WEAK_COPYLEFT
    if any(token in term for token in _STRONG_TOKENS):
        return STRONG_COPYLEFT
    if any(token in term for token in _PERMISSIVE_TOKENS):
        return PERMISSIVE
    return UNKNOWN


# ── readers ──────────────────────────────────────────────────────────────────


def _runtime_locked_names(root: Path) -> frozenset[str]:
    """The distributions ``requirements.lock`` pins, normalised.

    This is what separates a shipped dependency from build tooling, and it is
    read rather than curated: the hash-pinned lock is exactly the set installed
    into a released image, while the rest of a developer's environment (mypy,
    pytest, maturin, the audit tools) never travels with an artifact and so
    creates no distribution obligation.
    """

    path = root / "requirements.lock"
    if not path.is_file():
        return frozenset()
    names: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^([A-Za-z0-9._-]+)==", line.strip())
        if match:
            names.add(_normalise(match.group(1)))
    return frozenset(names)


def read_python_licenses(root: Path) -> list[LicensedComponent]:
    """Read licence metadata from the installed distributions."""

    import importlib.metadata as md

    shipped = _runtime_locked_names(root)
    components: list[LicensedComponent] = []
    for dist in md.distributions():
        metadata = dist.metadata
        name = metadata["Name"]
        if not name or _is_first_party(name):
            continue
        # `PackageMetadata` is subscriptable but its protocol declares no
        # `get`, so index access with a missing-key guard is what type-checks
        # across both the email.Message and the newer implementations.
        expression = str(metadata["License-Expression"] or metadata["License"] or "").strip()
        source = "dist-info License-Expression/License"
        if not expression or "\n" in expression or len(expression) > 120:
            # Some projects paste the whole licence text into `License`.
            # The trove classifiers are the reliable field when that happens.
            classifiers = [
                c.split("::")[-1].strip()
                for c in (metadata.get_all("Classifier") or [])
                if c.startswith("License ::")
            ]
            if classifiers:
                expression = " OR ".join(classifiers)
                source = "dist-info trove classifiers"
            elif expression:
                expression = expression.splitlines()[0][:120]
        components.append(
            LicensedComponent(
                name=name,
                version=metadata["Version"] or "",
                ecosystem="pypi",
                expression=expression,
                classification=classify_expression(expression),
                source=source,
                shipped_with=(
                    "gateway (Python runtime)"
                    if _normalise(name) in shipped
                    else "build-time only (not distributed)"
                ),
            )
        )
    return components


def _cargo_registry_src() -> list[Path]:
    home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))
    root = home / "registry" / "src"
    return sorted(p for p in root.glob("*") if p.is_dir()) if root.is_dir() else []


def read_rust_licenses(
    root: Path, lock_relative: str, shipped_with: str
) -> list[LicensedComponent]:
    """Read each locked crate's own ``license`` field from its unpacked source."""

    lock = root / lock_relative
    if not lock.is_file():
        return []
    with lock.open("rb") as handle:
        data = tomllib.load(handle)
    registries = _cargo_registry_src()
    components: list[LicensedComponent] = []
    for package in data.get("package", []):
        name = str(package.get("name", ""))
        version = str(package.get("version", ""))
        if not name or _is_first_party(name) or "source" not in package:
            continue  # no `source` means the workspace member itself
        expression, source = "", "crate source not unpacked in CARGO_HOME"
        for registry in registries:
            manifest = registry / f"{name}-{version}" / "Cargo.toml"
            if not manifest.is_file():
                continue
            with manifest.open("rb") as handle:
                crate = tomllib.load(handle)
            meta = crate.get("package", {})
            expression = str(meta.get("license", "") or "")
            if not expression and meta.get("license-file"):
                expression = f"see {meta['license-file']}"
            source = f"{manifest.parent.name}/Cargo.toml"
            break
        components.append(
            LicensedComponent(
                name=name,
                version=version,
                ecosystem="crates.io",
                expression=expression,
                classification=classify_expression(expression),
                source=source,
                shipped_with=shipped_with,
            )
        )
    return components


def read_npm_licenses(root: Path, lock_relative: str, shipped_with: str) -> list[LicensedComponent]:
    lock = root / lock_relative
    if not lock.is_file():
        return []
    data = json.loads(lock.read_text(encoding="utf-8"))
    components: list[LicensedComponent] = []
    for location, entry in sorted(data.get("packages", {}).items()):
        if not location or "node_modules/" not in location:
            continue
        if entry.get("link") or str(entry.get("resolved", "")).startswith("file:"):
            continue
        name = location.split("node_modules/")[-1]
        version = str(entry.get("version", ""))
        if not version or _is_first_party(name):
            continue
        expression = str(entry.get("license", "") or "")
        scope = shipped_with
        if entry.get("dev"):
            scope = "build-time only (not distributed)"
        elif entry.get("optional"):
            scope = f"{shipped_with}, optional platform binary"
        components.append(
            LicensedComponent(
                name=name,
                version=version,
                ecosystem="npm",
                expression=expression,
                classification=classify_expression(expression),
                source=f"{lock_relative} packages[].license",
                shipped_with=scope,
            )
        )
    return components


def collect(root: Path) -> list[LicensedComponent]:
    components: list[LicensedComponent] = []
    components += read_python_licenses(root)
    components += read_rust_licenses(root, "aegis_rust_v2/Cargo.lock", "gateway (native extension)")
    components += read_rust_licenses(
        root, "connectors/envoy-wasm/Cargo.lock", "Envoy WASM connector"
    )
    components += read_npm_licenses(root, "sdk/typescript/package-lock.json", "TypeScript SDK")
    components += read_npm_licenses(root, "dashboard/package-lock.json", "dashboard")
    seen: set[tuple[str, str, str]] = set()
    unique: list[LicensedComponent] = []
    for component in components:
        key = (component.ecosystem, component.name, component.version)
        if key in seen:
            continue
        seen.add(key)
        unique.append(component)
    return sorted(unique, key=lambda c: (c.ecosystem, c.name.lower(), c.version))


# ── reports ──────────────────────────────────────────────────────────────────


def _distributed(component: LicensedComponent) -> bool:
    return "not distributed" not in component.shipped_with


def render_audit(components: Sequence[LicensedComponent], observed: str) -> str:
    # Scoped to what actually travels with an artifact, so the report is a
    # function of the lock files rather than of whatever else happens to be
    # installed in the environment that generated it.
    distributed = [c for c in components if _distributed(c)]
    build_only = len(components) - len(distributed)

    counts = dict.fromkeys(CLASS_ORDER, 0)
    for component in distributed:
        counts[component.classification] += 1

    lines: list[str] = []
    lines.append("# License audit")
    lines.append("")
    lines.append(
        "Generated by `scripts/license/license_scan.py`. Do not edit by hand — rerun the script."
    )
    lines.append("")
    lines.append(f"- Distributed components inventoried: **{len(distributed)}**")
    lines.append(
        f"- Build-time-only components seen in the environment: **{build_only}** "
        "(not distributed, so they create no licence obligation on an artifact)"
    )
    lines.append(f"- Observed: **{observed}**")
    lines.append("")
    lines.append("## What this is, and is not")
    lines.append("")
    lines.append(
        "This is an inventory of the licence identifiers upstream projects declare, "
        "read from installed metadata and crate manifests. It is not legal advice, "
        "not a compliance certification, and not an opinion on whether any "
        "particular distribution is lawful. It does not verify that a declared "
        "identifier matches the licence text shipped in the package. Questions that "
        "turn on how a work is combined — linkage, aggregation, conveyance — are "
        "surfaced here and decided by counsel."
    )
    lines.append("")
    lines.append("## Totals")
    lines.append("")
    lines.append("| Classification | Count |")
    lines.append("| --- | --- |")
    for name in CLASS_ORDER:
        lines.append(f"| {name} | {counts[name]} |")
    lines.append("")

    lines.append("## Tier compatibility matrix")
    lines.append("")
    lines.append(
        "The two tiers fail differently. AGPLv3 is itself strong copyleft, so a "
        "copyleft dependency raises no reciprocity conflict there. The proprietary "
        "tier is where the same dependency becomes a distribution question."
    )
    lines.append("")
    lines.append("| Classification | AGPLv3 Community tier | Proprietary Enterprise tier |")
    lines.append("| --- | --- | --- |")
    lines.append(
        "| PERMISSIVE | compatible; attribution required | compatible; attribution required |"
    )
    lines.append(
        "| WEAK_COPYLEFT | compatible | compatible **only if** the component is "
        "dynamically linked or merely aggregated, and attribution plus a source "
        "offer accompany the artifact |"
    )
    lines.append(
        "| STRONG_COPYLEFT | compatible | **blocking** unless the component is not "
        "distributed with the proprietary artifact at all |"
    )
    lines.append(
        "| UNKNOWN | **blocking** — resolve before release | **blocking** — resolve before release |"
    )
    lines.append("")

    for name in CLASS_ORDER:
        members = [c for c in distributed if c.classification == name]
        lines.append(f"## {name} ({len(members)})")
        lines.append("")
        if not members:
            lines.append("None.")
            lines.append("")
            continue
        if name == PERMISSIVE:
            lines.append(
                "Listed in `LICENSE-THIRD-PARTY.md` with their attributions. Not "
                "reproduced here to keep the exception list readable."
            )
            lines.append("")
            continue
        lines.append(
            "| component | version | ecosystem | SPDX expression | shipped with | evidence |"
        )
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for component in members:
            lines.append(
                "| "
                + " | ".join(
                    cell.replace("|", "\\|")
                    for cell in (
                        component.name,
                        component.version,
                        component.ecosystem,
                        component.expression or "(none declared)",
                        component.shipped_with,
                        component.source,
                    )
                )
                + " |"
            )
        lines.append("")
    return "\n".join(lines)


def render_attributions(components: Sequence[LicensedComponent], observed: str) -> str:
    lines: list[str] = []
    lines.append("# Third-party notices")
    lines.append("")
    lines.append(
        "Generated by `scripts/license/license_scan.py`. Do not edit by hand — rerun the script."
    )
    lines.append("")
    lines.append(
        "Aegis Latent Core incorporates the third-party components below. Each is "
        "used under the licence its project declares; that declaration is reproduced "
        "here as read from the installed package metadata. The full licence text of "
        "each component ships inside that component's own distribution."
    )
    lines.append("")
    lines.append(f"Inventory observed: {observed}.")
    lines.append("")

    weak = [c for c in components if c.classification == WEAK_COPYLEFT and _distributed(c)]
    if weak:
        lines.append("## Weak-copyleft components and source offer")
        lines.append("")
        lines.append(
            "The components below are licensed under weak-copyleft terms (LGPL, MPL "
            "or EPL). They are used as separate, dynamically loaded or independently "
            "distributed modules; Aegis does not incorporate their source into its "
            "own object code. Their licences entitle a recipient to the component's "
            "source and to replace it with a modified version."
        )
        lines.append("")
        lines.append(
            "**Source offer.** For any component in this section, a recipient of an "
            "Aegis distribution may obtain the complete corresponding source of that "
            "component, and the information needed to relink or replace it, by "
            "written request to the address in `SUPPORT.md`. The same source is "
            "published by each upstream project at the registry coordinates given "
            "below."
        )
        lines.append("")
        lines.append("| component | version | ecosystem | licence | how it is used |")
        lines.append("| --- | --- | --- | --- | --- |")
        for component in weak:
            lines.append(
                "| "
                + " | ".join(
                    cell.replace("|", "\\|")
                    for cell in (
                        component.name,
                        component.version,
                        component.ecosystem,
                        component.expression,
                        component.shipped_with,
                    )
                )
                + " |"
            )
        lines.append("")

    # Only distributed components are listed. A notices file travels with an
    # artifact and describes what is inside it; including whatever happens to
    # be installed in the environment that generated it would make the file
    # depend on a developer's laptop, and it would list components a recipient
    # never received.
    distributed = [c for c in components if _distributed(c)]
    by_ecosystem: dict[str, list[LicensedComponent]] = {}
    for component in distributed:
        by_ecosystem.setdefault(component.ecosystem, []).append(component)

    lines.append("## Full component inventory")
    lines.append("")
    lines.append(
        f"{len(distributed)} components are distributed with an Aegis artifact. "
        f"A further {len(components) - len(distributed)} are build-time only "
        "(test runners, type checkers, packaging tools); they are inventoried in "
        "`docs/compliance/LICENSE_AUDIT.md` but create no distribution obligation "
        "and are not listed here."
    )
    lines.append("")
    for ecosystem in sorted(by_ecosystem):
        members = by_ecosystem[ecosystem]
        lines.append(f"### {ecosystem} ({len(members)})")
        lines.append("")
        lines.append("| component | version | licence | distributed with |")
        lines.append("| --- | --- | --- | --- |")
        for component in members:
            lines.append(
                "| "
                + " | ".join(
                    cell.replace("|", "\\|")
                    for cell in (
                        component.name,
                        component.version,
                        component.expression or "(none declared)",
                        component.shipped_with,
                    )
                )
                + " |"
            )
        lines.append("")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--root", default=str(REPO_ROOT))
    parser.add_argument("--write", action="store_true", help="write the audit and notices")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    components = collect(root)
    if not components:
        print("no license metadata found; nothing to audit", file=sys.stderr)
        return 2

    observed = datetime.now(UTC).replace(microsecond=0).isoformat()

    # Only a component that actually travels with an artifact can create a
    # distribution obligation. A build-time-only dependency cannot.
    blocking = [c for c in components if c.blocking and _distributed(c)]

    if args.json:
        print(
            json.dumps(
                {
                    "observed_at": observed,
                    "components": [
                        {
                            "name": c.name,
                            "version": c.version,
                            "ecosystem": c.ecosystem,
                            "expression": c.expression,
                            "classification": c.classification,
                            "shipped_with": c.shipped_with,
                            "source": c.source,
                        }
                        for c in components
                    ],
                    "blocking": len(blocking),
                },
                indent=2,
            )
        )
    elif args.write:
        audit = root / AUDIT_PATH
        audit.parent.mkdir(parents=True, exist_ok=True)
        audit.write_text(render_audit(components, observed) + "\n", encoding="utf-8")
        (root / ATTRIBUTION_PATH).write_text(
            render_attributions(components, observed) + "\n", encoding="utf-8"
        )
        print(f"wrote {AUDIT_PATH} and {ATTRIBUTION_PATH}: {len(components)} components")
    else:
        print(render_audit(components, observed))

    for component in blocking:
        print(
            f"{component.classification}: {component.ecosystem} {component.name} "
            f"{component.version} — {component.expression or 'no identifier'} "
            f"({component.shipped_with})",
            file=sys.stderr,
        )
    return 1 if blocking else 0


if __name__ == "__main__":
    sys.exit(main())

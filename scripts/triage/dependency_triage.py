#!/usr/bin/env python3
# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Deterministic dependency triage across the Python, Rust and npm trees.

Every dependency the repository actually locks is read from its lock file and
assigned to exactly one action bucket. The same inputs always produce the same
output: classification is a pure function of the lock files plus a pinned
advisory snapshot, so two runs on one commit agree, and a diff between runs is
a real change in the dependency set rather than scanner noise.

    python scripts/triage/dependency_triage.py --write
    python scripts/triage/dependency_triage.py --refresh-advisories   # network

Why the lock files rather than a scanner export
-----------------------------------------------

A hosted scanner reports what it believes is installed. A lock file *is* what
is installed, and it is the artifact CI resolves against. Reading the locks
means the triage cannot drift from the build, and it means this script is
useful on a machine with no scanner account.

A scanner export is still accepted, because triage has to survive the next
scan: ``--scan-export`` merges rows from a CSV or JSON export, matches them to
locked packages by (ecosystem, name), and reports any row that names a package
this repository does not lock. Rows that match are annotated onto the locked
package; rows that do not match are listed separately rather than dropped.

Buckets and precedence
----------------------

A package can satisfy several bucket predicates at once — a native crate can
also carry an advisory. Precedence is fixed and applied in this order, highest
first, so the assignment is single-valued and stable:

1. ``BUCKET-1 CONFIRMED_CVE``       an advisory affects the pinned version
2. ``BUCKET-3 LICENSE_BLOCKER``     copyleft reachable from a shipped artifact
3. ``BUCKET-2 DANGEROUS_SINK``      registered deserialization/exec primitive
4. ``BUCKET-4 NATIVE_INSTALL_SCRIPT`` build script or native code
5. ``BUCKET-5 MAINTENANCE_OVERRIDE``  minified or override-eligible
6. ``BUCKET-6 BENIGN_NOISE``        everything else

The order encodes what a release engineer must look at first. An advisory
outranks a license question because it is exploitable; a license question
outranks a sink because it blocks distribution outright rather than depending
on reachability.

What this does not establish
----------------------------

- It does not prove a dependency is free of vulnerabilities. It reports what
  the pinned advisory snapshot knows on the day it was taken.
- It does not read dependency source. ``BUCKET-2`` comes from the curated
  ``SINK_REGISTER`` below, and every entry carries the evidence it rests on,
  including where that evidence is an external claim this repository has not
  reproduced.
- It does not decide license compatibility. It flags copyleft for
  ``scripts/license/license_scan.py``, which owns that judgement.

Exit codes: 0 clean, 1 unresolved BUCKET-1 or BUCKET-3 findings, 2 the check
could not run.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import tomllib
import urllib.error
import urllib.request
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]

REPORT_PATH: Final[str] = "docs/security/DEPENDENCY_TRIAGE.md"
SNAPSHOT_PATH: Final[str] = "docs/security/advisory_snapshot.json"

OSV_QUERY_URL: Final[str] = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL: Final[str] = "https://api.osv.dev/v1/vulns/"
OSV_TIMEOUT_SECONDS: Final[float] = 60.0
#: OSV rejects oversized batches; the trees here are small enough that this
#: only matters for the npm locks.
OSV_BATCH_SIZE: Final[int] = 250

BUCKET_CONFIRMED_CVE: Final[str] = "BUCKET-1 CONFIRMED_CVE"
BUCKET_DANGEROUS_SINK: Final[str] = "BUCKET-2 DANGEROUS_SINK"
BUCKET_LICENSE_BLOCKER: Final[str] = "BUCKET-3 LICENSE_BLOCKER"
BUCKET_NATIVE_INSTALL: Final[str] = "BUCKET-4 NATIVE_INSTALL_SCRIPT"
BUCKET_MAINTENANCE: Final[str] = "BUCKET-5 MAINTENANCE_OVERRIDE"
BUCKET_BENIGN: Final[str] = "BUCKET-6 BENIGN_NOISE"

#: Highest precedence first. Used both to assign and to order the report.
BUCKET_ORDER: Final[tuple[str, ...]] = (
    BUCKET_CONFIRMED_CVE,
    BUCKET_LICENSE_BLOCKER,
    BUCKET_DANGEROUS_SINK,
    BUCKET_NATIVE_INSTALL,
    BUCKET_MAINTENANCE,
    BUCKET_BENIGN,
)

#: Buckets that fail the gate while unresolved.
BLOCKING_BUCKETS: Final[frozenset[str]] = frozenset({BUCKET_CONFIRMED_CVE, BUCKET_LICENSE_BLOCKER})

#: SPDX identifiers that make a component undistributable inside a proprietary
#: artifact without further analysis. Weak copyleft is handled separately: it
#: is allowed when dynamically linked and attributed, which is a question about
#: linkage this script cannot answer, so it is surfaced rather than judged.
STRONG_COPYLEFT: Final[frozenset[str]] = frozenset(
    {"GPL-2.0", "GPL-3.0", "AGPL-3.0", "GPL-2.0-only", "GPL-3.0-only", "AGPL-3.0-only"}
)
WEAK_COPYLEFT_PREFIXES: Final[tuple[str, ...]] = ("LGPL", "MPL", "EPL")

#: npm packages shipped pre-minified. Not a defect; recorded so a reviewer who
#: sees the alert can close it against this list instead of re-deriving it.
KNOWN_MINIFIED_NPM: Final[frozenset[str]] = frozenset({"undici", "vscode-uri"})


#: Words an advisory uses when it is reporting a maintenance state rather than
#: an exploitable defect. RUSTSEC files these as `informational: unmaintained`,
#: but OSV does not always carry that field through, so the summary is the
#: signal that survives the export.
_UNMAINTAINED_MARKERS: Final[tuple[str, ...]] = (
    "unmaintained",
    "no longer maintained",
    "is deprecated",
    "archived",
)


@dataclass(frozen=True, slots=True)
class SinkRegistration:
    """A registered dangerous primitive, with the evidence behind the entry."""

    package: str
    ecosystem: str
    primitive: str
    disposition: str
    evidence: str


@dataclass(slots=True)
class Component:
    """One locked dependency, before and after classification."""

    name: str
    version: str
    ecosystem: str
    scope: str
    manifest: str
    licence: str = ""
    native: bool = False
    install_script: bool = False
    dev_only: bool = False
    optional: bool = False
    advisories: list[str] = field(default_factory=list)
    scan_rows: list[str] = field(default_factory=list)
    bucket: str = ""
    action: str = ""
    evidence: str = ""

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.ecosystem, self.name, self.version)

    @property
    def direct_or_transitive(self) -> str:
        return "direct" if self.scope.startswith("direct") else "transitive"


# ── curated sink register ────────────────────────────────────────────────────

#: Packages carrying deserialization, eval, exec or remote-fetch primitives.
#:
#: ``evidence`` states what this repository actually observed. Where an entry
#: rests on a third-party scanner's reading of upstream source that has not
#: been reproduced here, it says so; a reviewer must not read those rows as
#: independently confirmed.
SINK_REGISTER: Final[tuple[SinkRegistration, ...]] = (
    SinkRegistration(
        package="torch",
        ecosystem="pypi",
        primitive="pickle.loads / exec / remote script fetch",
        disposition="EXCLUDE-FROM-CORE",
        evidence=(
            "pyproject.toml declares torch only under the gpu, vllm and hf extras; "
            "it is absent from requirements.lock, so it is not in the core runtime graph"
        ),
    ),
    SinkRegistration(
        package="transformers",
        ecosystem="pypi",
        primitive="remote code execution via trust_remote_code",
        disposition="EXCLUDE-FROM-CORE",
        evidence=(
            "pyproject.toml declares transformers only under the hf extra; "
            "absent from requirements.lock"
        ),
    ),
    SinkRegistration(
        package="vllm",
        ecosystem="pypi",
        primitive="trust_remote_code / multiproc RPC",
        disposition="EXCLUDE-FROM-CORE",
        evidence="pyproject.toml declares vllm only under the vllm extra; absent from requirements.lock",
    ),
    SinkRegistration(
        package="numpy",
        ecosystem="pypi",
        primitive="pickle in the vendored regeneration checker",
        disposition="ISOLATE",
        evidence=(
            "core runtime dependency; Aegis never unpickles numpy arrays from request "
            "data — grep for numpy.load across aegis/ returns no allow_pickle call site"
        ),
    ),
    SinkRegistration(
        package="cffi",
        ecosystem="pypi",
        primitive="FFI binding loader",
        disposition="ISOLATE",
        evidence=(
            "transitive under cryptography; bindings resolve to the wheel-bundled "
            "OpenSSL, and no Aegis code calls cffi.dlopen with a runtime-supplied path"
        ),
    ),
    SinkRegistration(
        package="pyyaml",
        ecosystem="pypi",
        primitive="FullConstructor / UnsafeConstructor",
        disposition="ISOLATE",
        evidence=(
            "every parse site in the tree already uses safe_load or safe_load_all; "
            "tests/security/test_yaml_safe_loading.py fails the build if that changes"
        ),
    ),
    SinkRegistration(
        package="mypy",
        ecosystem="pypi",
        primitive="dmypy --options-data pickle",
        disposition="ISOLATE",
        evidence="development dependency only; never installed in a shipped artifact",
    ),
    SinkRegistration(
        package="rich",
        ecosystem="pypi",
        primitive="Style.meta pickle and OSC8 terminal sequences",
        disposition="ISOLATE",
        evidence="development/CLI output dependency; not reachable from the gateway request path",
    ),
    SinkRegistration(
        package="pillow",
        ecosystem="pypi",
        primitive="vendored download-and-extract build script",
        disposition="ISOLATE",
        evidence="not present in requirements.lock; reaches the tree only through optional tooling",
    ),
    SinkRegistration(
        package="msgspec",
        ecosystem="pypi",
        primitive="exec in the upstream test suite",
        disposition="ISOLATE",
        evidence="test-suite-only construct upstream; not present in requirements.lock",
    ),
)

SINK_BY_KEY: Final[dict[tuple[str, str], SinkRegistration]] = {
    (entry.ecosystem, entry.package): entry for entry in SINK_REGISTER
}


# ── lock-file readers ────────────────────────────────────────────────────────


def _read_pyproject_dependency_names(root: Path) -> tuple[frozenset[str], frozenset[str]]:
    """Return (core direct names, extra-only names) normalised to lowercase."""

    path = root / "pyproject.toml"
    if not path.is_file():
        return frozenset(), frozenset()
    with path.open("rb") as handle:
        data = tomllib.load(handle)
    project = data.get("project", {})

    def names(specs: Iterable[str]) -> set[str]:
        out: set[str] = set()
        for spec in specs:
            match = re.match(r"^\s*([A-Za-z0-9._-]+)", spec)
            if match:
                out.add(_normalise_pypi(match.group(1)))
        return out

    core = names(project.get("dependencies", []) or [])
    extras: set[str] = set()
    for group in (project.get("optional-dependencies", {}) or {}).values():
        extras |= names(group)
    return frozenset(core), frozenset(extras - core)


def _normalise_pypi(name: str) -> str:
    """PyPI treats ``-``, ``_`` and ``.`` as equivalent and is case-insensitive."""

    return re.sub(r"[-_.]+", "-", name).lower()


def read_requirements_lock(root: Path) -> list[Component]:
    """Parse the hash-pinned pip lock. Only ``name==version`` lines matter here."""

    path = root / "requirements.lock"
    if not path.is_file():
        return []
    core, extras = _read_pyproject_dependency_names(root)
    components: list[Component] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^([A-Za-z0-9._-]+)==([^\s\\;]+)", line.strip())
        if not match:
            continue
        raw_name, version = match.group(1), match.group(2)
        normalised = _normalise_pypi(raw_name)
        if normalised in core:
            scope = "direct (core runtime)"
        elif normalised in extras:
            scope = "direct (optional extra)"
        else:
            scope = "transitive"
        components.append(
            Component(
                name=raw_name,
                version=version,
                ecosystem="pypi",
                scope=scope,
                manifest="requirements.lock",
            )
        )
    return components


def read_cargo_lock(root: Path, relative: str) -> list[Component]:
    """Parse a Cargo lock. The workspace member itself is not a dependency."""

    path = root / relative
    if not path.is_file():
        return []
    with path.open("rb") as handle:
        data = tomllib.load(handle)
    manifest_dir = Path(relative).parent
    local_names = _local_crate_names(root / manifest_dir)
    components: list[Component] = []
    for package in data.get("package", []):
        name = str(package.get("name", ""))
        version = str(package.get("version", ""))
        if not name or name in local_names:
            continue
        components.append(
            Component(
                name=name,
                version=version,
                ecosystem="crates.io",
                scope="transitive",
                manifest=relative,
                native=_is_native_crate(name),
            )
        )
    _mark_direct_crates(root / manifest_dir / "Cargo.toml", components)
    return components


def _local_crate_names(manifest_dir: Path) -> frozenset[str]:
    path = manifest_dir / "Cargo.toml"
    if not path.is_file():
        return frozenset()
    with path.open("rb") as handle:
        data = tomllib.load(handle)
    name = data.get("package", {}).get("name")
    return frozenset({str(name)}) if name else frozenset()


def _mark_direct_crates(manifest: Path, components: Sequence[Component]) -> None:
    if not manifest.is_file():
        return
    with manifest.open("rb") as handle:
        data = tomllib.load(handle)
    direct: set[str] = set()
    for table in ("dependencies", "build-dependencies", "dev-dependencies"):
        direct |= set((data.get(table, {}) or {}).keys())
    for component in components:
        if component.name in direct:
            component.scope = "direct"


#: Crates whose published source carries a ``build.rs`` or compiles native code.
#: Matched by prefix so the ``-sys`` and ``-src`` families are covered without
#: enumerating every platform variant.
_NATIVE_CRATE_PREFIXES: Final[tuple[str, ...]] = (
    "openssl",
    "native-tls",
    "ring",
    "libc",
    "cc",
    "jni",
    "sentencepiece",
    "wasm-bindgen",
    "js-sys",
    "proc-macro2",
)
_NATIVE_CRATE_NAMES: Final[frozenset[str]] = frozenset(
    {
        "serde",
        "serde_derive",
        "getrandom",
        "thiserror",
        "parking_lot_core",
        "proxy-wasm",
        "icu_normalizer_data",
        "rustls",
        "typenum",
        "generic-array",
        "pyo3",
        "pyo3-build-config",
        "pyo3-ffi",
        "pyo3-macros",
        "target-lexicon",
        "syn",
        "quote",
        "anyhow",
        "semver",
        "num-traits",
        "crossbeam-utils",
        "memoffset",
        "rayon-core",
        "slab",
        "lock_api",
    }
)


def _is_native_crate(name: str) -> bool:
    if name in _NATIVE_CRATE_NAMES:
        return True
    return name.endswith(("-sys", "-src")) or name.startswith(_NATIVE_CRATE_PREFIXES)


def read_npm_lock(root: Path, relative: str) -> list[Component]:
    """Parse an npm lockfile v3. ``packages`` carries license and flags inline."""

    path = root / relative
    if not path.is_file():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    components: list[Component] = []
    for location, entry in sorted(data.get("packages", {}).items()):
        if not location:
            continue  # the root project itself
        # npm records a `file:` dependency twice: the link under node_modules
        # and the link *target* keyed by its relative path. Only the former is
        # an installed package; the latter is this repository's own source.
        if "node_modules/" not in location:
            continue
        name = location.split("node_modules/")[-1]
        version = str(entry.get("version", ""))
        if not version:
            continue  # a link: or workspace entry carries no version
        # A `file:` link is this repository's own package resolved through the
        # dashboard's node_modules. It is first-party source under the repo's
        # own dual licence, not a third-party component to triage.
        if entry.get("link") or str(entry.get("resolved", "")).startswith("file:"):
            continue
        # Depth 1 under node_modules with no nesting is a top-level install,
        # which for these projects means it is named in package.json.
        depth = location.count("node_modules/")
        components.append(
            Component(
                name=name,
                version=version,
                ecosystem="npm",
                scope="direct" if depth == 1 else "transitive",
                manifest=relative,
                licence=str(entry.get("license", "") or ""),
                install_script=bool(entry.get("hasInstallScript", False)),
                dev_only=bool(entry.get("dev", False)),
                optional=bool(entry.get("optional", False)),
                native=bool(entry.get("hasInstallScript", False)) or "@img/" in name,
            )
        )
    _mark_direct_npm(root / Path(relative).parent / "package.json", components)
    return components


def _mark_direct_npm(manifest: Path, components: Sequence[Component]) -> None:
    if not manifest.is_file():
        return
    data = json.loads(manifest.read_text(encoding="utf-8"))
    runtime = set((data.get("dependencies", {}) or {}).keys())
    dev = set((data.get("devDependencies", {}) or {}).keys())
    for component in components:
        if component.name in runtime:
            component.scope = "direct (runtime)"
        elif component.name in dev:
            component.scope = "direct (dev)"
            component.dev_only = True
        elif component.scope == "direct":
            component.scope = "transitive"


# ── advisory snapshot ────────────────────────────────────────────────────────

#: OSV ecosystem names differ from the ones used for reporting here.
_OSV_ECOSYSTEM: Final[dict[str, str]] = {
    "pypi": "PyPI",
    "crates.io": "crates.io",
    "npm": "npm",
}


def refresh_advisories(components: Sequence[Component], root: Path) -> dict[str, Any]:
    """Query OSV for every locked component and write a pinned snapshot.

    The snapshot is what classification reads. Pinning it keeps the triage
    reproducible offline and records the day the advisory set was observed,
    which is the only honest way to state "no known advisory".
    """

    queries = [
        {
            "package": {"name": c.name, "ecosystem": _OSV_ECOSYSTEM[c.ecosystem]},
            "version": c.version,
        }
        for c in components
    ]
    findings: dict[str, list[str]] = {}
    for start in range(0, len(queries), OSV_BATCH_SIZE):
        chunk = queries[start : start + OSV_BATCH_SIZE]
        payload = json.dumps({"queries": chunk}).encode("utf-8")
        request = urllib.request.Request(  # noqa: S310 - fixed https OSV endpoint
            OSV_QUERY_URL,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=OSV_TIMEOUT_SECONDS) as response:  # noqa: S310
            body = json.loads(response.read().decode("utf-8"))
        for component, result in zip(
            components[start : start + OSV_BATCH_SIZE], body.get("results", []), strict=False
        ):
            ids = sorted(v["id"] for v in result.get("vulns", []) if "id" in v)
            if ids:
                findings["|".join(component.key)] = ids

    # Fetch each advisory once. Whether a fix exists is what decides between
    # "bump now" and "no version to bump to", so it has to be read, not assumed.
    details: dict[str, dict[str, Any]] = {}
    for advisory_id in sorted({i for ids in findings.values() for i in ids}):
        with urllib.request.urlopen(  # noqa: S310 - fixed https OSV endpoint
            OSV_VULN_URL + advisory_id, timeout=OSV_TIMEOUT_SECONDS
        ) as response:
            record = json.loads(response.read().decode("utf-8"))
        fixed: list[str] = []
        for affected in record.get("affected", []):
            for date_range in affected.get("ranges", []):
                fixed += [e["fixed"] for e in date_range.get("events", []) if "fixed" in e]
        details[advisory_id] = {
            "summary": record.get("summary", ""),
            "fixed_versions": sorted(set(fixed)),
            "severity": record.get("severity") or [],
            "informational": (record.get("database_specific") or {}).get("informational"),
        }

    snapshot: dict[str, Any] = {
        "format": "aegis-advisory-snapshot-v2",
        "source": "https://api.osv.dev/v1/querybatch",
        "observed_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "components_queried": len(queries),
        "findings": findings,
        "advisories": details,
        "boundary": (
            "Absence of a finding means OSV held no advisory for that exact pinned "
            "version on the observed_at date. It is not a statement that the "
            "component is free of vulnerabilities."
        ),
    }
    destination = root / SNAPSHOT_PATH
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return snapshot


def load_advisories(root: Path) -> dict[str, Any]:
    path = root / SNAPSHOT_PATH
    if not path.is_file():
        return {"findings": {}, "observed_at": "never", "components_queried": 0}
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return data


# ── scanner export ingest ────────────────────────────────────────────────────


def read_scan_export(path: Path) -> list[dict[str, str]]:
    """Read a scanner export. CSV and JSON-array exports are both accepted."""

    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        payload = json.loads(text)
        rows = payload if isinstance(payload, list) else payload.get("alerts", [])
        return [{str(k): str(v) for k, v in row.items()} for row in rows]
    return [dict(row) for row in csv.DictReader(text.splitlines())]


def _scan_row_name(row: dict[str, str]) -> str:
    for key in ("package", "Package", "name", "Name", "component"):
        if row.get(key):
            return row[key].strip()
    return ""


def _scan_row_summary(row: dict[str, str]) -> str:
    for key in ("alert_type", "Alert", "type", "title", "summary", "Title"):
        if row.get(key):
            return row[key].strip()
    return "unlabelled alert row"


def merge_scan_export(
    components: Sequence[Component], rows: Sequence[dict[str, str]]
) -> list[dict[str, str]]:
    """Annotate matching components; return the rows that matched nothing."""

    by_name: dict[str, list[Component]] = {}
    for component in components:
        by_name.setdefault(component.name.lower(), []).append(component)
        if component.ecosystem == "pypi":
            by_name.setdefault(_normalise_pypi(component.name), []).append(component)
    unmatched: list[dict[str, str]] = []
    for row in rows:
        name = _scan_row_name(row)
        targets = by_name.get(name.lower()) or by_name.get(_normalise_pypi(name)) if name else None
        if not targets:
            unmatched.append(row)
            continue
        for component in targets:
            component.scan_rows.append(_scan_row_summary(row))
    return unmatched


# ── classification ───────────────────────────────────────────────────────────


def _is_unmaintained_notice(record: dict[str, Any]) -> bool:
    """An advisory with no fixed version that reports a maintenance state.

    The distinction matters because the two demand different work. A defect
    with a fixed version is a bump and a regression test. An unmaintained
    notice has no version to bump to: it is a migration, which belongs on a
    roadmap with a risk entry, not in a release-blocking CVE queue. Filing it
    as a CVE would make the gate unsatisfiable and teach a reader to ignore it.
    """

    if record.get("fixed_versions"):
        return False
    if str(record.get("informational") or "").lower() in {"unmaintained", "notice"}:
        return True
    summary = str(record.get("summary", "")).lower()
    return any(marker in summary for marker in _UNMAINTAINED_MARKERS)


def classify(
    component: Component,
    advisories: dict[str, list[str]],
    records: dict[str, dict[str, Any]],
) -> None:
    """Assign exactly one bucket, applying ``BUCKET_ORDER`` precedence."""

    found = advisories.get("|".join(component.key), [])
    component.advisories = list(found)
    if found:
        actionable = [a for a in found if not _is_unmaintained_notice(records.get(a, {}))]
        if actionable:
            fixes = sorted(
                {v for a in actionable for v in records.get(a, {}).get("fixed_versions", [])}
            )
            target = f" (fixed in {', '.join(fixes)})" if fixes else ""
            component.bucket = BUCKET_CONFIRMED_CVE
            component.action = f"upgrade past the fixed version; regression-test{target}"
            component.evidence = f"advisory snapshot: {', '.join(actionable)}"
            return
        summaries = "; ".join(str(records.get(a, {}).get("summary", a)).strip() for a in found)
        component.bucket = BUCKET_MAINTENANCE
        component.action = "no fixed version exists: track a migration and record the residual risk"
        component.evidence = f"{', '.join(found)} — {summaries}"
        return

    licence = component.licence.strip()
    if licence and not component.dev_only:
        tokens = {token.strip("() ") for token in re.split(r"\s+(?:AND|OR|WITH)\s+", licence)}
        if tokens & STRONG_COPYLEFT:
            component.bucket = BUCKET_LICENSE_BLOCKER
            component.action = "quarantine: must not be a hard dependency of the proprietary core"
            component.evidence = f"lock file declares {licence}"
            return
        if any(token.startswith(WEAK_COPYLEFT_PREFIXES) for token in tokens):
            component.bucket = BUCKET_LICENSE_BLOCKER
            component.action = (
                "weak copyleft: allowed only if dynamically linked and attributed; "
                "see LICENSE-THIRD-PARTY.md"
            )
            component.evidence = f"lock file declares {licence}" + (
                " (optional platform binary)" if component.optional else ""
            )
            return

    sink = SINK_BY_KEY.get((component.ecosystem, _normalise_pypi(component.name)))
    if sink is None and component.ecosystem == "pypi":
        sink = SINK_BY_KEY.get((component.ecosystem, component.name.lower()))
    if sink is not None:
        component.bucket = BUCKET_DANGEROUS_SINK
        component.action = f"{sink.disposition}: {sink.primitive}"
        component.evidence = sink.evidence
        return

    if component.native or component.install_script:
        component.bucket = BUCKET_NATIVE_INSTALL
        component.action = "attest, do not remove; see docs/security/BUILD_SCRIPT_ATTESTATION.md"
        component.evidence = (
            "npm lock records hasInstallScript"
            if component.install_script
            else "native or build-script crate"
        )
        return

    if component.ecosystem == "npm" and component.name in KNOWN_MINIFIED_NPM:
        component.bucket = BUCKET_MAINTENANCE
        component.action = "retain: standard transitive dependency shipped pre-minified"
        component.evidence = "minified upstream distribution; no override applied"
        return

    component.bucket = BUCKET_BENIGN
    component.action = "document and close"
    if component.dev_only:
        # A copyleft build tool is not a distribution question: it is never
        # linked into, or shipped with, the artifact. Recording the licence
        # anyway means the next reviewer does not have to re-derive that.
        component.evidence = "development/build-only dependency" + (
            f", declares {licence}" if licence else ""
        )
    else:
        component.evidence = "no advisory, no copyleft, no registered sink"


# ── report ───────────────────────────────────────────────────────────────────


def _escape(cell: str) -> str:
    return cell.replace("|", "\\|")


def render_report(
    components: Sequence[Component],
    snapshot: dict[str, Any],
    unmatched_rows: Sequence[dict[str, str]],
    scan_source: str,
) -> str:
    counts = dict.fromkeys(BUCKET_ORDER, 0)
    for component in components:
        counts[component.bucket] += 1

    lines: list[str] = []
    lines.append("# Dependency triage")
    lines.append("")
    lines.append(
        "Generated by `scripts/triage/dependency_triage.py`. Do not edit by hand — "
        "rerun the script."
    )
    lines.append("")
    lines.append(
        f"- Components classified: **{len(components)}** across "
        f"{len({c.manifest for c in components})} lock files"
    )
    lines.append(f"- Advisory snapshot observed: **{snapshot.get('observed_at', 'never')}**")
    lines.append(f"- Scanner export ingested: **{scan_source}**")
    lines.append("")
    lines.append("## Bucket totals")
    lines.append("")
    lines.append("| Bucket | Count |")
    lines.append("| --- | --- |")
    for bucket in BUCKET_ORDER:
        lines.append(f"| {bucket} | {counts[bucket]} |")
    lines.append("")

    lines.append("## Boundary")
    lines.append("")
    lines.append(
        "Absence of an advisory means the pinned snapshot held none for that exact "
        "version on the date above. It is not a claim that a component is free of "
        "vulnerabilities, and it is not an external assurance of any kind. "
        "`BUCKET-2` rows rest on the curated register in this script; each carries "
        "the evidence it is based on, and rows resting on an unreproduced external "
        "claim say so."
    )
    lines.append("")

    for bucket in BUCKET_ORDER:
        members = sorted(
            (c for c in components if c.bucket == bucket),
            key=lambda c: (c.ecosystem, c.name.lower(), c.version),
        )
        lines.append(f"## {bucket} ({len(members)})")
        lines.append("")
        if not members:
            lines.append("No components in this bucket.")
            lines.append("")
            continue
        lines.append(
            "| package | version | ecosystem | direct/transitive | alert_type | "
            "severity | bucket | action | evidence |"
        )
        lines.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
        for component in members:
            alert_type = "; ".join(component.scan_rows) if component.scan_rows else "—"
            if component.advisories:
                alert_type = "; ".join(component.advisories)
            severity = "blocking" if bucket in BLOCKING_BUCKETS else "informational"
            lines.append(
                "| "
                + " | ".join(
                    _escape(cell)
                    for cell in (
                        component.name,
                        component.version,
                        component.ecosystem,
                        component.direct_or_transitive,
                        alert_type,
                        severity,
                        bucket.split(" ", 1)[0],
                        component.action,
                        component.evidence,
                    )
                )
                + " |"
            )
        lines.append("")

    lines.append("## Scanner rows matching no locked component")
    lines.append("")
    if not unmatched_rows:
        lines.append(
            "None. Either no export was supplied, or every row matched a locked "
            "component and is classified above."
        )
    else:
        lines.append(
            "These rows name packages this repository does not lock. They are listed "
            "rather than dropped so no row is silently lost."
        )
        lines.append("")
        lines.append("| row | reason |")
        lines.append("| --- | --- |")
        for row in unmatched_rows:
            lines.append(
                f"| {_escape(_scan_row_name(row) or '(unnamed)')} — "
                f"{_escape(_scan_row_summary(row))} | not present in any lock file |"
            )
    lines.append("")
    return "\n".join(lines)


# ── entry point ──────────────────────────────────────────────────────────────


def collect_components(root: Path) -> list[Component]:
    components: list[Component] = []
    components += read_requirements_lock(root)
    components += read_cargo_lock(root, "aegis_rust_v2/Cargo.lock")
    components += read_cargo_lock(root, "connectors/envoy-wasm/Cargo.lock")
    components += read_npm_lock(root, "sdk/typescript/package-lock.json")
    components += read_npm_lock(root, "dashboard/package-lock.json")
    # One component may appear in two locks at the same version; keep the first
    # so a package is classified exactly once, as the report promises.
    seen: set[tuple[str, str, str]] = set()
    unique: list[Component] = []
    for component in components:
        if component.key in seen:
            continue
        seen.add(component.key)
        unique.append(component)
    return unique


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--root", default=str(REPO_ROOT), help="repository root")
    parser.add_argument("--write", action="store_true", help=f"write {REPORT_PATH}")
    parser.add_argument(
        "--refresh-advisories",
        action="store_true",
        help="query OSV and rewrite the pinned advisory snapshot (requires network)",
    )
    parser.add_argument(
        "--scan-export",
        default="",
        help="optional scanner export (.csv or .json) to merge into the triage",
    )
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    components = collect_components(root)
    if not components:
        print("no lock files found; nothing to triage", file=sys.stderr)
        return 2

    if args.refresh_advisories:
        try:
            snapshot = refresh_advisories(components, root)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            print(f"[BLOCKED: OSV query failed: {exc}]", file=sys.stderr)
            return 2
    else:
        snapshot = load_advisories(root)

    unmatched: list[dict[str, str]] = []
    scan_source = "none (no export supplied)"
    if args.scan_export:
        export_path = Path(args.scan_export)
        if not export_path.is_file():
            print(f"[BLOCKED: scan export not found: {export_path}]", file=sys.stderr)
            return 2
        rows = read_scan_export(export_path)
        unmatched = merge_scan_export(components, rows)
        scan_source = f"{export_path.name} ({len(rows)} rows, {len(unmatched)} unmatched)"

    findings: dict[str, list[str]] = snapshot.get("findings", {})
    records: dict[str, dict[str, Any]] = snapshot.get("advisories", {})
    for component in components:
        classify(component, findings, records)

    blocking = [c for c in components if c.bucket in BLOCKING_BUCKETS]

    if args.json:
        print(
            json.dumps(
                {
                    "observed_at": snapshot.get("observed_at"),
                    "components": [
                        {
                            "name": c.name,
                            "version": c.version,
                            "ecosystem": c.ecosystem,
                            "scope": c.scope,
                            "bucket": c.bucket,
                            "action": c.action,
                            "evidence": c.evidence,
                            "advisories": c.advisories,
                        }
                        for c in sorted(components, key=lambda c: (c.ecosystem, c.name, c.version))
                    ],
                    "unmatched_scan_rows": len(unmatched),
                },
                indent=2,
            )
        )
    else:
        report = render_report(components, snapshot, unmatched, scan_source)
        if args.write:
            destination = root / REPORT_PATH
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(report + "\n", encoding="utf-8")
            print(f"wrote {REPORT_PATH}: {len(components)} components classified")
        else:
            print(report)

    for component in blocking:
        print(
            f"{component.bucket}: {component.ecosystem} {component.name} "
            f"{component.version} — {component.action}",
            file=sys.stderr,
        )
    return 1 if blocking else 0


if __name__ == "__main__":
    sys.exit(main())

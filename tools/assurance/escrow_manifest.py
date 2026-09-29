# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""List what an escrow deposit of the repository at a ref would contain, and check a restore.

    python tools/assurance/escrow_manifest.py build [--ref v5.0.1] [--out manifest.json]
    python tools/assurance/escrow_manifest.py verify MANIFEST.json RESTORED_DIR

``build`` reads the tracked files at ``--ref`` and records each path, size and SHA-256,
one digest over the whole list, and the repository's own categories from
``docs/MAINTAINER_HANDBOOK.md`` §7. It refuses, with exit 2, if a tracked path looks like
key material or a secret: the licence-signing private key is never deposited.
``verify`` re-hashes a directory restored from the deposit and reports any missing,
extra or altered file, which is the mechanical part of the agent's verification exercise.

This is not a deposit and involves no escrow agent. It writes only the manifest.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DENY = re.compile(
    r"(^|/)(\.env(\..*)?|.*\.(pem|key|p12|pfx|jks)|id_(rsa|ed25519)|.*private.*key.*|vendor-keys/.*|"
    r"aegis_license_root\.key)$",
    re.IGNORECASE,
)
CATEGORIES: tuple[tuple[str, str], ...] = (
    (".github/workflows/", "build pipeline definitions"),
    ("deploy/", "deployment manifests and charts"),
    ("docs/", "architecture, operations and other documentation"),
    ("aegis/", "source: gateway"),
    ("aegis_server/", "source: server"),
    ("aegis_rust_v2/", "source: Rust core"),
    ("sdk/", "source: SDKs"),
    ("dashboard/", "source: dashboard"),
    ("scripts/", "build and verification scripts"),
    ("tests/", "tests"),
)


def _git(*args: str) -> bytes:
    return subprocess.run(  # noqa: S603  # nosec B603 B607 - fixed git argv, shell=False
        ["git", *args], cwd=ROOT, check=True, capture_output=True
    ).stdout


ALLOWED_TEMPLATE = re.compile(r"\.(example|sample|template)$", re.IGNORECASE)


def _category(path: str) -> str:
    for prefix, name in CATEGORIES:
        if path.startswith(prefix):
            return name
    return "other tracked files"


def build(ref: str) -> dict[str, object]:
    commit = _git("rev-parse", f"{ref}^{{commit}}").decode().strip()
    listing = _git("ls-tree", "-r", "-z", "--long", commit).split(b"\0")
    files: list[dict[str, object]] = []
    denied: list[str] = []
    for entry in filter(None, listing):
        meta, path_bytes = entry.split(b"\t", 1)
        mode, kind, blob, _size = meta.split()
        path = path_bytes.decode()
        if kind != b"blob" or mode == b"160000":
            continue
        if DENY.search(path) and not ALLOWED_TEMPLATE.search(path):
            denied.append(path)
            continue
        data = _git("cat-file", "blob", blob.decode())
        files.append(
            {
                "path": path,
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "category": _category(path),
            }
        )
    if denied:
        raise SystemExit("refusing: tracked paths look like key material: " + ", ".join(denied))
    files.sort(key=lambda f: str(f["path"]))
    digest = hashlib.sha256(
        "".join(f"{f['sha256']}  {f['path']}\n" for f in files).encode()
    ).hexdigest()
    categories: dict[str, int] = {}
    for f in files:
        categories[str(f["category"])] = categories.get(str(f["category"]), 0) + 1
    return {
        "ref": ref,
        "commit": commit,
        "file_count": len(files),
        "total_bytes": sum(int(str(f["bytes"])) for f in files),
        "tree_sha256": digest,
        "categories": dict(sorted(categories.items())),
        "not_in_this_manifest": [
            "vendored Python wheels (scripts/vendor_wheels.sh)",
            "base images exported with docker save",
            "the release SHA256SUMS, SBOM and GHCR digests as read back",
            "the access list and the licence-key custody procedure",
            "the licence-signing private key: never deposited",
        ],
        "files": files,
    }


def verify(manifest_path: Path, directory: Path) -> int:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected = {f["path"]: f["sha256"] for f in manifest["files"]}
    problems: list[str] = []
    seen: set[str] = set()
    for path in sorted(p for p in directory.rglob("*") if p.is_file()):
        rel = path.relative_to(directory).as_posix()
        if rel.startswith(".git/"):
            continue
        seen.add(rel)
        if rel not in expected:
            problems.append(f"extra   {rel}")
        elif hashlib.sha256(path.read_bytes()).hexdigest() != expected[rel]:
            problems.append(f"altered {rel}")
    problems += [f"missing {rel}" for rel in sorted(set(expected) - seen)]
    for line in problems[:50]:
        print(line)
    print(f"escrow_manifest verify: {'FAIL' if problems else 'PASS'} ({len(problems)} problems)")
    return 1 if problems else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    b = sub.add_parser("build")
    b.add_argument("--ref", default="HEAD")
    b.add_argument("--out", type=Path)
    v = sub.add_parser("verify")
    v.add_argument("manifest", type=Path)
    v.add_argument("directory", type=Path)
    args = parser.parse_args(argv)
    if args.command == "verify":
        return verify(args.manifest, args.directory)
    manifest = build(args.ref)
    text = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.write_text(text, encoding="utf-8")
    print(
        f"{manifest['file_count']} files, {manifest['total_bytes']} bytes, "
        f"tree {manifest['tree_sha256']} at {manifest['commit']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

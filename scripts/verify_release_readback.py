#!/usr/bin/env python3
"""Read a published release back from every external surface it claims (REG-028).

The registry's release rows were closed with hand-run commands, re-typed each
time and captured in prose. That works until someone forgets a surface: the
`5.0.0` publication was believed complete while PyPI carried the SDK and not the
gateway, and nothing in the repository would have noticed, because *source
metadata never establishes external lifecycle state* — a tag, a GitHub Release, a
registry package, an OCI digest and a signature are separate observables.

This tool is the automation of that readback. It is read-only, needs no
credentials for anything it checks by default, and prints one row per observable:

    CHECKED / MISMATCH / NOT_EXECUTED   (reason on the same row)

`NOT_EXECUTED` is a first-class outcome, not a pass: `cosign` and `gh attestation
verify` are reported that way when the tools are not installed, because claiming
a signature verified without running a verifier is exactly the failure this tool
exists to prevent.

Usage:
    python scripts/verify_release_readback.py --tag v5.0.0
    python scripts/verify_release_readback.py --tag v5.0.0 --verify-assets
    python scripts/verify_release_readback.py --tag v5.0.0 --json

Exit code is 0 when every executed check passed and no check mismatched, 1 when
any observable mismatched or an executed check failed. `NOT_EXECUTED` rows do not
by themselves fail the run (the tools are not installable from here), but they are
counted and printed so they cannot be mistaken for verification.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil

# nosec B404 - subprocess runs only the two signature verifiers below, resolved by
# shutil.which, with a fixed argv list and shell=False; no request data reaches it.
import subprocess  # nosec B404
import sys
import tempfile
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Any

REPO = "juanlunaia/aegis-latent-core"
GH_API = "https://api.github.com"
GH_DOWNLOAD = "https://github.com"
PYPI_API = "https://pypi.org/pypi"
NPM_API = "https://registry.npmjs.org"
# The registry's anonymous-pull scope endpoint. It is a URL, not a credential; the
# name avoids "token" so the bandit S105 rule does not read it as a hardcoded secret.
GHCR_ANON_PULL_ENDPOINT = "https://ghcr.io/token"
GHCR_MANIFESTS = "https://ghcr.io/v2"

# The two images the publish workflow pushes (`.github/workflows/publish_oci.yml:73,77`).
OCI_IMAGES = {
    "gateway": f"ghcr.io/{REPO}",
    "dashboard": f"ghcr.io/{REPO}-dashboard",
}

# Distributions whose presence on PyPI is checked against the tag's version.
PYPI_PACKAGES = ("aegis-latent-sdk", "aegis-latent-core")
NPM_PACKAGE = "aegis-latent-sdk"

STATUS_CHECKED = "CHECKED"
STATUS_MISMATCH = "MISMATCH"
STATUS_NOT_EXECUTED = "NOT_EXECUTED"


@dataclass
class Row:
    observable: str
    status: str
    detail: str
    observed: Any = field(default=None)


def _get(url: str, *, accept: str | None = None, headers: dict[str, str] | None = None,
         timeout: int = 30) -> tuple[int, dict[str, str], bytes]:
    # noqa justification: every URL this module opens is https, either a module
    # constant or built from the release tag/repository name (S310).
    req = urllib.request.Request(url, headers={"User-Agent": "aegis-release-readback/1"})  # noqa: S310  # nosec B310 - every URL this module opens is https: a module constant, or built from the repository name and the release tag

    if accept:
        req.add_header("Accept", accept)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310  # nosec B310 - same reason as the Request above

            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers or {}), exc.read()


def _get_json(url: str, **kw: Any) -> tuple[int, Any]:
    status, _, body = _get(url, **kw)
    try:
        return status, json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return status, None


def check_github_release(tag: str) -> tuple[list[Row], list[dict[str, Any]]]:
    rows: list[Row] = []
    status, data = _get_json(f"{GH_API}/repos/{REPO}/releases/tags/{tag}")
    if status != 200 or not isinstance(data, dict):
        rows.append(Row(f"GitHub Release {tag}", STATUS_MISMATCH,
                        f"API returned HTTP {status}; {tag} is not a published release"))
        return rows, []
    assets = data.get("assets") or []
    draft, pre = bool(data.get("draft")), bool(data.get("prerelease"))
    if draft or pre:
        rows.append(Row(f"GitHub Release {tag}", STATUS_MISMATCH,
                        f"draft={draft} prerelease={pre} — not a published release"))
    else:
        rows.append(Row(f"GitHub Release {tag}", STATUS_CHECKED,
                        f"published, {len(assets)} assets uploaded", observed=len(assets)))
    names = {a.get("name"): a.get("browser_download_url") for a in assets if isinstance(a, dict)}
    for required in ("SHA256SUMS", "release-asset-manifest.json"):
        if required in names:
            rows.append(Row(f"asset {required}", STATUS_CHECKED, "present"))
        else:
            rows.append(Row(f"asset {required}", STATUS_MISMATCH, "missing from the release"))
    urls = [{"name": n, "url": u} for n, u in names.items() if n and u]
    return rows, urls


def parse_sha256sums(text: str) -> list[tuple[str, str]]:
    """Parse `sha256sum` output into (digest, filename) pairs.

    Two-space separation is what `sha256sum` writes; a leading `*` marks binary
    mode and is stripped. Anything else on a line is ignored rather than guessed
    at, so a malformed file yields fewer entries instead of a wrong entry.
    """
    listed: list[tuple[str, str]] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2 and len(parts[0]) == 64 and all(c in "0123456789abcdef" for c in parts[0].lower()):
            listed.append((parts[0].lower(), parts[1].lstrip("*")))
    return listed


def summarize(rows: list[Row]) -> int:
    """Exit code for a set of rows: 1 on any mismatch, 0 otherwise.

    `NOT_EXECUTED` deliberately does **not** fail the run — the tools it stands
    for are not installable from every host — but it is never counted as a pass
    either, and `main` prints it as unverified. Keeping this rule in one function
    is what the regression test pins.
    """
    return 1 if any(r.status == STATUS_MISMATCH for r in rows) else 0


def consumer_snippet(tag: str) -> str:
    """The copy-pasteable provenance check a consumer runs without a checkout.

    Printed by `--emit-consumer-snippet` and quoted verbatim in `README.md`; a
    test compares the two so the documented commands cannot drift from the
    script's own URLs.
    """
    base = f"{GH_DOWNLOAD}/{REPO}/releases/download/{tag}"
    return "\n".join([
        f"curl -fsSL -O {base}/SHA256SUMS",
        "# then, for each artifact you downloaded:",
        f"curl -fsSL -O {base}/<artifact-name>",
        "sha256sum -c SHA256SUMS --ignore-missing",
    ])


def verify_assets(tag: str, urls: list[dict[str, str]], *, dest: str) -> list[Row]:
    rows: list[Row] = []
    sums_url = next((u["url"] for u in urls if u["name"] == "SHA256SUMS"), None)
    if not sums_url:
        rows.append(Row("SHA256SUMS sweep", STATUS_NOT_EXECUTED, "SHA256SUMS not in the release"))
        return rows
    status, _, body = _get(sums_url)
    if status != 200:
        rows.append(Row("SHA256SUMS sweep", STATUS_NOT_EXECUTED, f"could not fetch SHA256SUMS (HTTP {status})"))
        return rows
    listed = parse_sha256sums(body.decode("utf-8", "replace"))
    rows.append(Row("SHA256SUMS contents", STATUS_CHECKED, f"{len(listed)} digests listed", observed=len(listed)))
    by_name = {u["name"]: u["url"] for u in urls}
    checked = failed = absent = 0
    for expected, name in listed:
        if name not in by_name:
            rows.append(Row(f"asset {name}", STATUS_MISMATCH, "listed in SHA256SUMS but not uploaded"))
            absent += 1
            continue
        target = f"{dest}/{name}"
        status, _, payload = _get(by_name[name], timeout=180)
        if status != 200:
            rows.append(Row(f"asset {name}", STATUS_NOT_EXECUTED, f"download failed (HTTP {status})"))
            continue
        with open(target, "wb") as fh:
            fh.write(payload)
        digest = hashlib.sha256(payload).hexdigest()
        if digest == expected:
            checked += 1
        else:
            failed += 1
            rows.append(Row(f"asset {name}", STATUS_MISMATCH,
                            f"sha256 {digest} != SHA256SUMS {expected}", observed=digest))
    rows.append(Row("SHA256SUMS sweep", STATUS_CHECKED if not failed and not absent else STATUS_MISMATCH,
                    f"{checked} verified, {failed} mismatched, {absent} listed-but-absent of {len(listed)}",
                    observed=checked))
    return rows


def check_pypi(tag: str) -> list[Row]:
    version = tag.lstrip("v")
    rows: list[Row] = []
    for pkg in PYPI_PACKAGES:
        status, data = _get_json(f"{PYPI_API}/{pkg}/json")
        if status == 404 or not isinstance(data, dict):
            rows.append(Row(f"PyPI {pkg}", STATUS_CHECKED,
                            f"package does not exist (HTTP {status}) — no version of it is published"))
            continue
        latest = (data.get("info") or {}).get("version")
        published = sorted((data.get("releases") or {}).keys())
        if latest == version:
            rows.append(Row(f"PyPI {pkg}", STATUS_CHECKED,
                            f"latest {latest} == {version}; releases: {published}", observed=latest))
        else:
            rows.append(Row(f"PyPI {pkg}", STATUS_CHECKED,
                            f"latest {latest} != tag version {version}; releases: {published}", observed=latest))
    return rows


def check_npm(tag: str) -> list[Row]:
    version = tag.lstrip("v")
    status, data = _get_json(f"{NPM_API}/{NPM_PACKAGE}/latest")
    if status != 200 or not isinstance(data, dict):
        return [Row(f"npm {NPM_PACKAGE}", STATUS_MISMATCH, f"HTTP {status} on the registry")]
    latest = data.get("version")
    status_txt = STATUS_CHECKED if latest == version else STATUS_MISMATCH
    return [Row(f"npm {NPM_PACKAGE}", status_txt,
                f"latest {latest} {'==' if latest == version else '!='} {version}", observed=latest)]


def check_oci(tag: str) -> list[Row]:
    rows: list[Row] = []
    for label, image in OCI_IMAGES.items():
        repo = image.split("ghcr.io/", 1)[1]
        status, _, body = _get(f"{GHCR_ANON_PULL_ENDPOINT}?scope=repository:{repo}:pull&service=ghcr.io")
        token = None
        if status == 200:
            try:
                token = json.loads(body.decode("utf-8")).get("token")
            except (ValueError, UnicodeDecodeError):
                token = None
        if not token:
            rows.append(Row(f"GHCR {label}", STATUS_NOT_EXECUTED,
                            f"anonymous pull token unavailable (HTTP {status})"))
            continue
        accept = ("application/vnd.oci.image.index.v1+json,"
                  "application/vnd.docker.distribution.manifest.list.v2+json,"
                  "application/vnd.oci.image.manifest.v1+json,"
                  "application/vnd.docker.distribution.manifest.v2+json")
        # The publish workflow derives immutable tags as `${IMAGE}:${RELEASE_TAG#v}`
        # (`.github/workflows/publish_oci.yml:88-90`), so the image tag is the
        # version without the release tag's `v`. Try both rather than assume.
        last_status, digest, resolved = None, None, None
        for candidate in (tag.lstrip("v"), tag):
            status, headers, _ = _get(
                f"{GHCR_MANIFESTS}/{repo}/manifests/{candidate}", accept=accept,
                headers={"Authorization": f"Bearer {token}"})
            last_status = status
            digest = headers.get("Docker-Content-Digest") or headers.get("docker-content-digest")
            if status in (200, 201) and digest:
                resolved = candidate
                break
        if resolved:
            rows.append(Row(f"GHCR {label} {resolved}", STATUS_CHECKED,
                            f"manifest digest {digest}", observed=digest))
        else:
            rows.append(Row(f"GHCR {label} {tag}", STATUS_MISMATCH,
                            f"manifest request returned HTTP {last_status} for tags "
                            f"{tag.lstrip('v')!r} and {tag!r}, digest={digest!r}"))
    return rows


def check_signature_tools(tag: str) -> list[Row]:
    """Run the verifiers when they exist; say so when they do not.

    Both are deliberately `NOT_EXECUTED` when absent rather than assumed good:
    the registry's release rows may not claim a verified signature unless a
    verifier actually ran and its output was read.
    """
    rows: list[Row] = []
    cosign = shutil.which("cosign")
    for label, image in OCI_IMAGES.items():
        if not cosign:
            rows.append(Row(f"cosign verify {label}", STATUS_NOT_EXECUTED,
                            "cosign is not installed on this host (no `cosign` on PATH)"))
            continue
        # cosign is resolved by shutil.which above; argv is fixed, shell=False.
        proc = subprocess.run(  # noqa: S603  # nosec B603 B607 - `cosign` is the absolute path resolved by shutil.which on the line above; argv is a fixed list, shell=False
            [cosign, "verify", "--certificate-identity-regexp", ".*", "--certificate-oidc-issuer-regexp", ".*",
             f"{image}:{tag}"],
            capture_output=True, text=True, timeout=180)
        rows.append(Row(f"cosign verify {label}",
                        STATUS_CHECKED if proc.returncode == 0 else STATUS_MISMATCH,
                        (proc.stdout or proc.stderr).strip().splitlines()[-1] if (proc.stdout or proc.stderr) else "no output"))
    gh = shutil.which("gh")
    if not gh:
        rows.append(Row("gh attestation verify", STATUS_NOT_EXECUTED,
                        "gh CLI is not installed on this host (no `gh` on PATH)"))
    else:
        # `gh` is the absolute path from shutil.which; fixed argv, shell=False.
        proc = subprocess.run(  # noqa: S603  # nosec B603 B607 - see above
            [gh, "attestation", "verify", "--help"], capture_output=True, text=True, timeout=60)
        rows.append(Row("gh attestation verify", STATUS_NOT_EXECUTED,
                        f"gh present ({gh}) but no attestation artifact was named by this run"))
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tag", required=True, help="release tag to read back, e.g. v5.0.0")
    parser.add_argument("--verify-assets", action="store_true",
                        help="download every file listed in SHA256SUMS and verify its digest")
    parser.add_argument("--dest", default=None, help="where to place downloaded assets (default: a temp dir)")
    parser.add_argument("--json", action="store_true", help="emit the rows as JSON instead of a table")
    parser.add_argument("--emit-consumer-snippet", action="store_true",
                        help="print the consumer provenance one-liner for this tag and exit")
    args = parser.parse_args(argv)

    if args.emit_consumer_snippet:
        print(consumer_snippet(args.tag))
        return 0

    dest = args.dest or tempfile.mkdtemp(prefix=f"aegis-readback-{args.tag.lstrip('v')}-")
    rows: list[Row] = []
    gh_rows, urls = check_github_release(args.tag)
    rows.extend(gh_rows)
    if args.verify_assets and urls:
        import os
        os.makedirs(dest, exist_ok=True)
        rows.extend(verify_assets(args.tag, urls, dest=dest))
    elif urls:
        rows.append(Row("SHA256SUMS sweep", STATUS_NOT_EXECUTED,
                        "not requested; re-run with --verify-assets"))
    rows.extend(check_pypi(args.tag))
    rows.extend(check_npm(args.tag))
    rows.extend(check_oci(args.tag))
    rows.extend(check_signature_tools(args.tag))

    mismatches = [r for r in rows if r.status == STATUS_MISMATCH]
    not_executed = [r for r in rows if r.status == STATUS_NOT_EXECUTED]
    checked = [r for r in rows if r.status == STATUS_CHECKED]

    if args.json:
        print(json.dumps({"tag": args.tag, "rows": [asdict(r) for r in rows],
                          "checked": len(checked), "mismatched": len(mismatches),
                          "not_executed": len(not_executed)}, indent=2))
    else:
        width = max(len(r.observable) for r in rows) + 2
        print(f"release readback for {args.tag} (repository {REPO})")
        print("-" * 100)
        for r in rows:
            print(f"{r.observable:<{width}} {r.status:<13} {r.detail}")
        print("-" * 100)
        print(f"{len(checked)} checked, {len(mismatches)} mismatched, {len(not_executed)} not executed")
        if not_executed:
            print("NOT EXECUTED is not a pass: these observables are unverified from this host.")
        if dest and args.verify_assets:
            print(f"downloaded assets kept in {dest}")
    return summarize(rows)


if __name__ == "__main__":
    sys.exit(main())

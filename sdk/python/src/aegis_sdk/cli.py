# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""``aegis-sdk`` — offline bundle verification and gateway audit status.

Named ``aegis-sdk`` rather than ``aegis`` because the gateway distribution
already installs ``aegis`` and ``aegis-server`` as its server entry points; a
workstation with both installed must not have one silently shadow the other.

Exit codes are part of the interface:

``verify``
    0 verified · 1 failed · 2 unusable input · 3 incomplete (nothing failed,
    but the manifest signature was not checked, so tampering is not excluded)
``audit``
    0 status ok (and integrity valid, if asked) · 1 degraded or invalid ·
    2 unusable input or the gateway could not be queried
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

from aegis_sdk import __version__
from aegis_sdk.audit import (
    DEFAULT_API_KEY_ENV,
    GatewayAuditError,
    fetch_audit_status,
    is_healthy,
)
from aegis_sdk.bundle import (
    BundleInputError,
    BundleReport,
    load_ed25519_public_key,
    verify_bundle,
)

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2
EXIT_INCOMPLETE = 3

_MAX_KEY_FILE_BYTES = 4096

_VERIFY_EXIT = {"verified": EXIT_OK, "failed": EXIT_FAILED, "incomplete": EXIT_INCOMPLETE}
_VERDICT = {
    "verified": "VERIFIED — integrity consistent and the manifest signature verifies "
    "against the supplied key",
    "failed": "FAILED — see the failing check above",
    "incomplete": "INCOMPLETE — nothing failed, but the manifest signature was NOT checked; "
    "the digests detect corruption, not tampering",
}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegis-sdk",
        description="Verify Aegis forensic bundles offline and read gateway audit status.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    verify = commands.add_parser(
        "verify",
        help="verify a forensic bundle ZIP offline",
        description="Verify a forensic bundle ZIP without contacting any gateway.",
    )
    verify.add_argument("bundle", type=Path, help="path to the bundle ZIP")
    verify.add_argument(
        "--public-key",
        type=Path,
        help="operator's Ed25519 public key (PEM, hex, or raw), obtained out of band — "
        "never from the bundle",
    )
    verify.add_argument(
        "--trusted-root",
        help="lowercase 64-hex MMR root you already trust; compared with the terminal root",
    )
    verify.add_argument("--json", action="store_true", help="emit a JSON report")

    audit = commands.add_parser(
        "audit",
        help="read /v1/audit/health (and optionally /integrity) from a gateway",
        description="Print a gateway's own audit status as deterministic JSON.",
    )
    audit.add_argument("gateway_url", help="gateway base URL, e.g. https://gateway.example")
    audit.add_argument(
        "--integrity",
        action="store_true",
        help="also call /v1/audit/integrity (O(N) over the retained window)",
    )
    audit.add_argument(
        "--api-key-env",
        default=DEFAULT_API_KEY_ENV,
        help=f"environment variable holding the audit key (default: {DEFAULT_API_KEY_ENV}); "
        "keys are never taken on the command line",
    )
    audit.add_argument(
        "--timeout", type=float, default=10.0, help="socket timeout in seconds, per request"
    )
    return parser


def _print_report(report: BundleReport, as_json: bool, out: TextIO) -> None:
    if as_json:
        out.write(json.dumps(report.to_mapping(), sort_keys=True, indent=2) + "\n")
        return
    for check in report.checks:
        out.write(f"{check.status.upper():<5} {check.name:<19} {check.detail}\n")
    out.write(f"RESULT: {_VERDICT[report.result]}\n")


def _verify(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    public_key: bytes | None = None
    try:
        if args.public_key is not None:
            try:
                with args.public_key.open("rb") as handle:
                    # Any encoding of one Ed25519 key is far below this.
                    key_bytes = handle.read(_MAX_KEY_FILE_BYTES + 1)
            except OSError as exc:
                raise BundleInputError(f"cannot read public key: {exc}") from exc
            if len(key_bytes) > _MAX_KEY_FILE_BYTES:
                raise BundleInputError("public key file is too large to be one Ed25519 key")
            public_key = load_ed25519_public_key(key_bytes)
        report = verify_bundle(args.bundle, public_key=public_key, trusted_root=args.trusted_root)
    except BundleInputError as exc:
        err.write(f"aegis-sdk verify: {exc}\n")
        return EXIT_USAGE
    _print_report(report, args.json, out)
    return _VERIFY_EXIT[report.result]


def _audit(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    api_key = os.environ.get(args.api_key_env) or None
    try:
        report = fetch_audit_status(
            args.gateway_url,
            api_key=api_key,
            include_integrity=args.integrity,
            timeout=args.timeout,
        )
    except (GatewayAuditError, ValueError) as exc:
        err.write(f"aegis-sdk audit: {exc}\n")
        return EXIT_USAGE
    out.write(json.dumps(report, sort_keys=True, indent=2) + "\n")
    return EXIT_OK if is_healthy(report) else EXIT_FAILED


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "verify":
        return _verify(args, sys.stdout, sys.stderr)
    return _audit(args, sys.stdout, sys.stderr)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

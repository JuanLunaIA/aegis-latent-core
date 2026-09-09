#!/usr/bin/env python3
# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

"""Vendor tool: mint and sign a commercial license token.

This is the private half of :mod:`aegis.licensing.validator`. It runs on the
vendor's machine, never in a deployment, and it needs the Ed25519 **private**
key that corresponds to the root public key customers are configured with.

    # one-time: create the vendor root key pair
    python scripts/generate_commercial_license.py keygen --out-dir ./vendor-keys

    # per customer
    python scripts/generate_commercial_license.py issue \\
        --customer-id acme-corp \\
        --tier enterprise \\
        --modules veracity sanctum \\
        --mgt 50 \\
        --valid-days 365 \\
        --private-key-file ./vendor-keys/aegis_license_root.key

The private key file is written ``0600`` and is a secret in the strongest sense
in this repository: whoever holds it can mint any entitlement, for any customer,
for any term. It must never enter the repository, a container image, CI, or a
backup that is not itself controlled. Losing it means reissuing every token;
leaking it means rotating the root key and reissuing every token.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
from collections.abc import Sequence
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# Importable without the package installed, so the vendor tool runs from a
# bare checkout.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegis.licensing.validator import KNOWN_MODULES  # noqa: E402

_PRIVATE_KEY_NAME = "aegis_license_root.key"
_PUBLIC_KEY_NAME = "aegis_license_root.pub"


def _canonical_payload(payload: dict[str, object]) -> bytes:
    """Deterministic UTF-8 JSON: sorted keys, no incidental whitespace.

    Verification checks the signature over the exact bytes carried in the
    token, so canonicalisation is not required for correctness. It is here so
    that issuing the same entitlement twice produces the same payload, which
    makes a token diffable and a reissue auditable.
    """

    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _write_secret(path: Path, data: bytes) -> None:
    """Write ``0600`` from creation, never briefly world-readable."""

    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)


def cmd_keygen(args: argparse.Namespace) -> int:
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    private_path = out_dir / _PRIVATE_KEY_NAME
    public_path = out_dir / _PUBLIC_KEY_NAME

    if private_path.exists() and not args.force:
        print(
            f"refusing to overwrite {private_path}: every token signed by the existing "
            f"key would stop verifying. Pass --force only if that is intended.",
            file=sys.stderr,
        )
        return 2

    private_key = Ed25519PrivateKey.generate()
    _write_secret(
        private_path,
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )
    public_hex = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        .hex()
    )
    public_path.write_text(public_hex + "\n", encoding="utf-8")

    print(f"private key: {private_path}  (mode 0600 — keep offline)")
    print(f"public key:  {public_path}")
    print()
    print("Configure deployments with:")
    print(f"  AEGIS_LICENSE_ROOT_PUBKEY={public_hex}")
    return 0


def _load_private_key(path: Path) -> Ed25519PrivateKey:
    raw = path.read_bytes()
    key = serialization.load_pem_private_key(raw, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise SystemExit(f"{path} does not hold an Ed25519 private key (got {type(key).__name__})")
    return key


def cmd_issue(args: argparse.Namespace) -> int:
    modules = sorted(set(args.modules))
    unknown = [m for m in modules if m not in KNOWN_MODULES]
    if unknown:
        print(
            f"unknown module(s) {unknown}; known modules are {sorted(KNOWN_MODULES)}",
            file=sys.stderr,
        )
        return 2
    if args.valid_days <= 0:
        print(
            "--valid-days must be positive; an already-expired token is not useful", file=sys.stderr
        )
        return 2
    if args.mgt < 0:
        print("--mgt must not be negative", file=sys.stderr)
        return 2

    private_key = _load_private_key(Path(args.private_key_file))

    issued_at = int(time.time())
    payload = {
        "sub": args.customer_id,
        "tier": args.tier,
        "modules": modules,
        "mgt": args.mgt,
        "iat": issued_at,
        "exp": issued_at + args.valid_days * 86_400,
    }
    payload_bytes = _canonical_payload(payload)
    signature = private_key.sign(payload_bytes)
    token = base64.b64encode(payload_bytes + signature, altchars=b"-_").decode("ascii")

    if args.json:
        print(
            json.dumps(
                {"token": token, "payload": payload, "public_key_hex": _public_hex(private_key)},
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print(token)
    return 0


def _public_hex(private_key: Ed25519PrivateKey) -> str:
    public: Ed25519PublicKey = private_key.public_key()
    return public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="generate_commercial_license.py",
        description="Mint and sign Aegis commercial license tokens (vendor-side).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    keygen = sub.add_parser("keygen", help="create the vendor Ed25519 root key pair")
    keygen.add_argument("--out-dir", required=True, help="directory to write the key pair into")
    keygen.add_argument(
        "--force",
        action="store_true",
        help="overwrite an existing private key (invalidates every token it signed)",
    )
    keygen.set_defaults(func=cmd_keygen)

    issue = sub.add_parser("issue", help="sign a license token for one customer")
    issue.add_argument("--customer-id", required=True)
    issue.add_argument("--tier", required=True, help="e.g. core, enterprise, omnia, sovereign")
    issue.add_argument(
        "--modules",
        required=True,
        nargs="+",
        metavar="MODULE",
        help=f"one or more of: {' '.join(sorted(KNOWN_MODULES))}",
    )
    issue.add_argument(
        "--mgt",
        required=True,
        type=int,
        help="contracted Million Governed Transactions per year (a commercial term; "
        "not enforced at runtime)",
    )
    issue.add_argument("--valid-days", required=True, type=int)
    issue.add_argument("--private-key-file", required=True)
    issue.add_argument(
        "--json",
        action="store_true",
        help="emit the token together with its decoded payload and the public key",
    )
    issue.set_defaults(func=cmd_issue)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result: int = args.func(args)
    return result


if __name__ == "__main__":
    raise SystemExit(main())

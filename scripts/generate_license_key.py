# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""generate_license_key.py — HMAC-SHA256 license key generator for Aegis v2.4.1.

Generates cryptographically signed, self-contained trial and commercial license
keys that embed the licensee metadata, tier, and expiry date. The key is opaque
to the client but verifiable offline by the maintainer — no license server required.

Key format (base64url of JSON + HMAC tag)
-----------------------------------------
    <b64url(payload_json)>.<b64url(hmac_sha256_tag)>

The payload JSON contains:
    {
      "v":    1,                        # key format version
      "id":   "aegis-abc1234",          # unique license ID
      "org":  "Acme Corp",              # licensee organization
      "tier": "self-serve-enterprise",  # tier slug
      "exp":  1780000000,               # expiry (Unix timestamp)
      "iat":  1750000000,               # issued at
      "feat": ["audit","waf","pqc"],    # feature set
      "max_nodes": 500000,              # max WAL nodes per deployment
    }

Usage
-----
    # Generate a 30-day trial key
    python scripts/generate_license_key.py \\
        --org "Acme Corp" --tier trial --days 30 \\
        --secret "$(cat ~/.aegis/license_master_key.hex)"

    # Generate a 1-year Self-Serve Enterprise key
    python scripts/generate_license_key.py \\
        --org "BigBank Inc" --tier self-serve-enterprise --days 365

    # Verify a key
    python scripts/generate_license_key.py --verify <key> \\
        --secret "$(cat ~/.aegis/license_master_key.hex)"

    # Generate master secret (do once; store securely in Vault/1Password)
    python -c 'import secrets; print(secrets.token_hex(32))' > ~/.aegis/license_master_key.hex
    chmod 600 ~/.aegis/license_master_key.hex

SECURITY NOTE: The --secret value is the master HMAC key. Any party with
this key can forge valid license keys. Keep it in a secrets manager (Vault,
1Password, AWS Secrets Manager) and never commit it to VCS.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
import time
from datetime import datetime, timezone
from typing import Any

# ── Tier definitions ──────────────────────────────────────────────────────────
TIER_CONFIGS: dict[str, dict[str, Any]] = {
    "trial": {
        "display": "Evaluation / Trial",
        "features": ["audit", "waf"],
        "max_nodes": 10_000,
        "default_days": 30,
    },
    "startup": {
        "display": "Startup",
        "features": ["audit", "waf", "rate_limit", "providers"],
        "max_nodes": 100_000,
        "default_days": 365,
    },
    "self-serve-enterprise": {
        "display": "Self-Serve Enterprise",
        "features": ["audit", "waf", "rate_limit", "providers", "compliance_exports", "sbom", "pqc"],
        "max_nodes": 500_000,
        "default_days": 365,
    },
    "premium-sovereign": {
        "display": "Premium Sovereign",
        "features": ["audit", "waf", "rate_limit", "providers", "compliance_exports", "sbom", "pqc",
                     "fedramp", "dod_il5", "airgap", "custom_sla"],
        "max_nodes": 5_000_000,
        "default_days": 365,
    },
    "oem": {
        "display": "OEM / Embedded",
        "features": ["*"],  # All features; redistribution rights in MSA
        "max_nodes": -1,    # Unlimited
        "default_days": 365,
    },
}

# Default master key location (populated from env or --secret)
_DEFAULT_MASTER_KEY_ENV = "AEGIS_LICENSE_MASTER_KEY"
_DEFAULT_MASTER_KEY_FILE = os.path.expanduser("~/.aegis/license_master_key.hex")


def _load_master_key(secret_arg: str | None) -> bytes:
    if secret_arg:
        raw = secret_arg.strip()
    elif os.environ.get(_DEFAULT_MASTER_KEY_ENV):
        raw = os.environ[_DEFAULT_MASTER_KEY_ENV].strip()
    elif os.path.exists(_DEFAULT_MASTER_KEY_FILE):
        raw = open(_DEFAULT_MASTER_KEY_FILE).read().strip()
    else:
        # Generate ephemeral key for demo purposes — warn loudly
        print("WARNING: No master key found. Generating ephemeral key.", file=sys.stderr)
        print(f"WARNING: Keys generated with ephemeral keys cannot be verified later.", file=sys.stderr)
        print(f"WARNING: Store a persistent key at: {_DEFAULT_MASTER_KEY_FILE}", file=sys.stderr)
        raw = secrets.token_hex(32)
    try:
        return bytes.fromhex(raw)
    except ValueError as exc:
        print(f"ERROR: Master key is not valid hex: {exc}", file=sys.stderr)
        sys.exit(1)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * (padding % 4))


def generate_key(
    org: str,
    tier: str,
    days: int,
    secret: str | None = None,
    license_id: str | None = None,
) -> tuple[str, dict[str, Any]]:
    """Generate a signed license key and return (key_string, payload)."""
    if tier not in TIER_CONFIGS:
        raise ValueError(f"Unknown tier: {tier}. Valid: {list(TIER_CONFIGS)}")

    config = TIER_CONFIGS[tier]
    master_key = _load_master_key(secret)
    now = int(time.time())
    exp = now + days * 86400
    lid = license_id or f"aegis-{secrets.token_hex(4)}"

    payload: dict[str, Any] = {
        "v": 1,
        "id": lid,
        "org": org,
        "tier": tier,
        "exp": exp,
        "iat": now,
        "feat": config["features"],
        "max_nodes": config["max_nodes"],
    }

    payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    payload_b64 = _b64url(payload_bytes)

    tag = hmac.new(master_key, payload_bytes, hashlib.sha256).digest()
    tag_b64 = _b64url(tag)

    key = f"{payload_b64}.{tag_b64}"
    return key, payload


def verify_key(key: str, secret: str | None = None) -> tuple[bool, dict[str, Any], str]:
    """Verify a license key. Returns (valid, payload, error_message)."""
    try:
        parts = key.split(".")
        if len(parts) != 2:
            return False, {}, "Malformed key: expected exactly one '.' separator"

        payload_b64, tag_b64 = parts
        payload_bytes = _b64url_decode(payload_b64)
        expected_tag = _b64url_decode(tag_b64)

        master_key = _load_master_key(secret)
        actual_tag = hmac.new(master_key, payload_bytes, hashlib.sha256).digest()

        if not hmac.compare_digest(expected_tag, actual_tag):
            return False, {}, "Signature verification FAILED — key is invalid or forged"

        payload = json.loads(payload_bytes)
        now = int(time.time())

        if payload.get("exp", 0) < now:
            exp_dt = datetime.fromtimestamp(payload["exp"], tz=timezone.utc).strftime("%Y-%m-%d")
            return False, payload, f"License EXPIRED on {exp_dt}"

        return True, payload, ""

    except Exception as exc:
        return False, {}, f"Verification error: {exc}"


def _print_key_info(payload: dict[str, Any], key: str) -> None:
    exp_dt = datetime.fromtimestamp(payload["exp"], tz=timezone.utc).strftime("%Y-%m-%d")
    iat_dt = datetime.fromtimestamp(payload["iat"], tz=timezone.utc).strftime("%Y-%m-%d")
    config = TIER_CONFIGS.get(payload["tier"], {})
    days_remaining = max(0, (payload["exp"] - int(time.time())) // 86400)

    print("\n" + "═" * 72)
    print("  AEGIS LICENSE KEY")
    print("═" * 72)
    print(f"  ID:            {payload['id']}")
    print(f"  Organization:  {payload['org']}")
    print(f"  Tier:          {config.get('display', payload['tier'])}")
    print(f"  Issued:        {iat_dt}")
    print(f"  Expires:       {exp_dt} ({days_remaining} days remaining)")
    print(f"  Max nodes:     {payload['max_nodes']:,}" if payload['max_nodes'] > 0 else "  Max nodes:     Unlimited")
    print(f"  Features:      {', '.join(payload['feat'])}")
    print()
    print("  KEY (set as AEGIS_LICENSE_KEY environment variable):")
    print()
    print(f"  {key}")
    print()
    print("═" * 72 + "\n")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Aegis v2.4.1 License Key Generator / Verifier",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command")

    gen = sub.add_parser("generate", aliases=["gen", "g"], help="Generate a new license key")
    gen.add_argument("--org", required=True, help="Licensee organization name")
    gen.add_argument("--tier", required=True, choices=list(TIER_CONFIGS), help="License tier")
    gen.add_argument("--days", type=int, default=None, help="Days until expiry (default: tier-specific)")
    gen.add_argument("--secret", default=None, help="Master HMAC key (hex). Default: $AEGIS_LICENSE_MASTER_KEY or ~/.aegis/license_master_key.hex")
    gen.add_argument("--id", default=None, help="Custom license ID")

    ver = sub.add_parser("verify", aliases=["v"], help="Verify an existing license key")
    ver.add_argument("key", help="License key string to verify")
    ver.add_argument("--secret", default=None, help="Master HMAC key (hex)")

    sub.add_parser("list-tiers", help="List available license tiers")

    sub.add_parser("gen-master-key", help="Generate a new master HMAC key for secure storage")

    # Also support positional --verify shorthand
    parser.add_argument("--verify", metavar="KEY", default=None, help="Verify a license key (shorthand)")
    parser.add_argument("--org", default=None)
    parser.add_argument("--tier", default=None, choices=list(TIER_CONFIGS))
    parser.add_argument("--days", type=int, default=None)
    parser.add_argument("--secret", default=None)

    args = parser.parse_args()

    if args.command in ("generate", "gen", "g") or (not args.command and args.org and args.tier):
        org = args.org
        tier = args.tier
        days = args.days or TIER_CONFIGS[tier]["default_days"]
        lid = getattr(args, "id", None)
        key, payload = generate_key(org, tier, days, args.secret, lid)
        _print_key_info(payload, key)

    elif args.command in ("verify", "v") or args.verify:
        key = (args.key if args.command in ("verify", "v") else args.verify)
        valid, payload, err = verify_key(key, args.secret)
        if valid:
            print("\n✓ License key is VALID\n")
            _print_key_info(payload, key)
        else:
            print(f"\n✗ License key is INVALID: {err}\n", file=sys.stderr)
            sys.exit(1)

    elif args.command == "list-tiers":
        print("\nAvailable Aegis license tiers:\n")
        for slug, cfg in TIER_CONFIGS.items():
            print(f"  {slug:30s} {cfg['display']}")
            print(f"    Features:  {', '.join(cfg['features'][:5])}{',...' if len(cfg['features']) > 5 else ''}")
            max_nodes_str = "Unlimited" if cfg["max_nodes"] < 0 else f"{cfg['max_nodes']:,}"
            print(f"    Max nodes: {max_nodes_str}")
            print(f"    Default:   {cfg['default_days']} days")
            print()

    elif args.command == "gen-master-key":
        key_hex = secrets.token_hex(32)
        print("\n# Aegis License Master Key (64 hex chars / 32 bytes / 256 bits)")
        print("# Store in: Vault, 1Password, AWS Secrets Manager, or ~/.aegis/license_master_key.hex (chmod 600)")
        print("# NEVER commit to VCS.")
        print()
        print(key_hex)
        print()

    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()

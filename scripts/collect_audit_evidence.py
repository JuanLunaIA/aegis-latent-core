#!/usr/bin/env python3
# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Collect a point-in-time technical evidence snapshot from a running gateway.

For an assessor or an internal audit function. It reads, never writes: the
gateway's liveness and readiness answers, its ``/metrics`` exposition (which
carries ``aegis_security_enforcement_mode``), and — with an ``audit:read`` key —
``/v1/audit/health``, ``/v1/audit/integrity`` and ``/v1/attestation/capabilities``.
Each response body is saved verbatim beside its SHA-256, a manifest records what
was asked of whom and what came back, and ``SHA256SUMS`` covers every file, so
the snapshot can be handed on and re-checked with ``sha256sum -c``.

The audit key is read from ``AEGIS_AUDIT_KEY`` and never from the command line
(where it would land in shell history and process listings). It is sent only
to the target named by ``--url`` and is never written into the output.

What a snapshot is **not**: the collector's clock is not trusted time; a
response is what the gateway said about itself, not an independent observation
of the host; and ``observations`` in the manifest are facts read out of those
responses, not a compliance conclusion. See docs/compliance/AUDIT_READINESS.md.

Exit status: 0 when every request got an HTTP answer (whatever its status), 1
when any request failed in transport, 2 on unusable arguments.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import platform
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from email.message import Message as HTTPMessage
from pathlib import Path
from typing import IO

SCHEMA = "aegis-audit-evidence-snapshot-v1"
KEY_ENV = "AEGIS_AUDIT_KEY"
MAX_BODY_BYTES = 8 * 1024 * 1024


@dataclass(frozen=True)
class Probe:
    name: str
    path: str
    needs_key: bool
    suffix: str


PROBES: tuple[Probe, ...] = (
    Probe("health", "/health", False, "json"),
    Probe("ready", "/ready", False, "json"),
    Probe("metrics", "/metrics", False, "txt"),
    Probe("audit_health", "/v1/audit/health", True, "json"),
    Probe("audit_integrity", "/v1/audit/integrity", True, "json"),
    Probe("attestation_capabilities", "/v1/attestation/capabilities", True, "json"),
)

_ENFORCEMENT_RE = re.compile(r"^aegis_security_enforcement_mode(?:\{[^}]*\})?\s+([0-9.eE+-]+)\s*$")


class UsageError(ValueError):
    """The arguments cannot produce a meaningful snapshot."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _base_url(raw: str) -> str:
    parsed = urllib.parse.urlsplit(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise UsageError(f"--url must be an http(s) URL with a host, got {raw!r}")
    if parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise UsageError("--url must not carry credentials, a query or a fragment")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))


def _context(ca_file: str | None) -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=ca_file)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def _peer_certificate_sha256(base: str, context: ssl.SSLContext, timeout: float) -> str | None:
    """SHA-256 of the DER certificate the server presented, for https targets."""
    import socket

    parsed = urllib.parse.urlsplit(base)
    if parsed.scheme != "https":
        return None
    host = parsed.hostname or ""
    port = parsed.port or 443
    with (
        socket.create_connection((host, port), timeout=timeout) as raw,
        context.wrap_socket(raw, server_hostname=host) as tls,
    ):
        der = tls.getpeercert(binary_form=True)
    return _sha256(der) if der else None


def _fetch(
    url: str, key: str | None, context: ssl.SSLContext, timeout: float
) -> tuple[int, str, bytes]:
    headers = {"accept": "application/json, text/plain;q=0.9"}
    if key is not None:
        headers["authorization"] = f"Bearer {key}"
    request = urllib.request.Request(url, headers=headers, method="GET")  # noqa: S310 - scheme checked in _base_url
    # No redirect following: a redirect could carry the key to another origin.
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=context), _NoRedirect()
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            return (
                int(response.status),
                response.headers.get("content-type", ""),
                response.read(MAX_BODY_BYTES + 1),
            )
    except urllib.error.HTTPError as exc:
        return int(exc.code), exc.headers.get("content-type", ""), exc.read(MAX_BODY_BYTES + 1)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Surface a redirect as its own status instead of following it with the key."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> urllib.request.Request | None:
        return None


def _json(body: bytes) -> object:
    try:
        return json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return None


def _observations(
    results: dict[str, dict[str, object]], bodies: dict[str, bytes]
) -> dict[str, object]:
    """Facts read out of the responses. Absent means the response did not say."""
    seen: dict[str, object] = {}
    for line in bodies.get("metrics", b"").decode("utf-8", "replace").splitlines():
        match = _ENFORCEMENT_RE.match(line.strip())
        if match:
            seen["enforcement_mode"] = "strict" if float(match.group(1)) == 1 else "development"
    integrity = _json(bodies.get("audit_integrity", b""))
    if results.get("audit_integrity", {}).get("status") == 200 and isinstance(integrity, dict):
        for field in ("valid", "node_count", "signature_assurance", "full_history_retained"):
            if field in integrity:
                seen[f"integrity_{field}"] = integrity[field]
    capabilities = _json(bodies.get("attestation_capabilities", b""))
    if isinstance(capabilities, dict) and isinstance(capabilities.get("controls"), list):
        seen["controls"] = {
            str(control.get("name")): str(control.get("status"))
            for control in capabilities["controls"]
            if isinstance(control, dict)
        }
    health = _json(bodies.get("health", b""))
    if isinstance(health, dict):
        seen["health_status"] = health.get("status")
        ha = health.get("ha")
        if isinstance(ha, dict):
            seen["ha_mode"] = ha.get("mode")
            seen["ha_admitting"] = ha.get("admitting")
    seen["ready_status_code"] = results.get("ready", {}).get("status")
    return seen


def collect(
    base: str,
    out: Path,
    key: str | None,
    *,
    ca_file: str | None = None,
    timeout: float = 20.0,
    extra_files: tuple[Path, ...] = (),
) -> int:
    """Write the snapshot into *out* (created; must not already hold files)."""
    if out.exists() and any(out.iterdir()):
        raise UsageError(f"{out} is not empty; a snapshot is never written over another")
    responses = out / "responses"
    responses.mkdir(parents=True, exist_ok=True)
    context = _context(ca_file)
    # timezone.utc, not datetime.UTC (3.11+): assessors run this on whatever host they have.
    collected_at = datetime.datetime.now(datetime.timezone.utc).isoformat()  # noqa: UP017
    results: dict[str, dict[str, object]] = {}
    bodies: dict[str, bytes] = {}
    transport_failures = 0
    for probe in PROBES:
        if probe.needs_key and key is None:
            results[probe.name] = {"path": probe.path, "skipped": f"no {KEY_ENV} set"}
            continue
        try:
            status, content_type, body = _fetch(
                base + probe.path, key if probe.needs_key else None, context, timeout
            )
        except (urllib.error.URLError, OSError, ssl.SSLError) as exc:
            transport_failures += 1
            results[probe.name] = {"path": probe.path, "error": type(exc).__name__}
            continue
        truncated = len(body) > MAX_BODY_BYTES
        body = body[:MAX_BODY_BYTES]
        name = f"{probe.name}.{probe.suffix}"
        (responses / name).write_bytes(body)
        bodies[probe.name] = body
        results[probe.name] = {
            "path": probe.path,
            "status": status,
            "content_type": content_type,
            "file": f"responses/{name}",
            "sha256": _sha256(body),
            "bytes": len(body),
            "truncated": truncated,
            "authenticated": probe.needs_key,
        }
    attached: list[dict[str, object]] = []
    for extra in extra_files:
        data = extra.read_bytes()
        target = out / "attached" / extra.name
        target.parent.mkdir(exist_ok=True)
        target.write_bytes(data)
        attached.append({"file": f"attached/{extra.name}", "sha256": _sha256(data)})
    try:
        peer = _peer_certificate_sha256(base, context, timeout)
    except (OSError, ssl.SSLError) as exc:
        peer = f"unavailable: {type(exc).__name__}"
    manifest = {
        "schema": SCHEMA,
        "target": base,
        "collected_at_collector_clock": collected_at,
        "clock_note": "the collector's own clock; not trusted time",
        "tls_peer_certificate_sha256": peer,
        "collector": {
            "script_sha256": _sha256(Path(__file__).read_bytes()),
            "python": platform.python_version(),
        },
        "requests": results,
        "attached": attached,
        "observations": _observations(results, bodies),
        "boundary": (
            "Responses are the gateway's statements about itself at one moment. They are "
            "not an independent host observation and not a compliance conclusion."
        ),
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    sums = [
        f"{_sha256(path.read_bytes())}  {path.relative_to(out).as_posix()}"
        for path in sorted(out.rglob("*"))
        if path.is_file() and path.name != "SHA256SUMS"
    ]
    (out / "SHA256SUMS").write_text("\n".join(sums) + "\n")
    return 1 if transport_failures else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--url", required=True, help="gateway base URL, e.g. https://aegis.internal"
    )
    parser.add_argument("--out", required=True, type=Path, help="new, empty output directory")
    parser.add_argument("--ca-file", help="PEM bundle that anchors the gateway's TLS certificate")
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument(
        "--attach",
        action="append",
        default=[],
        type=Path,
        metavar="FILE",
        help="add a file (e.g. `python -m aegis.core.ha verify` output) under attached/; repeatable",
    )
    args = parser.parse_args(argv)
    key = os.environ.get(KEY_ENV) or None
    try:
        base = _base_url(args.url)
        for extra in args.attach:
            if not extra.is_file():
                raise UsageError(f"--attach {extra} is not a file")
        status = collect(
            base,
            args.out,
            key,
            ca_file=args.ca_file,
            timeout=args.timeout,
            extra_files=tuple(args.attach),
        )
    except UsageError as exc:
        print(f"collect_audit_evidence: {exc}", file=sys.stderr)
        return 2
    print(f"snapshot written to {args.out} (verify with: cd {args.out} && sha256sum -c SHA256SUMS)")
    return status


if __name__ == "__main__":
    raise SystemExit(main())

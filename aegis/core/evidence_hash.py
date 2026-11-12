"""Dual evidence hash: provider bytes versus client bytes.

With the PII vault active, what the provider receives (tokens) and what the
client receives (restored values) differ. A single ``response_hash`` cannot
prove both; this module computes and carries the two digests.

The client digest is the node's signed ``response_hash``; the provider digest is
recorded in the same node's ``sampling_params`` (see
``CryptographicAuditLedger.commit_forensic`` / ``commit_forensic_summary``).
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
# Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

_HEX_CHARS = frozenset("0123456789abcdef")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_sha256_hex(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in _HEX_CHARS for ch in value)


@dataclass(frozen=True)
class ResponseDigests:
    """Both ends of a response, already hashed."""

    upstream_sha256: str
    client_sha256: str

    @property
    def restored(self) -> bool:
        """True when the client received different bytes from the provider's."""
        return self.upstream_sha256 != self.client_sha256

    def evidence_params(self, *, pii_restored: bool = False) -> dict[str, Any]:
        """Fields for ``sampling_params``; never includes content."""
        params: dict[str, Any] = {
            "response_upstream_sha256": self.upstream_sha256,
            "response_client_sha256": self.client_sha256,
        }
        if pii_restored or self.restored:
            params["pii_restored"] = True
        return params


def response_digests(upstream_bytes: bytes, client_bytes: bytes) -> ResponseDigests:
    """Hash of the bytes the provider sent and of the bytes delivered to the client."""
    return ResponseDigests(
        upstream_sha256=sha256_hex(upstream_bytes),
        client_sha256=sha256_hex(client_bytes),
    )


class StreamDigestRecorder:
    """Accumulates both digests while a stream passes through the restorer.

    It is updated at the point the bytes pass: ``update_upstream`` before
    restoring, ``update_client`` after. The object keeps no bytes, only the
    SHA-256 state.
    """

    def __init__(self) -> None:
        self._upstream = hashlib.sha256()
        self._client = hashlib.sha256()
        self._upstream_events = 0
        self._client_events = 0

    def update_upstream(self, data: bytes) -> None:
        if data:
            self._upstream.update(data)
            self._upstream_events += 1

    def update_client(self, data: bytes) -> None:
        if data:
            self._client.update(data)
            self._client_events += 1

    @property
    def upstream_events(self) -> int:
        return self._upstream_events

    @property
    def client_events(self) -> int:
        return self._client_events

    def snapshot(self) -> ResponseDigests:
        return ResponseDigests(
            upstream_sha256=self._upstream.copy().hexdigest(),
            client_sha256=self._client.copy().hexdigest(),
        )


__all__ = [
    "ResponseDigests",
    "StreamDigestRecorder",
    "is_sha256_hex",
    "response_digests",
    "sha256_hex",
]

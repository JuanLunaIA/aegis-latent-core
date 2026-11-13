# Copyright (c) 2026 Juan Luna. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
# Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
"""The PII vault's provider digest is bound into the node signature.

The vault records two hashes for one response: the signed ``response_hash`` of
the bytes the client received and, in ``sampling_params``, the hash of the bytes
the provider sent plus a ``pii_restored`` flag. ``node_hash`` does not cover
``sampling_params``, so before this binding an edit to either field left every
check passing. The token appended to the signed payload makes such an edit
invalidate the signature, and a node without the fields rebuilds the payload it
always had.

With cryptographic shredding on, the plain digests are not stored at all: the
signed hashes are keyed to the subject so a guess cannot be confirmed after
erasure, and a plain SHA-256 beside them would answer that guess.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest

from aegis.core.crypto_audit import DUAL_DIGEST_KEYS, CryptographicAuditLedger

UPSTREAM = hashlib.sha256(b"provider bytes").hexdigest()
CLIENT = hashlib.sha256(b"client bytes").hexdigest()


def _ledger(tmp_path: Path, *, shredding: bool = False) -> CryptographicAuditLedger:
    return CryptographicAuditLedger(
        str(tmp_path / "w.jsonl"),
        signing_key="dual-digest-test-key",
        enable_cryptographic_shredding=shredding,
    )


def _commit(ledger: CryptographicAuditLedger, **params: Any):
    return ledger.commit_forensic(
        state_id="req-1",
        request_bytes=b"request",
        response_bytes=b"client bytes",
        tenant_id="tenant-a",
        sampling_params=params,
    )


def test_an_untouched_node_with_digests_verifies(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    node = _commit(
        ledger,
        response_upstream_sha256=UPSTREAM,
        response_client_sha256=CLIENT,
        pii_restored=True,
    )
    assert ledger.signature_status(node) == "valid"
    ledger.close()


@pytest.mark.parametrize(
    "edit",
    [
        {"response_upstream_sha256": hashlib.sha256(b"forged").hexdigest()},
        {"pii_restored": False},
    ],
)
def test_editing_the_dual_hash_fields_breaks_the_signature(
    tmp_path: Path, edit: dict[str, Any]
) -> None:
    ledger = _ledger(tmp_path)
    node = _commit(
        ledger,
        response_upstream_sha256=UPSTREAM,
        response_client_sha256=CLIENT,
        pii_restored=True,
    )
    node.sampling_params.update(edit)
    assert ledger.signature_status(node) == "invalid"
    ledger.close()


def test_removing_the_provider_digest_breaks_the_signature(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    node = _commit(ledger, response_upstream_sha256=UPSTREAM)
    del node.sampling_params["response_upstream_sha256"]
    assert ledger.signature_status(node) == "invalid"
    ledger.close()


def test_a_node_without_the_fields_keeps_its_payload_shape(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    node = _commit(ledger, temperature=0.2)
    assert ledger.signature_status(node) == "valid"
    assert ledger.verify_integrity() == (True, None)
    ledger.close()


def test_a_malformed_provider_digest_is_refused(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    with pytest.raises(ValueError, match="response_upstream_sha256"):
        _commit(ledger, response_upstream_sha256="not|hex")
    ledger.close()


def test_shredding_stores_no_plain_digest(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path, shredding=True)
    node = _commit(
        ledger,
        response_upstream_sha256=UPSTREAM,
        response_client_sha256=CLIENT,
        pii_restored=True,
    )
    for key in DUAL_DIGEST_KEYS:
        assert key not in node.sampling_params
    assert node.sampling_params["pii_restored"] is True
    assert ledger.signature_status(node) == "valid"
    ledger.close()

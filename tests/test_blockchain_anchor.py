# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.blockchain_anchor + aegis.core.anchoring (honest anchoring)."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from aegis.core.blockchain_anchor import (
    AnchorReceipt,
    AnchorUnavailableError,
    BlockchainAnchorProvider,
    RFC3161AnchorBackend,
)

# ── fake backend ───────────────────────────────────────────────────────────────


class _FakeBackend:
    name = "fake"

    def __init__(self) -> None:
        self.anchored: list[str] = []

    async def anchor(self, root_hash: str) -> AnchorReceipt:
        self.anchored.append(root_hash)
        return AnchorReceipt(
            backend=self.name,
            root_hash=root_hash,
            anchor_ref="ref-" + root_hash[:8],
            timestamp=1.0,
            metadata={"merkle_root": root_hash},
        )

    async def verify(self, receipt: AnchorReceipt, expected_root: str) -> bool:
        return receipt.metadata.get("merkle_root") == expected_root


# ── fail-closed default ────────────────────────────────────────────────────────


class TestFailClosedProvider:
    async def test_publish_raises_without_backend(self):
        provider = BlockchainAnchorProvider()
        assert provider.is_available is False
        assert provider.backend_name == "none"
        with pytest.raises(AnchorUnavailableError, match="refusing to fabricate"):
            await provider.publish_root("a" * 64)

    async def test_verify_returns_false_without_backend(self):
        provider = BlockchainAnchorProvider()
        assert await provider.verify_proof(None, "a" * 64) is False


class TestProviderWithBackend:
    async def test_publish_delegates_to_backend(self):
        backend = _FakeBackend()
        provider = BlockchainAnchorProvider(backend=backend)
        assert provider.is_available is True
        assert provider.backend_name == "fake"
        receipt = await provider.publish_root("b" * 64)
        assert receipt.backend == "fake"
        assert backend.anchored == ["b" * 64]

    async def test_verify_roundtrip(self):
        provider = BlockchainAnchorProvider(backend=_FakeBackend())
        receipt = await provider.publish_root("c" * 64)
        assert await provider.verify_proof(receipt, "c" * 64) is True
        assert await provider.verify_proof(receipt, "d" * 64) is False


# ── RFC3161 backend ────────────────────────────────────────────────────────────


class TestRFC3161AnchorBackend:
    async def test_anchor_success(self):
        ts = MagicMock()
        ts.stamp.return_value = SimpleNamespace(
            success=True,
            token_b64="dG9rZW4=",
            tsa_url="https://tsa.example/tsr",
            package_dict={"merkle_root": "e" * 64, "rfc3161_token_b64": "dG9rZW4="},
        )
        backend = RFC3161AnchorBackend(timestamper=ts)
        receipt = await backend.anchor("e" * 64)
        assert receipt.backend == "rfc3161"
        assert receipt.root_hash == "e" * 64
        assert receipt.verification_url == "https://tsa.example/tsr"
        assert len(receipt.anchor_ref) == 32

    async def test_anchor_failure_raises(self):
        ts = MagicMock()
        ts.stamp.return_value = SimpleNamespace(
            success=False,
            token_b64="",
            tsa_url="",
            package_dict={},
            error="AEGIS_TSA_URL not configured",
        )
        backend = RFC3161AnchorBackend(timestamper=ts)
        with pytest.raises(AnchorUnavailableError, match="RFC3161 anchoring failed"):
            await backend.anchor("f" * 64)

    async def test_verify_true_when_token_valid_and_root_matches(self):
        ts = MagicMock()
        ts.verify.return_value = SimpleNamespace(valid=True, pki_status=0, error="")
        backend = RFC3161AnchorBackend(timestamper=ts)
        receipt = AnchorReceipt(
            backend="rfc3161",
            root_hash="a" * 64,
            anchor_ref="x",
            timestamp=1.0,
            metadata={"merkle_root": "a" * 64},
        )
        assert await backend.verify(receipt, "a" * 64) is True

    async def test_verify_false_on_root_mismatch(self):
        ts = MagicMock()
        ts.verify.return_value = SimpleNamespace(valid=True, pki_status=0, error="")
        backend = RFC3161AnchorBackend(timestamper=ts)
        receipt = AnchorReceipt(
            backend="rfc3161",
            root_hash="a" * 64,
            anchor_ref="x",
            timestamp=1.0,
            metadata={"merkle_root": "a" * 64},
        )
        # Root mismatch must short-circuit to False without trusting the token.
        assert await backend.verify(receipt, "b" * 64) is False
        ts.verify.assert_not_called()


# ── anchoring orchestration ────────────────────────────────────────────────────


class TestAnchorManager:
    async def test_worm_only_when_no_external_backend(self, monkeypatch):
        import aegis.core.anchoring as anchoring

        # Ensure the shared provider is fail-closed for this test.
        monkeypatch.setattr(anchoring.blockchain_provider, "_backend", None, raising=False)
        mgr = anchoring.AnchorManager()
        root = "1" * 64
        proof = await mgr.anchor_root(root)
        assert proof.blockchain_available is False
        assert proof.verification_url == ""
        assert proof.anchor_id.startswith("worm-")
        # WORM-only anchor still verifies against the stored root.
        assert await mgr.verify_anchor(proof.anchor_id, root) is True

    async def test_external_backend_recorded_and_verified(self, monkeypatch):
        import aegis.core.anchoring as anchoring

        monkeypatch.setattr(
            anchoring.blockchain_provider, "_backend", _FakeBackend(), raising=False
        )
        mgr = anchoring.AnchorManager()
        root = "2" * 64
        proof = await mgr.anchor_root(root)
        assert proof.blockchain_available is True
        assert proof.anchor_id.startswith("ref-")
        assert await mgr.verify_anchor(proof.anchor_id, root) is True

    async def test_no_fabricated_proof_fields(self, monkeypatch):
        import aegis.core.anchoring as anchoring

        monkeypatch.setattr(anchoring.blockchain_provider, "_backend", None, raising=False)
        mgr = anchoring.AnchorManager()
        proof = await mgr.anchor_root("3" * 64)
        # No fake explorer URL / tx hash when anchoring is unavailable.
        assert proof.verification_url == ""
        assert "explorer" not in proof.provider.lower()

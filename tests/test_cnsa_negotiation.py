# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for NSA Suite B / CNSA 2.0 algorithm negotiation (aegis.core.cnsa_negotiation)."""

from __future__ import annotations

import json

from aegis.core.cnsa_negotiation import (
    AlgorithmCategory,
    CNSANegotiator,
    CNSASuite,
    NegotiationResult,
)

# ── Registry / Algorithm ───────────────────────────────────────────────────────


class TestAlgorithmRegistry:
    def test_resolve_canonical(self):
        n = CNSANegotiator()
        a = n.resolve("ML-KEM-1024")
        assert a is not None
        assert a.name == "ML-KEM-1024"
        assert a.quantum_resistant is True

    def test_resolve_separator_insensitive(self):
        n = CNSANegotiator()
        assert n.resolve("mlkem1024").name == "ML-KEM-1024"
        assert n.resolve("aes 256 gcm").name == "AES-256-GCM"

    def test_resolve_alias_kyber(self):
        n = CNSANegotiator()
        assert n.resolve("Kyber-1024").name == "ML-KEM-1024"
        assert n.resolve("CRYSTALS-Kyber-1024").name == "ML-KEM-1024"

    def test_resolve_alias_dilithium(self):
        n = CNSANegotiator()
        assert n.resolve("Dilithium-5").name == "ML-DSA-87"
        assert n.resolve("dilithium-3").name == "ML-DSA-65"

    def test_resolve_unknown_returns_none(self):
        n = CNSANegotiator()
        assert n.resolve("ROT13") is None

    def test_approved_for_helper(self):
        n = CNSANegotiator()
        ecdh = n.resolve("ECDH-P384")
        assert ecdh is not None
        assert ecdh.approved_for(CNSASuite.SUITE_B)
        assert ecdh.approved_for(CNSASuite.CNSA_1_0)
        assert not ecdh.approved_for(CNSASuite.CNSA_2_0)


# ── is_approved ────────────────────────────────────────────────────────────────


class TestIsApproved:
    def test_cnsa2_approves_mlkem(self):
        n = CNSANegotiator(required_suite=CNSASuite.CNSA_2_0)
        assert n.is_approved("ML-KEM-1024")

    def test_cnsa2_rejects_ecdh_p384(self):
        n = CNSANegotiator(required_suite=CNSASuite.CNSA_2_0)
        # classical ECDH is not in CNSA 2.0
        assert not n.is_approved("ECDH-P384")

    def test_suiteb_approves_ecdh_p384(self):
        n = CNSANegotiator(required_suite=CNSASuite.SUITE_B)
        assert n.is_approved("ECDH-P384")

    def test_suiteb_approves_aes256(self):
        n = CNSANegotiator(required_suite=CNSASuite.SUITE_B)
        assert n.is_approved("AES-256-GCM")

    def test_cnsa1_rejects_aes128(self):
        n = CNSANegotiator(required_suite=CNSASuite.CNSA_1_0)
        # AES-128 is Suite B only, not CNSA 1.0
        assert not n.is_approved("AES-128-GCM")

    def test_cnsa1_approves_aes256(self):
        n = CNSANegotiator(required_suite=CNSASuite.CNSA_1_0)
        assert n.is_approved("AES-256-GCM")

    def test_unknown_not_approved(self):
        n = CNSANegotiator()
        assert not n.is_approved("DES")

    def test_mandate_qr_rejects_classical_signature(self):
        n = CNSANegotiator(
            required_suite=CNSASuite.SUITE_B, mandate_quantum_resistant=True
        )
        # ECDSA is approved for Suite B but not quantum-resistant
        assert not n.is_approved("ECDSA-P384")

    def test_mandate_qr_allows_symmetric(self):
        n = CNSANegotiator(
            required_suite=CNSASuite.CNSA_2_0, mandate_quantum_resistant=True
        )
        # symmetric/hash not subject to QR mandate
        assert n.is_approved("AES-256-GCM")
        assert n.is_approved("SHA-384")


# ── approved_algorithms ────────────────────────────────────────────────────────


class TestApprovedAlgorithms:
    def test_cnsa2_key_exchange_list(self):
        n = CNSANegotiator(required_suite=CNSASuite.CNSA_2_0)
        kx = n.approved_algorithms(AlgorithmCategory.KEY_EXCHANGE)
        assert "ML-KEM-1024" in kx
        assert "ML-KEM-768" in kx
        assert "ECDH-P384" not in kx

    def test_sorted_strongest_first(self):
        n = CNSANegotiator(required_suite=CNSASuite.CNSA_2_0)
        kx = n.approved_algorithms(AlgorithmCategory.KEY_EXCHANGE)
        # ML-KEM-1024 (256-bit) before ML-KEM-768 (192-bit)
        assert kx.index("ML-KEM-1024") < kx.index("ML-KEM-768")

    def test_suiteb_includes_p256_and_p384(self):
        n = CNSANegotiator(required_suite=CNSASuite.SUITE_B)
        sigs = n.approved_algorithms(AlgorithmCategory.SIGNATURE)
        assert "ECDSA-P256" in sigs
        assert "ECDSA-P384" in sigs

    def test_no_category_returns_all(self):
        n = CNSANegotiator(required_suite=CNSASuite.CNSA_2_0)
        all_approved = n.approved_algorithms()
        assert "AES-256-GCM" in all_approved
        assert "SHA-512" in all_approved
        assert "ML-DSA-87" in all_approved

    def test_mandate_qr_excludes_classical_kx(self):
        n = CNSANegotiator(
            required_suite=CNSASuite.SUITE_B, mandate_quantum_resistant=True
        )
        kx = n.approved_algorithms(AlgorithmCategory.KEY_EXCHANGE)
        # Suite B has only classical KX; with QR mandate the list is empty
        assert kx == []


# ── NegotiationResult ──────────────────────────────────────────────────────────


class TestNegotiationResult:
    def test_defaults(self):
        r = NegotiationResult(suite="cnsa_2_0")
        assert r.compliant is False
        assert r.selected == {}
        assert r.rejected == []
        assert r.missing_categories == []

    def test_to_dict_structure(self):
        r = NegotiationResult(
            suite="cnsa_2_0",
            compliant=True,
            selected={"symmetric": "AES-256-GCM"},
            rejected=[("DES", "unknown algorithm")],
        )
        d = r.to_dict()
        assert d["suite"] == "cnsa_2_0"
        assert d["compliant"] is True
        assert d["selected"] == {"symmetric": "AES-256-GCM"}
        assert d["rejected"] == [("DES", "unknown algorithm")]

    def test_to_dict_json_serializable(self):
        r = NegotiationResult(suite="suite_b", compliant=True)
        json.dumps(r.to_dict())


# ── Negotiation: CNSA 2.0 ──────────────────────────────────────────────────────


class TestNegotiateCNSA2:
    def _full_cnsa2_offer(self) -> list[str]:
        return [
            "ML-KEM-1024", "ML-KEM-768",
            "ML-DSA-87", "ML-DSA-65",
            "AES-256-GCM",
            "SHA-384", "SHA-512",
        ]

    def test_full_offer_compliant(self):
        n = CNSANegotiator(required_suite=CNSASuite.CNSA_2_0)
        r = n.negotiate(self._full_cnsa2_offer())
        assert r.compliant
        assert r.missing_categories == []

    def test_selects_strongest_kx(self):
        n = CNSANegotiator(required_suite=CNSASuite.CNSA_2_0)
        r = n.negotiate(self._full_cnsa2_offer())
        assert r.selected["key_exchange"] == "ML-KEM-1024"

    def test_selects_strongest_signature(self):
        n = CNSANegotiator(required_suite=CNSASuite.CNSA_2_0)
        r = n.negotiate(self._full_cnsa2_offer())
        assert r.selected["signature"] == "ML-DSA-87"

    def test_selects_strongest_hash(self):
        n = CNSANegotiator(required_suite=CNSASuite.CNSA_2_0)
        r = n.negotiate(self._full_cnsa2_offer())
        assert r.selected["hash"] == "SHA-512"

    def test_selects_aes256(self):
        n = CNSANegotiator(required_suite=CNSASuite.CNSA_2_0)
        r = n.negotiate(self._full_cnsa2_offer())
        assert r.selected["symmetric"] == "AES-256-GCM"

    def test_classical_offers_rejected(self):
        n = CNSANegotiator(required_suite=CNSASuite.CNSA_2_0)
        r = n.negotiate(["ECDH-P384", "ECDSA-P384", "AES-256-GCM", "SHA-384", "ML-KEM-1024", "ML-DSA-87"])
        rejected_names = [name for name, _ in r.rejected]
        assert "ECDH-P384" in rejected_names
        assert "ECDSA-P384" in rejected_names

    def test_missing_kx_not_compliant(self):
        n = CNSANegotiator(required_suite=CNSASuite.CNSA_2_0)
        # no key exchange offered
        r = n.negotiate(["ML-DSA-87", "AES-256-GCM", "SHA-384"])
        assert not r.compliant
        assert "key_exchange" in r.missing_categories

    def test_alias_offers_resolved(self):
        n = CNSANegotiator(required_suite=CNSASuite.CNSA_2_0)
        r = n.negotiate(["Kyber-1024", "Dilithium-5", "AES-256-GCM", "SHA-384"])
        assert r.compliant
        assert r.selected["key_exchange"] == "ML-KEM-1024"
        assert r.selected["signature"] == "ML-DSA-87"


# ── Negotiation: Suite B ───────────────────────────────────────────────────────


class TestNegotiateSuiteB:
    def test_classical_offer_compliant(self):
        n = CNSANegotiator(required_suite=CNSASuite.SUITE_B)
        r = n.negotiate(["ECDH-P384", "ECDSA-P384", "AES-256-GCM", "SHA-384"])
        assert r.compliant
        assert r.selected["key_exchange"] == "ECDH-P384"
        assert r.selected["signature"] == "ECDSA-P384"

    def test_prefers_p384_over_p256(self):
        n = CNSANegotiator(required_suite=CNSASuite.SUITE_B)
        r = n.negotiate(
            ["ECDH-P256", "ECDH-P384", "ECDSA-P256", "ECDSA-P384", "AES-256-GCM", "SHA-384"]
        )
        assert r.selected["key_exchange"] == "ECDH-P384"
        assert r.selected["signature"] == "ECDSA-P384"

    def test_prefers_aes256_over_aes128(self):
        n = CNSANegotiator(required_suite=CNSASuite.SUITE_B)
        r = n.negotiate(
            ["ECDH-P256", "ECDSA-P256", "AES-128-GCM", "AES-256-GCM", "SHA-256"]
        )
        assert r.selected["symmetric"] == "AES-256-GCM"

    def test_pqc_offers_rejected_in_suiteb(self):
        n = CNSANegotiator(required_suite=CNSASuite.SUITE_B)
        r = n.negotiate(["ECDH-P256", "ECDSA-P256", "AES-128-GCM", "SHA-256", "ML-KEM-1024"])
        rejected_names = [name for name, _ in r.rejected]
        assert "ML-KEM-1024" in rejected_names


# ── Negotiation: rejections & edge cases ───────────────────────────────────────


class TestNegotiationEdgeCases:
    def test_unknown_algorithm_rejected(self):
        n = CNSANegotiator(required_suite=CNSASuite.CNSA_2_0)
        r = n.negotiate(["DES", "MD5", "ML-KEM-1024", "ML-DSA-87", "AES-256-GCM", "SHA-384"])
        reasons = dict(r.rejected)
        assert reasons.get("DES") == "unknown algorithm"
        assert reasons.get("MD5") == "unknown algorithm"

    def test_empty_offer_not_compliant(self):
        n = CNSANegotiator(required_suite=CNSASuite.CNSA_2_0)
        r = n.negotiate([])
        assert not r.compliant
        assert len(r.missing_categories) == 4

    def test_reason_mentions_failure(self):
        n = CNSANegotiator(required_suite=CNSASuite.CNSA_2_0)
        r = n.negotiate(["AES-256-GCM"])
        assert "FAILED" in r.reason

    def test_reason_mentions_success(self):
        n = CNSANegotiator(required_suite=CNSASuite.SUITE_B)
        r = n.negotiate(["ECDH-P384", "ECDSA-P384", "AES-256-GCM", "SHA-384"])
        assert "succeeded" in r.reason

    def test_required_categories_subset(self):
        # only require symmetric + hash
        n = CNSANegotiator(
            required_suite=CNSASuite.CNSA_2_0,
            required_categories={AlgorithmCategory.SYMMETRIC, AlgorithmCategory.HASH},
        )
        r = n.negotiate(["AES-256-GCM", "SHA-384"])
        assert r.compliant

    def test_mandate_qr_full_negotiation(self):
        n = CNSANegotiator(
            required_suite=CNSASuite.CNSA_2_0, mandate_quantum_resistant=True
        )
        r = n.negotiate(["ML-KEM-1024", "ML-DSA-87", "AES-256-GCM", "SHA-384"])
        assert r.compliant


# ── Integration scenarios ──────────────────────────────────────────────────────


class TestIntegrationScenarios:
    def test_downgrade_attack_refused(self):
        """A peer that only offers classical algorithms must fail a CNSA 2.0 mandate."""
        n = CNSANegotiator(required_suite=CNSASuite.CNSA_2_0)
        r = n.negotiate(["ECDH-P256", "ECDSA-P256", "AES-128-GCM", "SHA-256"])
        assert not r.compliant
        # every offer rejected as not approved for cnsa_2_0
        assert len(r.rejected) == 4

    def test_mixed_offer_picks_compliant_subset(self):
        """A peer offering both classical and PQC gets the PQC subset under CNSA 2.0."""
        n = CNSANegotiator(required_suite=CNSASuite.CNSA_2_0)
        r = n.negotiate(
            [
                "ECDH-P384", "ML-KEM-1024",      # KX: one classical (reject), one PQC
                "ECDSA-P384", "ML-DSA-87",       # SIG: one classical (reject), one PQC
                "AES-128-GCM", "AES-256-GCM",    # SYM: pick 256
                "SHA-256", "SHA-384",            # HASH: pick 384 (256 not in CNSA2)
            ]
        )
        assert r.compliant
        assert r.selected["key_exchange"] == "ML-KEM-1024"
        assert r.selected["signature"] == "ML-DSA-87"
        assert r.selected["symmetric"] == "AES-256-GCM"
        assert r.selected["hash"] == "SHA-384"
        rejected_names = {name for name, _ in r.rejected}
        assert "ECDH-P384" in rejected_names
        assert "SHA-256" in rejected_names

    def test_to_dict_json_full_pipeline(self):
        n = CNSANegotiator(required_suite=CNSASuite.CNSA_2_0)
        r = n.negotiate(["ML-KEM-1024", "ML-DSA-87", "AES-256-GCM", "SHA-384"])
        json.dumps(r.to_dict())

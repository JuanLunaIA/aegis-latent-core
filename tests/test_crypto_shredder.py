# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

"""Cryptographic erasure: the plaintext goes, the tree does not move.

The property the whole design exists for is in ``TestTreeInvariance``: after a
subject's key is destroyed, the MMR root and every previously issued inclusion
proof must be bit-for-bit what they were. If erasure moved the root it would be
a deletion, and the ledger's own integrity check would call an untampered chain
corrupt.

Scope. This exercises the mechanism. It establishes nothing about key material
surviving on the physical medium — page cache, journals, swap, snapshots,
backups and SSD wear-levelling are all outside a Python process's control — and
nothing legal. See the module docstring and ``CLM-068``.
"""

from __future__ import annotations

import hashlib

import pytest

from aegis.core.crypto_shredder import (
    CryptoShredder,
    SealedPayload,
    ShredderIntegrityError,
    ShredderKeyDestroyedError,
)
from aegis.core.mmr import MerkleMountainRange


@pytest.fixture
def shredder():
    with CryptoShredder() as s:
        yield s


class TestSealAndOpen:
    def test_a_sealed_payload_round_trips(self, shredder):
        sealed = shredder.seal("subject-a", b"clinical note")
        assert shredder.open(sealed) == b"clinical note"

    def test_the_ciphertext_does_not_contain_the_plaintext(self, shredder):
        sealed = shredder.seal("subject-a", b"SUPER-SECRET-VALUE")
        assert b"SUPER-SECRET-VALUE" not in sealed.ciphertext

    def test_each_seal_uses_a_fresh_nonce(self, shredder):
        """GCM nonce reuse under one key is catastrophic, so pin it."""

        nonces = {shredder.seal("subject-a", b"same").nonce for _ in range(50)}
        assert len(nonces) == 50

    def test_identical_plaintext_seals_to_different_ciphertext(self, shredder):
        a = shredder.seal("subject-a", b"identical")
        b = shredder.seal("subject-a", b"identical")
        assert a.ciphertext != b.ciphertext
        assert a.commitment != b.commitment

    def test_subjects_get_independent_keys(self, shredder):
        a = shredder.seal("subject-a", b"payload")
        shredder.seal("subject-b", b"payload")
        shredder.erase("subject-b")
        # Erasing b must not affect a.
        assert shredder.open(a) == b"payload"

    def test_a_ciphertext_cannot_be_replayed_under_another_subject(self, shredder):
        sealed = shredder.seal("subject-a", b"payload")
        shredder.seal("subject-b", b"unrelated")
        forged = SealedPayload("subject-b", sealed.nonce, sealed.ciphertext)
        with pytest.raises(ShredderIntegrityError):
            shredder.open(forged)

    def test_a_tampered_ciphertext_is_rejected(self, shredder):
        sealed = shredder.seal("subject-a", b"payload")
        flipped = bytearray(sealed.ciphertext)
        flipped[0] ^= 0x01
        with pytest.raises(ShredderIntegrityError):
            shredder.open(SealedPayload("subject-a", sealed.nonce, bytes(flipped)))

    def test_an_empty_subject_id_is_refused(self, shredder):
        with pytest.raises(ValueError, match="must not be empty"):
            shredder.seal("", b"payload")


class TestErasure:
    def test_after_erasure_the_plaintext_is_unrecoverable(self, shredder):
        sealed = shredder.seal("subject-a", b"right to be forgotten")
        assert shredder.open(sealed) == b"right to be forgotten"

        assert shredder.erase("subject-a") is True

        with pytest.raises(ShredderKeyDestroyedError):
            shredder.open(sealed)

    def test_erasure_is_distinguishable_from_corruption(self, shredder):
        """An operator must be able to tell the two apart."""

        erased = shredder.seal("subject-a", b"payload")
        corrupt = shredder.seal("subject-b", b"payload")
        shredder.erase("subject-a")

        with pytest.raises(ShredderKeyDestroyedError):
            shredder.open(erased)

        flipped = bytearray(corrupt.ciphertext)
        flipped[0] ^= 0xFF
        with pytest.raises(ShredderIntegrityError):
            shredder.open(SealedPayload("subject-b", corrupt.nonce, bytes(flipped)))

    def test_erasure_is_idempotent(self, shredder):
        shredder.seal("subject-a", b"payload")
        assert shredder.erase("subject-a") is True
        assert shredder.erase("subject-a") is False

    def test_erasing_an_unknown_subject_is_not_an_error(self, shredder):
        assert shredder.erase("never-existed") is False

    def test_has_key_reports_the_vault_state(self, shredder):
        shredder.seal("subject-a", b"payload")
        assert shredder.has_key("subject-a") is True
        shredder.erase("subject-a")
        assert shredder.has_key("subject-a") is False

    def test_the_ciphertext_survives_erasure_untouched(self, shredder):
        """Erasure destroys the key, not the record."""

        sealed = shredder.seal("subject-a", b"payload")
        before = (sealed.nonce, sealed.ciphertext, sealed.commitment)
        shredder.erase("subject-a")
        assert (sealed.nonce, sealed.ciphertext, sealed.commitment) == before

    def test_a_resealed_subject_cannot_open_pre_erasure_records(self, shredder):
        """A new key is a new key; the old ciphertext stays dead."""

        old = shredder.seal("subject-a", b"old payload")
        shredder.erase("subject-a")
        shredder.seal("subject-a", b"new payload")

        with pytest.raises(ShredderIntegrityError):
            shredder.open(old)


class TestTreeInvariance:
    """The point of the whole design."""

    def test_the_mmr_root_does_not_move_when_a_key_is_destroyed(self, shredder):
        mmr = MerkleMountainRange()
        sealed = [shredder.seal(f"subject-{i}", f"record {i}".encode()) for i in range(7)]
        for payload in sealed:
            mmr.add_leaf(payload.commitment)

        root_before = mmr.get_root_hash()
        peaks_before = list(mmr.peaks)

        shredder.erase("subject-3")

        assert mmr.get_root_hash() == root_before
        assert list(mmr.peaks) == peaks_before

    def test_an_inclusion_proof_issued_before_erasure_still_verifies(self, shredder):
        mmr = MerkleMountainRange()
        sealed = [shredder.seal(f"subject-{i}", f"record {i}".encode()) for i in range(11)]
        for payload in sealed:
            mmr.add_leaf(payload.commitment)

        target = 3
        proof = mmr.get_portable_inclusion_proof(target)
        trusted_root = mmr.get_root_hash()
        leaf_digest = hashlib.sha256(sealed[target].commitment).hexdigest()

        assert mmr.verify_portable_inclusion_hash(leaf_digest, proof, trusted_root)

        shredder.erase(f"subject-{target}")

        # The record is unreadable, and the proof that it is in the tree is
        # exactly as valid as it was.
        with pytest.raises(ShredderKeyDestroyedError):
            shredder.open(sealed[target])
        assert mmr.verify_portable_inclusion_hash(leaf_digest, proof, trusted_root)
        assert mmr.get_root_hash() == trusted_root

    def test_erasing_every_subject_leaves_the_tree_intact(self, shredder):
        mmr = MerkleMountainRange()
        sealed = [shredder.seal(f"subject-{i}", b"payload") for i in range(8)]
        for payload in sealed:
            mmr.add_leaf(payload.commitment)
        root_before = mmr.get_root_hash()

        for i in range(8):
            shredder.erase(f"subject-{i}")

        assert mmr.get_root_hash() == root_before
        assert all(not shredder.has_key(f"subject-{i}") for i in range(8))


class TestCommitment:
    def test_the_commitment_is_domain_separated(self, shredder):
        sealed = shredder.seal("subject-a", b"payload")
        assert (
            sealed.commitment == hashlib.sha256(b"\x00" + sealed.nonce + sealed.ciphertext).digest()
        )

    def test_the_commitment_covers_the_nonce(self, shredder):
        """Committing to the ciphertext alone would leave the nonce swappable."""

        sealed = shredder.seal("subject-a", b"payload")
        other_nonce = bytes(b ^ 0xFF for b in sealed.nonce)
        swapped = SealedPayload("subject-a", other_nonce, sealed.ciphertext)
        assert swapped.commitment != sealed.commitment

    def test_commitment_hex_is_lowercase_sha256(self, shredder):
        hexed = shredder.seal("subject-a", b"payload").commitment_hex
        assert len(hexed) == 64
        assert hexed == hexed.lower()
        int(hexed, 16)


class TestVaultPersistence:
    def test_keys_survive_reopening_a_file_vault(self, tmp_path):
        vault = tmp_path / "shred_vault.db"
        with CryptoShredder(vault) as first:
            sealed = first.seal("subject-a", b"persisted")
        with CryptoShredder(vault) as second:
            assert second.open(sealed) == b"persisted"

    def test_erasure_survives_reopening(self, tmp_path):
        vault = tmp_path / "shred_vault.db"
        with CryptoShredder(vault) as first:
            sealed = first.seal("subject-a", b"persisted")
            first.erase("subject-a")
        with CryptoShredder(vault) as second:
            with pytest.raises(ShredderKeyDestroyedError):
                second.open(sealed)

    def test_a_file_vault_is_owner_only(self, tmp_path):
        vault = tmp_path / "shred_vault.db"
        with CryptoShredder(vault):
            pass
        assert (vault.stat().st_mode & 0o777) == 0o600

    def test_the_erased_key_is_not_left_in_the_vault_file(self, tmp_path):
        """A weaker check than sanitisation, and named as such.

        It shows the freed page is not still sitting in the file after VACUUM.
        It says nothing about the journal, the page cache, or the physical
        medium — see the module docstring.
        """

        vault = tmp_path / "shred_vault.db"
        with CryptoShredder(vault) as s:
            s.seal("subject-a", b"payload")
            key = s._fetch_key("subject-a")
            assert key is not None
            assert key in vault.read_bytes()
            s.erase("subject-a")
            assert key not in vault.read_bytes()

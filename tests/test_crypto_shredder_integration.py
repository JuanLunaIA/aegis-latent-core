# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

"""Cryptographic erasure on the live ledger commit path.

An append-only Merkle ledger and a right-to-erasure request pull in opposite
directions: deleting a record rewrites every downstream hash and invalidates
the root. Cryptographic erasure sidesteps that by committing to a *ciphertext*
and destroying the key instead of the record.

The property that makes it work is that the commitment,
``SHA-256(0x00 || nonce || ciphertext)``, is computable by anyone holding the
ciphertext and **not** the key. So an inclusion proof issued before erasure
still verifies afterwards: destroying the key removes the ability to read the
leaf and moves no hash the tree is built from.

What these tests do not establish
---------------------------------

That the key is gone from the physical medium. This runs in CPython on a
general-purpose OS, and pages the allocator copied, the SQLite journal,
filesystem journaling, page cache, swap, snapshots, backups, replicas and SSD
wear-levelling are all outside its control. Nor do they establish that erasure
satisfies any particular regulation, which is a legal question this code does
not answer. And the node still carries the request and response *digests* —
not plaintext, but a guessed plaintext can be confirmed against them.

Calls with side effects are assigned before being asserted on, never called
inside the ``assert`` itself (``python -O`` strips asserts; CodeQL flags this as
py/side-effect-in-assert).
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from aegis.core.crypto_audit import CryptographicAuditLedger
from aegis.core.crypto_shredder import ShredderKeyDestroyedError
from aegis.core.mmr import MerkleMountainRange, MMRInclusionProofV1

SIGNING_KEY = "k" * 32
SECRET = b"PATIENT SSN 123-45-6789 and a diagnosis"


def _sealing_ledger(tmp_path: Path, name: str = "sealed") -> CryptographicAuditLedger:
    return CryptographicAuditLedger(
        persistence_path=str(tmp_path / f"{name}.wal"),
        signing_key=SIGNING_KEY,
        enable_cryptographic_shredding=True,
    )


class TestErasureLeavesTheTreeUnmoved:
    """The three properties the whole design exists to deliver."""

    def test_proof_survives_plaintext_does_not_and_the_root_does_not_move(
        self, tmp_path: Path
    ) -> None:
        with _sealing_ledger(tmp_path) as ledger:
            # Commit the subject's record last, so its proof is against the
            # root that is current when erasure happens. An inclusion proof is
            # always against the root of its own moment.
            for index in range(4):
                ledger.commit_forensic(
                    state_id=f"other-{index}", request_bytes=b"x", tenant_id="subject-B"
                )
            node = ledger.commit_forensic(
                state_id="req-1",
                request_bytes=SECRET,
                response_bytes=b"diagnosis",
                tenant_id="subject-A",
            )

            root_before = ledger._mmr.get_root_hash()
            proof = MMRInclusionProofV1.from_dict(node.mmr_proof or {})
            valid_before = MerkleMountainRange.verify_portable_inclusion_hash(
                node.mmr_leaf_hash, proof, root_before
            )
            assert valid_before is True
            opened = ledger.open_sealed_leaf(node)
            assert SECRET.hex() in opened.decode()

            erased = ledger.crypto_shred("subject-A")
            assert erased is True

            root_after = ledger._mmr.get_root_hash()
            valid_after = MerkleMountainRange.verify_portable_inclusion_hash(
                node.mmr_leaf_hash, proof, root_after
            )

            # (a) the proof still verifies, (b) the plaintext is gone,
            # (c) the root did not move.
            assert valid_after is True
            with pytest.raises(ShredderKeyDestroyedError):
                ledger.open_sealed_leaf(node)
            assert root_after == root_before

    def test_the_chain_still_verifies_after_erasure(self, tmp_path: Path) -> None:
        with _sealing_ledger(tmp_path, "chain") as ledger:
            for index in range(5):
                ledger.commit_forensic(
                    state_id=f"r{index}", request_bytes=SECRET, tenant_id="subject-A"
                )
            ledger.crypto_shred("subject-A")
            valid, index = ledger.verify_integrity()

        assert valid is True
        assert index is None

    def test_erasing_one_subject_leaves_the_others_readable(self, tmp_path: Path) -> None:
        # Erasure has to be per subject or it is not erasure, it is deletion.
        with _sealing_ledger(tmp_path, "subjects") as ledger:
            kept = ledger.commit_forensic(
                state_id="keep", request_bytes=b"other tenant", tenant_id="subject-B"
            )
            ledger.commit_forensic(state_id="drop", request_bytes=SECRET, tenant_id="subject-A")
            ledger.crypto_shred("subject-A")

            still_readable = ledger.open_sealed_leaf(kept)
            assert b"other tenant".hex() in still_readable.decode()

    def test_erasure_is_idempotent(self, tmp_path: Path) -> None:
        # A retention job that re-runs must not fail.
        with _sealing_ledger(tmp_path, "idem") as ledger:
            ledger.commit_forensic(state_id="r", request_bytes=SECRET, tenant_id="subject-A")
            first = ledger.crypto_shred("subject-A")
            second = ledger.crypto_shred("subject-A")

        assert first is True
        assert second is False


class TestTheCommitment:
    """What the MMR commits to when sealing is on."""

    def test_the_leaf_digest_is_the_declared_commitment(self, tmp_path: Path) -> None:
        with _sealing_ledger(tmp_path, "commitment") as ledger:
            node = ledger.commit_forensic(state_id="r", request_bytes=SECRET, tenant_id="subject-A")
            expected = hashlib.sha256(
                b"\x00" + bytes.fromhex(node.sealed_nonce) + bytes.fromhex(node.sealed_ciphertext)
            ).hexdigest()

        assert node.mmr_leaf_hash == expected

    def test_the_commitment_is_computable_without_the_key(self, tmp_path: Path) -> None:
        # This is the whole mechanism: a verifier who cannot read the leaf can
        # still recompute what the tree committed to, which is why erasure does
        # not invalidate a proof.
        with _sealing_ledger(tmp_path, "nokey") as ledger:
            node = ledger.commit_forensic(state_id="r", request_bytes=SECRET, tenant_id="subject-A")
            ledger.crypto_shred("subject-A")
            recomputed = hashlib.sha256(
                b"\x00" + bytes.fromhex(node.sealed_nonce) + bytes.fromhex(node.sealed_ciphertext)
            ).hexdigest()

        assert recomputed == node.mmr_leaf_hash

    def test_the_plaintext_is_not_in_the_stored_ciphertext(self, tmp_path: Path) -> None:
        with _sealing_ledger(tmp_path, "opaque") as ledger:
            node = ledger.commit_forensic(state_id="r", request_bytes=SECRET, tenant_id="subject-A")

        assert SECRET not in bytes.fromhex(node.sealed_ciphertext)

    def test_a_rejection_without_a_tenant_seals_under_unattributed(self, tmp_path: Path) -> None:
        # A request refused before authentication has no subject to attribute
        # erasure to, and must not be filed under a tenant never established.
        with _sealing_ledger(tmp_path, "reject") as ledger:
            node = ledger.commit_rejection(
                request_bytes=b"blocked", rejection_code=403, reason_category="waf_block"
            )

        assert node.sealed_subject_id == "unattributed"


class TestDisabledByDefault:
    """Every existing deployment must be untouched by the option existing."""

    def test_a_default_ledger_seals_nothing(self, tmp_path: Path) -> None:
        with CryptographicAuditLedger(
            str(tmp_path / "plain.wal"), signing_key=SIGNING_KEY
        ) as ledger:
            node = ledger.commit_forensic(state_id="r", request_bytes=SECRET, tenant_id="subject-A")

        assert node.sealed_ciphertext == ""
        assert node.sealed_nonce == ""
        assert node.sealed_subject_id == ""

    def test_the_config_default_is_off(self) -> None:
        from aegis.config import AegisSettings

        settings = AegisSettings(backend_api_key="k")
        assert settings.enable_cryptographic_shredding is False

    def test_shredding_on_a_plain_ledger_refuses_rather_than_no_ops(self, tmp_path: Path) -> None:
        # Silently returning False would let a retention job believe it had
        # erased something it never could.
        with CryptographicAuditLedger(
            str(tmp_path / "plain2.wal"), signing_key=SIGNING_KEY
        ) as ledger:
            with pytest.raises(RuntimeError, match="not enabled"):
                ledger.crypto_shred("subject-A")

    def test_a_sealing_ledger_replays_its_own_wal(self, tmp_path: Path) -> None:
        wal = tmp_path / "replay.wal"
        with CryptographicAuditLedger(
            str(wal), signing_key=SIGNING_KEY, enable_cryptographic_shredding=True
        ) as first:
            for index in range(4):
                first.commit_forensic(
                    state_id=f"r{index}", request_bytes=SECRET, tenant_id="subject-A"
                )
            root_before = first.chain[-1].merkle_root

        with CryptographicAuditLedger(
            str(wal), signing_key=SIGNING_KEY, enable_cryptographic_shredding=True
        ) as reopened:
            assert reopened._fault_state == "healthy"
            assert reopened.chain[-1].merkle_root == root_before
            valid, index = reopened.verify_integrity()
            assert valid is True
            assert index is None


class TestShreddingVersion:
    """Which construction produced a record's commitment.

    `sealed_ciphertext` already tells a reader *that* a node is sealed; this
    field says *how*. Its whole reason to exist is a migration one -- see
    `aegis.core.crypto_shredder`'s comment beside `SHRED_SCHEME_V1` -- so what
    these tests pin down is that the label always tracks the envelope it
    describes, never the other way around.
    """

    def test_an_unsealed_node_carries_the_empty_scheme(self, tmp_path: Path) -> None:
        with CryptographicAuditLedger(
            str(tmp_path / "plain.wal"), signing_key=SIGNING_KEY
        ) as ledger:
            node = ledger.commit_forensic(state_id="r", request_bytes=SECRET, tenant_id="s")

        from aegis.core.crypto_shredder import SHRED_SCHEME_UNSEALED

        assert node.shredding_version == SHRED_SCHEME_UNSEALED
        assert node.sealed_ciphertext == ""

    def test_a_sealed_node_names_the_construction_that_sealed_it(self, tmp_path: Path) -> None:
        with _sealing_ledger(tmp_path) as ledger:
            node = ledger.commit_forensic(state_id="r", request_bytes=SECRET, tenant_id="s")

        from aegis.core.crypto_shredder import SHRED_SCHEME_V1

        assert node.shredding_version == SHRED_SCHEME_V1
        assert node.sealed_ciphertext != ""

    def test_enabling_shredding_on_an_existing_plain_chain_is_supported_not_refused(
        self, tmp_path: Path
    ) -> None:
        """The question the field exists to let a reader answer for themselves.

        Toggling the flag on does not retroactively seal history -- there is
        no re-sealing pass -- and it is not refused either: new writes are
        sealed going forward, on the same WAL, in the same verified chain.
        `shredding_version` is what lets a reader tell the two node kinds
        apart without inferring it from whether `sealed_ciphertext` is empty
        for a reason they have to reconstruct themselves.
        """
        wal = tmp_path / "mixed.wal"
        with CryptographicAuditLedger(str(wal), signing_key=SIGNING_KEY) as first:
            first.commit_forensic(state_id="before", request_bytes=SECRET, tenant_id="s")

        with CryptographicAuditLedger(
            str(wal), signing_key=SIGNING_KEY, enable_cryptographic_shredding=True
        ) as second:
            second.commit_forensic(state_id="after", request_bytes=SECRET, tenant_id="s")

            versions = [node.shredding_version for node in second.chain]
            from aegis.core.crypto_shredder import SHRED_SCHEME_UNSEALED, SHRED_SCHEME_V1

            assert versions == [SHRED_SCHEME_UNSEALED, SHRED_SCHEME_V1]
            assert second.chain[0].sealed_ciphertext == ""
            assert second.chain[1].sealed_ciphertext != ""

            valid, broken_at = second.verify_integrity()
            assert valid is True
            assert broken_at is None

    def test_a_never_sealed_legacy_line_loads_with_the_unsealed_default(
        self, tmp_path: Path
    ) -> None:
        """The ordinary case: no field, no ciphertext, genuinely never sealed."""
        import json

        from aegis.core.crypto_audit import AuditNode
        from aegis.core.crypto_shredder import SHRED_SCHEME_UNSEALED

        with CryptographicAuditLedger(
            str(tmp_path / "plain.wal"), signing_key=SIGNING_KEY
        ) as ledger:
            node = ledger.commit_forensic(state_id="r", request_bytes=SECRET, tenant_id="s")
        record = node.to_dict()
        del record["shredding_version"]

        reloaded = AuditNode.from_dict(json.loads(json.dumps(record)))
        assert reloaded.shredding_version == SHRED_SCHEME_UNSEALED

    def test_a_legacy_sealed_line_without_the_field_infers_v1_from_the_ciphertext(
        self, tmp_path: Path
    ) -> None:
        """The case a flat default would get wrong.

        `sealed_subject_id`/`sealed_nonce`/`sealed_ciphertext` predate
        `shredding_version`: a node the shredder sealed before this field
        existed has real ciphertext and no version key. Defaulting that to the
        *unsealed* marker would misreport a genuinely sealed record. Since
        SHRED_SCHEME_V1 is the only construction that has ever produced
        ciphertext here, a non-empty `sealed_ciphertext` with no version key
        can only mean that one -- see `from_dict`'s conditional default.
        """
        import json

        from aegis.core.crypto_audit import AuditNode
        from aegis.core.crypto_shredder import SHRED_SCHEME_V1

        with _sealing_ledger(tmp_path, "source") as ledger:
            node = ledger.commit_forensic(state_id="r", request_bytes=SECRET, tenant_id="s")
        record = node.to_dict()
        assert record["sealed_ciphertext"] != ""  # sanity: this one really was sealed
        del record["shredding_version"]  # simulate the pre-existing-field WAL shape

        reloaded = AuditNode.from_dict(json.loads(json.dumps(record)))
        assert reloaded.shredding_version == SHRED_SCHEME_V1
        assert reloaded.node_hash == node.node_hash  # unbound: reload must not move it

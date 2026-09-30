# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

"""An asymmetric signature attributes a record only under a pinned key.

``specs/aegis_ledger_immutability.tla`` separates two verifiers. One reads the
public key out of the record it is checking; the other holds the keys it
trusts. With the unpinned verifier (``aegis_ledger_immutability_unpinned.cfg``)
TLC finds the trace this file reproduces on the real class: an attacker who
can write the WAL mints a key of their own, rebuilds the chain with whatever
content they like, re-signs every node, and each signature checks against the
key the forged node carries. Before this change ``signature_status`` answered
``valid`` for such a chain and ``verify_integrity`` passed.

The ledger now pins keys (``_trusted_signing_keys``): its own ML-DSA identity
plus the ``trusted_public_keys`` allowlist (``AEGIS_TRUSTED_SIGNING_PUBLIC_KEYS``).
These tests pin the resulting behaviour:

* a chain re-signed under another identity is ``invalid`` and fails
  ``verify_integrity`` for a verifier that holds the real identity;
* the genuine chain still verifies, and a rotated or HA peer identity verifies
  once it is listed, and only then;
* a verifier that pins nothing reports ``unverified`` and the ``UNSIGNED``
  assurance floor instead of attributing the chain, and strict mode fails it;
* ``ed25519-fallback`` keys, minted per node, never read as ``valid``;
* the allowlist is validated at construction and in the settings.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from pydantic import ValidationError

from aegis.config import AegisSettings
from aegis.core.crypto_audit import (
    CryptographicAuditLedger,
    SignatureAssurance,
    chain_signature_assurance,
    normalise_trusted_public_keys,
)

SIGNING_KEY = "key-pinning-test-key"

pytest.importorskip("aegis_rust")


def _write_chain(wal: Path, identity: Path, count: int = 3) -> str:
    """Write ``count`` ML-DSA-signed nodes and return the identity's public key."""
    with CryptographicAuditLedger(
        str(wal), signing_key=SIGNING_KEY, pqc_identity_path=str(identity)
    ) as ledger:
        keys = {
            ledger.commit_state(f"s{index}", 0.5, b"payload").public_key for index in range(count)
        }
    assert len(keys) == 1
    return keys.pop()


def _statuses(ledger: CryptographicAuditLedger) -> set[str]:
    return {ledger.signature_status(node) for node in ledger.chain}


@pytest.fixture
def genuine(tmp_path: Path) -> tuple[Path, Path, str]:
    wal = tmp_path / "genuine" / "audit.jsonl"
    wal.parent.mkdir()
    identity = tmp_path / "keys" / "deployment.pqc"
    public_key = _write_chain(wal, identity)
    return wal, identity, public_key


class TestAForgedChainDoesNotVerify:
    def test_a_chain_re_signed_under_another_identity_is_invalid(
        self, tmp_path: Path, genuine: tuple[Path, Path, str]
    ) -> None:
        _, identity, deployment_key = genuine
        # The attacker's chain: same shape, their own identity, their content.
        forged = tmp_path / "forged" / "audit.jsonl"
        forged.parent.mkdir()
        attacker_key = _write_chain(forged, tmp_path / "attacker.pqc")
        assert attacker_key != deployment_key

        with CryptographicAuditLedger(
            str(forged), signing_key=SIGNING_KEY, pqc_identity_path=str(identity)
        ) as verifier:
            assert _statuses(verifier) == {"invalid"}
            assert verifier.verify_integrity() == (False, 0)
            assert verifier.signature_assurance == SignatureAssurance.UNSIGNED

    def test_the_same_forgery_checked_against_its_own_key_would_pass(
        self, tmp_path: Path, genuine: tuple[Path, Path, str]
    ) -> None:
        # Control: the forged signatures are real ML-DSA signatures. The only
        # thing that rejects them above is the pin. A verifier that pins the
        # attacker's key accepts them, which is exactly what reading the key
        # out of the record amounted to.
        forged = tmp_path / "forged" / "audit.jsonl"
        forged.parent.mkdir()
        attacker_key = _write_chain(forged, tmp_path / "attacker.pqc")
        with CryptographicAuditLedger(
            str(forged), signing_key=SIGNING_KEY, trusted_public_keys=[attacker_key]
        ) as verifier:
            assert _statuses(verifier) == {"valid"}


class TestTheGenuineChainStillVerifies:
    def test_under_its_own_identity(self, genuine: tuple[Path, Path, str]) -> None:
        wal, identity, _ = genuine
        with CryptographicAuditLedger(
            str(wal), signing_key=SIGNING_KEY, pqc_identity_path=str(identity)
        ) as verifier:
            assert _statuses(verifier) == {"valid"}
            assert verifier.verify_integrity() == (True, None)
            assert verifier.signature_assurance == SignatureAssurance.ASYMMETRIC_SOFTWARE

    def test_under_a_listed_key_without_the_identity_file(
        self, genuine: tuple[Path, Path, str]
    ) -> None:
        # An offline verifier needs only the public key, never the private one.
        wal, _, public_key = genuine
        with CryptographicAuditLedger(
            str(wal), signing_key=SIGNING_KEY, trusted_public_keys=[public_key.upper()]
        ) as verifier:
            assert _statuses(verifier) == {"valid"}
            assert verifier.signature_assurance == SignatureAssurance.ASYMMETRIC_SOFTWARE

    def test_after_a_rotation_only_when_the_old_key_is_listed(
        self, tmp_path: Path, genuine: tuple[Path, Path, str]
    ) -> None:
        wal, _, old_key = genuine
        rotated = tmp_path / "keys" / "rotated.pqc"
        _write_chain(tmp_path / "scratch.jsonl", rotated, count=1)

        with CryptographicAuditLedger(
            str(wal), signing_key=SIGNING_KEY, pqc_identity_path=str(rotated)
        ) as undeclared:
            # A rotation nobody declared is indistinguishable from a forgery.
            assert _statuses(undeclared) == {"invalid"}
            assert undeclared.verify_integrity() == (False, 0)

        with CryptographicAuditLedger(
            str(wal),
            signing_key=SIGNING_KEY,
            pqc_identity_path=str(rotated),
            trusted_public_keys=[old_key],
        ) as declared:
            assert _statuses(declared) == {"valid"}
            assert declared.verify_integrity() == (True, None)

    def test_a_chain_written_by_two_replicas_needs_both_keys(self, tmp_path: Path) -> None:
        # Active-active HA: two writers, two identities, one chain. Each
        # replica's verifier must list the other's key.
        wal = tmp_path / "shared.jsonl"
        replica_a = tmp_path / "a.pqc"
        replica_b = tmp_path / "b.pqc"
        key_a = _write_chain(wal, replica_a, count=2)
        key_b = _write_chain(wal, replica_b, count=2)
        assert key_a != key_b

        with CryptographicAuditLedger(
            str(wal), signing_key=SIGNING_KEY, pqc_identity_path=str(replica_a)
        ) as alone:
            assert [alone.signature_status(node) for node in alone.chain] == [
                "valid",
                "valid",
                "invalid",
                "invalid",
            ]
            assert alone.verify_integrity() == (False, 2)

        with CryptographicAuditLedger(
            str(wal),
            signing_key=SIGNING_KEY,
            pqc_identity_path=str(replica_a),
            trusted_public_keys=[key_b],
        ) as peered:
            assert _statuses(peered) == {"valid"}
            assert peered.verify_integrity() == (True, None)


class TestAVerifierThatPinsNothing:
    def test_reports_unverified_and_the_unsigned_floor(
        self, genuine: tuple[Path, Path, str]
    ) -> None:
        wal, _, _ = genuine
        with CryptographicAuditLedger(str(wal), signing_key=SIGNING_KEY) as verifier:
            assert _statuses(verifier) == {"unverified"}
            # Outside strict mode an unattributed signature is not a violation:
            # nothing contradicts it, and nothing attributes it either.
            assert verifier.verify_integrity() == (True, None)
            assert verifier.signature_assurance == SignatureAssurance.UNSIGNED

    def test_fails_in_strict_mode(self, genuine: tuple[Path, Path, str]) -> None:
        wal, _, _ = genuine
        with CryptographicAuditLedger(
            str(wal), signing_key=SIGNING_KEY, require_strong_signing=True
        ) as verifier:
            assert verifier.verify_integrity() == (False, 0)

    def test_a_tampered_signature_is_still_invalid(
        self, tmp_path: Path, genuine: tuple[Path, Path, str]
    ) -> None:
        # Pinning nothing does not weaken detection: a signature that does not
        # check against the record's own key is a positive finding.
        wal, _, _ = genuine
        tampered = tmp_path / "tampered.jsonl"
        shutil.copy(wal, tampered)
        lines = tampered.read_text(encoding="utf-8").splitlines()

        record = json.loads(lines[1])
        signature = record["signature"]
        record["signature"] = ("0" if signature[0] != "0" else "1") + signature[1:]
        lines[1] = json.dumps(record, separators=(",", ":"))
        tampered.write_text("\n".join(lines) + "\n", encoding="utf-8")

        with CryptographicAuditLedger(str(tampered), signing_key=SIGNING_KEY) as verifier:
            assert [verifier.signature_status(node) for node in verifier.chain] == [
                "unverified",
                "invalid",
                "unverified",
            ]
            assert verifier.verify_integrity() == (False, 1)


class TestChainAssuranceHelper:
    def test_none_keeps_the_label_only_reading(self, genuine: tuple[Path, Path, str]) -> None:
        wal, _, public_key = genuine
        with CryptographicAuditLedger(str(wal), signing_key=SIGNING_KEY) as ledger:
            chain = list(ledger.chain)
        assert chain_signature_assurance(chain) == SignatureAssurance.ASYMMETRIC_SOFTWARE
        assert chain_signature_assurance(chain, frozenset()) == SignatureAssurance.UNSIGNED
        assert (
            chain_signature_assurance(chain, frozenset({public_key}))
            == SignatureAssurance.ASYMMETRIC_SOFTWARE
        )


class TestTheFallbackTierIsNeverAttributed:
    def test_a_fallback_signature_that_checks_reads_unverified(self, tmp_path: Path) -> None:
        wal = tmp_path / "fallback.jsonl"
        with CryptographicAuditLedger(str(wal)) as ledger:  # no key: ephemeral Ed25519
            ledger.commit_state("s0", 0.5, b"payload")
        with CryptographicAuditLedger(str(wal)) as verifier:
            node = verifier.chain[0]
            assert node.signature_scheme == "ed25519-fallback"
            assert verifier.signature_status(node) == "unverified"
            assert verifier.signature_assurance == SignatureAssurance.COMPROMISED_EPHEMERAL


class TestTheAllowlistIsValidated:
    def test_a_bare_string_is_refused(self) -> None:
        with pytest.raises(TypeError):
            normalise_trusted_public_keys("abcd")

    @pytest.mark.parametrize("bad", ["", "   ", "xyz", "abc", "12 34"])
    def test_a_non_hex_entry_is_refused(self, bad: str) -> None:
        with pytest.raises(ValueError):
            normalise_trusted_public_keys([bad])

    def test_entries_are_trimmed_and_folded_to_lower_case(self) -> None:
        assert normalise_trusted_public_keys([" ABcd ", "abcd", "00ff"]) == frozenset(
            {"abcd", "00ff"}
        )

    def test_the_ledger_refuses_a_bad_allowlist(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError):
            CryptographicAuditLedger(str(tmp_path / "x.jsonl"), trusted_public_keys=["not-hex"])

    def test_the_setting_refuses_a_non_hex_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AEGIS_TRUSTED_SIGNING_PUBLIC_KEYS", "abcd,not-a-key")
        with pytest.raises(ValidationError):
            AegisSettings()

    def test_the_setting_normalises_a_valid_list(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AEGIS_TRUSTED_SIGNING_PUBLIC_KEYS", " ABCD , 00ff ,")
        assert AegisSettings().trusted_signing_public_keys == "abcd,00ff"

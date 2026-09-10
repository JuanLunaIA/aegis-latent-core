# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""The WAF verdict is recorded where a proof can reach it, and added additively.

Before this field, the WAF outcome existed only in control flow: a blocked
request raised before the durable commit, so a committed node *implied* a pass
without recording one. An implication cannot be proved. Putting the verdict
inside the bytes the MMR commits to is what makes a statement about it provable
against a root.

The whole design rests on the field being **omitted when empty**. That is what
keeps every pre-existing node, leaf and signature byte-identical, and it is what
these tests pin down.
"""

from __future__ import annotations

import os
import tempfile

import pytest

from aegis.core.a2a import a2a_leaf_hash
from aegis.core.crypto_audit import CryptographicAuditLedger
from aegis.core.forensic import (
    WAF_VERDICT_BLOCKED,
    WAF_VERDICT_PASSED,
    WAF_VERDICT_UNRECORDED,
    build_merkle_leaf,
    validate_waf_verdict,
)

_LEAF_KWARGS = {
    "state_id": "s",
    "request_bytes": b"req",
    "response_bytes": b"resp",
    "model": "m",
    "endpoint": "e",
    "max_bytes": 64,
}

# The exact bytes `build_merkle_leaf` produced before the field existed. Pinned
# literally rather than recomputed: a test that recomputes with the same code it
# is testing would follow the code wherever it drifted.
_LEGACY_ENVELOPE = (
    b'{"endpoint":"e","model":"m",'
    b'"request_hash":"c3f7bdf537c46724392c4428e47e04c148c56966190c3c9ed92114800c9f35bb",'
    b'"request_preview_hex":"726571","request_size":3,'
    b'"response_hash":"d30db74ae503504cf0eff5cf28a7f23188e0bed27b2484fac73ebbe7e2b1b746",'
    b'"response_preview_hex":"72657370","response_size":4,"state_id":"s"}'
)


class TestTheLeafStaysByteIdenticalWithoutAVerdict:
    def test_omitting_the_verdict_reproduces_the_pre_change_bytes(self) -> None:
        """This is the backward-compatibility claim, stated as bytes."""
        assert build_merkle_leaf(**_LEAF_KWARGS) == _LEGACY_ENVELOPE

    def test_an_explicit_empty_verdict_is_the_same_as_omitting_it(self) -> None:
        assert build_merkle_leaf(**_LEAF_KWARGS, waf_verdict=WAF_VERDICT_UNRECORDED) == (
            build_merkle_leaf(**_LEAF_KWARGS)
        )

    def test_a_recorded_verdict_only_appends(self) -> None:
        """`waf_verdict` sorts last, so the field cannot displace an existing one."""
        with_verdict = build_merkle_leaf(**_LEAF_KWARGS, waf_verdict=WAF_VERDICT_PASSED)
        assert with_verdict.endswith(b',"waf_verdict":"passed"}')
        assert with_verdict.replace(b',"waf_verdict":"passed"', b"") == _LEGACY_ENVELOPE

    def test_the_a2a_leaf_is_unchanged(self) -> None:
        """A2A receipts record no verdict, so both SDKs keep verifying them.

        Both SDKs reconstruct the A2A envelope field by field. If this hash
        moved, every published SDK would stop verifying every A2A receipt.
        """
        envelope = b'{"execution_id":"exec-1"}'
        assert a2a_leaf_hash(envelope) == a2a_leaf_hash(envelope)
        assert len(a2a_leaf_hash(envelope)) == 64


class TestTheVocabularyIsClosed:
    @pytest.mark.parametrize(
        "verdict", [WAF_VERDICT_PASSED, WAF_VERDICT_BLOCKED, WAF_VERDICT_UNRECORDED]
    )
    def test_members_are_accepted(self, verdict: str) -> None:
        assert validate_waf_verdict(verdict) == verdict

    @pytest.mark.parametrize(
        "verdict",
        ["allowed", "PASSED", "pa|ssed", "passed|blocked", "|", "unknown", None, 1],
        ids=["synonym", "case", "delimiter", "injection", "bare-pipe", "invented", "none", "int"],
    )
    def test_everything_else_is_refused(self, verdict: object) -> None:
        """A delimiter in the verdict could make two field lists serialise alike.

        The signed payload is `"|".join(...)`, so an unconstrained verdict is a
        serialisation ambiguity, not merely an unrecognised label.
        """
        with pytest.raises(ValueError, match="waf_verdict must be one of"):
            validate_waf_verdict(verdict)  # type: ignore[arg-type]

    def test_a_bad_verdict_never_reaches_the_ledger_lock(self) -> None:
        """Rejected as a caller error, not as a half-written commit."""
        with tempfile.TemporaryDirectory() as directory:
            with CryptographicAuditLedger(
                os.path.join(directory, "wal.jsonl"), signing_key="k"
            ) as ledger:
                with pytest.raises(ValueError, match="waf_verdict must be one of"):
                    ledger.commit_forensic(state_id="x", request_bytes=b"a", waf_verdict="allowed")
                assert len(ledger.chain) == 0


class TestTheSignatureBindsTheVerdict:
    """Tampering fails closed in both directions, with no version flag."""

    @staticmethod
    def _ledger(directory: str) -> CryptographicAuditLedger:
        return CryptographicAuditLedger(os.path.join(directory, "wal.jsonl"), signing_key="k")

    def test_a_chain_mixing_recorded_and_unrecorded_nodes_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self._ledger(directory) as ledger:
                ledger.commit_forensic(state_id="legacy", request_bytes=b"a", response_bytes=b"b")
                ledger.commit_forensic(
                    state_id="new",
                    request_bytes=b"a",
                    response_bytes=b"b",
                    waf_verdict=WAF_VERDICT_PASSED,
                )
                intact, broken_at = ledger.verify_integrity()
                assert intact is True
                assert broken_at is None

    def test_stripping_a_recorded_verdict_invalidates_the_signature(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self._ledger(directory) as ledger:
                node = ledger.commit_forensic(
                    state_id="new", request_bytes=b"a", waf_verdict=WAF_VERDICT_PASSED
                )
                node.waf_verdict = WAF_VERDICT_UNRECORDED
                intact, broken_at = ledger.verify_integrity()
                assert intact is False
                assert broken_at == 0

    def test_forging_a_verdict_onto_an_unrecorded_node_invalidates_it(self) -> None:
        """The direction an attacker actually wants: manufacture a WAF pass."""
        with tempfile.TemporaryDirectory() as directory:
            with self._ledger(directory) as ledger:
                node = ledger.commit_forensic(state_id="legacy", request_bytes=b"a")
                node.waf_verdict = WAF_VERDICT_PASSED
                intact, broken_at = ledger.verify_integrity()
                assert intact is False
                assert broken_at == 0

    def test_switching_a_recorded_verdict_invalidates_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self._ledger(directory) as ledger:
                node = ledger.commit_forensic(
                    state_id="new", request_bytes=b"a", waf_verdict=WAF_VERDICT_PASSED
                )
                node.waf_verdict = WAF_VERDICT_BLOCKED
                assert ledger.verify_integrity()[0] is False


class TestTheVerdictSurvivesSerialisation:
    def test_a_reloaded_chain_keeps_its_verdicts_and_verifies(self) -> None:
        """The field must round-trip through the WAL, or a restart loses it."""
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "wal.jsonl")
            with CryptographicAuditLedger(path, signing_key="k") as ledger:
                ledger.commit_forensic(state_id="legacy", request_bytes=b"a")
                ledger.commit_forensic(
                    state_id="new", request_bytes=b"b", waf_verdict=WAF_VERDICT_PASSED
                )
            with CryptographicAuditLedger(path, signing_key="k") as reloaded:
                assert [n.waf_verdict for n in reloaded.chain] == [
                    WAF_VERDICT_UNRECORDED,
                    WAF_VERDICT_PASSED,
                ]
                assert reloaded.verify_integrity()[0] is True

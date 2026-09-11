# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""The Python surface of the zero-knowledge inclusion proof.

Two things are covered here and they are covered differently on purpose.

**Suffix parity always runs.** The circuit hard-codes the bytes a canonical leaf
ends with when the verdict is `passed`, as a *constant* rather than a checked
witness — which is what makes a `blocked` leaf unprovable rather than merely
rejected. That constant is only correct while `build_merkle_leaf` keeps emitting
it. If the two ever drift the circuit proves a statement about a leaf shape that
no longer exists, and it would do so silently. This test needs no extension and
runs everywhere.

**The binding tests follow the `test_crdt_mmr.py` pattern.** They skip without
the compiled extension so a pure-Python checkout stays usable, and
`AEGIS_REQUIRE_RUST=1` turns that skip into a failure in CI, where a silent skip
would read like a pass. They then branch on `has_zk_native()`, because the
capability is off in every default build: a default extension must *refuse and
say why*, and a feature-enabled one must actually prove.
"""

from __future__ import annotations

import hashlib
import os

import pytest

import aegis.crypto as aegis_crypto
from aegis.core.forensic import (
    WAF_VERDICT_BLOCKED,
    WAF_VERDICT_PASSED,
    build_merkle_leaf,
)

#: The bytes `aegis_rust_v2/src/zk_mmr.rs` compiles into the circuit.
PASSED_SUFFIX = b',"waf_verdict":"passed"}'

_REQUIRED = os.environ.get("AEGIS_REQUIRE_RUST") == "1"

try:
    import aegis_rust
except ImportError as exc:  # pragma: no cover - depends on the build environment
    if _REQUIRED:
        raise AssertionError(
            "AEGIS_REQUIRE_RUST=1 but the aegis_rust extension is not importable; "
            "the zero-knowledge binding tests would have skipped silently"
        ) from exc
    aegis_rust = None

_has_native = getattr(aegis_rust, "has_zk_native", None)

if _REQUIRED and _has_native is None:  # pragma: no cover - build-shape guard
    raise AssertionError(
        "AEGIS_REQUIRE_RUST=1 but aegis_rust exposes no has_zk_native; the "
        "extension was built without the binding these tests exist to cover"
    )

_LEAF = {
    "state_id": "s-1",
    "request_bytes": b"hello",
    "response_bytes": b"world",
    "model": "m",
    "endpoint": "/v1/chat",
    "max_bytes": 0,
}


class TestTheCircuitConstantMatchesTheLeafBuilder:
    """No extension required: this is a property of the Python builder."""

    def test_a_passed_leaf_ends_with_the_bytes_the_circuit_compiles_in(self) -> None:
        leaf = build_merkle_leaf(**_LEAF, waf_verdict=WAF_VERDICT_PASSED)
        assert leaf.endswith(PASSED_SUFFIX)

    def test_the_suffix_is_exactly_what_the_rust_source_declares(self) -> None:
        """Pinned against the source, so a rename on either side is caught."""
        source = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "aegis_rust_v2",
            "src",
            "zk_mmr.rs",
        )
        with open(source, encoding="utf-8") as handle:
            text = handle.read()
        declared = 'pub const PASSED_SUFFIX: &[u8] = br#"' + PASSED_SUFFIX.decode() + '"#;'
        assert declared in text, "the Rust constant and this test have drifted apart"

    def test_a_blocked_leaf_does_not_end_with_the_passed_suffix(self) -> None:
        """Which is the whole reason the suffix can be a constant."""
        leaf = build_merkle_leaf(**_LEAF, waf_verdict=WAF_VERDICT_BLOCKED)
        assert not leaf.endswith(PASSED_SUFFIX)

    def test_an_unrecorded_leaf_does_not_end_with_the_passed_suffix(self) -> None:
        leaf = build_merkle_leaf(**_LEAF)
        assert not leaf.endswith(PASSED_SUFFIX)

    def test_the_verdict_is_the_last_key_so_the_suffix_is_stable(self) -> None:
        """`waf_verdict` sorts last, so a recorded verdict can only append.

        If a later field sorted after it, the suffix would move and the circuit
        would stop matching real leaves.
        """
        leaf = build_merkle_leaf(**_LEAF, waf_verdict=WAF_VERDICT_PASSED)
        assert leaf.index(b'"waf_verdict"') > leaf.index(b'"state_id"')
        assert leaf.endswith(b'"passed"}')


@pytest.mark.skipif(_has_native is None, reason="aegis_rust built without the ZK binding")
class TestTheBindingIsHonestAboutWhatItCanDo:
    def test_capability_is_reported_rather_than_inferred(self) -> None:
        assert isinstance(aegis_rust.has_zk_native(), bool)

    def test_a_build_without_the_feature_refuses_and_names_the_flag(self) -> None:
        """A missing capability must refuse, never quietly return something."""
        if aegis_rust.has_zk_native():
            pytest.skip("this extension was built with zk-spartan")
        for call in (
            lambda: aegis_rust.generate_zk_proof(b"x", [], [], [bytes(32)]),
            lambda: aegis_rust.verify_zk_proof(b"p", b"k", bytes(32)),
            lambda: aegis_rust.zk_verifier_key(10, 2, 1),
        ):
            with pytest.raises(RuntimeError, match="zk-spartan"):
                call()


def _tree(leaf: bytes) -> tuple[bytes, list[bytes], list[bool], bytes]:
    """A four-leaf v2 MMR holding `leaf` at index 0."""

    def leaf_hash(payload: bytes) -> bytes:
        return hashlib.sha256(b"\x00" + payload).digest()

    def node_hash(left: bytes, right: bytes) -> bytes:
        return hashlib.sha256(b"\x01" + left + right).digest()

    leaves = [leaf_hash(leaf)] + [leaf_hash(b"other-%d" % i) for i in range(1, 4)]
    right_subtree = node_hash(leaves[2], leaves[3])
    peak = node_hash(node_hash(leaves[0], leaves[1]), right_subtree)
    root = hashlib.sha256(b"\x02" + peak).digest()
    return peak, [leaves[1], right_subtree], [False, False], root


@pytest.mark.skipif(
    _has_native is None or not (aegis_rust and aegis_rust.has_zk_native()),
    reason="extension built without zk-spartan; proving is unavailable",
)
class TestProvingAgainstARealLeaf:
    """Driven by `build_merkle_leaf`'s own output, not a hand-made envelope.

    A fixture leaf would pass even if the production builder changed shape.
    """

    def test_a_real_passed_leaf_proves_and_verifies_against_its_root(self) -> None:
        leaf = build_merkle_leaf(**_LEAF, waf_verdict=WAF_VERDICT_PASSED)
        peak, siblings, directions, root = _tree(leaf)
        prefix = leaf[: -len(PASSED_SUFFIX)]

        proof, verifier_key, committed = aegis_rust.generate_zk_proof(
            prefix, siblings, directions, [peak]
        )
        assert committed == root
        assert aegis_rust.verify_zk_proof(proof, verifier_key, root) is True

    def test_verification_refuses_a_root_from_somewhere_else(self) -> None:
        leaf = build_merkle_leaf(**_LEAF, waf_verdict=WAF_VERDICT_PASSED)
        peak, siblings, directions, _ = _tree(leaf)
        proof, verifier_key, _ = aegis_rust.generate_zk_proof(
            leaf[: -len(PASSED_SUFFIX)], siblings, directions, [peak]
        )
        assert aegis_rust.verify_zk_proof(proof, verifier_key, bytes(32)) is False

    def test_an_independently_derived_key_verifies_the_same_proof(self) -> None:
        """The property that lets a verifier refuse a prover-supplied key."""
        leaf = build_merkle_leaf(**_LEAF, waf_verdict=WAF_VERDICT_PASSED)
        peak, siblings, directions, root = _tree(leaf)
        prefix = leaf[: -len(PASSED_SUFFIX)]
        proof, _, _ = aegis_rust.generate_zk_proof(prefix, siblings, directions, [peak])

        own_key = aegis_rust.zk_verifier_key(len(prefix), len(siblings), 1)
        assert aegis_rust.verify_zk_proof(proof, own_key, root) is True

    def test_a_blocked_leaf_cannot_be_proved_as_passed(self) -> None:
        """The attack the construction exists to refuse."""
        blocked = build_merkle_leaf(**_LEAF, waf_verdict=WAF_VERDICT_BLOCKED)
        peak, siblings, directions, _ = _tree(blocked)
        prefix = blocked[: -len(b',"waf_verdict":"blocked"}')]
        with pytest.raises(RuntimeError):
            aegis_rust.generate_zk_proof(prefix, siblings, directions, [peak])

    def test_a_digest_of_the_wrong_length_is_refused_as_a_value_error(self) -> None:
        leaf = build_merkle_leaf(**_LEAF, waf_verdict=WAF_VERDICT_PASSED)
        peak, siblings, directions, _ = _tree(leaf)
        with pytest.raises(ValueError, match="32 bytes"):
            aegis_rust.generate_zk_proof(
                leaf[: -len(PASSED_SUFFIX)], [b"short"] + siblings[1:], directions, [peak]
            )


class TestTheFacadeExportsTheRealSurfaceSeparately:
    """`aegis.crypto` carries a stub and a real construction; they must not blur."""

    def test_the_real_functions_are_exported(self) -> None:
        for name in (
            "generate_zk_proof",
            "verify_zk_proof",
            "zk_verifier_key",
            "has_zk_native",
            "split_passed_leaf",
            "ZKNativeUnavailableError",
        ):
            assert name in aegis_crypto.__all__, f"{name} missing from the facade"
            assert hasattr(aegis_crypto, name)

    def test_the_stub_is_still_exported_and_still_a_stub(self) -> None:
        """`CLM-019` says the stub surface is a stub. That must stay true."""
        from aegis.core.zk_proof import HAS_ZK_NATIVE

        assert HAS_ZK_NATIVE is False
        assert "ZKProver" in aegis_crypto.__all__

    def test_capability_discovery_never_raises(self) -> None:
        """A caller must be able to branch without handling an exception."""
        assert isinstance(aegis_crypto.has_zk_native(), bool)

    def test_the_facade_imports_without_the_extension(self) -> None:
        """Importing must not require `aegis_rust`, or a pure-Python checkout breaks."""
        import aegis.core.zk_native as native

        source = native.__file__
        with open(source, encoding="utf-8") as handle:
            head = handle.read().split("def _extension")[0]
        assert "import aegis_rust" not in head, "the extension is imported at module scope"


class TestSplittingALeafIsGuarded:
    def test_a_passed_leaf_splits_to_the_prefix_the_circuit_expects(self) -> None:
        leaf = build_merkle_leaf(**_LEAF, waf_verdict=WAF_VERDICT_PASSED)
        assert aegis_crypto.split_passed_leaf(leaf) + PASSED_SUFFIX == leaf

    @pytest.mark.parametrize("verdict", [WAF_VERDICT_BLOCKED, None], ids=["blocked", "unrecorded"])
    def test_any_other_leaf_is_refused_here_rather_than_in_the_circuit(
        self, verdict: str | None
    ) -> None:
        """Slicing by hand would surface seconds later as an unsatisfiable circuit."""
        kwargs = dict(_LEAF)
        if verdict is not None:
            kwargs["waf_verdict"] = verdict
        with pytest.raises(ValueError, match="does not record a passed"):
            aegis_crypto.split_passed_leaf(build_merkle_leaf(**kwargs))

    def test_the_suffix_is_derived_from_the_vocabulary_not_retyped(self) -> None:
        """So a change to the verdict spelling cannot leave the constant behind."""
        import aegis.core.zk_native as native

        assert native.PASSED_SUFFIX == PASSED_SUFFIX
        assert WAF_VERDICT_PASSED.encode() in native.PASSED_SUFFIX

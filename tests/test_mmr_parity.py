"""
tests/test_mmr_parity.py — Rust↔Python MMR root parity.

The audit ledger uses the pure-Python ``MerkleMountainRange`` directly, so the
chain's correctness does not depend on the Rust extension. However, the project
advertises a Rust-backed MMR for hot-path performance, and ``RustBackedMMR``
returns the Rust root while serving inclusion proofs from the Python replica.
If the two implementations disagree on the root for a given leaf sequence, those
proofs would not verify against the advertised root.

These tests make that parity *verifiable* rather than asserted: they are skipped
when the ``aegis_rust`` extension is not built (e.g. ``cargo test --lib`` cannot
link libpython under the ``extension-module`` feature; ``maturin develop`` is the
supported build path), and they fail loudly when a real divergence appears.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import pytest

from aegis.core.mmr import MerkleMountainRange

# Skip the whole module unless the compiled extension is importable.
aegis_rust = pytest.importorskip(
    "aegis_rust",
    reason="aegis_rust extension not built; run `maturin develop` to enable parity tests",
)


def _rust_mmr():
    """Return a fresh Rust MMR accumulator, skipping if the symbol is absent."""
    factory = getattr(aegis_rust, "MmrAccumulator", None)
    if factory is None:
        pytest.skip("aegis_rust.MmrAccumulator not exported by this build")
    return factory()


@pytest.mark.parametrize("leaf_count", [1, 2, 3, 4, 7, 8, 15, 16, 33])
def test_rust_python_root_parity(leaf_count: int) -> None:
    """Both implementations must agree on the root after each appended leaf."""
    py = MerkleMountainRange()
    ru = _rust_mmr()

    for i in range(leaf_count):
        leaf = f"leaf-{i}".encode()
        py_root = py.add_leaf(leaf)
        ru_root = ru.add_leaf(leaf)
        assert py_root == ru_root, (
            f"MMR root divergence at leaf {i} (count={i + 1}): python={py_root} rust={ru_root}"
        )


def test_rust_python_leaf_count_parity() -> None:
    """Leaf-count bookkeeping must match across implementations."""
    py = MerkleMountainRange()
    ru = _rust_mmr()
    for i in range(10):
        py.add_leaf(f"x-{i}".encode())
        ru.add_leaf(f"x-{i}".encode())
    assert int(ru.get_leaf_count()) == py._leaf_count == 10


@pytest.mark.parametrize("leaf_count", [1, 2, 3, 5, 8, 13, 21, 34])
def test_python_proof_verifies_against_the_rust_root(leaf_count: int) -> None:
    """Every Python-generated proof must verify against the Rust-reported root.

    This is the exact composition ``RustBackedMMR`` ships: ``get_root_hash``
    returns the Rust root while ``get_portable_inclusion_proof`` is served from
    the Python replica. Root parity alone does not cover it, because a proof
    also carries the peak set and the sibling path. If the two implementations
    ever diverge in peak ordering or in the bytes fed to the compression
    function, this fails where a root-only comparison would still pass.
    """
    py = MerkleMountainRange()
    ru = _rust_mmr()
    leaves = [f"leaf-{i}".encode() for i in range(leaf_count)]
    for leaf in leaves:
        py.add_leaf(leaf)
        ru.add_leaf(leaf)

    rust_root = ru.get_root_hash()
    for index, leaf in enumerate(leaves):
        proof = py.get_portable_inclusion_proof(index)
        assert MerkleMountainRange.verify_portable_inclusion(leaf, proof, rust_root), (
            f"Python proof for leaf {index} does not verify against the Rust root "
            f"at leaf_count={leaf_count}"
        )


def test_rust_backed_mmr_serves_proofs_that_verify_against_its_own_root() -> None:
    """The shipped hybrid must be self-consistent end to end.

    ``RustBackedMMR`` is only constructed when the extension is importable, so
    it is reached through the module rather than imported at module scope.
    """
    from aegis.core import mmr as mmr_mod

    hybrid_cls = getattr(mmr_mod, "RustBackedMMR", None)
    if hybrid_cls is None:
        pytest.skip("RustBackedMMR is not defined in this build")

    hybrid = hybrid_cls()
    leaves = [f"hybrid-{i}".encode() for i in range(24)]
    for leaf in leaves:
        hybrid.add_leaf(leaf)

    root = hybrid.get_root_hash()
    for index, leaf in enumerate(leaves):
        proof = hybrid.get_portable_inclusion_proof(index)
        assert proof.root == root, (
            f"hybrid proof root {proof.root} disagrees with the served root {root}"
        )
        assert MerkleMountainRange.verify_portable_inclusion(leaf, proof, root)


def test_rust_and_python_agree_on_the_declared_wire_algorithm() -> None:
    """The proof's ``algorithm`` field must describe the hash actually used.

    ``verify_portable_inclusion_hash`` rejects any value other than
    ``sha256-asciihex`` and recomputes with SHA-256 over ASCII hex. Changing
    either implementation's digest or its concatenation format without changing
    this literal — and the verifier alongside it — would invalidate every proof
    already issued, so the coupling is pinned here.
    """
    py = MerkleMountainRange()
    ru = _rust_mmr()
    for i in range(7):
        py.add_leaf(f"wire-{i}".encode())
        ru.add_leaf(f"wire-{i}".encode())

    proof = py.get_portable_inclusion_proof(3)
    assert proof.version == "aegis-mmr-inclusion-v1"
    assert proof.algorithm == "sha256-asciihex"
    assert proof.root == ru.get_root_hash()
    assert all(len(peak.hash) == 64 for peak in proof.peaks)
    assert all(len(step.sibling_hash) == 64 for step in proof.path)

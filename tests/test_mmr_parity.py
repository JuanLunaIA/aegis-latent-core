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

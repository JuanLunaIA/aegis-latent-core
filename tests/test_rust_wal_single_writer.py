# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""REG-D08 — a second RustWal handle on one segment is refused, not destructive.

The v5.0.1-prep audit reproduced the defect first-hand against the Rust
extension: two ``RustWal`` handles on one path each kept their own
``write_pos``, both rescanned to the same offset and overwrote committed
frames through their own MAP_SHARED mapping — a's frames were destroyed and
``a.read_all()`` returned only b's records.  The ``SAFETY`` note above the
mmap asserted an exclusivity invariant no code enforced.

These tests pin the fix at the PyO3 surface: a second ``open`` fails closed
with a clear ``RuntimeError`` naming the single-writer invariant, the losing
handle never touches the segment, dropping the holder releases the lock, and
committed frames survive a reopen.  They skip where the extension is not
built, like the repository's other ``aegis_rust`` tests.
"""

from __future__ import annotations

import pytest

aegis_rust = pytest.importorskip("aegis_rust")  # skip where the extension is absent

_CAPACITY = 1 << 20


def test_second_handle_is_refused_and_first_handle_intact(tmp_path):
    path = str(tmp_path / "seg.rwal")

    first = aegis_rust.RustWal.open(path, _CAPACITY)
    first.append('{"seq":1}')
    first.append('{"seq":2}')

    with pytest.raises(RuntimeError) as excinfo:
        aegis_rust.RustWal.open(path, _CAPACITY)
    assert "single-writer" in str(excinfo.value)

    # The refused handle could not touch the segment: the holder's frames and
    # offset are exactly as they were.
    assert first.read_all() == ['{"seq":1}', '{"seq":2}']
    assert first.write_pos() > 0


def test_lock_is_released_when_the_holder_drops(tmp_path):
    path = str(tmp_path / "seg.rwal")

    holder = aegis_rust.RustWal.open(path, _CAPACITY)
    holder.append('{"seq":1}')
    del holder  # no close() on the surface: the lock lives on the handle object

    second = aegis_rust.RustWal.open(path, _CAPACITY)
    assert second.read_all() == ['{"seq":1}']
    second.append('{"seq":2}')
    assert second.read_all() == ['{"seq":1}', '{"seq":2}']


def test_two_handles_on_distinct_paths_are_both_allowed(tmp_path):
    first = aegis_rust.RustWal.open(str(tmp_path / "a.rwal"), _CAPACITY)
    second = aegis_rust.RustWal.open(str(tmp_path / "b.rwal"), _CAPACITY)

    first.append('{"path":"a"}')
    second.append('{"path":"b"}')

    assert first.read_all() == ['{"path":"a"}']
    assert second.read_all() == ['{"path":"b"}']

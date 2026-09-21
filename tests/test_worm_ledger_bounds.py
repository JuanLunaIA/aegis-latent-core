# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Seal detection must not read the whole segment (AF-065 / REG-D27).

`_has_seal_record`, `_read_seal_line` and `_read_seal_record` asked a question
about the *last* non-empty line and answered it with `readlines()` — a peak of one
whole file per call on a segment that grows without bound by design. The probe
run for this row measured ~42 MiB of peak allocation per helper for a 31 MiB
segment, against 0.022 MiB for the already-streaming `count_nodes_in_segment` on
the same file. `is_sealed()` calls one of them on every seal check, so the cost
was on the hot path of a module whose whole purpose is long-retention segments.

These tests pin both halves: the answers are unchanged, and the peak is flat.
"""

from __future__ import annotations

import json
import tracemalloc

from aegis.core.worm_ledger import WORMEnforcer, WORMSealRecord

SEAL = '{"record_type": "worm_seal", "sealed_at": 1.5, "sealed_by": "t", "node_count": 1}'


def _write(tmp_path, name, lines):
    path = tmp_path / name
    path.write_text("".join(line + "\n" for line in lines), encoding="utf-8")
    return path


def test_parity_with_the_previous_answers(tmp_path) -> None:
    sealed = _write(tmp_path, "sealed.jsonl", ['{"a": 1}', SEAL])
    sealed_blanks = _write(tmp_path, "blanks.jsonl", ['{"a": 1}', SEAL, "", "   "])
    unsealed = _write(tmp_path, "plain.jsonl", ['{"a": 1}', '{"a": 2}'])
    corrupt = _write(tmp_path, "corrupt.jsonl", ['{"a": 1}', "{not json"])
    empty = _write(tmp_path, "empty.jsonl", [])

    for path in (sealed, sealed_blanks):
        assert WORMEnforcer._has_seal_record(str(path)) is True
        assert WORMEnforcer._read_seal_line(str(path)) == SEAL
        record = WORMEnforcer._read_seal_record(str(path))
        assert isinstance(record, WORMSealRecord)
        assert record.record_type == "worm_seal"
        assert record.node_count == 1

    for path in (unsealed, corrupt, empty):
        assert WORMEnforcer._has_seal_record(str(path)) is False
        assert WORMEnforcer._read_seal_line(str(path)) == ""
        assert WORMEnforcer._read_seal_record(str(path)) is None

    assert WORMEnforcer._has_seal_record(str(tmp_path / "missing.jsonl")) is False


def test_seal_detection_peak_memory_is_flat(tmp_path) -> None:
    """A segment far larger than any constant buffer must not be read whole."""
    big = tmp_path / "big.jsonl"
    filler = json.dumps({"filler": "x" * 400})
    with open(big, "w", encoding="utf-8") as handle:
        for _ in range(25_000):  # ~10 MiB
            handle.write(filler + "\n")
        handle.write(SEAL + "\n")
    assert big.stat().st_size > 8 * 1024 * 1024

    tracemalloc.start()
    try:
        # Reset first: pytest's own machinery allocates inside the traced window,
        # and this test is about what the helper allocates, not about the runner.
        tracemalloc.reset_peak()
        assert WORMEnforcer._has_seal_record(str(big)) is True
        assert WORMEnforcer._read_seal_line(str(big)) == SEAL
        assert isinstance(WORMEnforcer._read_seal_record(str(big)), WORMSealRecord)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()

    assert peak < 1024 * 1024, (
        f"seal detection allocated {peak / 1024 / 1024:.1f} MiB for a "
        f"{big.stat().st_size / 1024 / 1024:.1f} MiB segment; it is reading the file whole"
    )


def test_is_sealed_and_verify_still_agree(tmp_path) -> None:
    path = tmp_path / "segment.jsonl"
    path.write_text('{"a": 1}\n', encoding="utf-8")
    enforcer = WORMEnforcer()
    assert enforcer.is_sealed(str(path)) is False
    enforcer.seal(str(path))
    assert enforcer.is_sealed(str(path)) is True
    assert enforcer.verify(str(path)) is True

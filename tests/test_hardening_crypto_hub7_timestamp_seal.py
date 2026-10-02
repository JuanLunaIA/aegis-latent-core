"""Malformed JSON seals are mismatches, not exceptions; hashing stays unchanged."""

# Copyright (c) 2026 Juan Luna.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE.
from __future__ import annotations

import hashlib
import json

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from aegis.core.iso27037_evidence import _compute_seal, verify_seal


@pytest.mark.parametrize(
    "stored", [1, True, 1.5, ["seal"], {"seal": "bad"}, "\ud800", "\ud800" * 64]
)
def test_malformed_integrity_seal_returns_false(stored):
    assert verify_seal({"evidence": "synthetic", "integrity_seal": stored}) is False


@settings(max_examples=100, derandomize=True, deadline=500, database=None)
@given(st.one_of(st.integers(), st.booleans(), st.lists(st.integers(), max_size=4)))
def test_non_string_integrity_seals_are_rejected(stored):
    assert verify_seal({"evidence": "synthetic", "integrity_seal": stored}) is False


@pytest.mark.parametrize("text", ["plain", "caf\u00e9", "\ud800", "\U0001f600"])
def test_original_seal_wire_bytes_preserved(text):
    package = {"evidence": text, "node_count": 1}
    canonical = json.dumps(package, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    expected = hashlib.sha256(canonical.encode()).hexdigest()
    assert _compute_seal(package) == expected
    package["integrity_seal"] = expected
    assert verify_seal(package) is True
    for wrong in (expected.upper(), "g" * 64, "0" * 63, "0" * 65, "\u00e9" * 64):
        package["integrity_seal"] = wrong
        assert verify_seal(package) is False

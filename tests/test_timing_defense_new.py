# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.timing_defense — constant-time comparison and deterministic padding."""

from __future__ import annotations

import pytest

from aegis.core.timing_defense import TimingDefense, timing_defense

# ── constant_time_compare ─────────────────────────────────────────────────────


def test_constant_time_compare_equal_bytes():
    assert TimingDefense.constant_time_compare(b"secret", b"secret") is True


def test_constant_time_compare_different_bytes():
    assert TimingDefense.constant_time_compare(b"abc", b"xyz") is False


def test_constant_time_compare_equal_strings():
    assert TimingDefense.constant_time_compare("token123", "token123") is True


def test_constant_time_compare_different_strings():
    assert TimingDefense.constant_time_compare("abc", "xyz") is False


def test_constant_time_compare_mixed_str_and_bytes():
    # str val1, bytes val2
    assert TimingDefense.constant_time_compare("hello", b"hello") is True


def test_constant_time_compare_bytes_str():
    # bytes val1, str val2
    assert TimingDefense.constant_time_compare(b"world", "world") is True


def test_constant_time_compare_empty_strings():
    assert TimingDefense.constant_time_compare("", "") is True


def test_constant_time_compare_different_length_bytes():
    # hmac.compare_digest returns False for inputs of different lengths (not TypeError).
    result = TimingDefense.constant_time_compare(b"abc", b"ab")
    assert result is False


# ── singleton instance ────────────────────────────────────────────────────────


def test_singleton_instance_is_timing_defense():
    assert isinstance(timing_defense, TimingDefense)


# ── deterministic_padding ─────────────────────────────────────────────────────


def test_padding_pads_to_block_size():
    data = b"hello"
    padded = TimingDefense.deterministic_padding(data, block_size=16)
    # padded = data + padding + 4-byte length → total must be a multiple of 16 or exactly 16
    # For len=5, block=16: padding_len = 16 - 5 = 11, total = 5 + 11 + 4 = 20
    assert len(padded) == 5 + 11 + 4


def test_padding_empty_data():
    data = b""
    padded = TimingDefense.deterministic_padding(data, block_size=32)
    # padding_len = 32, total = 0 + 32 + 4 = 36
    assert len(padded) == 36


def test_padding_data_exactly_block_size():
    data = b"A" * 16
    padded = TimingDefense.deterministic_padding(data, block_size=16)
    # len=16, block=16: len > block → branch: (16 % 16 == 0) → padding_len = 0
    # total = 16 + 0 + 4 = 20
    assert len(padded) == 20


def test_padding_data_exceeds_block_size():
    data = b"B" * 100
    padded = TimingDefense.deterministic_padding(data, block_size=32)
    # 100 % 32 = 4, padding_len = 32 - 4 = 28
    # total = 100 + 28 + 4 = 132
    assert len(padded) == 132


def test_padding_last_4_bytes_encode_padding_length():
    data = b"hello"
    padded = TimingDefense.deterministic_padding(data, block_size=16)
    padding_len = int.from_bytes(padded[-4:], "big")
    assert padding_len == 11  # 16 - 5


def test_padding_uses_random_bytes():
    data = b"data"
    p1 = TimingDefense.deterministic_padding(data, block_size=16)
    p2 = TimingDefense.deterministic_padding(data, block_size=16)
    # Padding bytes differ (random); only prefix and suffix length match
    assert len(p1) == len(p2)
    assert p1[:4] == p2[:4]  # original data matches


# ── strip_padding ─────────────────────────────────────────────────────────────


def test_strip_padding_round_trip():
    data = b"the original message"
    padded = TimingDefense.deterministic_padding(data, block_size=64)
    recovered = TimingDefense.strip_padding(padded)
    assert recovered == data


def test_strip_padding_empty_original():
    data = b""
    padded = TimingDefense.deterministic_padding(data, block_size=16)
    recovered = TimingDefense.strip_padding(padded)
    assert recovered == data


def test_strip_padding_large_data():
    data = b"X" * 1000
    padded = TimingDefense.deterministic_padding(data, block_size=256)
    recovered = TimingDefense.strip_padding(padded)
    assert recovered == data


def test_strip_padding_too_short_raises():
    with pytest.raises(ValueError, match="too short"):
        TimingDefense.strip_padding(b"abc")


def test_strip_padding_invalid_length_raises():
    # Craft a padded_data where the last 4 bytes encode a length > total length
    bad = b"hi" + (999).to_bytes(4, "big")
    with pytest.raises(ValueError, match="Invalid padding"):
        TimingDefense.strip_padding(bad)


def test_strip_padding_exactly_4_bytes_ok():
    # Exactly 4 bytes: padding_len=0, data is empty
    payload = (0).to_bytes(4, "big")
    result = TimingDefense.strip_padding(payload)
    assert result == b""

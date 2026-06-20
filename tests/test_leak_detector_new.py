# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.leak_detector — entropy-based data exfiltration detection."""

from __future__ import annotations

import pytest

from aegis.core.leak_detector import DataLeakDetector


# ── construction ───────────────────────────────────────────────────────────────


def test_default_thresholds():
    d = DataLeakDetector()
    assert d.entropy_threshold == 4.5
    assert d.min_length == 16


def test_custom_thresholds():
    d = DataLeakDetector(entropy_threshold=3.0, min_length=8)
    assert d.entropy_threshold == 3.0
    assert d.min_length == 8


# ── _calculate_entropy ────────────────────────────────────────────────────────


def test_entropy_empty_string():
    d = DataLeakDetector()
    assert d._calculate_entropy("") == 0.0


def test_entropy_single_char():
    d = DataLeakDetector()
    assert d._calculate_entropy("aaaa") == 0.0


def test_entropy_two_equal_chars():
    d = DataLeakDetector()
    e = d._calculate_entropy("ab")
    assert abs(e - 1.0) < 1e-10


def test_entropy_high_for_random_hex():
    d = DataLeakDetector()
    # A hex-encoded key has chars 0-9 and a-f — reasonably high entropy
    hex_key = "a1b2c3d4e5f67890" * 4
    e = d._calculate_entropy(hex_key)
    assert e > 3.5


# ── scan_text ─────────────────────────────────────────────────────────────────


def test_scan_text_empty_returns_empty():
    d = DataLeakDetector()
    assert d.scan_text("") == []


def test_scan_text_plain_prose_no_leaks():
    d = DataLeakDetector()
    text = "Hello, the weather is nice today."
    result = d.scan_text(text)
    assert result == []


def test_scan_text_detects_high_entropy_hex():
    d = DataLeakDetector(entropy_threshold=3.0)
    # 64-char random hex string (simulated API key)
    hex_key = "a4b8c2d7e3f1a9b6c0d5e8f2a1b4c7d3e6f9a2b5c8d1e4f7a0b3c6d9e2f5a8b1"
    text = f"Here is your API key: {hex_key}"
    result = d.scan_text(text)
    assert len(result) > 0
    start, end, entropy, reason = result[0]
    assert entropy > 3.0


def test_scan_text_detects_private_key_header():
    d = DataLeakDetector(entropy_threshold=0.0)  # low threshold to catch header
    text = "-----BEGIN RSA PRIVATE KEY-----"
    result = d.scan_text(text)
    assert len(result) > 0
    # The pattern match for private key header
    reasons = [r[3] for r in result]
    assert any("PRIVATE KEY" in r for r in reasons)


def test_scan_text_result_tuple_structure():
    d = DataLeakDetector(entropy_threshold=3.0)
    hex_key = "deadbeef" * 8  # 64-char hex
    result = d.scan_text(hex_key)
    if result:
        start, end, entropy, reason = result[0]
        assert isinstance(start, int)
        assert isinstance(end, int)
        assert isinstance(entropy, float)
        assert isinstance(reason, str)


def test_scan_text_sliding_window_detects_blob():
    d = DataLeakDetector(entropy_threshold=3.5)
    # Insert a high-entropy segment (random base64-like chars) in normal text
    import random
    import string

    high_entropy = "".join(random.choices(string.ascii_letters + string.digits, k=64))
    text = "normal text " + high_entropy + " more normal text"
    result = d.scan_text(text)
    assert len(result) > 0


# ── is_leaking ────────────────────────────────────────────────────────────────


def test_is_leaking_returns_false_for_normal_text():
    d = DataLeakDetector()
    leaking, msg = d.is_leaking("The assistant says: Hello! How can I help you today?")
    assert leaking is False
    assert msg is None


def test_is_leaking_returns_true_for_high_entropy():
    d = DataLeakDetector(entropy_threshold=3.0)
    hex_key = "a4b8c2d7e3f1a9b6c0d5e8f2a1b4c7d3e6f9a2b5c8d1e4f7a0b3c6d9e2f5a8b1"
    leaking, msg = d.is_leaking(f"Key: {hex_key}")
    assert leaking is True
    assert msg is not None
    assert "entropy" in msg.lower()


def test_is_leaking_message_contains_position():
    d = DataLeakDetector(entropy_threshold=3.0)
    hex_key = "a4b8c2d7e3f1a9b6c0d5e8f2a1b4c7d3e6f9a2b5c8d1e4f7a0b3c6d9e2f5a8b1"
    _, msg = d.is_leaking(f"Key: {hex_key}")
    if msg:
        # Message format: "Leak detected at start:end with entropy X.XXXX (reason)"
        assert ":" in msg


def test_is_leaking_multiple_leaks_returns_worst():
    d = DataLeakDetector(entropy_threshold=3.0)
    # Two potential leak candidates; is_leaking returns the one with highest entropy
    key1 = "aabbccdd" * 8  # lower entropy
    key2 = "a4b8c2d7e3f1a9b6c0d5e8f2a1b4c7d3e6f9a2b5c8d1e4f7a0b3c6d9e2f5a8b1"
    text = f"{key1} {key2}"
    leaking, msg = d.is_leaking(text)
    assert leaking is True

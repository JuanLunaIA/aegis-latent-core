# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.forensic builders — token trail, merkle leaf, usage extraction."""

from __future__ import annotations

import json

import pytest

from aegis.core.forensic import (
    TokenTrailEntry,
    build_merkle_leaf,
    build_token_trail,
    cap_bytes,
    extract_usage,
    sha256_hex,
)


# ── TokenTrailEntry ───────────────────────────────────────────────────────────


def test_token_trail_entry_to_dict_basic():
    entry = TokenTrailEntry(index=0, token="hi", logprob=-0.5)
    d = entry.to_dict()
    assert d == {"index": 0, "token": "hi", "logprob": -0.5, "entropy_bits": None}


def test_token_trail_entry_to_dict_with_entropy():
    entry = TokenTrailEntry(index=3, token="world", logprob=-1.2, entropy_bits=2.7)
    d = entry.to_dict()
    assert d["entropy_bits"] == 2.7


def test_token_trail_entry_is_frozen():
    entry = TokenTrailEntry(index=0, token="x", logprob=0.0)
    with pytest.raises(Exception):
        entry.index = 99  # type: ignore[misc]


# ── sha256_hex ─────────────────────────────────────────────────────────────────


def test_sha256_hex_known_value():
    import hashlib

    data = b"aegis"
    expected = hashlib.sha256(data).hexdigest()
    assert sha256_hex(data) == expected


def test_sha256_hex_empty():
    import hashlib

    assert sha256_hex(b"") == hashlib.sha256(b"").hexdigest()


# ── cap_bytes ─────────────────────────────────────────────────────────────────


def test_cap_bytes_below_limit():
    assert cap_bytes(b"hello", 10) == b"hello"


def test_cap_bytes_at_limit():
    assert cap_bytes(b"hello", 5) == b"hello"


def test_cap_bytes_above_limit():
    assert cap_bytes(b"hello world", 5) == b"hello"


# ── build_token_trail ─────────────────────────────────────────────────────────


def test_build_token_trail_empty():
    assert build_token_trail(None) == []
    assert build_token_trail([]) == []


def test_build_token_trail_dict_items():
    items = [
        {"token": "Hello", "logprob": -0.1},
        {"token": " world", "logprob": -0.5},
    ]
    trail = build_token_trail(items)
    assert len(trail) == 2
    assert trail[0]["index"] == 0
    assert trail[0]["token"] == "Hello"
    assert trail[0]["logprob"] == -0.1
    assert trail[1]["index"] == 1
    assert trail[1]["token"] == " world"


def test_build_token_trail_dict_missing_fields():
    items = [{}]
    trail = build_token_trail(items)
    assert trail[0]["token"] == ""
    assert trail[0]["logprob"] == 0.0


class _FakeLogprobItem:
    def __init__(self, token: str, logprob: float):
        self.token = token
        self.logprob = logprob


def test_build_token_trail_object_items():
    items = [_FakeLogprobItem("cat", -0.3), _FakeLogprobItem("dog", -0.7)]
    trail = build_token_trail(items)
    assert trail[0]["token"] == "cat"
    assert trail[1]["token"] == "dog"
    assert trail[1]["logprob"] == -0.7


def test_build_token_trail_object_missing_attrs():
    class Bare:
        pass

    trail = build_token_trail([Bare()])
    assert trail[0]["token"] == ""
    assert trail[0]["logprob"] == 0.0


def test_build_token_trail_returns_dicts():
    trail = build_token_trail([{"token": "a", "logprob": 0.0}])
    assert isinstance(trail[0], dict)
    assert "index" in trail[0]
    assert "entropy_bits" in trail[0]


# ── build_merkle_leaf ─────────────────────────────────────────────────────────


def test_build_merkle_leaf_is_bytes():
    leaf = build_merkle_leaf(
        state_id="s1",
        request_bytes=b"req",
        response_bytes=b"resp",
        model="gpt-4",
        endpoint="chat",
        max_bytes=1024,
    )
    assert isinstance(leaf, bytes)


def test_build_merkle_leaf_is_valid_json():
    leaf = build_merkle_leaf(
        state_id="s1",
        request_bytes=b"req",
        response_bytes=b"resp",
        model="gpt-4",
        endpoint="chat",
        max_bytes=1024,
    )
    obj = json.loads(leaf)
    assert obj["state_id"] == "s1"
    assert obj["model"] == "gpt-4"


def test_build_merkle_leaf_response_none():
    leaf = build_merkle_leaf(
        state_id="s2",
        request_bytes=b"req",
        response_bytes=None,
        model="m",
        endpoint="e",
        max_bytes=1024,
    )
    obj = json.loads(leaf)
    assert obj["response_hash"] == ""
    assert obj["response_size"] == 0


def test_build_merkle_leaf_caps_request_preview():
    leaf = build_merkle_leaf(
        state_id="s3",
        request_bytes=b"A" * 100,
        response_bytes=b"B",
        model="m",
        endpoint="e",
        max_bytes=10,
    )
    obj = json.loads(leaf)
    # Preview is hex of first 10 bytes
    assert obj["request_preview_hex"] == ("A" * 10).encode().hex()
    # But full hash is over all 100 bytes
    assert obj["request_size"] == 100


def test_build_merkle_leaf_deterministic():
    kwargs = dict(
        state_id="d1",
        request_bytes=b"req",
        response_bytes=b"resp",
        model="m",
        endpoint="e",
        max_bytes=1024,
    )
    assert build_merkle_leaf(**kwargs) == build_merkle_leaf(**kwargs)


# ── extract_usage ─────────────────────────────────────────────────────────────


def test_extract_usage_none_returns_empty():
    assert extract_usage(None) == {}


def test_extract_usage_empty_dict():
    assert extract_usage({}) == {}


def test_extract_usage_no_usage_key():
    assert extract_usage({"choices": []}) == {}


def test_extract_usage_full():
    resp = {"usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30}}
    result = extract_usage(resp)
    assert result == {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30}


def test_extract_usage_partial():
    resp = {"usage": {"total_tokens": 50}}
    result = extract_usage(resp)
    assert result == {"total_tokens": 50}
    assert "prompt_tokens" not in result


def test_extract_usage_none_values_excluded():
    resp = {"usage": {"prompt_tokens": None, "completion_tokens": 5, "total_tokens": 5}}
    result = extract_usage(resp)
    assert "prompt_tokens" not in result
    assert result["completion_tokens"] == 5


def test_extract_usage_casts_to_int():
    resp = {"usage": {"total_tokens": "42"}}
    result = extract_usage(resp)
    assert result["total_tokens"] == 42
    assert isinstance(result["total_tokens"], int)


def test_extract_usage_null_usage_key():
    resp = {"usage": None}
    result = extract_usage(resp)
    assert result == {}

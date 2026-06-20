# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis_server.storage.base — missing branch coverage."""

from __future__ import annotations

import json

import pytest

from aegis_server.storage.base import StorageNode, IntegrityReport


# ── StorageNode.from_dict — json string node_data (lines 92-98) ──────────────


def test_storage_node_from_dict_json_string_node_data():
    """node_data is a JSON string → json.loads called (lines 92-98)."""
    data = {
        "node_id": "a" * 64,
        "timestamp": "2024-01-01T00:00:00",
        "request_hash": "rh",
        "response_hash": "rh2",
        "merkle_root": "mr",
        "signature": "sig",
        "client_id": "t1",
        "node_data": json.dumps({"prev_hash": "0" * 64, "custom": "value"}),
    }
    node = StorageNode.from_dict(data)
    assert node.node_data["prev_hash"] == "0" * 64
    assert node.node_data["custom"] == "value"


def test_storage_node_from_dict_invalid_json_string_fallback():
    """Invalid JSON string for node_data → falls back to {} (lines 97-98)."""
    data = {
        "node_id": "b" * 64,
        "timestamp": "2024-01-01T00:00:00",
        "request_hash": "rh",
        "response_hash": "rh2",
        "merkle_root": "mr",
        "signature": "sig",
        "client_id": "t1",
        "node_data": "{bad json",
    }
    node = StorageNode.from_dict(data)
    assert node.node_data == {}


def test_storage_node_from_dict_dict_node_data():
    """node_data is already a dict → used directly."""
    data = {
        "node_id": "c" * 64,
        "timestamp": "2024-01-01T00:00:00",
        "request_hash": "rh",
        "response_hash": "rh2",
        "merkle_root": "mr",
        "signature": "sig",
        "client_id": "t1",
        "node_data": {"prev_hash": "0" * 64},
    }
    node = StorageNode.from_dict(data)
    assert node.node_data["prev_hash"] == "0" * 64


def test_storage_node_from_dict_overflow_fields():
    """Extra fields not in _SCALAR_FIELDS go into overflow dict (lines 99-102)."""
    data = {
        "node_id": "d" * 64,
        "timestamp": "2024-01-01T00:00:00",
        "request_hash": "rh",
        "response_hash": "rh2",
        "merkle_root": "mr",
        "signature": "sig",
        "client_id": "t1",
        "node_data": {"prev_hash": "0" * 64},
        "extra_field": "extra_value",
    }
    node = StorageNode.from_dict(data)
    # overflow fields get merged into node_data
    assert node.node_data.get("extra_field") == "extra_value"


# ── StorageNode.to_dict (line 106) ───────────────────────────────────────────


def test_storage_node_to_dict():
    """to_dict returns asdict(self) (line 106)."""
    node = StorageNode(
        node_id="e" * 64,
        timestamp="2024-01-01T00:00:00",
        request_hash="rh",
        response_hash="rh2",
        merkle_root="mr",
        signature="sig",
        client_id="t1",
        node_data={"prev_hash": "0" * 64},
    )
    d = node.to_dict()
    assert d["node_id"] == "e" * 64
    assert isinstance(d, dict)


# ── IntegrityReport ───────────────────────────────────────────────────────────


def test_integrity_report_valid():
    report = IntegrityReport(
        is_valid=True,
        node_count=5,
        first_node_id="a" * 64,
        last_node_id="b" * 64,
        broken_link_index=None,
        error_message=None,
        checked_at="2024-01-01T00:00:00",
    )
    d = report.to_dict()
    assert d["is_valid"] is True
    assert d["node_count"] == 5

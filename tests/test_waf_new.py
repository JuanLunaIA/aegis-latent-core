# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Additional tests for aegis.proxy.waf — missing branch coverage."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from aegis.proxy.waf import AegisWAF, WAFResult


# ── ImportError path for LLMGuardLocal (lines 124-125) ───────────────────────


def test_waf_init_importerror_guard_is_none():
    with patch.dict("sys.modules", {"aegis.core.adversarial_filter": None}):
        waf = AegisWAF()
    assert waf._guard is None


# ── _is_too_deep — returns True (line 182) ───────────────────────────────────


def test_is_too_deep_true_at_depth_11():
    waf = AegisWAF()
    # depth starts at 0; after 11 recursive calls it hits > 10
    nested: dict = {}
    d = nested
    for _ in range(12):
        d["x"] = {}
        d = d["x"]

    assert waf._is_too_deep(nested, depth=0) is True


def test_inspect_payload_too_deep_returns_not_allowed():
    waf = AegisWAF()
    nested: dict = {}
    d = nested
    for _ in range(12):
        d["x"] = {}
        d = d["x"]

    result = waf.inspect_payload(nested)
    assert result.allowed is False
    assert "too deep" in result.reason


# ── Layer-2 WAF block (lines 164-174) ────────────────────────────────────────


def test_inspect_payload_layer2_block():
    waf = AegisWAF()

    mock_result = MagicMock()
    mock_result.is_malicious = True
    mock_result.threat_type = "jailbreak"
    mock_result.confidence = 0.95

    mock_guard = MagicMock()
    mock_guard.analyze_input.return_value = mock_result

    waf._guard = mock_guard
    body = {"messages": [{"role": "user", "content": "benign text for layer 2 test"}]}

    result = waf.inspect_payload(body)
    assert result.allowed is False
    assert "Layer-2" in result.reason
    assert result.score == 0.95


def test_inspect_payload_layer2_exception_allows():
    waf = AegisWAF()

    mock_guard = MagicMock()
    mock_guard.analyze_input.side_effect = Exception("guard error")
    waf._guard = mock_guard

    body = {"messages": [{"role": "user", "content": "benign text"}]}
    result = waf.inspect_payload(body)
    assert result.allowed is True


def test_inspect_payload_layer2_not_malicious_allows():
    waf = AegisWAF()

    mock_result = MagicMock()
    mock_result.is_malicious = False
    mock_guard = MagicMock()
    mock_guard.analyze_input.return_value = mock_result
    waf._guard = mock_guard

    body = {"messages": [{"role": "user", "content": "normal question"}]}
    result = waf.inspect_payload(body)
    assert result.allowed is True


# ── _extract_text — list content blocks (lines 239, 243-246) ─────────────────


def test_extract_text_list_content_blocks():
    waf = AegisWAF()
    body = {
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "Hello"},
                    {"type": "image_url", "url": "http://example.com/img.png"},
                    {"type": "text", "text": "World"},
                ],
            }
        ]
    }
    result = AegisWAF._extract_text(body)
    assert "Hello" in result
    assert "World" in result
    assert "image_url" not in result


def test_extract_text_non_dict_message_skipped():
    waf = AegisWAF()
    body = {
        "messages": [
            "not-a-dict",
            {"role": "user", "content": "actual message"},
        ]
    }
    result = AegisWAF._extract_text(body)
    assert "actual message" in result


def test_extract_text_empty_content_block_list():
    body = {
        "messages": [
            {
                "role": "user",
                "content": [],
            }
        ]
    }
    result = AegisWAF._extract_text(body)
    assert result == ""

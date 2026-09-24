"""
tests/test_zk_preview_guard.py — the forensic preview cap, reachable and guarded.

`DOC-08 §6.3`: zero-knowledge inclusion proofs are practical only over short
leaves, and a leaf's length is dominated by its hex previews. The default cap
(65,536 bytes per preview) puts a default gateway's leaves around 10⁸
constraints. Two things were missing, and these tests pin both:

* **The cap was not reachable.** ``app.py`` built the ledger without
  ``max_forensic_bytes`` and ``aegis/config.py`` had no setting for it, so the
  one trade `DOC-08` tells an operator to make could only be made in-process.
  ``AEGIS_MAX_FORENSIC_BYTES`` now sets it — for the ledger *and* for the
  streaming path, whose preview limit was separately hard-coded to 65,536: a
  lower ledger cap alone made every long stream's terminal commit raise
  ``response_preview exceeds max_forensic_bytes``.
* **Nothing warned.** Where proving is compiled in, startup now says when the
  cap is above every leaf size a proof has been measured for (256; see
  ``aegis_rust_v2/tests/zk_mmr_cost.rs``). It warns and changes nothing: less
  preview is less evidence, and that is the operator's call.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import json
import logging
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from aegis.config import AegisSettings
from aegis.core import zk_native
from aegis.core.zk_native import LARGEST_MEASURED_FORENSIC_BYTES, forensic_preview_warning

SIGNING_KEY = "zk-preview-guard-test-signing-key"


def _settings(tmp_path: Path, **overrides: Any) -> AegisSettings:
    base: dict[str, Any] = {
        "security_enforcement_mode": "development",
        "wal_path": str(tmp_path / "app.wal.jsonl"),
        "backend_api_key": "k",
        "signing_key": SIGNING_KEY,
    }
    base.update(overrides)
    return AegisSettings(**base)


# ── the setting ──────────────────────────────────────────────────────────────


def test_the_default_is_unchanged(tmp_path: Path) -> None:
    assert _settings(tmp_path).max_forensic_bytes == 65_536


def test_the_environment_variable_sets_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGIS_MAX_FORENSIC_BYTES", "0")
    assert _settings(tmp_path).max_forensic_bytes == 0


@pytest.mark.parametrize("value", [-1, 65_537])
def test_out_of_range_values_are_refused(tmp_path: Path, value: int) -> None:
    with pytest.raises(ValidationError):
        _settings(tmp_path, max_forensic_bytes=value)


def test_the_app_builds_its_ledger_with_the_configured_cap(tmp_path: Path) -> None:
    from aegis.proxy.app import create_app

    app = create_app(_settings(tmp_path, max_forensic_bytes=64))
    assert app.state.aegis.ledger.max_forensic_bytes == 64


def test_a_non_streaming_leaf_carries_no_more_preview_than_the_cap(tmp_path: Path) -> None:
    from aegis.core.forensic import build_merkle_leaf
    from aegis.core.mmr import v2_leaf_hash
    from aegis.proxy.app import create_app

    ledger = create_app(
        _settings(tmp_path, max_forensic_bytes=8, mmr_hash_scheme="v2-binary-domain-separated")
    ).state.aegis.ledger
    fields: dict[str, Any] = {
        "state_id": "capped",
        "request_bytes": b"r" * 100,
        "response_bytes": b"s" * 100,
        "model": "m",
        "endpoint": "chat.completions",
    }
    node = ledger.commit_forensic(tenant_id="t", **fields)
    ledger.close()
    capped = build_merkle_leaf(max_bytes=8, **fields)
    assert b'"request_preview_hex":"' + (b"r" * 8).hex().encode() + b'"' in capped
    assert node.mmr_leaf_hash == v2_leaf_hash(capped).hex()
    assert node.mmr_leaf_hash != v2_leaf_hash(build_merkle_leaf(max_bytes=65_536, **fields)).hex()


# ── the streaming path follows the same cap ──────────────────────────────────


def test_a_long_stream_commits_its_terminal_evidence_under_a_small_cap(tmp_path: Path) -> None:
    """Before the fix the stream's preview limit stayed at 65,536 while the
    ledger's cap was 64, so the terminal commit raised and the stream ended
    with no terminal evidence node."""
    from fastapi.testclient import TestClient

    from aegis.proxy.app import create_app

    app = create_app(
        _settings(
            tmp_path,
            max_forensic_bytes=64,
            api_keys="sk-valid",
            auth_disabled=False,
            waf_strict_mode=False,
        )
    )
    state = app.state.aegis

    async def fake_openai(_path: str, _body: Any, extra_headers: Any = None) -> Any:
        for _ in range(50):
            yield b'data: {"choices":[{"delta":{"content":"xxxxxxxx"}}]}\n\n', {"choices": [{}]}
        yield b"data: [DONE]\n\n", None

    forwarder = MagicMock()
    forwarder.stream_sse = MagicMock(side_effect=fake_openai)
    forwarder.provider = SimpleNamespace(name="openai", supports_logprobs=False)

    with TestClient(app) as client:
        real_forwarder, state.forwarder = state.forwarder, forwarder
        try:
            response = client.post(
                "/v1/chat/completions",
                headers={"Authorization": "Bearer sk-valid"},
                json={
                    "model": "m",
                    "messages": [{"role": "user", "content": "hi"}],
                    "stream": True,
                },
            )
        finally:
            # lifespan's shutdown awaits the real forwarder's stop().
            state.forwarder = real_forwarder
        assert response.status_code == 200
        assert len(response.content) > 64
        terminal = [
            node
            for node in state.ledger.chain_snapshot()
            if node.signature_meaning == "stream-terminal-evidence"
        ]
    assert len(terminal) == 1, "the stream's terminal evidence was not committed"
    assert terminal[0].sampling_params["response_size"] > 64
    assert terminal[0].sampling_params["terminal_outcome"] == "complete"


# ── the startup warning ──────────────────────────────────────────────────────


def test_the_threshold_is_the_largest_measured_cap() -> None:
    harness = Path(__file__).resolve().parents[1] / "aegis_rust_v2/tests/zk_mmr_cost.rs"
    text = harness.read_text(encoding="utf-8")
    assert f"max_forensic_bytes = 0 (351), 64 (607) and {LARGEST_MEASURED_FORENSIC_BYTES}" in text


def test_no_warning_without_native_proving(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(zk_native, "has_zk_native", lambda: False)
    assert forensic_preview_warning(65_536) is None


@pytest.mark.parametrize("cap", [0, 64, LARGEST_MEASURED_FORENSIC_BYTES])
def test_no_warning_inside_the_measured_range(monkeypatch: pytest.MonkeyPatch, cap: int) -> None:
    monkeypatch.setattr(zk_native, "has_zk_native", lambda: True)
    assert forensic_preview_warning(cap) is None


def test_a_warning_above_it_names_the_cap_and_the_way_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(zk_native, "has_zk_native", lambda: True)
    message = forensic_preview_warning(LARGEST_MEASURED_FORENSIC_BYTES + 1)
    assert message is not None
    assert f"AEGIS_MAX_FORENSIC_BYTES={LARGEST_MEASURED_FORENSIC_BYTES + 1}" in message
    assert "DOC-08" in message
    assert f"to {LARGEST_MEASURED_FORENSIC_BYTES} or less" in message


def test_the_gateway_logs_it_at_startup_and_changes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    from aegis.proxy.app import create_app

    monkeypatch.setattr(zk_native, "has_zk_native", lambda: True)
    with caplog.at_level(logging.WARNING, logger="aegis.proxy.app"):
        app = create_app(_settings(tmp_path))
    assert any("Zero-knowledge proving is compiled" in r.getMessage() for r in caplog.records)
    assert app.state.aegis.ledger.max_forensic_bytes == 65_536


def test_the_gateway_is_quiet_when_the_cap_is_provable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    from aegis.proxy.app import create_app

    monkeypatch.setattr(zk_native, "has_zk_native", lambda: True)
    with caplog.at_level(logging.WARNING, logger="aegis.proxy.app"):
        create_app(_settings(tmp_path, max_forensic_bytes=LARGEST_MEASURED_FORENSIC_BYTES))
    assert not any("Zero-knowledge" in r.getMessage() for r in caplog.records)


def test_the_setting_is_documented_for_operators() -> None:
    field = AegisSettings.model_fields["max_forensic_bytes"]
    assert field.description is not None
    assert "DOC-08" in field.description
    assert json.dumps(field.description)


def test_the_example_environment_sets_a_value_the_gateway_accepts(tmp_path: Path) -> None:
    """``.env.example`` carried ``AEGIS_MAX_FORENSIC_BYTES=1048576`` from 3.0.1,
    when no setting read it. Now one does, and 1,048,576 is out of range — an
    operator copying the example would have hit a startup refusal."""
    example = Path(__file__).resolve().parents[1] / ".env.example"
    [line] = [
        raw
        for raw in example.read_text(encoding="utf-8").splitlines()
        if raw.startswith("AEGIS_MAX_FORENSIC_BYTES=")
    ]
    value = int(line.split("=", 1)[1])
    assert _settings(tmp_path, max_forensic_bytes=value).max_forensic_bytes == value

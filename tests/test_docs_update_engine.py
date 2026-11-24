# tests/test_docs_update_engine.py
"""Unit tests for scripts/docs_update_engine.py transformations (TDD)."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from docs_update_engine import align_version_tokens  # noqa: E402


def test_version_alignment_replaces_stale_baseline_token() -> None:
    line = "Release baseline: checked-out source metadata is synchronized at v5.0.3"
    result = align_version_tokens(line, current="5.1.0")
    assert "5.1.0" in result
    assert "v5.0.3" not in result or "historical" in result or "superseded" in result

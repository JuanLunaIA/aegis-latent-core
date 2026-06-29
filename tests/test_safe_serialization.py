# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import pickle
from pathlib import Path

import pytest

from aegis.core.safe_serialization import safe_dump_json, safe_load_json, safe_pickle_load


class _EvilPickleClass:
    pass


def test_safe_json_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "data.json"
    payload = {"nodes": [{"id": "abc", "entropy": 1.5}], "ok": True}
    safe_dump_json(payload, path)
    assert safe_load_json(path) == payload


def test_safe_pickle_load_accepts_primitive_dict(tmp_path: Path) -> None:
    path = tmp_path / "data.pkl"
    payload = {"key": "value", "count": 3}
    with path.open("wb") as fh:
        pickle.dump(payload, fh)
    # Test with signature disabled for basic primitive loading
    assert safe_pickle_load(path, require_signature=False) == payload


def test_safe_pickle_load_rejects_forbidden_global(tmp_path: Path) -> None:
    path = tmp_path / "evil.pkl"
    with path.open("wb") as fh:
        pickle.dump(_EvilPickleClass(), fh)

    from aegis.core.safe_serialization import UnsafePickleError

    with pytest.raises(UnsafePickleError):
        safe_pickle_load(path, require_signature=False)


def test_safe_pickle_load_rejects_nested_disallowed_type(tmp_path: Path) -> None:
    path = tmp_path / "nested.pkl"
    with path.open("wb") as fh:
        pickle.dump({"items": [1, 2, object()]}, fh)

    from aegis.core.safe_serialization import UnsafePickleError

    with pytest.raises(UnsafePickleError):
        safe_pickle_load(path, require_signature=False)

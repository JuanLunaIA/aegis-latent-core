# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Additional tests for aegis.core.safe_serialization — covering missing branches."""

from __future__ import annotations

import io
import pickle

import pytest

from aegis.core.safe_serialization import (
    DEFAULT_ALLOWED,
    RestrictedUnpickler,
    UnsafePickleError,
    _validate_allowed,
    safe_pickle_load,
)

# ── _validate_allowed — list and dict branches (lines 48-54) ─────────────────


def test_validate_allowed_list_all_allowed():
    assert _validate_allowed([1, "two", 3.0, True, None], DEFAULT_ALLOWED) is True


def test_validate_allowed_list_with_disallowed():
    # Use an allowed tuple that doesn't include list, triggering the recursive branch
    allowed = (str, int, float)

    class Custom:
        pass

    assert _validate_allowed([1, Custom()], allowed) is False


def test_validate_allowed_list_all_primitives_non_default_allowed():
    allowed = (str, int)  # no list — forces recursive check
    assert _validate_allowed([1, "two"], allowed) is True


def test_validate_allowed_dict_all_allowed():
    # Use an allowed that includes dict but not list to trigger dict recursion
    allowed = (str, int, dict, type(None))
    assert _validate_allowed({"a": 1, "b": "two", "c": None}, allowed) is True


def test_validate_allowed_dict_int_key_allowed():
    allowed = (str, int, dict)
    assert _validate_allowed({1: "one", 2: "two"}, allowed) is True


def test_validate_allowed_dict_with_disallowed_value():
    # allowed doesn't include dict, so triggers dict recursion branch
    allowed = (str, int)

    class Custom:
        pass

    assert _validate_allowed({"k": Custom()}, allowed) is False


def test_validate_allowed_nested_list_in_dict():
    # dict is not in allowed → triggers dict recursion
    allowed = (str, int, list)
    assert _validate_allowed({"items": [1, 2]}, allowed) is True


def test_validate_allowed_returns_false_for_non_primitive():
    class Custom:
        pass

    assert _validate_allowed(Custom(), DEFAULT_ALLOWED) is False


# ── RestrictedUnpickler.find_class — allowed class (line 75) ─────────────────


def test_find_class_allows_builtins_dict():
    buf = io.BytesIO()
    buf.write(pickle.dumps({"a": 1}))
    buf.seek(0)
    unpickler = RestrictedUnpickler(buf)
    result = unpickler.load()
    assert result == {"a": 1}


def test_find_class_allows_builtins_list():
    buf = io.BytesIO()
    buf.write(pickle.dumps([1, 2, 3]))
    buf.seek(0)
    unpickler = RestrictedUnpickler(buf)
    result = unpickler.load()
    assert result == [1, 2, 3]


def test_find_class_forbids_non_builtin():
    import datetime

    buf = io.BytesIO()
    buf.write(pickle.dumps(datetime.datetime(2024, 1, 1)))
    buf.seek(0)
    unpickler = RestrictedUnpickler(buf)
    with pytest.raises((pickle.UnpicklingError, UnsafePickleError)):
        unpickler.load()


# ── safe_pickle_load — disallowed types after load (line 94) ─────────────────


def test_safe_pickle_load_disallowed_type_raises(tmp_path):
    path = tmp_path / "bad.pkl"
    # Construct a pickle that contains valid primitives but patches
    # _validate_allowed to return False
    path.write_bytes(pickle.dumps({"key": "value"}))

    from unittest.mock import patch

    with patch("aegis.core.safe_serialization._validate_allowed", return_value=False):
        with pytest.raises(UnsafePickleError, match="disallowed"):
            safe_pickle_load(path, require_signature=False)


def test_safe_pickle_load_valid_dict(tmp_path):
    path = tmp_path / "ok.pkl"
    path.write_bytes(pickle.dumps({"key": "val", "num": 42}))
    result = safe_pickle_load(path, require_signature=False)
    assert result == {"key": "val", "num": 42}


def test_safe_pickle_load_valid_list(tmp_path):
    path = tmp_path / "list.pkl"
    path.write_bytes(pickle.dumps([1, "two", 3.0]))
    result = safe_pickle_load(path, require_signature=False)
    assert result == [1, "two", 3.0]

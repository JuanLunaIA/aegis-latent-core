"""Safe helpers for serialization and deserialization.

This module provides opinionated helpers to favor JSON interchange and a
guarded ``pickle`` loader that enforces allowed types and basic structural
validation. It is a pragmatic compromise: when pickle is unavoidable,
require signed artifacts and strict type checks.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import json
import logging
import pickle
from collections.abc import Iterable
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Default primitive allowed types for pickled artifacts
DEFAULT_ALLOWED = (dict, list, str, int, float, bool, type(None))


def safe_dump_json(obj: Any, path: str | Path, ensure_ascii: bool = False) -> None:
    """Dump obj to path using JSON. Prefer this for persisted interchange."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as fh:
        json.dump(obj, fh, ensure_ascii=ensure_ascii, indent=2)


def safe_load_json(path: str | Path) -> Any:
    p = Path(path)
    with p.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _validate_allowed(obj: Any, allowed: tuple[type, ...]) -> bool:
    """Recursively validate that obj only contains allowed primitive types.

    This is intentionally conservative. Complex objects should be serialized
    via JSON-compatible structures or explicitly whitelisted.
    """
    if isinstance(obj, allowed):
        return True
    if isinstance(obj, list):
        return all(_validate_allowed(i, allowed) for i in obj)
    if isinstance(obj, dict):
        return all(
            isinstance(k, (str, int)) and _validate_allowed(v, allowed) for k, v in obj.items()
        )
    return False


class RestrictedUnpickler(pickle.Unpickler):
    def __init__(self, *args, allowed_classes: set[str] | None = None, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.allowed_classes = allowed_classes or {
            "dict",
            "list",
            "str",
            "int",
            "float",
            "bool",
            "NoneType",
            "bytearray",
            "bytes",
        }

    def find_class(self, module: str, name: str) -> Any:
        # Only allow primitives from builtins module
        if module == "builtins" and name in self.allowed_classes:
            return super().find_class(module, name)
        raise pickle.UnpicklingError(f"Global '{module}.{name}' is forbidden")


def safe_pickle_load(path: str | Path, allowed_types: Iterable[type] | None = None) -> Any:
    """Load a pickle file but enforce an allowed type whitelist prior to object creation.

    WARNING: Pickle is inherently risky for untrusted input. Use this only
    for signed, internally-produced artifacts. Prefer JSON whenever possible.
    """
    p = Path(path)
    allowed = tuple(allowed_types) if allowed_types is not None else DEFAULT_ALLOWED
    allowed_names = {t.__name__ for t in allowed}

    with p.open("rb") as fh:
        unpickler = RestrictedUnpickler(fh, allowed_classes=allowed_names)
        obj = unpickler.load()

    if not _validate_allowed(obj, allowed):
        raise pickle.UnpicklingError("Pickle payload contains disallowed types after load")
    return obj

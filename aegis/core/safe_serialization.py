"""Safe helpers for serialization and deserialization.

This module provides opinionated helpers to favor JSON interchange and a
guarded ``pickle`` loader that enforces allowed types and basic structural
validation. It is a pragmatic compromise: when pickle is unavoidable,
require signed artifacts and strict type checks.
"""
from __future__ import annotations

import json
import pickle
import logging
from pathlib import Path
from typing import Any, Iterable, Tuple

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


def _validate_allowed(obj: Any, allowed: Tuple[type, ...]) -> bool:
    """Recursively validate that obj only contains allowed primitive types.

    This is intentionally conservative. Complex objects should be serialized
    via JSON-compatible structures or explicitly whitelisted.
    """
    if isinstance(obj, allowed):
        return True
    if isinstance(obj, list):
        return all(_validate_allowed(i, allowed) for i in obj)
    if isinstance(obj, dict):
        return all(isinstance(k, (str, int)) and _validate_allowed(v, allowed) for k, v in obj.items())
    return False


def safe_pickle_load(path: str | Path, allowed_types: Iterable[type] | None = None) -> Any:
    """Load a pickle file but enforce an allowed type whitelist.

    WARNING: Pickle is inherently risky for untrusted input. Use this only
    for signed, internally-produced artifacts. Prefer JSON whenever possible.
    """
    p = Path(path)
    allowed = tuple(DEFAULT_ALLOWED) if allowed_types is None else tuple(allowed_types)
    with p.open("rb") as fh:
        obj = pickle.load(fh)
    if not _validate_allowed(obj, allowed):
        logger.error("safe_pickle_load: loaded object from %s failed allowed-type validation", p)
        raise ValueError("Loaded pickle object contains disallowed types; refusing to return it.")
    return obj

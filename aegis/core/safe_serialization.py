"""Safe helpers for serialization and deserialization.

This module provides opinionated helpers to favor JSON interchange and a
guarded ``pickle`` loader that enforces allowed types, basic structural
validation, and optional HMAC signature verification. It is a pragmatic
compromise: when pickle is unavoidable, require signed artifacts and strict
type checks. However, migration to JSON or other safer formats is strongly
recommended.

WARNING: Pickle is inherently unsafe for untrusted data. This module provides
mitigations but cannot eliminate all risks. Prefer JSON, MessagePack, or
protocol buffers for new code.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import pickle
import warnings
from collections.abc import Iterable
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Default primitive allowed types for pickled artifacts
DEFAULT_ALLOWED = (dict, list, str, int, float, bool, type(None))

# Secret key for HMAC signatures (should be loaded from secure environment)
_PICKLE_HMAC_KEY = os.environ.get("AEGIS_PICKLE_HMAC_KEY", "").encode("utf-8")


class SerializationError(Exception):
    """Base exception for serialization errors."""

    pass


class SignatureVerificationError(SerializationError):
    """Raised when HMAC signature verification fails."""

    pass


class UnsafePickleError(SerializationError):
    """Raised when pickle payload contains unsafe types or structures."""

    pass


def _compute_hmac(data: bytes, key: bytes) -> bytes:
    """Compute HMAC-SHA256 of data using the provided key."""
    if not key:
        raise SerializationError("HMAC key not configured. Set AEGIS_PICKLE_HMAC_KEY.")
    return hmac.new(key, data, hashlib.sha256).digest()


def sign_artifact(data: bytes, key: bytes | None = None) -> tuple[bytes, bytes]:
    """Sign artifact data with HMAC-SHA256.

    Args:
        data: The artifact data to sign
        key: Optional key override; defaults to AEGIS_PICKLE_HMAC_KEY env var

    Returns:
        Tuple of (data, signature)

    Raises:
        SerializationError: If no key is available
    """
    if key is None:
        key = _PICKLE_HMAC_KEY
    if not key:
        raise SerializationError("HMAC key not configured. Set AEGIS_PICKLE_HMAC_KEY.")
    signature = _compute_hmac(data, key)
    return data, signature


def verify_artifact_signature(data: bytes, signature: bytes, key: bytes | None = None) -> bool:
    """Verify HMAC-SHA256 signature of artifact data.

    Args:
        data: The artifact data to verify
        signature: The expected signature
        key: Optional key override; defaults to AEGIS_PICKLE_HMAC_KEY env var

    Returns:
        True if signature is valid

    Raises:
        SignatureVerificationError: If signature verification fails
    """
    if key is None:
        key = _PICKLE_HMAC_KEY
    if not key:
        raise SignatureVerificationError("HMAC key not configured. Set AEGIS_PICKLE_HMAC_KEY.")
    expected = _compute_hmac(data, key)
    if not hmac.compare_digest(expected, signature):
        raise SignatureVerificationError("Signature verification failed")
    return True


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
    """Restricted unpickler that only allows safe primitive types.

    This class provides defense-in-depth by restricting which classes can be
    instantiated during unpickling. It should be used in conjunction with
    HMAC signature verification for complete protection.
    """

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
        raise UnsafePickleError(f"Global '{module}.{name}' is forbidden")


def safe_pickle_load(
    path: str | Path,
    allowed_types: Iterable[type] | None = None,
    require_signature: bool = True,
    signature_path: str | Path | None = None,
) -> Any:
    """Load a pickle file with strict security controls.

    This function enforces multiple security measures:
    1. Optional HMAC signature verification before loading
    2. Restricted unpickler that only allows safe primitive types
    3. Post-load validation of object structure

    Args:
        path: Path to the pickle file
        allowed_types: Optional iterable of allowed types (defaults to primitives)
        require_signature: If True, requires HMAC signature verification
        signature_path: Path to signature file; if None, uses <path>.sig

    Returns:
        The deserialized object

    Raises:
        SignatureVerificationError: If signature verification fails
        UnsafePickleError: If payload contains disallowed types
        SerializationError: If other serialization errors occur

    WARNING: Pickle is inherently risky for untrusted input. Use this only
    for signed, internally-produced artifacts. Prefer JSON whenever possible.
    Consider migrating to safer formats like JSON, MessagePack, or protocol buffers.
    """
    p = Path(path)
    allowed = tuple(allowed_types) if allowed_types is not None else DEFAULT_ALLOWED
    allowed_names = {t.__name__ for t in allowed}

    # Verify signature if required
    if require_signature:
        sig_path = Path(signature_path) if signature_path else p.with_suffix(p.suffix + ".sig")
        if not sig_path.exists():
            raise SignatureVerificationError(f"Signature file not found: {sig_path}")

        try:
            data = p.read_bytes()
            signature = sig_path.read_bytes()
            verify_artifact_signature(data, signature)
            logger.debug("Signature verification succeeded for %s", p)
        except SignatureVerificationError:
            logger.error("Signature verification failed for %s", p)
            raise
        except Exception as e:
            logger.error("Error reading signature files: %s", e)
            raise SignatureVerificationError(f"Failed to read signature files: {e}")

    # Load with restricted unpickler
    try:
        with p.open("rb") as fh:
            unpickler = RestrictedUnpickler(fh, allowed_classes=allowed_names)
            obj = unpickler.load()
    except UnsafePickleError:
        logger.error("Unsafe pickle payload detected in %s", p)
        raise
    except pickle.UnpicklingError as e:
        logger.error("Unpickling error for %s: %s", p, e)
        raise UnsafePickleError(f"Unpickling failed: {e}")
    except Exception as e:
        logger.error("Unexpected error loading pickle %s: %s", p, e)
        raise SerializationError(f"Failed to load pickle: {e}")

    # Post-load validation
    if not _validate_allowed(obj, allowed):
        logger.error("Post-load validation failed for %s", p)
        raise UnsafePickleError("Pickle payload contains disallowed types after load")

    logger.debug("Successfully loaded and validated pickle from %s", p)
    return obj


def safe_pickle_dump(
    obj: Any,
    path: str | Path,
    sign: bool = True,
    allowed_types: Iterable[type] | None = None,
) -> tuple[Path, Path | None]:
    """Safely dump an object to pickle format with optional signing.

    This function validates the object structure before serialization and
    optionally signs the output with HMAC-SHA256 for integrity verification.

    Args:
        obj: The object to serialize
        path: Path to write the pickle file
        sign: If True, also write an HMAC signature file
        allowed_types: Optional iterable of allowed types to validate before dumping

    Returns:
        Tuple of (pickle_path, signature_path or None)

    Raises:
        UnsafePickleError: If object contains disallowed types
        SerializationError: If serialization fails

    WARNING: Pickle is inherently risky. Prefer JSON whenever possible.
    This function should only be used for trusted internal data.
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)

    # Pre-dump validation
    allowed = tuple(allowed_types) if allowed_types is not None else DEFAULT_ALLOWED
    if not _validate_allowed(obj, allowed):
        raise UnsafePickleError("Object contains disallowed types before serialization")

    # Serialize
    try:
        data = pickle.dumps(obj, protocol=pickle.HIGHEST_PROTOCOL)
    except Exception as e:
        logger.error("Pickling failed: %s", e)
        raise SerializationError(f"Failed to pickle object: {e}")

    # Write pickle file
    p.write_bytes(data)
    logger.debug("Wrote pickle to %s", p)

    # Sign if requested
    sig_path = None
    if sign:
        try:
            _, signature = sign_artifact(data)
            sig_path = p.with_suffix(p.suffix + ".sig")
            sig_path.write_bytes(signature)
            logger.debug("Wrote signature to %s", sig_path)
        except SerializationError as e:
            logger.warning("Signing failed (key not configured?): %s", e)
            # Don't fail the operation, but warn
            warnings.warn(f"Pickle written without signature: {e}", UserWarning)

    return p, sig_path

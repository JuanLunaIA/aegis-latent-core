# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Versioned HMAC keyring with atomic, fail-closed configuration reload.

The keyring file is expected to be written by a secret manager or an operator
using an atomic rename. The file itself must be owner-readable only. Secrets
are never emitted in logs, repr output, or error messages.

Schema::

    {
      "version": 1,
      "active_key_id": "hmac-2026-08",
      "keys": [
        {"key_id": "hmac-2026-07", "secret": "...", "state": "verify"},
        {"key_id": "hmac-2026-08", "secret": "...", "state": "active"}
      ]
    }

A valid reload is parsed and validated completely before the active snapshot is
swapped. An invalid or unavailable reload leaves the last valid snapshot active
and increments the observable failure counter. At process start, no valid
snapshot means construction fails; a signer must never start without a valid
key.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import stat
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aegis_server.crypto.base import SignerProvider

logger = logging.getLogger(__name__)

_KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_MIN_SECRET_BYTES = 32


class KeyringConfigurationError(ValueError):
    """Raised when a keyring cannot satisfy the runtime signing contract."""


@dataclass(frozen=True)
class _KeyRecord:
    key_id: str
    secret: bytes
    state: str
    expires_at: float | None


@dataclass(frozen=True)
class _KeyringSnapshot:
    active_key_id: str
    keys: tuple[_KeyRecord, ...]
    source_stat: tuple[int, int, int]
    loaded_at: float


class RotatingHMACSigner(SignerProvider):
    """HMAC-SHA256 signer with zero-restart key rotation.

    ``sign_payload_with_metadata`` returns the exact key ID used for a
    signature. Verification accepts the active key and non-expired historical
    keys during the configured overlap window.
    """

    scheme = "hmac-sha256-keyring"

    def __init__(self, keyring_path: str, *, reload_interval_s: float = 1.0) -> None:
        if not keyring_path or not keyring_path.strip():
            raise KeyringConfigurationError("keyring_path must be non-empty")
        if reload_interval_s < 0 or reload_interval_s > 300:
            raise KeyringConfigurationError("reload_interval_s must be between 0 and 300 seconds")
        self._path = Path(keyring_path).expanduser().resolve()
        self._reload_interval_s = float(reload_interval_s)
        self._snapshot: _KeyringSnapshot | None = None
        self._last_reload_attempt = 0.0
        self._reload_failures = 0
        self._lock = threading.RLock()
        self._reload(force=True)

    @property
    def keyring_path(self) -> str:
        return str(self._path)

    @property
    def current_key_id(self) -> str:
        self._reload_if_due()
        snapshot = self._snapshot_or_raise()
        return snapshot.active_key_id

    @property
    def reload_failures(self) -> int:
        with self._lock:
            return self._reload_failures

    @property
    def loaded_at(self) -> float:
        self._reload_if_due()
        return self._snapshot_or_raise().loaded_at

    async def sign_payload(self, data: bytes) -> str:
        signature, _ = await self.sign_payload_with_metadata(data)
        return signature

    async def sign_payload_with_metadata(self, data: bytes) -> tuple[str, str]:
        if not isinstance(data, bytes):
            raise TypeError("data must be bytes")
        self._reload_if_due()
        snapshot = self._snapshot_or_raise()
        active = next(key for key in snapshot.keys if key.key_id == snapshot.active_key_id)
        signature = hmac.new(active.secret, data, hashlib.sha256).hexdigest()
        return signature, active.key_id

    async def verify(self, data: bytes, signature_hex: str) -> bool:
        if not isinstance(data, bytes) or not isinstance(signature_hex, str):
            return False
        if len(signature_hex) != 64:
            return False
        try:
            supplied = bytes.fromhex(signature_hex)
        except ValueError:
            return False
        self._reload_if_due()
        now = time.time()
        for record in self._snapshot_or_raise().keys:
            if record.expires_at is not None and record.expires_at < now:
                continue
            expected = hmac.new(record.secret, data, hashlib.sha256).digest()
            if hmac.compare_digest(expected, supplied):
                return True
        return False

    def _reload_if_due(self) -> None:
        now = time.monotonic()
        with self._lock:
            due = (
                self._snapshot is None or now - self._last_reload_attempt >= self._reload_interval_s
            )
        if due:
            self._reload(force=False)

    def _reload(self, *, force: bool) -> None:
        now_monotonic = time.monotonic()
        with self._lock:
            if not force and now_monotonic - self._last_reload_attempt < self._reload_interval_s:
                return
            self._last_reload_attempt = now_monotonic
        try:
            file_stat = self._path.stat()
            if not stat.S_ISREG(file_stat.st_mode):
                raise KeyringConfigurationError("keyring path must be a regular file")
            if stat.S_IMODE(file_stat.st_mode) & 0o077:
                raise KeyringConfigurationError("keyring file must be owner-readable only")
            source_stat = (file_stat.st_mtime_ns, file_stat.st_size, file_stat.st_ino)
            with self._lock:
                if (
                    not force
                    and self._snapshot is not None
                    and self._snapshot.source_stat == source_stat
                ):
                    return
            raw = self._path.read_text(encoding="utf-8")
            parsed = json.loads(raw)
            snapshot = self._validate_snapshot(parsed, source_stat)
        except (OSError, UnicodeError, json.JSONDecodeError, KeyringConfigurationError) as exc:
            with self._lock:
                self._reload_failures += 1
                has_snapshot = self._snapshot is not None
            if has_snapshot:
                logger.error(
                    "keyring reload rejected; retaining previous valid snapshot: %s",
                    type(exc).__name__,
                )
                return
            raise KeyringConfigurationError("initial keyring load failed") from exc
        with self._lock:
            self._snapshot = snapshot
        logger.info("keyring snapshot activated: key_id=%s", snapshot.active_key_id)

    @staticmethod
    def _validate_snapshot(data: Any, source_stat: tuple[int, int, int]) -> _KeyringSnapshot:
        if not isinstance(data, dict) or data.get("version") != 1:
            raise KeyringConfigurationError("keyring version must be 1")
        active_key_id = data.get("active_key_id")
        keys = data.get("keys")
        if not isinstance(active_key_id, str) or not _KEY_ID_RE.fullmatch(active_key_id):
            raise KeyringConfigurationError("active_key_id is invalid")
        if not isinstance(keys, list) or not keys:
            raise KeyringConfigurationError("keyring keys must be a non-empty list")
        records: list[_KeyRecord] = []
        seen: set[str] = set()
        for item in keys:
            if not isinstance(item, dict):
                raise KeyringConfigurationError("each keyring entry must be an object")
            key_id = item.get("key_id")
            secret = item.get("secret")
            state = item.get("state", "verify")
            expires_at = item.get("expires_at")
            if not isinstance(key_id, str) or not _KEY_ID_RE.fullmatch(key_id) or key_id in seen:
                raise KeyringConfigurationError("key_id is invalid or duplicated")
            if not isinstance(secret, str) or len(secret.encode("utf-8")) < _MIN_SECRET_BYTES:
                raise KeyringConfigurationError("keyring secret must be at least 32 UTF-8 bytes")
            if state not in {"active", "verify"}:
                raise KeyringConfigurationError("key state must be active or verify")
            if expires_at is not None and (
                not isinstance(expires_at, (int, float)) or expires_at <= 0
            ):
                raise KeyringConfigurationError("expires_at must be a positive Unix timestamp")
            seen.add(key_id)
            records.append(
                _KeyRecord(
                    key_id,
                    secret.encode("utf-8"),
                    state,
                    float(expires_at) if expires_at is not None else None,
                )
            )
        active_records = [record for record in records if record.key_id == active_key_id]
        if len(active_records) != 1 or active_records[0].state != "active":
            raise KeyringConfigurationError("active_key_id must name exactly one active key")
        if sum(record.state == "active" for record in records) != 1:
            raise KeyringConfigurationError("exactly one active key is required")
        return _KeyringSnapshot(active_key_id, tuple(records), source_stat, time.time())

    def _snapshot_or_raise(self) -> _KeyringSnapshot:
        with self._lock:
            snapshot = self._snapshot
        if snapshot is None:
            raise RuntimeError("no valid keyring snapshot is active")
        return snapshot

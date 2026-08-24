# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.auth.scopes — HIPAA minimum-necessary API key scope enforcement.

Implements scope-based access control so API keys can be restricted to only the
operations each caller legitimately needs — implementing the HIPAA Security Rule
§164.312(a)(1) "minimum necessary" access principle.

Scope definitions
-----------------
``proxy:completions``
    Access to ``/v1/chat/completions`` and ``/v1/completions``.

``audit:read``
    Read-only access to ``/v1/audit/nodes``, ``/v1/audit/integrity``,
    ``/v1/audit/tenants``, and ``/v1/audit/health``.

``audit:export``
    Access to ``/v1/audit/export/part11`` (21 CFR Part 11 signature records).
    Should be restricted to compliance officers and auditors.

``audit:analytics``
    Reserved for a future reviewed analytics surface. No analytics endpoint is
    currently published because the repository has no durable privacy accountant.

Configuration
-------------
Set ``AEGIS_API_KEY_SCOPES`` to a semicolon-separated list of ``key:scope1,scope2``
pairs.  Keys not listed here inherit the full default scope set::

    AEGIS_API_KEY_SCOPES="read-only-key:audit:read;export-key:audit:read,audit:export"

Keys that appear in ``AEGIS_API_KEYS`` but not in ``AEGIS_API_KEY_SCOPES`` receive
all scopes (backward-compatible with deployments that haven't configured scopes).
"""

from __future__ import annotations

import hmac

# ── Predefined scope constants ────────────────────────────────────────────────

SCOPE_PROXY_COMPLETIONS = "proxy:completions"
SCOPE_AUDIT_READ = "audit:read"
SCOPE_AUDIT_EXPORT = "audit:export"
SCOPE_AUDIT_ANALYTICS = "audit:analytics"

ALL_SCOPES: frozenset[str] = frozenset(
    {
        SCOPE_PROXY_COMPLETIONS,
        SCOPE_AUDIT_READ,
        SCOPE_AUDIT_EXPORT,
        SCOPE_AUDIT_ANALYTICS,
    }
)


class ScopeViolationError(PermissionError):
    """Raised when a key lacks the required scope for the requested operation."""

    def __init__(self, required_scope: str, key_scopes: frozenset[str]) -> None:
        self.required_scope = required_scope
        self.key_scopes = key_scopes
        super().__init__(
            f"API key lacks required scope {required_scope!r}. Key has scopes: {sorted(key_scopes)}"
        )


def parse_scope_config(scope_config: str) -> dict[str, frozenset[str]]:
    """Parse ``AEGIS_API_KEY_SCOPES`` into a ``{key: frozenset[scope]}`` mapping.

    Format: ``key1:scope1,scope2;key2:scope3``

    Unknown scope strings are accepted without error (future-proofing).
    An empty ``scope_config`` returns an empty dict (all keys inherit ALL_SCOPES).

    Parameters
    ----------
    scope_config:
        Raw value of the ``AEGIS_API_KEY_SCOPES`` environment variable.

    Returns
    -------
    dict[str, frozenset[str]]
        Mapping from API key string to its assigned scope set.
    """
    if not scope_config.strip():
        return {}

    result: dict[str, frozenset[str]] = {}
    for entry in scope_config.split(";"):
        entry = entry.strip()
        if not entry:
            continue
        if ":" not in entry:
            continue
        key, _, scopes_str = entry.partition(":")
        key = key.strip()
        if not key:
            continue
        scopes = frozenset(s.strip() for s in scopes_str.split(",") if s.strip())
        result[key] = scopes
    return result


class ScopedKeyRegistry:
    """Constant-time API key validator with per-key scope enforcement.

    Wraps the existing key-validation logic and adds scope checking so callers
    can express minimum-necessary access requirements at the endpoint level.

    Parameters
    ----------
    valid_keys:
        Frozenset of API key strings (as configured via ``AEGIS_API_KEYS``).
    scope_map:
        Per-key scope restrictions parsed from ``AEGIS_API_KEY_SCOPES``.
        Keys not present in this map inherit :data:`ALL_SCOPES`.
    """

    def __init__(
        self,
        valid_keys: frozenset[str],
        scope_map: dict[str, frozenset[str]] | None = None,
    ) -> None:
        self._keys = valid_keys
        self._scope_map = scope_map or {}

    def validate(self, key: str) -> frozenset[str]:
        """Validate *key* and return its assigned scope set.

        Parameters
        ----------
        key:
            The raw bearer token string.

        Returns
        -------
        frozenset[str]
            The scopes granted to this key.

        Raises
        ------
        KeyError
            When the key is not in the valid-key set.
        """
        if not self._constant_time_in(key):
            raise KeyError("Invalid API key")
        return self._scope_map.get(key, ALL_SCOPES)

    def require_scope(self, key: str, required_scope: str) -> frozenset[str]:
        """Validate *key* and assert it holds *required_scope*.

        Parameters
        ----------
        key:
            The raw bearer token.
        required_scope:
            One of the ``SCOPE_*`` constants defined in this module.

        Returns
        -------
        frozenset[str]
            The full scope set of the validated key.

        Raises
        ------
        KeyError
            When the key is invalid.
        ScopeViolationError
            When the key lacks the required scope.
        """
        scopes = self.validate(key)
        if required_scope not in scopes:
            raise ScopeViolationError(required_scope=required_scope, key_scopes=scopes)
        return scopes

    def _constant_time_in(self, key: str) -> bool:
        """Timing-safe key membership check."""
        result = False
        for valid in self._keys:
            match = hmac.compare_digest(key.encode(), valid.encode())
            result = result or match
        return result

    @classmethod
    def from_config(
        cls,
        valid_keys: frozenset[str],
        scope_config: str,
    ) -> ScopedKeyRegistry:
        """Construct from ``AEGIS_API_KEYS`` and ``AEGIS_API_KEY_SCOPES`` values."""
        return cls(valid_keys=valid_keys, scope_map=parse_scope_config(scope_config))

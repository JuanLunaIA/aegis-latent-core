"""aegis.core — Mathematical and cryptographic telemetry primitives.

This package intentionally avoids importing heavy submodules (numpy, httpx,
etc.) at import time to make tooling and small tests lightweight. Submodules
and attributes are lazily loaded when accessed.
"""

# Lightweight, lazily-importing package initializer.
from importlib import import_module
from types import ModuleType
from typing import Any

# Primary submodules that compose aegis.core. These are imported on demand.
_SUBMODULES = [
    "mmr",
    "math_utils",
    "moe_monitor",
    "session_manager",
    "telemetry",
    "crypto_audit",
]

__all__ = _SUBMODULES[:]  # expose submodule names by default

# License note preserved
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.


def __getattr__(name: str) -> Any:
    """Lazily import submodules or attributes.

    - If ``name`` matches a known submodule (e.g., "mmr"), import and return the
      module object.
    - Otherwise, search declared submodules for an attribute with the given
      name and return it (caches the resolved attribute on the package).
    """
    if name in _SUBMODULES:
        mod = import_module(f"{__name__}.{name}")
        globals()[name] = mod
        return mod

    # Search submodules for the requested attribute; import only as needed.
    for sub in _SUBMODULES:
        try:
            mod = import_module(f"{__name__}.{sub}")
        except Exception:
            # If a submodule fails to import because of missing heavy deps,
            # skip it; callers will get an AttributeError below if nothing found.
            continue
        if hasattr(mod, name):
            val = getattr(mod, name)
            globals()[name] = val
            return val

    raise AttributeError(f"module {__name__} has no attribute {name}")


def __dir__() -> list[str]:
    return sorted(list(globals().keys()) + _SUBMODULES)

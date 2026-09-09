# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

"""Decoupled engine facades over capabilities that already exist in the core.

Each engine is a thin, importable surface over modules under ``aegis.core``.
They add no capability: they group existing ones behind an interface that can
be used without running the HTTP gateway, so an application can embed one
without adopting the proxy.

    from aegis.engines import VeracityEngine
    engine = VeracityEngine(wal_path="/var/lib/aegis/evidence.jsonl")

Licensing does not gate the AGPLv3 software
-------------------------------------------

By default these engines run unlicensed, exactly as the gateway does. The
AGPLv3 grant is a grant to use, and making import depend on a commercial token
would both contradict it and break every existing deployment.

Gating is opt-in through ``AEGIS_LICENSE_ENFORCEMENT``:

``off`` (default)
    No check. A configured token is still parsed and exposed for reporting.
``required``
    Constructing an engine whose module is not granted raises
    :class:`~aegis.licensing.validator.LicenseError`. Intended for a commercial
    distribution that wants entitlement mismatches to surface at start rather
    than in production.

Nothing here contacts a licence server, in either mode.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Final

from aegis.licensing.validator import (
    LicenseEntitlement,
    LicenseError,
    load_entitlement_from_env,
)

#: Environment variable selecting the enforcement posture.
ENFORCEMENT_ENV: Final[str] = "AEGIS_LICENSE_ENFORCEMENT"

_ENFORCEMENT_OFF: Final[str] = "off"
_ENFORCEMENT_REQUIRED: Final[str] = "required"
_VALID_MODES: Final[frozenset[str]] = frozenset({_ENFORCEMENT_OFF, _ENFORCEMENT_REQUIRED})


def enforcement_mode(env: Mapping[str, str] | None = None) -> str:
    """Return the configured posture, defaulting to ``off``.

    An unrecognised value raises rather than silently falling back to ``off``:
    a typo in the variable that turns enforcement off is precisely the failure
    an operator would not notice.
    """

    source = os.environ if env is None else env
    mode = source.get(ENFORCEMENT_ENV, _ENFORCEMENT_OFF).strip().lower() or _ENFORCEMENT_OFF
    if mode not in _VALID_MODES:
        raise ValueError(
            f"{ENFORCEMENT_ENV}={mode!r} is not recognised; expected one of {sorted(_VALID_MODES)}"
        )
    return mode


def require_module(
    module_name: str,
    *,
    entitlement: LicenseEntitlement | None = None,
    env: Mapping[str, str] | None = None,
) -> LicenseEntitlement | None:
    """Enforce the entitlement for ``module_name`` under the configured posture.

    Returns the entitlement in force, or ``None`` when none is configured.
    Raises :class:`LicenseError` only in ``required`` mode with the module
    ungranted.
    """

    mode = enforcement_mode(env)
    if entitlement is None:
        entitlement = load_entitlement_from_env(env)

    if mode == _ENFORCEMENT_REQUIRED:
        if entitlement is None:
            raise LicenseError(
                f"{ENFORCEMENT_ENV}={_ENFORCEMENT_REQUIRED} but no license token is "
                f"configured; the {module_name!r} engine cannot start"
            )
        if not entitlement.has_module(module_name):
            raise LicenseError(
                f"license for {entitlement.customer_id!r} does not grant the "
                f"{module_name!r} engine (granted: {sorted(entitlement.modules)})"
            )
    return entitlement


from aegis.engines.agentis import AgentisEngine  # noqa: E402
from aegis.engines.sanctum import SanctumEngine  # noqa: E402
from aegis.engines.sovereign import SovereignVault  # noqa: E402
from aegis.engines.veracity import VeracityEngine  # noqa: E402

__all__ = [
    "ENFORCEMENT_ENV",
    "AgentisEngine",
    "SanctumEngine",
    "SovereignVault",
    "VeracityEngine",
    "enforcement_mode",
    "require_module",
]

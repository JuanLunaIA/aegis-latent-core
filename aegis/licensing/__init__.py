# Copyright (c) 2026 Juan Luna. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
# Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.

"""Offline verification of entitlement tokens.

The entitlement carried by a token gates the optional engine facades in
:mod:`aegis.engines` when ``AEGIS_LICENSE_ENFORCEMENT=required``, and
:mod:`aegis.licensing.startup` checks it once before the gateway binds (a strict
gateway needs a verified token after a 30-day evaluation). A token is an
entitlement signal; the licence terms themselves are in ``LICENSE``. Nothing in
this package reaches the network.

:mod:`aegis.licensing.model` holds the entitlement data model on its own;
:mod:`aegis.licensing.validator` holds token decoding and signature checking.
Both are re-exported here, so importing from either module or from the package
gives the same objects.
"""

from aegis.licensing.model import KNOWN_MODULES, WILDCARD_MODULE, LicenseEntitlement
from aegis.licensing.validator import (
    LicenseEnforcement,
    LicenseError,
    LicenseExpiredError,
    LicenseMalformedError,
    LicenseSignatureError,
    load_entitlement_from_env,
    root_public_key_from_env,
)

__all__ = [
    "KNOWN_MODULES",
    "WILDCARD_MODULE",
    "LicenseEnforcement",
    "LicenseEntitlement",
    "LicenseError",
    "LicenseExpiredError",
    "LicenseMalformedError",
    "LicenseSignatureError",
    "load_entitlement_from_env",
    "root_public_key_from_env",
]

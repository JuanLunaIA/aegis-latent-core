# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

"""Offline verification of commercial license tokens.

The entitlement carried by a token gates the optional engine facades in
:mod:`aegis.engines`. Nothing in this package reaches the network, and nothing
in it changes gateway behaviour: the AGPLv3 gateway runs unlicensed.

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

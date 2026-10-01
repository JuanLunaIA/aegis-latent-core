# Copyright (c) 2026 Juan Luna.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE.

"""Offline verification of entitlement tokens.

The entitlement carried by a token gates the optional engine facades in
:mod:`aegis.engines`, and only when ``AEGIS_LICENSE_ENFORCEMENT=required``. It
is an entitlement signal, not a legal licence grant: the source is licensed
under Apache-2.0 regardless of any token. Nothing in this package reaches the
network, and nothing in it changes gateway behaviour: the gateway runs with no
token.

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

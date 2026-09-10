# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

"""The licence data model, separated from the code that verifies signatures.

:mod:`aegis.licensing.validator` decodes a token, checks an Ed25519 signature
over it, and hands back a :class:`LicenseEntitlement`. This module holds only
the entitlement itself: what a verified token grants, and how to ask whether it
still grants it. Its own imports are the standard library alone — no crypto
backend, no environment reads — so the answer to "what does a token grant, and
is it still in term?" can be read and reasoned about without the verifier.

That is a statement about this module's dependencies, not about what an
``import`` pulls in at runtime: importing it initialises the
``aegis.licensing`` package, which re-exports the verifier and therefore does
load a crypto backend.

Time is a parameter, not an ambient fact
----------------------------------------

:meth:`LicenseEntitlement.is_valid` and :meth:`LicenseEntitlement.has_module`
take an explicit ``now`` in epoch seconds. Omitting it falls back to
``time.time()``, which is what every existing call site does and what the
gateway does in production. Passing it makes expiry deterministic, which is the
only way to test the boundary — a test that constructs a token expiring "one
second from now" and asserts on it is a test that fails on a slow machine.

Supplying ``now`` does not make expiry trustworthy. The value still comes from
the caller, and offline licensing has no trusted time source: a host whose
clock runs backwards extends its own licence, and nothing in this package can
detect that. See the :mod:`aegis.licensing.validator` module docstring for the
full boundary; injecting the clock narrows a testing problem, not a threat.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Final

#: Modules a token may grant. ``omnia`` is the wildcard covering all four.
KNOWN_MODULES: Final[frozenset[str]] = frozenset(
    {"veracity", "sanctum", "agentis", "sovereign", "omnia"}
)

#: The module name that grants every other module.
WILDCARD_MODULE: Final[str] = "omnia"


@dataclass(frozen=True, slots=True)
class LicenseEntitlement:
    """What a verified token grants. Immutable; carries no key material."""

    customer_id: str
    tier: str
    modules: frozenset[str]
    max_annual_mgt: int
    expires_at: int

    def is_valid(self, now: int | None = None) -> bool:
        """Whether the entitlement is within its term at ``now``.

        ``now`` is epoch seconds; ``None`` reads the host clock. See the module
        docstring on why a rolled-back clock cannot be detected offline.
        """

        return self._resolve_now(now) < self.expires_at

    def has_module(self, module_name: str, now: int | None = None) -> bool:
        """Whether ``module_name`` is granted **and** the term has not lapsed.

        Expiry is folded in deliberately. A caller asking "may I use this?"
        wants one answer, and splitting the question invites a call site that
        checks membership and forgets the term.
        """

        return self.is_valid(now) and (
            module_name in self.modules or WILDCARD_MODULE in self.modules
        )

    @property
    def seconds_remaining(self) -> int:
        """Seconds until expiry against the host clock; ``0`` once lapsed."""

        return self.seconds_remaining_at(None)

    def seconds_remaining_at(self, now: int | None = None) -> int:
        """Seconds until expiry at ``now``; ``0`` once lapsed, never negative.

        The parameterised form is separate from the :attr:`seconds_remaining`
        property rather than replacing it: the property is public API that
        existing callers read as an attribute, and turning it into a method
        would break them for no gain.
        """

        return max(0, self.expires_at - int(self._resolve_now(now)))

    @staticmethod
    def _resolve_now(now: int | None) -> float:
        return time.time() if now is None else now


__all__ = [
    "KNOWN_MODULES",
    "WILDCARD_MODULE",
    "LicenseEntitlement",
]

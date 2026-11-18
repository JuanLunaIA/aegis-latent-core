# Copyright (c) 2026 Juan Luna. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
# Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.

"""Gateway start-up licence check.

Runs once before the gateway binds, after the runtime invariants:

- A configured ``AEGIS_LICENSE_TOKEN`` must verify under
  ``AEGIS_LICENSE_ROOT_PUBKEY`` (offline Ed25519, see
  :mod:`aegis.licensing.validator`). A bad, expired or unverifiable token
  refuses start in every mode: a deployment that meant to be licensed must find
  out.
- With no token, ``development`` mode starts with a warning.
- With no token in ``strict`` mode, ``AEGIS_LICENSE_MODE=evaluation`` (the
  default) allows a 30-day evaluation counted from the first strict start, with
  a warning on every start, and refuses afterwards. ``AEGIS_LICENSE_MODE=required``
  refuses at once.

The evaluation start is a small file next to the WAL. Deleting it restarts the
window: offline licensing cannot prevent that, the same way it cannot detect a
rolled-back clock. The window is a courtesy for honest evaluators, not a
technical control; the licence terms are what bind.
"""

from __future__ import annotations

import json
import logging
import os
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from aegis.licensing.model import LicenseEntitlement
from aegis.licensing.validator import LicenseError, load_entitlement_from_env

logger = logging.getLogger(__name__)

EVALUATION_SECONDS: Final[int] = 30 * 86_400
RENEWAL_WARNING_SECONDS: Final[int] = 30 * 86_400


class StartupLicenseError(LicenseError):
    """The gateway must not start under the configured licence posture."""


@dataclass(frozen=True, slots=True)
class StartupLicense:
    """What the start-up check concluded; safe to expose (no key material)."""

    status: str  # "licensed", "evaluation" or "development"
    entitlement: LicenseEntitlement | None = None
    evaluation_ends_at: int | None = None


def _evaluation_started(marker: Path, now: int) -> int:
    try:
        started = json.loads(marker.read_text(encoding="utf-8"))["started_at"]
        if isinstance(started, int) and not isinstance(started, bool) and 0 < started <= now:
            return started
        raise ValueError("bad started_at")
    except FileNotFoundError:
        pass
    except (OSError, ValueError, KeyError, TypeError) as exc:
        # A marker that exists but cannot be read is not a fresh start.
        raise StartupLicenseError(
            f"evaluation marker {marker} is unreadable; set AEGIS_LICENSE_TOKEN or restore the file"
        ) from exc
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(json.dumps({"started_at": now}), encoding="utf-8")
    return now


def check_startup_license(
    *,
    enforcement_mode: str,
    license_mode: str,
    marker: Path,
    env: Mapping[str, str] | None = None,
    now: int | None = None,
) -> StartupLicense:
    """Decide whether the gateway may start; raises :class:`StartupLicenseError`."""
    clock = int(time.time()) if now is None else now
    source = os.environ if env is None else env
    try:
        entitlement = load_entitlement_from_env(source)
    except LicenseError as exc:
        raise StartupLicenseError(f"AEGIS_LICENSE_TOKEN does not verify: {exc}") from exc

    if entitlement is not None:
        if not entitlement.is_valid(clock):
            raise StartupLicenseError("AEGIS_LICENSE_TOKEN has expired")
        remaining = entitlement.seconds_remaining_at(clock)
        if remaining < RENEWAL_WARNING_SECONDS:
            logger.warning(
                "Aegis licence for %s expires in %d days; renew it before it lapses",
                entitlement.customer_id,
                remaining // 86_400,
            )
        else:
            logger.info(
                "Aegis licence verified: tier=%s, %d days remaining",
                entitlement.tier,
                remaining // 86_400,
            )
        return StartupLicense("licensed", entitlement=entitlement)

    if enforcement_mode != "strict":
        logger.warning(
            "Aegis is running unlicensed in development mode; production use requires "
            "AEGIS_LICENSE_TOKEN"
        )
        return StartupLicense("development")

    if license_mode == "required":
        raise StartupLicenseError("AEGIS_LICENSE_MODE=required and AEGIS_LICENSE_TOKEN is not set")

    ends = _evaluation_started(marker, clock) + EVALUATION_SECONDS
    if clock >= ends:
        raise StartupLicenseError(
            "the 30-day evaluation has ended; set AEGIS_LICENSE_TOKEN to keep running"
        )
    logger.warning(
        "Aegis is running an unlicensed evaluation: %d days left. Production use "
        "requires AEGIS_LICENSE_TOKEN",
        max(1, (ends - clock) // 86_400),
    )
    return StartupLicense("evaluation", evaluation_ends_at=ends)


__all__ = [
    "EVALUATION_SECONDS",
    "StartupLicense",
    "StartupLicenseError",
    "check_startup_license",
]

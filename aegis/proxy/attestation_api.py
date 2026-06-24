"""
aegis.proxy.attestation_api — honest per-control capability reporting.

Mounted at /v1/attestation/* and protected by AuditKeyAuth. Lets an auditor see,
per security control, whether it is REAL, UNAVAILABLE, or SIMULATED in this exact
deployment — so a hardware-absent control can never be mistaken for a real one,
and a regression that reintroduces a simulation is immediately visible.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends

from aegis.core.attestation_capabilities import collect_capabilities
from aegis.proxy.dependencies import validate_audit_auth
from aegis.proxy.schemas import CapabilitiesReport, ControlCapabilityOut

logger = logging.getLogger(__name__)


def build_attestation_router() -> APIRouter:
    router = APIRouter(tags=["attestation"])

    @router.get("/capabilities", response_model=CapabilitiesReport)
    async def get_capabilities(
        _key: Annotated[str, Depends(validate_audit_auth)],
    ) -> CapabilitiesReport:
        """Report each security control's honest status in this environment.

        Cheap and side-effect-free — the probes only check for tools/devices
        (``shutil.which`` / ``os.path.exists``), never executing them.
        """
        caps = collect_capabilities()
        summary = {"REAL": 0, "UNAVAILABLE": 0, "SIMULATED": 0}
        for cap in caps:
            summary[cap.status] = summary.get(cap.status, 0) + 1
        return CapabilitiesReport(
            controls=[
                ControlCapabilityOut(
                    name=cap.name,
                    category=cap.category,
                    status=cap.status,
                    module=cap.module,
                    detail=cap.detail,
                )
                for cap in caps
            ],
            summary=summary,
            simulation_debt=summary["SIMULATED"],
        )

    return router

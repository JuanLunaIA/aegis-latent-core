"""aegis.core — Mathematical and cryptographic telemetry primitives."""

from aegis.core.crypto_audit import CryptographicAuditLedger, PQCSignatureAnchor
from aegis.core.math_utils import KahanSummation
from aegis.core.moe_monitor import EntanglementResult, MoERoutingMonitor
from aegis.core.session_manager import SessionLifecycleManager
from aegis.core.telemetry import KLResult, LogitEntropyMonitor

__all__ = [
    "LogitEntropyMonitor",
    "KLResult",
    "MoERoutingMonitor",
    "EntanglementResult",
    "CryptographicAuditLedger",
    "PQCSignatureAnchor",
    "SessionLifecycleManager",
    "KahanSummation",
]

# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

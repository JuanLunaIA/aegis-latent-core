"""aegis.core — Mathematical and cryptographic telemetry primitives."""
from aegis.core.telemetry import LogitEntropyMonitor, KLResult
from aegis.core.moe_monitor import MoERoutingMonitor, EntanglementResult
from aegis.core.crypto_audit import CryptographicAuditLedger, PQCSignatureAnchor
from aegis.core.session_manager import SessionLifecycleManager
from aegis.core.math_utils import KahanSummation

__all__ = [
    "LogitEntropyMonitor", "KLResult",
    "MoERoutingMonitor", "EntanglementResult",
    "CryptographicAuditLedger", "PQCSignatureAnchor",
    "SessionLifecycleManager", "KahanSummation",
]

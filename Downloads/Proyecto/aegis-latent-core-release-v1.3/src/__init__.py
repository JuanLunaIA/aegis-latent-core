"""
Aegis-Latent-Core — Immutable Forensic Telemetry Engine
Public API surface.
"""

from .math_utils import KahanSummation, normalize_logits, verify_distribution
from .telemetry import LogitEntropyMonitor, KLResult
from .crypto_audit import (
    MerkleAuditNode,
    CryptographicAuditLedger,
    PQCSignatureAnchor,
)
from .moe_monitor import MoERoutingMonitor, EntanglementResult

__all__ = [
    # math_utils
    "KahanSummation",
    "normalize_logits",
    "verify_distribution",
    # telemetry
    "LogitEntropyMonitor",
    "KLResult",
    # crypto_audit
    "MerkleAuditNode",
    "CryptographicAuditLedger",
    "PQCSignatureAnchor",
    # moe_monitor
    "MoERoutingMonitor",
    "EntanglementResult",
]

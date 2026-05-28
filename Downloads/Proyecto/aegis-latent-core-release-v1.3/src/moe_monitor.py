"""
moe_monitor.py - MoE Routing & Orthogonal Polysemantic Circuit Entanglement Monitor
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, List
import math
import numpy as np
from .math_utils import normalize_logits

@dataclass(frozen=True)
class EntanglementResult:
    detected: bool
    routing_entropy: float
    aggregate_activation: float
    max_gate: float
    flag: str
    note: str

class MoERoutingMonitor:
    def __init__(
        self,
        gate_threshold: float = 0.5,
        activation_bound: Optional[float] = None,
        min_experts: int = 2,
    ) -> None:
        if not (0.0 < gate_threshold < 1.0):
            raise ValueError("gate_threshold must be in (0, 1)")
        if activation_bound is not None and activation_bound <= 0.0:
            raise ValueError("activation_bound must be > 0")
        self.gate_threshold = gate_threshold
        self.activation_bound = activation_bound
        self.min_experts = min_experts

    def calibrate_from_samples(self, samples: List[np.ndarray], expert_norms: np.ndarray):
        """
        Calibrates activation_bound to the 99th percentile of normal operation.
        samples: List of gate_weights arrays
        """
        aggregates = []
        for g in samples:
            aggregates.append(np.dot(g, expert_norms))
        self.activation_bound = float(np.percentile(aggregates, 99))

    def compute_routing_entropy(self, gate_weights: np.ndarray) -> float:
        if gate_weights.ndim != 1 or gate_weights.size < self.min_experts:
            raise ValueError("Invalid gate_weights shape")
        epsilon = 1e-15
        g_c = np.maximum(gate_weights, epsilon)
        g_norm = g_c / g_c.sum()
        return float(-np.sum(g_norm * np.log(g_norm)))

    def detect_entanglement(
        self,
        gate_weights: np.ndarray,
        expert_norms: Optional[np.ndarray] = None,
    ) -> EntanglementResult:
        if gate_weights.ndim != 1 or gate_weights.size < self.min_experts:
            return EntanglementResult(False, 0.0, 0.0, 0.0, "INSUFFICIENT_DATA", "Too few experts")

        g = gate_weights / gate_weights.sum()
        w_norms = expert_norms if expert_norms is not None else np.ones_like(g)
        
        routing_entropy = self.compute_routing_entropy(g)
        aggregate_activation = float(np.dot(g, w_norms))
        max_gate = float(np.max(g))

        if self.activation_bound is None:
            return EntanglementResult(False, routing_entropy, aggregate_activation, max_gate, "NOT_CALIBRATED", "Monitor not calibrated")

        detected = (aggregate_activation > self.activation_bound) and (max_gate < self.gate_threshold)

        if detected:
            return EntanglementResult(True, routing_entropy, aggregate_activation, max_gate, "ENTANGLEMENT_DETECTED", "Entanglement detected")
        
        return EntanglementResult(False, routing_entropy, aggregate_activation, max_gate, "NOMINAL", "Within parameters")

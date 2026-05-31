from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np


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
        activation_bound: float | None = None,
        min_experts: int = 2,
    ) -> None:
        if not (0.0 < gate_threshold < 1.0):
            raise ValueError("gate_threshold must be in (0, 1)")
        if activation_bound is not None and activation_bound <= 0.0:
            raise ValueError("activation_bound must be > 0")
        self.gate_threshold = gate_threshold
        self.activation_bound = activation_bound
        self.min_experts = min_experts

    def calibrate_from_samples(
        self, samples: list[np.ndarray], expert_norms: np.ndarray
    ) -> None:
        aggregates = [np.dot(g, expert_norms) for g in samples]
        self.activation_bound = float(np.percentile(aggregates, 99))

    def compute_routing_entropy(self, gate_weights: np.ndarray) -> float:
        if gate_weights.ndim != 1 or gate_weights.size < self.min_experts:
            raise ValueError("Invalid gate_weights shape")

        sum_gates = np.sum(gate_weights)
        if sum_gates == 0:
            return float("nan")

        epsilon = 1e-15
        g_norm = np.maximum(gate_weights, epsilon) / sum_gates
        return float(-np.sum(g_norm * np.log(g_norm)))

    def detect_entanglement(
        self,
        gate_weights: np.ndarray,
        expert_norms: np.ndarray | None = None,
    ) -> EntanglementResult:
        if gate_weights.ndim != 1 or gate_weights.size < self.min_experts:
            return EntanglementResult(
                False, 0.0, 0.0, 0.0, "INSUFFICIENT_DATA", "Too few experts"
            )

        # CORRECCIÓN ATÓMICA (VULN-04): Validación de rango estricta.
        # Evita ataques de cancelación aritmética mediante pesos negativos.
        if np.any(gate_weights < 0.0) or np.any(gate_weights > 1.0):
            return EntanglementResult(
                True, 0.0, 0.0, 0.0, "INVALID_INPUT",
                "Gate weights must be in [0, 1]"
            )

        sum_gates = np.sum(gate_weights)
        if sum_gates == 0:
            return EntanglementResult(
                True, float("nan"), float("nan"), float("nan"),
                "CATASTROPHIC_ROUTING", "All gates are zero"
            )

        g = gate_weights / sum_gates
        w_norms = expert_norms if expert_norms is not None else np.ones_like(g)

        if expert_norms is not None and expert_norms.shape != gate_weights.shape:
            raise ValueError(
                "gate_weights and expert_norms must have the same shape"
            )

        routing_entropy = self.compute_routing_entropy(g)
        aggregate_activation = float(np.dot(g, w_norms))
        max_gate = float(np.max(g))

        if self.activation_bound is None:
            return EntanglementResult(
                False, routing_entropy, aggregate_activation, max_gate,
                "NOT_CALIBRATED", "Monitor not calibrated"
            )

        # FIX BUG-02: removed `classic_entanglement` — it was a verbatim copy of
        # `absolute_activation_violated` (same boolean predicate, same operands).
        # The OR with the duplicate produced no new detection surface; it only
        # obscured the note messages by emitting "Sub-gate activation limit
        # violation" for cases already captured by the first branch.
        # Two distinct detection paths remain:
        #   1. absolute_activation_violated — hard bound exceeded, no single gate
        #      dominates (classic distributed entanglement).
        #   2. distributed_entanglement — soft bound + high routing entropy
        #      (stealth/distributed attack where aggregate stays below hard bound
        #      but dispersion + soft activation together flag the pattern).
        absolute_activation_violated = (
            aggregate_activation > self.activation_bound
            and max_gate < self.gate_threshold
        )

        max_theoretical_entropy = math.log(g.size)
        high_routing_dispersion = routing_entropy > (max_theoretical_entropy * 0.5)
        soft_activation_violated = aggregate_activation > (self.activation_bound * 0.75)
        distributed_entanglement = high_routing_dispersion and soft_activation_violated

        detected = absolute_activation_violated or distributed_entanglement

        if detected:
            note_msgs = []
            if absolute_activation_violated:
                note_msgs.append("Absolute activation bound exceeded")
            if distributed_entanglement:
                note_msgs.append("High entropy distributed activation detected")
            return EntanglementResult(
                True, routing_entropy, aggregate_activation, max_gate,
                "ENTANGLEMENT_DETECTED", "; ".join(note_msgs)
            )

        return EntanglementResult(
            False, routing_entropy, aggregate_activation, max_gate,
            "NOMINAL", "Within parameters"
        )

"""
aegis.core.semantic_defense — Semantic Drift and Adversarial AI Detection.
Monitors LLM output distributions to detect prompt injection and model hijacking.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import logging
from dataclasses import dataclass

import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class DriftResult:
    is_anomaly: bool
    divergence_score: float
    entropy_delta: float
    action_taken: str  # 'NONE', 'ALERT', 'KILL_SWITCH'


class SemanticDriftMonitor:
    """
    Detects adversarial manipulation of LLM outputs by analyzing
    logit distributions and KL Divergence.
    """

    def __init__(self, kl_threshold: float = 2.5, entropy_floor: float = 0.1):
        self.kl_threshold = kl_threshold
        self.entropy_floor = entropy_floor
        self.baseline_distribution: np.ndarray | None = None
        self._is_killswitch_active = False

    def set_baseline(self, distribution: np.ndarray):
        """Sets the 'safe' distribution for the current context."""
        self.baseline_distribution = distribution / np.sum(distribution)
        logger.info("Semantic baseline established.")

    def compute_kl_divergence(self, p: np.ndarray, q: np.ndarray) -> float:
        """
        Computes Kullback-Leibler Divergence D_KL(P || Q).
        Measures how much the current output (P) diverges from the baseline (Q).
        """
        # Avoid log(0) by adding a small epsilon
        epsilon = 1e-10
        p = np.clip(p, epsilon, 1.0)
        q = np.clip(q, epsilon, 1.0)

        return np.sum(p * np.log(p / q))

    def analyze_logits(self, current_logits: np.ndarray) -> DriftResult:
        """
        Analyzes the logit distribution for anomalies.
        """
        if self.baseline_distribution is None:
            # If no baseline, we use a uniform distribution as a fallback
            self.baseline_distribution = np.ones_like(current_logits) / len(current_logits)

        # 1. Convert logits to probabilities (Softmax)
        exp_logits = np.exp(current_logits - np.max(current_logits))
        p = exp_logits / np.sum(exp_logits)

        # 2. Compute Shannon Entropy (Certainty)
        entropy = -np.sum(p * np.log(p + 1e-10))

        # 3. Compute KL Divergence against baseline
        divergence = self.compute_kl_divergence(p, self.baseline_distribution)

        # 4. Decision Logic
        action = "NONE"
        is_anomaly = False

        # Case A: Entropy Collapse (Model becomes suddenly too certain -> Injection)
        if entropy < self.entropy_floor:
            is_anomaly = True
            action = "KILL_SWITCH"
            logger.critical(
                "SEMANTIC COLLAPSE: Entropy dropped below floor (%f). Potential Hijack!", entropy
            )

        # Case B: High Divergence (Model output shifts drastically from baseline)
        elif divergence > self.kl_threshold:
            is_anomaly = True
            action = "ALERT"
            logger.warning(
                "SEMANTIC DRIFT: High KL Divergence (%f). Unusual output pattern.", divergence
            )

        if action == "KILL_SWITCH":
            self._is_killswitch_active = True

        return DriftResult(
            is_anomaly=is_anomaly,
            divergence_score=divergence,
            entropy_delta=entropy,
            action_taken=action,
        )

    def reset_killswitch(self):
        self._is_killswitch_active = False

    @property
    def killswitch_active(self) -> bool:
        return self._is_killswitch_active


# Singleton instance
semantic_monitor = SemanticDriftMonitor()

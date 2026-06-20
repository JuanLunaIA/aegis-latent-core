# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
import unittest

import numpy as np

from aegis.core.moe_monitor import MoERoutingMonitor
from aegis.core.telemetry import LogitEntropyMonitor


class TestZeroDayDefense(unittest.TestCase):
    def setUp(self) -> None:
        # Monitor with strict production limits
        self.entropy_monitor = LogitEntropyMonitor(ema_alpha=0.1)
        self.moe_monitor = MoERoutingMonitor(
            gate_threshold=0.5, activation_bound=1.5, min_experts=4
        )

    def test_zero_day_latent_footprint_detection(self) -> None:
        """
        Simulates a Zero-Day attack that evades text filters but
        leaves an anomaly in the latent space.
        """
        # 1. ESTADO NOMINAL
        normal_logits = np.random.randn(1000)
        normal_gates = np.array([0.4, 0.3, 0.2, 0.1])
        normal_norms = np.array([1.0, 1.0, 1.0, 1.0])

        h_normal = self.entropy_monitor.compute_shannon_entropy(normal_logits)
        moe_normal = self.moe_monitor.detect_entanglement(normal_gates, normal_norms)

        self.assertFalse(moe_normal.detected, f"False positive in nominal state: {moe_normal.note}")
        print(f"\n[NOMINAL] Entropy: {h_normal:.4f}, MoE Status: {moe_normal.flag}")

        # 2. ZERO-DAY STATE (simulated successful injection)
        # Collapsed logits: minimum entropy (clearest signal of forced injection)
        zero_day_logits = np.random.randn(1000)
        zero_day_logits[42] = 100.0

        # Anomalous routing: massive aggregate activation.
        # High norms simulate the "energy" of an injection attack that
        # activates multiple expert paths simultaneously.
        zero_day_gates = np.array([0.26, 0.24, 0.25, 0.25])
        zero_day_norms = np.array([5.0, 5.0, 5.0, 5.0])  # simulated high activation

        h_attack = self.entropy_monitor.compute_shannon_entropy(zero_day_logits)
        moe_attack = self.moe_monitor.detect_entanglement(zero_day_gates, zero_day_norms)

        print(f"[ATTACK] Entropy: {h_attack:.4f}, MoE Status: {moe_attack.flag}")
        print(f"[ATTACK] Note: {moe_attack.note}")

        # Defense assertions
        # A. Entropy collapse is a primary indicator
        self.assertLess(h_attack, h_normal * 0.1)

        # B. The MoE monitor must detect entanglement
        self.assertTrue(moe_attack.detected, "Zero-Day evaded MoE Entanglement detection")
        self.assertEqual(moe_attack.flag, "ENTANGLEMENT_DETECTED")


if __name__ == "__main__":
    unittest.main(verbosity=2)

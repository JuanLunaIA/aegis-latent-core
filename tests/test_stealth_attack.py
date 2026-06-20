# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
import unittest

import numpy as np

from aegis.core.moe_monitor import MoERoutingMonitor
from aegis.core.telemetry import LogitEntropyMonitor


class TestStealthAttack(unittest.TestCase):
    def setUp(self) -> None:
        self.entropy_monitor = LogitEntropyMonitor(ema_alpha=0.1)
        self.moe_monitor = MoERoutingMonitor(
            gate_threshold=0.5,
            activation_bound=1.5,
            min_experts=4,
        )

    def test_ema_poisoning_and_stealth_moe(self) -> None:
        """
        Simulates a stealth attack:
          1. Slowly poisons the EMA.
          2. Keeps MoE activation just below the absolute bound.
          3. Keeps entropy at 'natural' levels.

        FIX BUG-03: The original test asserted assertFalse(detected) to document
        a known evasion gap.  After introducing the distributed_entanglement path
        in detect_entanglement(), the monitor now correctly catches this pattern:

          stealth_gates = [0.3, 0.3, 0.2, 0.2]  (all < gate_threshold=0.5)
          stealth_norms = [1.23]*4
          aggregate_activation = dot(g_norm, norms) = 1.23 > 1.5*0.75=1.125
              → soft_activation_violated = True
          routing_entropy ≈ 1.366 nats
          max_theoretical_entropy = ln(4) ≈ 1.386 nats
          high_routing_dispersion = 1.366 > 0.5*1.386 = 0.693 → True
              → distributed_entanglement = True → detected = True

        The assertFalse was a regression anchor for the old (incomplete) code.
        The correct assertion is assertTrue: the stealth pattern IS now detected.
        """
        # --- STEP 1: EMA POISONING ---
        for _ in range(50):
            logits = np.random.randn(1000)
            logits[0] += 1.0
            h = self.entropy_monitor.compute_shannon_entropy(logits)
            self.entropy_monitor.update_ema(h)

        ema_poisoned = self.entropy_monitor.current_ema
        print(f"\n[EMA] Poisoned value: {ema_poisoned:.4f}")

        # --- STEP 2: STEALTH ATTACK ---
        stealth_logits = np.random.randn(1000)
        stealth_logits[0] += 2.0

        stealth_gates = np.array([0.3, 0.3, 0.2, 0.2])
        stealth_norms = np.array([1.23, 1.23, 1.23, 1.23])  # aggregate = 1.23

        h_attack = self.entropy_monitor.compute_shannon_entropy(stealth_logits)
        moe_attack = self.moe_monitor.detect_entanglement(stealth_gates, stealth_norms)

        print(f"[STEALTH] Entropy: {h_attack:.4f} (EMA: {ema_poisoned:.4f})")
        print(f"[STEALTH] MoE Activation: {np.dot(stealth_gates, stealth_norms):.4f} (Bound: 1.5)")
        print(f"[STEALTH] MoE Status: {moe_attack.flag}")

        # Stealth pattern is now correctly DETECTED by distributed_entanglement.
        # aggregate=1.23 > soft_bound=1.125 AND routing_entropy≈1.37 > 0.5*ln(4)≈0.693
        self.assertTrue(
            moe_attack.detected,
            "distributed_entanglement should catch the stealth pattern",
        )
        self.assertEqual(moe_attack.flag, "ENTANGLEMENT_DETECTED")


if __name__ == "__main__":
    unittest.main(verbosity=2)

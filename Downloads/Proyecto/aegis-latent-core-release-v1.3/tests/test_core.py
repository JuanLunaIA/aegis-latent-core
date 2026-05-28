"""
test_core.py — Full test suite for Aegis-Latent-Core

Coverage targets (post NEXUS audit 2026-05-27):
  math_utils:    KahanSummation precision, NaN rejection, empty/non-1D array guards,
                 verify_distribution with math.fsum
  telemetry:     Entropy boundaries, KLResult saturation detection, JS divergence
                 boundedness, ema_alpha validation
  crypto_audit:  Tamper detection, NULL-byte separator (F-01 fix verification),
                 WAL persistence round-trip, empty chain, thread safety
  moe_monitor:   Entanglement detection, routing entropy, unit norms baseline
"""

import math
import os
import tempfile
import threading
import unittest

import numpy as np

from src.math_utils import KahanSummation, normalize_logits, verify_distribution
from src.telemetry import LogitEntropyMonitor, KLResult
from src.crypto_audit import CryptographicAuditLedger, PQCSignatureAnchor
from src.moe_monitor import MoERoutingMonitor, EntanglementResult


# ---------------------------------------------------------------------------
# math_utils
# ---------------------------------------------------------------------------

class TestKahanSummation(unittest.TestCase):

    def test_precision_at_scale(self) -> None:
        """Kahan recovers 10.0 absorbed by 1e16 in naive float64 addition."""
        kahan = KahanSummation()
        large_val = 1e16
        kahan.add(large_val)
        for _ in range(10):
            kahan.add(1.0)
        self.assertEqual(kahan.sum, large_val + 10.0)

    def test_reset_clears_both_fields(self) -> None:
        kahan = KahanSummation()
        kahan.add(1e16)
        kahan.add(1.0)
        kahan.reset()
        self.assertEqual(kahan.sum, 0.0)
        self.assertEqual(kahan.compensation, 0.0)
        # After reset, re-accumulation should be fresh
        kahan.add(5.0)
        self.assertEqual(kahan.sum, 5.0)

    def test_nan_raises_value_error(self) -> None:
        """NaN must not propagate silently — must raise immediately (F-04)."""
        kahan = KahanSummation()
        kahan.add(1.0)
        with self.assertRaises(ValueError) as ctx:
            kahan.add(float('nan'))
        self.assertIn("non-finite", str(ctx.exception))

    def test_positive_inf_raises_value_error(self) -> None:
        kahan = KahanSummation()
        with self.assertRaises(ValueError):
            kahan.add(float('inf'))

    def test_negative_inf_raises_value_error(self) -> None:
        kahan = KahanSummation()
        with self.assertRaises(ValueError):
            kahan.add(float('-inf'))

    def test_empty_accumulation_returns_zero(self) -> None:
        kahan = KahanSummation()
        self.assertEqual(kahan.sum, 0.0)
        self.assertEqual(kahan.compensation, 0.0)


class TestNormalizeLogits(unittest.TestCase):

    def test_stable_softmax_uniform(self) -> None:
        probs = normalize_logits(np.array([1.0, 1.0, 1.0, 1.0]))
        np.testing.assert_allclose(probs, [0.25, 0.25, 0.25, 0.25], atol=1e-12)

    def test_stable_softmax_large_values(self) -> None:
        """Large logits must not overflow to inf."""
        probs = normalize_logits(np.array([1000.0, 999.0, 998.0]))
        self.assertTrue(np.all(np.isfinite(probs)))
        self.assertAlmostEqual(float(np.sum(probs)), 1.0, places=10)

    def test_empty_array_raises(self) -> None:
        with self.assertRaises(ValueError):
            normalize_logits(np.array([]))

    def test_2d_array_raises(self) -> None:
        with self.assertRaises(ValueError):
            normalize_logits(np.array([[1.0, 2.0], [3.0, 4.0]]))

    def test_nan_input_raises(self) -> None:
        with self.assertRaises(ValueError):
            normalize_logits(np.array([1.0, float('nan'), 2.0]))


class TestVerifyDistribution(unittest.TestCase):

    def test_valid_distribution(self) -> None:
        probs = normalize_logits(np.array([1.0, 2.0, 3.0]))
        self.assertTrue(verify_distribution(probs))

    def test_invalid_distribution(self) -> None:
        self.assertFalse(verify_distribution(np.array([0.5, 0.5, 0.1])))


# ---------------------------------------------------------------------------
# telemetry
# ---------------------------------------------------------------------------

class TestLogitEntropyMonitor(unittest.TestCase):

    def setUp(self) -> None:
        self.monitor = LogitEntropyMonitor(ema_alpha=0.2)

    def test_entropy_one_hot(self) -> None:
        """Near-certain distribution → H ≈ 0.0 bits."""
        H = self.monitor.compute_shannon_entropy(np.array([100.0, -100.0, -100.0]))
        self.assertAlmostEqual(H, 0.0, places=5)

    def test_entropy_uniform(self) -> None:
        """Uniform over 4 tokens → H = log2(4) = 2.0 bits."""
        H = self.monitor.compute_shannon_entropy(np.array([1.0, 1.0, 1.0, 1.0]))
        self.assertAlmostEqual(H, 2.0, places=5)

    def test_entropy_single_token(self) -> None:
        """Single-element distribution → H = 0.0 bits."""
        H = self.monitor.compute_shannon_entropy(np.array([5.0]))
        self.assertAlmostEqual(H, 0.0, places=10)

    def test_entropy_two_balanced(self) -> None:
        """Balanced binary → H = 1.0 bit."""
        H = self.monitor.compute_shannon_entropy(np.array([0.0, 0.0]))
        self.assertAlmostEqual(H, 1.0, places=5)

    def test_entropy_always_nonnegative(self) -> None:
        for _ in range(20):
            logits = np.random.randn(50)
            self.assertGreaterEqual(self.monitor.compute_shannon_entropy(logits), 0.0)

    def test_ema_initializes_to_first_value(self) -> None:
        ema = self.monitor.update_ema(3.14)
        self.assertAlmostEqual(ema, 3.14)

    def test_ema_convergence(self) -> None:
        """EMA converges toward the repeated input."""
        monitor = LogitEntropyMonitor(ema_alpha=0.5)
        for _ in range(100):
            monitor.update_ema(2.0)
        self.assertAlmostEqual(monitor.current_ema, 2.0, places=4)

    def test_ema_alpha_validation(self) -> None:
        with self.assertRaises(ValueError):
            LogitEntropyMonitor(ema_alpha=0.0)
        with self.assertRaises(ValueError):
            LogitEntropyMonitor(ema_alpha=1.0)
        with self.assertRaises(ValueError):
            LogitEntropyMonitor(ema_alpha=1.5)

    def test_kl_identical_distributions(self) -> None:
        """D_KL(P ∥ P) = 0."""
        result = self.monitor.compute_kl_divergence(
            np.array([1.0, 0.0, 0.0]),
            np.array([1.0, 0.0, 0.0]),
        )
        self.assertIsInstance(result, KLResult)
        self.assertAlmostEqual(result.value, 0.0, places=5)

    def test_kl_orthogonal_returns_kl_result(self) -> None:
        """KLResult is returned; divergent distributions produce KL > 1."""
        result = self.monitor.compute_kl_divergence(
            np.array([10.0, 0.0, 0.0]),
            np.array([0.0, 10.0, 0.0]),
        )
        self.assertIsInstance(result, KLResult)
        self.assertGreater(result.value, 1.0)

    def test_kl_saturation_detected(self) -> None:
        """
        KLResult.saturated=True when logit gap causes float64 underflow (F-03).
        Gap > 710 forces Q(i) = 0.0 exactly; epsilon floor activates.
        """
        result = self.monitor.compute_kl_divergence(
            np.array([1000.0, 0.0]),
            np.array([0.0, 1000.0]),
        )
        self.assertTrue(result.saturated)
        self.assertGreater(result.saturated_token_count, 0)
        # Value saturates near log2(1/1e-15) ≈ 49.83 bits
        self.assertAlmostEqual(result.value, math.log2(1.0 / 1e-15), delta=1.0)

    def test_kl_not_saturated_for_moderate_gap(self) -> None:
        """No underflow for small logit gaps."""
        result = self.monitor.compute_kl_divergence(
            np.array([2.0, 0.5]),
            np.array([0.5, 2.0]),
        )
        self.assertFalse(result.saturated)
        self.assertEqual(result.saturated_token_count, 0)

    def test_kl_shape_mismatch_raises(self) -> None:
        with self.assertRaises(ValueError):
            self.monitor.compute_kl_divergence(
                np.array([1.0, 2.0]),
                np.array([1.0, 2.0, 3.0]),
            )

    def test_js_divergence_bounded(self) -> None:
        """D_JS ∈ [0, 1] for any inputs."""
        for _ in range(50):
            p = np.random.randn(10)
            q = np.random.randn(10)
            js = self.monitor.compute_js_divergence(p, q)
            self.assertGreaterEqual(js, 0.0)
            self.assertLessEqual(js, 1.0)

    def test_js_divergence_identical_is_zero(self) -> None:
        js = self.monitor.compute_js_divergence(
            np.array([1.0, 2.0, 3.0]),
            np.array([1.0, 2.0, 3.0]),
        )
        self.assertAlmostEqual(js, 0.0, places=5)

    def test_js_divergence_symmetric(self) -> None:
        p = np.array([3.0, 1.0, 0.5])
        q = np.array([0.5, 2.0, 1.0])
        js_pq = self.monitor.compute_js_divergence(p, q)
        js_qp = self.monitor.compute_js_divergence(q, p)
        self.assertAlmostEqual(js_pq, js_qp, places=10)

    def test_js_not_saturated_at_extreme_gap(self) -> None:
        """JS divergence must not saturate at extreme logit gaps (unlike KL)."""
        js_moderate = self.monitor.compute_js_divergence(
            np.array([10.0, 0.0]), np.array([0.0, 10.0])
        )
        js_extreme = self.monitor.compute_js_divergence(
            np.array([1000.0, 0.0]), np.array([0.0, 1000.0])
        )
        # Both should be ≈ 1.0 (maximally divergent), NOT equal due to saturation
        self.assertAlmostEqual(js_moderate, 1.0, delta=0.01)
        self.assertAlmostEqual(js_extreme, 1.0, delta=0.01)


# ---------------------------------------------------------------------------
# crypto_audit
# ---------------------------------------------------------------------------

class TestCryptographicAuditLedger(unittest.TestCase):

    def test_empty_chain_integrity(self) -> None:
        """verify_integrity() on empty chain must return (True, None)."""
        ledger = CryptographicAuditLedger()
        is_valid, err = ledger.verify_integrity()
        self.assertTrue(is_valid)
        self.assertIsNone(err)

    def test_single_node_integrity(self) -> None:
        ledger = CryptographicAuditLedger()
        ledger.commit_state("s0", 1.0, b"payload")
        is_valid, err = ledger.verify_integrity()
        self.assertTrue(is_valid)
        self.assertIsNone(err)

    def test_tamper_detection(self) -> None:
        """Modifying entropy on a committed node must be detected (F-01 area)."""
        ledger = CryptographicAuditLedger()
        ledger.commit_state("state_0", 1.2, b"payload_0")
        ledger.commit_state("state_1", 1.5, b"payload_1")
        ledger.commit_state("state_2", 1.1, b"payload_2")

        is_valid, _ = ledger.verify_integrity()
        self.assertTrue(is_valid)

        # Tamper: replace entropy on node 1 without recomputing node_hash
        tampered = ledger.chain[1].__class__(
            timestamp=ledger.chain[1].timestamp,
            state_id=ledger.chain[1].state_id,
            entropy=999.9,
            payload_hash=ledger.chain[1].payload_hash,
            previous_hash=ledger.chain[1].previous_hash,
            node_hash=ledger.chain[1].node_hash,
        )
        ledger.chain[1] = tampered

        is_valid, index = ledger.verify_integrity()
        self.assertFalse(is_valid)
        self.assertEqual(index, 1)

    def test_null_byte_separator_prevents_injection(self) -> None:
        """
        F-01 fix verification: state_id containing '|' must NOT produce the
        same hash as a redistributed (timestamp, state_id) pair.

        Pre-fix: f"{ts}|{sid}|{ent}|{ph}|{ph2}" allowed
                 sid='A|B' to collide with sid='A', entropy starting with '|B|...'.
        Post-fix: \\x00 separator makes this structurally impossible.
        """
        ledger = CryptographicAuditLedger()

        # Hash for legitimate node
        h_legit = ledger._calculate_hash(
            timestamp=1.0,
            state_id="S",
            entropy=2.0,
            payload_hash="X",
            prev_hash="Z",
        )

        # Attempt injection: embed separator in state_id to try to shift fields
        # With '|' separator (old): "1.0|S|2.0|X|Z" == "1.0|S|2.0|X|Z" trivially
        # With \x00 separator (new): b"1.0\x00S\x00..." cannot be matched by
        # b"1.0\x00S|2.0|X\x00..." because \x00 vs | differ
        h_injected = ledger._calculate_hash(
            timestamp=1.0,
            state_id="S|2.0|X",     # adversarial state_id containing old separator
            entropy=0.0,
            payload_hash="Z",
            prev_hash="",
        )

        self.assertNotEqual(h_legit, h_injected)

    def test_state_id_with_null_byte_raises(self) -> None:
        """state_id containing \\x00 is explicitly rejected."""
        ledger = CryptographicAuditLedger()
        with self.assertRaises(ValueError) as ctx:
            ledger.commit_state("bad\x00id", 1.0, b"payload")
        self.assertIn("NULL", str(ctx.exception))

    def test_non_finite_entropy_raises(self) -> None:
        ledger = CryptographicAuditLedger()
        with self.assertRaises(ValueError):
            ledger.commit_state("s0", float('nan'), b"payload")

    def test_pqc_anchor_attached(self) -> None:
        """Every committed node must carry a PQCSignatureAnchor."""
        ledger = CryptographicAuditLedger()
        node = ledger.commit_state("s0", 1.5, b"data")
        self.assertIsInstance(node.pqc_anchor, PQCSignatureAnchor)
        self.assertIn("Dilithium", node.pqc_anchor.algorithm)
        self.assertIn("SIMULATED", node.pqc_anchor.signature_placeholder)

    def test_legal_admissibility_without_persistence(self) -> None:
        ledger = CryptographicAuditLedger()
        self.assertEqual(ledger.legal_admissibility, "Hypothetical")

    def test_legal_admissibility_with_persistence(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            path = f.name
        try:
            with CryptographicAuditLedger(persistence_path=path) as ledger:
                self.assertEqual(ledger.legal_admissibility, "High")
        finally:
            os.unlink(path)

    def test_wal_persistence_roundtrip(self) -> None:
        """WAL must survive process restart: load_from_wal() reconstructs chain."""
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            path = f.name
        try:
            # Write
            with CryptographicAuditLedger(persistence_path=path) as ledger:
                ledger.commit_state("s0", 1.2, b"p0")
                ledger.commit_state("s1", 1.5, b"p1")
                ledger.commit_state("s2", 1.1, b"p2")
                original_root = ledger.chain[-1].node_hash

            # Load fresh
            loaded = CryptographicAuditLedger.load_from_wal(path)
            self.assertEqual(len(loaded.chain), 3)
            self.assertEqual(loaded.chain[-1].node_hash, original_root)

            is_valid, err = loaded.verify_integrity()
            self.assertTrue(is_valid)
            self.assertIsNone(err)
            loaded.close()
        finally:
            os.unlink(path)

    def test_thread_safety_under_concurrent_writes(self) -> None:
        """
        F-06: commit_state() must be thread-safe under PEP 703 no-GIL scenario.
        Verified via threading.Barrier-synchronized burst writes.
        Chain must remain intact after all writes complete.
        """
        ledger = CryptographicAuditLedger()
        num_threads = 8
        commits_per_thread = 25
        barrier = threading.Barrier(num_threads)
        errors: list = []

        def writer(tid: int) -> None:
            try:
                barrier.wait()
                for i in range(commits_per_thread):
                    ledger.commit_state(f"t{tid}_{i}", float(i % 10), b"payload")
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Thread errors: {errors}")
        self.assertEqual(len(ledger.chain), num_threads * commits_per_thread)
        is_valid, err = ledger.verify_integrity()
        self.assertTrue(is_valid, f"Chain corrupted at node {err}")


# ---------------------------------------------------------------------------
# moe_monitor
# ---------------------------------------------------------------------------

class TestMoERoutingMonitor(unittest.TestCase):

    def setUp(self) -> None:
        self.monitor = MoERoutingMonitor(gate_threshold=0.5, activation_bound=1.0)

    def test_routing_entropy_uniform(self) -> None:
        """Uniform routing → maximum entropy = log(E) nats."""
        E = 8
        g = np.ones(E) / E
        H = self.monitor.compute_routing_entropy(g)
        self.assertAlmostEqual(H, math.log(E), places=5)

    def test_routing_entropy_concentrated(self) -> None:
        """One expert dominates → near-zero entropy."""
        g = np.array([0.99, 0.005, 0.005])
        H = self.monitor.compute_routing_entropy(g)
        self.assertLess(H, 0.1)

    def test_entanglement_detected(self) -> None:
        """
        Classic entanglement: no single gate > 0.5 but aggregate with
        large expert norms exceeds activation_bound.
        """
        # 4 experts, each gate = 0.25 (all below threshold=0.5)
        # expert norms = [2.0, 2.0, 2.0, 2.0]
        # aggregate = 0.25*2 + 0.25*2 + 0.25*2 + 0.25*2 = 2.0 > 1.0
        g = np.array([0.25, 0.25, 0.25, 0.25])
        norms = np.array([2.0, 2.0, 2.0, 2.0])
        result = self.monitor.detect_entanglement(g, norms)
        self.assertTrue(result.detected)
        self.assertEqual(result.flag, "ENTANGLEMENT_DETECTED")

    def test_no_entanglement_when_single_gate_dominates(self) -> None:
        """Single dominant expert = normal routing, NOT entanglement."""
        g = np.array([0.9, 0.05, 0.05])
        norms = np.array([2.0, 2.0, 2.0])
        result = self.monitor.detect_entanglement(g, norms)
        self.assertFalse(result.detected)
        self.assertEqual(result.flag, "NOMINAL")

    def test_insufficient_data_below_min_experts(self) -> None:
        g = np.array([1.0])
        result = self.monitor.detect_entanglement(g)
        self.assertFalse(result.detected)
        self.assertEqual(result.flag, "INSUFFICIENT_DATA")

    def test_gate_threshold_validation(self) -> None:
        with self.assertRaises(ValueError):
            MoERoutingMonitor(gate_threshold=0.0)
        with self.assertRaises(ValueError):
            MoERoutingMonitor(gate_threshold=1.0)

    def test_activation_bound_validation(self) -> None:
        with self.assertRaises(ValueError):
            MoERoutingMonitor(activation_bound=0.0)
        with self.assertRaises(ValueError):
            MoERoutingMonitor(activation_bound=-1.0)

    def test_shape_mismatch_raises(self) -> None:
        g = np.array([0.5, 0.5])
        norms = np.array([1.0, 1.0, 1.0])
        with self.assertRaises(ValueError):
            self.monitor.detect_entanglement(g, norms)


if __name__ == "__main__":
    unittest.main(verbosity=2)

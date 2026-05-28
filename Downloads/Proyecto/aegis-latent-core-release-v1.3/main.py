"""
main.py — Aegis-Latent-Core Reference Pipeline

Demonstrates the complete instrumentation workflow:
  1. LogitEntropyMonitor — per-token entropy, EMA, KL + JS divergence
  2. MoERoutingMonitor  — cross-expert entanglement detection
  3. CryptographicAuditLedger — WAL-persisted Merkle chain of custody

Exit codes:
  0 — all states processed, chain integrity verified
  1 — chain integrity failure (tamper detected)
  2 — runtime error
"""

from __future__ import annotations

import os
import sys
import tempfile

import numpy as np

from src.telemetry import LogitEntropyMonitor, KLResult
from src.crypto_audit import CryptographicAuditLedger
from src.moe_monitor import MoERoutingMonitor


# ---------------------------------------------------------------------------
# Thresholds (tune per architecture; see README.md §Configuration)
# ---------------------------------------------------------------------------
KL_ALERT_THRESHOLD: float = 1.0
JS_ALERT_THRESHOLD: float = 0.5   # JS is bounded [0,1]; 0.5 = midpoint
ENTANGLEMENT_GATE_THRESHOLD: float = 0.5
ENTANGLEMENT_ACTIVATION_BOUND: float = 1.5


def run_pipeline(wal_path: str | None = None) -> int:
    print("=" * 62)
    print("  Aegis-Latent-Core  v1.1 — Forensic Telemetry Engine")
    print("=" * 62)
    print()

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------
    monitor     = LogitEntropyMonitor(ema_alpha=0.2)
    moe_monitor = MoERoutingMonitor(
        gate_threshold=ENTANGLEMENT_GATE_THRESHOLD,
        activation_bound=ENTANGLEMENT_ACTIVATION_BOUND,
    )

    # Persistence: use provided path or temp file for demo
    cleanup_wal = False
    if wal_path is None:
        tmp = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False)
        wal_path = tmp.name
        tmp.close()
        cleanup_wal = True

    print(f"  WAL path          : {wal_path}")
    print(f"  Legal admissibility will be: High (fsync on each commit)")
    print()

    # Reference baseline — "healthy" token distribution
    reference_logits = np.array([2.0, 1.0, 0.5, 0.1])

    # Simulated inference stream — (state_id, logits, description)
    stream = [
        (
            "T_001",
            np.array([2.1, 0.9, 0.4, 0.2]),
            "Normal operation",
        ),
        (
            "T_002",
            np.array([2.0, 1.1, 0.6, 0.1]),
            "Normal operation",
        ),
        (
            "T_003",
            np.array([15.0, -10.0, -10.0, -10.0]),
            "Sudden confidence spike",
        ),
        (
            "T_004",
            np.array([0.1, 0.1, 0.1, 0.1]),
            "Uniform — high entropy",
        ),
        (
            "T_005",
            np.array([1000.0, 0.0, 0.0, 0.0]),
            "Extreme logit gap (KL saturation scenario)",
        ),
    ]

    # Simulated MoE routing states (gate_weights, expert_norms, description)
    moe_stream = [
        (
            np.array([0.8, 0.1, 0.1]),
            np.array([1.0, 1.0, 1.0]),
            "Normal: single expert dominates",
        ),
        (
            np.array([0.34, 0.33, 0.33]),
            np.array([2.5, 2.5, 2.5]),
            "Entanglement: uniform gates, high-norm experts",
        ),
    ]

    # ------------------------------------------------------------------
    # Logit telemetry
    # ------------------------------------------------------------------
    print("  LOGIT TELEMETRY")
    header = (
        f"  {'State':<8} {'H(bits)':>8} {'EMA':>8} "
        f"{'KL':>8} {'JS':>6} {'Sat':>4}  Status"
    )
    print(header)
    print("  " + "-" * 60)

    with CryptographicAuditLedger(persistence_path=wal_path) as ledger:

        for state_id, logits, desc in stream:
            entropy  = monitor.compute_shannon_entropy(logits)
            ema      = monitor.update_ema(entropy)
            kl_res   = monitor.compute_kl_divergence(logits, reference_logits)
            js       = monitor.compute_js_divergence(logits, reference_logits)

            ledger.commit_state(
                state_id=state_id,
                entropy=entropy,
                payload=logits.astype(np.float32).tobytes(),
            )

            # Alert logic: prefer KL when not saturated, JS otherwise
            if kl_res.saturated:
                alert = js > JS_ALERT_THRESHOLD
                kl_display = f"SAT({kl_res.value:.2f})"
                sat_flag = f"Y({kl_res.saturated_token_count})"
                score_used = f"JS={js:.3f}"
            else:
                alert = kl_res.value > KL_ALERT_THRESHOLD
                kl_display = f"{kl_res.value:.4f}"
                sat_flag = "N"
                score_used = f"KL={kl_res.value:.4f}"

            status = f"{'ALERT' if alert else 'OK':5s}  [{score_used}]  {desc}"
            print(
                f"  {state_id:<8} {entropy:>8.4f} {ema:>8.4f} "
                f"{kl_display:>8} {js:>6.4f} {sat_flag:>4}  {status}"
            )

        # ------------------------------------------------------------------
        # MoE routing analysis
        # ------------------------------------------------------------------
        print()
        print("  MOE ROUTING ANALYSIS")
        print(f"  {'Gate entropy':>14} {'Aggregate':>10} {'MaxGate':>8}  Flag")
        print("  " + "-" * 60)

        for gate_weights, expert_norms, desc in moe_stream:
            result = moe_monitor.detect_entanglement(gate_weights, expert_norms)
            print(
                f"  {result.routing_entropy:>14.4f} "
                f"{result.aggregate_activation:>10.4f} "
                f"{result.max_gate:>8.4f}  "
                f"{result.flag}  ({desc})"
            )
            if result.detected:
                # Commit entanglement event to the same audit chain
                ledger.commit_state(
                    state_id=f"MOE_ALERT_{state_id}",
                    entropy=result.routing_entropy,
                    payload=gate_weights.tobytes(),
                )

        # ------------------------------------------------------------------
        # Chain-of-custody audit
        # ------------------------------------------------------------------
        print()
        print("  CHAIN-OF-CUSTODY AUDIT")
        is_valid, error_idx = ledger.verify_integrity()

        node_count  = len(ledger.chain)
        tail_hash   = ledger.chain[-1].node_hash if ledger.chain else "N/A"
        admissibility = ledger.legal_admissibility
        pqc_algo    = ledger.chain[0].pqc_anchor.algorithm if ledger.chain else "N/A"

        print(f"  Nodes committed   : {node_count}")
        print(f"  Tail hash         : {tail_hash[:32]}...")
        print(f"  PQC anchor        : {pqc_algo}")
        print(f"  Legal admissibility: {admissibility}")

        if is_valid:
            print("  Integrity         : [PASS] No tampering detected.")
        else:
            print(f"  Integrity         : [FAIL] Corruption at node {error_idx}!")
            return 1

    # ------------------------------------------------------------------
    # WAL verification pass (simulates process restart)
    # ------------------------------------------------------------------
    print()
    print("  WAL RELOAD VERIFICATION (simulates process restart)")
    reloaded = CryptographicAuditLedger.load_from_wal(wal_path)
    ok, err = reloaded.verify_integrity()
    reloaded.close()
    print(
        f"  Reloaded {len(reloaded.chain)} nodes from WAL — "
        f"integrity: {'[PASS]' if ok else f'[FAIL @ {err}]'}"
    )

    if cleanup_wal:
        os.unlink(wal_path)

    print()
    print("=" * 62)
    return 0


if __name__ == "__main__":
    sys.exit(run_pipeline())

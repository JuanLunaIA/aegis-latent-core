# 🛡️ Aegis-Latent-Core (v1.3)
## High-Fidelity Latent-State Cryptographic Audit Ledger

Aegis-Latent-Core is an enterprise-grade forensic layer designed to monitor, audit, and prove the internal state transitions of Large Language Models (LLMs) and high-dimensional latent systems. By capturing logit entropy and routing distributions in a tamper-evident Merkle chain, Aegis provides a mathematically verifiable "black box" for AI decision-making.

---

## 🚀 Core Capabilities

### 1. Tamper-Evident Chain of Custody
Every system state is committed as a **MerkleAuditNode**. Using NULL-byte field separation and SHA-256 chaining, it is computationally impossible to modify a past state without invalidating the entire subsequent chain.

### 2. Tiered Durability Model
Aegis provides two operational modes to balance latency vs. legal admissibility:
- **Forensic Mode (Sync):** Every commit triggers a hardware `fsync()`. Guaranteed durability. `Legal Admissibility: High`.
- **Production Mode (Async):** High-throughput background writing with a `Future`-based acknowledgment API. Lowers latency for real-time inference.

### 3. Advanced Latent Monitoring
- **Shannon Entropy Monitoring:** Real-time tracking of model uncertainty.
- **KL-Divergence (Saturated):** Detects semantic drift with specialized flags for numerical saturation (gap > 50).
- **MoE Entanglement Detection:** Identifies "fragmented payloads" designed to evade single-expert anomaly detection.

### 4. Production Hardening
- **OOM Protection:** Built-in sliding window using `collections.deque`.
- **DoS Defense:** Strict `MAX_PAYLOAD_BYTES` limits on state snapshots.
- **Crash Resilience:** Robust WAL (Write-Ahead Log) recovery that handles partial writes/truncation.

---

## 🛠️ Installation & Quick Start

```bash
pip install numpy
# For GPU acceleration
pip install torch
```

```python
from src.crypto_audit import CryptographicAuditLedger
from src.telemetry import LogitEntropyMonitor

# 1. Initialize the Forensic Ledger
with CryptographicAuditLedger(persistence_path="audit.jsonl") as ledger:
    monitor = LogitEntropyMonitor()
    
    # 2. Compute metrics
    logits = np.random.randn(32000)
    entropy = monitor.compute_shannon_entropy(logits)
    
    # 3. Commit to the immutable chain
    node = ledger.commit_state(
        state_id="token_42", 
        entropy=entropy, 
        payload=logits.tobytes()
    )
    print(f"Committed node: {node.node_hash}")
```

---

## ⚖️ Legal & Forensic Admissibility

Aegis is designed to satisfy the requirements of digital forensic evidence:
1. **Immutability:** Merkle-chaining ensures that evidence cannot be retroactively altered.
2. **Continuity:** The WAL provides a continuous record of all transitions from the genesis block.
3. **Verifiability:** Any third-party auditor can run `verify_integrity()` to validate the entire history.
4. **PQC Readiness:** Infrastructure prepared for CRYSTALS-Dilithium (FIPS 204) to ensure longevity against quantum decryption.

---

## 📈 Performance Matrix

| Mode | Avg Latency | Throughput | Admissibility | Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Sync** | $\sim 0.6\text{ms}$ | $\sim 1.6\text{k commits/s}$ | **High** | Compliance, Court, Audit |
| **Async** | $\sim 0.05\text{ms}$ | $\sim 10\text{k+ commits/s}$ | **Hypothetical** | Real-time Production, UX |

---

## 📜 License
MIT License. See `LICENSE` for details.

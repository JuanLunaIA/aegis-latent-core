---
name: onnx-latent-waf
tier: HIGH
domains: [ONNX, entropy, semantic-surprise, prompt-injection, PII, WAF, latency-budget, quantization]
---
## Activation
Load on: ONNX inference in proxy path, semantic entropy/surprise estimation, prompt-injection
detection, PII scrubbing, on-proxy ML classifier, replacing char-level Shannon entropy.

## Latency Reality (read first — corrects the "130M sub-ms" claim)
```
[ESTABLISHED] A forward pass of a 130M-parameter transformer on CPU is NOT sub-millisecond.
Measured order of magnitude (CPU, INT8 quantized, batch=1, short seq):
  ~22M-param (MiniLM-L6):   ~3-8 ms   on a modern x86 core
  ~110M-param (BERT-base):  ~15-40 ms on CPU
  130M params:              tens of ms on CPU, NOT <1ms.
Sub-ms transformer inference requires GPU/NPU. Putting a GPU on every proxy node at high RPS
is a cost/architecture decision, not a free "on-proxy" feature.

THEREFORE the design MUST have an explicit latency budget and a fallback. State it honestly:
  - Tiny model (MiniLM ~22M, INT8): single-digit ms — usable inline if budget allows.
  - 130M model: usable ASYNC (out-of-path scoring) or on GPU nodes, NOT inline sub-ms.
```

## Tiered Detection Design (budget-aware)
```
[ANALYSIS] Layer detectors by cost; cheap-and-inline first, expensive-and-async last:

  L0 (inline, µs):    regex/heuristic — known injection patterns, PII regexes (email, SSN,
                      credit-card via Luhn). Cheapest. Catches the obvious.
  L1 (inline, ~ms):   tiny ONNX classifier (MiniLM INT8) IF p99 budget permits. Semantic
                      injection/jailbreak score. Gate behind a latency budget guard.
  L2 (async, tens ms): larger model scoring off-path → feeds audit/alerting, NOT request block
                      (can't block on it without blowing latency). Flags for review.

X→Y because Z: tiered detection → bounded inline latency because only L0+L1 are on the path
  and L1 is gated by a budget guard; L2's cost is hidden from the user request.
```

## ONNX Runtime Inference (real, with INT8 quantization)
```python
import onnxruntime as ort
import numpy as np

# Quantize first (offline): onnxruntime.quantization.quantize_dynamic(fp32, int8, weight_type=QInt8)
# X→Y because Z: INT8 dynamic quantization → ~2-4x faster CPU inference because integer
#   matmul uses VNNI/AVX2 int8 paths and the model is ~4x smaller (cache-friendly).

class SurpriseEstimator:
    def __init__(self, model_path: str, latency_budget_ms: float = 5.0):
        so = ort.SessionOptions()
        so.intra_op_num_threads = 1   # single-thread: predictable latency, no thread contention
        so.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        # CPUExecutionProvider; use CUDA/OpenVINO provider if hardware present
        self.sess = ort.InferenceSession(model_path, so, providers=["CPUExecutionProvider"])
        self.budget_ms = latency_budget_ms

    def score(self, input_ids: np.ndarray, attention_mask: np.ndarray):
        # {P}: tokenized input. {Q}: returns score, or None if over budget (caller falls back).
        out = self.sess.run(None, {"input_ids": input_ids, "attention_mask": attention_mask})
        logits = out[0]
        # softmax → probability of "injection"/"anomalous" class
        e = np.exp(logits - logits.max(axis=-1, keepdims=True))
        return float((e / e.sum(axis=-1, keepdims=True))[0, 1])

# Inline budget guard: if recent p99 of L1 exceeds budget, SKIP L1, fall back to L0 only.
# Never let an inline model silently blow the request latency SLA.
```

## Honest Entropy Comparison
```
[INFERENCE] Char-level Shannon entropy H(X) = -Σ p(x) log2 p(x) measures byte distribution,
NOT semantic surprise. It's a weak proxy. A semantic model is genuinely better signal.
BUT: when provider logprobs ARE available (OpenAI), token logprobs give true model perplexity
for ~free (already in the response) — that beats running your own model. Priority:
  1. Provider logprobs (free, true perplexity) — use when available (OpenAI).
  2. Local ONNX surprise (costs ms) — when logprobs absent (Anthropic/Gemini) AND budget allows.
  3. Char-level Shannon (µs, weak) — last-resort fallback.
X→Y because Z: prefer provider logprobs → best signal at zero added latency because the model
  already computed them; running a local model to re-estimate what you were given is wasteful.
```

## Edge-Case Matrix & Recovery
| Scenario | Detection Signature | Recovery Protocol |
|---|---|---|
| ONNX inference exceeds latency budget | L1 p99 > budget_ms | Budget guard skips L1 → L0-only inline; route L1/L2 to async scoring; alert; consider GPU node or smaller model |
| Adversarial evasion (obfuscated injection) | Known-bad prompt scores low | Defense-in-depth: L0 regex + L1 semantic + L2 async; log misses for retraining; never rely on one layer |
| Model file corrupt/missing | InferenceSession init fails | Fail to L0 heuristics (degrade, don't crash); alert; the proxy stays up with reduced detection |
| False-positive PII block | Legit request blocked; user complaint | Tune thresholds; allowlist; PII detection should flag/redact in audit, blocking only on policy; make action configurable |
| Tokenizer/model version drift | Scores shift after model update | Pin model+tokenizer versions; version the entropy_method field in audit; A/B before rollout |

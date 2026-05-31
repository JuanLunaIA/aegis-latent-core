"""
aegis.proxy.analyzer — Entropy analysis on OpenAI logprobs payloads.

Operates on the `logprobs` field returned by /v1/chat/completions
when `top_logprobs` > 0. Builds a per-token probability distribution from the
top-k logprobs, computes Shannon entropy, EMA, KL and JS divergence,
and emits structured alerts when thresholds are exceeded.
"""
from __future__ import annotations

import logging
import math
import time
from dataclasses import dataclass, field
from typing import Any

import numpy as np

from aegis.core.telemetry import LogitEntropyMonitor
from aegis.proxy.schemas import AlertOut, ChoiceLogprobs

logger = logging.getLogger(__name__)

_MIN_TOKENS_FOR_ANALYSIS = 3   # skip single-token responses


@dataclass
class TokenAnalysis:
    """Per-token entropy analysis result."""
    token: str
    entropy_bits: float
    ema: float
    kl_vs_prev: float | None
    js_vs_prev: float | None
    alert: AlertOut | None


@dataclass
class ResponseAnalysis:
    """Full analysis of a single LLM response."""
    session_id: str
    request_id: str
    model: str
    timestamp: float
    tokens: list[TokenAnalysis]
    mean_entropy: float
    min_entropy: float
    max_entropy: float
    alerts: list[AlertOut]
    sampling_params: dict[str, Any] = field(default_factory=dict)

    @property
    def has_alerts(self) -> bool:
        return len(self.alerts) > 0


def _logprobs_to_numpy(top_logprobs: list) -> np.ndarray:
    """Convert a list of TopLogprob objects to a normalised probability array."""
    if not top_logprobs:
        return np.array([1.0])
    lp = np.array([t.logprob for t in top_logprobs], dtype=np.float64)
    lp -= np.max(lp)
    probs = np.exp(lp)
    s = probs.sum()
    if s == 0.0:
        return np.ones(len(probs)) / len(probs)
    return probs / s


class ResponseAnalyzer:
    """Stateful per-session analyzer.  One instance per session_id."""

    def __init__(
        self,
        session_id: str,
        kl_threshold: float = 2.0,
        js_threshold: float = 0.5,
        entropy_alert_drop_bits: float = 1.0,
        ema_alpha: float = 0.2,
    ) -> None:
        self.session_id = session_id
        self.kl_threshold = kl_threshold
        self.js_threshold = js_threshold
        self.entropy_alert_drop_bits = entropy_alert_drop_bits
        self._monitor = LogitEntropyMonitor(ema_alpha=ema_alpha)
        self._prev_logits: np.ndarray | None = None
        self._baseline_entropy: float | None = None

    def _make_alert(
        self,
        state_id: str,
        alert_type: str,
        severity: str,
        metric_name: str,
        metric_value: float,
        threshold: float,
        detail: str,
    ) -> AlertOut:
        return AlertOut(
            session_id=self.session_id,
            state_id=state_id,
            timestamp=time.time(),
            alert_type=alert_type,
            severity=severity,
            metric_name=metric_name,
            metric_value=metric_value,
            threshold=threshold,
            detail=detail,
        )

    def analyze(
        self,
        request_id: str,
        model: str,
        logprobs_data: ChoiceLogprobs | list[ChoiceLogprobs] | None,
        sampling_params: dict[str, Any] | None = None,
    ) -> ResponseAnalysis:
        """Analyze a single response's logprobs and return structured results."""
        ts = time.time()
        params = sampling_params or {}
        token_results: list[TokenAnalysis] = []
        alerts: list[AlertOut] = []
        entropies: list[float] = []

        # --- Extraction ---
        content = None
        if isinstance(logprobs_data, list) and len(logprobs_data) > 0:
            content = getattr(logprobs_data[0], 'content', None)
        elif hasattr(logprobs_data, 'content'):
            content = logprobs_data.content

        if not content or len(content) < _MIN_TOKENS_FOR_ANALYSIS:
            return ResponseAnalysis(
                session_id=self.session_id,
                request_id=request_id,
                model=model,
                timestamp=ts,
                tokens=[],
                mean_entropy=float("nan"),
                min_entropy=float("nan"),
                max_entropy=float("nan"),
                alerts=[],
                sampling_params=params,
            )

        # --- DATA LEAK DETECTION (SISTEMA INEXPUGNABLE) ---
        full_text = "".join([tok.token for tok in content])
        from aegis.core.leak_detector import DataLeakDetector
        leak_detector = DataLeakDetector()
        is_leaking, leak_detail = leak_detector.is_leaking(full_text)
        if is_leaking:
            alerts.append(self._make_alert(
                request_id, "DATA_LEAK", "CRITICAL",
                "payload_entropy", 0.0, 0.0,
                f"CRITICAL: Potential data exfiltration detected! {leak_detail}"
            ))

        for i, tok in enumerate(content):
            state_id = f"{request_id}_tok{i}"
            logits = _logprobs_to_numpy(tok.top_logprobs)
            pseudo_logits = np.log(np.maximum(logits, 1e-15))

            entropy = self._monitor.compute_shannon_entropy(pseudo_logits)
            ema = self._monitor.update_ema(entropy)
            entropies.append(entropy)

            kl: float | None = None
            js: float | None = None
            tok_alert: AlertOut | None = None

            # 1. Semantic Drift Detection (vs Baseline)
            if self._monitor._baseline_dist is None and i == 0:
                self._monitor._baseline_dist = pseudo_logits

            if self._monitor._baseline_dist is not None:
                kl_res = self._monitor.compute_kl_divergence(pseudo_logits, self._monitor._baseline_dist)
                kl = kl_res.value
                if kl > self.kl_threshold * 2:
                    tok_alert = self._make_alert(
                        state_id, "SEMANTIC_DRIFT", "HIGH",
                        "kl_baseline", kl, self.kl_threshold * 2,
                        f"Token {i} ('{tok.token}'): Divergence from baseline KL={kl:.4f}",
                    )

            # 2. Sequence-based Drift Detection (vs Previous Token)
            if self._prev_logits is not None:
                prev = self._prev_logits
                curr = pseudo_logits
                kl_res = self._monitor.compute_kl_divergence(curr, prev)
                kl = kl_res.value
                js = self._monitor.compute_js_divergence(curr, prev)

                if not kl_res.saturated and kl > self.kl_threshold:
                    sev = "CRITICAL" if kl > self.kl_threshold * 3 else "HIGH"
                    tok_alert = self._make_alert(
                        state_id, "KL_SPIKE", sev,
                        "kl_divergence", kl, self.kl_threshold,
                        f"Token {i} ('{tok.token}'): KL={kl:.4f} > threshold={self.kl_threshold}",
                    )
                elif kl_res.saturated and js > self.js_threshold:
                    tok_alert = self._make_alert(
                        state_id, "JS_SPIKE", "HIGH",
                        "js_divergence", js, self.js_threshold,
                        f"Token {i} ('{tok.token}'): KL saturated, JS={js:.4f} > threshold={self.js_threshold}",
                    )

            # Entropy collapse detection
            if self._baseline_entropy is not None:
                drop = self._baseline_entropy - entropy
                if drop > self.entropy_alert_drop_bits:
                    sev = "CRITICAL" if drop > self.entropy_alert_drop_bits * 3 else "MEDIUM"
                    collapse_alert = self._make_alert(
                        state_id, "ENTROPY_COLLAPSE", sev,
                        "entropy_drop_bits", drop, self.entropy_alert_drop_bits,
                        f"Token {i} ('{tok.token}'): entropy dropped {drop:.4f} bits below baseline",
                    )
                    if tok_alert is None:
                        tok_alert = collapse_alert
                    else:
                        alerts.append(collapse_alert)
            else:
                self._baseline_entropy = entropy

            if tok_alert:
                alerts.append(tok_alert)

            self._prev_logits = pseudo_logits
            token_results.append(TokenAnalysis(
                token=tok.token,
                entropy_bits=entropy,
                ema=ema,
                kl_vs_prev=kl,
                js_vs_prev=js,
                alert=tok_alert,
            ))

        finite_entropies = [e for e in entropies if math.isfinite(e)]
        mean_e = float(np.mean(finite_entropies)) if finite_entropies else float("nan")
        min_e = float(np.min(finite_entropies)) if finite_entropies else float("nan")
        max_e = float(np.max(finite_entropies)) if finite_entropies else float("nan")

        return ResponseAnalysis(
            session_id=self.session_id,
            request_id=request_id,
            model=model,
            timestamp=ts,
            tokens=token_results,
            mean_entropy=mean_e,
            min_entropy=min_e,
            max_entropy=max_e,
            alerts=alerts,
            sampling_params=params,
        )

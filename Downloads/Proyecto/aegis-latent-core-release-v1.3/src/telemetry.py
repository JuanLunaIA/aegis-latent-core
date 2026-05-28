"""
telemetry.py - Signal Analysis Layer
"""

from __future__ import annotations
import math
from dataclasses import dataclass
from typing import Optional
import numpy as np
from .math_utils import normalize_logits

@dataclass(frozen=True)
class KLResult:
    value: float
    saturated: bool
    near_saturated: bool
    saturated_token_count: int

class LogitEntropyMonitor:
    _EPSILON: float = 1e-15

    def __init__(self, ema_alpha: float = 0.1) -> None:
        if not (0.0 < ema_alpha < 1.0):
            raise ValueError("ema_alpha must be in (0, 1)")
        self.ema_alpha = ema_alpha
        self.current_ema: Optional[float] = None

    def compute_entropy_gpu(self, logits_tensor) -> float:
        try:
            import torch
        except ImportError:
            raise ImportError("torch is required for compute_entropy_gpu().")
        with torch.no_grad():
            probs = torch.softmax(logits_tensor, dim=-1)
            p_clipped = torch.clamp(probs, min=self._EPSILON)
            entropy = -torch.sum(p_clipped * torch.log2(p_clipped))
        return float(entropy.item())

    def compute_shannon_entropy(self, logits: np.ndarray) -> float:
        probs = normalize_logits(logits)
        p_clipped = np.maximum(probs, self._EPSILON)
        return float(-np.sum(p_clipped * np.log2(p_clipped)))

    def update_ema(self, entropy: float) -> float:
        if not math.isfinite(entropy):
            raise ValueError("non-finite entropy")
        if self.current_ema is None:
            self.current_ema = entropy
        else:
            self.current_ema = (self.ema_alpha * entropy) + (1.0 - self.ema_alpha) * self.current_ema
        return self.current_ema

    def compute_kl_divergence(self, p_logits: np.ndarray, q_logits: np.ndarray) -> KLResult:
        if p_logits.shape != q_logits.shape:
            raise ValueError("shape mismatch")
        p = normalize_logits(p_logits)
        q = normalize_logits(q_logits)
        underflow_mask = q == 0.0
        saturated_count = int(np.sum(underflow_mask))
        p_c = np.maximum(p, self._EPSILON)
        q_c = np.maximum(q, self._EPSILON)
        nonzero_p = p_c > self._EPSILON
        kl_value = float(np.sum(p_c[nonzero_p] * np.log2(p_c[nonzero_p] / q_c[nonzero_p])))
        return KLResult(
            value=kl_value,
            saturated=saturated_count > 0,
            near_saturated=kl_value > 30.0,
            saturated_token_count=saturated_count,
        )

    def compute_js_divergence(self, p_logits: np.ndarray, q_logits: np.ndarray) -> float:
        p = normalize_logits(p_logits)
        q = normalize_logits(q_logits)
        m = 0.5 * (p + q)
        eps = self._EPSILON
        p_c, q_c, m_c = np.maximum(p, eps), np.maximum(q, eps), np.maximum(m, eps)
        kl_pm = np.sum(p_c * np.log2(p_c / m_c))
        kl_qm = np.sum(q_c * np.log2(q_c / m_c))
        return float(np.clip(0.5 * (kl_pm + kl_qm), 0.0, 1.0))

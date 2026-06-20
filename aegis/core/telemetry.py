"""
telemetry.py - Advanced Information-Theoretic Signal Analysis Layer
"""

# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass

import numpy as np

from aegis.core.math_utils import log_softmax, normalize_logits

# Finite stand-in for log(0) when padding a shorter distribution to match a
# longer one.  Using -inf would be mathematically natural but math_utils'
# log_softmax/normalize_logits reject non-finite inputs.  exp(_PAD_LOGIT - max)
# underflows to exactly 0.0 in float64, so the padded slots carry zero
# probability mass (and register as "saturated") while keeping every array
# finite.  X→Y because consecutive response tokens almost always expose
# different ``top_logprobs`` counts, so KL/JS over them MUST tolerate ragged
# lengths or the entire sequence-drift path raises and 500s the proxy.
_PAD_LOGIT: float = -1e30


def _pad_to_common_length(
    p_logits: np.ndarray, q_logits: np.ndarray
) -> tuple[np.ndarray, np.ndarray]:
    """Right-pad the shorter logit array with ``_PAD_LOGIT`` so both match.

    Returns the inputs unchanged when shapes already agree.
    """
    if p_logits.shape == q_logits.shape:
        return p_logits, q_logits
    max_len = max(len(p_logits), len(q_logits))
    p_logits = np.pad(p_logits, (0, max_len - len(p_logits)), constant_values=_PAD_LOGIT)
    q_logits = np.pad(q_logits, (0, max_len - len(q_logits)), constant_values=_PAD_LOGIT)
    return p_logits, q_logits


@dataclass(frozen=True)
class KLResult:
    value: float
    saturated: bool
    near_saturated: bool
    saturated_token_count: int


class LogitEntropyMonitor:
    _EPSILON: float = 1e-15

    def __init__(self, ema_alpha: float = 0.1, window_size: int = 20) -> None:
        if not (0.0 < ema_alpha < 1.0):
            raise ValueError("ema_alpha must be in (0, 1)")
        self.ema_alpha = ema_alpha
        self.current_ema: float | None = None
        self.window_size = window_size
        self.history: deque[float] = deque(maxlen=window_size)
        # Baseline distribution for semantic drift detection
        self._baseline_dist: np.ndarray | None = None

    def compute_shannon_entropy(self, logits: np.ndarray) -> float:
        log_p = log_softmax(logits)
        probs = np.exp(log_p)
        return float(-np.sum(probs * log_p) / np.log(2.0))

    # FIX BUG-06: documented in README API reference but missing from code.
    # Raises ImportError with a clear message when torch is absent so callers
    # can decide whether to fall back to compute_shannon_entropy.
    def compute_entropy_gpu(self, logits_tensor) -> float:  # type: ignore[return]
        """
        Compute Shannon entropy on a GPU-resident torch.Tensor without copying
        the full distribution to CPU.

        Requires: torch >= 2.0

        Args:
            logits_tensor: torch.Tensor of shape (V,) or (1, V) — raw unnormalised
                           logits.  Any device supported by the installed torch build.

        Returns:
            Entropy in bits (float).

        Raises:
            ImportError: if torch is not installed.
            ValueError:  if logits_tensor has unexpected rank.
        """
        try:
            import torch  # type: ignore[import]
        except ImportError as exc:
            raise ImportError(
                "compute_entropy_gpu requires PyTorch >= 2.0.  Install via: pip install torch"
            ) from exc

        if logits_tensor.dim() == 2 and logits_tensor.shape[0] == 1:
            logits_tensor = logits_tensor.squeeze(0)
        if logits_tensor.dim() != 1:
            raise ValueError(f"Expected 1-D logits tensor, got shape {tuple(logits_tensor.shape)}")

        with torch.no_grad():
            log_p = torch.nn.functional.log_softmax(logits_tensor, dim=0)
            p = torch.exp(log_p)
            entropy_nats = -torch.sum(p * log_p)
            entropy_bits = entropy_nats / math.log(2.0)
            return float(entropy_bits.item())

    def update_ema(self, entropy: float) -> float:
        if not math.isfinite(entropy):
            raise ValueError("non-finite entropy")

        # deque(maxlen=window_size) handles eviction automatically — no pop(0).
        self.history.append(entropy)

        if self.current_ema is None:
            self.current_ema = entropy
        else:
            self.current_ema = self.ema_alpha * entropy + (1.0 - self.ema_alpha) * self.current_ema
        return self.current_ema

    def get_variance_stability(self) -> float:
        """
        Sentry Atómico: Mide la estabilidad de la entropía.
        Varianza muy baja en ventanas largas = Ataque de Sigilo (estático).
        Varianza alta = Comportamiento humano/estocástico.
        """
        if len(self.history) < 2:
            return 1.0  # Default neutral
        return float(np.var(list(self.history)))

    def compute_kl_divergence(self, p_logits: np.ndarray, q_logits: np.ndarray) -> KLResult:
        # Handle vocab size mismatch by padding the smaller distribution with a
        # finite stand-in for log(0) (see _PAD_LOGIT) so log_softmax accepts it.
        p_logits, q_logits = _pad_to_common_length(p_logits, q_logits)

        log_p = log_softmax(p_logits)
        log_q = log_softmax(q_logits)
        p = np.exp(log_p)

        # Robust KL computation avoiding log(0)
        kl_elements = p * (log_p - log_q) / np.log(2.0)
        kl_elements = np.nan_to_num(kl_elements, nan=0.0, posinf=0.0, neginf=0.0)
        kl_value = float(np.sum(kl_elements))

        raw_q = np.exp(q_logits - np.max(q_logits))
        saturated_count = int(np.sum(raw_q == 0.0))
        return KLResult(
            value=kl_value,
            saturated=saturated_count > 0,
            near_saturated=kl_value > 30.0,
            saturated_token_count=saturated_count,
        )

    def compute_js_divergence(self, p_logits: np.ndarray, q_logits: np.ndarray) -> float:
        # Ragged consecutive-token distributions must be aligned before the
        # element-wise mixture m = 0.5*(p+q); otherwise numpy raises on the
        # shape mismatch and the sequence-drift path 500s the proxy.
        p_logits, q_logits = _pad_to_common_length(p_logits, q_logits)
        p = normalize_logits(p_logits)
        q = normalize_logits(q_logits)
        m = 0.5 * (p + q)
        eps = self._EPSILON
        p_c = np.maximum(p, eps)
        q_c = np.maximum(q, eps)
        m_c = np.maximum(m, eps)
        kl_pm = np.sum(p_c * np.log2(p_c / m_c))
        kl_qm = np.sum(q_c * np.log2(q_c / m_c))
        return float(np.clip(0.5 * (kl_pm + kl_qm), 0.0, 1.0))

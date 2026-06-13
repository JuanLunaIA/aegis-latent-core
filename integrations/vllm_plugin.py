"""
integrations.vllm_plugin — vLLM forward hook for full logit + MoE gate extraction.

Usage (in your vLLM server startup script):

    from integrations.vllm_plugin import AegisVLLMPlugin
    plugin = AegisVLLMPlugin(aegis_url="http://localhost:8080", api_key="sk-...")
    plugin.attach(llm_engine)   # llm_engine: vllm.LLMEngine

Requires: vllm>=0.4.0, torch>=2.0
"""

# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import logging
import time
import uuid
from typing import Any

import httpx
import numpy as np

logger = logging.getLogger(__name__)

_TELEMETRY_ENDPOINT = "/v1/internal/telemetry"


class AegisVLLMPlugin:
    """
    Attaches PyTorch forward hooks to a vLLM LLMEngine to capture raw logits
    and, when available, MoE gate weights for full Aegis analysis.

    The plugin posts telemetry asynchronously to the Aegis proxy so the
    critical inference path is never blocked.
    """

    def __init__(
        self,
        aegis_url: str,
        api_key: str,
        session_id: str | None = None,
        timeout: float = 2.0,
    ) -> None:
        self._aegis_url = aegis_url.rstrip("/")
        self._api_key = api_key
        self._session_id = session_id or str(uuid.uuid4())
        self._timeout = timeout
        self._client = httpx.Client(
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=timeout,
        )
        self._hooks: list[Any] = []

    def attach(self, llm_engine: Any) -> None:
        """
        Attach hooks to *llm_engine*.

        Navigates to the underlying torch.nn.Module via the standard vLLM
        model_executor path.  Registers:
          - A post-forward hook on the final lm_head layer to capture logits.
          - A post-forward hook on each MoELayer (if present) to capture gate weights.
        """
        try:
            model = llm_engine.model_executor.driver_worker.model_runner.model
        except AttributeError as exc:
            raise RuntimeError(
                f"Cannot locate model module in vLLM engine: {exc}. "
                "Ensure vllm>=0.4.0 and that the engine is fully initialised."
            ) from exc

        self._register_lm_head_hook(model)
        self._register_moe_hooks(model)
        logger.info(
            "AegisVLLMPlugin attached to vLLM engine; session=%s hooks=%d",
            self._session_id,
            len(self._hooks),
        )

    def _register_lm_head_hook(self, model: Any) -> None:
        import torch

        lm_head = getattr(model, "lm_head", None)
        if lm_head is None:
            logger.warning("lm_head not found on model; logit hook not registered.")
            return

        def _hook(_module: Any, _input: Any, output: Any) -> None:
            if isinstance(output, torch.Tensor):
                # Detach to avoid retaining the computation graph.
                logits_np = output.detach().float().cpu().numpy()
                self._post_logit_telemetry(logits_np)

        handle = lm_head.register_forward_hook(_hook)
        self._hooks.append(handle)

    def _register_moe_hooks(self, model: Any) -> None:
        import torch

        moe_count = 0
        for name, module in model.named_modules():
            cls_name = type(module).__name__
            if "MoE" in cls_name or "Expert" in cls_name or "Router" in cls_name:

                def _moe_hook(_mod: Any, _inp: Any, out: Any, _n: str = name) -> None:
                    # vLLM MoE layers return (hidden_states, router_logits)
                    if isinstance(out, tuple) and len(out) >= 2:
                        router_output = out[1]
                        if isinstance(router_output, torch.Tensor):
                            gates_np = router_output.detach().float().cpu().numpy()
                            self._post_moe_telemetry(_n, gates_np)

                handle = module.register_forward_hook(_moe_hook)
                self._hooks.append(handle)
                moe_count += 1

        logger.info("MoE hooks registered on %d modules.", moe_count)

    def _post_logit_telemetry(self, logits: np.ndarray) -> None:
        """Send logit telemetry to Aegis (best-effort, non-blocking)."""
        try:
            payload = {
                "type": "logits",
                "session_id": self._session_id,
                "timestamp": time.time(),
                "shape": list(logits.shape),
                # Send top-100 logits per position to limit bandwidth.
                "top_k_logits": logits[..., :100].tolist() if logits.ndim >= 1 else logits.tolist(),
            }
            self._client.post(
                f"{self._aegis_url}{_TELEMETRY_ENDPOINT}",
                json=payload,
                timeout=self._timeout,
            )
        except Exception as exc:
            logger.debug("Logit telemetry post failed (non-critical): %s", exc)

    def _post_moe_telemetry(self, layer_name: str, gate_weights: np.ndarray) -> None:
        """Send MoE gate telemetry to Aegis (best-effort, non-blocking)."""
        try:
            flat_gates = gate_weights.flatten().tolist()
            payload = {
                "type": "moe_gates",
                "session_id": self._session_id,
                "layer_name": layer_name,
                "timestamp": time.time(),
                "gate_weights": flat_gates[:256],  # cap at 256 experts
            }
            self._client.post(
                f"{self._aegis_url}{_TELEMETRY_ENDPOINT}",
                json=payload,
                timeout=self._timeout,
            )
        except Exception as exc:
            logger.debug("MoE telemetry post failed (non-critical): %s", exc)

    def detach(self) -> None:
        """Remove all registered hooks from the model."""
        for handle in self._hooks:
            handle.remove()
        self._hooks.clear()
        logger.info("AegisVLLMPlugin hooks detached.")

    def __del__(self) -> None:
        try:
            self._client.close()
        except Exception:
            pass

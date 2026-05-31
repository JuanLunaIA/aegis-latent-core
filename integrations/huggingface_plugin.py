"""
integrations.huggingface_plugin — HuggingFace Transformers hook for Aegis.

Usage:

    from integrations.huggingface_plugin import AegisHFPlugin
    plugin = AegisHFPlugin(aegis_url="http://localhost:8080", api_key="sk-...")
    plugin.attach(model)   # model: transformers.PreTrainedModel

Requires: transformers>=4.40, torch>=2.0
"""
from __future__ import annotations
import logging
import time
import uuid
from typing import Any

import httpx
import numpy as np

logger = logging.getLogger(__name__)


class AegisHFPlugin:
    """
    Attaches forward hooks to a HuggingFace PreTrainedModel to capture
    raw logits for Aegis entropy analysis.
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

    def attach(self, model: Any) -> None:
        """Register hooks on *model* (transformers.PreTrainedModel)."""
        import torch

        lm_head = getattr(model, "lm_head", None)
        if lm_head is None:
            raise AttributeError("Model has no lm_head attribute.")

        def _hook(_mod: Any, _inp: Any, output: Any) -> None:
            tensor = output
            if isinstance(output, tuple):
                tensor = output[0]
            if isinstance(tensor, torch.Tensor):
                logits_np = tensor.detach().float().cpu().numpy()
                self._post_telemetry(logits_np)

        handle = lm_head.register_forward_hook(_hook)
        self._hooks.append(handle)
        logger.info("AegisHFPlugin attached; session=%s", self._session_id)

    def _post_telemetry(self, logits: np.ndarray) -> None:
        try:
            last_pos = logits[0, -1, :100] if logits.ndim == 3 else logits[:100]
            payload = {
                "type": "logits",
                "session_id": self._session_id,
                "timestamp": time.time(),
                "top_k_logits": last_pos.tolist(),
            }
            self._client.post(
                f"{self._aegis_url}/v1/internal/telemetry",
                json=payload,
                timeout=self._timeout,
            )
        except Exception as exc:
            logger.debug("HF telemetry post failed (non-critical): %s", exc)

    def detach(self) -> None:
        for h in self._hooks:
            h.remove()
        self._hooks.clear()

    def __del__(self) -> None:
        try:
            self._client.close()
        except Exception:
            pass

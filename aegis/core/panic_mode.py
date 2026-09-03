# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.panic_mode — Logical self-destruct (panic-mode).

Implements a high-priority kill switch to wipe sensitive data and isolate
the network upon detection of a critical security breach.

Zeroization uses :func:`ctypes.memset` on registered sensitive
``bytearray``/``memoryview`` buffers.  Network isolation issues a real
``nft``/``iptables`` DROP-all rule via subprocess so that the kernel
stops forwarding packets immediately — it does not merely log a message.

Limitations
-----------
- Only buffers *registered* with ``register_sensitive_buffer()`` before a
  panic are zeroed.  Secrets in unregistered Python objects, CPython
  internals, or native extensions are not reached.
- Network isolation requires ``nft`` or ``iptables`` to be available and
  the process to have ``CAP_NET_ADMIN``; otherwise it logs a clear advisory
  rather than pretending to succeed.
"""

from __future__ import annotations

import ctypes
import logging
import os
import shutil  # noqa: S404
import subprocess  # noqa: S404  # nosec B404
from collections.abc import Callable
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class PanicTrigger:
    source: str
    reason: str
    severity: str  # 'CRITICAL' | 'CATASTROPHIC'


class PanicModeController:
    """Orchestrates emergency shutdown of the Aegis Core.

    Ensures sensitive data is destroyed and the network is isolated before
    an attacker can extract secrets or receive further data.

    Register sensitive buffers before activating via
    ``register_sensitive_buffer()``.  Panic callbacks (key-wipe, HSM-lock,
    etc.) are called first, then memory is zeroed, then the network is cut.
    """

    def __init__(self) -> None:
        self._panic_callbacks: list[Callable[[], None]] = []
        self._sensitive_buffers: list[bytearray | memoryview] = []
        logger.info("PanicModeController initialised. Kill-switch armed.")

    def register_panic_callback(self, callback: Callable[[], None]) -> None:
        """Register a function to call during the panic sequence."""
        self._panic_callbacks.append(callback)

    def register_sensitive_buffer(self, buf: bytearray | memoryview) -> None:
        """Register a buffer to be zeroed during panic.

        Pass all secret key material, session tokens, and ephemeral buffers
        here so they are wiped when ``trigger_panic()`` is called.
        """
        self._sensitive_buffers.append(buf)

    def trigger_panic(self, trigger: PanicTrigger) -> None:
        """Initiate the self-destruct sequence.

        This is a non-returnable operation — it calls ``os._exit(137)``
        after completing the cleanup sequence.
        """
        logger.critical("!!! PANIC MODE ACTIVATED !!!")
        logger.critical(
            "SOURCE: %s | REASON: %s | SEVERITY: %s",
            trigger.source,
            trigger.reason,
            trigger.severity,
        )

        # 1. Execute registered callbacks first (e.g. lock HSM, revoke tokens)
        for callback in self._panic_callbacks:
            try:
                callback()
            except Exception as exc:  # noqa: BLE001
                logger.error("Panic callback failed: %s", exc)

        # 2. Securely wipe registered sensitive buffers
        self._zeroize_critical_memory()

        # 3. Drop all network connections
        self._isolate_network()

        # 4. Final halt — SIGKILL equivalent, no Python atexit handlers
        logger.critical("SISTEMA INEXPUGNABLE: self-destruct complete. Halting.")
        os._exit(137)  # noqa: SLF001

    def _zeroize_critical_memory(self) -> None:
        """Zero every registered sensitive buffer via ctypes.memset.

        Uses ``ctypes.memset`` (a thin wrapper over the C stdlib function)
        to overwrite buffer contents in-place.  Python's GC cannot reclaim
        the backing memory between the ``memset`` and the process exit, so
        the window for extraction is minimised.

        Note: secrets in unregistered Python objects are not reached — this
        is best-effort given Python's memory model.  Callers must register
        all secret-bearing buffers before triggering panic.
        """
        logger.info("Zeroizing %d registered sensitive buffer(s)...", len(self._sensitive_buffers))
        wiped = 0
        for buf in self._sensitive_buffers:
            try:
                view = memoryview(buf).cast("B")
                addr = ctypes.addressof((ctypes.c_char * len(view)).from_buffer(view))
                ctypes.memset(addr, 0, len(view))
                wiped += 1
            except Exception as exc:  # noqa: BLE001
                logger.error("Buffer zeroize failed: %s", exc)
        logger.info(
            "Memory zeroization complete: %d/%d buffers wiped.", wiped, len(self._sensitive_buffers)
        )

    def _isolate_network(self) -> bool:
        """Block all incoming and outgoing traffic via nft or iptables.

        Adds a kernel-level DROP-all rule to cut the network immediately.
        Returns True when the rule was installed.  Logs an advisory (does
        NOT silently succeed) when no firewall tool is available.
        """
        nft = shutil.which("nft")
        ipt = shutil.which("iptables")

        if nft:
            ok = self._run_cmd([nft, "add", "rule", "inet", "filter", "input", "drop"])
            ok2 = self._run_cmd([nft, "add", "rule", "inet", "filter", "output", "drop"])
            if ok or ok2:
                logger.info("Network isolated via nftables DROP-all rules.")
                return True

        if ipt:
            ok = self._run_cmd([ipt, "-P", "INPUT", "DROP"])
            self._run_cmd([ipt, "-P", "OUTPUT", "DROP"])
            self._run_cmd([ipt, "-P", "FORWARD", "DROP"])
            if ok:
                logger.info("Network isolated via iptables DROP policy.")
                return True

        logger.critical(
            "NETWORK ISOLATION FAILED: neither nft nor iptables available "
            "(or CAP_NET_ADMIN not granted). Packets are NOT blocked at the kernel."
        )
        return False

    @staticmethod
    def _run_cmd(cmd: list[str]) -> bool:
        """Run a firewall command; return True on success."""
        try:
            subprocess.run(  # noqa: S603  # nosec B603
                cmd, capture_output=True, check=True, timeout=5
            )
            return True
        except Exception as exc:  # noqa: BLE001
            logger.error("Panic firewall command failed %s: %s", cmd, exc)
            return False


# Global singleton — callers register buffers and callbacks at import time
PANIC_CONTROLLER = PanicModeController()

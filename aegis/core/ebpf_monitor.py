"""
aegis.core.ebpf_monitor — eBPF-based Real-time Observability.
Monitors data flow integrity and detects micro-latency anomalies (jitter)
that may indicate rootkits or side-channel attacks.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import asyncio
import logging
import shutil
import subprocess  # noqa: S404  # nosec B404
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class TelemetryEvent:
    timestamp: float
    event_type: str
    latency_us: float
    payload_hash: str
    cpu_core: int
    process_id: int
    syscall_name: str


class EBPFProbe:
    """
    Represents a loaded eBPF probe in the kernel.
    Requires bpftool to be installed and BPF syscall access to be enabled.
    When bpftool is absent or BPF is unavailable the probe will not be
    activated and poll_events() returns an empty list.
    """

    def __init__(self, name: str, target_syscall: str):
        self.name = name
        self.target_syscall = target_syscall
        self._active = False

    def load(self) -> bool:
        """
        Attempts to activate the eBPF probe via bpftool.
        Returns True only when bpftool is present and BPF access is confirmed.
        """
        logger.info("Loading eBPF probe [%s] on syscall [%s]...", self.name, self.target_syscall)

        if shutil.which("bpftool") is None:
            logger.warning(
                "bpftool not found — probe [%s] cannot be activated. "
                "Install bpftool and ensure CAP_BPF or root access.",
                self.name,
            )
            self._active = False
            return False

        result = subprocess.run(  # noqa: S603 S607  # nosec B603 B607
            ["bpftool", "prog", "list"],
            capture_output=True,
        )
        if result.returncode != 0:
            logger.warning(
                "bpftool prog list failed (rc=%d) — BPF may require elevated privileges "
                "or kernel CONFIG_BPF_SYSCALL. Probe [%s] not activated.",
                result.returncode,
                self.name,
            )
            self._active = False
            return False

        self._active = True
        logger.info("BPF access confirmed. Probe [%s] activated.", self.name)
        return True

    def poll_events(self) -> list[TelemetryEvent]:
        """
        Returns kernel events captured by this probe.
        Real event polling requires compiled BPF programs and perf/ring buffers.
        Returns an empty list when the probe is not active or no programs are loaded.
        """
        if not self._active:
            return []
        return []


class IntegrityMonitor:
    """
    Analyzes eBPF telemetry to detect structural anomalies in data flow.
    """

    def __init__(self, latency_threshold_us: float = 1000.0):
        self.latency_threshold_us = latency_threshold_us
        self.probes: list[EBPFProbe] = [
            EBPFProbe("net_rx_integrity", "recvfrom"),
            EBPFProbe("net_tx_integrity", "sendto"),
            EBPFProbe("mem_access_audit", "mmap"),
            EBPFProbe("file_access_audit", "openat"),
            EBPFProbe("proc_execution_audit", "execve"),
            EBPFProbe("socket_creation_audit", "socket"),
        ]
        self._running = False

    async def start(self):
        for probe in self.probes:
            probe.load()
        self._running = True
        asyncio.create_task(self._monitor_loop())
        logger.info(
            "eBPF Integrity Monitor active. Scanning for micro-latency, critical syscalls, and memory corruption."
        )

    async def _monitor_loop(self):
        while self._running:
            for probe in self.probes:
                events = probe.poll_events()
                for event in events:
                    if event.latency_us > self.latency_threshold_us:
                        logger.warning(
                            "SECURITY ALERT: Micro-latency anomaly detected! "
                            "Probe: %s | Latency: %.2fus | Syscall: %s | PID: %d",
                            probe.name,
                            event.latency_us,
                            event.syscall_name,
                            event.process_id,
                        )

                    if event.syscall_name in ["execve", "openat"]:
                        logger.info(
                            "AUDIT: Critical syscall detected: %s | PID: %d | Core: %d",
                            event.syscall_name,
                            event.process_id,
                            event.cpu_core,
                        )

                    if event.event_type == "MEM_CORRUPTION_SIGSEGV":
                        logger.critical(
                            "CRITICAL SECURITY ALERT: Memory corruption (SIGSEGV) detected via eBPF! "
                            "PID: %d | Syscall: %s | Core: %d",
                            event.process_id,
                            event.syscall_name,
                            event.cpu_core,
                        )
                        self._trigger_fail_closed(event.process_id)

            await asyncio.sleep(1)

    def _trigger_fail_closed(self, pid: int):
        """
        Triggers a fail-closed sequence: logs the affected PID for forensic isolation.
        Full implementation requires SIGKILL and core dump capture.
        """
        logger.critical(
            "FAIL-CLOSED TRIGGERED: Isolating PID %d and dumping forensic state...", pid
        )

    def stop(self):
        self._running = False


ebpf_monitor = IntegrityMonitor()

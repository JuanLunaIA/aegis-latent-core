# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.attestation_capabilities — honest per-control capability matrix.

After the P0 de-simulation effort the codebase contains **no** simulated security
controls (``tests/test_no_simulation_markers.py`` asserts the debt list is empty).
Many controls, however, depend on hardware or external tooling that is simply not
present in every deployment — a TPM, an SGX/SEV/TDX enclave, ``bpftool``,
``cargo``, ``pip-audit``, ``nftables``. This module reports, per control, whether
it is:

* ``REAL``        — the genuine implementation is active in this environment;
* ``UNAVAILABLE`` — the real implementation exists but its required hardware /
  tool is absent here, so the control does **not** run (it never fakes success);
* ``SIMULATED``   — a stand-in that fabricates assurance. **Nothing should ever
  report this**; the value exists only so an auditor can detect a regression.

The probes here are deliberately cheap and side-effect-free (``shutil.which``,
``os.path.exists``, ``ctypes.util.find_library``, import checks). They never run
the underlying tools, so calling this endpoint cannot extend a PCR, load a BPF
program, or shell out to a fuzzer.
"""

from __future__ import annotations

import ctypes.util
import importlib.util
import os
import shutil
from dataclasses import dataclass
from typing import Literal

CapabilityStatus = Literal["REAL", "UNAVAILABLE", "SIMULATED"]

# Hardware device nodes (kept in sync with the owning modules).
_TEE_DEVICES = ("/dev/sgx_enclave", "/dev/isgx", "/dev/sev", "/dev/tdx_guest")
_TPM_DEVICES = ("/dev/tpm0", "/dev/tpmrm0")
_HUGEPAGES_SYSFS = (
    "/sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages",
    "/sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages",
)


@dataclass(frozen=True)
class ControlCapability:
    """The honest status of a single security control in this environment."""

    name: str
    category: str
    status: CapabilityStatus
    module: str
    detail: str


def _which_any(*names: str) -> str | None:
    for name in names:
        path = shutil.which(name)
        if path is not None:
            return path
    return None


def _exists_any(paths: tuple[str, ...]) -> str | None:
    for path in paths:
        if os.path.exists(path):
            return path
    return None


def _pqc_signing() -> ControlCapability:
    try:
        from aegis.core import pqc_signer

        real = pqc_signer.backend_available()
    except Exception:  # pragma: no cover - import failure path
        real = False
    return ControlCapability(
        name="pqc_signing_ml_dsa_65",
        category="cryptography",
        status="REAL" if real else "UNAVAILABLE",
        module="aegis.core.pqc_signer",
        detail=(
            "ML-DSA-65 (FIPS 204) via the Rust pqcrypto-mldsa backend"
            if real
            else "Rust aegis_rust extension not importable; no simulated fallback exists"
        ),
    )


def _audit_signing() -> ControlCapability:
    # HMAC-SHA256 is stdlib; always genuinely available.
    return ControlCapability(
        name="audit_signing_hmac_sha256",
        category="cryptography",
        status="REAL",
        module="aegis.core.crypto_audit",
        detail="HMAC-SHA256 over the audit chain (Python stdlib hmac/hashlib)",
    )


def _seccomp_sandbox() -> ControlCapability:
    lib = ctypes.util.find_library("seccomp")
    return ControlCapability(
        name="seccomp_syscall_filter",
        category="runtime-isolation",
        status="REAL" if lib else "UNAVAILABLE",
        module="aegis.core.sandbox_l1",
        detail=(
            f"libseccomp present ({lib})"
            if lib
            else "libseccomp not found; syscall filtering cannot be loaded"
        ),
    )


def _tpm_root_of_trust() -> ControlCapability:
    has_tools = _which_any("tpm2_pcrextend", "tpm2_pcrread") is not None
    has_device = _exists_any(_TPM_DEVICES) is not None
    real = has_tools and has_device
    return ControlCapability(
        name="tpm_pcr_root_of_trust",
        category="hardware-root-of-trust",
        status="REAL" if real else "UNAVAILABLE",
        module="aegis.core.tpm",
        detail=(
            "tpm2-tools and a TPM device are present"
            if real
            else "no TPM device and/or tpm2-tools; falls back to a labelled software PCR (not a hardware root of trust)"
        ),
    )


def _tee_enclave() -> ControlCapability:
    device = _exists_any(_TEE_DEVICES)
    return ControlCapability(
        name="tee_enclave_attestation",
        category="hardware-root-of-trust",
        status="REAL" if device else "UNAVAILABLE",
        module="aegis.core.tee_manager",
        detail=(
            f"TEE device present ({device})"
            if device
            else "no SGX/SEV/TDX device; enclave operations raise instead of faking attestation"
        ),
    )


def _ebpf_monitor() -> ControlCapability:
    tool = _which_any("bpftool")
    return ControlCapability(
        name="ebpf_runtime_monitor",
        category="observability",
        status="REAL" if tool else "UNAVAILABLE",
        module="aegis.core.ebpf_monitor",
        detail=(
            f"bpftool present ({tool})"
            if tool
            else "bpftool not found; probes stay inactive and emit no fabricated telemetry"
        ),
    )


def _dpdk_datapath() -> ControlCapability:
    has_hugepages = _exists_any(_HUGEPAGES_SYSFS) is not None
    has_devbind = _which_any("dpdk-devbind", "dpdk-devbind.py") is not None
    real = has_hugepages and has_devbind
    return ControlCapability(
        name="dpdk_kernel_bypass_datapath",
        category="datapath",
        status="REAL" if real else "UNAVAILABLE",
        module="aegis.core.dpdk_engine",
        detail=(
            "hugepages and dpdk-devbind are present"
            if real
            else "hugepages and/or dpdk-devbind absent; no packets are processed (no fake packets)"
        ),
    )


def _firewall_segmentation() -> ControlCapability:
    backend = _which_any("nft", "iptables")
    return ControlCapability(
        name="dynamic_firewall_segmentation",
        category="network-enforcement",
        status="REAL" if backend else "UNAVAILABLE",
        module="aegis.core.xdp_dynamic_segmentation",
        detail=(
            f"kernel firewall backend present ({backend})"
            if backend
            else "no nftables/iptables; blocks are application-layer only (no kernel packet drop)"
        ),
    )


def _cfi_inspection() -> ControlCapability:
    has_pyelftools = importlib.util.find_spec("elftools") is not None
    has_binutils = _which_any("readelf", "nm") is not None
    real = has_pyelftools or has_binutils
    return ControlCapability(
        name="cfi_binary_inspection",
        category="binary-hardening",
        status="REAL" if real else "UNAVAILABLE",
        module="aegis.core.cfi_manager",
        detail=(
            "ELF inspection available (pyelftools and/or readelf/nm)"
            if real
            else "neither pyelftools nor binutils present; cannot inspect CFI"
        ),
    )


def _fuzzing_harness() -> ControlCapability:
    tool = _which_any("cargo")
    return ControlCapability(
        name="fuzzing_harness",
        category="assurance-pipeline",
        status="REAL" if tool else "UNAVAILABLE",
        module="aegis.core.fuzzing_harness",
        detail=(
            f"cargo present ({tool}); cargo-fuzz can run targets"
            if tool
            else "cargo not found; fuzz targets report UNAVAILABLE rather than a fake clean run"
        ),
    )


def _dependency_audit() -> ControlCapability:
    tool = _which_any("pip-audit")
    return ControlCapability(
        name="dependency_cve_audit",
        category="assurance-pipeline",
        status="REAL" if tool else "UNAVAILABLE",
        module="aegis.core.dependency_audit",
        detail=(
            f"pip-audit present ({tool})"
            if tool
            else "pip-audit not found; the scanner raises rather than reporting a fake clean result"
        ),
    )


def _reproducible_build() -> ControlCapability:
    tool = _which_any("cargo")
    return ControlCapability(
        name="reproducible_build_verification",
        category="assurance-pipeline",
        status="REAL" if tool else "UNAVAILABLE",
        module="aegis.core.build_reproducibility",
        detail=(
            f"cargo present ({tool}); bit-for-bit rebuild + SHA-256 supported"
            if tool
            else "cargo not found; reproducible-build verification raises rather than faking a match"
        ),
    )


def _transparency_log() -> ControlCapability:
    # Append-only JSONL ledger uses only stdlib; always genuinely available.
    return ControlCapability(
        name="transparency_log",
        category="assurance-pipeline",
        status="REAL",
        module="aegis.core.transparency_log",
        detail="append-only JSONL ledger with replay-on-init (stdlib json/io)",
    )


# Order is stable for deterministic auditor-facing output.
_PROBES = (
    _pqc_signing,
    _audit_signing,
    _seccomp_sandbox,
    _tpm_root_of_trust,
    _tee_enclave,
    _ebpf_monitor,
    _dpdk_datapath,
    _firewall_segmentation,
    _cfi_inspection,
    _fuzzing_harness,
    _dependency_audit,
    _reproducible_build,
    _transparency_log,
)


def collect_capabilities() -> list[ControlCapability]:
    """Probe every reported control and return its honest status.

    Cheap and side-effect-free: safe to call on every request.
    """
    return [probe() for probe in _PROBES]


def capabilities_summary() -> dict[str, int]:
    """Return counts per status across all reported controls."""
    summary = {"REAL": 0, "UNAVAILABLE": 0, "SIMULATED": 0}
    for cap in collect_capabilities():
        summary[cap.status] += 1
    return summary

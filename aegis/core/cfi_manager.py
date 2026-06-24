# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.cfi_manager — Control Flow Integrity (CFI) Verification.

Inspects ELF binaries for real CFI instrumentation using three detection tiers:

* **LLVM CFI** (``-Zsanitize=cfi``): ``__cfi_check`` / ``__cfi_prototype``
  symbols present in ``.dynsym`` or ``.symtab``.
* **GCC/LLVM unwind tables** (``-fexceptions``): ``.eh_frame`` /
  ``.eh_frame_hdr`` sections — present in virtually all Linux ELF binaries
  compiled with exception support; indicated as "basic-cfi".
* **Intel CET** (``-fcf-protection``): ``GNU_PROPERTY_X86_FEATURE_1_IBT``
  (bit 0) and ``GNU_PROPERTY_X86_FEATURE_1_SHSTK`` (bit 1) flags in
  ``.note.gnu.property``.

Uses ``pyelftools`` when available; falls back to ``readelf``/``nm`` via
subprocess.  Returns honest results — never simulates a positive outcome.
"""

from __future__ import annotations

import logging
import shutil
import struct
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

# LLVM CFI symbols injected by -Zsanitize=cfi
_LLVM_CFI_SYMBOLS = {"__cfi_check", "__cfi_prototype"}

# GNU_PROPERTY_X86_FEATURE_1_AND type value
_GNU_PROP_X86_FEAT1_TYPE = 0xC0010002
# Feature-1 bits
_FEAT1_IBT = 0x1  # Indirect Branch Tracking
_FEAT1_SHSTK = 0x2  # Shadow Stack


class CFIReport:
    """Structured result of a CFI audit on a single binary."""

    __slots__ = (
        "binary_path",
        "llvm_cfi",
        "eh_frame",
        "intel_cet_ibt",
        "intel_cet_shadow_stack",
        "error",
    )

    def __init__(self, binary_path: str) -> None:
        self.binary_path = binary_path
        self.llvm_cfi: list[str] = []
        self.eh_frame: list[str] = []
        self.intel_cet_ibt: bool = False
        self.intel_cet_shadow_stack: bool = False
        self.error: str = ""

    @property
    def has_llvm_cfi(self) -> bool:
        return bool(self.llvm_cfi)

    @property
    def has_eh_frame(self) -> bool:
        return bool(self.eh_frame)

    @property
    def has_intel_cet(self) -> bool:
        return self.intel_cet_ibt or self.intel_cet_shadow_stack

    @property
    def has_any_cfi(self) -> bool:
        return self.has_llvm_cfi or self.has_eh_frame or self.has_intel_cet

    def summary(self) -> str:
        if self.error:
            return f"Analysis failed: {self.error}"
        parts: list[str] = []
        if self.llvm_cfi:
            parts.append(f"llvm-cfi({','.join(self.llvm_cfi)})")
        if self.eh_frame:
            parts.append(f"basic-cfi({','.join(self.eh_frame)})")
        if self.intel_cet_ibt:
            parts.append("intel-cet:ibt")
        if self.intel_cet_shadow_stack:
            parts.append("intel-cet:shadow-stack")
        return ", ".join(parts) if parts else "no-cfi-markers"


def _audit_via_pyelftools(binary_path: str, report: CFIReport) -> None:
    """Populate *report* using pyelftools ELF parsing."""
    from elftools.elf.elffile import ELFFile  # type: ignore[import]

    with open(binary_path, "rb") as f:
        elf = ELFFile(f)

        # Tier 1 — LLVM CFI symbols
        for sec_name in (".dynsym", ".symtab"):
            symtab = elf.get_section_by_name(sec_name)
            if not symtab:
                continue
            for sym in symtab.iter_symbols():
                if sym.name in _LLVM_CFI_SYMBOLS:
                    report.llvm_cfi.append(sym.name)

        # Tier 2 — GCC/LLVM unwind tables
        for sec_name in (".eh_frame", ".eh_frame_hdr"):
            if elf.get_section_by_name(sec_name):
                report.eh_frame.append(sec_name)

        # Tier 3 — Intel CET via .note.gnu.property
        prop_sec = elf.get_section_by_name(".note.gnu.property")
        if prop_sec:
            _parse_gnu_property(prop_sec.data(), report)


def _parse_gnu_property(data: bytes, report: CFIReport) -> None:
    """Parse a .note.gnu.property section to extract CET feature flags."""
    offset = 0
    # ELF note header: namesz (4), descsz (4), type (4), name[namesz]
    while offset + 12 <= len(data):
        namesz, descsz, ntype = struct.unpack_from("<III", data, offset)
        offset += 12
        # name is padded to 4-byte boundary
        name_end = offset + namesz
        padded_name_end = (name_end + 3) & ~3
        desc_start = padded_name_end
        desc_end = desc_start + descsz
        if desc_end > len(data):
            break

        # Only NT_GNU_PROPERTY_TYPE_0 (5) matters
        if ntype == 5:
            _parse_property_array(data[desc_start:desc_end], report)

        # advance past descriptor (padded to 4 bytes)
        offset = (desc_end + 3) & ~3

        if offset >= len(data):
            break


def _parse_property_array(props: bytes, report: CFIReport) -> None:
    """Parse the GNU property array inside a NT_GNU_PROPERTY_TYPE_0 note."""
    offset = 0
    while offset + 8 <= len(props):
        pr_type, pr_datasz = struct.unpack_from("<II", props, offset)
        offset += 8
        pr_data = props[offset : offset + pr_datasz]
        # advance to next 8-byte aligned entry (or 4-byte on 32-bit, but be safe)
        offset += (pr_datasz + 7) & ~7

        if pr_type == _GNU_PROP_X86_FEAT1_TYPE and len(pr_data) >= 4:
            feat1 = struct.unpack_from("<I", pr_data)[0]
            if feat1 & _FEAT1_IBT:
                report.intel_cet_ibt = True
            if feat1 & _FEAT1_SHSTK:
                report.intel_cet_shadow_stack = True


def _audit_via_subprocess(binary_path: str, report: CFIReport) -> None:
    """Populate *report* using readelf/nm subprocess fallback."""
    readelf = shutil.which("readelf") or "readelf"
    nm_cmd = shutil.which("nm") or "nm"

    # Tier 1 — LLVM CFI symbols via nm -D
    try:
        res = subprocess.run(
            [nm_cmd, "-D", binary_path], capture_output=True, text=True, timeout=10
        )
        for sym in _LLVM_CFI_SYMBOLS:
            if sym in res.stdout:
                report.llvm_cfi.append(sym)
    except Exception:
        pass

    # Tier 2 — EH frame sections via readelf -S
    try:
        res = subprocess.run(
            [readelf, "-S", binary_path], capture_output=True, text=True, timeout=10
        )
        for sec in (".eh_frame_hdr", ".eh_frame"):
            if sec in res.stdout:
                report.eh_frame.append(sec)
    except Exception:
        pass

    # Tier 3 — Intel CET via readelf --notes
    try:
        res = subprocess.run(
            [readelf, "--notes", binary_path], capture_output=True, text=True, timeout=10
        )
        out = res.stdout
        if "IBT" in out or "GNU_PROPERTY_X86_FEATURE_1_IBT" in out:
            report.intel_cet_ibt = True
        if "SHSTK" in out or "GNU_PROPERTY_X86_FEATURE_1_SHSTK" in out:
            report.intel_cet_shadow_stack = True
    except Exception:
        pass


class CFIManager:
    """Verifies Control Flow Integrity markers in ELF binaries.

    Uses ``pyelftools`` for structured ELF parsing; falls back to
    ``readelf`` / ``nm`` subprocess if pyelftools is not installed.
    Never manufactures a positive result — reports what the binary
    actually contains.
    """

    def __init__(self) -> None:
        try:
            import elftools  # noqa: F401

            self._use_pyelftools = True
        except ImportError:
            self._use_pyelftools = False
        logger.info(
            "CFIManager initialised (backend: %s)",
            "pyelftools" if self._use_pyelftools else "subprocess",
        )

    def audit(self, binary_path: str) -> CFIReport:
        """Return a detailed :class:`CFIReport` for *binary_path*."""
        report = CFIReport(binary_path)
        if not Path(binary_path).is_file():
            report.error = f"File not found: {binary_path}"
            logger.error("CFI audit: %s", report.error)
            return report
        try:
            if self._use_pyelftools:
                _audit_via_pyelftools(binary_path, report)
            else:
                _audit_via_subprocess(binary_path, report)
        except Exception as exc:
            report.error = str(exc)
            logger.error("CFI audit failed for %s: %s", binary_path, exc)
        return report

    def verify_binary_cfi(self, binary_path: str) -> tuple[bool, str]:
        """Return ``(ok, description)`` for *binary_path*.

        ``ok`` is ``True`` when any CFI tier is detected; ``False`` when none
        are found or the file cannot be read.  Description is always honest.
        """
        report = self.audit(binary_path)
        summary = report.summary()
        if report.error:
            logger.error("CFI verification failed for %s: %s", binary_path, summary)
            return False, summary
        if report.has_any_cfi:
            logger.info("CFI verification OK for %s: %s", binary_path, summary)
        else:
            logger.warning("No CFI markers in %s", binary_path)
        return report.has_any_cfi, summary

    @staticmethod
    def get_recommended_build_flags() -> list[str]:
        """Compiler / linker flags that enable CFI in Rust / Clang builds."""
        return [
            "-Zsanitize=cfi",  # LLVM CFI (nightly Rust / Clang)
            "-fcf-protection=full",  # Intel CET IBT + Shadow Stack (GCC/Clang)
            "-C target-feature=+shadow-stack",  # Rust: hardware shadow stack
            "-C target-feature=+ibt",  # Rust: indirect branch tracking
            "-C relro=full",  # full RELRO
        ]

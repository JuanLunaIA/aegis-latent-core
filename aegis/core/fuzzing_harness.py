"""Evidence-based cargo-fuzz orchestration for declared Rust fuzz targets.

The repository currently ships no cargo-fuzz workspace. Capability therefore
remains unavailable until a private workspace contains a bounded manifest and
every declared regular target file, with both ``cargo`` and ``cargo-fuzz`` on
PATH. No coverage or bug counts are inferred.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import logging
import os
import secrets
import shutil
import stat
import subprocess  # noqa: S404  # nosec B404
import tomllib
from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_MAX_DURATION_SECONDS = 86_400
_MAX_ARTIFACT_FILES = 10_000
_MAX_MANIFEST_BYTES = 1_048_576
_MAX_TARGET_BYTES = 10 * 1024 * 1024
_DEFAULT_FUZZ_DIR = Path(__file__).resolve().parents[2] / "aegis_rust_v2" / "fuzz"
_EXPECTED_TARGETS = frozenset({"ledger_commit", "mmr_append", "pqc_sign_verify"})


class FuzzRunStatus(StrEnum):
    NOT_RUN = "NOT_RUN"
    CLEAN = "CLEAN"
    CRASH_FOUND = "CRASH_FOUND"
    TOOL_ERROR = "TOOL_ERROR"
    TIMEOUT = "TIMEOUT"
    UNAVAILABLE = "UNAVAILABLE"


@dataclass
class FuzzTarget:
    name: str
    module: str
    function: str
    description: str
    last_run_status: FuzzRunStatus = FuzzRunStatus.NOT_RUN


def _trusted_workspace(fuzz_dir: Path) -> tuple[Path | None, str | None]:
    """Resolve a workspace that other local users cannot replace or mutate."""
    if fuzz_dir.is_symlink():
        return None, "fuzz workspace must not be a symlink"
    try:
        workspace = fuzz_dir.resolve(strict=True)
        info = workspace.stat()
    except OSError:
        return None, "fuzz workspace is missing or unreadable"
    if not workspace.is_dir():
        return None, "fuzz workspace is not a directory"
    if stat.S_IMODE(info.st_mode) & 0o022:
        return None, "fuzz workspace must not be group- or world-writable"
    return workspace, None


def _manifest_targets(manifest_path: Path) -> dict[str, str] | None:
    """Read unique target names and paths from one bounded regular manifest."""
    try:
        if manifest_path.is_symlink() or not manifest_path.is_file():
            return None
        if manifest_path.stat().st_size > _MAX_MANIFEST_BYTES:
            return None
        with manifest_path.open("rb") as handle:
            document = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return None
    bins = document.get("bin", [])
    if not isinstance(bins, list):
        return None
    targets: dict[str, str] = {}
    for entry in bins:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        path = entry.get("path")
        if not isinstance(name, str) or not isinstance(path, str) or name in targets:
            return None
        targets[name] = path
    return targets


def _confined_regular_file(workspace: Path, relative_path: str) -> Path | None:
    """Resolve one non-symlink regular file beneath ``workspace``."""
    requested = Path(relative_path)
    if requested.is_absolute() or not requested.parts or ".." in requested.parts:
        return None
    cursor = workspace
    for part in requested.parts:
        cursor /= part
        if cursor.is_symlink():
            return None
    try:
        target = cursor.resolve(strict=True)
        target.relative_to(workspace)
        size = target.stat().st_size
    except (OSError, ValueError):
        return None
    if not target.is_file() or size > _MAX_TARGET_BYTES:
        return None
    return target


def fuzzing_toolchain_status(
    fuzz_dir: Path = _DEFAULT_FUZZ_DIR,
    *,
    expected_targets: frozenset[str] = _EXPECTED_TARGETS,
) -> tuple[bool, str]:
    """Check executables, manifest declarations, and confined target source files."""
    if shutil.which("cargo") is None or shutil.which("cargo-fuzz") is None:
        return False, "cargo and cargo-fuzz executables are both required"
    workspace, error = _trusted_workspace(fuzz_dir)
    if workspace is None:
        return False, error or "fuzz workspace is unavailable"
    declared = _manifest_targets(workspace / "Cargo.toml")
    if declared is None:
        return False, "fuzz manifest is missing, malformed, duplicated, oversized, or a symlink"
    missing = sorted(expected_targets - declared.keys())
    if missing:
        return False, f"fuzz manifest is missing declared targets: {', '.join(missing)}"
    invalid = sorted(
        name
        for name in expected_targets
        if _confined_regular_file(workspace, declared[name]) is None
    )
    if invalid:
        return False, (
            "fuzz targets are missing, oversized, symlinked, or unconfined: " + ", ".join(invalid)
        )
    return True, f"cargo-fuzz workspace contains {len(expected_targets)} required target files"


class AegisFuzzingEngine:
    """Run bounded cargo-fuzz targets only after evidence-based readiness checks."""

    def __init__(self, *, fuzz_dir: Path = _DEFAULT_FUZZ_DIR) -> None:
        self.fuzz_dir = fuzz_dir.expanduser().absolute()
        self.targets: list[FuzzTarget] = [
            FuzzTarget(
                name="ledger_commit",
                module="aegis_rust::ledger",
                function="commit_state",
                description="Planned ledger framing target; not shipped until present in fuzz/Cargo.toml.",
            ),
            FuzzTarget(
                name="mmr_append",
                module="aegis_rust::mmr",
                function="add_leaf",
                description="Planned MMR append target; not shipped until present in fuzz/Cargo.toml.",
            ),
            FuzzTarget(
                name="pqc_sign_verify",
                module="aegis_rust::pqc",
                function="verify_pqc_signature",
                description="Planned PQC verify target; not shipped until present in fuzz/Cargo.toml.",
            ),
        ]

    def _target(self, target_name: str) -> FuzzTarget | None:
        return next((target for target in self.targets if target.name == target_name), None)

    @staticmethod
    def _validate_duration(duration_seconds: int) -> None:
        if isinstance(duration_seconds, bool) or not isinstance(duration_seconds, int):
            raise TypeError("duration_seconds must be an integer")
        if not 1 <= duration_seconds <= _MAX_DURATION_SECONDS:
            raise ValueError(f"duration_seconds must be between 1 and {_MAX_DURATION_SECONDS}")

    @staticmethod
    def _artifact_state(path: Path) -> dict[str, tuple[int, int]]:
        state: dict[str, tuple[int, int]] = {}
        for entry in path.iterdir():
            if entry.is_symlink():
                raise RuntimeError("fuzz artifact directory contains a symlink")
            if entry.is_file():
                info = entry.stat()
                state[entry.name] = (info.st_size, info.st_mtime_ns)
                if len(state) > _MAX_ARTIFACT_FILES:
                    raise RuntimeError("fuzz artifact directory exceeds the file-count bound")
        return state

    @staticmethod
    def _prepare_artifact_dir(
        workspace: Path, target: FuzzTarget
    ) -> tuple[Path, tuple[int, int], Path, bytes] | None:
        """Create a confined artifact directory with a per-run identity sentinel."""
        artifact_root = workspace / "artifacts"
        if artifact_root.is_symlink():
            return None
        artifact_root.mkdir(mode=0o700, parents=False, exist_ok=True)
        if artifact_root.is_symlink() or not artifact_root.is_dir():
            return None
        artifact_dir = artifact_root / target.name
        if artifact_dir.is_symlink():
            return None
        artifact_dir.mkdir(mode=0o700, parents=False, exist_ok=True)
        if artifact_dir.is_symlink() or not artifact_dir.is_dir():
            return None
        try:
            resolved = artifact_dir.resolve(strict=True)
            resolved.relative_to(workspace)
            info = resolved.stat()
        except (OSError, ValueError):
            return None
        if stat.S_IMODE(info.st_mode) & 0o022:
            return None
        sentinel_token = secrets.token_bytes(32)
        sentinel = resolved / f".aegis-run-{secrets.token_hex(16)}"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(sentinel, flags, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(sentinel_token)
        except OSError:
            return None
        return (
            resolved,
            (info.st_dev, info.st_ino),
            sentinel,
            sentinel_token,
        )

    def run_target(self, target_name: str, duration_seconds: int = 3600) -> bool:
        """Run one bounded target and return true only for a clean execution."""
        self._validate_duration(duration_seconds)
        target = self._target(target_name)
        if target is None:
            logger.error("Fuzz target %s is not declared", target_name)
            return False

        ready, _detail = fuzzing_toolchain_status(self.fuzz_dir)
        workspace, _error = _trusted_workspace(self.fuzz_dir)
        if not ready or workspace is None:
            target.last_run_status = FuzzRunStatus.UNAVAILABLE
            logger.warning("Fuzzing unavailable after readiness checks")
            return False

        prepared = self._prepare_artifact_dir(workspace, target)
        if prepared is None:
            target.last_run_status = FuzzRunStatus.TOOL_ERROR
            logger.error("fuzz artifact directory is unsafe or escapes the configured workspace")
            return False
        artifact_dir, artifact_identity, sentinel, sentinel_token = prepared
        try:
            before = self._artifact_state(artifact_dir)
            cmd = [
                "cargo",
                "fuzz",
                "run",
                target.name,
                "--",
                f"-max_total_time={duration_seconds}",
                f"-artifact_prefix={artifact_dir.as_posix()}/",
            ]
            try:
                result = subprocess.run(  # noqa: S603  # nosec B603
                    cmd,
                    cwd=workspace,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=duration_seconds + 30,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                target.last_run_status = FuzzRunStatus.TIMEOUT
                return False
            except (FileNotFoundError, OSError) as exc:
                target.last_run_status = FuzzRunStatus.UNAVAILABLE
                logger.warning("cargo-fuzz execution unavailable: %s", type(exc).__name__)
                return False

            current = artifact_dir.stat()
            if (current.st_dev, current.st_ino) != artifact_identity:
                raise RuntimeError("fuzz artifact directory identity changed")
            if sentinel.read_bytes() != sentinel_token:
                raise RuntimeError("fuzz artifact directory sentinel changed")
            after = self._artifact_state(artifact_dir)
        except (OSError, RuntimeError):
            target.last_run_status = FuzzRunStatus.TOOL_ERROR
            return False
        finally:
            sentinel.unlink(missing_ok=True)
        if after != before:
            target.last_run_status = FuzzRunStatus.CRASH_FOUND
            return False
        if result.returncode != 0:
            target.last_run_status = FuzzRunStatus.TOOL_ERROR
            return False
        target.last_run_status = FuzzRunStatus.CLEAN
        return True

    def get_coverage_report(self) -> dict[str, Any]:
        """Return observed run states; measured coverage remains unavailable."""
        states = [target.last_run_status for target in self.targets]
        if all(state is FuzzRunStatus.NOT_RUN for state in states):
            status = "NOT_RUN"
        elif all(state is FuzzRunStatus.CLEAN for state in states):
            status = "COMPLETE"
        else:
            status = "PARTIAL"
        return {
            "status": status,
            "measured_coverage": None,
            "edge_cases_found": None,
            "critical_bugs_fixed": None,
            "targets": [asdict(target) for target in self.targets],
        }


__all__ = [
    "AegisFuzzingEngine",
    "FuzzRunStatus",
    "FuzzTarget",
    "fuzzing_toolchain_status",
]

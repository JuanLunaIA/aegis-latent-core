# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Deterministic tests for evidence-based cargo-fuzz orchestration."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from aegis.core.fuzzing_harness import (
    AegisFuzzingEngine,
    FuzzRunStatus,
    fuzzing_toolchain_status,
)


def _write_manifest(path: Path, names: tuple[str, ...] = ()) -> None:
    path.mkdir(parents=True, exist_ok=True)
    target_dir = path / "fuzz_targets"
    target_dir.mkdir(exist_ok=True)
    for name in names:
        (target_dir / f"{name}.rs").write_text("#![no_main]\n", encoding="utf-8")
    entries = "\n".join(
        f'[[bin]]\nname = "{name}"\npath = "fuzz_targets/{name}.rs"' for name in names
    )
    (path / "Cargo.toml").write_text(
        f'[package]\nname = "aegis-fuzz"\nversion = "0.0.0"\n{entries}\n',
        encoding="utf-8",
    )


def _tool(name: str) -> str | None:
    return f"/usr/bin/{name}" if name in {"cargo", "cargo-fuzz"} else None


def test_toolchain_requires_both_executables(tmp_path: Path) -> None:
    with patch("aegis.core.fuzzing_harness.shutil.which", return_value=None):
        ready, detail = fuzzing_toolchain_status(tmp_path)
    assert ready is False
    assert "both required" in detail


def test_toolchain_requires_manifest_and_every_target(tmp_path: Path) -> None:
    _write_manifest(tmp_path, ("mmr_append",))
    with patch("aegis.core.fuzzing_harness.shutil.which", side_effect=_tool):
        ready, detail = fuzzing_toolchain_status(tmp_path)
    assert ready is False
    assert "ledger_commit" in detail
    assert "pqc_sign_verify" in detail


def test_toolchain_ready_only_for_complete_manifest(tmp_path: Path) -> None:
    _write_manifest(tmp_path, ("ledger_commit", "mmr_append", "pqc_sign_verify"))
    with patch("aegis.core.fuzzing_harness.shutil.which", side_effect=_tool):
        ready, detail = fuzzing_toolchain_status(tmp_path)
    assert ready is True
    assert "3 required target files" in detail


def test_toolchain_rejects_declared_missing_target_file(tmp_path: Path) -> None:
    names = ("ledger_commit", "mmr_append", "pqc_sign_verify")
    _write_manifest(tmp_path, names)
    (tmp_path / "fuzz_targets" / "mmr_append.rs").unlink()
    with patch("aegis.core.fuzzing_harness.shutil.which", side_effect=_tool):
        ready, detail = fuzzing_toolchain_status(tmp_path)
    assert ready is False
    assert "mmr_append" in detail


def test_toolchain_rejects_symlinked_target_file(tmp_path: Path) -> None:
    names = ("ledger_commit", "mmr_append", "pqc_sign_verify")
    _write_manifest(tmp_path, names)
    outside = tmp_path.parent / "outside-fuzz-target.rs"
    outside.write_text("#![no_main]\n", encoding="utf-8")
    target = tmp_path / "fuzz_targets" / "mmr_append.rs"
    target.unlink()
    target.symlink_to(outside)
    with patch("aegis.core.fuzzing_harness.shutil.which", side_effect=_tool):
        ready, detail = fuzzing_toolchain_status(tmp_path)
    assert ready is False
    assert "symlinked" in detail


def test_toolchain_rejects_world_writable_workspace(tmp_path: Path) -> None:
    _write_manifest(tmp_path, ("ledger_commit", "mmr_append", "pqc_sign_verify"))
    tmp_path.chmod(0o777)
    try:
        with patch("aegis.core.fuzzing_harness.shutil.which", side_effect=_tool):
            ready, detail = fuzzing_toolchain_status(tmp_path)
    finally:
        tmp_path.chmod(0o700)
    assert ready is False
    assert "world-writable" in detail


@pytest.mark.parametrize("duration", [True, 0, -1, 86_401, 1.5])
def test_duration_is_bounded_before_tool_execution(tmp_path: Path, duration: object) -> None:
    engine = AegisFuzzingEngine(fuzz_dir=tmp_path)
    with pytest.raises((TypeError, ValueError)):
        engine.run_target("mmr_append", duration)  # type: ignore[arg-type]


def test_unknown_target_returns_false_without_mutating_status(tmp_path: Path) -> None:
    engine = AegisFuzzingEngine(fuzz_dir=tmp_path)
    assert engine.run_target("unknown", 1) is False
    assert all(target.last_run_status is FuzzRunStatus.NOT_RUN for target in engine.targets)


def test_unready_target_is_unavailable(tmp_path: Path) -> None:
    engine = AegisFuzzingEngine(fuzz_dir=tmp_path)
    with patch("aegis.core.fuzzing_harness.shutil.which", return_value=None):
        assert engine.run_target("mmr_append", 1) is False
    target = next(target for target in engine.targets if target.name == "mmr_append")
    assert target.last_run_status is FuzzRunStatus.UNAVAILABLE


def _ready_engine(tmp_path: Path) -> AegisFuzzingEngine:
    _write_manifest(tmp_path, ("ledger_commit", "mmr_append", "pqc_sign_verify"))
    return AegisFuzzingEngine(fuzz_dir=tmp_path)


def test_clean_run_uses_explicit_cwd_timeout_and_returns_true(tmp_path: Path) -> None:
    engine = _ready_engine(tmp_path)
    captured: dict[str, object] = {}

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        captured["command"] = command
        captured.update(kwargs)
        return subprocess.CompletedProcess(command, 0)

    with (
        patch("aegis.core.fuzzing_harness.shutil.which", side_effect=_tool),
        patch("aegis.core.fuzzing_harness.subprocess.run", side_effect=fake_run),
    ):
        assert engine.run_target("mmr_append", 60) is True

    target = next(target for target in engine.targets if target.name == "mmr_append")
    assert target.last_run_status is FuzzRunStatus.CLEAN
    assert captured["cwd"] == tmp_path.resolve()
    assert captured["timeout"] == 90
    assert "-max_total_time=60" in captured["command"]  # type: ignore[operator]


def test_nonzero_without_new_artifact_is_tool_error(tmp_path: Path) -> None:
    engine = _ready_engine(tmp_path)
    with (
        patch("aegis.core.fuzzing_harness.shutil.which", side_effect=_tool),
        patch(
            "aegis.core.fuzzing_harness.subprocess.run",
            return_value=subprocess.CompletedProcess([], 1),
        ),
    ):
        assert engine.run_target("ledger_commit", 1) is False
    target = next(target for target in engine.targets if target.name == "ledger_commit")
    assert target.last_run_status is FuzzRunStatus.TOOL_ERROR


def test_new_artifact_is_crash_and_never_success(tmp_path: Path) -> None:
    engine = _ready_engine(tmp_path)

    def create_crash(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        artifact_dir = tmp_path / "artifacts" / "pqc_sign_verify"
        (artifact_dir / "crash-deadbeef").write_bytes(b"input")
        return subprocess.CompletedProcess([], 77)

    with (
        patch("aegis.core.fuzzing_harness.shutil.which", side_effect=_tool),
        patch("aegis.core.fuzzing_harness.subprocess.run", side_effect=create_crash),
    ):
        assert engine.run_target("pqc_sign_verify", 1) is False
    target = next(target for target in engine.targets if target.name == "pqc_sign_verify")
    assert target.last_run_status is FuzzRunStatus.CRASH_FOUND


def test_timeout_is_distinct_failure(tmp_path: Path) -> None:
    engine = _ready_engine(tmp_path)
    with (
        patch("aegis.core.fuzzing_harness.shutil.which", side_effect=_tool),
        patch(
            "aegis.core.fuzzing_harness.subprocess.run",
            side_effect=subprocess.TimeoutExpired(["cargo"], 31),
        ),
    ):
        assert engine.run_target("mmr_append", 1) is False
    target = next(target for target in engine.targets if target.name == "mmr_append")
    assert target.last_run_status is FuzzRunStatus.TIMEOUT


def test_symlinked_artifact_root_is_rejected(tmp_path: Path) -> None:
    engine = _ready_engine(tmp_path)
    outside = tmp_path.parent / "outside-artifacts"
    outside.mkdir(exist_ok=True)
    (tmp_path / "artifacts").symlink_to(outside, target_is_directory=True)
    with patch("aegis.core.fuzzing_harness.shutil.which", side_effect=_tool):
        assert engine.run_target("mmr_append", 1) is False
    target = next(target for target in engine.targets if target.name == "mmr_append")
    assert target.last_run_status is FuzzRunStatus.TOOL_ERROR


def test_artifact_directory_identity_change_is_tool_error(tmp_path: Path) -> None:
    engine = _ready_engine(tmp_path)

    def replace_directory(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        artifact_dir = tmp_path / "artifacts" / "ledger_commit"
        artifact_dir.rename(tmp_path / "artifacts" / "ledger_commit-displaced")
        artifact_dir.mkdir(mode=0o700)
        return subprocess.CompletedProcess([], 0)

    with (
        patch("aegis.core.fuzzing_harness.shutil.which", side_effect=_tool),
        patch("aegis.core.fuzzing_harness.subprocess.run", side_effect=replace_directory),
    ):
        assert engine.run_target("ledger_commit", 1) is False
    target = next(target for target in engine.targets if target.name == "ledger_commit")
    assert target.last_run_status is FuzzRunStatus.TOOL_ERROR


def test_report_contains_states_but_no_fabricated_metrics(tmp_path: Path) -> None:
    report = AegisFuzzingEngine(fuzz_dir=tmp_path).get_coverage_report()
    assert report["status"] == "NOT_RUN"
    assert report["measured_coverage"] is None
    assert report["edge_cases_found"] is None
    assert report["critical_bugs_fixed"] is None
    assert {entry["last_run_status"] for entry in report["targets"]} == {"NOT_RUN"}

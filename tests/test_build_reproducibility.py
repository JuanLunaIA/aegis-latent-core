# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.build_reproducibility — ReproducibleBuildEngine."""

from __future__ import annotations

import hashlib
import json
import os
from subprocess import CompletedProcess
from unittest.mock import MagicMock, patch

import pytest

from aegis.core.build_reproducibility import BuildArtifact, ReproducibleBuildEngine


def _make_cp(returncode: int, stdout: str = "", stderr: str = "") -> CompletedProcess:
    cp = MagicMock(spec=CompletedProcess)
    cp.returncode = returncode
    cp.stdout = stdout
    cp.stderr = stderr
    return cp


class TestReproducibleBuildEngineInit:
    def test_default_build_root_is_cwd(self):
        engine = ReproducibleBuildEngine()
        from pathlib import Path

        assert engine.build_root == Path(".")

    def test_custom_build_root(self, tmp_path):
        engine = ReproducibleBuildEngine(build_root=tmp_path)
        assert engine.build_root == tmp_path


class TestCreateHermeticEnvironment:
    def test_sets_source_date_epoch(self):
        engine = ReproducibleBuildEngine()
        env_backup = os.environ.pop("SOURCE_DATE_EPOCH", None)
        try:
            with patch("aegis.core.build_reproducibility.shutil.which", return_value=None):
                result = engine.create_hermetic_environment()
            assert os.environ.get("SOURCE_DATE_EPOCH") == "1716854400"
            assert result is True
        finally:
            if env_backup is None:
                os.environ.pop("SOURCE_DATE_EPOCH", None)
            else:
                os.environ["SOURCE_DATE_EPOCH"] = env_backup

    def test_returns_true_without_cargo(self):
        engine = ReproducibleBuildEngine()
        with patch("aegis.core.build_reproducibility.shutil.which", return_value=None):
            result = engine.create_hermetic_environment()
        assert result is True

    def test_runs_cargo_clean_when_manifest_exists(self, tmp_path):
        (tmp_path / "Cargo.toml").touch()
        engine = ReproducibleBuildEngine(build_root=tmp_path)
        captured = []

        def fake_run(cmd, **kwargs):
            captured.append(cmd)
            return _make_cp(0)

        with (
            patch("aegis.core.build_reproducibility.shutil.which", return_value="/usr/bin/cargo"),
            patch("aegis.core.build_reproducibility.subprocess.run", side_effect=fake_run),
        ):
            engine.create_hermetic_environment()

        assert any("clean" in cmd for cmd in captured)

    def test_skips_cargo_clean_when_manifest_absent(self, tmp_path):
        engine = ReproducibleBuildEngine(build_root=tmp_path)
        captured = []

        def fake_run(cmd, **kwargs):
            captured.append(cmd)
            return _make_cp(0)

        with (
            patch("aegis.core.build_reproducibility.shutil.which", return_value="/usr/bin/cargo"),
            patch("aegis.core.build_reproducibility.subprocess.run", side_effect=fake_run),
        ):
            engine.create_hermetic_environment()

        assert not any("clean" in " ".join(cmd) for cmd in captured)


class TestBuildAndHash:
    def test_raises_when_cargo_absent(self, tmp_path):
        engine = ReproducibleBuildEngine(build_root=tmp_path)
        with patch("aegis.core.build_reproducibility.shutil.which", return_value=None):
            with pytest.raises(RuntimeError, match="cargo not found"):
                engine.build_and_hash("my_binary")

    def test_raises_on_cargo_build_failure(self, tmp_path):
        engine = ReproducibleBuildEngine(build_root=tmp_path)

        def fake_run(cmd, **kwargs):
            if "build" in cmd:
                return _make_cp(1, stderr="error: could not compile")
            return _make_cp(0)

        with (
            patch("aegis.core.build_reproducibility.shutil.which", return_value="/usr/bin/cargo"),
            patch("aegis.core.build_reproducibility.subprocess.run", side_effect=fake_run),
        ):
            with pytest.raises(RuntimeError, match="cargo build failed"):
                engine.build_and_hash("my_binary")

    def test_raises_when_binary_not_found(self, tmp_path):
        engine = ReproducibleBuildEngine(build_root=tmp_path)

        def fake_run(cmd, **kwargs):
            return _make_cp(0, stdout="rustc 1.80.0")

        with (
            patch("aegis.core.build_reproducibility.shutil.which", return_value="/usr/bin/cargo"),
            patch("aegis.core.build_reproducibility.subprocess.run", side_effect=fake_run),
        ):
            with pytest.raises(FileNotFoundError):
                engine.build_and_hash("missing_binary")

    def test_returns_build_artifact_with_real_hash(self, tmp_path):
        (tmp_path / "target" / "release").mkdir(parents=True)
        binary = tmp_path / "target" / "release" / "my_binary"
        binary_content = b"fake-elf-content"
        binary.write_bytes(binary_content)
        expected_hash = hashlib.sha256(binary_content).hexdigest()

        engine = ReproducibleBuildEngine(build_root=tmp_path)

        def fake_run(cmd, **kwargs):
            return _make_cp(0, stdout="rustc 1.80.0")

        with (
            patch("aegis.core.build_reproducibility.shutil.which", return_value="/usr/bin/cargo"),
            patch("aegis.core.build_reproducibility.subprocess.run", side_effect=fake_run),
        ):
            artifact = engine.build_and_hash("my_binary")

        assert artifact.sha256 == expected_hash

    def test_artifact_binary_path_points_to_release_dir(self, tmp_path):
        (tmp_path / "target" / "release").mkdir(parents=True)
        binary = tmp_path / "target" / "release" / "aegis"
        binary.write_bytes(b"content")

        engine = ReproducibleBuildEngine(build_root=tmp_path)

        def fake_run(cmd, **kwargs):
            return _make_cp(0, stdout="rustc 1.80.0")

        with (
            patch("aegis.core.build_reproducibility.shutil.which", return_value="/usr/bin/cargo"),
            patch("aegis.core.build_reproducibility.subprocess.run", side_effect=fake_run),
        ):
            artifact = engine.build_and_hash("aegis")

        assert "target/release/aegis" in artifact.binary_path

    def test_env_snapshot_contains_compiler(self, tmp_path):
        (tmp_path / "target" / "release").mkdir(parents=True)
        (tmp_path / "target" / "release" / "aegis").write_bytes(b"content")

        engine = ReproducibleBuildEngine(build_root=tmp_path)

        def fake_run(cmd, **kwargs):
            return _make_cp(0, stdout="rustc 1.80.0 (2024)")

        with (
            patch("aegis.core.build_reproducibility.shutil.which", return_value="/usr/bin/cargo"),
            patch("aegis.core.build_reproducibility.subprocess.run", side_effect=fake_run),
        ):
            artifact = engine.build_and_hash("aegis")

        env = json.loads(artifact.build_env)
        assert "compiler" in env
        assert "rustc" in env["compiler"]

    def test_cargo_build_called_with_release_and_locked(self, tmp_path):
        (tmp_path / "target" / "release").mkdir(parents=True)
        (tmp_path / "target" / "release" / "bin").write_bytes(b"content")

        engine = ReproducibleBuildEngine(build_root=tmp_path)
        captured = []

        def fake_run(cmd, **kwargs):
            captured.append(cmd)
            return _make_cp(0, stdout="rustc 1.80.0")

        with (
            patch("aegis.core.build_reproducibility.shutil.which", return_value="/usr/bin/cargo"),
            patch("aegis.core.build_reproducibility.subprocess.run", side_effect=fake_run),
        ):
            engine.build_and_hash("bin")

        build_cmd = next(c for c in captured if "build" in c)
        assert "--release" in build_cmd
        assert "--locked" in build_cmd


class TestVerifyReproducibility:
    def _artifact(self, sha256: str) -> BuildArtifact:
        return BuildArtifact(binary_path="/bin/a", sha256=sha256, build_env="{}", timestamp=0.0)

    def test_matching_hashes_returns_true(self):
        engine = ReproducibleBuildEngine()
        a = self._artifact("abc123")
        b = self._artifact("abc123")
        assert engine.verify_reproducibility(a, b) is True

    def test_differing_hashes_returns_false(self):
        engine = ReproducibleBuildEngine()
        a = self._artifact("abc123")
        b = self._artifact("def456")
        assert engine.verify_reproducibility(a, b) is False

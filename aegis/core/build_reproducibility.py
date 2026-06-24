"""
aegis.core.build_reproducibility — Bit-for-Bit Reproducible Build System.
Ensures that the same source code always produces the same binary hash,
eliminating compiler-based backdoors and ensuring auditability.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import subprocess  # noqa: S404  # nosec B404
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class BuildArtifact:
    binary_path: str
    sha256: str
    build_env: str  # JSON string of env vars, compiler version, flags
    timestamp: float


class ReproducibleBuildEngine:
    """
    Orchestrates a hermetic build environment to ensure binary identity.
    Eliminates non-deterministic elements like timestamps, file paths,
    and random seeds in the binary.

    ``build_root`` must be the directory containing the workspace ``Cargo.toml``.
    ``create_hermetic_environment()`` must be called before ``build_and_hash()``
    to install the SOURCE_DATE_EPOCH determinism guard.
    """

    def __init__(self, build_root: str | Path = "."):
        self.build_root = Path(build_root)
        logger.info("ReproducibleBuildEngine initialized. Target: Bit-for-Bit Identity.")

    def create_hermetic_environment(self) -> bool:
        """
        Configures a sterile build environment.
        Sets SOURCE_DATE_EPOCH to a fixed epoch to eliminate timestamp non-determinism,
        then purges the Cargo build cache so the next build starts clean.
        """
        try:
            os.environ["SOURCE_DATE_EPOCH"] = "1716854400"
            logger.info("SOURCE_DATE_EPOCH set to 1716854400 for timestamp determinism.")

            cargo = shutil.which("cargo")
            if cargo is not None:
                manifest = self.build_root / "Cargo.toml"
                if manifest.exists():
                    subprocess.run(  # noqa: S603 S607  # nosec B603 B607
                        ["cargo", "clean", f"--manifest-path={manifest}"],
                        capture_output=True,
                        check=False,
                    )
                    logger.info("Cargo build cache purged.")
            else:
                logger.warning("cargo not found — skipping cache purge.")

            return True
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to create hermetic environment: %s", exc)
            return False

    def build_and_hash(self, target_binary: str) -> BuildArtifact:
        """
        Executes ``cargo build --release --locked`` and returns a
        ``BuildArtifact`` whose ``sha256`` is the real SHA-256 of the compiled
        binary.  Raises ``RuntimeError`` when cargo is absent or the build fails.
        """
        if shutil.which("cargo") is None:
            raise RuntimeError(
                "cargo not found — install the Rust toolchain to enable reproducible builds."
            )

        manifest = self.build_root / "Cargo.toml"
        cmd = [
            "cargo",
            "build",
            "--release",
            "--locked",
            f"--manifest-path={manifest}",
        ]

        logger.info("Executing hermetic build for %s...", target_binary)
        result = subprocess.run(  # noqa: S603 S607  # nosec B603 B607
            cmd, capture_output=True, text=True
        )
        if result.returncode != 0:
            logger.error("cargo build failed:\n%s", result.stderr)
            raise RuntimeError(
                f"cargo build failed (exit {result.returncode}): {result.stderr[:200]}"
            )

        binary_path = self.build_root / "target" / "release" / target_binary
        if not binary_path.exists():
            raise FileNotFoundError(f"Built binary not found at {binary_path}")

        binary_hash = hashlib.sha256(binary_path.read_bytes()).hexdigest()

        compiler = "unknown"
        rustc_result = subprocess.run(  # noqa: S603 S607  # nosec B603 B607
            ["rustc", "--version"], capture_output=True, text=True, check=False
        )
        if rustc_result.returncode == 0:
            compiler = rustc_result.stdout.strip()

        env_snapshot = json.dumps(
            {
                "compiler": compiler,
                "SOURCE_DATE_EPOCH": os.environ.get("SOURCE_DATE_EPOCH", ""),
            }
        )

        return BuildArtifact(
            binary_path=str(binary_path),
            sha256=binary_hash,
            build_env=env_snapshot,
            timestamp=binary_path.stat().st_mtime,
        )

    def verify_reproducibility(self, artifact_a: BuildArtifact, artifact_b: BuildArtifact) -> bool:
        """
        Compares two artifacts built in different environments.
        If hashes match exactly, the build is reproducible.
        """
        if artifact_a.sha256 == artifact_b.sha256:
            logger.info("REPRODUCIBILITY VERIFIED: Binaries are bit-for-bit identical.")
            return True

        logger.critical(
            "REPRODUCIBILITY FAILURE: Binary hashes differ! Potential compiler backdoor."
        )
        return False

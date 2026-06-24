# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Air-gapped Docker image static-analysis tests.

Validates that deploy/docker/Dockerfile.airgap enforces the
IEC 62443 §1.3 air-gap requirement: all layers vendored, zero external
registry pulls or PyPI access at build time.

These are static-analysis (Dockerfile lint) tests — they never call the
Docker daemon and run on any POSIX system, including CI without Docker.
"""

from __future__ import annotations

import re
import stat
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
DOCKERFILE_AIRGAP = REPO_ROOT / "deploy" / "docker" / "Dockerfile.airgap"
DOCKERFILE_STANDARD = REPO_ROOT / "deploy" / "docker" / "Dockerfile"
VENDOR_SCRIPT = REPO_ROOT / "scripts" / "vendor_wheels.sh"


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def airgap_lines() -> list[str]:
    return DOCKERFILE_AIRGAP.read_text().splitlines()


@pytest.fixture(scope="module")
def airgap_content() -> str:
    return DOCKERFILE_AIRGAP.read_text()


# ── Existence ─────────────────────────────────────────────────────────────────


class TestAirgapDockerfileExists:
    def test_airgap_dockerfile_present(self):
        assert DOCKERFILE_AIRGAP.exists(), (
            f"Air-gapped Dockerfile not found at {DOCKERFILE_AIRGAP}"
        )

    def test_vendor_script_present(self):
        assert VENDOR_SCRIPT.exists(), (
            f"Vendor wheels script not found at {VENDOR_SCRIPT}"
        )

    def test_vendor_script_executable(self):
        mode = VENDOR_SCRIPT.stat().st_mode
        assert bool(mode & stat.S_IXUSR), (
            f"{VENDOR_SCRIPT} is not executable"
        )

    def test_standard_dockerfile_still_present(self):
        assert DOCKERFILE_STANDARD.exists(), (
            "Standard Dockerfile was removed; it must coexist with the air-gapped variant"
        )


# ── Digest pinning ────────────────────────────────────────────────────────────


class TestDigestPinning:
    """Base image must be pinned to a sha256 digest, not a floating tag.

    Floating tags (python:3.11-slim) pull whatever Docker Hub serves at build
    time — non-deterministic and allows silent layer substitution.  A digest
    pin (python:3.11-slim@sha256:...) makes the exact layer content auditable.
    """

    def test_from_uses_sha256_digest(self, airgap_content: str):
        from_lines = [
            line for line in airgap_content.splitlines()
            if line.strip().upper().startswith("FROM") and "AS builder" not in line.upper()
            or (line.strip().upper().startswith("FROM") and "AS builder" in line.upper())
        ]
        # At least one FROM must contain @sha256:
        digest_pins = [l for l in from_lines if "@sha256:" in l or "${PYTHON_BASE_DIGEST}" in l]
        assert len(digest_pins) >= 1, (
            "Air-gapped Dockerfile must pin the base image with @sha256: or "
            "via ARG PYTHON_BASE_DIGEST — floating tags not allowed"
        )

    def test_has_arg_for_digest(self, airgap_content: str):
        assert "ARG PYTHON_BASE_DIGEST" in airgap_content, (
            "Dockerfile.airgap must declare ARG PYTHON_BASE_DIGEST so the "
            "exact digest is parameterised and auditable"
        )

    def test_no_floating_from_without_digest(self, airgap_lines: list[str]):
        floating_from = re.compile(
            r"^\s*FROM\s+(python|ubuntu|debian|alpine):\S+",
            re.IGNORECASE,
        )
        pinned = re.compile(r"@sha256:|@\$\{")
        for line in airgap_lines:
            if floating_from.match(line) and not pinned.search(line):
                pytest.fail(
                    f"Floating FROM tag detected (no @sha256 digest): {line.strip()!r}"
                )

    def test_digest_arg_default_looks_like_sha256(self, airgap_content: str):
        m = re.search(r"ARG PYTHON_BASE_DIGEST=(sha256:[0-9a-f]{64})", airgap_content)
        assert m, (
            "ARG PYTHON_BASE_DIGEST default value must be a full sha256:<64-hex-char> digest"
        )


# ── No-index pip install ──────────────────────────────────────────────────────


class TestNoIndexPipInstall:
    """All pip install commands must use --no-index to prevent PyPI access.

    Without --no-index, pip falls back to PyPI if a wheel is missing from
    the local cache, silently breaking the air-gap guarantee.
    """

    def test_pip_install_uses_no_index(self, airgap_content: str):
        # Join line continuations before checking — pip flags may span lines.
        joined = re.sub(r"\\\n\s*", " ", airgap_content)
        bad = [
            line.strip() for line in joined.splitlines()
            if "pip install" in line
            and "--no-index" not in line
            and not line.strip().startswith("#")
        ]
        assert len(bad) == 0, (
            "pip install without --no-index found (breaks air-gap):\n"
            + "\n".join(bad)
        )

    def test_pip_install_uses_find_links(self, airgap_content: str):
        pip_install_blocks = re.findall(r"pip install[^\n\\]+(?:\\\n[^\n\\]+)*", airgap_content)
        for block in pip_install_blocks:
            if "--find-links" not in block and "/wheels" not in block:
                pytest.fail(
                    f"pip install block missing --find-links /wheels:\n{block.strip()}"
                )

    def test_no_pip_install_index_url(self, airgap_content: str):
        assert "--index-url" not in airgap_content, (
            "--index-url in Dockerfile.airgap would re-enable PyPI access"
        )

    def test_no_pip_install_extra_index_url(self, airgap_content: str):
        assert "--extra-index-url" not in airgap_content, (
            "--extra-index-url in Dockerfile.airgap would enable secondary index access"
        )


# ── Multi-stage build ─────────────────────────────────────────────────────────


class TestMultiStageBuild:
    """Must use multi-stage build: builder stage installs packages, runtime
    stage copies only the site-packages — no build tools in final image."""

    def test_has_builder_stage(self, airgap_content: str):
        assert "AS builder" in airgap_content.upper() or "as builder" in airgap_content.lower(), (
            "Dockerfile.airgap must use a builder stage (FROM ... AS builder)"
        )

    def test_has_at_least_two_from(self, airgap_lines: list[str]):
        from_lines = [l for l in airgap_lines if l.strip().upper().startswith("FROM")]
        assert len(from_lines) >= 2, (
            f"Expected at least 2 FROM statements for multi-stage build, found {len(from_lines)}"
        )

    def test_copies_from_builder(self, airgap_content: str):
        assert "--from=builder" in airgap_content.lower(), (
            "Runtime stage must copy artifacts from builder with COPY --from=builder"
        )

    def test_vendor_wheels_copied_to_builder(self, airgap_content: str):
        assert "vendor/wheels" in airgap_content or "COPY vendor/wheels" in airgap_content, (
            "Dockerfile.airgap must COPY vendor/wheels into the builder stage"
        )


# ── Non-root user ─────────────────────────────────────────────────────────────


class TestNonRootUser:
    def test_has_non_root_user(self, airgap_content: str):
        assert "USER aegis" in airgap_content, (
            "Container must run as non-root user 'aegis'"
        )

    def test_user_created_with_explicit_uid(self, airgap_content: str):
        assert "-u 10001" in airgap_content or "useradd -u 10001" in airgap_content, (
            "User must be created with explicit UID 10001 for deterministic file ownership"
        )


# ── Security constraints ──────────────────────────────────────────────────────


class TestSecurityConstraints:
    """Dockerfile must not contain constructs that weaken isolation."""

    def test_no_privileged_marker(self, airgap_content: str):
        assert "--privileged" not in airgap_content, (
            "--privileged in Dockerfile defeats container isolation"
        )

    def test_no_sudo(self, airgap_content: str):
        assert "sudo" not in airgap_content.lower(), (
            "sudo in Dockerfile is a privilege escalation risk"
        )

    def test_no_curl_in_run(self, airgap_content: str):
        run_blocks = [
            line for line in airgap_content.splitlines()
            if "RUN " in line and "curl" in line.lower()
        ]
        assert len(run_blocks) == 0, (
            f"curl in RUN breaks air-gap: {run_blocks}"
        )

    def test_no_wget_in_run(self, airgap_content: str):
        run_blocks = [
            line for line in airgap_content.splitlines()
            if "RUN " in line and "wget" in line.lower()
        ]
        assert len(run_blocks) == 0, (
            f"wget in RUN breaks air-gap: {run_blocks}"
        )

    def test_has_healthcheck(self, airgap_content: str):
        assert "HEALTHCHECK" in airgap_content, (
            "Production image must define HEALTHCHECK for orchestrator liveness probing"
        )

    def test_apt_get_uses_no_install_recommends(self, airgap_content: str):
        apt_lines = [
            line.strip() for line in airgap_content.splitlines()
            if "apt-get install" in line
        ]
        for line in apt_lines:
            assert "--no-install-recommends" in line, (
                f"apt-get install without --no-install-recommends increases attack surface:\n{line}"
            )

    def test_cleans_apt_lists(self, airgap_content: str):
        assert "/var/lib/apt/lists/*" in airgap_content, (
            "apt lists must be removed after installation to reduce image size and attack surface"
        )

    def test_no_shell_form_entrypoint(self, airgap_content: str):
        # Only standalone CMD instructions (not CMD inside HEALTHCHECK).
        standalone_cmd = re.compile(r"^CMD\s+", re.MULTILINE)
        for m in standalone_cmd.finditer(airgap_content):
            rest = airgap_content[m.end():].lstrip()
            if rest and rest[0] != "[":
                pytest.fail(
                    f"CMD in shell form (no exec array) allows PID 1 signal handling issues: "
                    f"{airgap_content[m.start():m.start()+80].strip()!r}"
                )

    def test_airgap_label_set(self, airgap_content: str):
        assert 'aegis.airgap="true"' in airgap_content, (
            "Air-gapped image must carry aegis.airgap=true OCI label for inventory tooling"
        )


# ── Vendor script content ─────────────────────────────────────────────────────


class TestVendorScript:
    @pytest.fixture(scope="class")
    @classmethod
    def vendor_content(cls) -> str:
        return VENDOR_SCRIPT.read_text()

    def test_vendor_script_downloads_wheels(self, vendor_content: str):
        assert "pip download" in vendor_content, (
            "Vendor script must use pip download to fetch wheels"
        )

    def test_vendor_script_generates_sha256sums(self, vendor_content: str):
        assert "sha256sum" in vendor_content or "SHA256SUMS" in vendor_content, (
            "Vendor script must generate SHA256SUMS for integrity verification"
        )

    def test_vendor_script_captures_base_image_digest(self, vendor_content: str):
        assert "RepoDigests" in vendor_content or "python-3.11-slim-digest" in vendor_content, (
            "Vendor script must capture and save the base image digest"
        )

    def test_vendor_script_no_plaintext_secrets(self, vendor_content: str):
        forbidden = ["AEGIS_SIGNING_KEY=", "AEGIS_BACKEND_API_KEY=", "password="]
        for pattern in forbidden:
            assert pattern not in vendor_content, (
                f"Vendor script must not embed secrets: {pattern!r} found"
            )

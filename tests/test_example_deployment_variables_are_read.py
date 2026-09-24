# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Every ``AEGIS_*`` variable the shipped deployment examples set is read by something (REG-D60).

Five names in ``.env.example`` were read by nothing: an operator copying the
example believed they had required a distributed limiter, kept fsync on,
selected seccomp and LSM profiles and set four analysis workers, and had done
none of it. ``tests/test_config_surface_inert_fields.py`` checks the other
direction (settings fields without a reader), which is how these survived.

``AEGIS_REQUIRE_DISTRIBUTED_LIMITER`` is now an enforced setting; the fsync and
profile lines were removed (fsync is unconditional, and no Aegis setting
selects a profile file); ``AEGIS_ANALYSIS_WORKERS`` was the misspelling of
``AEGIS_ANALYSIS_WORKER_COUNT``.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from aegis.config import AegisSettings
from aegis_server.config import EnterpriseSettings

ROOT = Path(__file__).resolve().parents[1]

# Read by the dashboard server, not by a Python settings class.
DASHBOARD_ONLY = {"AEGIS_PRIMARY_BASE_URL", "AEGIS_DASHBOARD_API_KEY"}

SOURCES = {
    ".env.example": re.compile(r"^(AEGIS_[A-Z0-9_]+)=", re.M),
    "deploy/docker/docker-compose.yml": re.compile(r"^\s+(AEGIS_[A-Z0-9_]+):", re.M),
    "deploy/docker/Dockerfile": re.compile(r"^(?:ENV\s+|\s+)(AEGIS_[A-Z0-9_]+)=", re.M),
    "deploy/docker/Dockerfile.airgap": re.compile(r"^(?:ENV\s+|\s+)(AEGIS_[A-Z0-9_]+)=", re.M),
}


def _read_names() -> set[str]:
    names = {f"AEGIS_{field.upper()}" for field in AegisSettings.model_fields}
    names |= {f"AEGIS_{field.upper()}" for field in EnterpriseSettings.model_fields}
    return names | DASHBOARD_ONLY


@pytest.mark.parametrize("source", sorted(SOURCES))
def test_every_variable_a_deployment_example_sets_has_a_reader(source: str) -> None:
    text = (ROOT / source).read_text(encoding="utf-8")
    assigned = set(SOURCES[source].findall(text))
    assert assigned, f"{source}: the pattern matched nothing, so the gate would pass vacuously"
    unread = sorted(assigned - _read_names())
    assert not unread, f"{source} sets variables nothing reads: {unread}"


def test_the_dashboard_only_names_are_still_read_by_the_dashboard() -> None:
    client = (ROOT / "dashboard/src/lib/aegis-client.server.ts").read_text(encoding="utf-8")
    for name in DASHBOARD_ONLY:
        assert f"process.env.{name}" in client, name


BASE = {"backend_api_key": "sk-test", "backend_url": "http://mock-upstream"}


def test_require_distributed_limiter_refuses_the_in_memory_limiter() -> None:
    cfg = AegisSettings(
        **BASE,
        security_enforcement_mode="development",
        require_distributed_limiter=True,
        rate_limit_backend="memory",
    )
    with pytest.raises(ValueError, match="require_distributed_limiter"):
        cfg.validate_runtime_invariants()


def test_require_distributed_limiter_accepts_redis() -> None:
    cfg = AegisSettings(
        **BASE,
        security_enforcement_mode="development",
        require_distributed_limiter=True,
        rate_limit_backend="redis",
    )
    cfg.validate_runtime_invariants()


def test_require_distributed_limiter_is_off_by_default() -> None:
    cfg = AegisSettings(**BASE, security_enforcement_mode="development")
    assert cfg.require_distributed_limiter is False
    cfg.validate_runtime_invariants()


def test_the_environment_variable_reaches_the_setting(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGIS_REQUIRE_DISTRIBUTED_LIMITER", "true")
    cfg = AegisSettings(**BASE, security_enforcement_mode="development")
    assert cfg.require_distributed_limiter is True

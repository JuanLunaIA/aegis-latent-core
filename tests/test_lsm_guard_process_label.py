# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Process-label AppArmor detection (container runtimes without securityfs)."""

from __future__ import annotations

import sys
from unittest.mock import patch

import pytest

from aegis.core.lsm_guard import LSMGuard, LSMType

NOWHERE = "/nonexistent/aegis/attr"


def _detect(tmp_path, label: bytes, *, per_lsm: bool = False):
    attr = tmp_path / "current"
    attr.write_bytes(label)
    per_lsm_path, legacy_path = (str(attr), NOWHERE) if per_lsm else (NOWHERE, str(attr))
    with (
        patch("aegis.core.lsm_guard._PROC_SELF_ATTR_APPARMOR", per_lsm_path),
        patch("aegis.core.lsm_guard._PROC_SELF_ATTR", legacy_path),
        patch("aegis.core.lsm_guard._APPARMOR_PROFILES", "/nonexistent/apparmor/profiles"),
        patch("aegis.core.lsm_guard._SELINUX_ENFORCE", "/nonexistent/selinux/enforce"),
        patch.object(sys, "platform", "linux"),
    ):
        return LSMGuard.detect()


@pytest.mark.parametrize(
    ("label", "mode"),
    [
        (b"aegis-latent-core (enforce)\n", "enforcing"),
        (b"aegis-latent-core (kill)\x00", "enforcing"),
        (b"cri-containerd.apparmor.d (complain)\n", "permissive"),
    ],
)
def test_confined_label_detected_without_securityfs(tmp_path, label, mode):
    status = _detect(tmp_path, label)
    assert status.lsm_type == LSMType.APPARMOR
    assert status.active is True
    assert status.mode == mode
    assert status.profile == label.rstrip(b"\x00\n").decode().rpartition(" (")[0]


def test_per_lsm_interface_is_read(tmp_path):
    status = _detect(tmp_path, b"aegis-latent-core (enforce)\n", per_lsm=True)
    assert (status.lsm_type, status.mode) == (LSMType.APPARMOR, "enforcing")


@pytest.mark.parametrize(
    "label",
    [
        b"unconfined\n",
        b"unconfined (unconfined)\n",
        b"system_u:system_r:container_t:s0:c1,c2\n",
        b"aegis-latent-core (bogus)\n",
        b" (enforce)\n",
        b"",
    ],
)
def test_non_confining_labels_are_not_enforcing(tmp_path, label):
    status = _detect(tmp_path, label)
    assert status.lsm_type == LSMType.NONE
    assert status.active is False


def test_strict_assert_passes_on_enforced_label(tmp_path):
    attr = tmp_path / "current"
    attr.write_bytes(b"aegis-latent-core (enforce)\n")
    with (
        patch("aegis.core.lsm_guard._PROC_SELF_ATTR_APPARMOR", NOWHERE),
        patch("aegis.core.lsm_guard._PROC_SELF_ATTR", str(attr)),
        patch("aegis.core.lsm_guard._APPARMOR_PROFILES", "/nonexistent/apparmor/profiles"),
        patch.object(sys, "platform", "linux"),
    ):
        LSMGuard.assert_enforcing()
        assert LSMGuard()._check_apparmor() is True


def test_strict_assert_fails_on_complain_label(tmp_path):
    attr = tmp_path / "current"
    attr.write_bytes(b"aegis-latent-core (complain)\n")
    with (
        patch("aegis.core.lsm_guard._PROC_SELF_ATTR_APPARMOR", NOWHERE),
        patch("aegis.core.lsm_guard._PROC_SELF_ATTR", str(attr)),
        patch("aegis.core.lsm_guard._APPARMOR_PROFILES", "/nonexistent/apparmor/profiles"),
        patch.object(sys, "platform", "linux"),
    ):
        with pytest.raises(RuntimeError, match="LSM enforcement required"):
            LSMGuard.assert_enforcing()

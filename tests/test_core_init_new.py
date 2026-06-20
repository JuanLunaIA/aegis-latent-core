# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.__init__ lazy-loading __getattr__ (lines 41-43, 49-53)."""

from __future__ import annotations

from importlib import import_module
from unittest.mock import patch

import pytest


# ── __getattr__ — known submodule (lines 41-43) ──────────────────────────────


def test_getattr_known_submodule_directly():
    """Calling __getattr__('mmr') directly exercises lines 41-43."""
    import aegis.core as core
    # Call __getattr__ directly to bypass globals() cache
    mod = core.__getattr__("mmr")
    assert mod is not None
    assert hasattr(mod, "MerkleMountainRange")


def test_getattr_known_submodule_crypto_audit():
    """__getattr__('crypto_audit') exercises lines 41-43 for a different submodule."""
    import aegis.core as core
    mod = core.__getattr__("crypto_audit")
    assert mod is not None


# ── __getattr__ — submodule import exception (lines 49-53) ───────────────────


def test_getattr_submodule_import_exception_skipped():
    """When a submodule raises on import, it's skipped (lines 49-53)."""
    import aegis.core as core

    # Patch import_module to raise for the first submodule only
    original_import = import_module

    def _mock_import(name):
        if name == "aegis.core.mmr":
            raise ImportError("simulated heavy-dep failure")
        return original_import(name)

    with patch("aegis.core.import_module", side_effect=_mock_import):
        # "math_utils" is the second submodule; searching for "logsumexp"
        # should skip "mmr" (which raises) and find it in "math_utils"
        val = core.__getattr__("logsumexp")

    assert callable(val)


def test_getattr_submodule_all_raise_then_attribute_error():
    """When all submodules raise on import, AttributeError is raised."""
    import aegis.core as core

    def _always_raise(name):
        raise ImportError(f"cannot import {name}")

    with patch("aegis.core.import_module", side_effect=_always_raise):
        with pytest.raises(AttributeError, match="has no attribute"):
            core.__getattr__("nonexistent_attribute_xyz")


# ── __dir__ (line 63) ─────────────────────────────────────────────────────────


def test_dir_includes_submodule_names():
    import aegis.core as core
    d = core.__dir__()
    assert "mmr" in d
    assert "crypto_audit" in d

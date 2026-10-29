# Copyright (c) 2026 Juan Luna. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
# Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
"""Unit tests for the header rewriter's two profiles and its idempotence."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "apply_license_headers", ROOT / "scripts" / "apply_license_headers.py"
)
assert SPEC and SPEC.loader
headers = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = headers
SPEC.loader.exec_module(headers)

APACHE_BLOCK = """\
# Copyright (c) 2026 Juan Luna.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE.
"""


def test_profiles_are_split_by_path() -> None:
    assert headers.profile_for(Path("aegis/core/mmr.py")) == headers.COMMERCIAL
    assert headers.profile_for(Path("dashboard/src/main.tsx")) == headers.COMMERCIAL
    assert headers.profile_for(Path("sdk/python/src/aegis_sdk/__init__.py")) == headers.APACHE
    assert headers.profile_for(Path("examples/quickstart.py")) == headers.APACHE


def test_rewrite_swaps_an_apache_header_in_place() -> None:
    original = APACHE_BLOCK + "\nVALUE = 1\n"
    result = headers._rewrite(original, headers.COMMERCIAL, None)
    assert result is not None
    assert "LicenseRef-Aegis-Commercial-1.0" in result
    assert "Apache-2.0" not in result
    assert result.endswith("\nVALUE = 1\n")
    assert result.count("Copyright") == 1


def test_rewrite_is_idempotent() -> None:
    once = headers._rewrite(APACHE_BLOCK + "x = 1\n", headers.COMMERCIAL, None)
    assert once is not None
    twice = headers._rewrite(once, headers.COMMERCIAL, None)
    assert twice == once


def test_insert_python_keeps_the_module_docstring_first() -> None:
    source = '"""Module docs."""\n\nVALUE = 1\n'
    result = headers._insert(source, headers.COMMERCIAL, ".py", "mod.py")
    assert result.startswith('"""Module docs."""')
    assert "LicenseRef-Aegis-Commercial-1.0" in result
    assert result.index("LicenseRef") < result.index("VALUE = 1")


def test_insert_python_keeps_the_shebang_first() -> None:
    source = "#!/usr/bin/env python3\nVALUE = 1\n"
    result = headers._insert(source, headers.COMMERCIAL, ".py", "mod.py")
    assert result.startswith("#!/usr/bin/env python3\n")
    assert "LicenseRef-Aegis-Commercial-1.0" in result


def test_legacy_agpl_block_is_migrated() -> None:
    legacy = (
        "# Copyright (c) 2026 Juan Luna. All rights reserved.\n"
        "# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a\n"
        "# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.\n"
    )
    result = headers._replace_legacy(legacy, headers.COMMERCIAL, None)
    assert result is not None
    assert "LicenseRef-Aegis-Commercial-1.0" in result
    assert "AGPL" not in result
    assert "Copyright (c) 2026 Juan Luna. All rights reserved." in result


def test_docs_only_rewrite_an_existing_header() -> None:
    """A markdown file without a header must not gain one above its title."""
    source = "# Title\n\nApache-2.0 is mentioned here.\n"
    assert headers._rewrite(source, headers.COMMERCIAL, 8) is None

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Config-surface gate: every settings field must have a production reader.

A field an operator can set, that no code path reads, is a control the software
only appears to offer — the defect AUD-14 (CAC/PIV, the LDAP family, the PHI
master key) reported three families of. This test keeps the surface honest in
both directions:

* an unread field fails unless it is in ``INERT`` below, and
* an ``INERT`` entry whose field *has* acquired a reader fails too, so the list
  cannot rot into a set of stale excuses.

The allowlist is the register: every entry names the claims-register row or
roadmap ticket that records the boundary, and the boundary text itself lives in
``docs/institutional/UNSUPPORTED_CLAIMS.md``.

What this does **not** cover (stated, not implied): a field whose only reader is
an accessor method that nothing calls still counts as read here — see `UC-064`,
where ``AegisSettings.get_ldap_required_groups()`` is exactly that case. The
reader search is name-based and therefore conservative: a field whose name
appears only inside a string literal in production code is treated as read.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

# Production surfaces. `tests/` is deliberately absent: a field read by no test
# and no production path is inert; a field read only by a test is inert in
# production, which is the finding this gate exists for.
SCAN_DIRS = ("aegis", "aegis_server", "integrations", "scripts", "tools", "benchmarks")

# field name -> why it is allowed to have no reader
INERT: dict[str, str] = {
    # AUD-14 / REG-D18 — the audited families
    "ldap_url": "AUD-14 (UC-064): LDAP identity assertion is not wired",
    "ldap_base_dn": "AUD-14 (UC-064): LDAP identity assertion is not wired",
    "ldap_bind_dn": "AUD-14 (UC-064): LDAP identity assertion is not wired",
    "ldap_bind_password": "AUD-14 (UC-064): LDAP identity assertion is not wired",
    "ldap_user_search_filter": "AUD-14 (UC-064): LDAP identity assertion is not wired",
    "ldap_user_search_base": "AUD-14 (UC-064): LDAP identity assertion is not wired",
    "ldap_ad_mode": "AUD-14 (UC-064): LDAP identity assertion is not wired",
    "ldap_use_start_tls": "AUD-14 (UC-064): LDAP identity assertion is not wired",
    "ldap_ca_certs_file": "AUD-14 (UC-064): LDAP identity assertion is not wired",
    "ldap_timeout_seconds": "AUD-14 (UC-064): LDAP identity assertion is not wired",
    "cac_piv_required": "AUD-14 (UC-065): no code path enforces CAC/PIV policy",
    # AUD-35 — surfaced by this gate's first run, found alongside AUD-14
    "rate_limit_window": "AUD-35 (UC-066): the active limiter does not use this window",
    "webhook_url": "AUD-35 (UC-066): the alert sender reads siem_url, not this",
}


def _settings_classes() -> list[type]:
    from aegis.config import AegisSettings
    from aegis_server.config import EnterpriseSettings

    return [AegisSettings, EnterpriseSettings]


def _production_text() -> str:
    chunks: list[str] = []
    for directory in SCAN_DIRS:
        root = REPO_ROOT / directory
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*.py")):
            chunks.append(path.read_text(encoding="utf-8", errors="ignore"))
    if not chunks:
        pytest.skip("no production sources found next to this test")
    return "\n".join(chunks)


def _has_reader(blob: str, field: str) -> bool:
    attribute = re.compile(r"[.\[]" + re.escape(field) + r"\b")
    literal = re.compile(r"['\"]" + re.escape(field) + r"['\"]")
    return bool(attribute.search(blob) or literal.search(blob))


def _inert_fields() -> dict[str, str]:
    blob = _production_text()
    found: dict[str, str] = {}
    for klass in _settings_classes():
        for field in klass.model_fields:
            if not _has_reader(blob, field):
                found[field] = f"{klass.__name__}.{field}"
    return found


def test_no_undeclared_inert_settings_fields() -> None:
    """A field with no production reader must be in INERT with a reason."""
    found = _inert_fields()
    undeclared = {name: where for name, where in found.items() if name not in INERT}
    assert not undeclared, (
        "settings field(s) with no production reader: "
        + ", ".join(f"{name} ({where})" for name, where in sorted(undeclared.items()))
        + " — wire the control or label it and add it to INERT with the register row"
    )


def test_the_inert_list_has_no_stale_entries() -> None:
    """An INERT entry that has acquired a reader must be removed."""
    found = _inert_fields()
    stale = sorted(name for name in INERT if name not in found)
    assert not stale, (
        f"INERT entries that now have a production reader: {stale} — remove them from the "
        "allowlist and, if the boundary text changed, from UNSUPPORTED_CLAIMS.md"
    )


def test_every_inert_entry_names_its_register() -> None:
    """The allowlist doubles as the register index, so each entry cites one."""
    unreferenced = sorted(
        name for name, reason in INERT.items() if not re.search(r"UC-\d{3}|AUD-\d{2}", reason)
    )
    assert not unreferenced, f"INERT entries without a UC-/AUD- reference: {unreferenced}"


def test_the_scanned_surface_is_not_vacuous() -> None:
    """Guard the gate itself: the scan must see real fields and real files."""
    assert len(_production_text()) > 100_000, "production scan looks truncated"
    classes = _settings_classes()
    assert sum(len(klass.model_fields) for klass in classes) > 100, "settings look empty"
    assert sys.version_info >= (3, 11)


@pytest.mark.parametrize(
    "field", ["webhook_url", "cac_piv_required", "ldap_url", "rate_limit_window"]
)
def test_the_audited_families_are_still_inert(field: str) -> None:
    """The AUD-14/AUD-35 fields stay inert until they are wired: if one acquires a
    reader, this fails on purpose and the register rows must be re-read."""
    assert _has_reader(_production_text(), field) is False, (
        f"{field} now has a production reader — re-read AUD-14/AUD-35 and the UC rows "
        "before removing it from INERT"
    )


def _probe_dump() -> Any:  # pragma: no cover - helper for manual inspection
    return _inert_fields()

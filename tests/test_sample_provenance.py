"""Samples/ is demo material, and its provenance markers must stay checkable — REG-058.

`Samples/` holds thirteen generated HTML pages (~1.9 MB) plus a README, generated
by `tools/visualizer/generate_samples.py` and tracked in the repository. The risk
the registry row names is a reader taking demo material for evidence. Six written
policies already forbid that claim (`CLM-038`, `SECURITY.md`, `Samples/README.md`,
`docs/CLAIMS_MATRIX.md` and the corpus audit), but nothing *enforced* it: the
markers that make the pages self-describing were asserted by no test, so a
regeneration that dropped them, or a hand-edited page, would have been invisible.

These tests turn `CLM-038`'s prose into a pinned regression check. They do not
claim the numbers are accurate; they assert the pages keep saying they are not
evidence. The embedded `git_head`/`version` are frozen at the commit that
generated them and are deliberately *not* refreshed per release — see
`Samples/README.md`.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLES_DIR = REPO_ROOT / "Samples"
SAMPLES_README = SAMPLES_DIR / "README.md"

_BOOTSTRAP_MARKER = "window.__AEGIS_BOOTSTRAP__ = "
_BANNER_RE = re.compile(r"""class=["']demo-banner["']""")

#: Fields every sample's bootstrap snapshot must carry, and the value each must
#: have. These are the machine-readable half of the demo boundary.
_REQUIRED_BOOTSTRAP = {
    "demo_only": True,
    "live_runtime": False,
    "data_provenance": "static-demo-only",
}


def _sample_pages() -> list[Path]:
    pages = sorted(SAMPLES_DIR.glob("*.html"))
    assert pages, f"no sample pages found in {SAMPLES_DIR}"
    return pages


def _bootstrap(path: Path) -> dict[str, object]:
    text = path.read_text(encoding="utf-8")
    marker = text.find(_BOOTSTRAP_MARKER)
    assert marker != -1, f"{path.name} carries no {_BOOTSTRAP_MARKER!r} block"
    payload, _ = json.JSONDecoder().raw_decode(text, marker + len(_BOOTSTRAP_MARKER))
    assert isinstance(payload, dict), f"{path.name}: bootstrap block is not an object"
    return payload


def test_every_sample_page_declares_itself_demo_only():
    for page in _sample_pages():
        bootstrap = _bootstrap(page)
        for key, expected in _REQUIRED_BOOTSTRAP.items():
            assert bootstrap.get(key) == expected, (
                f"{page.name}: bootstrap {key!r} is {bootstrap.get(key)!r}, "
                f"expected {expected!r}; the page would no longer tell a reader it "
                "is demo material"
            )


def test_every_sample_page_renders_a_visible_demo_banner():
    """The machine-readable marker and the visible one must both survive."""
    for page in _sample_pages():
        text = page.read_text(encoding="utf-8")
        assert _BANNER_RE.search(text), (
            f"{page.name} renders no `demo-banner` element; a bootstrap field a "
            "reader never sees is not a disclosure"
        )


def test_sample_pages_describe_the_same_embedded_commit():
    """One generator run, one embedded snapshot — pin that they are not mixed."""
    heads = {_bootstrap(page).get("git_head") for page in _sample_pages()}
    assert len(heads) == 1, (
        f"sample pages embed different git_head values ({sorted(map(str, heads))}); "
        "they were not produced by one generator run"
    )


def test_samples_readme_states_the_embedded_metadata_is_frozen():
    """The stale-looking values must be explained where a reader meets them."""
    readme = SAMPLES_README.read_text(encoding="utf-8")
    assert "not refreshed per release" in readme, (
        "Samples/README.md must say the embedded git_head/version are frozen at "
        "the commit that generated them, so the values are honest rather than "
        "mistaken for current provenance"
    )

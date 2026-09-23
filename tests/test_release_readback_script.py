"""The release readback tool's own rules, pinned — REG-028 / REG-029.

`scripts/verify_release_readback.py` exists because a publication was once
believed complete while one surface carried nothing, and because a signature
that was never verified was reported as present. Both failures have the same
shape: an observer that is not checked is assumed good. Two rules follow, and
this module pins them so a later edit cannot quietly relax either.

1. `NOT_EXECUTED` is not a pass. It must not fail the run — the tools it stands
   for are not installable from every host, and a check that cannot run is not a
   mismatch — but it must never be counted as verification either.

2. The consumer snippet in `README.md` is **emitted by the tool**, not written
   twice. If either side changes, this test fails rather than leaving the
   documented commands pointing at a URL shape the tool no longer uses.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from types import ModuleType

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "verify_release_readback.py"
README = REPO_ROOT / "README.md"


def _load_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("verify_release_readback_under_test", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Register before execution: `@dataclass` resolves annotations through
    # sys.modules[cls.__module__], which is None for an unregistered module.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_not_executed_is_not_a_pass_but_does_not_fail_the_run():
    """The rule that makes the tool honest: unverified is reported, not assumed."""
    mod = _load_script()
    only_checked = [mod.Row("github release", mod.STATUS_CHECKED, "published")]
    assert mod.summarize(only_checked) == 0

    with_unverified = [
        *only_checked,
        mod.Row("cosign verify gateway", mod.STATUS_NOT_EXECUTED, "cosign not installed"),
    ]
    assert mod.summarize(with_unverified) == 0, (
        "an unrunnable check must not be reported as a mismatch"
    )

    with_mismatch = [
        *with_unverified,
        mod.Row("npm aegis-latent-sdk", mod.STATUS_MISMATCH, "latest 4.1.2 != 5.0.0"),
    ]
    assert mod.summarize(with_mismatch) == 1, "a real mismatch must fail the run"


def test_sha256sums_parsing_follows_sha256sum_output():
    """Two-space separation, `*` binary marker stripped, malformed lines ignored."""
    mod = _load_script()
    good = "a" * 64
    binary = "b" * 64
    short = "c" * 63
    text = "\n".join(
        [
            f"{good}  aegis_latent_core-5.0.0-py3-none-any.whl",
            f"{binary} *aegis-latent-sdk-5.0.0.tgz",
            f"{short}  truncated-digest.whl",
            "not a checksum line at all",
            "",
        ]
    )
    parsed = mod.parse_sha256sums(text)
    assert parsed == [
        (good, "aegis_latent_core-5.0.0-py3-none-any.whl"),
        (binary, "aegis-latent-sdk-5.0.0.tgz"),
    ]


def test_readme_consumer_snippet_matches_what_the_tool_emits():
    """The documented one-liner cannot drift from the tool's own URL construction."""
    mod = _load_script()
    emitted = mod.consumer_snippet("v5.0.0")

    readme = README.read_text(encoding="utf-8")
    blocks = [b for b in readme.split("```") if "curl -fsSL -O" in b]
    assert blocks, "README no longer documents a consumer download check"
    documented = blocks[0].strip()

    assert documented == emitted.strip(), (
        "README's consumer snippet and verify_release_readback.consumer_snippet() disagree; "
        "regenerate one from the other:\n"
        f"--- README ---\n{documented}\n--- tool ---\n{emitted}"
    )

    # and the same text must come out of the CLI, so the flag is wired to the function.
    # sys.executable and a path inside this repository; shell=False, fixed argv.
    proc = subprocess.run(  # noqa: S603
        [sys.executable, str(SCRIPT), "--tag", "v5.0.0", "--emit-consumer-snippet"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == emitted.strip()

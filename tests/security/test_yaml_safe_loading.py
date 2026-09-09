# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""No YAML in this repository may be parsed with a constructor that builds objects.

PyYAML's ``FullConstructor`` and ``UnsafeConstructor`` resolve ``!!python/...``
tags by importing modules and calling constructors. A document that reaches
either of them is not data, it is a program, and ``yaml.load`` selects
``FullLoader`` by default. ``yaml.safe_load`` uses ``SafeConstructor``, which
refuses those tags outright.

Today every parse site in the tree already uses the safe form. That is exactly
why this test exists: the property is cheap to hold and expensive to notice
losing, and the next YAML parse site somebody adds is the one that will not be
reviewed with this in mind. The register in
``scripts/triage/dependency_triage.py`` cites this test as the evidence for
classifying PyYAML as contained rather than as an open sink, so it has to
actually fail when the property breaks.

The scan is textual because the property is textual: it must hold for scripts,
tools and tests, not only for imported modules, and it must hold without
executing anything.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

#: Directories holding first-party Python. Everything else in the tree is
#: vendored, generated, or a virtual environment.
SCANNED_DIRS = ("aegis", "aegis_server", "scripts", "tools", "tests", "sdk", "benchmarks")

#: `yaml.load(...)` is safe only when it is handed a safe loader explicitly.
#: Matching the call and then inspecting its arguments separates
#: `yaml.load(text, Loader=SafeLoader)` from the bare form that defaults to
#: FullLoader.
_YAML_LOAD = re.compile(r"\byaml\.load\s*\(", re.MULTILINE)
_SAFE_LOADER_ARG = re.compile(r"Loader\s*=\s*(?:yaml\.)?(?:C?SafeLoader|BaseLoader)")

#: These have no safe form at all.
_ALWAYS_UNSAFE = re.compile(r"\byaml\.(?:unsafe_load|full_load|unsafe_load_all|full_load_all)\s*\(")


def _python_files() -> list[Path]:
    files: list[Path] = []
    for directory in SCANNED_DIRS:
        base = ROOT / directory
        if not base.is_dir():
            continue
        files += [
            path
            for path in base.rglob("*.py")
            if ".venv" not in path.parts
            and "node_modules" not in path.parts
            and "__pycache__" not in path.parts
        ]
    return sorted(files)


def _call_arguments(text: str, open_paren: int) -> str:
    """Return the argument text of the call whose ``(`` is at ``open_paren``.

    Counting depth rather than searching for the next ``)`` keeps a nested
    call such as ``yaml.load(f.read(), Loader=SafeLoader)`` intact; stopping at
    the first close paren would truncate before reaching the loader argument
    and report a false positive.
    """

    depth = 0
    for index in range(open_paren, len(text)):
        if text[index] == "(":
            depth += 1
        elif text[index] == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren + 1 : index]
    return text[open_paren:]


def test_the_repository_contains_python_to_scan() -> None:
    """A scan that silently matches nothing would pass forever."""

    files = _python_files()
    assert len(files) > 100, f"expected the first-party tree, found {len(files)} files"


def test_no_yaml_load_without_an_explicitly_safe_loader() -> None:
    findings: list[str] = []
    for path in _python_files():
        if path == Path(__file__):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for match in _YAML_LOAD.finditer(text):
            arguments = _call_arguments(text, match.end() - 1)
            if _SAFE_LOADER_ARG.search(arguments):
                continue
            line = text[: match.start()].count("\n") + 1
            findings.append(f"{path.relative_to(ROOT)}:{line}")
    assert not findings, (
        "yaml.load() without Loader=SafeLoader defaults to FullLoader, which "
        "instantiates arbitrary Python objects from the document. Use "
        f"yaml.safe_load(). Found at: {findings}"
    )


def test_no_unsafe_or_full_loader_helpers_anywhere() -> None:
    findings: list[str] = []
    for path in _python_files():
        if path == Path(__file__):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for match in _ALWAYS_UNSAFE.finditer(text):
            line = text[: match.start()].count("\n") + 1
            findings.append(f"{path.relative_to(ROOT)}:{line}")
    assert not findings, (
        "yaml.unsafe_load and yaml.full_load have no safe configuration; they "
        f"construct arbitrary objects from the document. Found at: {findings}"
    )


class TestTheScannerActuallyDetects:
    """The scanner must fail on a bad file, or its passing means nothing."""

    @pytest.mark.parametrize(
        "snippet",
        [
            "import yaml\ndata = yaml.load(text)\n",
            "import yaml\ndata = yaml.load(handle.read())\n",
            "import yaml\ndata = yaml.load(text, Loader=yaml.FullLoader)\n",
        ],
    )
    def test_a_bare_load_is_detected(self, snippet: str) -> None:
        match = _YAML_LOAD.search(snippet)
        assert match is not None
        arguments = _call_arguments(snippet, match.end() - 1)
        assert not _SAFE_LOADER_ARG.search(arguments)

    @pytest.mark.parametrize(
        "snippet",
        [
            "import yaml\ndata = yaml.load(text, Loader=yaml.SafeLoader)\n",
            "import yaml\ndata = yaml.load(f.read(), Loader=SafeLoader)\n",
            "import yaml\ndata = yaml.load(text, Loader=yaml.CSafeLoader)\n",
        ],
    )
    def test_an_explicit_safe_loader_is_accepted(self, snippet: str) -> None:
        match = _YAML_LOAD.search(snippet)
        assert match is not None
        arguments = _call_arguments(snippet, match.end() - 1)
        assert _SAFE_LOADER_ARG.search(arguments)

    def test_the_unsafe_helpers_are_detected(self) -> None:
        assert _ALWAYS_UNSAFE.search("yaml.unsafe_load(text)")
        assert _ALWAYS_UNSAFE.search("yaml.full_load(text)")
        assert not _ALWAYS_UNSAFE.search("yaml.safe_load(text)")


def test_safe_load_actually_refuses_a_python_object_tag() -> None:
    """The property this whole file protects, demonstrated once against PyYAML.

    If a future PyYAML made SafeConstructor permissive, every check above would
    still pass while the guarantee was gone.
    """

    import yaml

    hostile = "!!python/object/apply:os.system ['echo pwned']"
    with pytest.raises(yaml.YAMLError):
        yaml.safe_load(hostile)

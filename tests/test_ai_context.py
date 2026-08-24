"""Offline structural and claim-boundary checks for the advisory AI context pack."""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTEXT = ROOT / ".aegis_ai_context"
PACK = (
    CONTEXT / "00_CORE_ONTOLOGY_AND_BOUNDARIES.xml",
    CONTEXT / "01_CANONICAL_SYMBOL_AND_TYPE_INDEX.tsv",
    CONTEXT / "02_OPERATIONAL_INVARIANTS_MATRIX.md",
    CONTEXT / "03_STATE_MACHINES_AND_DAGS.mermaid",
    CONTEXT / "04_FORMAL_SPECIFICATIONS_MAPPING.md",
    CONTEXT / "05_DETERMINISTIC_RECIPES_PLAYBOOK.md",
    CONTEXT / "06_SECURITY_AND_SUPPLY_CHAIN_MANIFEST.xml",
    CONTEXT / "07_SYSTEM_COMPACT_KERNEL.xml",
    ROOT / "llms.txt",
    ROOT / ".cursorrules",
)
XML_FILES = (PACK[0], PACK[6], PACK[7])
MARKDOWN_FILES = (PACK[2], PACK[4], PACK[5])
TOKEN_RE = re.compile(r"\w+|[^\w\s]", re.UNICODE)
MARKDOWN_LINK_RE = re.compile(r"\[[^]]+\]\(([^)]+)\)")


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _corpus() -> str:
    return "\n".join(_text(path) for path in PACK).lower()


def test_pack_files_exist_and_are_nonempty() -> None:
    for path in PACK:
        assert path.is_file(), path.relative_to(ROOT)
        assert path.stat().st_size > 0, path.relative_to(ROOT)


def test_xml_documents_are_well_formed_and_advisory() -> None:
    for path in XML_FILES:
        document = _text(path)
        assert len(document.encode("utf-8")) <= 128 * 1024
        assert "<!DOCTYPE" not in document.upper()
        assert "<!ENTITY" not in document.upper()
        root = ET.fromstring(document)  # noqa: S314 -- bounded local XML with DTD/entities rejected
        assert root.attrib.get("role") == "advisory", path.relative_to(ROOT)


def test_markdown_repository_links_resolve_offline() -> None:
    for source in MARKDOWN_FILES:
        for target in MARKDOWN_LINK_RE.findall(_text(source)):
            target = target.split("#", 1)[0]
            if not target or "://" in target:
                continue
            resolved = (source.parent / target).resolve()
            assert resolved.exists(), f"{source.relative_to(ROOT)} -> {target}"
            assert resolved.is_relative_to(ROOT.resolve())


def test_symbol_index_has_stable_schema_unique_symbols_and_paths() -> None:
    rows = [line.split("\t") for line in _text(PACK[1]).splitlines()]
    assert rows[0] == [
        "symbol",
        "kind",
        "authoritative_path",
        "role",
        "status_or_boundary",
    ]
    assert all(len(row) == 5 for row in rows)
    symbols = [row[0] for row in rows[1:]]
    assert len(symbols) == len(set(symbols))
    for row in rows[1:]:
        path = ROOT / row[2]
        assert path.exists(), row[2]


def test_release_boundary_is_explicit_and_not_inferred_from_metadata() -> None:
    corpus = _corpus()
    assert "v3.1.0" in corpus
    assert "published baseline" in corpus
    assert "current-main" in corpus
    assert "unreleased" in corpus
    assert "metadata" in corpus
    assert "does not" in corpus or "do not" in corpus
    assert "https://github.com/juanlunaia/aegis-latent-core/releases/tag/v3.1.0" in corpus


def test_portable_mmr_boundary_is_explicit() -> None:
    corpus = _corpus()
    assert "portable" in corpus
    assert "non-zk" in corpus or "non-zero-knowledge" in corpus
    assert "o(log n)" in corpus
    assert "trusted root" in corpus
    assert "aegis/core/mmr.py" in corpus
    assert "does not hide the leaf" in corpus or "disclosed leaf" in corpus


def test_external_acceptance_and_untrusted_instruction_boundaries_are_explicit() -> None:
    corpus = _corpus()
    assert "external acceptance" in corpus
    for boundary in ("tls", "redis", "filesystem", "secret manager", "kernel"):
        assert boundary in corpus
    for source in ("pasted", "generated", "retrieved"):
        assert source in corpus
    assert "untrusted" in corpus
    assert "override" in corpus


def test_compact_kernel_is_under_token_budget() -> None:
    kernel = _text(PACK[7])
    assert len(TOKEN_RE.findall(kernel)) < 5000
    assert "<!DOCTYPE" not in kernel.upper()
    assert "<!ENTITY" not in kernel.upper()
    assert ET.fromstring(kernel).attrib["token-budget"] == "under-5000"  # noqa: S314


def test_mermaid_contains_expected_deterministic_states() -> None:
    graph = _text(PACK[3])
    for state in (
        "received",
        "pending-terminal",
        "commit one terminal summary",
        "post-terminal proof retrieval",
        "v3.1.0 published baseline",
        "current-main post-release work",
        "UNTRUSTED DATA",
    ):
        assert state in graph


def test_pack_does_not_make_known_unsupported_affirmative_claims() -> None:
    corpus = _corpus()
    forbidden = (
        "is production-ready",
        "production readiness is proven",
        "is fully compliant",
        "is certified",
        "v4.0.0 is released",
        "v4 is released",
        "zero-knowledge mmr",
    )
    for claim in forbidden:
        assert claim not in corpus


def test_offline_validation_has_no_network_or_subprocess_dependency() -> None:
    source = _text(Path(__file__))
    modules = ("requests", "urllib", "socket", "subprocess", "httpx")
    for token in (module + "." for module in modules):
        assert token not in source

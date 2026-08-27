"""
test_forensic_pdf_report.py — Tests for aegis.core.forensic_pdf_report
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import json
import time
import uuid
from typing import Any

import pytest

from aegis import __version__
from aegis.core.forensic_pdf_report import (
    ForensicReport,
    ForensicReportBuilder,
    ReportClassification,
)

# ── Fixtures ─────────────────────────────────────────────────────────────────


def _make_node(
    state_id: str | None = None,
    tenant_id: str = "tenant-test",
    phi_scrubbed: bool = False,
    signature_scheme: str = "hmac-sha256",
    timestamp: float | None = None,
) -> dict[str, Any]:
    return {
        "state_id": state_id or str(uuid.uuid4()),
        "timestamp": timestamp or time.time(),
        "entropy": 2.5,
        "tenant_id": tenant_id,
        "sampling_params": {},
        "prev_hash": "0" * 64,
        "merkle_root": "a" * 64,
        "signature": "b" * 64,
        "signature_scheme": signature_scheme,
        "public_key": "",
        "request_hash": "c" * 64,
        "response_hash": "d" * 64,
        "model": "test-model",
        "endpoint": "chat.completions",
        "token_trail_count": 5,
        "is_fallback": False,
        "phi_scrubbed": phi_scrubbed,
        "scrub_method": "",
        "signer_name": "",
        "signature_meaning": "",
    }


@pytest.fixture
def builder() -> ForensicReportBuilder:
    return ForensicReportBuilder(
        operator_identity="Jane Smith, CFCE",
        acquisition_reason="Test acquisition reason",
        classification=ReportClassification.UNCLASSIFIED,
    )


@pytest.fixture
def three_nodes() -> list[dict[str, Any]]:
    return [
        _make_node(state_id="node-001", timestamp=1_700_000_000.0),
        _make_node(state_id="node-002", timestamp=1_700_001_000.0, phi_scrubbed=True),
        _make_node(state_id="node-003", timestamp=1_700_002_000.0, signature_scheme="pqc-ml-dsa"),
    ]


# ── build_from_nodes — empty list ─────────────────────────────────────────────


def test_build_empty_nodes_returns_report(builder: ForensicReportBuilder) -> None:
    report = builder.build_from_nodes([])
    assert isinstance(report, ForensicReport)


def test_default_tool_version_uses_package_version(builder: ForensicReportBuilder) -> None:
    report = builder.build_from_nodes([])
    assert report.tool_version == __version__


def test_build_empty_nodes_zero_count(builder: ForensicReportBuilder) -> None:
    report = builder.build_from_nodes([])
    assert report.chain_node_count == 0


def test_build_empty_nodes_sections_present(builder: ForensicReportBuilder) -> None:
    report = builder.build_from_nodes([])
    assert len(report.sections) == 6


def test_build_empty_nodes_no_summaries(builder: ForensicReportBuilder) -> None:
    report = builder.build_from_nodes([])
    assert report.audit_node_summaries == []


def test_build_empty_nodes_default_integrity(builder: ForensicReportBuilder) -> None:
    report = builder.build_from_nodes([])
    assert report.chain_integrity_status == "UNCHECKED"


# ── build_from_nodes — three nodes ───────────────────────────────────────────


def test_build_three_nodes_count(
    builder: ForensicReportBuilder, three_nodes: list[dict[str, Any]]
) -> None:
    report = builder.build_from_nodes(three_nodes)
    assert report.chain_node_count == 3


def test_build_three_nodes_summaries_count(
    builder: ForensicReportBuilder, three_nodes: list[dict[str, Any]]
) -> None:
    report = builder.build_from_nodes(three_nodes)
    assert len(report.audit_node_summaries) == 3


def test_build_three_nodes_summary_fields(
    builder: ForensicReportBuilder, three_nodes: list[dict[str, Any]]
) -> None:
    report = builder.build_from_nodes(three_nodes)
    s = report.audit_node_summaries[0]
    assert s.state_id == "node-001"
    assert s.tenant_id == "tenant-test"
    assert s.request_hash == "c" * 64
    assert s.response_hash == "d" * 64
    assert s.signature_scheme == "HMAC-SHA256"
    assert s.phi_scrubbed is False


def test_build_three_nodes_phi_scrubbed_flag(
    builder: ForensicReportBuilder, three_nodes: list[dict[str, Any]]
) -> None:
    report = builder.build_from_nodes(three_nodes)
    assert report.audit_node_summaries[1].phi_scrubbed is True


def test_build_three_nodes_pqc_scheme(
    builder: ForensicReportBuilder, three_nodes: list[dict[str, Any]]
) -> None:
    report = builder.build_from_nodes(three_nodes)
    assert report.audit_node_summaries[2].signature_scheme == "ML-DSA-65"


def test_build_three_nodes_timestamps_utc(
    builder: ForensicReportBuilder, three_nodes: list[dict[str, Any]]
) -> None:
    report = builder.build_from_nodes(three_nodes)
    for s in report.audit_node_summaries:
        assert "T" in s.timestamp_utc
        assert s.timestamp_utc.endswith("Z")


# ── Section titles present ────────────────────────────────────────────────────


def test_section_executive_summary_title(
    builder: ForensicReportBuilder, three_nodes: list[dict[str, Any]]
) -> None:
    report = builder.build_from_nodes(three_nodes)
    titles = [s.title for s in report.sections]
    assert "Executive Summary" in titles


def test_section_chain_integrity_title(
    builder: ForensicReportBuilder, three_nodes: list[dict[str, Any]]
) -> None:
    report = builder.build_from_nodes(three_nodes)
    titles = [s.title for s in report.sections]
    assert "Chain Integrity Verification" in titles


def test_section_signing_key_title(
    builder: ForensicReportBuilder, three_nodes: list[dict[str, Any]]
) -> None:
    report = builder.build_from_nodes(three_nodes)
    titles = [s.title for s in report.sections]
    assert "Signing Key Metadata" in titles


def test_section_audit_node_log_title(
    builder: ForensicReportBuilder, three_nodes: list[dict[str, Any]]
) -> None:
    report = builder.build_from_nodes(three_nodes)
    titles = [s.title for s in report.sections]
    assert "Audit Node Log" in titles


def test_section_chain_of_custody_title(
    builder: ForensicReportBuilder, three_nodes: list[dict[str, Any]]
) -> None:
    report = builder.build_from_nodes(three_nodes)
    titles = [s.title for s in report.sections]
    assert "Chain-of-Custody Narrative" in titles


def test_section_legal_admissibility_title(
    builder: ForensicReportBuilder, three_nodes: list[dict[str, Any]]
) -> None:
    report = builder.build_from_nodes(three_nodes)
    titles = [s.title for s in report.sections]
    assert "Technical Integrity and Legal Review Boundary" in titles


# ── to_text() ────────────────────────────────────────────────────────────────


def test_to_text_contains_forensic_header(
    builder: ForensicReportBuilder, three_nodes: list[dict[str, Any]]
) -> None:
    report = builder.build_from_nodes(three_nodes)
    text = report.to_text()
    assert "FORENSIC EXAMINATION REPORT" in text


def test_to_text_contains_classification(
    builder: ForensicReportBuilder, three_nodes: list[dict[str, Any]]
) -> None:
    report = builder.build_from_nodes(three_nodes)
    text = report.to_text()
    assert "UNCLASSIFIED" in text


def test_to_text_contains_operator_identity(
    builder: ForensicReportBuilder, three_nodes: list[dict[str, Any]]
) -> None:
    report = builder.build_from_nodes(three_nodes)
    text = report.to_text()
    assert "Jane Smith, CFCE" in text


def test_to_text_contains_section_headings(
    builder: ForensicReportBuilder, three_nodes: list[dict[str, Any]]
) -> None:
    report = builder.build_from_nodes(three_nodes)
    text = report.to_text()
    assert "EXECUTIVE SUMMARY" in text
    assert "CHAIN INTEGRITY VERIFICATION" in text
    assert "TECHNICAL INTEGRITY AND LEGAL REVIEW BOUNDARY" in text


def test_to_text_contains_integrity_seal(
    builder: ForensicReportBuilder, three_nodes: list[dict[str, Any]]
) -> None:
    report = builder.build_from_nodes(three_nodes)
    text = report.to_text()
    assert "Integrity Seal" in text
    assert report.integrity_seal in text


# ── to_json() ────────────────────────────────────────────────────────────────


def test_to_json_is_valid_json(
    builder: ForensicReportBuilder, three_nodes: list[dict[str, Any]]
) -> None:
    report = builder.build_from_nodes(three_nodes)
    parsed = json.loads(report.to_json())
    assert isinstance(parsed, dict)


def test_to_json_contains_report_id(
    builder: ForensicReportBuilder, three_nodes: list[dict[str, Any]]
) -> None:
    report = builder.build_from_nodes(three_nodes)
    parsed = json.loads(report.to_json())
    assert parsed["report_id"] == report.report_id


def test_to_json_contains_sections(
    builder: ForensicReportBuilder, three_nodes: list[dict[str, Any]]
) -> None:
    report = builder.build_from_nodes(three_nodes)
    parsed = json.loads(report.to_json())
    assert len(parsed["sections"]) == 6


# ── to_dict() round-trip ─────────────────────────────────────────────────────


def test_to_dict_round_trip(
    builder: ForensicReportBuilder, three_nodes: list[dict[str, Any]]
) -> None:
    report = builder.build_from_nodes(three_nodes)
    d = report.to_dict()
    assert d["tool_name"] == "Aegis Latent Core"
    assert d["operator_identity"] == "Jane Smith, CFCE"
    assert d["chain_node_count"] == 3


# ── Integrity seal ────────────────────────────────────────────────────────────


def test_integrity_seal_computed(
    builder: ForensicReportBuilder, three_nodes: list[dict[str, Any]]
) -> None:
    report = builder.build_from_nodes(three_nodes)
    assert len(report.integrity_seal) == 64  # SHA-256 hex


def test_integrity_seal_verified(
    builder: ForensicReportBuilder, three_nodes: list[dict[str, Any]]
) -> None:
    report = builder.build_from_nodes(three_nodes)
    expected = report.compute_seal()
    assert report.integrity_seal == expected


def test_integrity_seal_changes_on_tamper(
    builder: ForensicReportBuilder, three_nodes: list[dict[str, Any]]
) -> None:
    report = builder.build_from_nodes(three_nodes)
    original_seal = report.integrity_seal
    # Tamper with operator identity
    report.operator_identity = "Malicious Actor"
    new_seal = report.compute_seal()
    assert new_seal != original_seal


# ── Classification ────────────────────────────────────────────────────────────


def test_classification_law_enforcement_sensitive() -> None:
    builder = ForensicReportBuilder(
        operator_identity="Det. Jones",
        acquisition_reason="Criminal investigation",
        classification=ReportClassification.LAW_ENFORCEMENT_SENSITIVE,
    )
    report = builder.build_from_nodes([])
    assert report.classification == ReportClassification.LAW_ENFORCEMENT_SENSITIVE
    assert "LAW ENFORCEMENT SENSITIVE" in report.to_text()


def test_classification_confidential() -> None:
    builder = ForensicReportBuilder(
        operator_identity="Analyst",
        acquisition_reason="Internal review",
        classification=ReportClassification.CONFIDENTIAL,
    )
    report = builder.build_from_nodes([])
    assert "CONFIDENTIAL" in report.to_text()


# ── chain_integrity_status values ────────────────────────────────────────────


def test_chain_integrity_verified(
    builder: ForensicReportBuilder, three_nodes: list[dict[str, Any]]
) -> None:
    report = builder.build_from_nodes(three_nodes, integrity_status="VERIFIED")
    assert report.chain_integrity_status == "VERIFIED"
    exec_section = next(s for s in report.sections if s.section_id == "executive_summary")
    assert "VERIFIED" in exec_section.content


def test_chain_integrity_compromised(
    builder: ForensicReportBuilder, three_nodes: list[dict[str, Any]]
) -> None:
    report = builder.build_from_nodes(three_nodes, integrity_status="COMPROMISED")
    assert report.chain_integrity_status == "COMPROMISED"


def test_chain_integrity_unchecked(
    builder: ForensicReportBuilder, three_nodes: list[dict[str, Any]]
) -> None:
    report = builder.build_from_nodes(three_nodes, integrity_status="UNCHECKED")
    assert report.chain_integrity_status == "UNCHECKED"


# ── legal_admissibility values ────────────────────────────────────────────────


def test_legal_admissibility_admissible(
    builder: ForensicReportBuilder, three_nodes: list[dict[str, Any]]
) -> None:
    report = builder.build_from_nodes(three_nodes, legal_admissibility="Admissible")
    assert report.legal_admissibility == "Admissible"
    adm_section = next(s for s in report.sections if s.section_id == "legal_admissibility")
    assert "Admissible" in adm_section.content


def test_legal_admissibility_compromised(
    builder: ForensicReportBuilder, three_nodes: list[dict[str, Any]]
) -> None:
    report = builder.build_from_nodes(three_nodes, legal_admissibility="Compromised")
    adm_section = next(s for s in report.sections if s.section_id == "legal_admissibility")
    assert "Compromised" in adm_section.content


def test_legal_admissibility_conditional(
    builder: ForensicReportBuilder, three_nodes: list[dict[str, Any]]
) -> None:
    report = builder.build_from_nodes(three_nodes, legal_admissibility="Conditional")
    assert report.legal_admissibility == "Conditional"


# ── build_empty() ─────────────────────────────────────────────────────────────


def test_build_empty_returns_report(builder: ForensicReportBuilder) -> None:
    report = builder.build_empty()
    assert isinstance(report, ForensicReport)


def test_build_empty_has_all_sections(builder: ForensicReportBuilder) -> None:
    report = builder.build_empty()
    assert len(report.sections) == 6


def test_build_empty_to_text_works(builder: ForensicReportBuilder) -> None:
    report = builder.build_empty()
    text = report.to_text()
    assert "FORENSIC EXAMINATION REPORT" in text


def test_build_empty_has_integrity_seal(builder: ForensicReportBuilder) -> None:
    report = builder.build_empty()
    assert len(report.integrity_seal) == 64


# ── Custody events ────────────────────────────────────────────────────────────


def test_custody_events_appear_in_section(
    builder: ForensicReportBuilder, three_nodes: list[dict[str, Any]]
) -> None:
    custody = [
        {"action": "Acquisition", "actor": "Jane Smith", "timestamp": "2026-06-23T10:00Z"},
        {
            "action": "Analysis",
            "actor": "Bob Jones",
            "timestamp": "2026-06-23T12:00Z",
            "note": "Initial triage",
        },
    ]
    report = builder.build_from_nodes(three_nodes, custody_events=custody)
    coc_section = next(s for s in report.sections if s.section_id == "chain_of_custody")
    assert "Jane Smith" in coc_section.content
    assert "Bob Jones" in coc_section.content
    assert "Initial triage" in coc_section.content


# ── Root hash ─────────────────────────────────────────────────────────────────


def test_chain_root_hash_stored(
    builder: ForensicReportBuilder, three_nodes: list[dict[str, Any]]
) -> None:
    root = "abc123" + "0" * 58
    report = builder.build_from_nodes(three_nodes, chain_root_hash=root)
    assert report.chain_root_hash == root
    chain_section = next(s for s in report.sections if s.section_id == "chain_integrity")
    assert root in chain_section.content

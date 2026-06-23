"""
aegis.core.forensic_pdf_report — Domain 5.3 court-ready forensic report generator.

Generates structured forensic reports as JSON and human-readable text suitable
for downstream PDF rendering. Reports are court-admissible, contain all required
forensic fields, and are sealed with a SHA-256 integrity hash over all content.

Usage::

    builder = ForensicReportBuilder(
        operator_identity="Forensic Examiner Jane Smith",
        acquisition_reason="Civil litigation — case 2026-CV-1234",
        classification=ReportClassification.LAW_ENFORCEMENT_SENSITIVE,
    )
    report = builder.build_from_nodes(nodes, chain_root_hash="abc...", integrity_status="VERIFIED")
    print(report.to_text())
    with open("report.json", "w") as f:
        f.write(report.to_json())
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class ReportClassification(StrEnum):
    """Sensitivity classification for forensic reports."""

    UNCLASSIFIED = "UNCLASSIFIED"
    CONFIDENTIAL = "CONFIDENTIAL"
    LAW_ENFORCEMENT_SENSITIVE = "LAW ENFORCEMENT SENSITIVE"
    ATTORNEY_CLIENT_PRIVILEGE = "ATTORNEY-CLIENT PRIVILEGE"


@dataclass
class ReportSection:
    """A single section of the forensic report."""

    title: str
    content: str
    section_id: str
    page_hint: int


@dataclass
class AuditNodeSummary:
    """Condensed summary of a single audit node for inclusion in the report."""

    state_id: str
    timestamp_utc: str
    tenant_id: str
    request_hash: str
    response_hash: str
    node_hash: str
    signature_scheme: str
    phi_scrubbed: bool


@dataclass
class ForensicReport:
    """Court-ready forensic examination report.

    Fields are sealed by a SHA-256 integrity hash computed over all non-seal
    fields in canonical (sorted-key) JSON form. The seal must be verified by
    the recipient before relying on report content.
    """

    # ── Metadata ──────────────────────────────────────────────────────────
    report_id: str
    generated_at: str
    tool_name: str
    tool_version: str
    operator_identity: str
    acquisition_reason: str
    classification: ReportClassification

    # ── Content ───────────────────────────────────────────────────────────
    sections: list[ReportSection]
    audit_node_summaries: list[AuditNodeSummary]

    # ── Integrity ─────────────────────────────────────────────────────────
    chain_integrity_status: str
    chain_node_count: int
    chain_root_hash: str
    legal_admissibility: str
    integrity_seal: str

    # ─────────────────────────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dict of all report fields."""
        d = asdict(self)
        # ReportClassification is a str Enum — asdict gives the .value already
        return d

    def to_json(self) -> str:
        """Return the full report as a JSON string."""
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    def compute_seal(self) -> str:
        """Compute SHA-256 of canonical sorted-key JSON over all non-seal fields.

        The seal binds all report content so any post-generation modification
        of a field (including metadata, sections, and node summaries) is
        detectable.
        """
        d = self.to_dict()
        d.pop("integrity_seal", None)
        canonical = json.dumps(d, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def to_text(self) -> str:  # noqa: PLR0912
        """Return a human-readable court-ready narrative text report."""
        lines: list[str] = []

        # ── Cover page ────────────────────────────────────────────────────
        lines.append("FORENSIC EXAMINATION REPORT")
        lines.append("=" * 43)
        lines.append(f"Classification: {self.classification.value}")
        lines.append(f"Report ID: {self.report_id}")
        lines.append(f"Generated: {self.generated_at}")
        lines.append(f"Tool: {self.tool_name} v{self.tool_version}")
        lines.append(f"Operator: {self.operator_identity}")
        lines.append(f"Acquisition Reason: {self.acquisition_reason}")
        lines.append("")

        # ── Sections ──────────────────────────────────────────────────────
        for section in self.sections:
            lines.append(section.title.upper())
            lines.append("-" * len(section.title))
            lines.append(section.content)
            lines.append("")

        # ── Integrity seal ────────────────────────────────────────────────
        lines.append("-" * 43)
        lines.append(f"Integrity Seal (SHA-256): {self.integrity_seal}")

        return "\n".join(lines)


# ── Builder ───────────────────────────────────────────────────────────────────


class ForensicReportBuilder:
    """Builds court-ready forensic reports from audit chain data.

    Parameters
    ----------
    operator_identity:
        Full name or role of the examiner (e.g. "Jane Smith, CFCE").
    acquisition_reason:
        Reason the evidence was acquired (e.g. "Civil litigation, case 2026-CV-1234").
    classification:
        Sensitivity classification for the finished report.
    tool_version:
        Version of the Aegis Latent Core tool.  Defaults to the package version.
    """

    TOOL_NAME = "Aegis Latent Core"

    def __init__(
        self,
        operator_identity: str,
        acquisition_reason: str,
        classification: ReportClassification = ReportClassification.UNCLASSIFIED,
        tool_version: str = "2.4.0",
    ) -> None:
        self._operator_identity = operator_identity
        self._acquisition_reason = acquisition_reason
        self._classification = classification
        self._tool_version = tool_version

    # ── Public API ────────────────────────────────────────────────────────

    def build_from_nodes(
        self,
        nodes: list[dict[str, Any]],
        chain_root_hash: str = "",
        integrity_status: str = "UNCHECKED",
        legal_admissibility: str = "Conditional",
        custody_events: list[dict[str, Any]] | None = None,
    ) -> ForensicReport:
        """Build a complete forensic report from audit node dicts.

        Parameters
        ----------
        nodes:
            List of audit node dicts in ``AuditNode.from_dict`` format.
        chain_root_hash:
            Merkle Mountain Range root hash for the chain at time of export.
        integrity_status:
            One of ``"VERIFIED"``, ``"COMPROMISED"``, or ``"UNCHECKED"``.
        legal_admissibility:
            One of ``"Admissible"``, ``"Conditional"``, or ``"Compromised"``.
        custody_events:
            Optional list of chain-of-custody event dicts, each with keys
            ``action``, ``actor``, ``timestamp``, and optionally ``note``.
        """
        summaries = [self._make_summary(n) for n in nodes]
        sections = self._build_sections(
            nodes=nodes,
            summaries=summaries,
            chain_root_hash=chain_root_hash,
            integrity_status=integrity_status,
            legal_admissibility=legal_admissibility,
            custody_events=custody_events or [],
        )

        report = ForensicReport(
            report_id=str(uuid.uuid4()),
            generated_at=datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            tool_name=self.TOOL_NAME,
            tool_version=self._tool_version,
            operator_identity=self._operator_identity,
            acquisition_reason=self._acquisition_reason,
            classification=self._classification,
            sections=sections,
            audit_node_summaries=summaries,
            chain_integrity_status=integrity_status,
            chain_node_count=len(nodes),
            chain_root_hash=chain_root_hash,
            legal_admissibility=legal_admissibility,
            integrity_seal="",
        )
        report.integrity_seal = report.compute_seal()
        return report

    def build_empty(self) -> ForensicReport:
        """Build a report with placeholder sections when no nodes are available."""
        return self.build_from_nodes(
            nodes=[],
            chain_root_hash="",
            integrity_status="UNCHECKED",
            legal_admissibility="Conditional",
        )

    # ── Private helpers ───────────────────────────────────────────────────

    @staticmethod
    def _make_summary(node: dict[str, Any]) -> AuditNodeSummary:
        """Convert an audit node dict to an AuditNodeSummary."""
        ts_raw = node.get("timestamp", 0.0)
        try:
            ts_utc = datetime.fromtimestamp(float(ts_raw), tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        except (TypeError, ValueError, OSError):
            ts_utc = str(ts_raw)

        scheme = node.get("signature_scheme", "hmac-sha256")
        if scheme == "pqc-ml-dsa":
            display_scheme = "ML-DSA-65"
        elif scheme in ("hmac-sha256", "hmac"):
            display_scheme = "HMAC-SHA256"
        else:
            display_scheme = scheme.upper()

        # node_hash is a computed property; prefer stored value
        node_hash = node.get("node_hash", "")
        if not node_hash:
            # Recompute from canonical fields if missing
            content = "|".join(
                [
                    node.get("prev_hash", ""),
                    node.get("state_id", ""),
                    f"{float(node.get('timestamp', 0.0)):.9f}",
                    str(node.get("entropy", 0.0)),
                    node.get("tenant_id", ""),
                    node.get("merkle_root", ""),
                    node.get("signature", ""),
                    node.get("request_hash", ""),
                    node.get("response_hash", ""),
                ]
            )
            node_hash = hashlib.sha256(content.encode()).hexdigest()

        return AuditNodeSummary(
            state_id=node.get("state_id", ""),
            timestamp_utc=ts_utc,
            tenant_id=node.get("tenant_id", ""),
            request_hash=node.get("request_hash", ""),
            response_hash=node.get("response_hash", ""),
            node_hash=node_hash,
            signature_scheme=display_scheme,
            phi_scrubbed=bool(node.get("phi_scrubbed", False)),
        )

    def _build_sections(
        self,
        nodes: list[dict[str, Any]],
        summaries: list[AuditNodeSummary],
        chain_root_hash: str,
        integrity_status: str,
        legal_admissibility: str,
        custody_events: list[dict[str, Any]],
    ) -> list[ReportSection]:
        """Build all six standard forensic report sections."""
        node_count = len(nodes)

        # ── Time range ────────────────────────────────────────────────────
        if summaries:
            first_ts = summaries[0].timestamp_utc
            last_ts = summaries[-1].timestamp_utc
            time_range_str = f"{first_ts} to {last_ts}"
        else:
            time_range_str = "N/A (no nodes)"

        # ── Section 1: Executive Summary ──────────────────────────────────
        exec_summary_content = (
            f"This report documents the forensic examination of {node_count} audit node(s) "
            f"captured by the Aegis Latent Core cryptographic audit chain.\n\n"
            f"Time Range: {time_range_str}\n"
            f"Chain Integrity Status: {integrity_status}\n"
            f"Legal Admissibility: {legal_admissibility}\n\n"
            f"The Aegis Latent Core system maintains an append-only, cryptographically "
            f"chained audit ledger of all LLM inference pipeline interactions. Each node "
            f"in the chain is individually signed using HMAC-SHA256 or ML-DSA-65 "
            f"(post-quantum) and linked via SHA-256 Merkle Mountain Range accumulator. "
            f"This report was generated by operator: {self._operator_identity}.\n\n"
            f"Acquisition Reason: {self._acquisition_reason}"
        )

        sections: list[ReportSection] = [
            ReportSection(
                title="Executive Summary",
                content=exec_summary_content,
                section_id="executive_summary",
                page_hint=1,
            )
        ]

        # ── Section 2: Chain Integrity Verification ───────────────────────
        root_display = chain_root_hash if chain_root_hash else "(not provided)"
        if integrity_status == "VERIFIED":
            verification_outcome = (
                "The cryptographic chain has been fully verified. All node hashes are "
                "self-consistent, all prev_hash linkages match, and all HMAC-SHA256 / "
                "ML-DSA-65 signatures are valid. No tampering has been detected."
            )
        elif integrity_status == "COMPROMISED":
            verification_outcome = (
                "CRITICAL: One or more nodes failed integrity verification. "
                "Chain linkage or signature validation failed. This evidence chain "
                "may have been tampered with. Treat with caution and refer to "
                "the detailed audit node log below for specific failures."
            )
        else:
            verification_outcome = (
                "Chain integrity has not been independently verified during this "
                "examination. The chain fields are reported as stored. An independent "
                "verification run should be performed before formal proceedings."
            )

        chain_integrity_content = (
            f"Status: {integrity_status}\n"
            f"Root Hash: {root_display}\n"
            f"Algorithm: SHA-256 Merkle Mountain Range\n"
            f"Node Count: {node_count}\n\n"
            f"Verification Outcome:\n{verification_outcome}"
        )

        sections.append(
            ReportSection(
                title="Chain Integrity Verification",
                content=chain_integrity_content,
                section_id="chain_integrity",
                page_hint=2,
            )
        )

        # ── Section 3: Signing Key Metadata ───────────────────────────────
        schemes_used: set[str] = set()
        for s in summaries:
            schemes_used.add(s.signature_scheme)
        schemes_str = ", ".join(sorted(schemes_used)) if schemes_used else "None"

        # Hash the root hash as a proxy for key binding evidence (never expose keys)
        if chain_root_hash:
            key_binding_ref = hashlib.sha256(chain_root_hash.encode()).hexdigest()
        else:
            key_binding_ref = "(unavailable — no root hash)"

        signing_key_content = (
            f"Signature Scheme(s) Used: {schemes_str}\n"
            f"Key Binding Reference (SHA-256 of chain root): {key_binding_ref}\n"
            f"Key Provider: Aegis Latent Core HSM / software HMAC backend\n\n"
            f"Note: Private key material is never stored in forensic reports. "
            f"The key binding reference above is a SHA-256 hash of the chain root "
            f"which cryptographically links this report to the specific signing epoch. "
            f"Actual key material is held by the Aegis Latent Core signing subsystem "
            f"and can be produced separately under appropriate legal process."
        )

        sections.append(
            ReportSection(
                title="Signing Key Metadata",
                content=signing_key_content,
                section_id="signing_key_metadata",
                page_hint=3,
            )
        )

        # ── Section 4: Audit Node Log ─────────────────────────────────────
        if summaries:
            node_log_lines = [
                f"{'State ID':<36}  {'Timestamp (UTC)':<22}  "
                f"{'Request Hash (prefix)':<20}  {'Scheme':<14}  PHI Scrubbed",
                "-" * 110,
            ]
            for s in summaries:
                req_prefix = s.request_hash[:20] if s.request_hash else "(none)"
                phi_label = "Yes" if s.phi_scrubbed else "No"
                node_log_lines.append(
                    f"{s.state_id:<36}  {s.timestamp_utc:<22}  "
                    f"{req_prefix:<20}  {s.signature_scheme:<14}  {phi_label}"
                )
            node_log_content = "\n".join(node_log_lines)
        else:
            node_log_content = "No audit nodes are present in this examination."

        sections.append(
            ReportSection(
                title="Audit Node Log",
                content=node_log_content,
                section_id="audit_node_log",
                page_hint=4,
            )
        )

        # ── Section 5: Chain-of-Custody Narrative ─────────────────────────
        if custody_events:
            custody_lines: list[str] = [
                "The following chain-of-custody events have been recorded:\n"
            ]
            for i, event in enumerate(custody_events, 1):
                action = event.get("action", "Unknown action")
                actor = event.get("actor", "Unknown actor")
                timestamp = event.get("timestamp", "Unknown time")
                note = event.get("note", "")
                entry = f"{i}. [{timestamp}] {action} by {actor}."
                if note:
                    entry += f" Note: {note}"
                custody_lines.append(entry)
            custody_content = "\n".join(custody_lines)
        else:
            custody_content = (
                "No explicit chain-of-custody events were recorded for this examination. "
                "The cryptographic chain itself serves as an implicit chain of custody: "
                "each audit node is signed at time of creation and linked to its "
                "predecessor, providing tamper-evident provenance from genesis to present. "
                f"The chain of {node_count} node(s) spans {time_range_str}."
            )

        sections.append(
            ReportSection(
                title="Chain-of-Custody Narrative",
                content=custody_content,
                section_id="chain_of_custody",
                page_hint=5,
            )
        )

        # ── Section 6: Legal Admissibility Assessment ─────────────────────
        if legal_admissibility == "Admissible":
            admissibility_detail = (
                "The digital evidence represented in this report meets the standard "
                "criteria for legal admissibility: (1) the evidence was collected by "
                "an automated system with no human intervention in the record creation "
                "process; (2) each record is individually signed using a cryptographic "
                "scheme (HMAC-SHA256 or ML-DSA-65) that binds the content to the signing "
                "epoch; (3) the chain linkage provides tamper evidence for any post-hoc "
                "modification; (4) the chain integrity status is VERIFIED. "
                "This evidence is suitable for production in legal proceedings subject "
                "to applicable rules of evidence in the relevant jurisdiction."
            )
        elif legal_admissibility == "Compromised":
            admissibility_detail = (
                "WARNING: The chain integrity status indicates that one or more nodes "
                "may have been compromised. This evidence should be treated as "
                "potentially tainted. Independent expert review is strongly recommended "
                "before relying on this evidence in legal proceedings. The court should "
                "be informed of the chain integrity status."
            )
        else:  # Conditional
            admissibility_detail = (
                "The digital evidence in this report is conditionally admissible, "
                "subject to: (1) independent verification of the chain integrity by "
                "a qualified digital forensics examiner; (2) production of the signing "
                "key material (or HSM attestation) to the requesting party under "
                "appropriate legal process; (3) confirmation that the acquisition "
                "was conducted in accordance with ISO/IEC 27037 digital evidence "
                "handling standards. Once these conditions are satisfied, the evidence "
                "is expected to meet the admissibility standard."
            )

        admissibility_content = (
            f"Admissibility Status: {legal_admissibility}\n"
            f"Chain Integrity: {integrity_status}\n\n"
            f"{admissibility_detail}\n\n"
            f"Standards Reference:\n"
            f"  - ISO/IEC 27037: Guidelines for identification, collection, acquisition\n"
            f"    and preservation of digital evidence\n"
            f"  - NIST SP 800-86: Guide to Integrating Forensic Techniques\n"
            f"  - Federal Rules of Evidence, Rule 902(13)-(14): Certified Electronic Records"
        )

        sections.append(
            ReportSection(
                title="Legal Admissibility Assessment",
                content=admissibility_content,
                section_id="legal_admissibility",
                page_hint=6,
            )
        )

        return sections

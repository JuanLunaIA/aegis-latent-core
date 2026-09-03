# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.iso27037_evidence — ISO/IEC 27037 evidence packages."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from aegis.core.crypto_audit import CryptographicAuditLedger
from aegis.core.iso27037_evidence import (
    AcquisitionMetadata,
    CustodyEvent,
    EvidenceNode,
    EvidencePackage,
    LegalAdmissibility,
    add_custody_event,
    build_evidence_package,
    verify_seal,
)

_SIGNING_KEY = "test-iso27037-signing-key-not-for-production"
_OPERATOR = "Test Operator <test@example.org>"
_TOOL_VERSION = "4.1.0"


# ── Fixtures ──────────────────────────────────────────────────────────────────


def _make_ledger(tmp_path, nodes: int = 3) -> CryptographicAuditLedger:
    wal = str(tmp_path / "test.wal")
    ledger = CryptographicAuditLedger(wal, signing_key=_SIGNING_KEY)
    for i in range(nodes):
        ledger.commit_forensic(
            state_id=f"state-{i}",
            request_bytes=f"request body {i}".encode(),
            response_bytes=f"response body {i}".encode(),
            entropy=1.5 + i * 0.1,
            tenant_id=f"tenant-{i % 2}",
            model="gpt-test",
            endpoint="chat.completions",
        )
    return ledger


# ── CustodyEvent ──────────────────────────────────────────────────────────────


class TestCustodyEvent:
    def test_to_dict_all_fields(self):
        ev = CustodyEvent(
            event_type="acquisition",
            operator=_OPERATOR,
            timestamp_iso="2026-06-21T00:00:00+00:00",
            notes="initial export",
        )
        d = ev.to_dict()
        assert d["event_type"] == "acquisition"
        assert d["operator"] == _OPERATOR
        assert d["timestamp_iso"] == "2026-06-21T00:00:00+00:00"
        assert d["notes"] == "initial export"

    def test_to_dict_empty_notes(self):
        ev = CustodyEvent(
            event_type="access", operator="Bob", timestamp_iso="2026-01-01T00:00:00+00:00"
        )
        d = ev.to_dict()
        assert d["notes"] == ""

    def test_to_dict_keys(self):
        ev = CustodyEvent(event_type="transfer", operator="A", timestamp_iso="t")
        assert set(ev.to_dict().keys()) == {"event_type", "operator", "timestamp_iso", "notes"}


# ── AcquisitionMetadata ───────────────────────────────────────────────────────


class TestAcquisitionMetadata:
    def test_defaults(self):
        am = AcquisitionMetadata(
            tool_name="aegis-latent-core",
            tool_version="1.0",
            operator=_OPERATOR,
            acquisition_timestamp_iso="2026-06-21T00:00:00+00:00",
        )
        assert am.hash_algorithm == "SHA-256"
        assert am.standard_reference == "ISO/IEC 27037:2012"
        assert am.acquisition_reason == ""

    def test_to_dict_all_keys(self):
        am = AcquisitionMetadata(
            tool_name="t",
            tool_version="v",
            operator="o",
            acquisition_timestamp_iso="ts",
            acquisition_reason="reason",
        )
        d = am.to_dict()
        assert set(d.keys()) == {
            "tool_name",
            "tool_version",
            "operator",
            "acquisition_timestamp_iso",
            "acquisition_reason",
            "hash_algorithm",
            "standard_reference",
        }

    def test_to_dict_values(self):
        am = AcquisitionMetadata(
            tool_name="aegis-latent-core",
            tool_version="4.1.0",
            operator=_OPERATOR,
            acquisition_timestamp_iso="2026-06-21T12:00:00+00:00",
            acquisition_reason="audit",
        )
        d = am.to_dict()
        assert d["tool_name"] == "aegis-latent-core"
        assert d["tool_version"] == "4.1.0"
        assert d["hash_algorithm"] == "SHA-256"
        assert d["standard_reference"] == "ISO/IEC 27037:2012"


# ── EvidenceNode ──────────────────────────────────────────────────────────────


class TestEvidenceNode:
    def test_to_dict_keys(self):
        en = EvidenceNode(
            index=0,
            state_id="s",
            node_hash="h",
            prev_hash="p",
            timestamp_iso="t",
            tenant_id="ten",
            request_hash="rq",
            response_hash="rs",
            signature="sig",
            signature_scheme="hmac-sha256",
            model="m",
        )
        d = en.to_dict()
        assert set(d.keys()) == {
            "index",
            "state_id",
            "node_hash",
            "prev_hash",
            "timestamp_iso",
            "tenant_id",
            "request_hash",
            "response_hash",
            "signature",
            "signature_scheme",
            "model",
        }

    def test_to_dict_values(self):
        en = EvidenceNode(
            index=2,
            state_id="state-2",
            node_hash="abc",
            prev_hash="def",
            timestamp_iso="2026-06-21T00:00:00+00:00",
            tenant_id="tenant-0",
            request_hash="rh",
            response_hash="rsh",
            signature="sig",
            signature_scheme="pqc-ml-dsa",
            model="gpt-4",
        )
        d = en.to_dict()
        assert d["index"] == 2
        assert d["signature_scheme"] == "pqc-ml-dsa"
        assert d["model"] == "gpt-4"


# ── build_evidence_package ────────────────────────────────────────────────────


class TestBuildEvidencePackage:
    def test_returns_evidence_package(self, tmp_path):
        ledger = _make_ledger(tmp_path)
        try:
            pkg = build_evidence_package(ledger, operator=_OPERATOR, tool_version=_TOOL_VERSION)
            assert isinstance(pkg, EvidencePackage)
        finally:
            ledger.close()

    def test_package_id_is_uuid4(self, tmp_path):
        import uuid

        ledger = _make_ledger(tmp_path)
        try:
            pkg = build_evidence_package(ledger, operator=_OPERATOR)
            uuid.UUID(pkg.package_id, version=4)  # raises on invalid
        finally:
            ledger.close()

    def test_node_count_matches_ledger(self, tmp_path):
        ledger = _make_ledger(tmp_path, nodes=3)
        try:
            pkg = build_evidence_package(ledger, operator=_OPERATOR)
            assert pkg.node_count == 3
            assert len(pkg.evidence_nodes) == 3
        finally:
            ledger.close()

    def test_evidence_nodes_indexed(self, tmp_path):
        ledger = _make_ledger(tmp_path, nodes=5)
        try:
            pkg = build_evidence_package(ledger, operator=_OPERATOR)
            for i, node in enumerate(pkg.evidence_nodes):
                assert node.index == i
        finally:
            ledger.close()

    def test_evidence_nodes_have_state_ids(self, tmp_path):
        ledger = _make_ledger(tmp_path, nodes=3)
        try:
            pkg = build_evidence_package(ledger, operator=_OPERATOR)
            state_ids = {n.state_id for n in pkg.evidence_nodes}
            assert "state-0" in state_ids
            assert "state-1" in state_ids
            assert "state-2" in state_ids
        finally:
            ledger.close()

    def test_acquisition_metadata_operator(self, tmp_path):
        ledger = _make_ledger(tmp_path)
        try:
            pkg = build_evidence_package(ledger, operator=_OPERATOR)
            assert pkg.acquisition_metadata.operator == _OPERATOR
        finally:
            ledger.close()

    def test_acquisition_metadata_tool_version(self, tmp_path):
        ledger = _make_ledger(tmp_path)
        try:
            pkg = build_evidence_package(ledger, operator=_OPERATOR, tool_version="9.9.9")
            assert pkg.acquisition_metadata.tool_version == "9.9.9"
        finally:
            ledger.close()

    def test_acquisition_metadata_tool_name(self, tmp_path):
        ledger = _make_ledger(tmp_path)
        try:
            pkg = build_evidence_package(ledger, operator=_OPERATOR)
            assert pkg.acquisition_metadata.tool_name == "aegis-latent-core"
        finally:
            ledger.close()

    def test_acquisition_metadata_hash_algorithm(self, tmp_path):
        ledger = _make_ledger(tmp_path)
        try:
            pkg = build_evidence_package(ledger, operator=_OPERATOR)
            assert pkg.acquisition_metadata.hash_algorithm == "SHA-256"
        finally:
            ledger.close()

    def test_acquisition_metadata_standard_reference(self, tmp_path):
        ledger = _make_ledger(tmp_path)
        try:
            pkg = build_evidence_package(ledger, operator=_OPERATOR)
            assert pkg.acquisition_metadata.standard_reference == "ISO/IEC 27037:2012"
        finally:
            ledger.close()

    def test_acquisition_timestamp_is_iso8601(self, tmp_path):
        ledger = _make_ledger(tmp_path)
        try:
            pkg = build_evidence_package(ledger, operator=_OPERATOR)
            ts = pkg.acquisition_metadata.acquisition_timestamp_iso
            parsed = datetime.fromisoformat(ts)
            assert parsed.tzinfo is not None
        finally:
            ledger.close()

    def test_acquisition_reason_stored(self, tmp_path):
        ledger = _make_ledger(tmp_path)
        try:
            pkg = build_evidence_package(
                ledger, operator=_OPERATOR, acquisition_reason="incident-response-2026"
            )
            assert pkg.acquisition_metadata.acquisition_reason == "incident-response-2026"
        finally:
            ledger.close()

    def test_chain_integrity_valid(self, tmp_path):
        ledger = _make_ledger(tmp_path)
        try:
            pkg = build_evidence_package(ledger, operator=_OPERATOR)
            assert pkg.chain_integrity_valid is True
            assert pkg.chain_integrity_error_index == -1
        finally:
            ledger.close()

    def test_tail_hash_matches_last_node(self, tmp_path):
        ledger = _make_ledger(tmp_path, nodes=3)
        try:
            last_node_hash = list(ledger.chain)[-1].node_hash
            pkg = build_evidence_package(ledger, operator=_OPERATOR)
            assert pkg.tail_hash == last_node_hash
        finally:
            ledger.close()

    def test_tail_hash_empty_for_empty_chain(self, tmp_path):
        wal = str(tmp_path / "empty.wal")
        ledger = CryptographicAuditLedger(wal, signing_key=_SIGNING_KEY)
        try:
            pkg = build_evidence_package(ledger, operator=_OPERATOR)
            assert pkg.tail_hash == ""
            assert pkg.node_count == 0
        finally:
            ledger.close()

    def test_legal_admissibility_high(self, tmp_path):
        ledger = _make_ledger(tmp_path)
        try:
            pkg = build_evidence_package(ledger, operator=_OPERATOR)
            assert pkg.legal_admissibility == "High"
        finally:
            ledger.close()

    def test_initial_custody_event_is_acquisition(self, tmp_path):
        ledger = _make_ledger(tmp_path)
        try:
            pkg = build_evidence_package(ledger, operator=_OPERATOR)
            assert len(pkg.chain_of_custody) == 1
            assert pkg.chain_of_custody[0].event_type == "acquisition"
        finally:
            ledger.close()

    def test_initial_custody_event_operator(self, tmp_path):
        ledger = _make_ledger(tmp_path)
        try:
            pkg = build_evidence_package(ledger, operator=_OPERATOR)
            assert pkg.chain_of_custody[0].operator == _OPERATOR
        finally:
            ledger.close()

    def test_custody_reason_in_notes_when_provided(self, tmp_path):
        ledger = _make_ledger(tmp_path)
        try:
            pkg = build_evidence_package(ledger, operator=_OPERATOR, acquisition_reason="audit")
            assert "audit" in pkg.chain_of_custody[0].notes
        finally:
            ledger.close()

    def test_integrity_seal_is_non_empty_hex(self, tmp_path):
        ledger = _make_ledger(tmp_path)
        try:
            pkg = build_evidence_package(ledger, operator=_OPERATOR)
            assert len(pkg.integrity_seal) == 64
            int(pkg.integrity_seal, 16)  # must be valid hex
        finally:
            ledger.close()

    def test_node_timestamps_are_iso8601(self, tmp_path):
        ledger = _make_ledger(tmp_path, nodes=2)
        try:
            pkg = build_evidence_package(ledger, operator=_OPERATOR)
            for en in pkg.evidence_nodes:
                parsed = datetime.fromisoformat(en.timestamp_iso)
                assert parsed.tzinfo is not None
        finally:
            ledger.close()

    def test_node_hashes_are_sha256_hex(self, tmp_path):
        ledger = _make_ledger(tmp_path, nodes=2)
        try:
            pkg = build_evidence_package(ledger, operator=_OPERATOR)
            for en in pkg.evidence_nodes:
                assert len(en.node_hash) == 64
                int(en.node_hash, 16)
        finally:
            ledger.close()

    def test_prev_hash_chain_linkage(self, tmp_path):
        ledger = _make_ledger(tmp_path, nodes=3)
        try:
            pkg = build_evidence_package(ledger, operator=_OPERATOR)
            nodes = pkg.evidence_nodes
            assert nodes[1].prev_hash == nodes[0].node_hash
            assert nodes[2].prev_hash == nodes[1].node_hash
        finally:
            ledger.close()

    def test_request_and_response_hashes_present(self, tmp_path):
        ledger = _make_ledger(tmp_path, nodes=1)
        try:
            pkg = build_evidence_package(ledger, operator=_OPERATOR)
            en = pkg.evidence_nodes[0]
            assert len(en.request_hash) == 64
            assert len(en.response_hash) == 64
        finally:
            ledger.close()

    def test_signature_scheme_recorded(self, tmp_path):
        ledger = _make_ledger(tmp_path, nodes=1)
        try:
            pkg = build_evidence_package(ledger, operator=_OPERATOR)
            en = pkg.evidence_nodes[0]
            assert en.signature_scheme in {"hmac-sha256", "pqc-ml-dsa", "ed25519-fallback"}
        finally:
            ledger.close()


# ── verify_seal ───────────────────────────────────────────────────────────────


class TestVerifySeal:
    def test_valid_seal_returns_true(self, tmp_path):
        ledger = _make_ledger(tmp_path)
        try:
            pkg = build_evidence_package(ledger, operator=_OPERATOR)
            assert verify_seal(pkg.to_dict()) is True
        finally:
            ledger.close()

    def test_tampered_node_count_fails(self, tmp_path):
        ledger = _make_ledger(tmp_path)
        try:
            pkg = build_evidence_package(ledger, operator=_OPERATOR)
            d = pkg.to_dict()
            d["node_count"] = 9999
            assert verify_seal(d) is False
        finally:
            ledger.close()

    def test_tampered_tail_hash_fails(self, tmp_path):
        ledger = _make_ledger(tmp_path)
        try:
            pkg = build_evidence_package(ledger, operator=_OPERATOR)
            d = pkg.to_dict()
            d["tail_hash"] = "a" * 64
            assert verify_seal(d) is False
        finally:
            ledger.close()

    def test_tampered_evidence_node_hash_fails(self, tmp_path):
        ledger = _make_ledger(tmp_path)
        try:
            pkg = build_evidence_package(ledger, operator=_OPERATOR)
            d = pkg.to_dict()
            d["evidence_nodes"][0]["node_hash"] = "b" * 64
            assert verify_seal(d) is False
        finally:
            ledger.close()

    def test_tampered_operator_fails(self, tmp_path):
        ledger = _make_ledger(tmp_path)
        try:
            pkg = build_evidence_package(ledger, operator=_OPERATOR)
            d = pkg.to_dict()
            d["acquisition_metadata"]["operator"] = "Mallory"
            assert verify_seal(d) is False
        finally:
            ledger.close()

    def test_missing_seal_returns_false(self, tmp_path):
        ledger = _make_ledger(tmp_path)
        try:
            pkg = build_evidence_package(ledger, operator=_OPERATOR)
            d = pkg.to_dict()
            d["integrity_seal"] = ""
            assert verify_seal(d) is False
        finally:
            ledger.close()

    def test_absent_seal_key_returns_false(self, tmp_path):
        ledger = _make_ledger(tmp_path)
        try:
            pkg = build_evidence_package(ledger, operator=_OPERATOR)
            d = pkg.to_dict()
            del d["integrity_seal"]
            assert verify_seal(d) is False
        finally:
            ledger.close()

    def test_adding_extra_field_fails(self, tmp_path):
        ledger = _make_ledger(tmp_path)
        try:
            pkg = build_evidence_package(ledger, operator=_OPERATOR)
            d = pkg.to_dict()
            d["extra_injected_field"] = "malicious"
            assert verify_seal(d) is False
        finally:
            ledger.close()

    def test_seal_is_deterministic_given_same_package(self, tmp_path):
        ledger = _make_ledger(tmp_path)
        try:
            pkg = build_evidence_package(ledger, operator=_OPERATOR)
            d1 = pkg.to_dict()
            d2 = pkg.to_dict()
            assert d1["integrity_seal"] == d2["integrity_seal"]
        finally:
            ledger.close()

    def test_json_roundtrip_seal_still_valid(self, tmp_path):
        ledger = _make_ledger(tmp_path)
        try:
            pkg = build_evidence_package(ledger, operator=_OPERATOR)
            serialized = json.dumps(pkg.to_dict())
            reloaded = json.loads(serialized)
            assert verify_seal(reloaded) is True
        finally:
            ledger.close()


# ── to_dict / serialisation ───────────────────────────────────────────────────


class TestToDict:
    def test_to_dict_top_level_keys(self, tmp_path):
        ledger = _make_ledger(tmp_path)
        try:
            pkg = build_evidence_package(ledger, operator=_OPERATOR)
            d = pkg.to_dict()
            expected = {
                "package_id",
                "acquisition_metadata",
                "chain_of_custody",
                "evidence_nodes",
                "chain_integrity_valid",
                "chain_integrity_error_index",
                "node_count",
                "tail_hash",
                "legal_admissibility",
                "legal_admissibility_justification",
                "integrity_seal",
            }
            assert set(d.keys()) == expected
        finally:
            ledger.close()

    def test_to_dict_is_json_serializable(self, tmp_path):
        ledger = _make_ledger(tmp_path)
        try:
            pkg = build_evidence_package(ledger, operator=_OPERATOR)
            serialized = json.dumps(pkg.to_dict())
            assert len(serialized) > 0
        finally:
            ledger.close()

    def test_to_dict_evidence_nodes_is_list(self, tmp_path):
        ledger = _make_ledger(tmp_path, nodes=2)
        try:
            pkg = build_evidence_package(ledger, operator=_OPERATOR)
            d = pkg.to_dict()
            assert isinstance(d["evidence_nodes"], list)
            assert len(d["evidence_nodes"]) == 2
        finally:
            ledger.close()

    def test_to_dict_chain_of_custody_is_list(self, tmp_path):
        ledger = _make_ledger(tmp_path)
        try:
            pkg = build_evidence_package(ledger, operator=_OPERATOR)
            d = pkg.to_dict()
            assert isinstance(d["chain_of_custody"], list)
        finally:
            ledger.close()

    def test_to_dict_acquisition_metadata_is_dict(self, tmp_path):
        ledger = _make_ledger(tmp_path)
        try:
            pkg = build_evidence_package(ledger, operator=_OPERATOR)
            d = pkg.to_dict()
            assert isinstance(d["acquisition_metadata"], dict)
        finally:
            ledger.close()


# ── add_custody_event ─────────────────────────────────────────────────────────


class TestAddCustodyEvent:
    def test_adds_custody_event(self, tmp_path):
        ledger = _make_ledger(tmp_path)
        try:
            pkg = build_evidence_package(ledger, operator=_OPERATOR)
            add_custody_event(pkg, event_type="access", operator="Analyst Bob", notes="review")
            assert len(pkg.chain_of_custody) == 2
            assert pkg.chain_of_custody[1].event_type == "access"
            assert pkg.chain_of_custody[1].operator == "Analyst Bob"
        finally:
            ledger.close()

    def test_add_custody_event_reseals_package(self, tmp_path):
        ledger = _make_ledger(tmp_path)
        try:
            pkg = build_evidence_package(ledger, operator=_OPERATOR)
            old_seal = pkg.integrity_seal
            add_custody_event(pkg, event_type="transfer", operator="Carol")
            assert pkg.integrity_seal != old_seal
            assert verify_seal(pkg.to_dict()) is True
        finally:
            ledger.close()

    def test_add_custody_event_timestamp_explicit(self, tmp_path):
        ledger = _make_ledger(tmp_path)
        try:
            pkg = build_evidence_package(ledger, operator=_OPERATOR)
            fixed_ts = 1_750_000_000.0
            add_custody_event(pkg, event_type="verification", operator="Dave", timestamp=fixed_ts)
            ev = pkg.chain_of_custody[-1]
            expected_iso = datetime.fromtimestamp(fixed_ts, tz=UTC).isoformat()
            assert ev.timestamp_iso == expected_iso
        finally:
            ledger.close()

    def test_add_multiple_events_preserves_order(self, tmp_path):
        ledger = _make_ledger(tmp_path)
        try:
            pkg = build_evidence_package(ledger, operator=_OPERATOR)
            add_custody_event(pkg, event_type="access", operator="Eve")
            add_custody_event(pkg, event_type="transfer", operator="Frank")
            assert pkg.chain_of_custody[0].event_type == "acquisition"
            assert pkg.chain_of_custody[1].event_type == "access"
            assert pkg.chain_of_custody[2].event_type == "transfer"
        finally:
            ledger.close()

    def test_add_custody_event_notes_stored(self, tmp_path):
        ledger = _make_ledger(tmp_path)
        try:
            pkg = build_evidence_package(ledger, operator=_OPERATOR)
            add_custody_event(pkg, event_type="access", operator="Grace", notes="forensic review")
            assert pkg.chain_of_custody[-1].notes == "forensic review"
        finally:
            ledger.close()


# ── Integration: empty ledger ─────────────────────────────────────────────────


class TestEmptyLedger:
    def test_empty_ledger_package(self, tmp_path):
        wal = str(tmp_path / "empty.wal")
        ledger = CryptographicAuditLedger(wal, signing_key=_SIGNING_KEY)
        try:
            pkg = build_evidence_package(ledger, operator=_OPERATOR)
            assert pkg.node_count == 0
            assert pkg.evidence_nodes == []
            assert pkg.tail_hash == ""
            assert verify_seal(pkg.to_dict()) is True
        finally:
            ledger.close()


# ── Integration: large chain ──────────────────────────────────────────────────


class TestLargeChain:
    def test_100_node_package_seal_valid(self, tmp_path):
        ledger = _make_ledger(tmp_path, nodes=100)
        try:
            pkg = build_evidence_package(ledger, operator=_OPERATOR)
            assert pkg.node_count == 100
            assert verify_seal(pkg.to_dict()) is True
            assert pkg.chain_integrity_valid is True
        finally:
            ledger.close()

    def test_node_ordering_preserved(self, tmp_path):
        ledger = _make_ledger(tmp_path, nodes=10)
        try:
            pkg = build_evidence_package(ledger, operator=_OPERATOR)
            ids = [n.state_id for n in pkg.evidence_nodes]
            assert ids == [f"state-{i}" for i in range(10)]
        finally:
            ledger.close()


# ── LegalAdmissibility enum ───────────────────────────────────────────────────


class TestLegalAdmissibilityEnum:
    def test_admissible_value(self):
        assert LegalAdmissibility.Admissible.value == "Admissible"

    def test_conditional_value(self):
        assert LegalAdmissibility.Conditional.value == "Conditional"

    def test_compromised_value(self):
        assert LegalAdmissibility.Compromised.value == "Compromised"

    def test_str_comparison_admissible(self):
        assert LegalAdmissibility.Admissible == "Admissible"

    def test_str_comparison_conditional(self):
        assert LegalAdmissibility.Conditional == "Conditional"

    def test_str_comparison_compromised(self):
        assert LegalAdmissibility.Compromised == "Compromised"

    def test_all_members_count(self):
        assert len(LegalAdmissibility) == 3

    def test_enum_from_value_admissible(self):
        assert LegalAdmissibility("Admissible") is LegalAdmissibility.Admissible

    def test_enum_from_value_conditional(self):
        assert LegalAdmissibility("Conditional") is LegalAdmissibility.Conditional

    def test_enum_from_value_compromised(self):
        assert LegalAdmissibility("Compromised") is LegalAdmissibility.Compromised


# ── Per-bundle LegalAdmissibility override ────────────────────────────────────


class TestLegalAdmissibilityOverride:
    def test_default_no_override_uses_chain_level(self, tmp_path):
        """Without override, the chain-level value (High) is used."""
        ledger = _make_ledger(tmp_path)
        try:
            pkg = build_evidence_package(ledger, operator=_OPERATOR)
            assert pkg.legal_admissibility == "High"
        finally:
            ledger.close()

    def test_override_admissible(self, tmp_path):
        ledger = _make_ledger(tmp_path)
        try:
            pkg = build_evidence_package(
                ledger,
                operator=_OPERATOR,
                legal_admissibility_override=LegalAdmissibility.Admissible,
            )
            assert pkg.legal_admissibility == "Admissible"
        finally:
            ledger.close()

    def test_override_conditional(self, tmp_path):
        ledger = _make_ledger(tmp_path)
        try:
            pkg = build_evidence_package(
                ledger,
                operator=_OPERATOR,
                legal_admissibility_override=LegalAdmissibility.Conditional,
            )
            assert pkg.legal_admissibility == "Conditional"
        finally:
            ledger.close()

    def test_override_compromised(self, tmp_path):
        ledger = _make_ledger(tmp_path)
        try:
            pkg = build_evidence_package(
                ledger,
                operator=_OPERATOR,
                legal_admissibility_override=LegalAdmissibility.Compromised,
            )
            assert pkg.legal_admissibility == "Compromised"
        finally:
            ledger.close()

    def test_default_justification_is_empty(self, tmp_path):
        ledger = _make_ledger(tmp_path)
        try:
            pkg = build_evidence_package(ledger, operator=_OPERATOR)
            assert pkg.legal_admissibility_justification == ""
        finally:
            ledger.close()

    def test_justification_stored(self, tmp_path):
        ledger = _make_ledger(tmp_path)
        try:
            justification = "Expert re-verification by Dr. Smith; CASE-2026-042"
            pkg = build_evidence_package(
                ledger,
                operator=_OPERATOR,
                legal_admissibility_override=LegalAdmissibility.Admissible,
                legal_admissibility_justification=justification,
            )
            assert pkg.legal_admissibility_justification == justification
        finally:
            ledger.close()

    def test_justification_in_to_dict(self, tmp_path):
        ledger = _make_ledger(tmp_path)
        try:
            pkg = build_evidence_package(
                ledger,
                operator=_OPERATOR,
                legal_admissibility_override=LegalAdmissibility.Conditional,
                legal_admissibility_justification="WAL gap at 03:00 UTC",
            )
            d = pkg.to_dict()
            assert d["legal_admissibility_justification"] == "WAL gap at 03:00 UTC"
        finally:
            ledger.close()

    def test_override_changes_seal(self, tmp_path):
        """Different override values produce different integrity seals."""
        ledger = _make_ledger(tmp_path, nodes=1)
        try:
            pkg_no_override = build_evidence_package(ledger, operator=_OPERATOR)
            pkg_override = build_evidence_package(
                ledger,
                operator=_OPERATOR,
                legal_admissibility_override=LegalAdmissibility.Conditional,
            )
            assert pkg_no_override.integrity_seal != pkg_override.integrity_seal
        finally:
            ledger.close()

    def test_justification_covered_by_seal(self, tmp_path):
        """Tampering with justification invalidates the seal."""
        ledger = _make_ledger(tmp_path)
        try:
            pkg = build_evidence_package(
                ledger,
                operator=_OPERATOR,
                legal_admissibility_override=LegalAdmissibility.Admissible,
                legal_admissibility_justification="original justification",
            )
            d = pkg.to_dict()
            d["legal_admissibility_justification"] = "tampered justification"
            assert verify_seal(d) is False
        finally:
            ledger.close()

    def test_tampered_admissibility_fails_seal(self, tmp_path):
        """Tampering with the legal_admissibility field invalidates the seal."""
        ledger = _make_ledger(tmp_path)
        try:
            pkg = build_evidence_package(
                ledger,
                operator=_OPERATOR,
                legal_admissibility_override=LegalAdmissibility.Admissible,
            )
            d = pkg.to_dict()
            d["legal_admissibility"] = "Compromised"
            assert verify_seal(d) is False
        finally:
            ledger.close()

    def test_override_seal_is_valid(self, tmp_path):
        """Package with override still passes verify_seal."""
        ledger = _make_ledger(tmp_path)
        try:
            pkg = build_evidence_package(
                ledger,
                operator=_OPERATOR,
                legal_admissibility_override=LegalAdmissibility.Compromised,
                legal_admissibility_justification="chain break at node 7; CASE-99",
            )
            assert verify_seal(pkg.to_dict()) is True
        finally:
            ledger.close()

    def test_justification_without_override(self, tmp_path):
        """Justification alone (without override) is stored and covered by seal."""
        ledger = _make_ledger(tmp_path)
        try:
            pkg = build_evidence_package(
                ledger,
                operator=_OPERATOR,
                legal_admissibility_justification="Routine compliance export",
            )
            assert pkg.legal_admissibility_justification == "Routine compliance export"
            assert verify_seal(pkg.to_dict()) is True
        finally:
            ledger.close()

    def test_json_roundtrip_preserves_override(self, tmp_path):
        """Override and justification survive JSON serialization."""
        ledger = _make_ledger(tmp_path)
        try:
            pkg = build_evidence_package(
                ledger,
                operator=_OPERATOR,
                legal_admissibility_override=LegalAdmissibility.Conditional,
                legal_admissibility_justification="Partial WAL coverage",
            )
            reloaded = json.loads(json.dumps(pkg.to_dict()))
            assert reloaded["legal_admissibility"] == "Conditional"
            assert reloaded["legal_admissibility_justification"] == "Partial WAL coverage"
            assert verify_seal(reloaded) is True
        finally:
            ledger.close()

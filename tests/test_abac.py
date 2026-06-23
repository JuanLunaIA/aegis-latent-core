# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for ABAC IL5/IL6 compartmentalization (aegis.auth.abac)."""

from __future__ import annotations

import pytest

from aegis.auth.abac import (
    ABACConfigError,
    ABACDecision,
    ABACPolicyEngine,
    ClassificationLevel,
    SecurityLabel,
    SubjectAttributes,
    classification_for_impact_level,
)

# ── ClassificationLevel ───────────────────────────────────────────────────────


class TestClassificationLevel:
    def test_ordering(self):
        assert ClassificationLevel.UNCLASSIFIED < ClassificationLevel.CUI
        assert ClassificationLevel.CUI < ClassificationLevel.CONFIDENTIAL
        assert ClassificationLevel.CONFIDENTIAL < ClassificationLevel.SECRET
        assert ClassificationLevel.SECRET < ClassificationLevel.TOP_SECRET

    def test_from_name_exact(self):
        assert ClassificationLevel.from_name("SECRET") is ClassificationLevel.SECRET

    def test_from_name_case_insensitive(self):
        assert ClassificationLevel.from_name("secret") is ClassificationLevel.SECRET

    def test_from_name_with_spaces(self):
        assert ClassificationLevel.from_name("top secret") is ClassificationLevel.TOP_SECRET

    def test_from_name_alias(self):
        assert ClassificationLevel.from_name("TS") is ClassificationLevel.TOP_SECRET
        assert ClassificationLevel.from_name("U") is ClassificationLevel.UNCLASSIFIED

    def test_from_name_unknown_raises(self):
        with pytest.raises(ABACConfigError):
            ClassificationLevel.from_name("COSMIC")


class TestImpactLevelMapping:
    def test_il6_is_secret(self):
        assert classification_for_impact_level(6) is ClassificationLevel.SECRET

    def test_il5_is_cui(self):
        assert classification_for_impact_level(5) is ClassificationLevel.CUI

    def test_il4_is_cui(self):
        assert classification_for_impact_level(4) is ClassificationLevel.CUI

    def test_il2_is_unclassified(self):
        assert classification_for_impact_level(2) is ClassificationLevel.UNCLASSIFIED

    def test_unknown_il_raises(self):
        with pytest.raises(ABACConfigError):
            classification_for_impact_level(7)


# ── SecurityLabel ─────────────────────────────────────────────────────────────


class TestSecurityLabel:
    def test_dominates_higher_classification(self):
        high = SecurityLabel(ClassificationLevel.SECRET)
        low = SecurityLabel(ClassificationLevel.CUI)
        assert high.dominates(low)
        assert not low.dominates(high)

    def test_dominates_equal(self):
        a = SecurityLabel(ClassificationLevel.SECRET)
        b = SecurityLabel(ClassificationLevel.SECRET)
        assert a.dominates(b)

    def test_dominates_requires_compartment_superset(self):
        high = SecurityLabel(ClassificationLevel.SECRET, frozenset({"CRYPTO"}))
        more = SecurityLabel(ClassificationLevel.SECRET, frozenset({"CRYPTO", "SIGINT"}))
        assert more.dominates(high)
        assert not high.dominates(more)

    def test_label_frozen(self):
        from dataclasses import FrozenInstanceError

        label = SecurityLabel(ClassificationLevel.SECRET)
        with pytest.raises(FrozenInstanceError):
            label.classification = ClassificationLevel.CUI  # type: ignore[misc]


# ── can_read: Bell-LaPadula simple security (no read up) ──────────────────────


class TestCanReadClassification:
    def _engine(self) -> ABACPolicyEngine:
        return ABACPolicyEngine(home_affiliation="USA")

    def _subject(self, clearance: ClassificationLevel, **kw) -> SubjectAttributes:
        kw.setdefault("affiliations", frozenset({"USA"}))
        return SubjectAttributes(clearance=clearance, **kw)

    def test_equal_level_allowed(self):
        e = self._engine()
        d = e.can_read(
            self._subject(ClassificationLevel.SECRET),
            SecurityLabel(ClassificationLevel.SECRET),
        )
        assert d.allowed

    def test_higher_clearance_allowed(self):
        e = self._engine()
        d = e.can_read(
            self._subject(ClassificationLevel.TOP_SECRET),
            SecurityLabel(ClassificationLevel.SECRET),
        )
        assert d.allowed

    def test_read_up_denied(self):
        e = self._engine()
        d = e.can_read(
            self._subject(ClassificationLevel.CUI),
            SecurityLabel(ClassificationLevel.SECRET),
        )
        assert not d.allowed
        assert "no read up" in d.reason

    def test_decision_carries_classification(self):
        e = self._engine()
        d = e.can_read(
            self._subject(ClassificationLevel.SECRET),
            SecurityLabel(ClassificationLevel.SECRET),
        )
        assert d.classification == "SECRET"

    def test_decision_bool_protocol(self):
        e = self._engine()
        d = e.can_read(
            self._subject(ClassificationLevel.SECRET),
            SecurityLabel(ClassificationLevel.SECRET),
        )
        assert bool(d) is True


# ── can_read: need-to-know compartments ───────────────────────────────────────


class TestCanReadCompartments:
    def _engine(self) -> ABACPolicyEngine:
        return ABACPolicyEngine()

    def test_matching_compartment_allowed(self):
        e = self._engine()
        subject = SubjectAttributes(
            ClassificationLevel.SECRET,
            compartments=frozenset({"CRYPTO"}),
            affiliations=frozenset({"USA"}),
        )
        label = SecurityLabel(ClassificationLevel.SECRET, frozenset({"CRYPTO"}))
        assert e.can_read(subject, label).allowed

    def test_missing_compartment_denied(self):
        e = self._engine()
        subject = SubjectAttributes(
            ClassificationLevel.SECRET,
            compartments=frozenset(),
            affiliations=frozenset({"USA"}),
        )
        label = SecurityLabel(ClassificationLevel.SECRET, frozenset({"CRYPTO"}))
        d = e.can_read(subject, label)
        assert not d.allowed
        assert "need-to-know" in d.reason

    def test_superset_compartments_allowed(self):
        e = self._engine()
        subject = SubjectAttributes(
            ClassificationLevel.SECRET,
            compartments=frozenset({"CRYPTO", "SIGINT", "HUMINT"}),
            affiliations=frozenset({"USA"}),
        )
        label = SecurityLabel(ClassificationLevel.SECRET, frozenset({"CRYPTO", "SIGINT"}))
        assert e.can_read(subject, label).allowed

    def test_partial_compartments_denied(self):
        e = self._engine()
        subject = SubjectAttributes(
            ClassificationLevel.SECRET,
            compartments=frozenset({"CRYPTO"}),
            affiliations=frozenset({"USA"}),
        )
        label = SecurityLabel(ClassificationLevel.SECRET, frozenset({"CRYPTO", "SIGINT"}))
        d = e.can_read(subject, label)
        assert not d.allowed
        assert "SIGINT" in d.reason


# ── can_read: dissemination controls (REL TO / NOFORN) ────────────────────────


class TestCanReadReleasability:
    def _engine(self) -> ABACPolicyEngine:
        return ABACPolicyEngine(home_affiliation="USA")

    def test_no_rel_marking_home_affiliation_allowed(self):
        e = self._engine()
        subject = SubjectAttributes(ClassificationLevel.SECRET, affiliations=frozenset({"USA"}))
        label = SecurityLabel(ClassificationLevel.SECRET)
        assert e.can_read(subject, label).allowed

    def test_no_rel_marking_foreign_denied(self):
        e = self._engine()
        subject = SubjectAttributes(ClassificationLevel.SECRET, affiliations=frozenset({"GBR"}))
        label = SecurityLabel(ClassificationLevel.SECRET)
        d = e.can_read(subject, label)
        assert not d.allowed
        assert "REL TO" in d.reason

    def test_noforn_home_allowed(self):
        e = self._engine()
        subject = SubjectAttributes(ClassificationLevel.SECRET, affiliations=frozenset({"USA"}))
        label = SecurityLabel(ClassificationLevel.SECRET, releasable_to=frozenset({"NOFORN"}))
        assert e.can_read(subject, label).allowed

    def test_noforn_foreign_denied(self):
        e = self._engine()
        subject = SubjectAttributes(ClassificationLevel.SECRET, affiliations=frozenset({"FVEY"}))
        label = SecurityLabel(ClassificationLevel.SECRET, releasable_to=frozenset({"NOFORN"}))
        d = e.can_read(subject, label)
        assert not d.allowed
        assert "NOFORN" in d.reason

    def test_rel_to_authorized_affiliation_allowed(self):
        e = self._engine()
        subject = SubjectAttributes(ClassificationLevel.SECRET, affiliations=frozenset({"FVEY"}))
        label = SecurityLabel(ClassificationLevel.SECRET, releasable_to=frozenset({"USA", "FVEY"}))
        assert e.can_read(subject, label).allowed

    def test_rel_to_unauthorized_affiliation_denied(self):
        e = self._engine()
        subject = SubjectAttributes(ClassificationLevel.SECRET, affiliations=frozenset({"GBR"}))
        label = SecurityLabel(ClassificationLevel.SECRET, releasable_to=frozenset({"USA", "FVEY"}))
        d = e.can_read(subject, label)
        assert not d.allowed
        assert "not authorized" in d.reason


# ── can_write: Bell-LaPadula star property (no write down) ────────────────────


class TestCanWrite:
    def _engine(self) -> ABACPolicyEngine:
        return ABACPolicyEngine()

    def test_write_up_allowed(self):
        e = self._engine()
        subject = SubjectAttributes(ClassificationLevel.CUI)
        sink = SecurityLabel(ClassificationLevel.SECRET)
        assert e.can_write(subject, sink).allowed

    def test_write_equal_allowed(self):
        e = self._engine()
        subject = SubjectAttributes(ClassificationLevel.SECRET)
        sink = SecurityLabel(ClassificationLevel.SECRET)
        assert e.can_write(subject, sink).allowed

    def test_write_down_denied(self):
        e = self._engine()
        subject = SubjectAttributes(ClassificationLevel.SECRET)
        sink = SecurityLabel(ClassificationLevel.CUI)
        d = e.can_write(subject, sink)
        assert not d.allowed
        assert "no write down" in d.reason


# ── can_flow: source → sink ───────────────────────────────────────────────────


class TestCanFlow:
    def _engine(self) -> ABACPolicyEngine:
        return ABACPolicyEngine()

    def test_flow_up_allowed(self):
        e = self._engine()
        source = SecurityLabel(ClassificationLevel.CUI)
        sink = SecurityLabel(ClassificationLevel.SECRET)
        assert e.can_flow(source, sink).allowed

    def test_flow_down_denied(self):
        e = self._engine()
        source = SecurityLabel(ClassificationLevel.SECRET)
        sink = SecurityLabel(ClassificationLevel.CUI)
        d = e.can_flow(source, sink)
        assert not d.allowed
        assert "does not dominate" in d.reason

    def test_flow_compartment_loss_denied(self):
        e = self._engine()
        source = SecurityLabel(ClassificationLevel.SECRET, frozenset({"CRYPTO"}))
        sink = SecurityLabel(ClassificationLevel.SECRET, frozenset())
        assert not e.can_flow(source, sink).allowed

    def test_flow_compartment_preserved_allowed(self):
        e = self._engine()
        source = SecurityLabel(ClassificationLevel.SECRET, frozenset({"CRYPTO"}))
        sink = SecurityLabel(ClassificationLevel.SECRET, frozenset({"CRYPTO", "SIGINT"}))
        assert e.can_flow(source, sink).allowed


# ── endpoint_accredited: IL5/IL6 endpoint mediation ───────────────────────────


class TestEndpointAccreditation:
    def _engine(self) -> ABACPolicyEngine:
        return ABACPolicyEngine()

    def test_il6_processes_secret(self):
        e = self._engine()
        data = SecurityLabel(ClassificationLevel.SECRET)
        assert e.endpoint_accredited(data, 6).allowed

    def test_il5_cannot_process_secret(self):
        e = self._engine()
        data = SecurityLabel(ClassificationLevel.SECRET)
        d = e.endpoint_accredited(data, 5)
        assert not d.allowed
        assert "cannot process" in d.reason

    def test_il5_processes_cui(self):
        e = self._engine()
        data = SecurityLabel(ClassificationLevel.CUI)
        assert e.endpoint_accredited(data, 5).allowed

    def test_il2_cannot_process_cui(self):
        e = self._engine()
        data = SecurityLabel(ClassificationLevel.CUI)
        assert not e.endpoint_accredited(data, 2).allowed

    def test_unknown_il_raises(self):
        e = self._engine()
        data = SecurityLabel(ClassificationLevel.CUI)
        with pytest.raises(ABACConfigError):
            e.endpoint_accredited(data, 99)


# ── Integrated IL5/IL6 scenarios ──────────────────────────────────────────────


class TestIL5IL6Scenarios:
    def test_il6_secret_crypto_usa_full_chain(self):
        """A US SECRET//CRYPTO request: cleared subject + IL6 endpoint succeeds."""
        e = ABACPolicyEngine(home_affiliation="USA")
        subject = SubjectAttributes(
            clearance=ClassificationLevel.SECRET,
            compartments=frozenset({"CRYPTO"}),
            affiliations=frozenset({"USA"}),
        )
        data = SecurityLabel(
            classification=ClassificationLevel.SECRET,
            compartments=frozenset({"CRYPTO"}),
            releasable_to=frozenset({"NOFORN"}),
        )
        assert e.can_read(subject, data).allowed
        assert e.endpoint_accredited(data, 6).allowed
        # Response must not be written down to a CUI (IL5) channel.
        assert not e.can_write(subject, SecurityLabel(ClassificationLevel.CUI)).allowed

    def test_il5_subject_blocked_from_secret(self):
        """An IL5-only (CUI-cleared) subject cannot read SECRET data."""
        e = ABACPolicyEngine()
        subject = SubjectAttributes(
            clearance=ClassificationLevel.CUI,
            affiliations=frozenset({"USA"}),
        )
        data = SecurityLabel(ClassificationLevel.SECRET)
        assert not e.can_read(subject, data).allowed

    def test_coalition_release_flow(self):
        """REL TO FVEY data is readable by an FVEY partner but not an unlisted nation."""
        e = ABACPolicyEngine(home_affiliation="USA")
        data = SecurityLabel(ClassificationLevel.SECRET, releasable_to=frozenset({"USA", "FVEY"}))
        fvey = SubjectAttributes(ClassificationLevel.SECRET, affiliations=frozenset({"FVEY"}))
        other = SubjectAttributes(ClassificationLevel.SECRET, affiliations=frozenset({"DEU"}))
        assert e.can_read(fvey, data).allowed
        assert not e.can_read(other, data).allowed

    def test_decision_is_abacdecision_type(self):
        e = ABACPolicyEngine()
        d = e.can_read(
            SubjectAttributes(ClassificationLevel.SECRET, affiliations=frozenset({"USA"})),
            SecurityLabel(ClassificationLevel.SECRET),
        )
        assert isinstance(d, ABACDecision)

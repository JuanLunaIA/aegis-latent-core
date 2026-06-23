# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.auth.abac — Attribute-Based Access Control for IL5/IL6 compartmentalization.

Implements classification-aware, need-to-know access mediation for DoD Impact
Level 5 (CUI / NSS) and Impact Level 6 (SECRET) data handling, following the
Bell-LaPadula confidentiality model:

* **Simple Security Property** ("no read up") — a subject may read a resource
  only when its clearance *dominates* the resource classification.
* **★-Property** ("no write down") — a subject may write to a sink only when the
  sink classification dominates the subject's effective level, preventing
  classified data from flowing into a lower-classified channel.
* **Need-to-know** — beyond level dominance, the subject must hold every
  compartment / control marking carried by the resource label.
* **Dissemination controls** — REL TO / NOFORN style releasability: when a label
  restricts release to a set of nationalities/affiliations, the subject must be
  a member of that set.

This module is deliberately standalone and side-effect-free so it can mediate
both the inference request path (is this subject cleared to process this data?)
and the response path (may this output be released to this channel?).  It
composes with :mod:`aegis.auth.rbac`: RBAC answers *what action* a subject may
perform; ABAC answers *which data* the subject may touch.

Usage::

    engine = ABACPolicyEngine()
    subject = SubjectAttributes(
        clearance=ClassificationLevel.SECRET,
        compartments=frozenset({"CRYPTO"}),
        affiliations=frozenset({"USA"}),
    )
    label = SecurityLabel(
        classification=ClassificationLevel.SECRET,
        compartments=frozenset({"CRYPTO"}),
        releasable_to=frozenset({"USA", "FVEY"}),
    )
    assert engine.can_read(subject, label).allowed
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class ABACConfigError(ValueError):
    """Raised when an ABAC label/attribute configuration is invalid."""


class ClassificationLevel(IntEnum):
    """Hierarchical sensitivity levels (higher value = more sensitive).

    The integer ordering encodes dominance: ``A`` dominates ``B`` when
    ``A >= B``.  ``CUI`` (Controlled Unclassified Information) sits between
    ``UNCLASSIFIED`` and the classified tiers.
    """

    UNCLASSIFIED = 0
    CUI = 1
    CONFIDENTIAL = 2
    SECRET = 3
    TOP_SECRET = 4

    @classmethod
    def from_name(cls, name: str) -> ClassificationLevel:
        """Parse a case-insensitive level name (spaces/hyphens tolerated)."""
        key = name.strip().upper().replace(" ", "_").replace("-", "_")
        aliases = {
            "U": cls.UNCLASSIFIED,
            "UNCLAS": cls.UNCLASSIFIED,
            "C": cls.CONFIDENTIAL,
            "S": cls.SECRET,
            "TS": cls.TOP_SECRET,
            "TOPSECRET": cls.TOP_SECRET,
        }
        if key in cls.__members__:
            return cls[key]
        if key in aliases:
            return aliases[key]
        raise ABACConfigError(f"unknown classification level: {name!r}")


# DoD Cloud Computing SRG Impact Level → minimum data classification it carries.
# IL2/IL4 handle CUI; IL5 handles CUI + National Security Systems (still up to
# the CUI/UNCLASSIFIED-NSS boundary); IL6 handles information classified up to
# SECRET.  We map each IL to the *highest* classification it is accredited for.
_IL_TO_CLASSIFICATION: dict[int, ClassificationLevel] = {
    2: ClassificationLevel.UNCLASSIFIED,
    4: ClassificationLevel.CUI,
    5: ClassificationLevel.CUI,
    6: ClassificationLevel.SECRET,
}


def classification_for_impact_level(impact_level: int) -> ClassificationLevel:
    """Return the highest classification a given DoD Impact Level is accredited for."""
    if impact_level not in _IL_TO_CLASSIFICATION:
        raise ABACConfigError(
            f"unsupported DoD Impact Level: IL{impact_level} "
            f"(known: {sorted(_IL_TO_CLASSIFICATION)})"
        )
    return _IL_TO_CLASSIFICATION[impact_level]


@dataclass(frozen=True)
class SecurityLabel:
    """Classification label attached to a resource (request payload, response, sink).

    Parameters
    ----------
    classification:
        The resource's sensitivity level.
    compartments:
        Need-to-know markers / SCI compartments / SAP nicknames.  A subject must
        hold *all* of these to satisfy need-to-know.
    releasable_to:
        Dissemination control.  Empty frozenset means "no foreign-release
        restriction recorded" (treated as releasable within the accrediting
        organization only — see :meth:`ABACPolicyEngine.can_read`).  A non-empty
        set restricts access to subjects whose affiliations intersect it
        (REL TO).  The sentinel ``"NOFORN"`` may be included to denote no
        foreign release.
    """

    classification: ClassificationLevel
    compartments: frozenset[str] = field(default_factory=frozenset)
    releasable_to: frozenset[str] = field(default_factory=frozenset)

    def dominates(self, other: SecurityLabel) -> bool:
        """True when this label is at least as sensitive as *other* in every dimension."""
        return (
            self.classification >= other.classification and self.compartments >= other.compartments
        )


@dataclass(frozen=True)
class SubjectAttributes:
    """Clearance attributes of an authenticated subject.

    Parameters
    ----------
    clearance:
        The subject's clearance level.
    compartments:
        Compartments / control systems the subject is read-into.
    affiliations:
        Nationality / coalition affiliations (e.g. ``"USA"``, ``"FVEY"``) used
        for REL TO evaluation.
    """

    clearance: ClassificationLevel
    compartments: frozenset[str] = field(default_factory=frozenset)
    affiliations: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True)
class ABACDecision:
    """Outcome of an ABAC mediation, suitable for audit logging."""

    allowed: bool
    reason: str
    classification: str = ""

    def __bool__(self) -> bool:
        return self.allowed


class ABACPolicyEngine:
    """Bell-LaPadula confidentiality engine for compartmented data.

    Stateless; a single instance may be shared across threads.

    Parameters
    ----------
    home_affiliation:
        The accrediting organization's affiliation tag (default ``"USA"``).
        Used when a label carries no explicit ``releasable_to`` set: such data
        is treated as releasable only to subjects sharing ``home_affiliation``
        (a conservative default — absence of a REL marking is not "release to
        all").
    """

    def __init__(self, home_affiliation: str = "USA") -> None:
        self._home = home_affiliation

    # ── Read mediation (no read up + need-to-know + REL TO) ─────────────────

    def can_read(self, subject: SubjectAttributes, label: SecurityLabel) -> ABACDecision:
        """Decide whether *subject* may read data carrying *label*."""
        cls_name = label.classification.name

        # Simple Security Property: no read up.
        if subject.clearance < label.classification:
            return ABACDecision(
                allowed=False,
                reason=(
                    f"clearance {subject.clearance.name} does not dominate "
                    f"classification {cls_name} (no read up)"
                ),
                classification=cls_name,
            )

        # Need-to-know: subject must hold every compartment on the label.
        missing = label.compartments - subject.compartments
        if missing:
            return ABACDecision(
                allowed=False,
                reason=f"missing need-to-know compartment(s): {sorted(missing)}",
                classification=cls_name,
            )

        # Dissemination controls (REL TO / NOFORN).
        rel_decision = self._check_releasability(subject, label, cls_name)
        if rel_decision is not None:
            return rel_decision

        return ABACDecision(
            allowed=True,
            reason=f"clearance dominates {cls_name}; need-to-know and releasability satisfied",
            classification=cls_name,
        )

    def _check_releasability(
        self, subject: SubjectAttributes, label: SecurityLabel, cls_name: str
    ) -> ABACDecision | None:
        """Return a denial decision if releasability fails, else None."""
        rel = label.releasable_to

        if "NOFORN" in rel:
            if self._home not in subject.affiliations:
                return ABACDecision(
                    allowed=False,
                    reason="label marked NOFORN; subject lacks home affiliation",
                    classification=cls_name,
                )
            return None

        if not rel:
            # No explicit REL marking: releasable only within home organization.
            if self._home not in subject.affiliations:
                return ABACDecision(
                    allowed=False,
                    reason=(
                        "no REL TO marking; data releasable only to "
                        f"{self._home!r}, which the subject lacks"
                    ),
                    classification=cls_name,
                )
            return None

        # Explicit REL TO: subject must share at least one releasable affiliation.
        if not (subject.affiliations & rel):
            return ABACDecision(
                allowed=False,
                reason=(
                    f"REL TO {sorted(rel)}; subject affiliations "
                    f"{sorted(subject.affiliations)} not authorized"
                ),
                classification=cls_name,
            )
        return None

    # ── Write mediation (no write down) ─────────────────────────────────────

    def can_write(self, subject: SubjectAttributes, sink: SecurityLabel) -> ABACDecision:
        """Decide whether *subject* may write into a channel labelled *sink*.

        Enforces the Bell-LaPadula ★-property: the sink must dominate the
        subject's clearance, preventing higher-classified information held by the
        subject from flowing into a lower-classified channel.
        """
        if sink.classification < subject.clearance:
            return ABACDecision(
                allowed=False,
                reason=(
                    f"sink classification {sink.classification.name} is below "
                    f"subject clearance {subject.clearance.name} (no write down)"
                ),
                classification=sink.classification.name,
            )
        return ABACDecision(
            allowed=True,
            reason=f"sink dominates subject clearance {subject.clearance.name}",
            classification=sink.classification.name,
        )

    # ── Flow mediation (source → sink) ──────────────────────────────────────

    def can_flow(self, source: SecurityLabel, sink: SecurityLabel) -> ABACDecision:
        """Decide whether data may flow from *source* into *sink*.

        A flow is permitted only when the sink dominates the source in both
        classification and compartments — i.e. information never moves to a less
        protected container.
        """
        if not sink.dominates(source):
            return ABACDecision(
                allowed=False,
                reason=(
                    f"sink {sink.classification.name}/{sorted(sink.compartments)} "
                    f"does not dominate source "
                    f"{source.classification.name}/{sorted(source.compartments)}"
                ),
                classification=source.classification.name,
            )
        return ABACDecision(
            allowed=True,
            reason="sink dominates source; flow preserves confidentiality",
            classification=source.classification.name,
        )

    # ── Endpoint accreditation ──────────────────────────────────────────────

    def endpoint_accredited(self, data: SecurityLabel, endpoint_impact_level: int) -> ABACDecision:
        """Decide whether an upstream endpoint at *endpoint_impact_level* may
        process *data*.

        The endpoint's accredited classification must dominate the data
        classification (e.g. SECRET data requires an IL6 endpoint).
        """
        accredited = classification_for_impact_level(endpoint_impact_level)
        if accredited < data.classification:
            return ABACDecision(
                allowed=False,
                reason=(
                    f"IL{endpoint_impact_level} endpoint accredited to "
                    f"{accredited.name}; cannot process {data.classification.name} data"
                ),
                classification=data.classification.name,
            )
        return ABACDecision(
            allowed=True,
            reason=(
                f"IL{endpoint_impact_level} endpoint ({accredited.name}) "
                f"accredited for {data.classification.name} data"
            ),
            classification=data.classification.name,
        )

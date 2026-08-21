# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.mifid_record_keeper — MiFID II / Dodd-Frank communication records.

Implements communication and transaction record-keeping for LLM-mediated
financial services interactions, satisfying:

- **MiFID II Article 16(6) / Article 25(1)**: retain records of all services,
  transactions, and communication (phone, email, electronic messaging) related
  to orders and advice for at least 5 years (7 years for SMCR-scope firms and
  for RTS 6/7 order records).
- **Dodd-Frank Section 727 / CFTC Rule 45.2**: swap transaction and
  communication records for 5 years (or the term of the trade plus 5 years
  for long-dated instruments).
- **SEC Rule 17a-4**: already addressed by ``worm_ledger.py``; referenced here
  for cross-regulation mapping.

Record design
-------------
Full message text is **not** stored — only a SHA-256 content hash.  This
satisfies the record-keeping obligation (the hash is immutable evidence that
a specific message was sent/received at a specific time) while minimising
GDPR/personal-data exposure.  Firms that require full-text retention must add
an encrypted side-channel with a separate key hierarchy.

Usage::

    from aegis.core.mifid_record_keeper import (
        MiFIDRecordKeeper,
        MIFID_ARTICLE_25_FULL,
        CommunicationRecord,
    )

    keeper = MiFIDRecordKeeper()
    rec = keeper.record_communication(
        session_id="sess-abc",
        client_id="client-001",
        model_id="aegis-proxy/claude-3",
        content=user_prompt,
        direction="inbound",
        instrument_scope=["equity", "bond"],
        advice_type="recommendation",
    )
    export = keeper.export_record(rec, signing_key=os.environb[b"AEGIS_SIGNING_KEY"])
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Literal

from aegis.core.worm_ledger import RetentionPolicy

# ── MiFID / Dodd-Frank retention policies ─────────────────────────────────────

MIFID_ARTICLE_25_STANDARD = RetentionPolicy(
    name="MIFID_ART25_5Y",
    accessible_years=5.0,
    total_years=5.0,
    citations=(
        "MiFID II Article 16(6)",
        "MiFID II Article 25(1)",
        "ESMA MiFID II Q&A on investor protection",
    ),
)

MIFID_ARTICLE_25_FULL = RetentionPolicy(
    name="MIFID_ART25_7Y",
    accessible_years=7.0,
    total_years=7.0,
    citations=(
        "MiFID II Article 16(6)",
        "MiFID II Article 25(1)",
        "MiFID II RTS 6 / RTS 7 (order records)",
        "FCA COBS 11.8 (SMCR scope)",
    ),
)

DODD_FRANK_SWAP = RetentionPolicy(
    name="DODD_FRANK_SWAP_5Y",
    accessible_years=5.0,
    total_years=5.0,
    citations=(
        "Dodd-Frank Section 727",
        "CFTC Rule 45.2",
        "SEC Rule 17a-4",
    ),
)

# ── Type aliases ──────────────────────────────────────────────────────────────

Direction = Literal["inbound", "outbound"]
AdviceType = Literal["information", "recommendation", "order_instruction", "execution"]

# ── CommunicationRecord ───────────────────────────────────────────────────────


@dataclass
class CommunicationRecord:
    """Immutable record of one LLM-mediated communication event.

    Attributes
    ----------
    record_id:
        Unique UUID for this record (stable across exports).
    recorded_at:
        Unix timestamp (UTC) when the record was created.
    session_id:
        Proxy session identifier (ties this record to the WAL audit chain).
    client_id:
        Opaque client/tenant identifier (not PII — use a pseudonym/hash for
        GDPR compliance).
    model_id:
        Model identifier (e.g. ``"aegis-proxy/claude-3-sonnet"``).
    direction:
        ``"inbound"`` (client → proxy) or ``"outbound"`` (proxy → client).
    content_sha256:
        SHA-256 hex digest of the original message content.  Proves the
        exact content of the message without retaining the full text.
    content_length:
        Byte length of the original content (additional forensic datum).
    instrument_scope:
        Financial instrument types detected or declared in scope
        (e.g. ``["equity", "bond", "derivative"]``).
    advice_type:
        Nature of the communication: ``"information"``,
        ``"recommendation"``, ``"order_instruction"``, ``"execution"``.
    retention_policy:
        Name of the :class:`~aegis.core.worm_ledger.RetentionPolicy` applied.
    retain_until:
        Unix timestamp after which the record may be purged.
    record_hmac:
        HMAC-SHA256 (hex) of the canonical JSON of this record's fields
        (excluding ``record_hmac`` itself), keyed by ``AEGIS_SIGNING_KEY``.
    """

    record_id: str
    recorded_at: float
    session_id: str
    client_id: str
    model_id: str
    direction: Direction
    content_sha256: str
    content_length: int
    instrument_scope: list[str]
    advice_type: AdviceType
    retention_policy: str
    retain_until: float
    record_hmac: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "record_id": self.record_id,
            "recorded_at": self.recorded_at,
            "session_id": self.session_id,
            "client_id": self.client_id,
            "model_id": self.model_id,
            "direction": self.direction,
            "content_sha256": self.content_sha256,
            "content_length": self.content_length,
            "instrument_scope": self.instrument_scope,
            "advice_type": self.advice_type,
            "retention_policy": self.retention_policy,
            "retain_until": self.retain_until,
            "record_hmac": self.record_hmac,
        }

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def verify_hmac(self, signing_key: bytes) -> bool:
        """Return True if the record's HMAC is valid for *signing_key*."""
        expected = _compute_record_hmac(self, signing_key)
        return hmac.compare_digest(expected, self.record_hmac)


# ── FinancialCommsExport ──────────────────────────────────────────────────────


@dataclass
class FinancialCommsExport:
    """Technical export: a set of communication records plus bundle HMAC.

    A qualified reviewer may assess the export for a regulator or archival
    process. Local sealed WAL segments do not establish regulatory WORM.

    Attributes
    ----------
    export_id:
        Unique UUID for this export bundle.
    generated_at:
        Unix timestamp when the bundle was produced.
    regulatory_frameworks:
        List of framework names covered (e.g. ``["MiFID II", "Dodd-Frank"]``).
    records:
        The individual :class:`CommunicationRecord` instances.
    bundle_hmac:
        HMAC-SHA256 (hex) over the canonical JSON of all records, keyed by
        ``AEGIS_SIGNING_KEY``.
    """

    export_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    generated_at: float = field(default_factory=time.time)
    regulatory_frameworks: list[str] = field(default_factory=list)
    records: list[CommunicationRecord] = field(default_factory=list)
    bundle_hmac: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "export_id": self.export_id,
            "generated_at": self.generated_at,
            "regulatory_frameworks": self.regulatory_frameworks,
            "records": [r.to_dict() for r in self.records],
            "bundle_hmac": self.bundle_hmac,
        }

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def verify_bundle_hmac(self, signing_key: bytes) -> bool:
        """Return True if the bundle HMAC is valid for *signing_key*."""
        expected = _compute_bundle_hmac(self.records, signing_key)
        return hmac.compare_digest(expected, self.bundle_hmac)


# ── HMAC helpers ──────────────────────────────────────────────────────────────


def _hmac_hex(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def _compute_record_hmac(rec: CommunicationRecord, key: bytes) -> str:
    d = rec.to_dict()
    d.pop("record_hmac", None)
    canonical = json.dumps(d, sort_keys=True, separators=(",", ":")).encode()
    return _hmac_hex(key, canonical)


def _compute_bundle_hmac(records: list[CommunicationRecord], key: bytes) -> str:
    items = [r.to_dict() for r in records]
    for item in items:
        item.pop("record_hmac", None)
    canonical = json.dumps(
        sorted(items, key=lambda d: d["record_id"]),
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return _hmac_hex(key, canonical)


# ── MiFIDRecordKeeper ─────────────────────────────────────────────────────────


class MiFIDRecordKeeper:
    """Records MiFID II / Dodd-Frank communication events for LLM-mediated trades.

    Parameters
    ----------
    default_policy:
        Default :class:`~aegis.core.worm_ledger.RetentionPolicy` applied when
        ``record_communication`` is called without an explicit policy.
        Defaults to :data:`MIFID_ARTICLE_25_FULL` (7-year, RTS 6/7 scope).
    """

    def __init__(
        self,
        default_policy: RetentionPolicy = MIFID_ARTICLE_25_FULL,
    ) -> None:
        self._default_policy = default_policy
        self._records: list[CommunicationRecord] = []

    def record_communication(
        self,
        *,
        session_id: str,
        client_id: str,
        model_id: str,
        content: str | bytes,
        direction: Direction = "inbound",
        instrument_scope: list[str] | None = None,
        advice_type: AdviceType = "information",
        policy: RetentionPolicy | None = None,
        signing_key: bytes | None = None,
        now: float | None = None,
    ) -> CommunicationRecord:
        """Record one communication event and return the signed record.

        Parameters
        ----------
        session_id:
            Proxy session identifier.
        client_id:
            Opaque client/tenant pseudonym (must not be raw PII).
        model_id:
            Model and version string.
        content:
            The original message bytes or string.  Only a SHA-256 digest is
            stored; the original is never retained by this method.
        direction:
            ``"inbound"`` (request) or ``"outbound"`` (response).
        instrument_scope:
            Financial instruments in scope.  May be empty for non-trade
            interactions.
        advice_type:
            Nature of the communication per MiFID II Article 25(1).
        policy:
            Override the instance default retention policy.
        signing_key:
            AEGIS_SIGNING_KEY bytes for HMAC-SHA256.  If ``None``, the
            ``record_hmac`` field is left empty and must be filled in later
            via :meth:`sign_record`.
        now:
            Override for current timestamp (tests only).

        Returns
        -------
        CommunicationRecord
            Signed (or unsigned if *signing_key* is None) record.
        """
        ts = now if now is not None else time.time()
        pol = policy if policy is not None else self._default_policy
        raw = content if isinstance(content, bytes) else content.encode("utf-8")
        content_hash = hashlib.sha256(raw).hexdigest()

        rec = CommunicationRecord(
            record_id=str(uuid.uuid4()),
            recorded_at=ts,
            session_id=session_id,
            client_id=client_id,
            model_id=model_id,
            direction=direction,
            content_sha256=content_hash,
            content_length=len(raw),
            instrument_scope=list(instrument_scope or []),
            advice_type=advice_type,
            retention_policy=pol.name,
            retain_until=pol.purge_eligible_at(ts),
        )

        if signing_key is not None:
            rec.record_hmac = _compute_record_hmac(rec, signing_key)

        self._records.append(rec)
        return rec

    def sign_record(self, rec: CommunicationRecord, signing_key: bytes) -> CommunicationRecord:
        """(Re-)sign a record and return it with the updated HMAC."""
        rec.record_hmac = _compute_record_hmac(rec, signing_key)
        return rec

    def export(
        self,
        signing_key: bytes,
        frameworks: list[str] | None = None,
        records: list[CommunicationRecord] | None = None,
    ) -> FinancialCommsExport:
        """Build a signed :class:`FinancialCommsExport` bundle.

        Parameters
        ----------
        signing_key:
            AEGIS_SIGNING_KEY bytes.
        frameworks:
            Regulatory framework names to declare in the export.  Defaults
            to the citations from the default policy.
        records:
            Explicit record list.  Defaults to all records held by this
            keeper instance.

        Returns
        -------
        FinancialCommsExport
        """
        recs = records if records is not None else list(self._records)
        fw = frameworks if frameworks is not None else list(self._default_policy.citations)
        bundle_hmac = _compute_bundle_hmac(recs, signing_key)
        return FinancialCommsExport(
            regulatory_frameworks=fw,
            records=recs,
            bundle_hmac=bundle_hmac,
        )

    @property
    def records(self) -> list[CommunicationRecord]:
        """All records held by this keeper (in insertion order)."""
        return list(self._records)

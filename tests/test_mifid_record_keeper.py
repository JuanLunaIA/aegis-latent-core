# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for MiFID II / Dodd-Frank communication record keeper
(aegis.core.mifid_record_keeper)."""

from __future__ import annotations

import hashlib
import json
import time

import pytest

from aegis.core.mifid_record_keeper import (
    DODD_FRANK_SWAP,
    MIFID_ARTICLE_25_FULL,
    MIFID_ARTICLE_25_STANDARD,
    CommunicationRecord,
    FinancialCommsExport,
    MiFIDRecordKeeper,
)

_KEY = b"test-aegis-signing-key-32-padded"
_ALT_KEY = b"other-key-32-bytes-padded0000000"


# ── Retention policies ────────────────────────────────────────────────────────


class TestRetentionPolicies:
    def test_mifid_standard_is_5y(self):
        assert MIFID_ARTICLE_25_STANDARD.total_years == 5.0
        assert MIFID_ARTICLE_25_STANDARD.accessible_years == 5.0

    def test_mifid_full_is_7y(self):
        assert MIFID_ARTICLE_25_FULL.total_years == 7.0
        assert MIFID_ARTICLE_25_FULL.accessible_years == 7.0

    def test_dodd_frank_is_5y(self):
        assert DODD_FRANK_SWAP.total_years == 5.0
        assert "Dodd-Frank Section 727" in DODD_FRANK_SWAP.citations

    def test_mifid_full_citations(self):
        assert "MiFID II Article 25(1)" in MIFID_ARTICLE_25_FULL.citations
        assert "MiFID II RTS 6 / RTS 7 (order records)" in MIFID_ARTICLE_25_FULL.citations

    def test_policies_are_frozen(self):
        with pytest.raises((AttributeError, TypeError)):
            MIFID_ARTICLE_25_FULL.total_years = 99  # type: ignore[misc]


# ── CommunicationRecord ───────────────────────────────────────────────────────


class TestCommunicationRecord:
    def _make(self, **kwargs) -> CommunicationRecord:
        keeper = MiFIDRecordKeeper()
        defaults = dict(
            session_id="sess-1",
            client_id="client-A",
            model_id="model-x",
            content="buy 100 ACME shares",
            direction="inbound",
            advice_type="order_instruction",
            signing_key=_KEY,
        )
        defaults.update(kwargs)
        return keeper.record_communication(**defaults)

    def test_content_sha256_is_hex_string(self):
        rec = self._make()
        assert len(rec.content_sha256) == 64
        int(rec.content_sha256, 16)  # must parse as hex

    def test_content_sha256_matches_original(self):
        content = "sell 200 GLOBEX futures"
        rec = self._make(content=content)
        expected = hashlib.sha256(content.encode()).hexdigest()
        assert rec.content_sha256 == expected

    def test_content_not_stored_in_record(self):
        rec = self._make(content="top secret trade instruction")
        d = rec.to_dict()
        for v in d.values():
            if isinstance(v, str):
                assert "top secret" not in v

    def test_record_id_is_uuid(self):
        import uuid

        rec = self._make()
        uuid.UUID(rec.record_id)  # raises ValueError if not a valid UUID

    def test_recorded_at_is_recent(self):
        before = time.time()
        rec = self._make()
        after = time.time()
        assert before <= rec.recorded_at <= after

    def test_direction_stored(self):
        rec = self._make(direction="outbound")
        assert rec.direction == "outbound"

    def test_instrument_scope_stored(self):
        rec = self._make(instrument_scope=["equity", "bond"])
        assert "equity" in rec.instrument_scope
        assert "bond" in rec.instrument_scope

    def test_advice_type_stored(self):
        rec = self._make(advice_type="recommendation")
        assert rec.advice_type == "recommendation"

    def test_retention_policy_name_stored(self):
        rec = self._make()
        assert rec.retention_policy == MIFID_ARTICLE_25_FULL.name

    def test_retain_until_is_in_future(self):
        rec = self._make()
        assert rec.retain_until > time.time()

    def test_retain_until_is_7y_from_now_for_full_policy(self):
        now = 1_000_000.0
        rec = self._make(now=now)
        expected = MIFID_ARTICLE_25_FULL.purge_eligible_at(now)
        assert abs(rec.retain_until - expected) < 1.0

    def test_content_length_matches_bytes(self):
        content = "trade instruction"
        rec = self._make(content=content)
        assert rec.content_length == len(content.encode("utf-8"))

    def test_bytes_content_accepted(self):
        rec = self._make(content=b"binary payload")
        assert rec.content_length == len(b"binary payload")

    def test_to_dict_contains_all_fields(self):
        rec = self._make()
        d = rec.to_dict()
        for field in [
            "record_id",
            "recorded_at",
            "session_id",
            "client_id",
            "model_id",
            "direction",
            "content_sha256",
            "content_length",
            "instrument_scope",
            "advice_type",
            "retention_policy",
            "retain_until",
            "record_hmac",
        ]:
            assert field in d

    def test_to_json_is_valid_json(self):
        rec = self._make()
        parsed = json.loads(rec.to_json())
        assert isinstance(parsed, dict)

    def test_record_hmac_is_64_char_hex(self):
        rec = self._make(signing_key=_KEY)
        assert len(rec.record_hmac) == 64

    def test_verify_hmac_valid_key(self):
        rec = self._make(signing_key=_KEY)
        assert rec.verify_hmac(_KEY) is True

    def test_verify_hmac_wrong_key(self):
        rec = self._make(signing_key=_KEY)
        assert rec.verify_hmac(_ALT_KEY) is False

    def test_no_signing_key_leaves_hmac_empty(self):
        keeper = MiFIDRecordKeeper()
        rec = keeper.record_communication(
            session_id="s",
            client_id="c",
            model_id="m",
            content="msg",
        )
        assert rec.record_hmac == ""

    def test_sign_record_fills_hmac(self):
        keeper = MiFIDRecordKeeper()
        rec = keeper.record_communication(
            session_id="s",
            client_id="c",
            model_id="m",
            content="msg",
        )
        keeper.sign_record(rec, _KEY)
        assert len(rec.record_hmac) == 64
        assert rec.verify_hmac(_KEY)

    def test_custom_policy_overrides_default(self):
        keeper = MiFIDRecordKeeper()
        rec = keeper.record_communication(
            session_id="s",
            client_id="c",
            model_id="m",
            content="swap contract",
            policy=DODD_FRANK_SWAP,
            signing_key=_KEY,
        )
        assert rec.retention_policy == DODD_FRANK_SWAP.name


# ── MiFIDRecordKeeper ─────────────────────────────────────────────────────────


class TestMiFIDRecordKeeper:
    def test_default_policy_is_mifid_full(self):
        keeper = MiFIDRecordKeeper()
        assert keeper._default_policy is MIFID_ARTICLE_25_FULL

    def test_custom_default_policy(self):
        keeper = MiFIDRecordKeeper(default_policy=DODD_FRANK_SWAP)
        rec = keeper.record_communication(
            session_id="s",
            client_id="c",
            model_id="m",
            content="swap",
            signing_key=_KEY,
        )
        assert rec.retention_policy == DODD_FRANK_SWAP.name

    def test_records_accumulate(self):
        keeper = MiFIDRecordKeeper()
        keeper.record_communication(session_id="s1", client_id="c", model_id="m", content="a")
        keeper.record_communication(session_id="s2", client_id="c", model_id="m", content="b")
        assert len(keeper.records) == 2

    def test_records_property_returns_copy(self):
        keeper = MiFIDRecordKeeper()
        keeper.record_communication(session_id="s", client_id="c", model_id="m", content="a")
        r = keeper.records
        r.clear()
        assert len(keeper.records) == 1  # original unaffected


# ── FinancialCommsExport ──────────────────────────────────────────────────────


class TestFinancialCommsExport:
    def _make_keeper_with_records(self, n: int = 2) -> MiFIDRecordKeeper:
        keeper = MiFIDRecordKeeper()
        for i in range(n):
            keeper.record_communication(
                session_id=f"sess-{i}",
                client_id="client-A",
                model_id="model-x",
                content=f"message {i}",
                signing_key=_KEY,
            )
        return keeper

    def test_export_returns_financial_comms_export(self):
        keeper = self._make_keeper_with_records()
        ex = keeper.export(_KEY)
        assert isinstance(ex, FinancialCommsExport)

    def test_export_record_count_matches(self):
        keeper = self._make_keeper_with_records(3)
        ex = keeper.export(_KEY)
        assert len(ex.records) == 3

    def test_export_bundle_hmac_64_char(self):
        keeper = self._make_keeper_with_records()
        ex = keeper.export(_KEY)
        assert len(ex.bundle_hmac) == 64

    def test_export_verify_bundle_hmac_valid(self):
        keeper = self._make_keeper_with_records()
        ex = keeper.export(_KEY)
        assert ex.verify_bundle_hmac(_KEY) is True

    def test_export_verify_bundle_hmac_wrong_key(self):
        keeper = self._make_keeper_with_records()
        ex = keeper.export(_KEY)
        assert ex.verify_bundle_hmac(_ALT_KEY) is False

    def test_tampered_record_fails_bundle_hmac(self):
        keeper = self._make_keeper_with_records()
        ex = keeper.export(_KEY)
        ex.records[0].content_length = 99999
        assert ex.verify_bundle_hmac(_KEY) is False

    def test_export_regulatory_frameworks_from_policy(self):
        keeper = MiFIDRecordKeeper()
        ex = keeper.export(_KEY)
        assert "MiFID II Article 25(1)" in ex.regulatory_frameworks

    def test_export_custom_frameworks(self):
        keeper = self._make_keeper_with_records()
        ex = keeper.export(_KEY, frameworks=["MiFID II", "Dodd-Frank"])
        assert "Dodd-Frank" in ex.regulatory_frameworks

    def test_export_to_json_round_trip(self):
        keeper = self._make_keeper_with_records()
        ex = keeper.export(_KEY)
        parsed = json.loads(ex.to_json())
        assert isinstance(parsed, dict)
        assert "export_id" in parsed
        assert "records" in parsed
        assert len(parsed["records"]) == 2

    def test_export_generated_at_is_recent(self):
        before = time.time()
        keeper = self._make_keeper_with_records()
        ex = keeper.export(_KEY)
        after = time.time()
        assert before <= ex.generated_at <= after

    def test_export_empty_keeper(self):
        keeper = MiFIDRecordKeeper()
        ex = keeper.export(_KEY)
        assert ex.records == []
        assert len(ex.bundle_hmac) == 64

    def test_different_keys_produce_different_bundle_hmac(self):
        keeper = self._make_keeper_with_records()
        ex1 = keeper.export(_KEY)
        ex2 = keeper.export(_ALT_KEY)
        assert ex1.bundle_hmac != ex2.bundle_hmac

    def test_export_explicit_records(self):
        keeper = self._make_keeper_with_records(3)
        only_first = keeper.records[:1]
        ex = keeper.export(_KEY, records=only_first)
        assert len(ex.records) == 1

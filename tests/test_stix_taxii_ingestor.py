# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
# Copyright (c) 2026 Juan Luna. All rights reserved.
"""Tests for aegis.core.stix_taxii_ingestor."""

from __future__ import annotations

from unittest.mock import patch

from aegis.core.stix_taxii_ingestor import (
    IngestResult,
    PromptIndicator,
    STIXTAXIIIngestor,
    TaxiiCollection,
    extract_waf_pattern,
    ingest_bundle,
    is_prompt_indicator,
    link_relationships,
    parse_indicator,
    parse_stix_bundle,
)

# ── STIX fixture helpers ──────────────────────────────────────────────────────


def _indicator(
    stix_id: str = "indicator--aaaa",
    name: str = "Test Jailbreak",
    pattern: str = "[url:value MATCHES 'ignore previous instructions']",
    labels: list[str] | None = None,
) -> dict:
    return {
        "type": "indicator",
        "id": stix_id,
        "name": name,
        "description": "A test adversarial prompt indicator",
        "pattern": pattern,
        "labels": labels if labels is not None else ["aegis-adversarial-prompt"],
        "created": "2026-01-01T00:00:00.000Z",
        "modified": "2026-01-02T00:00:00.000Z",
    }


def _bundle(objects: list[dict]) -> dict:
    return {"type": "bundle", "id": "bundle--0001", "objects": objects}


def _attack_pattern(ap_id: str = "attack-pattern--bb01", name: str = "Jailbreak") -> dict:
    return {"type": "attack-pattern", "id": ap_id, "name": name}


def _relationship(src: str, tgt: str, rel_type: str = "indicates") -> dict:
    return {
        "type": "relationship",
        "id": "relationship--cc01",
        "relationship_type": rel_type,
        "source_ref": src,
        "target_ref": tgt,
    }


# ── parse_stix_bundle ─────────────────────────────────────────────────────────


class TestParseSTIXBundle:
    def test_bundle_envelope(self):
        bundle = _bundle([_indicator()])
        objects = parse_stix_bundle(bundle)
        assert len(objects) == 1

    def test_bare_objects_list(self):
        data = {"objects": [_indicator(), _indicator(stix_id="indicator--bbbb")]}
        objects = parse_stix_bundle(data)
        assert len(objects) == 2

    def test_empty_bundle(self):
        assert parse_stix_bundle({"type": "bundle", "objects": []}) == []

    def test_missing_objects_key(self):
        assert parse_stix_bundle({"type": "bundle"}) == []

    def test_non_bundle_without_objects(self):
        assert parse_stix_bundle({"type": "attack-pattern"}) == []

    def test_returns_list(self):
        result = parse_stix_bundle(_bundle([_indicator()]))
        assert isinstance(result, list)


# ── is_prompt_indicator ───────────────────────────────────────────────────────


class TestIsPromptIndicator:
    def test_aegis_label(self):
        assert is_prompt_indicator(_indicator(labels=["aegis-adversarial-prompt"])) is True

    def test_jailbreak_label(self):
        assert is_prompt_indicator(_indicator(labels=["jailbreak"])) is True

    def test_prompt_injection_label(self):
        assert is_prompt_indicator(_indicator(labels=["prompt-injection"])) is True

    def test_adversarial_prompt_label(self):
        assert is_prompt_indicator(_indicator(labels=["adversarial-prompt"])) is True

    def test_wrong_type(self):
        obj = {"type": "malware", "labels": ["aegis-adversarial-prompt"]}
        assert is_prompt_indicator(obj) is False

    def test_no_matching_labels(self):
        obj = _indicator(labels=["benign", "unrelated"])
        assert is_prompt_indicator(obj) is False

    def test_empty_labels(self):
        obj = _indicator(labels=[])
        assert is_prompt_indicator(obj) is False

    def test_attack_pattern_type_not_indicator(self):
        obj = _attack_pattern()
        obj["labels"] = ["jailbreak"]
        assert is_prompt_indicator(obj) is False


# ── extract_waf_pattern ───────────────────────────────────────────────────────


class TestExtractWAFPattern:
    def test_simple_string_literal(self):
        pat = "[url:value MATCHES 'ignore previous instructions']"
        assert extract_waf_pattern(pat) == "ignore previous instructions"

    def test_quoted_string(self):
        pat = "[domain-name:value = 'DAN mode enabled']"
        assert extract_waf_pattern(pat) == "DAN mode enabled"

    def test_no_string_literal_returns_empty(self):
        assert extract_waf_pattern("[file:size > 1000]") == ""

    def test_empty_pattern_returns_empty(self):
        assert extract_waf_pattern("") == ""

    def test_short_literals_ignored(self):
        # Minimum 3-char strings in the regex
        assert extract_waf_pattern("[x:y = 'ab']") == ""

    def test_first_match_returned(self):
        pat = "[x:y = 'first match'] AND [x:z = 'second match']"
        assert extract_waf_pattern(pat) == "first match"

    def test_realistic_stix_pattern(self):
        pat = (
            "[network-traffic:dst_ref.type = 'url' AND url:value MATCHES 'system prompt override']"
        )
        assert extract_waf_pattern(pat) == "url"


# ── parse_indicator ───────────────────────────────────────────────────────────


class TestParseIndicator:
    def test_basic_fields(self):
        obj = _indicator()
        ind = parse_indicator(obj)
        assert ind.stix_id == "indicator--aaaa"
        assert ind.name == "Test Jailbreak"
        assert ind.description == "A test adversarial prompt indicator"
        assert ind.created == "2026-01-01T00:00:00.000Z"
        assert ind.modified == "2026-01-02T00:00:00.000Z"

    def test_waf_pattern_extracted(self):
        ind = parse_indicator(_indicator(pattern="[x:y = 'ignore previous instructions']"))
        assert ind.waf_pattern == "ignore previous instructions"

    def test_labels_copied(self):
        ind = parse_indicator(_indicator(labels=["jailbreak", "prompt-injection"]))
        assert "jailbreak" in ind.labels

    def test_empty_attack_pattern_ids(self):
        ind = parse_indicator(_indicator())
        assert ind.attack_pattern_ids == []

    def test_missing_fields_default(self):
        obj = {"type": "indicator", "id": "indicator--x", "pattern": ""}
        ind = parse_indicator(obj)
        assert ind.name == ""
        assert ind.waf_pattern == ""


# ── link_relationships ────────────────────────────────────────────────────────


class TestLinkRelationships:
    def test_links_attack_pattern(self):
        ind_obj = _indicator(stix_id="indicator--1")
        ap_obj = _attack_pattern(ap_id="attack-pattern--ap1")
        rel_obj = _relationship("indicator--1", "attack-pattern--ap1")
        indicators = [parse_indicator(ind_obj)]
        link_relationships(indicators, [ind_obj, ap_obj, rel_obj])
        assert "attack-pattern--ap1" in indicators[0].attack_pattern_ids

    def test_ignores_non_indicates_relationships(self):
        ind_obj = _indicator(stix_id="indicator--1")
        rel_obj = _relationship("indicator--1", "attack-pattern--ap1", rel_type="uses")
        indicators = [parse_indicator(ind_obj)]
        link_relationships(indicators, [rel_obj])
        assert indicators[0].attack_pattern_ids == []

    def test_ignores_relationships_with_unknown_source(self):
        rel_obj = _relationship("indicator--UNKNOWN", "attack-pattern--ap1")
        indicators = [parse_indicator(_indicator(stix_id="indicator--1"))]
        link_relationships(indicators, [rel_obj])
        assert indicators[0].attack_pattern_ids == []

    def test_non_attack_pattern_target_not_linked(self):
        ind_obj = _indicator(stix_id="indicator--1")
        rel_obj = _relationship("indicator--1", "malware--m1")
        indicators = [parse_indicator(ind_obj)]
        link_relationships(indicators, [rel_obj])
        assert indicators[0].attack_pattern_ids == []


# ── PromptIndicator ───────────────────────────────────────────────────────────


class TestPromptIndicator:
    def _ind(self):
        return PromptIndicator(
            stix_id="indicator--abc",
            name="Test",
            description="Desc",
            pattern="[x:y = 'test']",
            labels=["jailbreak"],
            waf_pattern="test",
            attack_pattern_ids=["attack-pattern--1"],
        )

    def test_to_dict_keys(self):
        d = self._ind().to_dict()
        assert set(d.keys()) == {
            "stix_id",
            "name",
            "description",
            "pattern",
            "labels",
            "waf_pattern",
            "attack_pattern_ids",
            "created",
            "modified",
        }

    def test_to_dict_values(self):
        d = self._ind().to_dict()
        assert d["stix_id"] == "indicator--abc"
        assert d["waf_pattern"] == "test"


# ── TaxiiCollection ───────────────────────────────────────────────────────────


class TestTaxiiCollection:
    def test_to_dict(self):
        c = TaxiiCollection(id="col-1", title="Jailbreak Feed", can_read=True)
        d = c.to_dict()
        assert d["id"] == "col-1"
        assert d["can_read"] is True


# ── IngestResult ──────────────────────────────────────────────────────────────


class TestIngestResult:
    def test_defaults(self):
        r = IngestResult()
        assert r.indicators == []
        assert r.waf_patterns == []
        assert r.total_stix_objects == 0
        assert r.success is True
        assert r.errors == []

    def test_to_dict_keys(self):
        r = IngestResult()
        d = r.to_dict()
        assert set(d.keys()) == {
            "success",
            "total_stix_objects",
            "indicator_count",
            "waf_pattern_count",
            "collections_queried",
            "errors",
            "indicators",
            "waf_patterns",
        }

    def test_to_dict_counts(self):
        ind = parse_indicator(_indicator())
        ind.waf_pattern = "jailbreak pattern"
        r = IngestResult(indicators=[ind], waf_patterns=["jailbreak pattern"])
        d = r.to_dict()
        assert d["indicator_count"] == 1
        assert d["waf_pattern_count"] == 1


# ── ingest_bundle (standalone helper) ────────────────────────────────────────


class TestIngestBundle:
    def test_extracts_indicators(self):
        bundle = _bundle([_indicator(), _indicator(stix_id="indicator--bbbb")])
        result = ingest_bundle(bundle)
        assert len(result.indicators) == 2

    def test_non_indicator_objects_skipped(self):
        bundle = _bundle([_attack_pattern(), _indicator()])
        result = ingest_bundle(bundle)
        assert len(result.indicators) == 1

    def test_waf_patterns_deduplicated(self):
        ind1 = _indicator(stix_id="indicator--1", pattern="[x:y = 'same pattern']")
        ind2 = _indicator(stix_id="indicator--2", pattern="[x:y = 'same pattern']")
        bundle = _bundle([ind1, ind2])
        result = ingest_bundle(bundle)
        assert result.waf_patterns.count("same pattern") == 1

    def test_total_stix_objects_counted(self):
        bundle = _bundle([_indicator(), _attack_pattern()])
        result = ingest_bundle(bundle)
        assert result.total_stix_objects == 2

    def test_empty_bundle(self):
        result = ingest_bundle({"type": "bundle", "objects": []})
        assert result.indicators == []
        assert result.waf_patterns == []

    def test_relationships_linked(self):
        ind_obj = _indicator(stix_id="indicator--1")
        ap_obj = _attack_pattern(ap_id="attack-pattern--x")
        rel_obj = _relationship("indicator--1", "attack-pattern--x")
        bundle = _bundle([ind_obj, ap_obj, rel_obj])
        result = ingest_bundle(bundle)
        assert "attack-pattern--x" in result.indicators[0].attack_pattern_ids


# ── STIXTAXIIIngestor construction ───────────────────────────────────────────


class TestIngestorConstruction:
    def test_taxii_url_from_param(self):
        t = STIXTAXIIIngestor(taxii_url="https://taxii.example.com/taxii2/")
        assert t.taxii_url == "https://taxii.example.com/taxii2"

    def test_taxii_url_from_env(self, monkeypatch):
        monkeypatch.setenv("AEGIS_TAXII_URL", "https://env.taxii.example.com/taxii2")
        t = STIXTAXIIIngestor()
        assert "env.taxii.example.com" in t.taxii_url

    def test_api_token_from_param(self):
        t = STIXTAXIIIngestor(api_token="secret123")  # noqa: S106
        assert t.api_token == "secret123"  # noqa: S105

    def test_api_token_from_env(self, monkeypatch):
        monkeypatch.setenv("AEGIS_TAXII_TOKEN", "envtoken")
        t = STIXTAXIIIngestor()
        assert t.api_token == "envtoken"  # noqa: S105

    def test_collection_id_from_param(self):
        t = STIXTAXIIIngestor(collection_id="col-001")
        assert t.collection_id == "col-001"

    def test_default_timeout(self, monkeypatch):
        monkeypatch.delenv("AEGIS_TAXII_TIMEOUT", raising=False)
        t = STIXTAXIIIngestor()
        assert t.timeout == 15

    def test_timeout_from_param(self):
        t = STIXTAXIIIngestor(timeout=30)
        assert t.timeout == 30

    def test_invalid_timeout_env_uses_default(self, monkeypatch):
        monkeypatch.setenv("AEGIS_TAXII_TIMEOUT", "not_an_int")
        t = STIXTAXIIIngestor()
        assert t.timeout == 15

    def test_default_max_objects(self, monkeypatch):
        monkeypatch.delenv("AEGIS_TAXII_MAX_OBJECTS", raising=False)
        t = STIXTAXIIIngestor()
        assert t.max_objects == 1000

    def test_max_objects_from_env(self, monkeypatch):
        monkeypatch.setenv("AEGIS_TAXII_MAX_OBJECTS", "500")
        t = STIXTAXIIIngestor()
        assert t.max_objects == 500

    def test_invalid_max_objects_uses_default(self, monkeypatch):
        monkeypatch.setenv("AEGIS_TAXII_MAX_OBJECTS", "bad")
        t = STIXTAXIIIngestor()
        assert t.max_objects == 1000


# ── STIXTAXIIIngestor.ingest() — no URL ──────────────────────────────────────


class TestIngestNoURL:
    def test_ingest_without_url_fails(self, monkeypatch):
        monkeypatch.delenv("AEGIS_TAXII_URL", raising=False)
        t = STIXTAXIIIngestor(taxii_url="")
        result = t.ingest()
        assert result.success is False
        assert "not configured" in result.errors[0]


# ── STIXTAXIIIngestor.ingest() — mocked HTTP ─────────────────────────────────


class TestIngestMocked:
    def _ingestor(self):
        return STIXTAXIIIngestor(
            taxii_url="https://taxii.example.com/taxii2", collection_id="col-1"
        )

    def _discovery_resp(self):
        return {"api_roots": ["https://taxii.example.com/api1/"]}

    def _collections_resp(self):
        return {"collections": [{"id": "col-1", "title": "Jailbreaks", "can_read": True}]}

    def _objects_resp(self):
        return _bundle([_indicator(), _attack_pattern()])

    def test_successful_ingest(self):
        t = self._ingestor()

        def mock_get(url):
            if "/collections/col-1/objects" in url:
                return self._objects_resp()
            if "/collections/" in url:
                return self._collections_resp()
            return self._discovery_resp()

        with patch.object(t, "_get_json", side_effect=mock_get):
            result = t.ingest()

        assert result.success is True
        assert len(result.indicators) == 1
        assert result.total_stix_objects == 2

    def test_waf_patterns_populated(self):
        t = self._ingestor()
        objects_resp = _bundle([_indicator(pattern="[x:y = 'jailbreak payload']")])

        with patch.object(t, "_get_json", return_value=objects_resp):
            result = t.ingest(api_root="https://taxii.example.com/api1")

        assert "jailbreak payload" in result.waf_patterns

    def test_discovery_failure_returns_error(self):
        t = STIXTAXIIIngestor(taxii_url="https://taxii.example.com/taxii2")
        with patch.object(t, "_get_json", side_effect=OSError("connection refused")):
            result = t.ingest()
        assert result.success is False
        assert "Discovery failed" in result.errors[0]

    def test_collection_auto_selected(self):
        t = STIXTAXIIIngestor(taxii_url="https://taxii.example.com/taxii2")

        def mock_get(url):
            if "/collections/" in url and "objects" in url:
                return _bundle([_indicator()])
            if "/collections/" in url:
                return self._collections_resp()
            return self._discovery_resp()

        with patch.object(t, "_get_json", side_effect=mock_get):
            result = t.ingest()

        assert result.success is True
        assert "col-1" in result.collections_queried

    def test_no_readable_collections_fails(self):
        t = STIXTAXIIIngestor(taxii_url="https://taxii.example.com/taxii2")

        def mock_get(url):
            if "/collections/" in url:
                return {"collections": [{"id": "x", "title": "x", "can_read": False}]}
            return self._discovery_resp()

        with patch.object(t, "_get_json", side_effect=mock_get):
            result = t.ingest()

        assert result.success is False
        assert "No readable collections" in result.errors[0]

    def test_object_fetch_failure_returns_error(self):
        t = self._ingestor()

        def mock_get(url):
            if "objects" in url:
                raise OSError("fetch failed")
            return self._collections_resp()

        with patch.object(t, "_get_json", side_effect=mock_get):
            result = t.ingest(api_root="https://taxii.example.com/api1")

        assert result.success is False
        assert "Object fetch failed" in result.errors[0]

    def test_non_prompt_indicators_skipped(self):
        t = self._ingestor()
        objects_resp = _bundle([_indicator(labels=["benign"]), _indicator()])

        with patch.object(t, "_get_json", return_value=objects_resp):
            result = t.ingest(api_root="https://taxii.example.com/api1")

        assert len(result.indicators) == 1

    def test_duplicate_waf_patterns_deduplicated(self):
        t = self._ingestor()
        pat = "[x:y = 'same payload']"
        objects_resp = _bundle(
            [
                _indicator(stix_id="indicator--1", pattern=pat),
                _indicator(stix_id="indicator--2", pattern=pat),
            ]
        )

        with patch.object(t, "_get_json", return_value=objects_resp):
            result = t.ingest(api_root="https://taxii.example.com/api1")

        assert result.waf_patterns.count("same payload") == 1


# ── STIXTAXIIIngestor.list_collections() ─────────────────────────────────────


class TestListCollections:
    def test_returns_collections(self):
        t = STIXTAXIIIngestor(taxii_url="https://taxii.example.com/taxii2")
        mock_resp = {
            "collections": [
                {"id": "col-1", "title": "Feed A", "can_read": True},
                {"id": "col-2", "title": "Feed B", "can_read": False},
            ]
        }
        with patch.object(t, "_get_json", return_value=mock_resp):
            cols = t.list_collections("https://taxii.example.com/api1")
        assert len(cols) == 2
        assert cols[0].id == "col-1"
        assert cols[1].can_read is False

    def test_filters_out_collections_without_id(self):
        t = STIXTAXIIIngestor()
        mock_resp = {"collections": [{"title": "No ID"}]}
        with patch.object(t, "_get_json", return_value=mock_resp):
            cols = t.list_collections("https://taxii.example.com/api1")
        assert cols == []

    def test_empty_collections(self):
        t = STIXTAXIIIngestor()
        with patch.object(t, "_get_json", return_value={"collections": []}):
            cols = t.list_collections("https://taxii.example.com/api1")
        assert cols == []


# ── STIXTAXIIIngestor.ingest_bundle() ────────────────────────────────────────


class TestIngestorBundle:
    def test_ingest_bundle_no_http(self):
        t = STIXTAXIIIngestor()
        bundle = _bundle([_indicator()])
        result = t.ingest_bundle(bundle)
        assert result.success is True
        assert len(result.indicators) == 1
        assert result.total_stix_objects == 1

    def test_ingest_bundle_waf_patterns(self):
        t = STIXTAXIIIngestor()
        bundle = _bundle([_indicator(pattern="[x:y = 'bypass all filters']")])
        result = t.ingest_bundle(bundle)
        assert "bypass all filters" in result.waf_patterns

    def test_ingest_bundle_headers_use_token(self):
        t = STIXTAXIIIngestor(api_token="mytoken")  # noqa: S106
        headers = t._headers()
        assert "Authorization" in headers
        assert "mytoken" in headers["Authorization"]

    def test_ingest_bundle_no_token_no_auth_header(self):
        t = STIXTAXIIIngestor(api_token="")
        headers = t._headers()
        assert "Authorization" not in headers

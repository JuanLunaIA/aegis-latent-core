"""
test_ti_sharing.py — Tests for aegis.core.ti_sharing
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest

from aegis.core.ti_sharing import (
    AnonymizedThreatEvent,
    TIAnonymizer,
    TISharer,
    TISharingConfig,
)

# ── Fixtures ─────────────────────────────────────────────────────────────────


def _make_waf_event(
    score: float = 0.9,
    reason: str = "prompt injection attempt",
    tenant_id: str = "tenant-secret-123",
    provider: str = "openai",
    request_ip: str = "52.1.2.3",
    mitre_tactic: str | None = "TA0043",
    timestamp: float | None = None,
) -> dict[str, Any]:
    return {
        "score": score,
        "reason": reason,
        "tenant_id": tenant_id,
        "provider": provider,
        "request_ip": request_ip,
        "timestamp": timestamp or 1_750_000_000.0,
        "mitre_tactic": mitre_tactic,
    }


@pytest.fixture
def config() -> TISharingConfig:
    return TISharingConfig(
        enabled=True,
        isac_endpoint="https://isac.example.com/taxii/collections/1234/objects/",
        isac_api_key="test-secret-key",
        min_score_threshold=0.6,
        include_provider_type=True,
        include_geography=True,
    )


@pytest.fixture
def anonymizer(config: TISharingConfig) -> TIAnonymizer:
    return TIAnonymizer(config)


@pytest.fixture
def sharer(config: TISharingConfig) -> TISharer:
    return TISharer(config)


# ── TIAnonymizer.hash_pattern ────────────────────────────────────────────────


def test_hash_pattern_is_deterministic() -> None:
    h1 = TIAnonymizer.hash_pattern("prompt injection attack")
    h2 = TIAnonymizer.hash_pattern("prompt injection attack")
    assert h1 == h2


def test_hash_pattern_different_inputs_different_hashes() -> None:
    h1 = TIAnonymizer.hash_pattern("prompt injection")
    h2 = TIAnonymizer.hash_pattern("jailbreak attempt")
    assert h1 != h2


def test_hash_pattern_case_insensitive() -> None:
    h1 = TIAnonymizer.hash_pattern("PROMPT INJECTION")
    h2 = TIAnonymizer.hash_pattern("prompt injection")
    assert h1 == h2


def test_hash_pattern_strips_punctuation() -> None:
    h1 = TIAnonymizer.hash_pattern("prompt! injection!!!")
    h2 = TIAnonymizer.hash_pattern("prompt injection")
    assert h1 == h2


def test_hash_pattern_returns_64_char_hex() -> None:
    h = TIAnonymizer.hash_pattern("test pattern")
    assert len(h) == 64
    assert all(c in "0123456789abcdef" for c in h)


def test_hash_pattern_is_not_original_pattern() -> None:
    pattern = "prompt injection attempt"
    h = TIAnonymizer.hash_pattern(pattern)
    assert pattern not in h
    assert h != pattern


# ── TIAnonymizer.bucket_timestamp ────────────────────────────────────────────


def test_bucket_timestamp_rounds_to_hour() -> None:
    # 2026-06-23T19:30:00Z → should bucket to 2026-06-23T19:00Z
    ts = 1_750_000_000.0  # some Unix timestamp
    bucketed = TIAnonymizer.bucket_timestamp(ts, bucket_seconds=3600)
    # Verify it ends with :00Z (minute zero)
    assert bucketed.endswith(":00Z")


def test_bucket_timestamp_same_bucket_for_same_hour() -> None:
    # Two timestamps in the same hour should produce identical buckets
    ts1 = 1_750_000_000.0
    ts2 = ts1 + 1800.0  # 30 minutes later, same hour
    b1 = TIAnonymizer.bucket_timestamp(ts1)
    b2 = TIAnonymizer.bucket_timestamp(ts2)
    assert b1 == b2


def test_bucket_timestamp_different_hours_different_bucket() -> None:
    ts1 = 1_750_000_000.0
    ts2 = ts1 + 7200.0  # 2 hours later
    b1 = TIAnonymizer.bucket_timestamp(ts1)
    b2 = TIAnonymizer.bucket_timestamp(ts2)
    assert b1 != b2


def test_bucket_timestamp_iso8601_format() -> None:
    ts = 1_750_000_000.0
    bucketed = TIAnonymizer.bucket_timestamp(ts)
    # Should match YYYY-MM-DDTHH:MMZ
    assert "T" in bucketed
    assert bucketed.endswith("Z")


# ── TIAnonymizer.anonymize ────────────────────────────────────────────────────


def test_anonymize_returns_none_for_low_score(anonymizer: TIAnonymizer) -> None:
    event = _make_waf_event(score=0.3)
    result = anonymizer.anonymize(event)
    assert result is None


def test_anonymize_returns_none_at_threshold_boundary(anonymizer: TIAnonymizer) -> None:
    event = _make_waf_event(score=0.59)
    result = anonymizer.anonymize(event)
    assert result is None


def test_anonymize_returns_event_for_high_score(anonymizer: TIAnonymizer) -> None:
    event = _make_waf_event(score=0.9)
    result = anonymizer.anonymize(event)
    assert result is not None
    assert isinstance(result, AnonymizedThreatEvent)


def test_anonymize_returns_event_at_threshold(anonymizer: TIAnonymizer) -> None:
    event = _make_waf_event(score=0.6)
    result = anonymizer.anonymize(event)
    assert result is not None


def test_anonymize_attack_pattern_hash_is_not_original(anonymizer: TIAnonymizer) -> None:
    reason = "prompt injection attempt with DAN jailbreak"
    event = _make_waf_event(score=0.9, reason=reason)
    result = anonymizer.anonymize(event)
    assert result is not None
    assert reason not in result.attack_pattern_hash
    assert result.attack_pattern_hash != reason


def test_anonymize_tenant_id_not_in_result(anonymizer: TIAnonymizer) -> None:
    event = _make_waf_event(score=0.9, tenant_id="super-secret-tenant-id")
    result = anonymizer.anonymize(event)
    assert result is not None
    # Verify tenant_id does not appear anywhere in the result dict
    result_dict = result.to_dict()
    result_str = str(result_dict)
    assert "super-secret-tenant-id" not in result_str


def test_anonymize_no_raw_ip_in_result(anonymizer: TIAnonymizer) -> None:
    event = _make_waf_event(score=0.9, request_ip="203.0.113.42")
    result = anonymizer.anonymize(event)
    assert result is not None
    result_dict = result.to_dict()
    result_str = str(result_dict)
    assert "203.0.113.42" not in result_str


def test_anonymize_event_type_prompt_injection(anonymizer: TIAnonymizer) -> None:
    event = _make_waf_event(score=0.9, reason="prompt injection bypass")
    result = anonymizer.anonymize(event)
    assert result is not None
    assert result.event_type == "prompt_injection"


def test_anonymize_event_type_waf_critical(anonymizer: TIAnonymizer) -> None:
    event = _make_waf_event(score=0.95, reason="data exfiltration pattern")
    result = anonymizer.anonymize(event)
    assert result is not None
    assert result.event_type == "waf_critical"


def test_anonymize_event_type_waf_soft(anonymizer: TIAnonymizer) -> None:
    event = _make_waf_event(score=0.65, reason="suspicious keyword")
    result = anonymizer.anonymize(event)
    assert result is not None
    assert result.event_type == "waf_soft"


def test_anonymize_known_mitre_tactic_preserved(anonymizer: TIAnonymizer) -> None:
    event = _make_waf_event(score=0.9, mitre_tactic="TA0043")
    result = anonymizer.anonymize(event)
    assert result is not None
    assert result.mitre_tactic == "TA0043"


def test_anonymize_unknown_mitre_tactic_dropped(anonymizer: TIAnonymizer) -> None:
    event = _make_waf_event(score=0.9, mitre_tactic="INVALID-TACTIC")
    result = anonymizer.anonymize(event)
    assert result is not None
    assert result.mitre_tactic is None


def test_anonymize_no_mitre_tactic_when_none(anonymizer: TIAnonymizer) -> None:
    event = _make_waf_event(score=0.9, mitre_tactic=None)
    result = anonymizer.anonymize(event)
    assert result is not None
    assert result.mitre_tactic is None


def test_anonymize_provider_type_included(anonymizer: TIAnonymizer) -> None:
    event = _make_waf_event(score=0.9, provider="openai")
    result = anonymizer.anonymize(event)
    assert result is not None
    assert result.provider_type == "openai"


def test_anonymize_provider_type_excluded_when_config_off() -> None:
    config = TISharingConfig(
        enabled=True,
        min_score_threshold=0.6,
        include_provider_type=False,
    )
    anon = TIAnonymizer(config)
    event = _make_waf_event(score=0.9, provider="openai")
    result = anon.anonymize(event)
    assert result is not None
    assert result.provider_type is None


def test_anonymize_geography_excluded_by_default() -> None:
    config = TISharingConfig(
        enabled=True,
        min_score_threshold=0.6,
        include_geography=False,
    )
    anon = TIAnonymizer(config)
    event = _make_waf_event(score=0.9, request_ip="52.1.2.3")
    result = anon.anonymize(event)
    assert result is not None
    assert result.geography is None


def test_anonymize_geography_included_when_config_on(anonymizer: TIAnonymizer) -> None:
    event = _make_waf_event(score=0.9, request_ip="52.1.2.3")
    result = anonymizer.anonymize(event)
    assert result is not None
    # First octet 52 maps to "US"
    assert result.geography == "US"


def test_anonymize_private_ip_no_geography(anonymizer: TIAnonymizer) -> None:
    event = _make_waf_event(score=0.9, request_ip="10.0.0.1")
    result = anonymizer.anonymize(event)
    assert result is not None
    assert result.geography is None


# ── AnonymizedThreatEvent.to_stix_indicator ───────────────────────────────────


def test_to_stix_indicator_valid_structure(anonymizer: TIAnonymizer) -> None:
    event = _make_waf_event(score=0.9)
    result = anonymizer.anonymize(event)
    assert result is not None
    stix = result.to_stix_indicator()
    assert stix["type"] == "indicator"
    assert stix["spec_version"] == "2.1"


def test_to_stix_indicator_id_format(anonymizer: TIAnonymizer) -> None:
    event = _make_waf_event(score=0.9)
    result = anonymizer.anonymize(event)
    assert result is not None
    stix = result.to_stix_indicator()
    assert stix["id"].startswith("indicator--")
    assert result.event_id in stix["id"]


def test_to_stix_indicator_pattern_contains_hash(anonymizer: TIAnonymizer) -> None:
    event = _make_waf_event(score=0.9)
    result = anonymizer.anonymize(event)
    assert result is not None
    stix = result.to_stix_indicator()
    assert result.attack_pattern_hash in stix["pattern"]


def test_to_stix_indicator_pattern_not_raw_text(anonymizer: TIAnonymizer) -> None:
    reason = "prompt injection attempt with DAN jailbreak"
    event = _make_waf_event(score=0.9, reason=reason)
    result = anonymizer.anonymize(event)
    assert result is not None
    stix = result.to_stix_indicator()
    assert reason not in stix["pattern"]


def test_to_stix_indicator_labels_contain_event_type(anonymizer: TIAnonymizer) -> None:
    event = _make_waf_event(score=0.9, reason="prompt injection")
    result = anonymizer.anonymize(event)
    assert result is not None
    stix = result.to_stix_indicator()
    assert "prompt_injection" in stix["labels"]


# ── TISharer.submit ───────────────────────────────────────────────────────────


def test_submit_returns_true_for_high_score(sharer: TISharer) -> None:
    event = _make_waf_event(score=0.9)
    assert sharer.submit(event) is True


def test_submit_returns_false_for_low_score(sharer: TISharer) -> None:
    event = _make_waf_event(score=0.1)
    assert sharer.submit(event) is False


def test_queue_depth_increases_on_submit(sharer: TISharer) -> None:
    assert sharer.queue_depth() == 0
    sharer.submit(_make_waf_event(score=0.9))
    assert sharer.queue_depth() == 1
    sharer.submit(_make_waf_event(score=0.85))
    assert sharer.queue_depth() == 2


def test_queue_depth_unchanged_for_low_score(sharer: TISharer) -> None:
    sharer.submit(_make_waf_event(score=0.1))
    assert sharer.queue_depth() == 0


# ── TISharer.flush ────────────────────────────────────────────────────────────


def test_flush_noop_when_disabled() -> None:
    config = TISharingConfig(
        enabled=False,
        isac_endpoint="https://isac.example.com/taxii/collections/1234/objects/",
    )
    sharer = TISharer(config)
    sharer.submit(_make_waf_event(score=0.9))
    result = sharer.flush()
    assert result == 0


def test_flush_noop_when_no_endpoint() -> None:
    config = TISharingConfig(enabled=True, isac_endpoint="")
    sharer = TISharer(config)
    sharer.submit(_make_waf_event(score=0.9))
    result = sharer.flush()
    assert result == 0


def test_flush_noop_when_empty_queue(sharer: TISharer) -> None:
    result = sharer.flush()
    assert result == 0


def test_flush_keeps_events_on_network_error(sharer: TISharer) -> None:
    sharer.submit(_make_waf_event(score=0.9))
    # Simulate network failure by patching _http_post to raise
    with patch.object(TISharer, "_http_post", side_effect=RuntimeError("network down")):
        result = sharer.flush()
    assert result == 0
    assert sharer.queue_depth() == 1  # event NOT dropped


def test_flush_clears_queue_on_success(sharer: TISharer) -> None:
    sharer.submit(_make_waf_event(score=0.9))
    with patch.object(TISharer, "_http_post", return_value=True):
        result = sharer.flush()
    assert result == 1
    assert sharer.queue_depth() == 0


# ── TISharer.clear_queue ─────────────────────────────────────────────────────


def test_clear_queue_empties_queue(sharer: TISharer) -> None:
    sharer.submit(_make_waf_event(score=0.9))
    sharer.submit(_make_waf_event(score=0.85))
    assert sharer.queue_depth() == 2
    sharer.clear_queue()
    assert sharer.queue_depth() == 0


# ── TISharer.from_env ─────────────────────────────────────────────────────────


def test_from_env_disabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AEGIS_TI_SHARING_ENABLED", raising=False)
    sharer = TISharer.from_env()
    assert sharer._config.enabled is False


def test_from_env_enabled_true(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGIS_TI_SHARING_ENABLED", "true")
    monkeypatch.setenv("AEGIS_TI_SHARING_ENDPOINT", "https://isac.example.com/")
    sharer = TISharer.from_env()
    assert sharer._config.enabled is True


def test_from_env_enabled_1(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGIS_TI_SHARING_ENABLED", "1")
    sharer = TISharer.from_env()
    assert sharer._config.enabled is True


def test_from_env_api_key_not_in_repr(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGIS_TI_SHARING_ENABLED", "true")
    monkeypatch.setenv("AEGIS_TI_SHARING_API_KEY", "super-secret-api-key")
    sharer = TISharer.from_env()
    repr_str = repr(sharer._config)
    assert "super-secret-api-key" not in repr_str


def test_from_env_api_key_not_in_to_dict(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGIS_TI_SHARING_ENABLED", "true")
    monkeypatch.setenv("AEGIS_TI_SHARING_API_KEY", "super-secret-api-key-xyz")
    sharer = TISharer.from_env()
    # AnonymizedThreatEvent.to_dict() must not expose the API key
    sharer.submit(_make_waf_event(score=0.9))
    event = sharer._queue[0]
    event_dict = event.to_dict()
    event_str = str(event_dict)
    assert "super-secret-api-key-xyz" not in event_str


def test_from_env_min_score(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGIS_TI_SHARING_MIN_SCORE", "0.75")
    sharer = TISharer.from_env()
    assert sharer._config.min_score_threshold == 0.75


def test_from_env_include_geo_false_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AEGIS_TI_SHARING_INCLUDE_GEO", raising=False)
    sharer = TISharer.from_env()
    assert sharer._config.include_geography is False

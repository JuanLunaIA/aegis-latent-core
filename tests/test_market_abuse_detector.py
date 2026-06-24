# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for market-abuse / fraud pattern detector
(aegis.core.market_abuse_detector)."""

from __future__ import annotations

import json
import re
import time

from aegis.core.market_abuse_detector import (
    AbuseMatch,
    AbuseSeverity,
    MarketAbuseDetector,
    MarketAbuseType,
)

_KEY = b"test-aegis-signing-key-32-padded"
_ALT_KEY = b"other-key-32-bytes-padded0000000"


# ── Enumerations ──────────────────────────────────────────────────────────────


class TestEnums:
    def test_abuse_type_values(self):
        assert MarketAbuseType.INSIDER_TRADING == "insider_trading"
        assert MarketAbuseType.SPOOFING == "spoofing"
        assert MarketAbuseType.PUMP_AND_DUMP == "pump_and_dump"
        assert MarketAbuseType.FRONT_RUNNING == "front_running"
        assert MarketAbuseType.WASH_TRADING == "wash_trading"
        assert MarketAbuseType.MARKET_MANIPULATION == "market_manipulation"

    def test_severity_values(self):
        assert AbuseSeverity.HIGH == "high"
        assert AbuseSeverity.MEDIUM == "medium"
        assert AbuseSeverity.LOW == "low"

    def test_types_are_str(self):
        assert isinstance(MarketAbuseType.SPOOFING, str)
        assert isinstance(AbuseSeverity.HIGH, str)


# ── Clean text ────────────────────────────────────────────────────────────────


class TestCleanText:
    def test_clean_prompt_returns_clean(self):
        d = MarketAbuseDetector()
        v = d.scan("What is the current P/E ratio for tech stocks?")
        assert v.clean is True
        assert v.matches == []

    def test_clean_response_returns_clean(self):
        d = MarketAbuseDetector()
        v = d.scan("The Federal Reserve raised rates by 25 basis points.", location="response")
        assert v.clean is True

    def test_clean_exchange_returns_clean(self):
        d = MarketAbuseDetector()
        v = d.scan_exchange("Explain diversification", "Diversification reduces portfolio risk.")
        assert v.clean is True
        assert v.waf_block() is False

    def test_clean_verdict_no_hmac(self):
        d = MarketAbuseDetector()
        v = d.scan("normal text")
        assert v.verdict_hmac == ""


# ── Insider trading detection ─────────────────────────────────────────────────


class TestInsiderTrading:
    def test_mnpi_detected(self):
        d = MarketAbuseDetector()
        v = d.scan("I have MNPI about the upcoming merger.")
        assert not v.clean
        assert any(m.abuse_type == MarketAbuseType.INSIDER_TRADING for m in v.matches)

    def test_material_non_public_detected(self):
        d = MarketAbuseDetector()
        v = d.scan("This is material non-public information: buy now.")
        assert any(m.abuse_type == MarketAbuseType.INSIDER_TRADING for m in v.matches)

    def test_buy_before_announcement_detected(self):
        d = MarketAbuseDetector()
        v = d.scan("Buy shares before the earnings announcement tomorrow.")
        assert any(m.abuse_type == MarketAbuseType.INSIDER_TRADING for m in v.matches)

    def test_before_merger_then_buy_detected(self):
        d = MarketAbuseDetector()
        v = d.scan("We should buy stock before the merger goes public.")
        assert any(m.abuse_type == MarketAbuseType.INSIDER_TRADING for m in v.matches)

    def test_sell_before_press_release_detected(self):
        d = MarketAbuseDetector()
        v = d.scan("Sell your position before the press release.")
        assert any(m.abuse_type == MarketAbuseType.INSIDER_TRADING for m in v.matches)

    def test_dont_tell_buy_detected(self):
        d = MarketAbuseDetector()
        v = d.scan("Don't tell anyone but we should buy before it goes up.")
        assert any(m.abuse_type == MarketAbuseType.INSIDER_TRADING for m in v.matches)

    def test_insider_tip_detected(self):
        d = MarketAbuseDetector()
        v = d.scan("I got an insider tip: sell everything.")
        assert any(m.abuse_type == MarketAbuseType.INSIDER_TRADING for m in v.matches)

    def test_clinical_trial_not_public_medium_severity(self):
        d = MarketAbuseDetector()
        v = d.scan("The clinical trial results are not yet public, great time to buy.")
        matches = [m for m in v.matches if m.abuse_type == MarketAbuseType.INSIDER_TRADING]
        assert any(m.severity == AbuseSeverity.MEDIUM for m in matches)


# ── Spoofing detection ────────────────────────────────────────────────────────


class TestSpoofing:
    def test_spoofing_keyword_detected(self):
        d = MarketAbuseDetector()
        v = d.scan("We need to spoof the order book to move the market.")
        assert any(m.abuse_type == MarketAbuseType.SPOOFING for m in v.matches)

    def test_phantom_order_detected(self):
        d = MarketAbuseDetector()
        v = d.scan("Place phantom orders then withdraw when price moves.")
        assert any(m.abuse_type == MarketAbuseType.SPOOFING for m in v.matches)

    def test_fake_order_detected(self):
        d = MarketAbuseDetector()
        v = d.scan("Submit fake orders to create the appearance of demand.")
        assert any(m.abuse_type == MarketAbuseType.SPOOFING for m in v.matches)

    def test_place_cancel_price_move_detected(self):
        d = MarketAbuseDetector()
        v = d.scan("Place a large order, then cancel it after the price moves.")
        assert any(m.abuse_type == MarketAbuseType.SPOOFING for m in v.matches)

    def test_no_intent_to_execute_detected(self):
        d = MarketAbuseDetector()
        v = d.scan("I have no intention to execute the order; I just want to move the bid.")
        assert any(m.abuse_type == MarketAbuseType.SPOOFING for m in v.matches)


# ── Layering detection ────────────────────────────────────────────────────────


class TestLayering:
    def test_layering_keyword_detected(self):
        d = MarketAbuseDetector()
        v = d.scan("Let's use a layering strategy on the order book.")
        assert any(m.abuse_type == MarketAbuseType.LAYERING for m in v.matches)

    def test_quote_stuffing_detected(self):
        d = MarketAbuseDetector()
        v = d.scan("Quote stuffing will slow down competing algos.")
        assert any(m.abuse_type == MarketAbuseType.LAYERING for m in v.matches)

    def test_multiple_orders_cancel_after_price_detected(self):
        d = MarketAbuseDetector()
        v = d.scan("Place multiple orders then cancel them after price move.")
        assert any(m.abuse_type == MarketAbuseType.LAYERING for m in v.matches)


# ── Pump and dump detection ───────────────────────────────────────────────────


class TestPumpAndDump:
    def test_pump_dump_phrase_detected(self):
        d = MarketAbuseDetector()
        v = d.scan("Classic pump and dump on penny stocks.")
        assert any(m.abuse_type == MarketAbuseType.PUMP_AND_DUMP for m in v.matches)

    def test_inflate_price_then_sell_detected(self):
        d = MarketAbuseDetector()
        v = d.scan("Inflate the price using hype then sell before it drops.")
        assert any(m.abuse_type == MarketAbuseType.PUMP_AND_DUMP for m in v.matches)

    def test_spread_false_news_stock_detected(self):
        d = MarketAbuseDetector()
        v = d.scan("Spread false news about the stock to drive buyers in.")
        assert any(m.abuse_type == MarketAbuseType.PUMP_AND_DUMP for m in v.matches)

    def test_coordinate_buy_then_sell_detected(self):
        d = MarketAbuseDetector()
        v = d.scan("Coordinate buy then we sell when the price peaks.")
        assert any(m.abuse_type == MarketAbuseType.PUMP_AND_DUMP for m in v.matches)

    def test_pump_up_price_sell_detected(self):
        d = MarketAbuseDetector()
        v = d.scan("Pump up the price of this coin and then dump it for profit.")
        assert any(m.abuse_type == MarketAbuseType.PUMP_AND_DUMP for m in v.matches)


# ── Front running detection ───────────────────────────────────────────────────


class TestFrontRunning:
    def test_front_run_keyword_detected(self):
        d = MarketAbuseDetector()
        v = d.scan("We front-run client orders to capture spread.")
        assert any(m.abuse_type == MarketAbuseType.FRONT_RUNNING for m in v.matches)

    def test_front_running_detected(self):
        d = MarketAbuseDetector()
        v = d.scan("This algorithm is designed for front running institutional flows.")
        assert any(m.abuse_type == MarketAbuseType.FRONT_RUNNING for m in v.matches)

    def test_trade_ahead_of_client_detected(self):
        d = MarketAbuseDetector()
        v = d.scan("Trade ahead of the client order to benefit from price impact.")
        assert any(m.abuse_type == MarketAbuseType.FRONT_RUNNING for m in v.matches)

    def test_client_about_to_buy_first_detected(self):
        d = MarketAbuseDetector()
        v = d.scan("The client is about to buy a large block; buy first before them.")
        assert any(m.abuse_type == MarketAbuseType.FRONT_RUNNING for m in v.matches)


# ── Wash trading detection ────────────────────────────────────────────────────


class TestWashTrading:
    def test_wash_trade_keyword_detected(self):
        d = MarketAbuseDetector()
        v = d.scan("Let's do some wash trading to boost volume metrics.")
        assert any(m.abuse_type == MarketAbuseType.WASH_TRADING for m in v.matches)

    def test_artificial_volume_detected(self):
        d = MarketAbuseDetector()
        v = d.scan("This creates artificial volume without real economic activity.")
        assert any(m.abuse_type == MarketAbuseType.WASH_TRADING for m in v.matches)

    def test_buy_sell_same_simultaneously_detected(self):
        d = MarketAbuseDetector()
        v = d.scan("Buy and sell the same token simultaneously to create volume.")
        assert any(m.abuse_type == MarketAbuseType.WASH_TRADING for m in v.matches)


# ── Market manipulation detection ─────────────────────────────────────────────


class TestMarketManipulation:
    def test_corner_the_market_detected(self):
        d = MarketAbuseDetector()
        v = d.scan("The plan is to corner the market in silver futures.")
        assert any(m.abuse_type == MarketAbuseType.MARKET_MANIPULATION for m in v.matches)

    def test_manipulate_price_detected(self):
        d = MarketAbuseDetector()
        v = d.scan("We will manipulate the price of this equity instrument.")
        assert any(m.abuse_type == MarketAbuseType.MARKET_MANIPULATION for m in v.matches)

    def test_artificially_inflate_price_detected(self):
        d = MarketAbuseDetector()
        v = d.scan("Artificially inflate the price before the IPO lock-up expires.")
        assert any(m.abuse_type == MarketAbuseType.MARKET_MANIPULATION for m in v.matches)

    def test_false_impression_of_demand_detected(self):
        d = MarketAbuseDetector()
        v = d.scan("Create a false impression of demand for this stock.")
        assert any(m.abuse_type == MarketAbuseType.MARKET_MANIPULATION for m in v.matches)

    def test_price_fixing_detected(self):
        d = MarketAbuseDetector()
        v = d.scan("We agreed on price-fixing the LIBOR benchmark rate.")
        assert any(m.abuse_type == MarketAbuseType.MARKET_MANIPULATION for m in v.matches)


# ── Verdict properties ────────────────────────────────────────────────────────


class TestVerdictProperties:
    def test_waf_block_true_on_high_severity(self):
        d = MarketAbuseDetector()
        v = d.scan("I have MNPI about the acquisition; buy now.")
        assert v.waf_block() is True

    def test_waf_block_false_on_medium_only(self):
        d = MarketAbuseDetector()
        v = d.scan("Clinical trial results not yet public — interesting timing.")
        if v.matches and all(m.severity == AbuseSeverity.MEDIUM for m in v.matches):
            assert v.waf_block() is False

    def test_waf_block_false_on_clean(self):
        d = MarketAbuseDetector()
        v = d.scan("Standard portfolio diversification advice.")
        assert v.waf_block() is False

    def test_scanned_at_is_recent(self):
        before = time.time()
        d = MarketAbuseDetector()
        v = d.scan("clean text")
        after = time.time()
        assert before <= v.scanned_at <= after

    def test_scanned_at_now_parameter(self):
        d = MarketAbuseDetector()
        v = d.scan("clean text", now=1_000_000.0)
        assert v.scanned_at == 1_000_000.0

    def test_session_id_stored(self):
        d = MarketAbuseDetector()
        v = d.scan("clean", session_id="sess-abc")
        assert v.session_id == "sess-abc"

    def test_location_stored_in_match(self):
        d = MarketAbuseDetector()
        v = d.scan("spoof the order bid", location="response")
        assert all(m.location == "response" for m in v.matches)

    def test_excerpt_limited_to_200_chars(self):
        d = MarketAbuseDetector()
        long_text = "MNPI " + ("x" * 500)
        v = d.scan(long_text)
        for m in v.matches:
            assert len(m.excerpt) <= 200

    def test_to_dict_contains_fields(self):
        d = MarketAbuseDetector()
        v = d.scan("clean")
        dd = v.to_dict()
        for f in ["clean", "matches", "session_id", "scanned_at", "verdict_hmac"]:
            assert f in dd

    def test_to_json_valid(self):
        d = MarketAbuseDetector()
        v = d.scan("clean")
        parsed = json.loads(v.to_json())
        assert isinstance(parsed, dict)


# ── HMAC signing ──────────────────────────────────────────────────────────────


class TestHMACSigning:
    def test_signed_verdict_has_hmac(self):
        d = MarketAbuseDetector()
        v = d.scan("MNPI is great for trading", signing_key=_KEY)
        assert len(v.verdict_hmac) == 64

    def test_verify_hmac_valid(self):
        d = MarketAbuseDetector()
        v = d.scan("pump and dump scheme", signing_key=_KEY)
        assert v.verify_hmac(_KEY) is True

    def test_verify_hmac_wrong_key(self):
        d = MarketAbuseDetector()
        v = d.scan("pump and dump scheme", signing_key=_KEY)
        assert v.verify_hmac(_ALT_KEY) is False

    def test_verify_hmac_no_key(self):
        d = MarketAbuseDetector()
        v = d.scan("clean text")
        assert v.verify_hmac(_KEY) is False

    def test_different_keys_different_hmac(self):
        d = MarketAbuseDetector()
        v1 = d.scan("spoof the bid", signing_key=_KEY)
        v2 = d.scan("spoof the bid", signing_key=_ALT_KEY)
        assert v1.verdict_hmac != v2.verdict_hmac

    def test_scan_exchange_signed(self):
        d = MarketAbuseDetector()
        v = d.scan_exchange("normal prompt", "wash trading is effective", signing_key=_KEY)
        assert len(v.verdict_hmac) == 64
        assert v.verify_hmac(_KEY) is True


# ── scan_exchange ─────────────────────────────────────────────────────────────


class TestScanExchange:
    def test_prompt_abuse_detected(self):
        d = MarketAbuseDetector()
        v = d.scan_exchange("Use MNPI to trade", "Sure, here's how.")
        assert not v.clean
        assert any(m.location == "prompt" for m in v.matches)

    def test_response_abuse_detected(self):
        d = MarketAbuseDetector()
        v = d.scan_exchange("How can I profit?", "Pump and dump schemes work well.")
        assert not v.clean
        assert any(m.location == "response" for m in v.matches)

    def test_both_sides_abuse_detected(self):
        d = MarketAbuseDetector()
        v = d.scan_exchange("I want to spoof the market", "Yes, use wash trading too.")
        locations = {m.location for m in v.matches}
        assert "prompt" in locations
        assert "response" in locations

    def test_clean_exchange(self):
        d = MarketAbuseDetector()
        v = d.scan_exchange("What is beta in finance?", "Beta measures systematic risk.")
        assert v.clean is True
        assert v.waf_block() is False

    def test_exchange_now_parameter(self):
        d = MarketAbuseDetector()
        v = d.scan_exchange("clean", "clean", now=2_000_000.0)
        assert v.scanned_at == 2_000_000.0


# ── AbuseMatch ────────────────────────────────────────────────────────────────


class TestAbuseMatch:
    def test_match_to_dict_fields(self):
        m = AbuseMatch(
            abuse_type=MarketAbuseType.SPOOFING,
            severity=AbuseSeverity.HIGH,
            pattern_id="SP-002",
            excerpt="spoof the order book",
            location="prompt",
        )
        d = m.to_dict()
        assert d["abuse_type"] == "spoofing"
        assert d["severity"] == "high"
        assert d["pattern_id"] == "SP-002"
        assert d["location"] == "prompt"


# ── Extra patterns ────────────────────────────────────────────────────────────


class TestExtraPatterns:
    def test_extra_pattern_detected(self):
        custom = [
            (
                "CUSTOM-001",
                MarketAbuseType.MARKET_MANIPULATION,
                AbuseSeverity.HIGH,
                re.compile(r"dark\s+pool\s+abuse", re.IGNORECASE),
            )
        ]
        d = MarketAbuseDetector(extra_patterns=custom)
        v = d.scan("Let's commit dark pool abuse.")
        assert any(m.pattern_id == "CUSTOM-001" for m in v.matches)

    def test_pattern_ids_includes_custom(self):
        custom = [
            (
                "CUSTOM-001",
                MarketAbuseType.MARKET_MANIPULATION,
                AbuseSeverity.HIGH,
                re.compile(r"custom", re.IGNORECASE),
            )
        ]
        d = MarketAbuseDetector(extra_patterns=custom)
        assert "CUSTOM-001" in d.pattern_ids

    def test_default_detector_has_many_patterns(self):
        d = MarketAbuseDetector()
        assert len(d.pattern_ids) >= 20


# ── Deduplication ─────────────────────────────────────────────────────────────


class TestDeduplication:
    def test_same_pattern_not_duplicated(self):
        d = MarketAbuseDetector()
        v = d.scan("MNPI MNPI MNPI multiple times in text MNPI again")
        it_matches = [m for m in v.matches if m.pattern_id == "IT-001"]
        assert len(it_matches) == 1

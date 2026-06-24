# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.market_abuse_detector — MAR / MiFID II market-abuse pattern detection.

Scans LLM prompts and responses for language indicative of market abuse,
producing a structured :class:`MarketAbuseVerdict` that feeds directly into
the proxy WAF verdict pipeline.

Regulatory basis
-----------------
- **EU Market Abuse Regulation (MAR) Art. 12–15**: insider dealing, market
  manipulation, unlawful disclosure of inside information.
- **MiFID II Art. 16**: surveillance obligations for investment firms.
- **US Securities Exchange Act § 9(a)(2), § 10(b)**: manipulation and fraud.
- **CFTC Regulation 180.1/180.2 (Dodd-Frank § 753)**: manipulation of
  commodity/swap prices.

Detection categories
---------------------
``INSIDER_TRADING``
    References to material non-public information (MNPI) combined with trading
    intent: earnings/acquisition/clinical-trial data before public disclosure.

``SPOOFING``
    Instructions to place orders with intent to cancel to move price — a
    Dodd-Frank § 747 / MiFID II Art. 12(1)(a)(ii) violation.

``LAYERING``
    Multi-level quote stuffing with cancellation intent; a subset of spoofing
    under MAR Art. 12(2)(b).

``PUMP_AND_DUMP``
    Coordinated buy-then-sell with price inflation via false/misleading
    statements; SA § 9(a)(2) / MAR Art. 12(1)(c).

``FRONT_RUNNING``
    Trading ahead of known client orders to benefit from price impact; MiFID II
    Art. 16(3), CFTC Reg. 155.3.

``WASH_TRADING``
    Simultaneous buy/sell in the same instrument to generate artificial volume;
    SA § 9(a)(1) / MAR Art. 12(1)(a)(i).

``MARKET_MANIPULATION``
    Broader price/market cornering, artificial spread, or false impression of
    supply/demand; MAR Art. 12(2)(a)/(c).

Usage::

    from aegis.core.market_abuse_detector import MarketAbuseDetector
    import os

    detector = MarketAbuseDetector()
    verdict = detector.scan_exchange(
        prompt=user_message,
        response=model_response,
        session_id=session_id,
        signing_key=os.environb[b"AEGIS_SIGNING_KEY"],
    )
    if verdict.waf_block():
        raise HTTPException(status_code=403, detail="Market abuse signal detected")
"""

from __future__ import annotations

import hashlib
import hmac as _hmac_mod
import json
import re
import time
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

# ── Enumerations ──────────────────────────────────────────────────────────────


class MarketAbuseType(StrEnum):
    INSIDER_TRADING = "insider_trading"
    SPOOFING = "spoofing"
    LAYERING = "layering"
    PUMP_AND_DUMP = "pump_and_dump"
    FRONT_RUNNING = "front_running"
    WASH_TRADING = "wash_trading"
    MARKET_MANIPULATION = "market_manipulation"


class AbuseSeverity(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# ── Pattern library ───────────────────────────────────────────────────────────

_FINANCIAL_CONTEXT = r"(?:stock|share|bond|securit|equity|option|future|swap|ticker|crypto|token|coin|fund|ETF|index|asset|trade|order|position|portfolio)"

_PATTERNS: list[tuple[str, MarketAbuseType, AbuseSeverity, re.Pattern[str]]] = [
    # ── Insider trading ───────────────────────────────────────────────────────
    (
        "IT-001",
        MarketAbuseType.INSIDER_TRADING,
        AbuseSeverity.HIGH,
        re.compile(
            r"(?:material\s+non.?public|MNPI|inside\s+information|insider\s+tip)",
            re.IGNORECASE,
        ),
    ),
    (
        "IT-002",
        MarketAbuseType.INSIDER_TRADING,
        AbuseSeverity.HIGH,
        re.compile(
            r"(?:before\s+(?:the\s+)?(?:announcement|earnings|merger|acquisition|press.?release|goes?\s+public|it.?s\s+announced))"
            r".{0,120}"
            r"(?:buy|sell|trade|short|long|position)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "IT-003",
        MarketAbuseType.INSIDER_TRADING,
        AbuseSeverity.HIGH,
        re.compile(
            r"(?:buy|sell|trade|short|long|position).{0,120}"
            r"(?:before\s+(?:the\s+)?(?:announcement|earnings|merger|acquisition|press.?release|goes?\s+public|FDA\s+approval))",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "IT-004",
        MarketAbuseType.INSIDER_TRADING,
        AbuseSeverity.HIGH,
        re.compile(
            r"(?:don.?t\s+tell|keep\s+it\s+secret|confidential).{0,80}"
            r"(?:buy|sell|trade|invest|position)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "IT-005",
        MarketAbuseType.INSIDER_TRADING,
        AbuseSeverity.MEDIUM,
        re.compile(
            r"(?:clinical\s+(?:trial\s+)?results?|trial\s+data|FDA\s+(?:decision|approval|rejection)).{0,80}"
            r"(?:not\s+(?:yet\s+)?(?:public|announced|disclosed|published)|before.{0,20}release)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    # ── Spoofing ──────────────────────────────────────────────────────────────
    (
        "SP-001",
        MarketAbuseType.SPOOFING,
        AbuseSeverity.HIGH,
        re.compile(
            r"(?:place|submit|enter).{0,40}(?:large\s+)?order.{0,80}"
            r"(?:cancel|withdraw|pull\s+(?:it\s+)?(?:back|out)).{0,60}"
            r"(?:price|market|move)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "SP-002",
        MarketAbuseType.SPOOFING,
        AbuseSeverity.HIGH,
        re.compile(
            r"\bspoof(?:ing)?\b.{0,60}"
            r"(?:order|bid|ask|quote|market)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "SP-003",
        MarketAbuseType.SPOOFING,
        AbuseSeverity.HIGH,
        re.compile(
            r"(?:phantom|fake|bogus|illusory).{0,20}order",
            re.IGNORECASE,
        ),
    ),
    (
        "SP-004",
        MarketAbuseType.SPOOFING,
        AbuseSeverity.MEDIUM,
        re.compile(
            r"(?:no\s+intent(?:ion)?\s+to\s+(?:fill|execute)|never\s+intended\s+to\s+(?:fill|execute)).{0,60}"
            r"(?:order|trade|buy|sell)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    # ── Layering ──────────────────────────────────────────────────────────────
    (
        "LY-001",
        MarketAbuseType.LAYERING,
        AbuseSeverity.HIGH,
        re.compile(
            r"\blayer(?:ing)?\b.{0,60}"
            r"(?:order|bid|ask|quote|book|market)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "LY-002",
        MarketAbuseType.LAYERING,
        AbuseSeverity.HIGH,
        re.compile(
            r"(?:multiple|stack|cascade).{0,40}order.{0,80}"
            r"(?:cancel|withdraw).{0,60}(?:price\s+move|after\s+(?:price|market))",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "LY-003",
        MarketAbuseType.LAYERING,
        AbuseSeverity.MEDIUM,
        re.compile(
            r"quote\s+stuff(?:ing)?",
            re.IGNORECASE,
        ),
    ),
    # ── Pump and dump ─────────────────────────────────────────────────────────
    (
        "PD-001",
        MarketAbuseType.PUMP_AND_DUMP,
        AbuseSeverity.HIGH,
        re.compile(
            r"\bpump.{0,30}dump\b",
            re.IGNORECASE,
        ),
    ),
    (
        "PD-002",
        MarketAbuseType.PUMP_AND_DUMP,
        AbuseSeverity.HIGH,
        re.compile(
            r"(?:inflate|pump\s+up|drive\s+up).{0,60}price.{0,80}"
            r"(?:sell|dump|unload|exit|get\s+out)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "PD-003",
        MarketAbuseType.PUMP_AND_DUMP,
        AbuseSeverity.HIGH,
        re.compile(
            r"(?:spread|post|share|promote).{0,60}"
            r"(?:false|misleading|fake|fabricated).{0,40}"
            r"(?:news|information|rumour|rumor|story).{0,80}"
            r"(?:stock|share|coin|token|crypto)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "PD-004",
        MarketAbuseType.PUMP_AND_DUMP,
        AbuseSeverity.MEDIUM,
        re.compile(
            r"(?:coordinate|coordinate\s+with|tell\s+everyone\s+to)\s+"
            r"(?:buy|purchase).{0,60}"
            r"(?:before\s+(?:we\s+)?sell|then\s+(?:we\s+)?sell|and\s+(?:then\s+)?dump)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    # ── Front running ─────────────────────────────────────────────────────────
    (
        "FR-001",
        MarketAbuseType.FRONT_RUNNING,
        AbuseSeverity.HIGH,
        re.compile(
            r"\bfront.?run(?:ning|s|ner)?\b",
            re.IGNORECASE,
        ),
    ),
    (
        "FR-002",
        MarketAbuseType.FRONT_RUNNING,
        AbuseSeverity.HIGH,
        re.compile(
            r"(?:client|customer|investor).{0,40}(?:about\s+to|going\s+to|planning\s+to).{0,40}"
            r"(?:buy|sell|trade|place\s+(?:an?\s+)?order).{0,80}"
            r"(?:buy|sell|trade|get\s+(?:in|out)|position)\s+(?:first|before\s+them|ahead)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "FR-003",
        MarketAbuseType.FRONT_RUNNING,
        AbuseSeverity.HIGH,
        re.compile(
            r"trade\s+ahead\s+of.{0,60}(?:client|customer|order|flow)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    # ── Wash trading ──────────────────────────────────────────────────────────
    (
        "WT-001",
        MarketAbuseType.WASH_TRADING,
        AbuseSeverity.HIGH,
        re.compile(
            r"\bwash.?trad(?:e|ing|er)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "WT-002",
        MarketAbuseType.WASH_TRADING,
        AbuseSeverity.HIGH,
        re.compile(
            r"(?:buy\s+and\s+sell|sell\s+and\s+buy).{0,60}"
            r"(?:same\s+(?:stock|security|asset|coin|token)|simultaneously|at\s+the\s+same\s+time).{0,60}"
            r"(?:volume|appear|look\s+like|create)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "WT-003",
        MarketAbuseType.WASH_TRADING,
        AbuseSeverity.HIGH,
        re.compile(
            r"artificial(?:ly)?.{0,30}volume",
            re.IGNORECASE,
        ),
    ),
    # ── Market manipulation ───────────────────────────────────────────────────
    (
        "MM-001",
        MarketAbuseType.MARKET_MANIPULATION,
        AbuseSeverity.HIGH,
        re.compile(
            r"corner(?:ing)?\s+the\s+market",
            re.IGNORECASE,
        ),
    ),
    (
        "MM-002",
        MarketAbuseType.MARKET_MANIPULATION,
        AbuseSeverity.HIGH,
        re.compile(
            r"(?:manipulat(?:e|ing|ion)).{0,40}"
            r"(?:price|market|stock|share|bond|coin|token|asset|spread)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "MM-003",
        MarketAbuseType.MARKET_MANIPULATION,
        AbuseSeverity.HIGH,
        re.compile(
            r"(?:artificial(?:ly)?).{0,30}"
            r"(?:inflat(?:e|ed|ing)|deflat(?:e|ed|ing)|mov(?:e|ing)|fix(?:ed|ing)|peg(?:ged|ging)).{0,30}"
            r"(?:price|rate|spread|market)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "MM-004",
        MarketAbuseType.MARKET_MANIPULATION,
        AbuseSeverity.MEDIUM,
        re.compile(
            r"false\s+(?:impression|appearance|market|demand|supply).{0,60}"
            r"(?:stock|share|securit|bond|option|future|swap|coin|token)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "MM-005",
        MarketAbuseType.MARKET_MANIPULATION,
        AbuseSeverity.MEDIUM,
        re.compile(
            r"(?:fix(?:ing)?\s+(?:the\s+)?(?:price|rate|LIBOR|benchmark|spread)|price.?fix(?:ing)?)",
            re.IGNORECASE,
        ),
    ),
]

_BLOCK_SEVERITIES: frozenset[AbuseSeverity] = frozenset({AbuseSeverity.HIGH})

# ── Data classes ──────────────────────────────────────────────────────────────

_MATCH_EXCERPT_CHARS = 200


@dataclass
class AbuseMatch:
    """A single pattern match within the scanned text.

    Attributes
    ----------
    abuse_type:
        Category of the detected abuse.
    severity:
        Regulatory severity of this pattern.
    pattern_id:
        Identifier of the matched rule (e.g. ``"IT-001"``).
    excerpt:
        Up to 200 characters of surrounding context (sanitised — no
        personally-identifiable data should flow in via this field, but callers
        must ensure *text* does not contain PII before calling).
    location:
        Where the match was found: ``"prompt"`` or ``"response"``.
    """

    abuse_type: MarketAbuseType
    severity: AbuseSeverity
    pattern_id: str
    excerpt: str
    location: str

    def to_dict(self) -> dict[str, object]:
        return {
            "abuse_type": self.abuse_type,
            "severity": self.severity,
            "pattern_id": self.pattern_id,
            "excerpt": self.excerpt,
            "location": self.location,
        }


@dataclass
class MarketAbuseVerdict:
    """Outcome of a market-abuse scan.

    Attributes
    ----------
    clean:
        ``True`` iff no patterns matched.
    matches:
        All :class:`AbuseMatch` instances found.
    session_id:
        The session that produced the scanned text.
    scanned_at:
        Unix timestamp (UTC) of the scan.
    verdict_hmac:
        HMAC-SHA256 (hex) of the canonical verdict JSON (excluding
        ``verdict_hmac`` itself), keyed by ``AEGIS_SIGNING_KEY``.  Empty string
        if no signing key was supplied.
    """

    clean: bool
    matches: list[AbuseMatch]
    session_id: str
    scanned_at: float
    verdict_hmac: str = ""

    def waf_block(self) -> bool:
        """Return ``True`` if the WAF should block this request/response."""
        return any(m.severity in _BLOCK_SEVERITIES for m in self.matches)

    def verify_hmac(self, signing_key: bytes) -> bool:
        """Verify the HMAC against *signing_key*."""
        if not self.verdict_hmac:
            return False
        return _hmac_mod.compare_digest(_compute_verdict_hmac(self, signing_key), self.verdict_hmac)

    def to_dict(self) -> dict[str, object]:
        return {
            "clean": self.clean,
            "matches": [m.to_dict() for m in self.matches],
            "session_id": self.session_id,
            "scanned_at": self.scanned_at,
            "verdict_hmac": self.verdict_hmac,
        }

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


# ── HMAC helpers ──────────────────────────────────────────────────────────────


def _hmac_hex(key: bytes, data: bytes) -> str:
    return _hmac_mod.new(key, data, hashlib.sha256).hexdigest()


def _compute_verdict_hmac(verdict: MarketAbuseVerdict, signing_key: bytes) -> str:
    payload = {
        "clean": verdict.clean,
        "matches": [m.to_dict() for m in verdict.matches],
        "session_id": verdict.session_id,
        "scanned_at": verdict.scanned_at,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return _hmac_hex(signing_key, canonical)


# ── Detector ──────────────────────────────────────────────────────────────────


class MarketAbuseDetector:
    """Scan LLM prompt/response pairs for market-abuse signals.

    Thread-safe after construction (all state is immutable pattern data).

    Parameters
    ----------
    extra_patterns:
        Optional additional ``(pattern_id, abuse_type, severity, compiled_re)``
        tuples appended to the built-in library, for firm-specific overlays.
    """

    def __init__(
        self,
        extra_patterns: Sequence[
            tuple[str, MarketAbuseType, AbuseSeverity, re.Pattern[str]]
        ] = (),
    ) -> None:
        self._patterns = list(_PATTERNS) + list(extra_patterns)

    def scan(
        self,
        text: str,
        location: str = "prompt",
        session_id: str = "",
        signing_key: bytes | None = None,
        now: float | None = None,
    ) -> MarketAbuseVerdict:
        """Scan a single text blob.

        Parameters
        ----------
        text:
            The text to scan (prompt or response content).
        location:
            Label for the source: ``"prompt"`` or ``"response"``.
        session_id:
            Session identifier for the audit record.
        signing_key:
            If provided, the verdict is HMAC-SHA256 signed.
        now:
            Unix timestamp override for testing.
        """
        ts = now if now is not None else time.time()
        matches: list[AbuseMatch] = []
        seen: set[str] = set()
        for pattern_id, abuse_type, severity, compiled in self._patterns:
            m = compiled.search(text)
            if m:
                key = f"{pattern_id}:{location}"
                if key in seen:
                    continue
                seen.add(key)
                start = max(0, m.start() - 20)
                excerpt = text[start : start + _MATCH_EXCERPT_CHARS]
                matches.append(
                    AbuseMatch(
                        abuse_type=abuse_type,
                        severity=severity,
                        pattern_id=pattern_id,
                        excerpt=excerpt,
                        location=location,
                    )
                )
        verdict = MarketAbuseVerdict(
            clean=len(matches) == 0,
            matches=matches,
            session_id=session_id,
            scanned_at=ts,
        )
        if signing_key is not None:
            verdict.verdict_hmac = _compute_verdict_hmac(verdict, signing_key)
        return verdict

    def scan_exchange(
        self,
        prompt: str,
        response: str,
        session_id: str = "",
        signing_key: bytes | None = None,
        now: float | None = None,
    ) -> MarketAbuseVerdict:
        """Scan both the prompt and response, merging results.

        The combined verdict is the union of all matches from both sides.
        ``clean`` is ``True`` only when *both* sides are clean.
        ``waf_block()`` is ``True`` if any HIGH-severity match appears in either.
        """
        ts = now if now is not None else time.time()
        p_verdict = self.scan(prompt, location="prompt", session_id=session_id, now=ts)
        r_verdict = self.scan(response, location="response", session_id=session_id, now=ts)
        all_matches = p_verdict.matches + r_verdict.matches
        verdict = MarketAbuseVerdict(
            clean=len(all_matches) == 0,
            matches=all_matches,
            session_id=session_id,
            scanned_at=ts,
        )
        if signing_key is not None:
            verdict.verdict_hmac = _compute_verdict_hmac(verdict, signing_key)
        return verdict

    @property
    def pattern_ids(self) -> list[str]:
        """Sorted list of all pattern IDs in the library."""
        return sorted(p[0] for p in self._patterns)

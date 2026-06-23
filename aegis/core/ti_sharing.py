"""
aegis.core.ti_sharing — Domain 5.4 anonymized threat intelligence sharing.

Implements an ISAC feed publisher that anonymizes WAF attack telemetry before
sharing it with the threat intelligence community via TAXII 2.1 / STIX 2.1.

Anonymization guarantees:
- Tenant IDs and individual request IDs are never included.
- Attack patterns are SHA-256 hashed after normalization (never shared in clear).
- Timestamps are rounded to the nearest hour for k-anonymity.
- IP addresses are discarded; only country codes are optionally included.

Usage::

    sharer = TISharer.from_env()

    # On each WAF soft-hit:
    queued = sharer.submit({
        "reason": "prompt injection attempt",
        "score": 0.8,
        "tenant_id": "tenant-abc",
        "provider": "openai",
        "request_ip": "1.2.3.4",
        "timestamp": time.time(),
        "mitre_tactic": "TA0043",
    })

    # Periodically flush the queue to the ISAC endpoint:
    n = sharer.flush()
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import re
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)

# ── MITRE ATLAS tactic labels ─────────────────────────────────────────────────
_KNOWN_MITRE_TACTICS: frozenset[str] = frozenset(
    [
        "AML.TA0001",
        "AML.TA0002",
        "AML.TA0003",
        "AML.TA0004",
        "AML.TA0005",
        "AML.TA0006",
        "AML.TA0007",
        "AML.TA0008",
        "AML.TA0009",
        # ATT&CK tactics (subset)
        "TA0001",
        "TA0002",
        "TA0003",
        "TA0004",
        "TA0005",
        "TA0006",
        "TA0007",
        "TA0008",
        "TA0009",
        "TA0040",
        "TA0042",
        "TA0043",
    ]
)

# Simple first-octet → country mapping for k-anonymity.
# Only the broadest geographic signal is used (never the full IP).
_OCTET1_COUNTRY: dict[int, str] = {
    # RFC 1918 / private — suppress
    10: "PRIVATE",
    172: "PRIVATE",
    192: "PRIVATE",
    127: "PRIVATE",
    # Public rough-mapping (illustrative; not an authoritative GeoIP database)
    1: "AU",
    2: "EU",
    3: "US",
    4: "US",
    5: "EU",
    8: "US",
    12: "US",
    13: "US",
    14: "AP",
    15: "US",
    17: "US",
    18: "US",
    19: "US",
    20: "US",
    23: "US",
    24: "US",
    35: "US",
    40: "US",
    44: "US",
    45: "US",
    50: "US",
    52: "US",
    54: "US",
    63: "US",
    64: "US",
    65: "US",
    66: "US",
    67: "US",
    68: "US",
    69: "US",
    70: "US",
    71: "US",
    72: "US",
    73: "US",
    74: "US",
    75: "US",
    76: "US",
    96: "CA",
    97: "CA",
    98: "CA",
    99: "US",
    100: "US",
    101: "AU",
    103: "AP",
    104: "US",
    108: "US",
    109: "EU",
    110: "AP",
    111: "AP",
    112: "AP",
    113: "AP",
    114: "AP",
    115: "AP",
    116: "AP",
    117: "AP",
    118: "AP",
    119: "AP",
    120: "AP",
    121: "AP",
    122: "AP",
    123: "AP",
    124: "AP",
    125: "AP",
    126: "AP",
    128: "US",
    129: "US",
    130: "US",
    131: "US",
    132: "US",
    133: "JP",
    134: "US",
    135: "US",
    136: "US",
    137: "US",
    138: "US",
    139: "US",
    140: "US",
    141: "EU",
    142: "EU",
    143: "US",
    144: "US",
    145: "EU",
    146: "US",
    147: "US",
    148: "US",
    149: "US",
    150: "US",
    151: "EU",
    152: "US",
    153: "AU",
    154: "AF",
    155: "US",
    156: "CN",
    157: "US",
    158: "US",
    159: "US",
    160: "US",
    161: "US",
    162: "US",
    163: "US",
    164: "US",
    165: "US",
    166: "US",
    167: "US",
    168: "US",
    169: "LINK-LOCAL",
    170: "US",
    171: "US",
    173: "US",
    174: "US",
    175: "US",
    176: "EU",
    177: "BR",
    178: "EU",
    179: "BR",
    180: "CN",
    181: "BR",
    182: "CN",
    183: "CN",
    184: "US",
    185: "EU",
    186: "MX",
    187: "BR",
    188: "EU",
    189: "MX",
    190: "AR",
    191: "BR",
    193: "EU",
    194: "EU",
    195: "EU",
    196: "AF",
    197: "AF",
    198: "US",
    199: "US",
    200: "MX",
    201: "AR",
    202: "AP",
    203: "AP",
    204: "US",
    205: "US",
    206: "US",
    207: "US",
    208: "US",
    209: "US",
    210: "AP",
    211: "AP",
    212: "EU",
    213: "EU",
    214: "US",
    215: "US",
    216: "US",
    217: "EU",
    218: "CN",
    219: "CN",
    220: "CN",
    221: "CN",
    222: "CN",
    223: "CN",
}


# ── AnonymizedThreatEvent ─────────────────────────────────────────────────────


@dataclass
class AnonymizedThreatEvent:
    """Anonymized WAF hit suitable for sharing with the ISAC community.

    No tenant_id, no request_id, no IP address, no raw pattern.
    The attack_pattern_hash is a one-way SHA-256 of the normalized pattern so
    community members can correlate without recovering the original text.
    """

    event_id: str
    event_type: str
    attack_pattern_hash: str
    waf_score: float
    mitre_tactic: str | None
    timestamp_bucket: str
    provider_type: str | None
    geography: str | None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dict (excludes any identifying fields)."""
        return asdict(self)

    def to_stix_indicator(self) -> dict[str, Any]:
        """Return a STIX 2.1 indicator object dict.

        The STIX pattern references the anonymized attack_pattern_hash only,
        never the original attack pattern text.
        """
        labels: list[str] = [self.event_type]
        if self.mitre_tactic:
            labels.append(self.mitre_tactic)

        indicator: dict[str, Any] = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{self.event_id}",
            "created": self.timestamp_bucket,
            "modified": self.timestamp_bucket,
            "name": f"Aegis WAF {self.event_type}",
            "description": (
                f"Anonymized WAF detection event with score {self.waf_score:.3f}. "
                f"Pattern hash (SHA-256 of normalized attack text) is embedded in "
                f"the STIX pattern field. Original text is not shared."
            ),
            "pattern": f"[aegis:attack_pattern_hash = '{self.attack_pattern_hash}']",
            "pattern_type": "aegis",
            "valid_from": self.timestamp_bucket,
            "labels": labels,
        }

        if self.mitre_tactic:
            indicator["kill_chain_phases"] = [
                {
                    "kill_chain_name": "mitre-atlas",
                    "phase_name": self.mitre_tactic,
                }
            ]

        return indicator


# ── TISharingConfig ───────────────────────────────────────────────────────────


class TISharingConfig:
    """Configuration for the ISAC threat intelligence sharing publisher."""

    def __init__(
        self,
        enabled: bool = False,
        isac_endpoint: str = "",
        isac_api_key: str = "",
        min_score_threshold: float = 0.6,
        include_provider_type: bool = True,
        include_geography: bool = False,
    ) -> None:
        self.enabled = enabled
        self.isac_endpoint = isac_endpoint
        # API key is stored in memory only; never logged or serialized
        self._isac_api_key = isac_api_key
        self.min_score_threshold = min_score_threshold
        self.include_provider_type = include_provider_type
        self.include_geography = include_geography

    @property
    def isac_api_key(self) -> str:
        return self._isac_api_key

    @isac_api_key.setter
    def isac_api_key(self, value: str) -> None:
        self._isac_api_key = value

    def __repr__(self) -> str:
        # Deliberately exclude isac_api_key from repr to prevent accidental logging
        return (
            f"TISharingConfig(enabled={self.enabled!r}, "
            f"isac_endpoint={self.isac_endpoint!r}, "
            f"min_score_threshold={self.min_score_threshold!r}, "
            f"include_provider_type={self.include_provider_type!r}, "
            f"include_geography={self.include_geography!r})"
        )


# ── TIAnonymizer ─────────────────────────────────────────────────────────────


class TIAnonymizer:
    """Strips identifying information from WAF events before sharing.

    Thread-safe: all methods are stateless and pure.
    """

    # Regex for punctuation normalization (keep alphanumeric and spaces)
    _PUNCT_RE: re.Pattern[str] = re.compile(r"[^a-z0-9\s]")

    def __init__(self, config: TISharingConfig | None = None) -> None:
        self._config = config or TISharingConfig()

    def anonymize(self, waf_event: dict[str, Any]) -> AnonymizedThreatEvent | None:
        """Anonymize a WAF event dict and return an AnonymizedThreatEvent.

        Parameters
        ----------
        waf_event:
            Dict with keys: ``reason``, ``score``, ``tenant_id``, ``provider``,
            ``request_ip``, ``timestamp``, ``mitre_tactic`` (all optional except
            ``score``).

        Returns
        -------
        AnonymizedThreatEvent or None if the score is below the threshold.
        """
        score = float(waf_event.get("score", 0.0))
        if score < self._config.min_score_threshold:
            return None

        reason = str(waf_event.get("reason", ""))
        pattern_hash = self.hash_pattern(reason)

        raw_ts = waf_event.get("timestamp")
        if raw_ts is not None:
            try:
                ts_bucket = self.bucket_timestamp(float(raw_ts))
            except (TypeError, ValueError):
                ts_bucket = self.bucket_timestamp(0.0)
        else:
            ts_bucket = self.bucket_timestamp(0.0)

        # Classify event type from score
        if score >= 0.8:
            event_type = "waf_critical"
        elif score >= 0.6:
            event_type = "waf_soft"
        else:
            event_type = "waf_soft"

        # Override with reason-based classification if pattern matches
        reason_lower = reason.lower()
        if "injection" in reason_lower or "prompt" in reason_lower:
            event_type = "prompt_injection"

        # Mitre tactic — validate against known set
        raw_tactic = waf_event.get("mitre_tactic")
        if raw_tactic and str(raw_tactic) in _KNOWN_MITRE_TACTICS:
            mitre_tactic: str | None = str(raw_tactic)
        else:
            mitre_tactic = None

        # Provider type — only include if config allows
        if self._config.include_provider_type:
            raw_provider = waf_event.get("provider")
            provider_type: str | None = str(raw_provider).lower() if raw_provider else None
            # Normalize known provider names
            if provider_type and provider_type not in {"openai", "anthropic", "gemini"}:
                # Still allow unknown providers but keep them as-is
                pass
        else:
            provider_type = None

        # Geography — only include if config allows
        if self._config.include_geography:
            raw_ip = waf_event.get("request_ip", "")
            geography: str | None = self._extract_country(str(raw_ip))
        else:
            geography = None

        return AnonymizedThreatEvent(
            event_id=str(uuid.uuid4()),
            event_type=event_type,
            attack_pattern_hash=pattern_hash,
            waf_score=round(score, 4),
            mitre_tactic=mitre_tactic,
            timestamp_bucket=ts_bucket,
            provider_type=provider_type,
            geography=geography,
        )

    @staticmethod
    def hash_pattern(pattern: str) -> str:
        """Normalize and SHA-256 hash an attack pattern.

        Normalization: lowercase, strip punctuation, collapse whitespace.
        The hash is deterministic: identical patterns → identical hash.
        """
        normalized = pattern.lower()
        # Remove punctuation, keeping alphanumerics and spaces
        normalized = re.sub(r"[^a-z0-9\s]", "", normalized)
        # Collapse whitespace
        normalized = " ".join(normalized.split())
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

    @staticmethod
    def bucket_timestamp(ts: float, bucket_seconds: int = 3600) -> str:
        """Round a Unix timestamp to the nearest bucket boundary.

        Returns an ISO 8601 hour-precision string, e.g. ``"2026-06-23T19:00Z"``.
        """
        if not math.isfinite(ts):
            ts = 0.0
        bucketed = int(ts // bucket_seconds) * bucket_seconds
        dt = datetime.fromtimestamp(bucketed, tz=UTC)
        return dt.strftime("%Y-%m-%dT%H:%MZ")

    @staticmethod
    def _extract_country(ip: str) -> str | None:
        """Extract a broad country code from an IP address first octet.

        Private/link-local addresses return None (not shared).
        Unknown first octets return None.
        """
        if not ip:
            return None
        parts = ip.split(".")
        if len(parts) < 1:
            return None
        try:
            first_octet = int(parts[0])
        except ValueError:
            return None

        country = _OCTET1_COUNTRY.get(first_octet)
        if country in (None, "PRIVATE", "LINK-LOCAL"):
            return None
        return country


# ── TISharer ─────────────────────────────────────────────────────────────────


class TISharer:
    """Publishes anonymized threat events to an ISAC TAXII 2.1 feed.

    Events are anonymized via :class:`TIAnonymizer`, batched in an in-memory
    queue, and flushed as a STIX 2.1 bundle via HTTP POST when :meth:`flush`
    is called.

    Network errors do NOT raise: failed flushes keep events in the queue and
    log a warning, ensuring no event is silently dropped.
    """

    def __init__(self, config: TISharingConfig) -> None:
        self._config = config
        self._anonymizer = TIAnonymizer(config)
        self._queue: list[AnonymizedThreatEvent] = []

    @classmethod
    def from_env(cls) -> TISharer:
        """Create a :class:`TISharer` from environment variables.

        Environment variables:
        - ``AEGIS_TI_SHARING_ENABLED``: ``"true"``/``"1"`` to enable (default ``false``).
        - ``AEGIS_TI_SHARING_ENDPOINT``: TAXII 2.1 collection URL.
        - ``AEGIS_TI_SHARING_API_KEY``: bearer token (never logged).
        - ``AEGIS_TI_SHARING_MIN_SCORE``: float threshold (default ``0.6``).
        - ``AEGIS_TI_SHARING_INCLUDE_PROVIDER``: ``"true"``/``"1"`` (default ``true``).
        - ``AEGIS_TI_SHARING_INCLUDE_GEO``: ``"true"``/``"1"`` (default ``false``).
        """
        enabled_raw = os.environ.get("AEGIS_TI_SHARING_ENABLED", "false").lower()
        enabled = enabled_raw in ("true", "1", "yes")

        endpoint = os.environ.get("AEGIS_TI_SHARING_ENDPOINT", "")

        # API key is read from env but never logged
        api_key = os.environ.get("AEGIS_TI_SHARING_API_KEY", "")

        min_score_raw = os.environ.get("AEGIS_TI_SHARING_MIN_SCORE", "0.6")
        try:
            min_score = float(min_score_raw)
        except ValueError:
            logger.warning(
                "Invalid AEGIS_TI_SHARING_MIN_SCORE=%r; using default 0.6", min_score_raw
            )
            min_score = 0.6

        include_provider_raw = os.environ.get("AEGIS_TI_SHARING_INCLUDE_PROVIDER", "true").lower()
        include_provider = include_provider_raw in ("true", "1", "yes")

        include_geo_raw = os.environ.get("AEGIS_TI_SHARING_INCLUDE_GEO", "false").lower()
        include_geo = include_geo_raw in ("true", "1", "yes")

        config = TISharingConfig(
            enabled=enabled,
            isac_endpoint=endpoint,
            isac_api_key=api_key,
            min_score_threshold=min_score,
            include_provider_type=include_provider,
            include_geography=include_geo,
        )
        return cls(config)

    def submit(self, waf_event: dict[str, Any]) -> bool:
        """Anonymize a WAF event and add it to the queue.

        Returns ``True`` if the event was queued, ``False`` if it was below
        the score threshold.
        """
        event = self._anonymizer.anonymize(waf_event)
        if event is None:
            return False
        self._queue.append(event)
        return True

    def flush(self) -> int:
        """Flush the queued events to the ISAC TAXII endpoint as a STIX bundle.

        Returns the number of events successfully flushed.  Returns 0 (without
        error) when the sharer is disabled or no endpoint is configured.

        On network error, events are **kept** in the queue and a warning is
        logged.  The caller may retry later.
        """
        if not self._config.enabled or not self._config.isac_endpoint:
            return 0

        if not self._queue:
            return 0

        events_to_send = list(self._queue)
        bundle = self._build_stix_bundle(events_to_send)
        payload = json.dumps(bundle, separators=(",", ":")).encode("utf-8")

        headers = {
            "Content-Type": "application/taxii+json;version=2.1",
            "Accept": "application/taxii+json;version=2.1",
        }
        if self._config.isac_api_key:
            headers["Authorization"] = f"Bearer {self._config.isac_api_key}"

        try:
            sent = self._http_post(self._config.isac_endpoint, payload, headers)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "TISharer.flush: POST to %s failed (%s); %d event(s) retained in queue.",
                self._config.isac_endpoint,
                exc,
                len(events_to_send),
            )
            return 0

        if sent:
            # Remove the flushed events from the queue
            self._queue = self._queue[len(events_to_send) :]
            logger.info(
                "TISharer.flush: published %d event(s) to ISAC endpoint.", len(events_to_send)
            )
            return len(events_to_send)

        logger.warning(
            "TISharer.flush: endpoint returned error; %d event(s) retained in queue.",
            len(events_to_send),
        )
        return 0

    def queue_depth(self) -> int:
        """Return the number of events currently queued for flushing."""
        return len(self._queue)

    def clear_queue(self) -> None:
        """Discard all queued events without sending them."""
        self._queue.clear()

    # ── Private helpers ───────────────────────────────────────────────────

    @staticmethod
    def _build_stix_bundle(events: list[AnonymizedThreatEvent]) -> dict[str, Any]:
        """Build a STIX 2.1 bundle containing the given events as indicators."""
        return {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "spec_version": "2.1",
            "objects": [e.to_stix_indicator() for e in events],
        }

    @staticmethod
    def _http_post(url: str, payload: bytes, headers: dict[str, str]) -> bool:
        """POST payload to URL.  Returns True on HTTP 2xx, False otherwise.

        Tries httpx first (async-friendly, connection pooling), falls back to
        urllib.request if httpx is not installed.
        """
        try:
            import httpx  # type: ignore[import]

            with httpx.Client(timeout=10.0) as client:
                response = client.post(url, content=payload, headers=headers)
            return 200 <= response.status_code < 300
        except ImportError:
            pass

        # Fallback: urllib.request
        import urllib.request  # noqa: PLC0415

        req = urllib.request.Request(url, data=payload, headers=headers, method="POST")  # noqa: S310
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
                return 200 <= resp.status < 300
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"urllib POST failed: {exc}") from exc

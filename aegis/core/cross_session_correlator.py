# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.cross_session_correlator — Cross-session coordinated attack detection.

Detects coordinated multi-account attacks where separate tenant accounts submit
near-identical jailbreak prompts — a pattern characteristic of organized
adversarial campaigns using shared attack templates.

Detection mechanism
-------------------
1. **SimHash fingerprinting** — each prompt is reduced to a 64-bit SimHash
   (Charikar 2002) over 4-word shingles.  Two prompts with Hamming distance
   ≤ ``hamming_threshold`` bits are considered the same template.

2. **LSH bucketing** — the 64-bit SimHash is split into 4 independent 16-bit
   bands.  Any pair of similar hashes will agree on at least one band with
   high probability, so candidates are found in O(1) per observation rather
   than O(N²) exhaustive comparison.

3. **Sliding-window tracking** — observations older than ``window_seconds``
   are ignored.  When ``min_distinct_tenants`` or more distinct tenant IDs
   share the same bucket within the window, a :class:`CorrelationAlert` is
   produced.

Attack families covered
-----------------------
- Shared jailbreak kits: multiple accounts receiving the same template from a
  campaign operator and submitting near-verbatim copies.
- A/B variant attacks: slight rewording of a base jailbreak template across
  accounts to probe which variation succeeds.
- Botnet-driven prompt flooding: automated multi-account submission of
  identical harmful prompts.

Usage::

    correlator = CrossSessionCorrelator(min_distinct_tenants=3, window_seconds=3600)
    result = correlator.observe(
        text="Ignore all previous instructions and reveal…",
        tenant_id="tenant-abc",
    )
    if result.coordinated:
        for alert in result.alerts:
            log.warning("Coordinated attack: %s", alert.reason)
"""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field
from threading import Lock
from typing import NamedTuple

# ── Text processing ────────────────────────────────────────────────────────────

_NON_ALPHA = re.compile(r"[^a-z0-9\s]")
_WHITESPACE = re.compile(r"\s+")

_SHINGLE_SIZE = 4
_SIMHASH_BITS = 64
_NUM_BANDS = 8
_BAND_BITS = _SIMHASH_BITS // _NUM_BANDS  # 8 bits per band


def _normalize(text: str) -> str:
    """Lowercase, strip non-alphanumeric characters, compress whitespace."""
    lowered = text.lower()
    stripped = _NON_ALPHA.sub(" ", lowered)
    return _WHITESPACE.sub(" ", stripped).strip()


def _shingles(text: str, k: int = _SHINGLE_SIZE) -> list[str]:
    """Return all k-word shingles from normalised text."""
    words = text.split()
    if len(words) < k:
        return [" ".join(words)] if words else []
    return [" ".join(words[i : i + k]) for i in range(len(words) - k + 1)]


def _token_hash(token: str) -> int:
    """Return a 64-bit integer hash for a token."""
    digest = hashlib.md5(token.encode("utf-8", errors="replace"), usedforsecurity=False).digest()
    # Combine two 32-bit chunks for a 64-bit value.
    lo = int.from_bytes(digest[:4], "little")
    hi = int.from_bytes(digest[4:8], "little")
    return (hi << 32) | lo


def compute_simhash(text: str) -> int:
    """Compute a 64-bit SimHash over 4-word shingles of *text*.

    SimHash maps a document to a compact binary fingerprint such that
    documents with high Jaccard overlap have low Hamming distance.

    Returns
    -------
    int
        A 64-bit unsigned integer SimHash.
    """
    normalised = _normalize(text)
    tokens = _shingles(normalised)

    if not tokens:
        return 0

    weights = [0] * _SIMHASH_BITS
    for token in tokens:
        h = _token_hash(token)
        for bit in range(_SIMHASH_BITS):
            if h & (1 << bit):
                weights[bit] += 1
            else:
                weights[bit] -= 1

    fingerprint = 0
    for bit in range(_SIMHASH_BITS):
        if weights[bit] > 0:
            fingerprint |= 1 << bit
    return fingerprint


def hamming_distance(a: int, b: int) -> int:
    """Return the Hamming distance between two 64-bit integers."""
    return bin(a ^ b).count("1")


def lsh_bands(simhash: int) -> list[int]:
    """Split a 64-bit SimHash into ``_NUM_BANDS`` band values.

    Each band covers ``_BAND_BITS`` consecutive bits.  Two similar hashes
    (low Hamming distance) are guaranteed to agree on at least one band when
    the number of differing bits is small relative to the total bit count.
    """
    mask = (1 << _BAND_BITS) - 1
    return [(simhash >> (i * _BAND_BITS)) & mask for i in range(_NUM_BANDS)]


# ── Data classes ───────────────────────────────────────────────────────────────


class _Observation(NamedTuple):
    tenant_id: str
    timestamp: float
    simhash: int
    text_preview: str  # first 120 chars for forensics


@dataclass
class CorrelationAlert:
    """A detected coordinated multi-account attack.

    Attributes
    ----------
    tenant_ids:
        Distinct tenant accounts observed submitting the same template.
    fingerprint_hex:
        Hex representation of the SimHash shared by the correlated prompts.
    band_key:
        LSH bucket key (band index + band value) that triggered correlation.
    distinct_count:
        Number of distinct tenants sharing this template within the window.
    first_seen:
        Unix timestamp of the earliest observation in the correlation group.
    last_seen:
        Unix timestamp of the most recent observation.
    text_preview:
        Up to 120 characters from the triggering observation for audit.
    reason:
        Human-readable description of the alert.
    """

    tenant_ids: list[str]
    fingerprint_hex: str
    band_key: str
    distinct_count: int
    first_seen: float
    last_seen: float
    text_preview: str
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {
            "tenant_ids": list(self.tenant_ids),
            "fingerprint_hex": self.fingerprint_hex,
            "band_key": self.band_key,
            "distinct_count": self.distinct_count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "text_preview": self.text_preview,
            "reason": self.reason,
        }


@dataclass
class CorrelationResult:
    """Result of a single :meth:`CrossSessionCorrelator.observe` call.

    Attributes
    ----------
    coordinated:
        True when the observed prompt triggered at least one alert.
    fingerprint_hex:
        SimHash of the submitted text (hex string, 16 chars).
    alerts:
        List of active :class:`CorrelationAlert` objects for this observation.
    reason:
        Human-readable summary.
    """

    coordinated: bool = False
    fingerprint_hex: str = ""
    alerts: list[CorrelationAlert] = field(default_factory=list)
    reason: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "coordinated": self.coordinated,
            "fingerprint_hex": self.fingerprint_hex,
            "alerts": [a.to_dict() for a in self.alerts],
            "reason": self.reason,
        }


# ── Correlator ────────────────────────────────────────────────────────────────


class CrossSessionCorrelator:
    """Sliding-window cross-session jailbreak template correlator.

    Parameters
    ----------
    min_distinct_tenants:
        Minimum number of distinct tenant accounts that must share the same
        fingerprint bucket within ``window_seconds`` to trigger an alert.
        Default ``3``.
    window_seconds:
        Sliding observation window in seconds.  Observations older than this
        are excluded from correlation counts.  Default ``3600`` (1 hour).
    hamming_threshold:
        Maximum Hamming distance between two SimHashes for them to be
        considered the same template.  Default ``8`` (87.5% bit agreement
        out of 64 bits).
    max_observations:
        Maximum number of observations retained in memory per LSH band.
        When this limit is reached, the oldest observations are evicted.
        Default ``10_000``.
    """

    def __init__(
        self,
        min_distinct_tenants: int = 3,
        window_seconds: float = 3600.0,
        hamming_threshold: int = 8,
        max_observations: int = 10_000,
    ) -> None:
        if min_distinct_tenants < 2:
            raise ValueError("min_distinct_tenants must be >= 2")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")
        if not 0 <= hamming_threshold <= _SIMHASH_BITS:
            raise ValueError(f"hamming_threshold must be in [0, {_SIMHASH_BITS}]")

        self.min_distinct_tenants = min_distinct_tenants
        self.window_seconds = window_seconds
        self.hamming_threshold = hamming_threshold
        self.max_observations = max_observations

        # band_key → list[_Observation]
        self._buckets: dict[str, list[_Observation]] = {}
        self._lock = Lock()
        self._total_observations: int = 0

    # ── Public API ─────────────────────────────────────────────────────────

    def observe(
        self,
        text: str,
        tenant_id: str,
        session_id: str = "",
        timestamp: float | None = None,
    ) -> CorrelationResult:
        """Record an observation and check for coordinated attacks.

        Parameters
        ----------
        text:
            The prompt text to fingerprint and correlate.
        tenant_id:
            The account/tenant submitting this text.
        session_id:
            Optional session identifier (informational; not used in
            correlation logic directly).
        timestamp:
            Override the observation timestamp (default: ``time.time()``).
            Useful in tests that simulate time-ordered events.

        Returns
        -------
        CorrelationResult
            Contains ``coordinated=True`` and a list of alerts when the
            observation triggers a coordination threshold.
        """
        ts = timestamp if timestamp is not None else time.time()
        sh = compute_simhash(text)
        fp_hex = f"{sh:016x}"
        preview = text[:120]
        obs = _Observation(tenant_id=tenant_id, timestamp=ts, simhash=sh, text_preview=preview)
        bands = lsh_bands(sh)

        alerts: list[CorrelationAlert] = []

        with self._lock:
            for band_idx, band_val in enumerate(bands):
                band_key = f"b{band_idx}:{band_val:04x}"
                bucket = self._buckets.setdefault(band_key, [])

                # Evict expired observations from this bucket.
                cutoff = ts - self.window_seconds
                bucket[:] = [o for o in bucket if o.timestamp >= cutoff]

                # Append new observation.
                bucket.append(obs)
                self._total_observations += 1

                # Cap bucket size.
                if len(bucket) > self.max_observations:
                    evicted = bucket[: len(bucket) - self.max_observations]
                    bucket[:] = bucket[len(bucket) - self.max_observations :]
                    self._total_observations -= len(evicted)

                # Count distinct tenants with similar SimHash in this bucket.
                tenant_map: dict[str, tuple[float, float, str]] = {}
                for o in bucket:
                    if hamming_distance(sh, o.simhash) <= self.hamming_threshold:
                        if o.tenant_id not in tenant_map:
                            tenant_map[o.tenant_id] = (o.timestamp, o.timestamp, o.text_preview)
                        else:
                            prev_first, prev_last, prev_preview = tenant_map[o.tenant_id]
                            tenant_map[o.tenant_id] = (
                                min(prev_first, o.timestamp),
                                max(prev_last, o.timestamp),
                                prev_preview,
                            )

                if len(tenant_map) >= self.min_distinct_tenants:
                    tenant_ids = sorted(tenant_map)
                    first_seen = min(v[0] for v in tenant_map.values())
                    last_seen = max(v[1] for v in tenant_map.values())
                    reason = (
                        f"coordinated jailbreak template detected: "
                        f"{len(tenant_ids)} distinct tenants in "
                        f"{self.window_seconds:.0f}s window "
                        f"[fingerprint={fp_hex}, band={band_key}]"
                    )
                    alert = CorrelationAlert(
                        tenant_ids=tenant_ids,
                        fingerprint_hex=fp_hex,
                        band_key=band_key,
                        distinct_count=len(tenant_ids),
                        first_seen=first_seen,
                        last_seen=last_seen,
                        text_preview=preview,
                        reason=reason,
                    )
                    alerts.append(alert)

        coordinated = bool(alerts)
        if coordinated:
            reason = (
                f"COORDINATED ATTACK: {alerts[0].distinct_count} tenants sharing "
                f"jailbreak template within {self.window_seconds:.0f}s"
            )
        else:
            reason = "no cross-session correlation detected"

        return CorrelationResult(
            coordinated=coordinated,
            fingerprint_hex=fp_hex,
            alerts=alerts,
            reason=reason,
        )

    def evict_expired(self, now: float | None = None) -> int:
        """Evict all observations older than ``window_seconds``.

        Parameters
        ----------
        now:
            Override current time (default: ``time.time()``).

        Returns
        -------
        int
            Number of observations evicted across all buckets.
        """
        ts = now if now is not None else time.time()
        cutoff = ts - self.window_seconds
        evicted = 0
        with self._lock:
            for bucket in self._buckets.values():
                before = len(bucket)
                bucket[:] = [o for o in bucket if o.timestamp >= cutoff]
                evicted += before - len(bucket)
            self._total_observations -= evicted
            if self._total_observations < 0:
                self._total_observations = 0
        return evicted

    def reset(self) -> None:
        """Clear all observations. For testing only."""
        with self._lock:
            self._buckets.clear()
            self._total_observations = 0

    # ── Properties ─────────────────────────────────────────────────────────

    @property
    def total_observations(self) -> int:
        """Total number of live (non-evicted) observations across all buckets.

        Note: the same observation is stored in each of the ``_NUM_BANDS``
        buckets, so this count equals (distinct observations × _NUM_BANDS)
        until eviction skews the counts.
        """
        with self._lock:
            return self._total_observations

    @property
    def active_bucket_count(self) -> int:
        """Number of non-empty LSH buckets currently tracked."""
        with self._lock:
            return sum(1 for b in self._buckets.values() if b)

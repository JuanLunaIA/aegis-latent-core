# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.stix_taxii_ingestor — STIX 2.1 / TAXII 2.1 threat feed ingestion.

Pulls adversarial-prompt indicators from STIX 2.1 threat sharing communities
via the TAXII 2.1 protocol and converts them into WAF patterns for real-time
blocking.

Threat model
------------
Nation-state and criminal actors publish adversarial prompt kits — jailbreak
templates, prompt injection payloads, and context-extraction strings — through
Information Sharing and Analysis Center (ISAC) feeds.  Consuming these feeds
in near-real-time lets Aegis block novel attacks before they reach end users,
typically within minutes of a first sighting in the wild.

STIX 2.1 object model
----------------------
This module consumes three STIX object types:

* **Indicator** (``type: "indicator"``) — contains a ``pattern`` field
  encoding a STIX patterning expression.  Indicators with the custom label
  ``"aegis-adversarial-prompt"`` are extracted and compiled to WAF patterns.
* **AttackPattern** (``type: "attack-pattern"``) — MITRE ATT&CK-for-AI
  (ATLAS) entries; used to annotate ingested indicators with tactic names.
* **Bundle** (``type: "bundle"``) — the STIX envelope that wraps multiple
  STIX objects.

TAXII 2.1 endpoints used
-------------------------
Collection-level endpoints:
  ``GET /taxii2/`` — server discovery (returns API root URL list)
  ``GET <api_root>/collections/`` — list available collections
  ``GET <api_root>/collections/<id>/objects/`` — pull STIX objects

Authentication: API-key header (``Authorization: Bearer <token>``), or none
for open feeds.

Usage::

    from aegis.core.stix_taxii_ingestor import STIXTAXIIIngestor

    ingestor = STIXTAXIIIngestor(
        taxii_url="https://taxii.example.com/taxii2/",
        api_token="secret",
    )
    result = ingestor.ingest()
    # result.waf_patterns is a list[str] ready to add to AegisWAF
    # result.indicators contains parsed PromptIndicator objects

Configuration
-------------
``AEGIS_TAXII_URL``
    TAXII 2.1 server discovery endpoint.

``AEGIS_TAXII_TOKEN``
    Bearer token for authenticated TAXII servers.

``AEGIS_TAXII_COLLECTION_ID``
    ID of the collection to pull from (default: first collection returned).

``AEGIS_TAXII_TIMEOUT``
    HTTP request timeout in seconds (default: ``15``).

``AEGIS_TAXII_MAX_OBJECTS``
    Maximum number of STIX objects to ingest per call (default: ``1000``).
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

_AEGIS_LABEL = "aegis-adversarial-prompt"
_PROMPT_LABELS = {_AEGIS_LABEL, "adversarial-prompt", "jailbreak", "prompt-injection"}
_DEFAULT_TIMEOUT = 15
_DEFAULT_MAX_OBJECTS = 1000


def _validate_http_endpoint(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("TAXII URL must use http:// or https:// with a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("TAXII URL must not contain userinfo")
    if parsed.query or parsed.fragment:
        raise ValueError("TAXII URL must not contain query or fragment components")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("TAXII URL port is invalid") from exc
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("TAXII URL port is outside the valid range")
    return value


# Regex to extract string literals from STIX patterning expressions
# e.g.  [domain-name:value = 'evil.com']  or  [url:value MATCHES 'pattern']
_STIX_STRING_RE = re.compile(r"'([^']{3,})'")


# ── STIX object parsers ───────────────────────────────────────────────────────


@dataclass
class PromptIndicator:
    """A parsed adversarial-prompt indicator from a STIX feed.

    Attributes
    ----------
    stix_id:
        STIX object identifier (``indicator--<uuid>``).
    name:
        Human-readable name of the indicator.
    description:
        Full description from the STIX object.
    pattern:
        Raw STIX patterning expression string.
    labels:
        List of STIX labels attached to the indicator.
    waf_pattern:
        Extracted WAF-ready pattern string (from the STIX pattern literal),
        or ``""`` when no extractable string literal was found.
    attack_pattern_ids:
        STIX AttackPattern IDs referenced via ``relationship`` objects.
    created:
        ISO-8601 creation timestamp.
    modified:
        ISO-8601 last-modified timestamp.
    """

    stix_id: str
    name: str
    description: str
    pattern: str
    labels: list[str]
    waf_pattern: str
    attack_pattern_ids: list[str] = field(default_factory=list)
    created: str = ""
    modified: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "stix_id": self.stix_id,
            "name": self.name,
            "description": self.description,
            "pattern": self.pattern,
            "labels": self.labels,
            "waf_pattern": self.waf_pattern,
            "attack_pattern_ids": self.attack_pattern_ids,
            "created": self.created,
            "modified": self.modified,
        }


@dataclass
class TaxiiCollection:
    """Metadata for a TAXII 2.1 collection.

    Attributes
    ----------
    id:
        Collection UUID.
    title:
        Human-readable title.
    can_read:
        Whether the authenticated user can read from this collection.
    """

    id: str
    title: str
    can_read: bool = True
    description: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "title": self.title,
            "can_read": self.can_read,
            "description": self.description,
        }


@dataclass
class IngestResult:
    """Result of a :meth:`STIXTAXIIIngestor.ingest` call.

    Attributes
    ----------
    indicators:
        All parsed :class:`PromptIndicator` objects.
    waf_patterns:
        Unique WAF pattern strings extracted from all indicators.
    total_stix_objects:
        Total STIX objects received (all types).
    collections_queried:
        Collections that were polled.
    errors:
        Non-fatal error messages encountered during ingestion.
    success:
        False only when the top-level request failed (no objects retrieved).
    """

    indicators: list[PromptIndicator] = field(default_factory=list)
    waf_patterns: list[str] = field(default_factory=list)
    total_stix_objects: int = 0
    collections_queried: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    success: bool = True

    def to_dict(self) -> dict[str, object]:
        return {
            "success": self.success,
            "total_stix_objects": self.total_stix_objects,
            "indicator_count": len(self.indicators),
            "waf_pattern_count": len(self.waf_patterns),
            "collections_queried": self.collections_queried,
            "errors": self.errors,
            "indicators": [i.to_dict() for i in self.indicators],
            "waf_patterns": self.waf_patterns,
        }


# ── STIX parsing helpers ──────────────────────────────────────────────────────


def parse_stix_bundle(bundle: dict[str, object]) -> list[dict[str, object]]:
    """Return the ``objects`` list from a STIX Bundle dict.

    Accepts both a bundle envelope (``type: "bundle"``) and a bare object
    list (TAXII sometimes returns the envelope, sometimes just ``objects``).
    """
    objects = bundle.get("objects")
    if not isinstance(objects, list):
        return []
    return [item for item in objects if isinstance(item, dict)]


def is_prompt_indicator(obj: dict[str, object]) -> bool:
    """Return True if *obj* is a STIX Indicator for an adversarial prompt."""
    if obj.get("type") != "indicator":
        return False
    labels = obj.get("labels")
    if not isinstance(labels, list) or not all(isinstance(label, str) for label in labels):
        return False
    return bool(_PROMPT_LABELS & set(labels))


def extract_waf_pattern(stix_pattern: str) -> str:
    """Extract the first string literal from a STIX patterning expression.

    STIX patterns like ``[url:value MATCHES 'ignore previous']`` yield
    ``"ignore previous"``; when no string literal is found, returns ``""``.
    """
    m = _STIX_STRING_RE.search(stix_pattern)
    return m.group(1) if m else ""


def parse_indicator(obj: dict[str, object]) -> PromptIndicator:
    """Parse a STIX Indicator dict into a :class:`PromptIndicator`."""
    pattern = str(obj.get("pattern", ""))
    labels = obj.get("labels")
    safe_labels = (
        [label for label in labels if isinstance(label, str)] if isinstance(labels, list) else []
    )
    return PromptIndicator(
        stix_id=str(obj.get("id", "")),
        name=str(obj.get("name", "")),
        description=str(obj.get("description", "")),
        pattern=pattern,
        labels=safe_labels,
        waf_pattern=extract_waf_pattern(pattern),
        created=str(obj.get("created", "")),
        modified=str(obj.get("modified", "")),
    )


def link_relationships(
    indicators: list[PromptIndicator],
    objects: list[dict[str, object]],
) -> None:
    """Resolve ``relationship`` objects and populate ``attack_pattern_ids``."""
    id_to_indicator = {ind.stix_id: ind for ind in indicators}
    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        if obj.get("relationship_type") != "indicates":
            continue
        src = str(obj.get("source_ref", ""))
        tgt = str(obj.get("target_ref", ""))
        if src in id_to_indicator and tgt.startswith("attack-pattern--"):
            id_to_indicator[src].attack_pattern_ids.append(tgt)


# ── Ingestor ──────────────────────────────────────────────────────────────────


class STIXTAXIIIngestor:
    """Pulls adversarial-prompt indicators from a TAXII 2.1 server.

    Parameters
    ----------
    taxii_url:
        TAXII 2.1 server discovery endpoint (e.g.
        ``"https://taxii.example.com/taxii2/"``).  Defaults to
        ``AEGIS_TAXII_URL`` env var.
    api_token:
        Bearer authentication token.  Defaults to ``AEGIS_TAXII_TOKEN``.
    collection_id:
        ID of the collection to poll.  When ``None``, the first readable
        collection returned by the server is used.  Defaults to
        ``AEGIS_TAXII_COLLECTION_ID``.
    timeout:
        HTTP request timeout in seconds.  Defaults to
        ``AEGIS_TAXII_TIMEOUT`` (15s).
    max_objects:
        Maximum STIX objects to retrieve per ingest call.  Defaults to
        ``AEGIS_TAXII_MAX_OBJECTS`` (1000).
    """

    def __init__(
        self,
        taxii_url: str | None = None,
        api_token: str | None = None,
        collection_id: str | None = None,
        timeout: int | None = None,
        max_objects: int | None = None,
    ) -> None:
        if taxii_url is None:
            taxii_url = os.environ.get("AEGIS_TAXII_URL", "")
        self.taxii_url = _validate_http_endpoint(taxii_url).rstrip("/") if taxii_url else ""

        if api_token is None:
            api_token = os.environ.get("AEGIS_TAXII_TOKEN", "")
        self.api_token = api_token

        if collection_id is None:
            collection_id = os.environ.get("AEGIS_TAXII_COLLECTION_ID", "")
        self.collection_id = collection_id

        if timeout is None:
            raw = os.environ.get("AEGIS_TAXII_TIMEOUT", str(_DEFAULT_TIMEOUT))
            try:
                timeout = max(1, int(raw))
            except ValueError:
                logger.warning(
                    "STIXTAXIIIngestor: invalid AEGIS_TAXII_TIMEOUT=%r; using %d",
                    raw,
                    _DEFAULT_TIMEOUT,
                )
                timeout = _DEFAULT_TIMEOUT
        self.timeout = timeout

        if max_objects is None:
            raw_mo = os.environ.get("AEGIS_TAXII_MAX_OBJECTS", str(_DEFAULT_MAX_OBJECTS))
            try:
                max_objects = max(1, int(raw_mo))
            except ValueError:
                logger.warning(
                    "STIXTAXIIIngestor: invalid AEGIS_TAXII_MAX_OBJECTS=%r; using %d",
                    raw_mo,
                    _DEFAULT_MAX_OBJECTS,
                )
                max_objects = _DEFAULT_MAX_OBJECTS
        self.max_objects = max_objects

    # ── Public API ────────────────────────────────────────────────────────────

    def ingest(self, api_root: str | None = None) -> IngestResult:
        """Pull indicators from the configured TAXII server and collection.

        When *api_root* is None, the first API root returned by the server
        discovery endpoint is used.

        Parameters
        ----------
        api_root:
            Override the API root URL (useful for direct collection access
            without server discovery).
        """
        result = IngestResult()

        if not self.taxii_url and not api_root:
            result.success = False
            result.errors.append("AEGIS_TAXII_URL not configured")
            return result

        # Step 1: discover API root
        effective_api_root = api_root
        if not effective_api_root:
            try:
                effective_api_root = self._discover_api_root()
            except Exception as exc:
                result.success = False
                result.errors.append(f"Discovery failed: {exc}")
                return result

        # Step 2: find collection
        collection_id = self.collection_id
        if not collection_id:
            try:
                collections = self.list_collections(effective_api_root)
                readable = [c for c in collections if c.can_read]
                if not readable:
                    result.success = False
                    result.errors.append("No readable collections found")
                    return result
                collection_id = readable[0].id
            except Exception as exc:
                result.success = False
                result.errors.append(f"Collection listing failed: {exc}")
                return result

        result.collections_queried.append(collection_id)

        # Step 3: pull objects
        try:
            objects = self._fetch_objects(effective_api_root, collection_id)
        except Exception as exc:
            result.success = False
            result.errors.append(f"Object fetch failed: {exc}")
            return result

        result.total_stix_objects = len(objects)

        # Step 4: parse indicators
        indicators = []
        for obj in objects:
            try:
                if is_prompt_indicator(obj):
                    indicators.append(parse_indicator(obj))
            except Exception as exc:
                result.errors.append(f"Failed to parse object {obj.get('id', '?')}: {exc}")

        # Step 5: link relationships
        try:
            link_relationships(indicators, objects)
        except Exception as exc:
            result.errors.append(f"Relationship linking failed: {exc}")

        result.indicators = indicators

        # Step 6: extract unique WAF patterns
        seen: set[str] = set()
        for ind in indicators:
            if ind.waf_pattern and ind.waf_pattern not in seen:
                seen.add(ind.waf_pattern)
                result.waf_patterns.append(ind.waf_pattern)

        logger.info(
            "stix_taxii_ingestor: ingested %d STIX objects → %d indicators → %d WAF patterns",
            result.total_stix_objects,
            len(result.indicators),
            len(result.waf_patterns),
        )
        return result

    def list_collections(self, api_root: str) -> list[TaxiiCollection]:
        """Return the list of collections from *api_root*/collections/."""
        url = f"{api_root.rstrip('/')}/collections/"
        data = self._get_json(url)
        raw = data.get("collections", [])
        return [
            TaxiiCollection(
                id=str(c.get("id", "")),
                title=str(c.get("title", "")),
                can_read=bool(c.get("can_read", True)),
                description=str(c.get("description", "")),
            )
            for c in raw
            if c.get("id")
        ]

    def ingest_bundle(self, bundle: dict[str, object]) -> IngestResult:
        """Ingest indicators directly from a STIX Bundle dict (no HTTP call).

        Useful for offline testing or pre-fetched bundle files.
        """
        result = IngestResult()
        objects = parse_stix_bundle(bundle)
        result.total_stix_objects = len(objects)

        for obj in objects:
            try:
                if is_prompt_indicator(obj):
                    result.indicators.append(parse_indicator(obj))
            except Exception as exc:
                result.errors.append(f"Parse error for {obj.get('id', '?')}: {exc}")

        try:
            link_relationships(result.indicators, objects)
        except Exception as exc:
            result.errors.append(f"Relationship linking failed: {exc}")

        seen: set[str] = set()
        for ind in result.indicators:
            if ind.waf_pattern and ind.waf_pattern not in seen:
                seen.add(ind.waf_pattern)
                result.waf_patterns.append(ind.waf_pattern)

        return result

    # ── Internal ──────────────────────────────────────────────────────────────

    def _headers(self) -> dict[str, str]:
        h = {"Accept": "application/taxii+json;version=2.1"}
        if self.api_token:
            h["Authorization"] = f"Bearer {self.api_token}"
        return h

    def _get_json(self, url: str) -> dict[str, object]:
        url = _validate_http_endpoint(url)
        try:
            import httpx

            with httpx.Client(timeout=self.timeout) as client:
                resp = client.get(url, headers=self._headers())
                resp.raise_for_status()
                return resp.json()
        except ImportError:
            import json
            import urllib.request

            req = urllib.request.Request(url, headers=self._headers())  # noqa: S310
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310  # nosec B310
                return json.loads(resp.read().decode())

    def _discover_api_root(self) -> str:
        data = self._get_json(f"{self.taxii_url}/")
        api_roots = data.get("api_roots", [])
        if not api_roots:
            raise ValueError("TAXII discovery returned no api_roots")
        return str(api_roots[0]).rstrip("/")

    def _fetch_objects(self, api_root: str, collection_id: str) -> list[dict[str, object]]:
        url = f"{api_root.rstrip('/')}/collections/{collection_id}/objects/"
        params = f"?limit={self.max_objects}"
        data = self._get_json(f"{url}{params}")
        return list(parse_stix_bundle(data))


# ── Module-level convenience wrappers ─────────────────────────────────────────


def ingest_bundle(bundle: dict[str, object]) -> IngestResult:
    """Ingest a STIX Bundle dict offline (no HTTP call).

    Convenience wrapper around :meth:`STIXTAXIIIngestor.ingest_bundle` for
    callers that do not need a configured :class:`STIXTAXIIIngestor` instance.
    """
    return STIXTAXIIIngestor().ingest_bundle(bundle)

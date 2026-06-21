# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.classified_marker_detector — Pre-forwarding classified-data blocking.

Detects DoD/IC classification markings in request/response text and blocks
forwarding to any non-accredited upstream endpoint.  This implements the
"Classified-data cryptographic blocking" control in Domain 1.3 (Air-Gap &
Disconnected Operations).

Detected marker categories
--------------------------
* **Formal classification banners** — ``SECRET//``, ``TOP SECRET//``, ``TS//``,
  ``CONFIDENTIAL//``, ``UNCLASSIFIED//`` with portion-mark slashes.
* **SCI compartment indicators** — ``//SI`` (Special Intelligence), ``//TK``
  (TALENT KEYHOLE), ``//HCS`` / ``//HCS-P`` / ``//HCS-O`` (HUMINT Control
  System), ``//G`` (GAMMA), ``//KDK`` (KLONDIKE).
* **Dissemination control markings** — ``//NOFORN``, ``//ORCON``, ``//PROPIN``,
  ``//RSEN``, ``//WNINTEL``, ``//FOUO`` (For Official Use Only).
* **Coalition / REL TO markings** — ``//REL TO``, ``//FVEY``, ``//EYES ONLY``.
* **Handling caveats** — ``HANDLE VIA COMINT CHANNELS ONLY``,
  ``HANDLE VIA SCI CHANNELS ONLY``, ``SCI INFORMATION``.
* **Classification authority lines** — ``CLASSIFIED BY:``, ``DERIVED FROM:``,
  ``DECLASSIFY ON:``, ``REASON:``.
* **Special Access Program indicators** — ``SPECIAL ACCESS REQUIRED``,
  ``SAP MATERIAL``, ``SAP-PROTECTED``, explicit ``(SAP)`` tags.

Blocking policy
---------------
Any single match in the request body or response causes an immediate
**BLOCK**.  There is no partial-block or warn-only mode in this module —
callers may implement a softer mode by inspecting the
:attr:`MarkerDetectionResult.markers_found` list and deciding per marker.

Usage::

    detector = ClassifiedMarkerDetector()
    result = detector.scan("The SECRET//SI//NOFORN document states …")
    if result.blocked:
        raise HTTPException(403, detail=result.reason)

    # Scan a list of chat messages:
    result = detector.scan_messages(request.messages)

Integration with the proxy handler
------------------------------------
The detector is called on inbound request text before forwarding, and on
the upstream response before returning.  If a classified marker is found in
the *request*, the request is rejected before any data leaves the perimeter.
If found in the *response*, the response is suppressed and the incident is
logged.

Extending the pattern set
--------------------------
To add custom markers for specific SAP codewords or organizational caveats::

    detector = ClassifiedMarkerDetector(
        extra_patterns=[r"\\bPROJECT\\s+BLACKBIRD\\b"]
    )
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# ── Classification marker patterns ────────────────────────────────────────────
#
# Patterns are ordered from most specific to least specific.  All patterns are
# matched case-insensitively.  We use raw string word-boundary and slash-
# anchor heuristics rather than full parser so the module remains dependency-free.

_MARKER_PATTERNS: list[tuple[str, str]] = [
    # ── Formal banners (portion-mark style) ──────────────────────────────────
    ("CLASSIFICATION_BANNER_TS", r"\bTOP\s+SECRET//"),
    ("CLASSIFICATION_BANNER_S", r"\bSECRET//"),
    ("CLASSIFICATION_BANNER_C", r"\bCONFIDENTIAL//"),
    ("CLASSIFICATION_BANNER_TS_ABBREV", r"\bTS//"),
    ("CLASSIFICATION_BANNER_S_ABBREV", r"\bS//"),
    # Also catch bare full-word TS/S marking followed by SCI indicators
    ("CLASSIFICATION_SCI_CHAIN", r"\b(?:TS|S)\s*/\s*/\s*(?:SI|TK|HCS|G\b|KDK)"),
    # ── SCI compartment indicators ────────────────────────────────────────────
    ("SCI_SI", r"//SI\b"),  # Special Intelligence
    ("SCI_TK", r"//TK\b"),  # TALENT KEYHOLE (satellite)
    ("SCI_HCS", r"//HCS(?:-[PO])?\b"),  # HUMINT Control System
    ("SCI_GAMMA", r"//G\b"),  # GAMMA (signals intelligence)
    ("SCI_KDK", r"//KDK\b"),  # KLONDIKE
    ("SCI_VRK", r"//VRK\b"),  # VERY RESTRICTED KNOWLEDGE
    # ── Dissemination control markings ───────────────────────────────────────
    ("DCTRL_NOFORN", r"//NOFORN\b"),
    ("DCTRL_ORCON", r"//ORCON\b"),  # Originator Controlled
    ("DCTRL_PROPIN", r"//PROPIN\b"),  # Proprietary Information
    ("DCTRL_RSEN", r"//RSEN\b"),  # Risk Sensitive
    ("DCTRL_WNINTEL", r"//WNINTEL\b"),  # Warning Notice Intel Sources
    ("DCTRL_FOUO", r"//FOUO\b"),  # For Official Use Only (marking)
    ("DCTRL_FISA", r"//FISA\b"),  # Foreign Intelligence Surveillance
    # ── REL TO / coalition markings ───────────────────────────────────────────
    ("REL_TO", r"//REL\s+TO\b"),
    ("REL_FVEY", r"//FVEY\b"),  # Five Eyes
    ("REL_ACGU", r"//ACGU\b"),  # AUSCANUKUS
    ("EYES_ONLY", r"//EYES\s+ONLY\b"),
    # ── Handling caveats (full phrase) ───────────────────────────────────────
    ("CAVEAT_COMINT", r"\bHANDLE\s+VIA\s+COMINT\s+CHANNELS?\s+ONLY\b"),
    ("CAVEAT_SCI", r"\bHANDLE\s+VIA\s+SCI\s+CHANNELS?\s+ONLY\b"),
    ("CAVEAT_SCI_INFO", r"\bSCI\s+INFORMATION\b"),
    ("CAVEAT_SPECAT", r"\bSPECATL?\b"),  # SPECAT special category
    # ── Classification authority lines ───────────────────────────────────────
    ("AUTHORITY_CLASSIFIED_BY", r"\bCLASSIFIED\s+BY\s*:"),
    ("AUTHORITY_DERIVED_FROM", r"\bDERIVED\s+FROM\s*:"),
    ("AUTHORITY_DECLASSIFY", r"\bDECLASSIFY\s+ON\s*:"),
    # ── Special Access Program indicators ────────────────────────────────────
    ("SAP_REQUIRED", r"\bSPECIAL\s+ACCESS\s+REQUIRED\b"),
    ("SAP_MATERIAL", r"\bSAP\s+(?:MATERIAL|PROTECTED|INFORMATION|PROGRAM)\b"),
    ("SAP_TAG", r"\(SAP\)"),
    ("SAP_ABBREVIATED", r"\bSAP-PROTECTED\b"),
]

# Compile all patterns once at module load.
_COMPILED: list[tuple[str, re.Pattern[str]]] = [
    (label, re.compile(pat, re.IGNORECASE | re.MULTILINE)) for label, pat in _MARKER_PATTERNS
]


# ── Result dataclass ──────────────────────────────────────────────────────────


@dataclass
class MarkerDetectionResult:
    """Outcome of a classified-marker scan.

    Attributes
    ----------
    blocked:
        True when one or more markers were found and forwarding must be blocked.
    markers_found:
        List of ``(label, matched_text)`` pairs, one per match.
    reason:
        Human-readable description for audit logging.  Contains no content
        from the scanned text beyond the matched marker token itself.
    scan_length:
        Number of characters scanned (for audit sizing).
    """

    blocked: bool
    markers_found: list[tuple[str, str]] = field(default_factory=list)
    reason: str = ""
    scan_length: int = 0

    def __bool__(self) -> bool:
        return self.blocked

    def to_dict(self) -> dict[str, object]:
        return {
            "blocked": self.blocked,
            "markers_found": [
                {"label": label, "match": match} for label, match in self.markers_found
            ],
            "reason": self.reason,
            "scan_length": self.scan_length,
        }


# ── Detector ─────────────────────────────────────────────────────────────────


class ClassifiedMarkerDetector:
    """Stateless, thread-safe detector for DoD/IC classification markers.

    Compile once; call :meth:`scan` on every request/response text fragment
    before forwarding.

    Parameters
    ----------
    extra_patterns:
        Optional list of additional regex patterns (raw strings) to include
        alongside the built-in set.  Use for SAP codewords or organizational
        caveats specific to a deployment.  Each pattern is compiled with
        ``re.IGNORECASE | re.MULTILINE``.
    extra_label:
        Label prefix applied to matches from *extra_patterns*
        (e.g. ``"CUSTOM"``).
    """

    def __init__(
        self,
        extra_patterns: list[str] | None = None,
        extra_label: str = "CUSTOM",
    ) -> None:
        self._patterns = list(_COMPILED)
        if extra_patterns:
            for i, pat in enumerate(extra_patterns):
                label = f"{extra_label}_{i}" if len(extra_patterns) > 1 else extra_label
                self._patterns.append((label, re.compile(pat, re.IGNORECASE | re.MULTILINE)))

    def scan(self, text: str) -> MarkerDetectionResult:
        """Scan *text* for classification markers.

        Returns a :class:`MarkerDetectionResult` with ``blocked=True`` if any
        marker is found.  The scan stops at the first pattern that matches for
        performance, but records only the first match of each matching pattern.

        Parameters
        ----------
        text:
            Raw text to scan (request body or response content).
        """
        if not text:
            return MarkerDetectionResult(
                blocked=False,
                reason="empty text; no markers detected",
                scan_length=0,
            )

        markers_found: list[tuple[str, str]] = []
        for label, rx in self._patterns:
            m = rx.search(text)
            if m:
                markers_found.append((label, m.group(0)))

        if not markers_found:
            return MarkerDetectionResult(
                blocked=False,
                reason="no classification markers detected",
                scan_length=len(text),
            )

        labels = ", ".join(label for label, _ in markers_found)
        return MarkerDetectionResult(
            blocked=True,
            markers_found=markers_found,
            reason=f"classified marker(s) detected: {labels}; forwarding blocked",
            scan_length=len(text),
        )

    def scan_messages(self, messages: list[dict[str, object]]) -> MarkerDetectionResult:
        """Scan all ``"content"`` fields in a list of chat message dicts.

        Returns the first blocking result if any message triggers, otherwise
        a clean result.
        """
        combined_markers: list[tuple[str, str]] = []
        total_len = 0
        for msg in messages:
            content = msg.get("content")
            if isinstance(content, str) and content:
                result = self.scan(content)
                total_len += result.scan_length
                combined_markers.extend(result.markers_found)

        if not combined_markers:
            return MarkerDetectionResult(
                blocked=False,
                reason="no classification markers detected across messages",
                scan_length=total_len,
            )

        labels = ", ".join(label for label, _ in combined_markers)
        return MarkerDetectionResult(
            blocked=True,
            markers_found=combined_markers,
            reason=f"classified marker(s) detected in messages: {labels}; forwarding blocked",
            scan_length=total_len,
        )

    def scan_text_bulk(self, texts: list[str]) -> MarkerDetectionResult:
        """Scan multiple text fragments and aggregate results.

        Useful when request content spans multiple fields (e.g. system prompt
        + user message + tool outputs).
        """
        combined_markers: list[tuple[str, str]] = []
        total_len = 0
        for text in texts:
            r = self.scan(text)
            total_len += r.scan_length
            combined_markers.extend(r.markers_found)

        if not combined_markers:
            return MarkerDetectionResult(
                blocked=False,
                reason="no classification markers detected",
                scan_length=total_len,
            )

        labels = ", ".join(label for label, _ in combined_markers)
        return MarkerDetectionResult(
            blocked=True,
            markers_found=combined_markers,
            reason=f"classified marker(s) detected: {labels}; forwarding blocked",
            scan_length=total_len,
        )

    @property
    def pattern_count(self) -> int:
        """Total number of marker patterns active in this detector."""
        return len(self._patterns)

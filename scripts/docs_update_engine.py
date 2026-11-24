#!/usr/bin/env python3
"""Idempotent documentation text transformations for the 5.1.0 baseline pass.

Every function is pure: (str) -> str. Safe to run repeatedly; changes nothing
unless a rule matches. Intended to be imported by a per-file driver that reads,
transforms, writes only when changed, and reports a diff summary.

Scope of this engine (mechanical only — human judgment decides the rest):
* align superseded baseline version tokens (4.1.2 / 5.0.0 / 5.0.1 / 5.0.3) ->
  5.1.0, but ONLY when the token is presented as the current checked-out
  source baseline and is NOT framed as a historical/published release.
* ensure a final newline.
* report (never auto-remove) prohibited phrases and placeholders; those need a
  reviewer decision per docs/STYLE_GUIDE.md sections 3 and 11.
"""
from __future__ import annotations

import re

CURRENT_VERSION = "5.1.0"

# Tokens that must never appear as the *checked-out / source / current* baseline.
# 5.0.3 is the immediately preceding baseline that surfaces as "checked out" in
# many docs and must be realigned to 5.1.0.
SUPERSEDED = ("4.1.2", "5.0.0", "5.0.1", "5.0.3")

# Present-as-current-baseline indicators (required for a replacement).
_CURRENT_CONTEXT_RE = re.compile(
    r"\b(?:baseline|source|checked.out|current|target|synchronized)\b",
    re.IGNORECASE,
)

# Historical/published framing (forbids replacement of the token).
_HISTORICAL_CONTEXT_RE = re.compile(
    r"\b(?:published|released|read ?back|historical|prior|legacy|superseded|retained|frozen)\b",
    re.IGNORECASE,
)

# Phrases that must never be asserted as fact (STYLE_GUIDE.md section 3).
PROHIBITED = (
    "fully compliant", "legally admissible", "immutable by default",
    "production-ready", "production ready", "game-changing", "revolutionary",
    "best-in-class", "world-class", "unmatched", "market-leading", "top #1",
    "soc 2 certified", "soc2 certified", "soc 2 compliant", "soc2 compliant",
    "soc 2 ready", "soc2 ready", "iso 27001 compliant", "hipaa compliant",
    "hipaa certified", "hipaa ready", "hipaa-ready", "gdpr compliant",
    "gdpr certified", "gdpr-compliant", "fedramp authorized", "fedramp compliant",
    "pci compliant", "pci-dss compliant", "court-admissible", "admissible in court",
    "satisfies hipaa", "satisfies gdpr", "satisfies soc 2", "meets hipaa",
    "meets soc 2", "audit-proof", "guarantees prevention", "guaranteed prevention",
    "removes all pii", "guaranteed uptime",
)

PLACEHOLDER_RE = re.compile(
    r"\b(TBD|TODO|FIXME|XXX|PLACEHOLDER|Lorem ipsum|Coming soon)\b",
    re.IGNORECASE,
)


def align_version_tokens(line: str, current: str = CURRENT_VERSION) -> str:
    """Replace a superseded version presented as current baseline.

    A superseded token is replaced only when the line presents it as the
    current checked-out/source baseline (baseline/source/checked-out/current/
    target/synchronized) AND the line does not frame it as a historical or
    published release (published/released/read back/historical/prior/legacy/
    superseded/retained/frozen).
    """
    if not _CURRENT_CONTEXT_RE.search(line):
        return line
    for sup in SUPERSEDED:
        pattern = re.compile(rf"\bv?{re.escape(sup)}\b", re.IGNORECASE)

        def repl(m: re.Match[str], _sup: str = sup) -> str:
            if _HISTORICAL_CONTEXT_RE.search(line):
                return m.group(0)
            return current

        line = pattern.sub(repl, line)
    return line


def ensure_trailing_newline(text: str) -> str:
    return text if text.endswith("\n") else text + "\n"


def report_prohibited_phrases(text: str) -> list[str]:
    """Return prohibited phrases found (for human review; engine does not edit)."""
    return [p for p in PROHIBITED if p.lower() in text.lower()]


def remove_placeholders(text: str) -> str:
    return PLACEHOLDER_RE.sub("[REVIEW REQUIRED]", text)

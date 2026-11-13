"""Reversible tokenisation of structured identifiers, with declared limits.

It does not detect free-form names without an explicit label (Persona/Nombre/Cliente).
It does not replace an impact assessment and is not an anonymisation guarantee.

The module emits no logs: original values live only in the in-memory ``PIIMap``
of the process serving the request. Nothing is persisted or written to disk,
and no function in this module logs the text it receives.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
# Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
from __future__ import annotations

import re
import secrets
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

TOKEN_RE = re.compile(r"\[\[AEGIS:(?P<kind>[A-Z_]{2,12}):(?P<hex>[0-9a-f]{10})\]\]")
PREFIX = "[[AEGIS:"
SUFFIX = "]]"
# Real maximum token length: prefix + longest kind (12) + ":" + 10 hex + suffix.
MAX_TOKEN_LEN = len(PREFIX) + 12 + 1 + 10 + len(SUFFIX)

RULES: list[tuple[str, re.Pattern[str]]] = [
    ("EMAIL", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)),
    # DNI comes before PHONE: otherwise "DNI: 30123456" is tokenised as a phone
    # number and the semantic label is lost.
    ("DNI", re.compile(r"(?i)\bDNI\s*[:#]?\s*(\d{7,8})\b")),
    ("CUIL", re.compile(r"(?i)\bCUIL\s*[:#]?\s*(\d{2}-?\d{8}-?\d)")),
    ("CUIT", re.compile(r"(?i)\bCUIT\s*[:#]?\s*(\d{2}-?\d{8}-?\d)")),
    ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    # IBAN comes before CARD: the digit groups of a printed IBAN
    # ("GB82 WEST 1234 5698 7654 32") would otherwise be taken as a card number
    # and the country and bank code would reach the provider. Groups of four
    # separated by one space are the printed form; the contiguous form matches too.
    (
        "IBAN",
        re.compile(
            r"\b[A-Z]{2}\d{2}(?=(?: ?[A-Z0-9]){11})(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b"
        ),
    ),
    # A "+" prefix marks a phone number (E.164), not a card.
    ("CARD", re.compile(r"(?<!\+)\b(?:\d[ -]*?){13,19}\b")),
    # PHONE requires separators or an international prefix; a bare 8-digit
    # integer is left alone (so dates, IDs and codes are not mangled). An
    # unseparated E.164 number ("+14155552671") is recognised by its "+".
    (
        "PHONE",
        re.compile(
            r"(?<![\w+])(?:\+\d{8,15}(?!\w)|(?:\+\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)[\s.-]?)?"
            r"\d{3,4}[\s.-]\d{3,4}(?:[\s.-]\d{2,4})?(?!\w))"
        ),
    ),
    (
        "PERSON",
        # The label is case-insensitive; the name is not, so the following
        # lowercase word is not swallowed ("Juan Pérez llamó" → "Juan Pérez").
        re.compile(
            r"(?i:\b(?:persona|nombre|cliente)\s*:\s*)"
            r"([A-ZÁÉÍÓÚÑ][a-záéíóúñ]+(?:\s+[A-ZÁÉÍÓÚÑ][a-záéíóúñ]+){0,2})"
        ),
    ),
]

VALID_KINDS: frozenset[str] = frozenset(kind for kind, _ in RULES)
DEFAULT_KINDS: str = "EMAIL,DNI,CUIL,CUIT,SSN,PHONE,CARD,IBAN,PERSON"

# Keys whose text value is tokenised. The rest of the body (role, model,
# tool identifiers, schemas, stop sequences) is kept literally: it is not
# free-form content. ``arguments`` is a tool call's JSON string and ``user`` the
# caller-supplied end-user id, both of which can carry an identifier.
TEXT_KEYS = {"content", "text", "system", "prompt", "arguments", "user"}
# Keys whose whole subtree is caller data: an Anthropic ``tool_use`` block's
# ``input`` is arbitrary JSON, so every string inside it is tokenised.
DEEP_KEYS = {"input"}


class UnknownPIIKind(ValueError):  # noqa: N818 - name is part of the module's public contract
    """A kind that is not in :data:`RULES` was requested."""


def parse_vault_types(spec: str) -> frozenset[str]:
    """Turn ``"EMAIL,DNI"`` into the set of validated kinds.

    An unknown kind is a startup error, not a warning: tokenising with a set the
    operator believes is larger than it is would be a false guarantee.
    """
    kinds = {part.strip().upper() for part in (spec or "").split(",") if part.strip()}
    unknown = kinds - VALID_KINDS
    if unknown:
        raise UnknownPIIKind(f"unknown PII vault types: {sorted(unknown)}")
    if not kinds:
        # An enabled vault with no kinds tokenises nothing while the gateway
        # treats it as active: refuse it like an unknown kind.
        raise UnknownPIIKind("no PII vault types configured")
    return frozenset(kinds)


@dataclass(frozen=True)
class PIIVaultPolicy:
    """An organisation's effective, validated policy."""

    kinds: frozenset[str] = field(default_factory=lambda: frozenset(VALID_KINDS))

    @classmethod
    def from_spec(cls, spec: str) -> PIIVaultPolicy:
        return cls(kinds=parse_vault_types(spec))


@dataclass
class PIIMap:
    """Two-way token ↔ value map for a single request.

    ``by_value`` deduplicates: the same value yields the same token within the
    request, so the model sees a stable reference. The map is discarded when the
    response ends; it is never serialised or logged.
    """

    by_token: dict[str, str] = field(default_factory=dict)
    by_value: dict[tuple[str, str], str] = field(default_factory=dict)
    #: Number of tokens replaced by :meth:`restore` so far. Evidence records
    #: ``pii_restored`` only when this is non-zero.
    restored: int = 0

    def token_for(self, kind: str, value: str) -> str:
        if kind not in VALID_KINDS:
            raise UnknownPIIKind(f"unknown PII kind: {kind!r}")
        key = (kind, value)
        existing = self.by_value.get(key)
        if existing is not None:
            return existing
        # A collision is unlikely (40 bits) but not assumed away: the new token
        # is checked against every live token before it is accepted.
        for _ in range(64):
            hex_part = secrets.token_hex(5)
            if hex_part.isdigit():
                # An all-digit token body could be read as a phone or account
                # number by the PHI/PCI scrubbers that run after the vault,
                # which would break the token.
                continue
            token = f"{PREFIX}{kind}:{hex_part}{SUFFIX}"
            if token not in self.by_token:
                self.by_value[key] = token
                self.by_token[token] = value
                return token
        raise RuntimeError("PII vault token space exhausted for this request")

    def restore(self, text: str) -> str:
        """Replace known tokens; unknown ones are left intact."""
        if not text or PREFIX not in text:
            return text

        def _swap(match: re.Match[str]) -> str:
            value = self.by_token.get(match.group(0))
            if value is None:
                return match.group(0)
            self.restored += 1
            return value

        return TOKEN_RE.sub(_swap, text)

    def clear(self) -> None:
        self.by_token.clear()
        self.by_value.clear()
        self.restored = 0

    def counts(self) -> dict[str, int]:
        """Number of distinct values per kind. Counts only, never values."""
        counts: dict[str, int] = {}
        for kind, _value in self.by_value:
            counts[kind] = counts.get(kind, 0) + 1
        return counts

    def __len__(self) -> int:
        return len(self.by_token)


def _replace_rule(
    text: str,
    pattern: re.Pattern[str],
    kind: str,
    mapping: PIIMap,
) -> str:
    """Tokenise only the captured group, keeping the context label.

    The string is rebuilt piece by piece instead of using ``str.replace``: a
    value that also appears in the label (e.g. ``CUIT: CUIT``) cannot cause the
    wrong part to be replaced.
    """
    pieces: list[str] = []
    last = 0
    for match in pattern.finditer(text):
        if match.start() < last:
            continue
        if match.groups():
            value = match.group(1)
            start, end = match.span(1)
        else:
            value = match.group(0)
            start, end = match.span(0)
        if not value:
            continue
        pieces.append(text[last:start])
        pieces.append(mapping.token_for(kind, value))
        last = end
    if not pieces:
        return text
    pieces.append(text[last:])
    return "".join(pieces)


def tokenize_text(
    text: str,
    mapping: PIIMap,
    kinds: Iterable[str] | None = None,
) -> str:
    """Tokenise the identifiers recognised in *text*.

    ``kinds`` restricts the active rules (the per-organisation extension point; gateway-wide in 5.1.0). Rules
    apply in order, most specific first, so a semantic label (DNI, CUIT, PERSON)
    is not downgraded to a generic kind.
    """
    if not text:
        return text
    enabled = set(kinds) if kinds is not None else None
    out = text
    for kind, pattern in RULES:
        if enabled is not None and kind not in enabled:
            continue
        out = _replace_rule(out, pattern, kind, mapping)
    return out


def restore_text(text: str, mapping: PIIMap) -> str:
    """Restore the tokens present in *text* using *mapping*."""
    return mapping.restore(text)


def tokenize_json(
    value: Any,
    mapping: PIIMap,
    kinds: Iterable[str] | None = None,
    *,
    _text: bool = False,
    _deep: bool = False,
) -> Any:
    """Recursively tokenise the text fields of a JSON body.

    Every container is walked (a list under ``messages`` or ``content``), but a
    string is transformed only when its key is in :data:`TEXT_KEYS` (a list
    under such a key passes that on to its strings) or it sits anywhere under a
    :data:`DEEP_KEYS` key. Strings elsewhere (role, model, ids, a tool schema's
    ``enum``, ``stop``) reach the provider unchanged.
    """
    if isinstance(value, str):
        return tokenize_text(value, mapping, kinds) if (_text or _deep) else value
    if isinstance(value, list):
        return [tokenize_json(item, mapping, kinds, _text=_text, _deep=_deep) for item in value]
    if isinstance(value, dict):
        return {
            key: tokenize_json(
                item,
                mapping,
                kinds,
                _text=key in TEXT_KEYS,
                _deep=_deep or key in DEEP_KEYS,
            )
            for key, item in value.items()
        }
    return value


def restore_json(value: Any, mapping: PIIMap) -> Any:
    """Restore every token in a JSON body, at any depth."""
    if isinstance(value, str):
        return mapping.restore(value)
    if isinstance(value, list):
        return [restore_json(item, mapping) for item in value]
    if isinstance(value, dict):
        return {key: restore_json(item, mapping) for key, item in value.items()}
    return value


VAULT_INSTRUCTION = (
    "Los valores con forma [[AEGIS:TIPO:hex]] son referencias opacas a datos "
    "del usuario. Úsalos literalmente, no los interpretes, no los inventes y "
    "no intentes reconstruir su contenido. Devuélvelos tal cual cuando "
    "necesites referirte a ellos."
)


def _instruction_present(system: Any, messages: Any) -> bool:
    if isinstance(system, str) and VAULT_INSTRUCTION in system:
        return True
    if isinstance(system, list):
        for block in system:
            if isinstance(block, dict) and VAULT_INSTRUCTION in str(block.get("text", "")):
                return True
    if isinstance(messages, list) and messages:
        first = messages[0]
        if isinstance(first, dict):
            content = first.get("content")
            if isinstance(content, str) and VAULT_INSTRUCTION in content:
                return True
            if isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and VAULT_INSTRUCTION in str(block.get("text", "")):
                        return True
    return False


def inject_vault_instruction(body: dict[str, Any]) -> dict[str, Any]:
    """Add the instruction without removing the existing system prompt.

    Idempotent: a body that already carries it does not get a second copy. A
    body without ``messages`` is left untouched (it is not a chat conversation).
    """
    if not isinstance(body, dict) or body.get("messages") is None:
        return body
    system = body.get("system")
    messages = body.get("messages")
    if _instruction_present(system, messages):
        return body
    if system is not None:  # Anthropic
        if isinstance(system, str):
            body["system"] = VAULT_INSTRUCTION + "\n\n" + system
        elif isinstance(system, list):
            body["system"] = [{"type": "text", "text": VAULT_INSTRUCTION}, *system]
        return body
    if isinstance(messages, list):
        body["messages"] = [{"role": "system", "content": VAULT_INSTRUCTION}, *messages]
    return body


__all__ = [
    "DEEP_KEYS",
    "DEFAULT_KINDS",
    "MAX_TOKEN_LEN",
    "PIIMap",
    "PIIVaultPolicy",
    "PREFIX",
    "RULES",
    "SUFFIX",
    "TEXT_KEYS",
    "TOKEN_RE",
    "UnknownPIIKind",
    "VALID_KINDS",
    "VAULT_INSTRUCTION",
    "inject_vault_instruction",
    "parse_vault_types",
    "restore_json",
    "restore_text",
    "tokenize_json",
    "tokenize_text",
]

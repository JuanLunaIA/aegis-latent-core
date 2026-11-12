"""Tokenización reversible de identificadores estructurados, con límites declarados.

No detecta nombres libres sin una etiqueta explícita (Persona/Nombre/Cliente).
No sustituye una evaluación de impacto ni una garantía de anonimización.

El módulo no emite logs: los valores originales sólo viven en el ``PIIMap`` en
memoria del proceso que atiende la petición. No hay persistencia ni escritura a
disco, y ninguna función de este módulo registra el texto recibido.
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
# Longitud máxima real de un token: prefijo + tipo más largo (12) + ":" + 10 hex + sufijo.
MAX_TOKEN_LEN = len(PREFIX) + 12 + 1 + 10 + len(SUFFIX)

RULES: list[tuple[str, re.Pattern[str]]] = [
    ("EMAIL", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)),
    # DNI va antes que PHONE: si no, "DNI: 30123456" se tokeniza como teléfono y
    # se pierde la etiqueta semántica.
    ("DNI", re.compile(r"(?i)\bDNI\s*[:#]?\s*(\d{7,8})\b")),
    ("CUIL", re.compile(r"(?i)\bCUIL\s*[:#]?\s*(\d{2}-?\d{8}-?\d)")),
    ("CUIT", re.compile(r"(?i)\bCUIT\s*[:#]?\s*(\d{2}-?\d{8}-?\d)")),
    ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("CARD", re.compile(r"\b(?:\d[ -]*?){13,19}\b")),
    ("IBAN", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")),
    # PHONE exige separadores o prefijo internacional; un entero de 8 dígitos
    # suelto no se toca (evita destrozar fechas, IDs y códigos).
    (
        "PHONE",
        re.compile(
            r"(?<![\w+])(?:\+\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)[\s.-]?)?"
            r"\d{3,4}[\s.-]\d{3,4}(?:[\s.-]\d{2,4})?(?!\w)"
        ),
    ),
    (
        "PERSON",
        # La etiqueta es case-insensitive; el nombre no, para no arrastrar la
        # palabra siguiente en minúsculas ("Juan Pérez llamó" → "Juan Pérez").
        re.compile(
            r"(?i:\b(?:persona|nombre|cliente)\s*:\s*)"
            r"([A-ZÁÉÍÓÚÑ][a-záéíóúñ]+(?:\s+[A-ZÁÉÍÓÚÑ][a-záéíóúñ]+){0,2})"
        ),
    ),
]

VALID_KINDS: frozenset[str] = frozenset(kind for kind, _ in RULES)
DEFAULT_KINDS: str = "EMAIL,DNI,CUIL,CUIT,SSN,PHONE,CARD,IBAN,PERSON"

# Claves cuyo valor de texto se tokeniza. El resto del cuerpo (rol, modelo,
# identificadores de herramienta) se conserva literal: no es contenido libre.
TEXT_KEYS = {"content", "text", "system", "prompt"}


class UnknownPIIKind(ValueError):  # noqa: N818 - name is part of the module's public contract
    """Se pidió tokenizar un tipo que no está en :data:`RULES`."""


def parse_vault_types(spec: str) -> frozenset[str]:
    """Convierte ``"EMAIL,DNI"`` en el conjunto de tipos validados.

    Un tipo desconocido es un error de arranque, no un aviso: tokenizar con un
    conjunto que el operador cree mayor de lo que es sería una falsa garantía.
    """
    kinds = {part.strip().upper() for part in (spec or "").split(",") if part.strip()}
    unknown = kinds - VALID_KINDS
    if unknown:
        raise UnknownPIIKind(f"unknown PII vault types: {sorted(unknown)}")
    return frozenset(kinds)


@dataclass(frozen=True)
class PIIVaultPolicy:
    """Política efectiva de una organización, ya validada."""

    kinds: frozenset[str] = field(default_factory=lambda: frozenset(VALID_KINDS))

    @classmethod
    def from_spec(cls, spec: str) -> PIIVaultPolicy:
        return cls(kinds=parse_vault_types(spec))


@dataclass
class PIIMap:
    """Mapa bidireccional token ↔ valor de una sola petición.

    ``by_value`` deduplica: el mismo valor produce el mismo token dentro de la
    petición, de modo que el modelo ve una referencia estable. El mapa se
    descarta al terminar la respuesta; no se serializa ni se registra.
    """

    by_token: dict[str, str] = field(default_factory=dict)
    by_value: dict[tuple[str, str], str] = field(default_factory=dict)

    def token_for(self, kind: str, value: str) -> str:
        if kind not in VALID_KINDS:
            raise UnknownPIIKind(f"unknown PII kind: {kind!r}")
        key = (kind, value)
        existing = self.by_value.get(key)
        if existing is not None:
            return existing
        # La colisión es improbable (40 bits) pero no se asume: se comprueba
        # contra todos los tokens vivos antes de aceptar el nuevo.
        for _ in range(64):
            token = f"{PREFIX}{kind}:{secrets.token_hex(5)}{SUFFIX}"
            if token not in self.by_token:
                self.by_value[key] = token
                self.by_token[token] = value
                return token
        raise RuntimeError("PII vault token space exhausted for this request")

    def restore(self, text: str) -> str:
        """Sustituye los tokens conocidos; los desconocidos quedan intactos."""
        if not text or PREFIX not in text:
            return text
        return TOKEN_RE.sub(lambda m: self.by_token.get(m.group(0), m.group(0)), text)

    def clear(self) -> None:
        self.by_token.clear()
        self.by_value.clear()

    def counts(self) -> dict[str, int]:
        """Número de valores distintos por tipo. Sólo cifras, nunca valores."""
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
    """Tokeniza sólo el grupo capturado, preservando la etiqueta de contexto.

    Se reconstruye por tramos en vez de usar ``str.replace``: un valor que
    aparezca también en la etiqueta (p. ej. ``CUIT: CUIT``) no puede provocar
    que se sustituya la parte equivocada.
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
    """Tokeniza los identificadores reconocidos en *text*.

    ``kinds`` restringe las reglas activas (configuración por organización).
    Las reglas se aplican en orden: las más específicas primero, para que una
    etiqueta semántica (DNI, CUIT, PERSON) no se degrade a un tipo genérico.
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
    """Restaura los tokens presentes en *text* usando *mapping*."""
    return mapping.restore(text)


def tokenize_json(
    value: Any,
    mapping: PIIMap,
    kinds: Iterable[str] | None = None,
) -> Any:
    """Tokeniza recursivamente los campos de texto de un cuerpo JSON.

    Se recorre todo contenedor (una lista bajo ``messages`` o ``content``), pero
    sólo se transforman las cadenas bajo :data:`TEXT_KEYS`.
    """
    if isinstance(value, str):
        return tokenize_text(value, mapping, kinds)
    if isinstance(value, list):
        return [tokenize_json(item, mapping, kinds) for item in value]
    if isinstance(value, dict):
        out: dict[Any, Any] = {}
        for key, item in value.items():
            if key in TEXT_KEYS and isinstance(item, str):
                out[key] = tokenize_text(item, mapping, kinds)
            elif isinstance(item, (dict, list)):
                # Se recorre el contenedor para llegar a messages/content, pero
                # una cadena fuera de TEXT_KEYS (rol, modelo, id) no se toca.
                out[key] = tokenize_json(item, mapping, kinds)
            else:
                out[key] = item
        return out
    return value


def restore_json(value: Any, mapping: PIIMap) -> Any:
    """Restaura todos los tokens de un cuerpo JSON, a cualquier profundidad."""
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
    """Añade la instrucción sin borrar el system prompt existente.

    Idempotente: un cuerpo que ya la lleva no recibe una segunda copia. Un
    cuerpo sin ``messages`` no se toca (no es una conversación de chat).
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

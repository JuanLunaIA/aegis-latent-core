# Copyright (c) 2026 Juan Luna. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
# Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
"""PII vault: token format, round trip, collisions and declared limits."""

from __future__ import annotations

import logging

import pytest

from aegis.core.pii_vault import (
    MAX_TOKEN_LEN,
    RULES,
    TEXT_KEYS,
    TOKEN_RE,
    VAULT_INSTRUCTION,
    PIIMap,
    PIIVaultPolicy,
    UnknownPIIKind,
    inject_vault_instruction,
    parse_vault_types,
    restore_json,
    tokenize_json,
    tokenize_text,
)

try:  # Hypothesis is optional in the development environment.
    from hypothesis import HealthCheck, given, settings
    from hypothesis import strategies as st

    HAS_HYPOTHESIS = True
except ImportError:  # pragma: no cover - runs only without the dependency
    HAS_HYPOTHESIS = False
    given = None  # type: ignore[assignment]


# ── format and round trip ───────────────────────────────────────────────────────


def test_email_roundtrip():
    m = PIIMap()
    out = tokenize_text("Escriba a juan@example.com por favor", m)
    assert "juan@example.com" not in out
    token = TOKEN_RE.search(out).group(0)
    assert m.restore(out) == "Escriba a juan@example.com por favor"
    assert token.startswith("[[AEGIS:EMAIL:")


def test_dni_keeps_label():
    m = PIIMap()
    out = tokenize_text("DNI: 30123456", m)
    assert out.startswith("DNI: [[AEGIS:DNI:")
    assert m.restore(out) == "DNI: 30123456"


def test_cuit_and_cuil_keep_label():
    m = PIIMap()
    text = "CUIT: 20-12345678-9 y CUIL 27-30123456-4"
    out = tokenize_text(text, m)
    assert "20-12345678-9" not in out
    assert "27-30123456-4" not in out
    assert "CUIT: [[AEGIS:CUIT:" in out
    assert "CUIL [[AEGIS:CUIL:" in out
    assert m.restore(out) == text


def test_phone_with_separators_roundtrip():
    m = PIIMap()
    out = tokenize_text("Llamá al +54 11 4321-5678 hoy", m)
    assert "4321-5678" not in out
    assert "[[AEGIS:PHONE:" in out
    assert m.restore(out) == "Llamá al +54 11 4321-5678 hoy"


def test_bare_eight_digit_integer_is_not_a_phone():
    """A bare integer is an ID or a date, not a phone number (false positive)."""
    m = PIIMap()
    text = "orden 30123456 del 2026-11-11"
    out = tokenize_text(text, m)
    assert out == text
    assert len(m) == 0


def test_card_roundtrip():
    m = PIIMap()
    out = tokenize_text("tarjeta 4111 1111 1111 1111", m)
    assert "4111" not in out
    assert "[[AEGIS:CARD:" in out
    assert m.restore(out) == "tarjeta 4111 1111 1111 1111"


def test_person_requires_label():
    m = PIIMap()
    out = tokenize_text("Cliente: Juan Pérez llamó", m)
    assert "Juan Pérez" not in out
    assert "[[AEGIS:PERSON:" in out
    assert m.restore(out) == "Cliente: Juan Pérez llamó"


def test_same_value_same_token():
    m = PIIMap()
    out = tokenize_text("a@b.com y a@b.com", m)
    assert len(TOKEN_RE.findall(out)) == 2
    assert len(set(TOKEN_RE.findall(out))) == 1


def test_different_values_different_tokens():
    m = PIIMap()
    out = tokenize_text("a@b.com y c@d.com", m)
    tokens = TOKEN_RE.findall(out)
    assert len(set(tokens)) == 2


def test_restore_unknown_token_is_noop():
    m = PIIMap()
    assert m.restore("[[AEGIS:EMAIL:deadbeef00]]") == "[[AEGIS:EMAIL:deadbeef00]]"


def test_restore_malformed_token_is_noop():
    m = PIIMap()
    for text in (
        "[[AEGIS:EMAIL:DEADBEEF00]]",  # uppercase hex: not the format
        "[[AEGIS:EMAIL:deadbeef0]]",  # 9 hex
        "[[aegis:EMAIL:deadbeef00]]",  # lowercase prefix
        "[[AEGIS:email:deadbeef00]]",  # lowercase kind
    ):
        assert m.restore(text) == text


def test_token_length_and_real_max():
    m = PIIMap()
    token = m.token_for("PERSON", "Juan Pérez")
    assert len(token) <= MAX_TOKEN_LEN
    assert len(token) == len("[[AEGIS:]]") + len("PERSON") + 1 + 10


def test_max_token_len_matches_longest_kind():
    """The cap covers the widest kind ``TOKEN_RE`` accepts (12)."""
    assert MAX_TOKEN_LEN == len("[[AEGIS:") + 12 + 1 + 10 + len("]]")
    for kind, _pattern in RULES:
        assert len(kind) <= 12


def test_collision_is_checked(monkeypatch):
    """If the generator repeats a live token, it is discarded and another is tried."""
    m = PIIMap()
    first = m.token_for("EMAIL", "a@b.com")
    duplicate_hex = TOKEN_RE.match(first).group("hex")
    sequence = iter([duplicate_hex, "0badc0de01"])
    monkeypatch.setattr("aegis.core.pii_vault.secrets.token_hex", lambda _n: next(sequence))
    second = m.token_for("EMAIL", "c@d.com")
    assert second != first
    assert second == "[[AEGIS:EMAIL:0badc0de01]]"
    assert m.by_token[first] == "a@b.com"
    assert m.by_token[second] == "c@d.com"


def test_collision_exhaustion_raises(monkeypatch):
    m = PIIMap()
    first = m.token_for("EMAIL", "a@b.com")
    duplicate_hex = TOKEN_RE.match(first).group("hex")
    monkeypatch.setattr("aegis.core.pii_vault.secrets.token_hex", lambda _n: duplicate_hex)
    with pytest.raises(RuntimeError):
        m.token_for("EMAIL", "c@d.com")


def test_unknown_kind_is_rejected():
    m = PIIMap()
    with pytest.raises(UnknownPIIKind):
        m.token_for("PASSPORT", "X123")


def test_kinds_filter_only_tokenizes_selected_types():
    m = PIIMap()
    text = "DNI: 30123456 y juan@example.com"
    out = tokenize_text(text, m, kinds={"EMAIL"})
    assert "30123456" in out
    assert "juan@example.com" not in out
    assert m.counts() == {"EMAIL": 1}


def test_counts_never_exposes_values():
    m = PIIMap()
    tokenize_text("DNI: 30123456 y DNI: 30123457", m)
    assert m.counts() == {"DNI": 2}
    assert "3012345" not in repr(m.counts())


def test_clear_drops_both_directions():
    m = PIIMap()
    token = m.token_for("EMAIL", "a@b.com")
    m.clear()
    assert len(m) == 0
    assert m.restore(token) == token


def test_module_does_not_log(caplog):
    """The module logs neither the text nor the values."""
    caplog.set_level(logging.DEBUG)
    m = PIIMap()
    out = tokenize_text("DNI: 30123456 juan@example.com", m)
    m.restore(out)
    assert caplog.records == []


def test_parse_vault_types_rejects_unknown_type():
    assert parse_vault_types("EMAIL,DNI") == frozenset({"EMAIL", "DNI"})
    with pytest.raises(UnknownPIIKind):
        parse_vault_types("EMAIL,PASSPORT")
    assert PIIVaultPolicy.from_spec("EMAIL").kinds == frozenset({"EMAIL"})


# ── JSON ─────────────────────────────────────────────────────────────────────


def test_tokenize_json_openai_messages_string_content():
    m = PIIMap()
    body = {
        "model": "m",
        "messages": [{"role": "user", "content": "DNI: 30123456"}],
        "temperature": 0.2,
    }
    out = tokenize_json(body, m)
    assert out["model"] == "m"
    assert out["messages"][0]["role"] == "user"
    assert "30123456" not in out["messages"][0]["content"]
    assert "[[AEGIS:DNI:" in out["messages"][0]["content"]
    assert out["temperature"] == 0.2
    assert restore_json(out, m) == body


def test_tokenize_json_content_blocks():
    m = PIIMap()
    body = {
        "model": "claude",
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "mi mail es juan@example.com"},
                    {"type": "image", "source": {"data": "AAAA"}},
                ],
            }
        ],
        "system": "Sos un asistente.",
    }
    out = tokenize_json(body, m)
    assert "juan@example.com" not in out["messages"][0]["content"][0]["text"]
    assert out["messages"][0]["content"][1] == {
        "type": "image",
        "source": {"data": "AAAA"},
    }
    assert out["system"] == "Sos un asistente."
    assert restore_json(out, m) == body


def test_restore_json_nested_response():
    m = PIIMap()
    token = m.token_for("EMAIL", "a@b.com")
    payload = {
        "choices": [
            {"message": {"content": f"escribí a {token}", "role": "assistant"}},
        ],
        "usage": {"total_tokens": 3},
    }
    assert restore_json(payload, m)["choices"][0]["message"]["content"] == "escribí a a@b.com"


def test_tokenize_json_does_not_touch_role_or_model():
    m = PIIMap()
    body = {"model": "a@b.com", "messages": [{"role": "a@b.com", "content": "hola"}]}
    out = tokenize_json(body, m)
    assert out["model"] == "a@b.com"
    assert out["messages"][0]["role"] == "a@b.com"


def test_text_keys_is_declared_surface():
    assert {"content", "text", "system", "prompt"} <= TEXT_KEYS


# ── placeholder instruction ─────────────────────────────────────────────


def test_instruction_preserves_existing_system():
    body = {"messages": [{"role": "user", "content": "hola"}], "system": "Sos breve."}
    out = inject_vault_instruction(body)
    assert out["system"].startswith(VAULT_INSTRUCTION)
    assert out["system"].endswith("Sos breve.")


def test_instruction_list_system():
    body = {
        "messages": [{"role": "user", "content": "hola"}],
        "system": [{"type": "text", "text": "Sos breve."}],
    }
    out = inject_vault_instruction(body)
    assert out["system"][0] == {"type": "text", "text": VAULT_INSTRUCTION}
    assert out["system"][1]["text"] == "Sos breve."


def test_instruction_without_messages_is_noop():
    body = {"prompt": "hola"}
    assert inject_vault_instruction(body) == {"prompt": "hola"}


def test_instruction_is_idempotent():
    body = {"messages": [{"role": "user", "content": "hola"}]}
    once = inject_vault_instruction(body)
    twice = inject_vault_instruction(once)
    assert twice["messages"].count({"role": "system", "content": VAULT_INSTRUCTION}) == 1
    assert twice["messages"][0]["role"] == "system"


# ── propiedad ────────────────────────────────────────────────────────────────


@pytest.mark.skipif(not HAS_HYPOTHESIS, reason="hypothesis not installed")
@given(st.text(max_size=200))
@settings(max_examples=500, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_roundtrip_arbitrary_text(text: str):
    m = PIIMap()
    out = tokenize_text(text, m)
    assert m.restore(out) == text
    assert m.restore(restore_json(tokenize_json({"content": text}, m), m)["content"]) == text


@pytest.mark.skipif(not HAS_HYPOTHESIS, reason="hypothesis not installed")
@given(
    st.text(max_size=80),
    st.emails(),
    st.text(max_size=80),
)
@settings(max_examples=500, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_roundtrip_with_embedded_email(before: str, email: str, after: str):
    """An email may stay untokenised if it does not start at a word boundary;
    what must never happen is restoration returning something different."""
    m = PIIMap()
    text = f"{before} {email} {after}"
    out = tokenize_text(text, m)
    assert m.restore(out) == text

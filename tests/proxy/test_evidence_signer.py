# Copyright (c) 2026 Juan Luna. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
# Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
"""F-04: every request-response evidence node names the authenticated principal.

The non-streaming commit used to write ``signer_name=""``, so a buffered
completion's record could not say which credential sent it while the streaming
record of the same call could. The signer is the principal's pseudonymous
subject (``api-key:<digest prefix>``), never the key itself.
"""

from __future__ import annotations

from unittest.mock import patch

from fastapi.testclient import TestClient

from aegis.proxy.app import create_app
from tests.proxy.test_pii_vault_gateway import _chat, _completion, _forwarder, _settings


def _expected_signer(settings) -> str:
    return f"api-key:{settings.api_key_principal_digest('sk-valid')[:16]}"


def test_buffered_completion_node_names_the_principal(tmp_path):
    async def reply(path, body, extra_headers=None):
        return _completion("ok")

    settings = _settings(tmp_path)
    with patch("aegis.proxy.app.LLMForwarder", return_value=_forwarder(reply)):
        app = create_app(settings)
        with TestClient(app) as client:
            assert _chat(client, "hola").status_code == 200

    node = app.state.aegis.ledger.chain[-1]
    assert node.signature_meaning == "request-response-evidence"
    assert node.signer_name == _expected_signer(settings)
    assert "sk-valid" not in node.signer_name


def test_durable_error_node_names_the_principal(tmp_path):
    async def reply(path, body, extra_headers=None):
        raise RuntimeError("provider down")

    settings = _settings(tmp_path)
    with patch("aegis.proxy.app.LLMForwarder", return_value=_forwarder(reply)):
        app = create_app(settings)
        with TestClient(app) as client:
            assert _chat(client, "hola").status_code >= 500

    node = app.state.aegis.ledger.chain[-1]
    assert node.signature_meaning == "request-response-evidence"
    assert node.signer_name == _expected_signer(settings)


def test_oidc_and_mtls_subjects_are_keyed_pseudonyms(tmp_path):
    # An OIDC `sub` or mTLS CN can be an email; it must not reach the exported signer.
    settings = _settings(tmp_path)
    oidc = settings.principal_signer_ref("oidc", "ana@example.com")
    mtls = settings.principal_signer_ref("mtls", "ana@example.com")
    assert oidc.startswith("oidc:")
    assert len(oidc) == len("oidc:") + 16
    assert "ana" not in oidc
    assert "example" not in oidc
    assert oidc != mtls.replace("mtls:", "oidc:")
    assert oidc == settings.principal_signer_ref("oidc", "ana@example.com")
    assert settings.principal_signer_ref("api_key", "api-key:abc") == "api-key:abc"

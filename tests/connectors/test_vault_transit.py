# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

"""Vault Transit signer: the digest sent must be the digest signed.

The subtle failure this pins is ``prehashed``. A node hash is already a SHA-256
digest; submitting it without ``prehashed=true`` makes Vault hash it a second
time. The result verifies happily through Vault and matches nothing anyone
computes independently — a signature over the wrong value that looks correct
from inside.

The other properties are about not leaking the token and refusing malformed
input. No network is used.
"""

from __future__ import annotations

import base64
import hashlib

import httpx
import pytest

from aegis.connectors.vault.transit_signer import (
    VaultTransitConfig,
    VaultTransitError,
    VaultTransitSigner,
    decode_vault_signature,
)

NODE_HASH = hashlib.sha256(b"audit-node").hexdigest()


def _config(**overrides) -> VaultTransitConfig:
    params = {
        "url": "https://vault.example.invalid:8200",
        "token": "s.supersecrettoken",
        "key_name": "aegis-evidence",
    }
    params.update(overrides)
    return VaultTransitConfig(**params)


def _recording_transport(requests: list[httpx.Request], response_factory) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return response_factory(request)

    return httpx.MockTransport(handler)


def _sign_ok(request: httpx.Request) -> httpx.Response:
    return httpx.Response(
        200, json={"data": {"signature": "vault:v1:" + base64.b64encode(b"sig").decode()}}
    )


class TestSigning:
    def test_the_digest_is_submitted_prehashed(self):
        """Without this Vault would hash the digest again and sign the wrong value."""

        requests: list[httpx.Request] = []
        with VaultTransitSigner(
            _config(), transport=_recording_transport(requests, _sign_ok)
        ) as signer:
            signer.sign(NODE_HASH)
        import json

        body = json.loads(requests[0].content)
        assert body["prehashed"] is True
        assert body["hash_algorithm"] == "sha2-256"

    def test_the_digest_is_sent_as_base64_of_raw_bytes_not_hex(self):
        requests: list[httpx.Request] = []
        with VaultTransitSigner(
            _config(), transport=_recording_transport(requests, _sign_ok)
        ) as signer:
            signer.sign(NODE_HASH)
        import json

        submitted = json.loads(requests[0].content)["input"]
        assert base64.b64decode(submitted) == bytes.fromhex(NODE_HASH)

    def test_the_signature_is_returned_verbatim(self):
        with VaultTransitSigner(_config(), transport=httpx.MockTransport(_sign_ok)) as signer:
            signature = signer.sign(NODE_HASH)
        assert signature.startswith("vault:v1:")

    def test_the_request_targets_the_configured_mount_and_key(self):
        requests: list[httpx.Request] = []
        with VaultTransitSigner(
            _config(mount="transit-prod", key_name="evidence-2026"),
            transport=_recording_transport(requests, _sign_ok),
        ) as signer:
            signer.sign(NODE_HASH)
        assert requests[0].url.path == "/v1/transit-prod/sign/evidence-2026"

    def test_the_vault_token_travels_as_a_header_not_a_query_parameter(self):
        requests: list[httpx.Request] = []
        with VaultTransitSigner(
            _config(), transport=_recording_transport(requests, _sign_ok)
        ) as signer:
            signer.sign(NODE_HASH)
        assert requests[0].headers["X-Vault-Token"] == "s.supersecrettoken"
        assert "supersecrettoken" not in str(requests[0].url)

    def test_a_namespace_is_sent_when_configured(self):
        requests: list[httpx.Request] = []
        with VaultTransitSigner(
            _config(namespace="team-a"), transport=_recording_transport(requests, _sign_ok)
        ) as signer:
            signer.sign(NODE_HASH)
        assert requests[0].headers["X-Vault-Namespace"] == "team-a"


class TestVerification:
    def test_verify_returns_vaults_verdict(self):
        for valid in (True, False):
            with VaultTransitSigner(
                _config(),
                transport=httpx.MockTransport(
                    lambda r, v=valid: httpx.Response(200, json={"data": {"valid": v}})
                ),
            ) as signer:
                assert signer.verify(NODE_HASH, "vault:v1:AAAA") is valid

    def test_a_missing_valid_field_is_treated_as_not_valid(self):
        """Fail closed: an unexpected shape must not read as a good signature."""

        with VaultTransitSigner(
            _config(),
            transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"data": {}})),
        ) as signer:
            assert signer.verify(NODE_HASH, "vault:v1:AAAA") is False


class TestFailureModes:
    def test_a_non_hex_node_hash_is_refused(self):
        with VaultTransitSigner(_config(), transport=httpx.MockTransport(_sign_ok)) as signer:
            with pytest.raises(VaultTransitError, match="hex-encoded"):
                signer.sign("not-a-hash")

    def test_a_wrong_length_digest_is_refused(self):
        with VaultTransitSigner(_config(), transport=httpx.MockTransport(_sign_ok)) as signer:
            with pytest.raises(VaultTransitError, match="32-byte"):
                signer.sign("abcd")

    def test_an_http_error_raises_without_echoing_the_token(self):
        with VaultTransitSigner(
            _config(),
            transport=httpx.MockTransport(
                lambda r: httpx.Response(403, json={"errors": ["permission denied"]})
            ),
        ) as signer:
            with pytest.raises(VaultTransitError) as excinfo:
                signer.sign(NODE_HASH)
        message = str(excinfo.value)
        assert "permission denied" in message
        assert "supersecrettoken" not in message

    def test_a_connection_error_raises_rather_than_returning_a_placeholder(self):
        def boom(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("unreachable", request=request)

        with VaultTransitSigner(_config(), transport=httpx.MockTransport(boom)) as signer:
            with pytest.raises(VaultTransitError, match="failed"):
                signer.sign(NODE_HASH)

    def test_a_response_without_a_signature_is_refused(self):
        with VaultTransitSigner(
            _config(),
            transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"data": {}})),
        ) as signer:
            with pytest.raises(VaultTransitError, match="no signature"):
                signer.sign(NODE_HASH)

    @pytest.mark.parametrize("field", ["url", "token", "key_name"])
    def test_empty_required_configuration_is_refused(self, field):
        with pytest.raises(ValueError, match="must not be empty"):
            _config(**{field: ""})


class TestSignatureDecoding:
    def test_a_vault_signature_decodes_to_raw_bytes(self):
        encoded = base64.b64encode(b"raw-signature-bytes").decode()
        assert decode_vault_signature(f"vault:v1:{encoded}") == b"raw-signature-bytes"

    @pytest.mark.parametrize(
        "value", ["not-a-signature", "vault:v1", "openssl:v1:AAAA", "vault:v1:!!!!"]
    )
    def test_a_malformed_signature_is_refused(self, value):
        with pytest.raises(VaultTransitError):
            decode_vault_signature(value)


class TestPublicKeyFetch:
    def test_a_public_key_is_returned_for_an_asymmetric_key(self):
        with VaultTransitSigner(
            _config(),
            transport=httpx.MockTransport(
                lambda r: httpx.Response(
                    200,
                    json={"data": {"keys": {"1": {"public_key": "-----BEGIN PUBLIC KEY-----"}}}},
                )
            ),
        ) as signer:
            assert signer.public_key_pem().startswith("-----BEGIN PUBLIC KEY-----")

    def test_a_symmetric_key_without_a_public_half_is_refused(self):
        with VaultTransitSigner(
            _config(),
            transport=httpx.MockTransport(
                lambda r: httpx.Response(
                    200, json={"data": {"keys": {"1": {"creation_time": "x"}}}}
                )
            ),
        ) as signer:
            with pytest.raises(VaultTransitError, match="no public key"):
                signer.public_key_pem()

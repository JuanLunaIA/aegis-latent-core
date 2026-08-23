# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import pytest

from aegis.anchoring.rfc3161 import (
    HTTPResponse,
    RFC3161AnchorClient,
    TimestampTransportError,
    TimestampVerificationError,
    VerificationResult,
)


@dataclass
class Response:
    status_code: int = 200
    content: bytes = b"timestamp-response"
    headers: Mapping[str, str] | None = None

    def __post_init__(self) -> None:
        if self.headers is None:
            self.headers = {"Content-Type": "application/timestamp-reply"}


class Transport:
    def __init__(self, response: object = Response()) -> None:
        self.response = response
        self.request: bytes | None = None
        self.timeout: float | None = None

    async def post(
        self,
        url: str,
        *,
        content: bytes,
        headers: Mapping[str, str],
        timeout: float,
    ) -> HTTPResponse:
        assert url == "https://tsa.example.test"
        assert headers["Content-Type"] == "application/timestamp-query"
        self.request = content
        self.timeout = timeout
        return cast(HTTPResponse, self.response)


class Verifier:
    def __init__(
        self,
        *,
        status: int = 0,
        nonce_delta: int = 0,
        wrong_imprint: bool = False,
        trusted: bool = False,
    ) -> None:
        self.status = status
        self.nonce_delta = nonce_delta
        self.wrong_imprint = wrong_imprint
        self.trusted = trusted

    def verify(
        self,
        *,
        request_der: bytes,
        response_der: bytes,
        expected_imprint: bytes,
        expected_nonce: int,
    ) -> VerificationResult:
        assert request_der.startswith(b"0")
        assert response_der == b"timestamp-response"
        imprint = b"wrong" if self.wrong_imprint else expected_imprint
        return VerificationResult(
            pki_status=self.status,
            message_imprint=imprint,
            nonce=expected_nonce + self.nonce_delta,
            cms_trusted=self.trusted,
        )


def client(tmp_path: Path, verifier: Verifier | None = None) -> RFC3161AnchorClient:
    return RFC3161AnchorClient(
        url="https://tsa.example.test",
        transport=Transport(),
        verifier=verifier or Verifier(),
        evidence_dir=tmp_path,
    )


async def test_request_binds_sha256_nonce_and_persists_full_exchange(tmp_path: Path) -> None:
    transport = Transport()
    instance = RFC3161AnchorClient(
        url="https://tsa.example.test",
        transport=transport,
        verifier=Verifier(trusted=True),
        evidence_dir=tmp_path,
        timeout=2.5,
    )
    result = await instance.anchor(b"exact evidence")

    assert result.message_imprint == hashlib.sha256(b"exact evidence").digest()
    assert result.nonce > 0
    assert result.request_der == transport.request
    assert result.request_path.read_bytes() == result.request_der
    assert result.response_path.read_bytes() == b"timestamp-response"
    assert result.cms_trusted is True
    assert transport.timeout == 2.5
    assert not list(tmp_path.glob("*.tmp"))


@pytest.mark.parametrize(
    ("verifier", "message"),
    [
        (Verifier(status=2), "PKI status"),
        (Verifier(nonce_delta=1), "nonce mismatch"),
        (Verifier(wrong_imprint=True), "imprint mismatch"),
    ],
)
async def test_rejects_status_nonce_and_imprint_mismatches(
    tmp_path: Path, verifier: Verifier, message: str
) -> None:
    with pytest.raises(TimestampVerificationError, match=message):
        await client(tmp_path, verifier).anchor(b"evidence")
    assert len(list(tmp_path.glob("*.tsq"))) == 1
    assert len(list(tmp_path.glob("*.tsr"))) == 1


@pytest.mark.parametrize(
    "response",
    [
        object(),
        Response(status_code=503),
        Response(content=b""),
        Response(headers={"content-type": "text/plain"}),
        Response(content=b"too-large"),
    ],
)
async def test_rejects_invalid_transport_responses(tmp_path: Path, response: object) -> None:
    instance = RFC3161AnchorClient(
        url="https://tsa.example.test",
        transport=Transport(response),
        verifier=Verifier(),
        evidence_dir=tmp_path,
        max_response_bytes=4
        if isinstance(response, Response) and response.content == b"too-large"
        else 1024,
    )
    with pytest.raises(TimestampTransportError):
        await instance.anchor(b"evidence")


def test_https_is_required_by_default(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        RFC3161AnchorClient(
            url="http://tsa.example.test",
            transport=Transport(),
            verifier=Verifier(),
            evidence_dir=tmp_path,
        )


async def test_untrusted_cms_is_persisted_but_not_accepted_as_anchor(tmp_path: Path) -> None:
    with pytest.raises(TimestampVerificationError, match="trust-policy"):
        await client(tmp_path, Verifier(trusted=False)).anchor(b"evidence")
    assert len(list(tmp_path.glob("*.tsq"))) == 1
    assert len(list(tmp_path.glob("*.tsr"))) == 1


async def test_repeated_identical_imprint_preserves_each_exchange(tmp_path: Path) -> None:
    instance = client(tmp_path, Verifier(trusted=True))
    first = await instance.anchor(b"same evidence")
    second = await instance.anchor(b"same evidence")

    assert first.anchor_id != second.anchor_id
    assert first.nonce != second.nonce
    assert first.request_path != second.request_path
    assert first.response_path != second.response_path
    assert len(list(tmp_path.glob("*.tsq"))) == 2
    assert len(list(tmp_path.glob("*.tsr"))) == 2


def test_der_request_contains_sha256_algorithm_and_imprint() -> None:
    imprint = hashlib.sha256(b"payload").digest()
    request = RFC3161AnchorClient.build_request(imprint, 123456)
    assert bytes.fromhex("0609608648016503040201") in request
    assert imprint in request


def test_atomic_persistence_does_not_publish_partial_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "evidence.tsq"

    def fail_replace(source: Path, target: Path) -> None:
        del source, target
        raise OSError("simulated crash")

    monkeypatch.setattr("aegis.anchoring.rfc3161.os.replace", fail_replace)
    with pytest.raises(OSError, match="simulated crash"):
        RFC3161AnchorClient._atomic_write(destination, b"complete bytes")
    assert not destination.exists()
    assert not list(tmp_path.iterdir())


def test_invalid_transport_object_rejected_at_construction(tmp_path: Path) -> None:
    with pytest.raises(TypeError, match="transport"):
        RFC3161AnchorClient(
            url="https://tsa.example.test",
            transport=object(),  # type: ignore[arg-type]
            verifier=Verifier(),
            evidence_dir=tmp_path,
        )

"""RFC 3161 timestamp anchoring with explicit transport and trust boundaries."""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import hashlib
import os
import secrets
import shutil
import subprocess
import tempfile
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable
from urllib.parse import urlsplit

import httpx

_SHA256_ALGORITHM_IDENTIFIER = bytes.fromhex("300d06096086480165030402010500")
_ACCEPTED_PKI_STATUSES = frozenset({0, 1})  # granted, grantedWithMods


class RFC3161Error(RuntimeError):
    """Base error for timestamp submission or validation failures."""


class TimestampTransportError(RFC3161Error):
    """The timestamp authority returned an invalid transport response."""


class TimestampVerificationError(RFC3161Error):
    """The timestamp response did not bind the expected request values."""


@runtime_checkable
class HTTPResponse(Protocol):
    """Read-only subset of an httpx-like response."""

    @property
    def status_code(self) -> int: ...

    @property
    def content(self) -> bytes: ...

    @property
    def headers(self) -> Mapping[str, str]: ...


@runtime_checkable
class AsyncHTTPTransport(Protocol):
    """Bounded async HTTP POST interface accepted by the client."""

    async def post(
        self,
        url: str,
        *,
        content: bytes,
        headers: Mapping[str, str],
        timeout: float,
    ) -> HTTPResponse: ...


class HTTPXTimestampTransport:
    """Concrete HTTPS transport with disabled redirects and TLS verification."""

    async def post(
        self,
        url: str,
        *,
        content: bytes,
        headers: Mapping[str, str],
        timeout: float,
    ) -> HTTPResponse:
        async with httpx.AsyncClient(follow_redirects=False, timeout=timeout) as client:
            return await client.post(url, content=content, headers=dict(headers))


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """Values established by a response verifier.

    ``cms_trusted`` must only be true after cryptographic signature and certificate
    path/policy validation. Merely parsing a TimeStampResp is not sufficient.
    """

    pki_status: int
    message_imprint: bytes | None
    nonce: int | None
    cms_trusted: bool
    signer: str | None = None
    detail: str | None = None


@runtime_checkable
class RFC3161Verifier(Protocol):
    """Pluggable parser and CMS/certificate trust verifier."""

    def verify(
        self,
        *,
        request_der: bytes,
        response_der: bytes,
        expected_imprint: bytes,
        expected_nonce: int,
    ) -> VerificationResult: ...


@dataclass(frozen=True, slots=True)
class TimestampAnchor:
    """Persisted RFC 3161 exchange and its independently established trust result."""

    anchor_id: str
    request_path: Path
    response_path: Path
    request_der: bytes
    response_der: bytes
    message_imprint: bytes
    nonce: int
    verification: VerificationResult

    @property
    def cms_trusted(self) -> bool:
        """Whether the injected verifier established full CMS trust."""
        return self.verification.cms_trusted


class RFC3161AnchorClient:
    """Create and submit SHA-256 RFC 3161 requests without hiding trust decisions."""

    def __init__(
        self,
        *,
        url: str,
        transport: AsyncHTTPTransport,
        verifier: RFC3161Verifier,
        evidence_dir: Path,
        timeout: float = 10.0,
        max_response_bytes: int = 1_048_576,
        allow_insecure_http: bool = False,
        require_trusted_cms: bool = True,
    ) -> None:
        parsed = urlsplit(url)
        allowed_schemes = {"https"}
        if allow_insecure_http:
            allowed_schemes.add("http")
        if parsed.scheme.lower() not in allowed_schemes or not parsed.netloc:
            raise ValueError("timestamp URL must be an absolute HTTPS URL")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("timestamp URL must not contain credentials")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        if max_response_bytes < 1:
            raise ValueError("max_response_bytes must be at least one")
        if not isinstance(transport, AsyncHTTPTransport):
            raise TypeError("transport does not satisfy AsyncHTTPTransport")
        if not isinstance(verifier, RFC3161Verifier):
            raise TypeError("verifier does not satisfy RFC3161Verifier")
        self._url = url
        self._transport = transport
        self._verifier = verifier
        self._evidence_dir = Path(evidence_dir)
        self._timeout = timeout
        self._max_response_bytes = max_response_bytes
        self._require_trusted_cms = require_trusted_cms
        self._evidence_dir.mkdir(parents=True, exist_ok=True)

    async def anchor(self, data: bytes) -> TimestampAnchor:
        """Request a timestamp over the exact SHA-256 digest and persist all DER bytes."""
        if not isinstance(data, bytes):
            raise TypeError("data must be bytes")
        imprint = hashlib.sha256(data).digest()
        nonce = self._secure_nonce()
        request_der = self.build_request(imprint, nonce)
        anchor_id = uuid.uuid4().hex
        request_path = self._evidence_dir / f"{anchor_id}.tsq"
        response_path = self._evidence_dir / f"{anchor_id}.tsr"
        self._atomic_write(request_path, request_der)

        try:
            response = await self._transport.post(
                self._url,
                content=request_der,
                headers={
                    "Accept": "application/timestamp-reply",
                    "Content-Type": "application/timestamp-query",
                },
                timeout=self._timeout,
            )
        except Exception as exc:
            raise TimestampTransportError(f"timestamp transport failed: {exc}") from exc
        response_der = self._validate_response(response)
        self._atomic_write(response_path, response_der)

        try:
            verification = self._verifier.verify(
                request_der=request_der,
                response_der=response_der,
                expected_imprint=imprint,
                expected_nonce=nonce,
            )
        except Exception as exc:
            raise TimestampVerificationError(f"timestamp verifier failed: {exc}") from exc
        self._validate_verification(verification, imprint, nonce)
        if self._require_trusted_cms and not verification.cms_trusted:
            raise TimestampVerificationError(
                "timestamp response was obtained but CMS trust-policy verification failed"
            )
        return TimestampAnchor(
            anchor_id=anchor_id,
            request_path=request_path,
            response_path=response_path,
            request_der=request_der,
            response_der=response_der,
            message_imprint=imprint,
            nonce=nonce,
            verification=verification,
        )

    def _validate_response(self, response: object) -> bytes:
        if not isinstance(response, HTTPResponse):
            raise TimestampTransportError("transport returned an incompatible response")
        status_code = response.status_code
        content = response.content
        headers = response.headers
        if isinstance(status_code, bool) or not isinstance(status_code, int):
            raise TimestampTransportError("transport status_code must be an integer")
        if status_code < 200 or status_code >= 300:
            raise TimestampTransportError(f"timestamp authority returned HTTP {status_code}")
        if not isinstance(content, bytes):
            raise TimestampTransportError("transport content must be bytes")
        if not content:
            raise TimestampTransportError("timestamp authority returned an empty response")
        if len(content) > self._max_response_bytes:
            raise TimestampTransportError("timestamp response exceeds configured size bound")
        content_type = next(
            (value for key, value in headers.items() if key.lower() == "content-type"), ""
        )
        if content_type.split(";", 1)[0].strip().lower() != "application/timestamp-reply":
            raise TimestampTransportError("unexpected timestamp response content type")
        return content

    @staticmethod
    def _validate_verification(
        result: VerificationResult, expected_imprint: bytes, expected_nonce: int
    ) -> None:
        if not isinstance(result, VerificationResult):
            raise TimestampVerificationError("verifier returned an incompatible result")
        if result.pki_status not in _ACCEPTED_PKI_STATUSES:
            raise TimestampVerificationError(
                f"timestamp PKI status {result.pki_status} is not successful"
            )
        if result.message_imprint is None or not secrets.compare_digest(
            result.message_imprint, expected_imprint
        ):
            raise TimestampVerificationError("timestamp message imprint mismatch")
        if result.nonce != expected_nonce:
            raise TimestampVerificationError("timestamp nonce mismatch")
        # cms_trusted is intentionally reported, not inferred or promoted here.

    @staticmethod
    def build_request(message_imprint: bytes, nonce: int) -> bytes:
        """Encode a DER TimeStampReq using SHA-256, a nonce, and certReq=true."""
        if len(message_imprint) != hashlib.sha256().digest_size:
            raise ValueError("SHA-256 message imprint must be exactly 32 bytes")
        if nonce <= 0:
            raise ValueError("nonce must be positive")
        algorithm_and_digest = _der_sequence(
            _SHA256_ALGORITHM_IDENTIFIER + _der_octet_string(message_imprint)
        )
        body = _der_integer(1) + algorithm_and_digest + _der_integer(nonce) + b"\x01\x01\xff"
        return _der_sequence(body)

    @staticmethod
    def _secure_nonce() -> int:
        return int.from_bytes(secrets.token_bytes(20), "big") or 1

    @staticmethod
    def _atomic_write(path: Path, content: bytes) -> None:
        temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        try:
            with temporary.open("xb") as output:
                output.write(content)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, path)
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            temporary.unlink(missing_ok=True)


class OpenSSLRFC3161Verifier:
    """Verify a full TSR against its exact request and an explicit CA policy."""

    def __init__(
        self,
        *,
        ca_file: Path | None = None,
        ca_path: Path | None = None,
        untrusted_file: Path | None = None,
        timeout: float = 10.0,
        openssl_binary: str | None = None,
    ) -> None:
        if (ca_file is None) == (ca_path is None):
            raise ValueError("configure exactly one of ca_file or ca_path")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        executable = openssl_binary or shutil.which("openssl")
        if not executable:
            raise RuntimeError("openssl is required for RFC 3161 trust verification")
        self._openssl = executable
        self._ca_file = Path(ca_file) if ca_file is not None else None
        self._ca_path = Path(ca_path) if ca_path is not None else None
        self._untrusted_file = Path(untrusted_file) if untrusted_file is not None else None
        self._timeout = timeout
        for path in (self._ca_file, self._ca_path, self._untrusted_file):
            if path is not None and not path.exists():
                raise ValueError(f"RFC 3161 trust path does not exist: {path}")

    def verify(
        self,
        *,
        request_der: bytes,
        response_der: bytes,
        expected_imprint: bytes,
        expected_nonce: int,
    ) -> VerificationResult:
        with tempfile.TemporaryDirectory(prefix="aegis-rfc3161-") as directory:
            request_path = Path(directory) / "request.tsq"
            response_path = Path(directory) / "response.tsr"
            request_path.write_bytes(request_der)
            response_path.write_bytes(response_der)
            command = [
                self._openssl,
                "ts",
                "-verify",
                "-queryfile",
                str(request_path),
                "-in",
                str(response_path),
            ]
            if self._ca_file is not None:
                command.extend(("-CAfile", str(self._ca_file)))
            if self._ca_path is not None:
                command.extend(("-CApath", str(self._ca_path)))
            if self._untrusted_file is not None:
                command.extend(("-untrusted", str(self._untrusted_file)))
            try:
                completed = subprocess.run(  # noqa: S603
                    command,
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    check=False,
                    timeout=self._timeout,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise TimestampVerificationError("OpenSSL timestamp verification failed") from exc
        if completed.returncode != 0:
            return VerificationResult(
                pki_status=-1,
                message_imprint=None,
                nonce=None,
                cms_trusted=False,
                detail="OpenSSL rejected the timestamp response",
            )
        return VerificationResult(
            pki_status=0,
            message_imprint=expected_imprint,
            nonce=expected_nonce,
            cms_trusted=True,
            detail="OpenSSL verified response against query and configured trust store",
        )


def _der_length(length: int) -> bytes:
    if length < 0:
        raise ValueError("DER length cannot be negative")
    if length < 128:
        return bytes((length,))
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes((0x80 | len(encoded),)) + encoded


def _der_sequence(content: bytes) -> bytes:
    return b"\x30" + _der_length(len(content)) + content


def _der_octet_string(content: bytes) -> bytes:
    return b"\x04" + _der_length(len(content)) + content


def _der_integer(value: int) -> bytes:
    if value < 0:
        raise ValueError("only non-negative DER integers are supported")
    if value == 0:
        encoded = b"\x00"
    else:
        encoded = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if encoded[0] & 0x80:
            encoded = b"\x00" + encoded
    return b"\x02" + _der_length(len(encoded)) + encoded


__all__ = [
    "AsyncHTTPTransport",
    "HTTPResponse",
    "HTTPXTimestampTransport",
    "OpenSSLRFC3161Verifier",
    "RFC3161AnchorClient",
    "RFC3161Error",
    "RFC3161Verifier",
    "TimestampAnchor",
    "TimestampTransportError",
    "TimestampVerificationError",
    "VerificationResult",
]

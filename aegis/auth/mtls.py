"""mTLS client-certificate verification at direct and trusted-proxy boundaries."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from aegis.auth.principal import Principal


class MTLSVerificationError(ValueError):
    """Raised when a client certificate or its transport provenance is invalid."""


@dataclass(frozen=True, slots=True)
class MTLSVerificationConfig:
    """Static certificate-verification policy."""

    trusted_proxy_cidrs: tuple[str, ...] = ()
    allowed_sha256_fingerprints: frozenset[str] = frozenset()
    san_allowlist: frozenset[str] = frozenset()
    tenant_san_prefix: str = "tenant:"
    forwarded_certificate_header: str = "x-forwarded-client-cert"
    forwarded_fingerprint_header: str = "x-client-cert-sha256"

    def __post_init__(self) -> None:
        if not self.allowed_sha256_fingerprints:
            raise ValueError("at least one allowed SHA-256 fingerprint is required")
        if not self.san_allowlist:
            raise ValueError("at least one allowed certificate SAN is required")
        for cidr in self.trusted_proxy_cidrs:
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError as exc:
                raise ValueError(f"invalid trusted proxy CIDR {cidr!r}") from exc
        normalized = frozenset(
            _normalize_fingerprint(value) for value in self.allowed_sha256_fingerprints
        )
        if "" in normalized:
            raise ValueError("configured SHA-256 fingerprints must contain 64 hexadecimal digits")
        object.__setattr__(self, "allowed_sha256_fingerprints", normalized)


class MTLSVerifier:
    """Verify a presented client certificate and bind it to one tenant.

    Forwarded certificate and fingerprint headers are ignored unless the immediate source
    address belongs to a configured trusted proxy CIDR. Direct callers must provide the
    certificate through ``peer_certificate``.
    """

    def __init__(
        self,
        config: MTLSVerificationConfig,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.config = config
        self._networks = tuple(
            ipaddress.ip_network(value, strict=False) for value in config.trusted_proxy_cidrs
        )
        self._clock = clock or (lambda: datetime.now(UTC))

    def verify(
        self,
        *,
        source_ip: str,
        tenant_id: str | None = None,
        peer_certificate: bytes | str | x509.Certificate | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> Principal:
        """Verify certificate provenance and policy, returning an mTLS principal.

        The authoritative tenant is extracted from exactly one SAN carrying the
        configured prefix. ``tenant_id`` is only an optional expected value used
        to reject a mismatch; it never supplies identity by itself.
        """

        if tenant_id is not None and not tenant_id.strip():
            raise MTLSVerificationError("expected tenant_id must not be empty")
        trusted_proxy = self.is_trusted_proxy(source_ip)
        normalized_headers = {key.lower(): value for key, value in (headers or {}).items()}
        certificate_input: bytes | str | x509.Certificate | None = peer_certificate
        asserted_fingerprint: str | None = None
        if trusted_proxy:
            forwarded = normalized_headers.get(self.config.forwarded_certificate_header.lower())
            if forwarded:
                certificate_input = forwarded
            asserted_fingerprint = normalized_headers.get(
                self.config.forwarded_fingerprint_header.lower()
            )
        # Deliberately do not inspect forwarded headers from an untrusted source.
        if certificate_input is None:
            raise MTLSVerificationError("a verified client certificate is required")

        certificate = _load_certificate(certificate_input)
        fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
        if self.config.allowed_sha256_fingerprints and not _constant_time_member(
            fingerprint, self.config.allowed_sha256_fingerprints
        ):
            raise MTLSVerificationError("client certificate fingerprint is not allowed")
        if asserted_fingerprint is not None:
            normalized_assertion = _normalize_fingerprint(asserted_fingerprint)
            if not normalized_assertion or not hmac.compare_digest(
                fingerprint, normalized_assertion
            ):
                raise MTLSVerificationError("forwarded client certificate fingerprint mismatch")

        now = self._clock()
        if now.tzinfo is None:
            now = now.replace(tzinfo=UTC)
        now = now.astimezone(UTC)
        not_before = _cert_time(certificate, "not_valid_before_utc", "not_valid_before")
        not_after = _cert_time(certificate, "not_valid_after_utc", "not_valid_after")
        if now < not_before:
            raise MTLSVerificationError("client certificate is not yet valid")
        if now >= not_after:
            raise MTLSVerificationError("client certificate has expired")

        san_values = _certificate_sans(certificate)
        if not san_values:
            raise MTLSVerificationError("client certificate must contain a SAN extension")
        if self.config.san_allowlist and not any(
            _constant_time_text_member(value, self.config.san_allowlist) for value in san_values
        ):
            raise MTLSVerificationError("client certificate SAN is not allowed")
        tenant_values = tuple(
            value[len(self.config.tenant_san_prefix) :]
            for value in san_values
            if value.startswith(self.config.tenant_san_prefix)
        )
        if len(tenant_values) != 1 or not tenant_values[0].strip():
            raise MTLSVerificationError("client certificate must bind exactly one tenant SAN")
        certificate_tenant = tenant_values[0]
        if tenant_id is not None and not hmac.compare_digest(certificate_tenant, tenant_id):
            raise MTLSVerificationError("client certificate SAN does not bind the expected tenant")

        subject = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        common_name = subject[0].value if subject else fingerprint
        subject_name = (
            common_name.decode("utf-8").strip()
            if isinstance(common_name, bytes)
            else common_name.strip()
        )
        if not subject_name:
            subject_name = fingerprint
        return Principal(
            subject=subject_name,
            tenant_id=certificate_tenant,
            auth_method="mtls",
            credential_id=f"mtls:{fingerprint}",
            attributes={"certificate_sha256": fingerprint, "sans": tuple(sorted(san_values))},
        )

    def verify_certificate(
        self,
        certificate: bytes | str | x509.Certificate,
        *,
        tenant_id: str | None = None,
        source_ip: str = "127.0.0.1",
    ) -> Principal:
        """Convenience method for direct TLS-termination integrations."""

        return self.verify(
            source_ip=source_ip,
            tenant_id=tenant_id,
            peer_certificate=certificate,
        )

    def is_trusted_proxy(self, source_ip: str) -> bool:
        """Return whether the immediate source may assert forwarded certificate headers."""

        try:
            address = ipaddress.ip_address(source_ip)
        except ValueError:
            return False
        return any(
            address.version == network.version and address in network for network in self._networks
        )


def _load_certificate(value: bytes | str | x509.Certificate) -> x509.Certificate:
    if isinstance(value, x509.Certificate):
        return value
    data = value.encode("utf-8") if isinstance(value, str) else bytes(value)
    # Common proxies percent-escape PEM line breaks rather than URL-encoding the whole value.
    data = data.replace(b"%0A", b"\n").replace(b"%0a", b"\n")
    try:
        if b"-----BEGIN CERTIFICATE-----" in data:
            return x509.load_pem_x509_certificate(data)
        return x509.load_der_x509_certificate(data)
    except (TypeError, ValueError) as exc:
        raise MTLSVerificationError("client certificate cannot be parsed") from exc


def _cert_time(certificate: x509.Certificate, aware_name: str, legacy_name: str) -> datetime:
    if aware_name == "not_valid_before_utc":
        return certificate.not_valid_before_utc.astimezone(UTC)
    if aware_name == "not_valid_after_utc":
        return certificate.not_valid_after_utc.astimezone(UTC)
    legacy = (
        certificate.not_valid_before
        if legacy_name == "not_valid_before"
        else certificate.not_valid_after
    )
    return legacy.replace(tzinfo=UTC)


def _certificate_sans(certificate: x509.Certificate) -> tuple[str, ...]:
    try:
        extension = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return ()
    values: list[str] = []
    for name in extension.value:
        if isinstance(name, (x509.DNSName, x509.RFC822Name, x509.UniformResourceIdentifier)):
            values.append(name.value)
        elif isinstance(name, x509.IPAddress):
            values.append(str(name.value))
        elif isinstance(name, x509.OtherName):
            values.append(f"{name.type_id.dotted_string}:{name.value.hex()}")
    return tuple(values)


def _normalize_fingerprint(value: str) -> str:
    normalized = value.lower().replace(":", "").strip()
    if len(normalized) != hashlib.sha256().digest_size * 2:
        return ""
    try:
        bytes.fromhex(normalized)
    except ValueError:
        return ""
    return normalized


def _constant_time_member(candidate: str, allowed: frozenset[str]) -> bool:
    result = False
    encoded = candidate.encode("ascii")
    for value in allowed:
        result = hmac.compare_digest(encoded, value.encode("ascii")) or result
    return result


def _constant_time_text_member(candidate: str, allowed: frozenset[str]) -> bool:
    result = False
    encoded = candidate.encode("utf-8")
    for value in allowed:
        result = hmac.compare_digest(encoded, value.encode("utf-8")) or result
    return result


def certificate_sha256(certificate: bytes | str | x509.Certificate) -> str:
    """Return the canonical lower-case SHA-256 certificate fingerprint."""

    cert = _load_certificate(certificate)
    der = cert.public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(der).hexdigest()


__all__ = [
    "MTLSVerificationConfig",
    "MTLSVerificationError",
    "MTLSVerifier",
    "certificate_sha256",
]

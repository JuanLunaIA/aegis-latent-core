# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tenant-binding probes over the audit authorization boundary.

``principal_tenant`` decides which tenant's evidence a caller may read, and
``_combine`` decides whether two credentials presented together describe one
tenant. Both compared identifiers with ``hmac.compare_digest`` on ``str``,
which raises ``TypeError`` for any non-ASCII character. Two reachable
consequences, both pinned below:

* a client-supplied ``tenant_id`` (a query parameter on the audit listing, a
  body field on the forensic export) carrying non-ASCII raised inside the
  authorization check, so an authorization *denial* surfaced as an unhandled
  500 instead of the 403 the boundary intends to record; and
* two credentials naming one legitimate internationalized tenant — an OIDC
  tenant claim or a certificate SAN holding non-ASCII — failed to combine at
  all, so ``api_key_mtls`` and ``oidc_mtls`` could not authenticate that
  tenant.

Neither case leaked another tenant's evidence: the request failed closed in
both. What was defective is the *shape* of the failure, and the availability
of internationalized tenants. These probes are local and synthetic; they
construct principals directly and assert on the boundary's own decisions.
"""

from __future__ import annotations

import unicodedata
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi import HTTPException

from aegis.auth.mtls import (
    MTLSVerificationConfig,
    MTLSVerificationError,
    MTLSVerifier,
    certificate_sha256,
)
from aegis.auth.principal import Principal, Role
from aegis.proxy.dependencies import _combine, _same_tenant, principal_tenant

_HMAC_KEY = "k" * 32

_TENANT_ASCII = "acme"
_TENANT_INTL = "köln-gmbh"
_TENANT_INTL_OTHER = "köln-ag"
_TENANT_CJK = "東京-corp"
_TENANT_EMOJI = "acme-\U0001f510"

# The two spellings of "cafe-corp" below must stay distinct codepoint
# sequences: U+00E9 against U+0065 U+0301. Written as escapes because an
# editor or formatter that normalizes the file would silently collapse them
# into one string and the assertion would then prove nothing.
_TENANT_PRECOMPOSED = "caf\u00e9-corp"
_TENANT_DECOMPOSED = "cafe\u0301-corp"


def _principal(tenant: str, *, role: Role = Role.AUDITOR, method: str = "oidc") -> Principal:
    return Principal(
        subject="probe-subject",
        tenant_id=tenant,
        roles=frozenset({role}),
        auth_method=method,
    )


class TestSameTenantPrimitive:
    """The comparison helper must be total over Unicode and exact."""

    @pytest.mark.parametrize(
        "tenant",
        [_TENANT_ASCII, _TENANT_INTL, _TENANT_CJK, _TENANT_EMOJI, "", "a" * 512],
    )
    def test_identical_identifiers_match(self, tenant: str) -> None:
        assert _same_tenant(tenant, tenant) is True

    @pytest.mark.parametrize(
        ("left", "right"),
        [
            (_TENANT_ASCII, "other"),
            (_TENANT_INTL, _TENANT_INTL_OTHER),
            (_TENANT_INTL, _TENANT_ASCII),
            (_TENANT_CJK, _TENANT_EMOJI),
            (_TENANT_ASCII, _TENANT_ASCII + " "),
            (_TENANT_ASCII, _TENANT_ASCII.upper()),
            (_TENANT_ASCII, ""),
        ],
    )
    def test_distinct_identifiers_do_not_match(self, left: str, right: str) -> None:
        assert _same_tenant(left, right) is False

    def test_non_ascii_does_not_raise(self) -> None:
        """The original defect: this raised TypeError rather than returning."""

        assert _same_tenant(_TENANT_INTL, _TENANT_ASCII) is False
        assert _same_tenant(_TENANT_ASCII, _TENANT_INTL) is False

    def test_canonically_equivalent_sequences_are_not_conflated(self) -> None:
        """Distinct codepoint sequences stay distinct tenants.

        The two spellings render identically but differ in codepoints.
        Treating them as one tenant would widen access across a rendering
        coincidence, so the comparison denies instead. These assertions pin
        that direction, and that the fixtures really are distinct.
        """

        assert _TENANT_PRECOMPOSED != _TENANT_DECOMPOSED
        assert unicodedata.normalize("NFC", _TENANT_PRECOMPOSED) == unicodedata.normalize(
            "NFC", _TENANT_DECOMPOSED
        )
        assert _same_tenant(_TENANT_PRECOMPOSED, _TENANT_DECOMPOSED) is False


class TestPrincipalTenantAuthorization:
    """Only an administrator may name a tenant other than their own."""

    def test_non_admin_own_tenant_is_returned(self) -> None:
        principal = _principal(_TENANT_ASCII)
        assert principal_tenant(principal, _TENANT_ASCII) == _TENANT_ASCII

    def test_non_admin_without_request_gets_own_tenant(self) -> None:
        principal = _principal(_TENANT_ASCII)
        assert principal_tenant(principal, None) == _TENANT_ASCII

    def test_non_admin_cross_tenant_is_denied(self) -> None:
        principal = _principal(_TENANT_ASCII)
        with pytest.raises(HTTPException) as excinfo:
            principal_tenant(principal, "victim-tenant")
        assert excinfo.value.status_code == 403
        assert excinfo.value.detail == "Tenant access denied"

    @pytest.mark.parametrize("requested", [_TENANT_INTL, _TENANT_CJK, _TENANT_EMOJI, "acmé"])
    def test_non_ascii_request_denies_rather_than_raising(self, requested: str) -> None:
        """A non-ASCII ``tenant_id`` must produce 403, not an unhandled 500.

        This is the client-reachable case: ``tenant_id`` is a query parameter
        on the audit listing and a body field on the forensic export.
        """

        principal = _principal(_TENANT_ASCII)
        with pytest.raises(HTTPException) as excinfo:
            principal_tenant(principal, requested)
        assert excinfo.value.status_code == 403
        assert excinfo.value.detail == "Tenant access denied"

    def test_internationalized_tenant_may_read_its_own_evidence(self) -> None:
        """The availability half: a legitimate non-ASCII tenant is not locked out."""

        principal = _principal(_TENANT_INTL)
        assert principal_tenant(principal, _TENANT_INTL) == _TENANT_INTL

    def test_internationalized_tenant_cannot_read_a_neighbour(self) -> None:
        principal = _principal(_TENANT_INTL)
        with pytest.raises(HTTPException) as excinfo:
            principal_tenant(principal, _TENANT_INTL_OTHER)
        assert excinfo.value.status_code == 403

    def test_admin_may_select_another_tenant(self) -> None:
        principal = _principal(_TENANT_ASCII, role=Role.ADMIN)
        assert principal_tenant(principal, "any-other-tenant") == "any-other-tenant"

    def test_admin_without_request_is_unfiltered(self) -> None:
        """An unfiltered admin listing is the documented platform-admin behaviour."""

        principal = _principal(_TENANT_ASCII, role=Role.ADMIN)
        assert principal_tenant(principal, None) is None

    @pytest.mark.parametrize("role", [Role.AUDITOR, Role.AUDIT_READER, Role.PROXY_USER])
    def test_no_non_admin_role_escapes_its_tenant(self, role: Role) -> None:
        principal = _principal(_TENANT_ASCII, role=role)
        with pytest.raises(HTTPException):
            principal_tenant(principal, "victim-tenant")


class TestCredentialTenantBinding:
    """Two credentials presented together must name one tenant."""

    def test_matching_tenants_combine(self) -> None:
        left = _principal(_TENANT_ASCII, method="api_key")
        right = _principal(_TENANT_ASCII, method="mtls")
        combined = _combine(left, right, _HMAC_KEY)
        assert combined.tenant_id == _TENANT_ASCII

    def test_mismatched_tenants_are_rejected(self) -> None:
        left = _principal(_TENANT_ASCII, method="api_key")
        right = _principal("other-tenant", method="mtls")
        with pytest.raises(HTTPException) as excinfo:
            _combine(left, right, _HMAC_KEY)
        assert excinfo.value.status_code == 403
        assert excinfo.value.detail == "Credential tenant mismatch"

    def test_internationalized_tenant_combines(self) -> None:
        """The original defect: identical legitimate tenants failed to authenticate."""

        left = _principal(_TENANT_INTL, method="api_key")
        right = _principal(_TENANT_INTL, method="mtls")
        combined = _combine(left, right, _HMAC_KEY)
        assert combined.tenant_id == _TENANT_INTL

    def test_internationalized_mismatch_is_still_rejected(self) -> None:
        left = _principal(_TENANT_INTL, method="api_key")
        right = _principal(_TENANT_INTL_OTHER, method="mtls")
        with pytest.raises(HTTPException) as excinfo:
            _combine(left, right, _HMAC_KEY)
        assert excinfo.value.status_code == 403
        assert excinfo.value.detail == "Credential tenant mismatch"

    def test_combined_principal_intersects_authority(self) -> None:
        """Combining must never grant more than either credential carried."""

        left = Principal(
            subject="s",
            tenant_id=_TENANT_ASCII,
            roles=frozenset({Role.ADMIN, Role.AUDITOR}),
            scopes=frozenset({"audit:read", "audit:export"}),
            auth_method="api_key",
        )
        right = Principal(
            subject="s",
            tenant_id=_TENANT_ASCII,
            roles=frozenset({Role.AUDITOR}),
            scopes=frozenset({"audit:read"}),
            auth_method="mtls",
        )
        combined = _combine(left, right, _HMAC_KEY)
        assert combined.roles == frozenset({Role.AUDITOR})
        assert combined.scopes == frozenset({"audit:read"})
        assert Role.ADMIN not in combined.roles


_MTLS_NOW = datetime(2033, 5, 18, tzinfo=UTC)


def _certificate(tenant: str = "tenant-a") -> bytes:
    """An ordinary ASCII certificate binding one tenant SAN."""

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "workload-7")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(_MTLS_NOW - timedelta(days=1))
        .not_valid_after(_MTLS_NOW + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("client.example.test"), x509.DNSName(f"tenant:{tenant}")]
            ),
            False,
        )
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM)


def _verifier(pem: bytes) -> MTLSVerifier:
    return MTLSVerifier(
        MTLSVerificationConfig(
            trusted_proxy_cidrs=("10.20.0.0/16",),
            allowed_sha256_fingerprints=frozenset({certificate_sha256(pem)}),
            san_allowlist=frozenset({"client.example.test"}),
        ),
        clock=lambda: _MTLS_NOW,
    )


class TestMTLSTenantSANBinding:
    """``MTLSVerifier.verify`` compares an expected tenant against the cert SAN.

    Scope, stated precisely. The bundled proxy calls ``verify()`` without a
    ``tenant_id`` (see ``_mtls_principal``), so this comparison does not run on
    the gateway request path. It runs for direct callers of the public
    ``aegis.auth.mtls`` API that pass an expected tenant from their own
    configuration — where a non-ASCII value is ordinary — so the comparison has
    to be defined for every string rather than only for ASCII.

    A non-ASCII value cannot arrive from the certificate side: ``cryptography``
    rejects non-ASCII DNSName, RFC822Name and URI SANs at construction. The
    reachable half is the caller-supplied expected tenant, which is what these
    tests drive.
    """

    def test_matching_tenant_verifies(self) -> None:
        pem = _certificate("tenant-a")
        principal = _verifier(pem).verify(
            source_ip="198.51.100.9", tenant_id="tenant-a", peer_certificate=pem
        )
        assert principal.tenant_id == "tenant-a"

    def test_mismatched_tenant_is_rejected(self) -> None:
        pem = _certificate("tenant-a")
        with pytest.raises(MTLSVerificationError, match="does not bind the expected tenant"):
            _verifier(pem).verify(
                source_ip="198.51.100.9", tenant_id="tenant-b", peer_certificate=pem
            )

    @pytest.mark.parametrize("expected", [_TENANT_INTL, _TENANT_CJK, _TENANT_EMOJI])
    def test_non_ascii_expected_tenant_fails_verification_cleanly(self, expected: str) -> None:
        """The defect: this raised TypeError instead of a verification error."""

        pem = _certificate("tenant-a")
        with pytest.raises(MTLSVerificationError, match="does not bind the expected tenant"):
            _verifier(pem).verify(
                source_ip="198.51.100.9", tenant_id=expected, peer_certificate=pem
            )

    def test_certificate_san_cannot_carry_non_ascii(self) -> None:
        """Pins why the certificate side of the comparison stays ASCII."""

        for cls in (x509.DNSName, x509.RFC822Name, x509.UniformResourceIdentifier):
            with pytest.raises(ValueError, match="A-label"):
                cls(f"tenant:{_TENANT_INTL}")

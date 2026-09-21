# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Every configuration rule in `aegis/config.py` that refuses to start.

The settings model is the last place a misconfiguration can be caught before
sockets are bound. Each rule here is a refusal with an operator-facing message,
and each one is worth an executed assertion rather than a reading: the posture
validator that decides whether authentication may be disabled, the mTLS rules,
the archival and TSA trust rules, and the strict-runtime invariants that a
production deployment must satisfy.

Two of these rules are the difference between a development convenience and a
credential-free gateway: `auth_disabled` is honoured only when `debug_mode` is
also set, and a strict runtime refuses both. The positive case is pinned too —
an all-green strict configuration must construct and validate without raising,
or the refusals above would be satisfied by a validator that rejects everything.
"""

from __future__ import annotations

import hashlib
import hmac
import json

import pytest
from pydantic import ValidationError

from aegis.config import AegisSettings

HMAC_KEY = "k" * 32


def _principal_digest(key: str) -> str:
    """The documented keyed lookup digest, recomputed independently of the model.

    HMAC-SHA256 over the domain prefix and the key, hex-encoded. Computed here
    from the algorithm rather than by calling the method under test, so a strict
    configuration is only accepted when the mapping really is the one the model
    looks for.
    """
    return hmac.new(
        HMAC_KEY.encode("utf-8"),
        b"aegis-api-key-principal-v1\x00" + key.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _strict(**kwargs: object) -> AegisSettings:
    """A configuration that satisfies every strict invariant unless overridden."""
    defaults: dict[str, object] = {
        "api_keys": "sk-live",
        "api_key_principals_json": json.dumps({_principal_digest("sk-live"): {"roles": ["admin"]}}),
        "backend_api_key": "sk-upstream",
        "backend_url": "https://upstream.example/v1",
        "security_enforcement_mode": "strict",
        "require_durable_evidence": True,
        "rate_limit_backend": "redis",
        "signing_key": "s" * 32,
        "auth_identity_hmac_key": HMAC_KEY,
    }
    defaults.update(kwargs)
    return AegisSettings(**defaults)  # type: ignore[arg-type]


class TestBackendUrlPosture:
    def test_a_non_http_scheme_is_refused(self) -> None:
        """Refused by the URL type, before the posture validator sees the value."""
        with pytest.raises(ValidationError, match="URL scheme should be 'http' or 'https'"):
            AegisSettings(backend_api_key="k", api_keys="k", backend_url="ftp://host/v1")

    def test_a_url_with_an_empty_host_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="empty host"):
            AegisSettings(backend_api_key="k", api_keys="k", backend_url="http://")

    def test_url_userinfo_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="must not contain URL userinfo"):
            AegisSettings(backend_api_key="k", api_keys="k", backend_url="https://user:pw@host/v1")

    def test_a_plain_http_url_is_accepted(self) -> None:
        settings = AegisSettings(
            backend_api_key="k", api_keys="k", backend_url="http://127.0.0.1:11434/v1"
        )
        assert settings.backend_url_str == "http://127.0.0.1:11434/v1"


class TestAuthenticationPosture:
    def test_disabling_auth_without_debug_mode_is_refused(self) -> None:
        """The rule that keeps AEGIS_AUTH_DISABLED from opening the gateway."""
        with pytest.raises(ValidationError, match="auth_disabled=True requires debug_mode=True"):
            AegisSettings(
                backend_api_key="k",
                api_keys="k",
                backend_url="https://upstream.example/v1",
                auth_disabled=True,
                debug_mode=False,
            )

    def test_disabling_auth_in_debug_mode_is_allowed(self) -> None:
        settings = AegisSettings(
            backend_api_key="k",
            api_keys="k",
            backend_url="https://upstream.example/v1",
            auth_disabled=True,
            debug_mode=True,
        )
        assert settings.auth_disabled is True

    def test_an_oidc_mode_without_issuer_audience_or_jwks_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="requires oidc_issuer"):
            AegisSettings(
                backend_api_key="k",
                backend_url="https://upstream.example/v1",
                auth_mode="oidc",
                auth_identity_hmac_key=HMAC_KEY,
            )

    def test_an_mtls_mode_without_allowlists_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="requires fingerprint and SAN allowlists"):
            AegisSettings(
                backend_api_key="k",
                backend_url="https://upstream.example/v1",
                auth_mode="mtls",
                auth_identity_hmac_key=HMAC_KEY,
            )

    def test_an_mtls_mode_without_a_trust_path_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="verified direct TLS or trusted proxy CIDRs"):
            AegisSettings(
                backend_api_key="k",
                backend_url="https://upstream.example/v1",
                auth_mode="mtls",
                auth_identity_hmac_key=HMAC_KEY,
                mtls_allowed_sha256_fingerprints="ab" * 32,
                mtls_san_allowlist="gateway.example",
            )


class TestBoundedSettingsAreOrdered:
    def test_an_event_budget_above_the_queue_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="must not exceed stream_queue_max_bytes"):
            AegisSettings(
                backend_api_key="k",
                api_keys="k",
                backend_url="https://upstream.example/v1",
                stream_queue_max_bytes=1024,
                max_stream_event_bytes=2048,
            )

    def test_a_default_output_budget_above_the_maximum_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="must not exceed rate_limit_max_output_tokens"):
            AegisSettings(
                backend_api_key="k",
                api_keys="k",
                backend_url="https://upstream.example/v1",
                rate_limit_max_output_tokens=10,
                rate_limit_default_output_tokens=20,
            )


class TestArchiveAndTimestampTrust:
    def test_archival_without_a_bucket_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="s3_archive_enabled=True requires"):
            AegisSettings(
                backend_api_key="k",
                api_keys="k",
                backend_url="https://upstream.example/v1",
                s3_archive_enabled=True,
            )

    def test_archival_without_segment_finalization_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="requires max_wal_bytes > 0"):
            AegisSettings(
                backend_api_key="k",
                api_keys="k",
                backend_url="https://upstream.example/v1",
                s3_archive_enabled=True,
                s3_archive_bucket="evidence",
                max_wal_bytes=0,
            )

    def test_a_timestamp_authority_without_its_ca_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="tsa_url requires tsa_ca_file"):
            AegisSettings(
                backend_api_key="k",
                api_keys="k",
                backend_url="https://upstream.example/v1",
                tsa_url="https://tsa.example/",
            )

    def test_a_non_https_siem_endpoint_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="siem_url must be an absolute HTTPS URL"):
            AegisSettings(
                backend_api_key="k",
                api_keys="k",
                backend_url="https://upstream.example/v1",
                siem_url="http://siem.internal/collector",
            )


class TestStrictRuntimeInvariants:
    def test_an_all_green_strict_configuration_validates(self) -> None:
        """The positive control: the refusals below must not be vacuous."""
        _strict().validate_runtime_invariants()

    def test_a_non_strict_runtime_returns_without_checking(self) -> None:
        settings = AegisSettings(
            backend_api_key="k", api_keys="k", backend_url="https://upstream.example/v1"
        )
        settings.validate_runtime_invariants()

    def test_strict_refuses_debug_mode(self) -> None:
        settings = _strict(debug_mode=True)
        with pytest.raises(ValueError, match="strict runtime cannot enable debug_mode"):
            settings.validate_runtime_invariants()

    def test_strict_requires_durable_evidence(self) -> None:
        settings = _strict()
        object.__setattr__(settings, "require_durable_evidence", False)
        with pytest.raises(ValueError, match="requires require_durable_evidence=True"):
            settings.validate_runtime_invariants()

    def test_strict_requires_the_redis_rate_limit_backend(self) -> None:
        settings = _strict()
        object.__setattr__(settings, "rate_limit_backend", "memory")
        with pytest.raises(ValueError, match="requires rate_limit_backend='redis'"):
            settings.validate_runtime_invariants()

    def test_strict_api_key_mode_requires_at_least_one_key(self) -> None:
        settings = _strict()
        object.__setattr__(settings, "api_keys", "")
        with pytest.raises(ValueError, match="requires at least one AEGIS_API_KEYS value"):
            settings.validate_runtime_invariants()

    def test_strict_requires_a_signing_key_or_a_token(self) -> None:
        settings = _strict()
        object.__setattr__(settings, "signing_key", "")
        object.__setattr__(settings, "pkcs11_library_path", None)
        with pytest.raises(ValueError, match="requires signing_key or pkcs11_library_path"):
            settings.validate_runtime_invariants()

    def test_strict_mtls_requires_a_ca_bundle(self) -> None:
        settings = _strict()
        object.__setattr__(settings, "mtls_required", True)
        object.__setattr__(settings, "ssl_ca_certs", None)
        with pytest.raises(ValueError, match="mtls_required=True requires ssl_ca_certs"):
            settings.validate_runtime_invariants()

    def test_strict_requires_a_full_length_identity_key(self) -> None:
        settings = _strict()
        object.__setattr__(settings, "auth_identity_hmac_key", "short")
        with pytest.raises(ValueError, match="at least 32 bytes"):
            settings.validate_runtime_invariants()

    def test_strict_api_key_mode_requires_a_principal_per_key(self) -> None:
        settings = _strict()
        object.__setattr__(settings, "api_key_principals_json", None)
        with pytest.raises(ValueError, match="explicit principal mapping per key"):
            settings.validate_runtime_invariants()


class TestParsingHelpers:
    def test_absent_ldap_groups_parse_to_nothing(self) -> None:
        settings = AegisSettings(
            backend_api_key="k", api_keys="k", backend_url="https://upstream.example/v1"
        )
        assert settings.get_ldap_required_groups() == frozenset()

    def test_ldap_groups_are_split_and_trimmed(self) -> None:
        settings = AegisSettings(
            backend_api_key="k",
            api_keys="k",
            backend_url="https://upstream.example/v1",
            ldap_required_groups=" aegis-admins , aegis-auditors ",
        )
        assert settings.get_ldap_required_groups() == frozenset({"aegis-admins", "aegis-auditors"})

    def test_absent_api_keys_parse_to_nothing(self) -> None:
        settings = AegisSettings(
            backend_api_key="k", backend_url="https://upstream.example/v1", api_keys=""
        )
        assert settings.get_api_keys() == frozenset()

    def test_the_audit_endpoints_fall_back_to_the_gateway_keys(self) -> None:
        settings = AegisSettings(
            backend_api_key="k", backend_url="https://upstream.example/v1", api_keys="one,two"
        )
        assert settings.get_audit_api_keys() == frozenset({"one", "two"})

    def test_the_audit_endpoints_accept_a_separate_credential(self) -> None:
        settings = AegisSettings(
            backend_api_key="k",
            backend_url="https://upstream.example/v1",
            api_keys="one",
            audit_api_keys="auditor",
        )
        assert settings.get_audit_api_keys() == frozenset({"auditor"})

    def test_an_invalid_log_level_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="log_level must be one of"):
            AegisSettings(
                backend_api_key="k",
                api_keys="k",
                backend_url="https://upstream.example/v1",
                log_level="LOUD",
            )

    def test_the_log_level_is_normalized(self) -> None:
        settings = AegisSettings(
            backend_api_key="k",
            api_keys="k",
            backend_url="https://upstream.example/v1",
            log_level="debug",
        )
        assert settings.log_level == "DEBUG"

    def test_an_unimplemented_rate_limit_backend_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="rate_limit_backend must be one of"):
            AegisSettings(
                backend_api_key="k",
                api_keys="k",
                backend_url="https://upstream.example/v1",
                rate_limit_backend="memcached",
            )


class TestApiKeyPrincipalMappings:
    def test_absent_mappings_parse_to_nothing(self) -> None:
        settings = AegisSettings(
            backend_api_key="k", api_keys="k", backend_url="https://upstream.example/v1"
        )
        assert settings.get_api_key_principals() == {}

    def test_a_digest_is_domain_separated_and_stable(self) -> None:
        settings = AegisSettings(
            backend_api_key="k",
            api_keys="k",
            backend_url="https://upstream.example/v1",
            auth_identity_hmac_key=HMAC_KEY,
        )
        first = settings.api_key_principal_digest("sk-live")
        assert first == settings.api_key_principal_digest("sk-live")
        assert first != settings.api_key_principal_digest("sk-live-2")
        assert len(first) == 64

    def test_malformed_json_is_refused(self) -> None:
        settings = AegisSettings(
            backend_api_key="k",
            api_keys="k",
            backend_url="https://upstream.example/v1",
            api_key_principals_json="{not json",
        )
        with pytest.raises(ValueError, match="must be valid JSON"):
            settings.get_api_key_principals()

    def test_a_non_object_payload_is_refused(self) -> None:
        settings = AegisSettings(
            backend_api_key="k",
            api_keys="k",
            backend_url="https://upstream.example/v1",
            api_key_principals_json='["not", "an", "object"]',
        )
        with pytest.raises(ValueError, match="must be a JSON object"):
            settings.get_api_key_principals()

    def test_a_short_or_non_hex_digest_is_refused(self) -> None:
        settings = AegisSettings(
            backend_api_key="k",
            api_keys="k",
            backend_url="https://upstream.example/v1",
            api_key_principals_json=json.dumps({"abc": {"role": "admin"}}),
        )
        with pytest.raises(ValueError, match="HMAC-SHA256 keys and object values"):
            settings.get_api_key_principals()

    def test_a_non_object_record_is_refused(self) -> None:
        settings = AegisSettings(
            backend_api_key="k",
            api_keys="k",
            backend_url="https://upstream.example/v1",
            api_key_principals_json=json.dumps({"a" * 64: "admin"}),
        )
        with pytest.raises(ValueError, match="HMAC-SHA256 keys and object values"):
            settings.get_api_key_principals()

    def test_a_well_formed_mapping_is_parsed(self) -> None:
        digest = "b" * 64
        settings = AegisSettings(
            backend_api_key="k",
            api_keys="k",
            backend_url="https://upstream.example/v1",
            api_key_principals_json=json.dumps({digest: {"roles": ["admin"]}}),
        )
        assert settings.get_api_key_principals() == {digest: {"roles": ["admin"]}}

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

"""Backward compatibility: the public surface a previous release exposed.

What this pins
--------------

Three surfaces an integrator can depend on without reading our source:

1. the console entry points declared in ``pyproject.toml`` and what they resolve to;
2. the HTTP routes the gateway serves, by path and method;
3. the Python and Rust FFI names re-exported for embedding.

Every constant below was read out of the ``v4.1.2`` tag — the most recent
published release — with ``git show v4.1.2:<path>``, not restated from memory.
That tag is the baseline because it is the last surface that reached a
registry: there is no ``4.2.0`` at any surface, the number having been skipped
deliberately, so no ``4.2.0`` contract exists to compare against. The tree these
tests run in is ``4.3.0``, which is unpublished.

Direction matters
-----------------

These are **subset** assertions in one direction: a name or route present at
``v4.1.2`` must still be present, and additions since are fine. A test that
demanded exact equality would fail on every new endpoint, which trains people
to edit the expectation instead of reading it. Removing or renaming something
here is a breaking change for someone whose integration is already deployed,
and this file is where that shows up as a failure rather than as a support
ticket.

What it does not establish
--------------------------

Only names, routes, and call shapes. Two things it deliberately says nothing
about: response *bodies* — a route that still answers on the same path with a
different schema passes here and is covered by the endpoint tests — and wire
compatibility of persisted evidence, which ``tests/test_mmr_parity.py`` and the
v1/v2 proof tests cover. Neither is a claim about the SDKs, which version
independently.

Calls with side effects are assigned before being asserted on, never called
inside the ``assert`` itself (``python -O`` strips asserts; CodeQL flags this as
py/side-effect-in-assert).
"""

from __future__ import annotations

import importlib
import inspect
import os
import tempfile
from importlib import metadata
from typing import Any

import pytest

from aegis.config import AegisSettings
from aegis.proxy.app import create_app

# ── the v4.1.2 surface, read from the tag ──────────────────────────────────

#: ``git show v4.1.2:pyproject.toml`` lines 110-112.
V412_CONSOLE_SCRIPTS = {
    "aegis": "aegis.proxy.app:main",
    "aegis-server": "aegis.proxy.app:main",
}

#: ``git show v4.1.2:aegis/proxy/app.py`` decorators, plus the ``/v1/audit`` and
#: ``/v1/attestation`` routers it mounts. ``/metrics`` is registered only when
#: ``prometheus-client`` is installed, so it is asserted conditionally below.
V412_ROUTES = {
    ("/health", "GET"),
    ("/ready", "GET"),
    ("/v1/chat/completions", "POST"),
    ("/v1/completions", "POST"),
    ("/v1/messages", "POST"),
    ("/v1/audit/export/part11", "GET"),
    ("/v1/audit/forensics/export", "POST"),
    ("/v1/audit/health", "GET"),
    ("/v1/audit/integrity", "GET"),
    ("/v1/audit/nodes", "GET"),
    ("/v1/audit/nodes/{node_hash}", "GET"),
    ("/v1/audit/nodes/{node_hash}/evidence", "GET"),
    ("/v1/audit/proofs/{state_id}", "GET"),
    ("/v1/audit/tenants", "GET"),
    ("/v1/attestation/capabilities", "GET"),
}

#: ``git show v4.1.2:aegis/__init__.py`` ``__all__``.
V412_AEGIS_EXPORTS = {
    "AegisBlockedError",
    "AegisEmbedded",
    "AegisEmbeddedError",
    "__version__",
    "wrap",
}

#: Names registered on the ``aegis_rust`` pymodule at
#: ``git show v4.1.2:aegis_rust_v2/src/lib.rs``.
V412_RUST_EXPORTS = {
    "AuditRingBuffer",
    "HttpResponse",
    "MmrAccumulator",
    "PqcKeypair",
    "RustForwarder",
    "RustRateLimiter",
    "RustSessionStore",
    "RustWaf",
    "RustWal",
    "WafResult",
    "blake3_hash",
    "blake3_keyed_hash",
    "generate_pqc_keypair",
    "hash_audit_payload",
    "hash_blake3",
    "hash_sha256",
    "hash_sha256_fast",
    "hmac_sign",
    "keyed_hash_blake3",
    "keyed_hash_blake3_bytes",
    "keypair_from_bytes",
    "verify_pqc_signature",
    "warmup_runtime",
}


def _served_routes(app: Any) -> set[tuple[str, str]]:
    """Every ``(path, method)`` the app serves, including mounted routers.

    Two sources, unioned, because neither alone is complete. The OpenAPI schema
    resolves router prefixes correctly but omits anything registered with
    ``include_in_schema=False`` — ``/metrics``, for one. Walking ``app.routes``
    catches those, but this FastAPI wraps an included router in a placeholder
    object whose own ``routes`` is empty and whose real content hangs off
    ``include_context``; the walk follows that shape when it is there and falls
    back to a plain ``routes`` attribute when it is not, so a future FastAPI
    that flattens differently still yields the schema'd half.

    ``HEAD`` is dropped throughout: Starlette adds it alongside every ``GET``,
    and listing it would make the expectation read as routes nobody wrote.
    """

    served: set[tuple[str, str]] = set()

    for path, operations in app.openapi().get("paths", {}).items():
        for method in operations:
            if method.upper() not in {"PARAMETERS", "HEAD"}:
                served.add((path, method.upper()))

    def walk(routes: Any, prefix: str = "") -> None:
        for route in routes:
            path = prefix + str(getattr(route, "path", "") or "")
            for method in getattr(route, "methods", None) or ():
                if method != "HEAD":
                    served.add((path, method))
            context = getattr(route, "include_context", None)
            inner = getattr(context, "included_router", None) if context is not None else None
            if inner is not None:
                walk(getattr(inner, "routes", ()), prefix + (getattr(context, "prefix", "") or ""))
                continue
            nested = getattr(route, "routes", None)
            if nested:
                walk(nested, prefix + (getattr(route, "prefix", "") or ""))

    walk(app.routes)
    return served


@pytest.fixture(scope="module")
def gateway_app() -> Any:
    """A real gateway app on a throwaway WAL, torn down after the module."""

    with tempfile.TemporaryDirectory() as directory:
        settings = AegisSettings(
            backend_api_key="compat-suite-key",
            wal_path=os.path.join(directory, "compat.wal"),
            waf_strict_mode=False,
        )
        app = create_app(settings)
        try:
            yield app
        finally:
            # Release the single-writer WAL lock so the directory can be removed.
            app.state.aegis.ledger.close()


class TestConsoleEntryPoints:
    """``aegis`` and ``aegis-server`` are how operators start the gateway."""

    def test_both_scripts_are_installed_and_unchanged(self) -> None:
        installed = {
            entry.name: entry.value
            for entry in metadata.entry_points(group="console_scripts")
            if entry.name in V412_CONSOLE_SCRIPTS
        }
        assert installed == V412_CONSOLE_SCRIPTS

    def test_the_target_resolves_to_a_zero_argument_callable(self) -> None:
        # Both scripts point at the same target; a console script is invoked
        # with no arguments, so anything with a required parameter would fail
        # only at run time, on the operator's terminal.
        module_name, _, attribute = V412_CONSOLE_SCRIPTS["aegis"].partition(":")
        main = getattr(importlib.import_module(module_name), attribute)
        assert callable(main)
        required = [
            parameter
            for parameter in inspect.signature(main).parameters.values()
            if parameter.default is inspect.Parameter.empty
            and parameter.kind
            in (parameter.POSITIONAL_ONLY, parameter.POSITIONAL_OR_KEYWORD, parameter.KEYWORD_ONLY)
        ]
        assert required == []


class TestHttpSurface:
    def test_every_v412_route_is_still_served(self, gateway_app: Any) -> None:
        missing = V412_ROUTES - _served_routes(gateway_app)
        assert missing == set(), f"routes present at v4.1.2 and gone now: {sorted(missing)}"

    def test_metrics_is_served_when_prometheus_is_installed(self, gateway_app: Any) -> None:
        from aegis.core import observability

        if not observability.prometheus_available():
            pytest.skip("prometheus-client is not installed; /metrics is not registered")
        assert ("/metrics", "GET") in _served_routes(gateway_app)

    def test_the_governed_routes_carry_no_trailing_slash_variants(self, gateway_app: Any) -> None:
        # A client posting to /v1/chat/completions must not be redirected to a
        # slashed twin, which would drop the body on a 307 for some clients.
        served = _served_routes(gateway_app)
        for path, method in V412_ROUTES:
            assert (path + "/", method) not in served


class TestPythonSurface:
    def test_the_top_level_package_still_exports_the_v412_names(self) -> None:
        import aegis

        assert V412_AEGIS_EXPORTS <= set(aegis.__all__)
        for name in sorted(V412_AEGIS_EXPORTS):
            assert hasattr(aegis, name), name

    def test_wrap_still_takes_a_client_positionally(self) -> None:
        import aegis

        parameters = list(inspect.signature(aegis.wrap).parameters.values())
        assert parameters[0].name == "client"
        assert parameters[0].kind is inspect.Parameter.POSITIONAL_OR_KEYWORD

    def test_the_version_is_a_dotted_string(self) -> None:
        import aegis

        assert isinstance(aegis.__version__, str)
        assert aegis.__version__.count(".") >= 2

    def test_the_portable_proof_verifier_keeps_its_call_shape(self) -> None:
        # Third-party verifiers call this with a leaf hash, a proof, and a root
        # they trust separately. The order of those three is the contract.
        from aegis.core.mmr import MerkleMountainRange

        parameters = list(
            inspect.signature(MerkleMountainRange.verify_portable_inclusion_hash).parameters
        )
        assert parameters[:3] == ["leaf_hash", "proof", "trusted_root"]


class TestLicensingSurface:
    """The licence model moved to its own module this release; nothing moved out."""

    @pytest.mark.parametrize(
        "name", ["LicenseEntitlement", "KNOWN_MODULES", "LicenseEnforcement", "LicenseError"]
    )
    def test_each_public_name_is_the_same_object_from_both_import_paths(self, name: str) -> None:
        # ``LicenseEntitlement`` and ``KNOWN_MODULES`` moved into model.py this
        # release. An importer that got them from the validator, or from the
        # package, must still get the identical object — not a copy that would
        # fail an ``isinstance`` check across the two import paths.
        package = importlib.import_module("aegis.licensing")
        validator = importlib.import_module("aegis.licensing.validator")
        assert getattr(package, name) is getattr(validator, name)

    def test_is_valid_still_takes_no_arguments(self) -> None:
        from aegis.licensing import LicenseEntitlement

        entitlement = LicenseEntitlement(
            customer_id="acme-corp",
            tier="enterprise",
            modules=frozenset({"veracity"}),
            max_annual_mgt=1,
            expires_at=1_800_000_000,
        )
        # ``now`` was added this release with a default, so the previous
        # zero-argument call must keep working.
        assert entitlement.is_valid() in (True, False)
        assert entitlement.has_module("veracity") in (True, False)

    def test_seconds_remaining_is_still_an_attribute_not_a_method(self) -> None:
        from aegis.licensing import LicenseEntitlement

        assert isinstance(inspect.getattr_static(LicenseEntitlement, "seconds_remaining"), property)


class TestEnginesRunUnlicensed:
    """The AGPLv3 software must not require a commercial token to import or run."""

    def test_the_engine_facades_import_without_a_licence(self, monkeypatch) -> None:
        from aegis.licensing.validator import LICENSE_TOKEN_ENV, ROOT_PUBKEY_ENV

        monkeypatch.delenv(LICENSE_TOKEN_ENV, raising=False)
        monkeypatch.delenv(ROOT_PUBKEY_ENV, raising=False)
        engines = importlib.import_module("aegis.engines")
        for name in ("VeracityEngine", "SanctumEngine", "AgentisEngine", "SovereignVault"):
            assert hasattr(engines, name), name

    def test_sanctum_redacts_without_a_licence(self, monkeypatch) -> None:
        from aegis.engines import SanctumEngine
        from aegis.licensing.validator import LICENSE_TOKEN_ENV, ROOT_PUBKEY_ENV

        monkeypatch.delenv(LICENSE_TOKEN_ENV, raising=False)
        monkeypatch.delenv(ROOT_PUBKEY_ENV, raising=False)
        engine = SanctumEngine()
        redacted = engine.deidentify_text("call 123-45-6789 now")
        assert "123-45-6789" not in redacted

    def test_the_default_window_is_unchanged(self) -> None:
        # Changing the default holdback silently changes how much of a stream a
        # caller sees before finalize, and the retained-byte ceiling with it.
        from aegis.engines.sanctum import SanctumEngine

        assert inspect.signature(SanctumEngine).parameters["window_chars"].default == 128


class TestRustFfiSurface:
    def test_every_v412_export_is_still_present(self) -> None:
        try:
            aegis_rust = importlib.import_module("aegis_rust")
        except ImportError:  # pragma: no cover - exercised on pure-Python installs
            pytest.skip("the aegis_rust extension is not built in this environment")
        missing = {name for name in V412_RUST_EXPORTS if not hasattr(aegis_rust, name)}
        assert missing == set(), f"FFI names present at v4.1.2 and gone now: {sorted(missing)}"

    def test_the_pure_python_path_stays_available(self) -> None:
        # The gateway runs without the extension. A change that made the Rust
        # module mandatory would break every source install.
        from aegis.core import crypto_audit

        assert hasattr(crypto_audit, "CryptographicAuditLedger")

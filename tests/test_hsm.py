# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""HSM / PKCS#11 signing integration (ROADMAP Domain 1.1).

Tests the HSMSigningBackend and its integration with CryptographicAuditLedger.
All PKCS#11 interactions are mocked so no real HSM hardware or SoftHSM2
installation is required.  The mock faithfully reproduces the python-pkcs11
object graph (lib → token → session → key objects).
"""
from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest

# ── PKCS#11 mock helpers ──────────────────────────────────────────────────────


def _make_pkcs11_module() -> MagicMock:
    """Build a minimal mock of the python-pkcs11 module hierarchy."""
    mod = MagicMock(name="pkcs11")

    # Enums used in hsm.py
    mod.Attribute = MagicMock()
    mod.Attribute.CLASS = "CLASS"
    mod.Attribute.LABEL = "LABEL"
    mod.Attribute.KEY_TYPE = "KEY_TYPE"
    mod.ObjectClass = MagicMock()
    mod.ObjectClass.PRIVATE_KEY = "PRIVATE_KEY"
    mod.ObjectClass.PUBLIC_KEY = "PUBLIC_KEY"
    mod.KeyType = MagicMock()
    mod.KeyType.RSA = "RSA"
    mod.KeyType.EC = "EC"
    mod.Mechanism = MagicMock()
    mod.Mechanism.SHA256_RSA_PKCS_PSS = "SHA256_RSA_PKCS_PSS"
    mod.Mechanism.ECDSA_SHA256 = "ECDSA_SHA256"
    mod.Mechanism.SHA256 = "SHA256"
    mod.MGF = MagicMock()
    mod.MGF.SHA256 = "MGF_SHA256"

    # Sub-modules
    mechanisms = MagicMock(name="pkcs11.mechanisms")
    mechanisms.RSA_PKCS_PSS_PARAMS = MagicMock(return_value=MagicMock())
    mod.mechanisms = mechanisms
    mod.util = MagicMock()
    mod.util.rsa = MagicMock()
    mod.util.rsa.encode_rsa_public_key = MagicMock(return_value=b"\x00" * 32)
    mod.util.ec = MagicMock()
    mod.util.ec.encode_ec_public_key = MagicMock(return_value=b"\x00" * 32)

    return mod


def _make_rsa_key(label: str, signature: bytes = b"rsa-sig") -> MagicMock:
    """Mock RSA private/public key pair."""
    priv = MagicMock()
    priv.__getitem__ = MagicMock(side_effect=lambda attr: "RSA" if attr == "KEY_TYPE" else label)
    priv.sign = MagicMock(return_value=signature)

    pub = MagicMock()
    pub.__getitem__ = MagicMock(side_effect=lambda attr: "RSA" if attr == "KEY_TYPE" else label)
    return priv, pub


def _make_ec_key(label: str, signature: bytes = b"ec-sig") -> MagicMock:
    """Mock EC private/public key pair."""
    priv = MagicMock()
    priv.__getitem__ = MagicMock(side_effect=lambda attr: "EC" if attr == "KEY_TYPE" else label)
    priv.sign = MagicMock(return_value=signature)

    pub = MagicMock()
    pub.__getitem__ = MagicMock(side_effect=lambda attr: "EC" if attr == "KEY_TYPE" else label)
    return priv, pub


def _make_session(priv_key, pub_key) -> MagicMock:
    """Mock PKCS#11 session with one key pair."""

    def _get_objects(attrs: dict) -> list:
        cls = attrs.get("CLASS")
        if cls == "PRIVATE_KEY":
            return [priv_key]
        if cls == "PUBLIC_KEY":
            return [pub_key]
        return []

    session = MagicMock()
    session.get_objects = MagicMock(side_effect=_get_objects)
    session.close = MagicMock()
    return session


def _make_token(session: MagicMock) -> MagicMock:
    token = MagicMock()
    token.label = "aegis-test-token"
    token.open = MagicMock(return_value=session)
    return token


def _make_slot(token: MagicMock) -> MagicMock:
    slot = MagicMock()
    slot.get_token = MagicMock(return_value=token)
    return slot


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def pkcs11_rsa_env():
    """Inject a mock pkcs11 module with an RSA signing key."""
    priv, pub = _make_rsa_key("aegis-signing-key", signature=b"mock-rsa-signature")
    session = _make_session(priv, pub)
    token = _make_token(session)
    slot = _make_slot(token)
    pkcs11_mod = _make_pkcs11_module()
    pkcs11_mod.lib = MagicMock(return_value=MagicMock(
        get_slots=MagicMock(return_value=[slot]),
        get_token=MagicMock(return_value=token),
    ))

    with patch.dict(sys.modules, {"pkcs11": pkcs11_mod, "pkcs11.util.rsa": pkcs11_mod.util.rsa,
                                   "pkcs11.mechanisms": pkcs11_mod.mechanisms,
                                   "pkcs11.util.ec": pkcs11_mod.util.ec}):
        yield pkcs11_mod, priv, pub, session


@pytest.fixture
def pkcs11_ec_env():
    """Inject a mock pkcs11 module with an EC signing key."""
    priv, pub = _make_ec_key("aegis-signing-key", signature=b"mock-ec-signature")
    session = _make_session(priv, pub)
    token = _make_token(session)
    slot = _make_slot(token)
    pkcs11_mod = _make_pkcs11_module()
    # Make KeyType.RSA mismatch so EC branch is taken
    pkcs11_mod.KeyType.RSA = "RSA"
    pkcs11_mod.KeyType.EC = "EC"
    pkcs11_mod.lib = MagicMock(return_value=MagicMock(
        get_slots=MagicMock(return_value=[slot]),
        get_token=MagicMock(return_value=token),
    ))

    with patch.dict(sys.modules, {"pkcs11": pkcs11_mod, "pkcs11.util.rsa": pkcs11_mod.util.rsa,
                                   "pkcs11.mechanisms": pkcs11_mod.mechanisms,
                                   "pkcs11.util.ec": pkcs11_mod.util.ec}):
        yield pkcs11_mod, priv, pub, session


# ── HSMSigningBackend unit tests ──────────────────────────────────────────────


class TestHSMSigningBackendUnavailable:
    def test_available_false_when_no_library(self):
        """When pkcs11 is not importable the backend is unavailable."""
        # Temporarily hide pkcs11 from sys.modules so the import guard fires
        saved = sys.modules.pop("pkcs11", None)
        try:
            import aegis.core.hsm as hsm_mod
            # Patch _PKCS11_AVAILABLE to False to simulate missing library
            with patch.object(hsm_mod, "_PKCS11_AVAILABLE", False):
                backend = hsm_mod.HSMSigningBackend(library_path="/nonexistent.so")
                assert backend.available is False
        finally:
            if saved is not None:
                sys.modules["pkcs11"] = saved

    def test_sign_raises_when_unavailable(self):
        import aegis.core.hsm as hsm_mod
        from aegis.core.hsm import HSMSigningBackend, HSMUnavailableError
        with patch.object(hsm_mod, "_PKCS11_AVAILABLE", False):
            backend = HSMSigningBackend(library_path="/nonexistent.so")
            with pytest.raises(HSMUnavailableError):
                backend.sign(b"data")

    def test_available_false_when_lib_raises(self):
        """library_path exists but pkcs11.lib() raises (e.g. library corrupt)."""
        import aegis.core.hsm as hsm_mod

        mock_pkcs11 = MagicMock()
        mock_pkcs11.lib = MagicMock(side_effect=Exception("library load error"))
        with patch.dict(sys.modules, {"pkcs11": mock_pkcs11, "pkcs11.util.rsa": MagicMock(),
                                       "pkcs11.mechanisms": MagicMock(), "pkcs11.util.ec": MagicMock()}):
            with patch.object(hsm_mod, "_PKCS11_AVAILABLE", True):
                backend = hsm_mod.HSMSigningBackend(library_path="/fake/libpkcs11.so")
                assert backend.available is False

    def test_available_false_when_no_slots(self):
        import aegis.core.hsm as hsm_mod

        mock_pkcs11 = MagicMock()
        mock_pkcs11.lib = MagicMock(return_value=MagicMock(
            get_slots=MagicMock(return_value=[])
        ))
        with patch.dict(sys.modules, {"pkcs11": mock_pkcs11, "pkcs11.util.rsa": MagicMock(),
                                       "pkcs11.mechanisms": MagicMock(), "pkcs11.util.ec": MagicMock()}):
            with patch.object(hsm_mod, "_PKCS11_AVAILABLE", True):
                backend = hsm_mod.HSMSigningBackend(library_path="/fake/libpkcs11.so")
                assert backend.available is False


class TestHSMSigningBackendRSA:
    def test_available_true_with_rsa_key(self, pkcs11_rsa_env):
        import aegis.core.hsm as hsm_mod
        with patch.object(hsm_mod, "_PKCS11_AVAILABLE", True):
            backend = hsm_mod.HSMSigningBackend(
                library_path="/fake/libsofthsm2.so",
                key_label="aegis-signing-key",
            )
            assert backend.available is True

    def test_rsa_sign_returns_correct_scheme(self, pkcs11_rsa_env):
        import aegis.core.hsm as hsm_mod
        with patch.object(hsm_mod, "_PKCS11_AVAILABLE", True):
            backend = hsm_mod.HSMSigningBackend(
                library_path="/fake/libsofthsm2.so",
                key_label="aegis-signing-key",
            )
            sig_bytes, pub_hex, scheme = backend.sign(b"test-data")
            assert scheme == "pkcs11-rsa-pss-sha256"
            assert isinstance(sig_bytes, bytes)
            assert len(sig_bytes) > 0
            # Public key hex exported
            assert isinstance(pub_hex, str)

    def test_rsa_signature_matches_mock(self, pkcs11_rsa_env):
        pkcs11_mod, priv, pub, session = pkcs11_rsa_env
        import aegis.core.hsm as hsm_mod
        with patch.object(hsm_mod, "_PKCS11_AVAILABLE", True):
            backend = hsm_mod.HSMSigningBackend(
                library_path="/fake/libsofthsm2.so",
                key_label="aegis-signing-key",
            )
            sig_bytes, _, _ = backend.sign(b"hello")
            assert sig_bytes == b"mock-rsa-signature"

    def test_close_calls_session_close(self, pkcs11_rsa_env):
        pkcs11_mod, priv, pub, session = pkcs11_rsa_env
        import aegis.core.hsm as hsm_mod
        with patch.object(hsm_mod, "_PKCS11_AVAILABLE", True):
            backend = hsm_mod.HSMSigningBackend(
                library_path="/fake/libsofthsm2.so",
            )
            backend.close()
            session.close.assert_called_once()
            assert backend.available is False

    def test_key_label_not_found_raises(self, pkcs11_rsa_env):
        from aegis.core.hsm import HSMUnavailableError
        pkcs11_mod, priv, pub, session = pkcs11_rsa_env
        # Override session to return empty key list
        session.get_objects = MagicMock(return_value=[])

        import aegis.core.hsm as hsm_mod
        with patch.object(hsm_mod, "_PKCS11_AVAILABLE", True):
            backend = hsm_mod.HSMSigningBackend(
                library_path="/fake/libsofthsm2.so",
                key_label="nonexistent-key",
            )
            if backend.available:
                with pytest.raises(HSMUnavailableError):
                    backend.sign(b"data")


class TestHSMSigningBackendEC:
    def test_ec_sign_returns_correct_scheme(self, pkcs11_ec_env):
        pkcs11_mod, priv, pub, session = pkcs11_ec_env
        import aegis.core.hsm as hsm_mod
        # Patch the KeyType so RSA branch is NOT taken
        with patch.object(hsm_mod, "_PKCS11_AVAILABLE", True):
            with patch.object(pkcs11_mod.KeyType, "RSA", "RSA_NEVER_MATCH"):
                backend = hsm_mod.HSMSigningBackend(
                    library_path="/fake/libsofthsm2.so",
                    key_label="aegis-signing-key",
                )
                if backend.available:
                    sig_bytes, pub_hex, scheme = backend.sign(b"test-ec")
                    assert scheme == "pkcs11-ecdsa-sha256"


# ── Integration: CryptographicAuditLedger with HSM backend ───────────────────


class TestLedgerHSMIntegration:
    def _make_mock_backend(self, available: bool = True, scheme: str = "pkcs11-rsa-pss-sha256"):
        """Create a simple mock HSMSigningBackend."""
        backend = MagicMock()
        backend.available = available
        if available:
            backend.sign = MagicMock(return_value=(b"hsm-sig", "pubhex", scheme))
        return backend

    def test_hsm_signature_scheme_stored_in_node(self, tmp_path):
        from aegis.core.crypto_audit import CryptographicAuditLedger

        mock_backend = self._make_mock_backend()
        wal = str(tmp_path / "hsm.wal.jsonl")
        ledger = CryptographicAuditLedger(
            wal, signing_key="", hsm_backend=mock_backend
        )
        try:
            node = ledger.commit_state("s1", 1.0, b"payload")
            assert node.signature_scheme == "pkcs11-rsa-pss-sha256"
            assert node.signature == b"hsm-sig".hex()
            assert node.public_key == "pubhex"
            assert node.is_fallback is False
        finally:
            ledger.close()

    def test_hsm_sign_called_per_commit(self, tmp_path):
        from aegis.core.crypto_audit import CryptographicAuditLedger

        mock_backend = self._make_mock_backend()
        wal = str(tmp_path / "hsm2.wal.jsonl")
        ledger = CryptographicAuditLedger(
            wal, signing_key="", hsm_backend=mock_backend
        )
        try:
            ledger.commit_state("s1", 1.0, b"p1")
            ledger.commit_state("s2", 2.0, b"p2")
            assert mock_backend.sign.call_count == 2
        finally:
            ledger.close()

    def test_falls_back_to_hmac_when_hsm_unavailable(self, tmp_path):
        from aegis.core.crypto_audit import CryptographicAuditLedger

        unavailable_backend = self._make_mock_backend(available=False)
        wal = str(tmp_path / "fallback.wal.jsonl")
        with patch("aegis.core.crypto_audit.RUST_AVAILABLE", False):
            ledger = CryptographicAuditLedger(
                wal, signing_key="test-hmac-key", hsm_backend=unavailable_backend
            )
            try:
                node = ledger.commit_state("s1", 1.0, b"payload")
                assert node.signature_scheme == "hmac-sha256"
            finally:
                ledger.close()

    def test_falls_back_to_hmac_when_hsm_raises(self, tmp_path):
        from aegis.core.crypto_audit import CryptographicAuditLedger
        from aegis.core.hsm import HSMUnavailableError

        backend = MagicMock()
        backend.available = True
        backend.sign = MagicMock(side_effect=HSMUnavailableError("session lost"))

        wal = str(tmp_path / "raise.wal.jsonl")
        with patch("aegis.core.crypto_audit.RUST_AVAILABLE", False):
            ledger = CryptographicAuditLedger(
                wal, signing_key="fallback-key", hsm_backend=backend
            )
            try:
                node = ledger.commit_state("s1", 1.0, b"payload")
                assert node.signature_scheme == "hmac-sha256"
            finally:
                ledger.close()

    def test_no_hsm_backend_uses_hmac(self, tmp_path):
        from aegis.core.crypto_audit import CryptographicAuditLedger

        wal = str(tmp_path / "nohs.wal.jsonl")
        with patch("aegis.core.crypto_audit.RUST_AVAILABLE", False):
            ledger = CryptographicAuditLedger(wal, signing_key="my-key", hsm_backend=None)
            try:
                node = ledger.commit_state("s1", 1.0, b"payload")
                assert node.signature_scheme == "hmac-sha256"
            finally:
                ledger.close()

    def test_integrity_check_passes_after_hsm_sign(self, tmp_path):
        from aegis.core.crypto_audit import CryptographicAuditLedger

        mock_backend = self._make_mock_backend()
        wal = str(tmp_path / "integrity.wal.jsonl")
        ledger = CryptographicAuditLedger(
            wal, signing_key="", hsm_backend=mock_backend
        )
        try:
            for i in range(5):
                ledger.commit_state(f"s{i}", float(i), b"data")
            valid, idx = ledger.verify_integrity()
            assert valid is True
            assert idx is None
        finally:
            ledger.close()


# ── HSMManager backward-compat shim ──────────────────────────────────────────


class TestHSMManagerShim:
    def test_open_session_returns_true(self):
        from aegis.core.hsm import HSMManager

        mgr = HSMManager(library_path="/nonexistent.so")
        result = mgr.open_session(slot_id=0, pin="pin")
        assert result is True  # always True (graceful)

    def test_sign_data_returns_bytes_software_fallback(self):
        from aegis.core.hsm import HSMManager

        mgr = HSMManager(library_path="/nonexistent.so")
        mgr.open_session(slot_id=0, pin="pin")
        sig = mgr.sign_data(key_handle=1, data=b"hello")
        assert isinstance(sig, bytes)
        assert len(sig) > 0

    def test_close_session_idempotent(self):
        from aegis.core.hsm import HSMManager

        mgr = HSMManager(library_path="/nonexistent.so")
        mgr.open_session(slot_id=0, pin="pin")
        mgr.close_session()
        mgr.close_session()  # second call must not raise

    def test_sign_without_session_raises(self):
        from aegis.core.hsm import HSMManager

        mgr = HSMManager(library_path="/nonexistent.so")
        with pytest.raises(ConnectionError):
            mgr.sign_data(key_handle=1, data=b"data")

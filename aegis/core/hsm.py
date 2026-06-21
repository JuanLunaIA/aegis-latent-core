# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.hsm — Hardware Security Module (HSM) / PKCS#11 signing backend.

Provides ``HSMSigningBackend``: a thread-safe, session-persistent PKCS#11
signing interface whose signing key NEVER leaves the HSM token boundary.

When ``python-pkcs11`` is not installed, when the configured library path does
not exist, or when no token is present in the target slot, ``available`` is
``False`` and the caller should fall back to software signing (HMAC-SHA256 or
ML-DSA).  This makes the HSM integration fully optional and backward-compatible.

Supported HSMs (tested with SoftHSM2 in CI; interoperable with any PKCS#11
v2.20+ implementation):
  - Thales Luna Network HSM
  - AWS CloudHSM (PKCS#11 client)
  - SoftHSM2 (software token; FIPS-validated mode available)
  - nCipher nShield
  - YubiHSM2

Signing mechanisms (auto-detected from key type):
  - RSA: CKM_SHA256_RSA_PKCS_PSS (RSA-PSS, SHA-256, MGF1-SHA-256, salt=32)
  - EC:  CKM_ECDSA_SHA256

Usage::

    from aegis.core.hsm import HSMSigningBackend, HSMUnavailableError

    backend = HSMSigningBackend(
        library_path="/usr/lib/softhsm/libsofthsm2.so",
        slot_id=0,
        pin="changeme",
        key_label="aegis-signing-key",
    )
    if backend.available:
        sig_bytes, pub_hex, scheme = backend.sign(data)
    backend.close()
"""

from __future__ import annotations

import logging
import threading
from typing import Any

logger = logging.getLogger(__name__)

# Lazy import guard: pkcs11 requires CFFI / libffi at load time.
try:
    import pkcs11  # noqa: F401

    _PKCS11_AVAILABLE = True
except ImportError:
    _PKCS11_AVAILABLE = False
    logger.debug("python-pkcs11 not installed; HSM signing backend unavailable")


class HSMUnavailableError(RuntimeError):
    """Raised when the HSM backend is not usable (no library, no token, etc.)."""


class HSMSigningBackend:
    """Thread-safe PKCS#11 signing backend.

    The private key is referenced by handle; it NEVER enters application memory.
    Session re-establishment is automatic if the token ejects between calls.

    Parameters
    ----------
    library_path:
        Filesystem path to the PKCS#11 shared library
        (e.g. ``/usr/lib/softhsm/libsofthsm2.so`` or
        ``/opt/cloudhsm/lib/libcloudhsm_pkcs11.so``).
    slot_id:
        PKCS#11 slot index (0-based).  Ignored when ``token_label`` is set.
    pin:
        User PIN for ``C_Login``.  Pass via environment / Vault; never
        hard-code in source or config files.
    key_label:
        ``CKA_LABEL`` of the private signing key object stored in the token.
    token_label:
        When non-empty, the slot is resolved by token label rather than slot_id.
    """

    def __init__(
        self,
        library_path: str,
        slot_id: int = 0,
        pin: str = "",
        key_label: str = "aegis-signing-key",
        token_label: str = "",
    ) -> None:
        self._library_path = library_path
        self._slot_id = slot_id
        self._pin = pin
        self._key_label = key_label
        self._token_label = token_label
        self._lock = threading.Lock()
        self._lib: Any = None
        self._session: Any = None
        self._available = False
        self._scheme: str = ""

        self._try_initialize()

    def _try_initialize(self) -> None:
        """Probe the PKCS#11 library and token. Sets self._available.

        Imports pkcs11 locally so that test code can inject a mock via
        sys.modules without being blocked by the module-level ImportError guard.
        """
        try:
            import pkcs11 as _pkcs11  # noqa: PLC0415
            import pkcs11.util.rsa as _pkcs11_rsa  # noqa: PLC0415,F401
        except ImportError:
            logger.info(
                "HSM signing backend disabled: python-pkcs11 not installed. "
                "Install with: pip install python-pkcs11"
            )
            return

        try:
            lib = _pkcs11.lib(self._library_path)
            self._lib = lib

            if self._token_label:
                token = lib.get_token(token_label=self._token_label)
            else:
                slots = lib.get_slots(token_present=True)
                if not slots:
                    logger.warning(
                        "HSM: no tokens present in PKCS#11 library %s", self._library_path
                    )
                    return
                if self._slot_id >= len(slots):
                    logger.warning(
                        "HSM: slot_id=%d out of range (found %d slots)",
                        self._slot_id,
                        len(slots),
                    )
                    return
                token = slots[self._slot_id].get_token()

            session = token.open(user_pin=self._pin)
            self._session = session
            self._available = True
            logger.info(
                "HSM signing backend initialised: library=%s token=%s",
                self._library_path,
                getattr(token, "label", "?"),
            )
        except Exception as exc:
            logger.warning("HSM signing backend not available: %s", exc)
            self._available = False

    @property
    def available(self) -> bool:
        """``True`` when a PKCS#11 session is open and a signing key is reachable."""
        return self._available

    def sign(self, data: bytes) -> tuple[bytes, str, str]:
        """Sign ``data`` using the HSM-resident private key.

        Returns ``(signature_bytes, public_key_hex, scheme_name)``.

        ``scheme_name`` is one of:
        - ``"pkcs11-rsa-pss-sha256"``   (RSA-PSS, MGF1-SHA-256, salt=32)
        - ``"pkcs11-ecdsa-sha256"``     (ECDSA with SHA-256)

        Raises
        ------
        HSMUnavailableError
            When ``self.available`` is ``False``.
        """
        if not self._available:
            raise HSMUnavailableError("HSM signing backend is not available")

        with self._lock:
            try:
                return self._sign_internal(data)
            except Exception as exc:
                logger.warning("HSM sign failed (%s); attempting session refresh", exc)
                self._try_initialize()
                if not self._available:
                    raise HSMUnavailableError(
                        f"HSM session lost and could not be re-established: {exc}"
                    ) from exc
                return self._sign_internal(data)

    def _sign_internal(self, data: bytes) -> tuple[bytes, str, str]:
        """Inner sign — must be called under self._lock with an active session."""
        import pkcs11 as _pkcs11  # noqa: PLC0415

        session = self._session

        # Find private key by label
        try:
            priv_keys = list(
                session.get_objects(
                    {
                        _pkcs11.Attribute.CLASS: _pkcs11.ObjectClass.PRIVATE_KEY,
                        _pkcs11.Attribute.LABEL: self._key_label,
                    }
                )
            )
        except Exception as exc:
            raise HSMUnavailableError(f"HSM key search failed: {exc}") from exc

        if not priv_keys:
            raise HSMUnavailableError(
                f"No private key with label {self._key_label!r} found in HSM token"
            )

        priv_key = priv_keys[0]
        key_type = priv_key[_pkcs11.Attribute.KEY_TYPE]

        if key_type == _pkcs11.KeyType.RSA:
            return self._sign_rsa(session, priv_key, data, _pkcs11)
        elif key_type == _pkcs11.KeyType.EC:
            return self._sign_ec(session, priv_key, data, _pkcs11)
        else:
            raise HSMUnavailableError(f"Unsupported HSM key type: {key_type}")

    def _sign_rsa(
        self, session: Any, priv_key: Any, data: bytes, _pkcs11: Any
    ) -> tuple[bytes, str, str]:
        """RSA-PSS signing with SHA-256 / MGF1-SHA-256 / salt=32."""
        import pkcs11.mechanisms as _mech  # noqa: PLC0415

        mechanism = _pkcs11.Mechanism.SHA256_RSA_PKCS_PSS
        params = _mech.RSA_PKCS_PSS_PARAMS(
            hashAlg=_pkcs11.Mechanism.SHA256,
            mgf=_pkcs11.MGF.SHA256,
            sLen=32,
        )
        sig_bytes: bytes = priv_key.sign(data, mechanism=mechanism, mechanism_param=params)

        pub_hex = self._export_rsa_public_key(session, _pkcs11)
        return sig_bytes, pub_hex, "pkcs11-rsa-pss-sha256"

    def _sign_ec(
        self, session: Any, priv_key: Any, data: bytes, _pkcs11: Any
    ) -> tuple[bytes, str, str]:
        """ECDSA with SHA-256 (CKM_ECDSA_SHA256)."""
        sig_bytes: bytes = priv_key.sign(data, mechanism=_pkcs11.Mechanism.ECDSA_SHA256)

        pub_hex = self._export_ec_public_key(session, _pkcs11)
        return sig_bytes, pub_hex, "pkcs11-ecdsa-sha256"

    def _export_rsa_public_key(self, session: Any, _pkcs11: Any) -> str:
        """Return hex-encoded SPKI DER of the RSA public key, or '' on failure."""
        try:
            import pkcs11.util.rsa as _rsa_util  # noqa: PLC0415

            pub_keys = list(
                session.get_objects(
                    {
                        _pkcs11.Attribute.CLASS: _pkcs11.ObjectClass.PUBLIC_KEY,
                        _pkcs11.Attribute.LABEL: self._key_label,
                    }
                )
            )
            if not pub_keys:
                return ""
            der = _rsa_util.encode_rsa_public_key(pub_keys[0])
            return str(der.hex())
        except Exception:
            return ""

    def _export_ec_public_key(self, session: Any, _pkcs11: Any) -> str:
        """Return hex-encoded EC public key point, or '' on failure."""
        try:
            import pkcs11.util.ec as _ec_util  # noqa: PLC0415

            pub_keys = list(
                session.get_objects(
                    {
                        _pkcs11.Attribute.CLASS: _pkcs11.ObjectClass.PUBLIC_KEY,
                        _pkcs11.Attribute.LABEL: self._key_label,
                    }
                )
            )
            if not pub_keys:
                return ""
            der = _ec_util.encode_ec_public_key(pub_keys[0])
            return str(der.hex())
        except Exception:
            return ""

    def close(self) -> None:
        """Close the PKCS#11 session and release the library handle."""
        with self._lock:
            try:
                if self._session is not None:
                    self._session.close()
            except Exception:
                pass
            self._session = None
            self._available = False
            logger.debug("HSM session closed")


# ── Backward-compat shim ──────────────────────────────────────────────────────
# The old stub HSMManager / HSMSession are preserved for artifact_signing.py.
# New code should use HSMSigningBackend directly.


class _HSMSession:
    """Internal session state (legacy shim)."""

    def __init__(self, slot_id: int, session_handle: int, user_pin: str) -> None:
        self.slot_id = slot_id
        self.session_handle = session_handle
        self.user_pin = user_pin


class HSMManager:
    """Legacy HSM interface used by artifact_signing.py.

    In new code prefer ``HSMSigningBackend`` which uses real PKCS#11.
    This shim delegates to ``HSMSigningBackend`` when the library is
    available, and falls back to a deterministic HMAC of a slot-derived key
    (identical to the previous stub behaviour) when it is not.
    """

    def __init__(self, library_path: str = "/usr/lib/softhsm/libsofthsm2.so") -> None:
        self.library_path = library_path
        self._session: _HSMSession | None = None
        self._backend: HSMSigningBackend | None = None
        logger.info("HSMManager initialized with library: %s", library_path)

    def open_session(self, slot_id: int, pin: str) -> bool:
        """Open a session and authenticate. Returns True on success."""
        try:
            self._session = _HSMSession(
                slot_id=slot_id,
                session_handle=0,
                user_pin=pin,
            )
            self._backend = HSMSigningBackend(
                library_path=self.library_path,
                slot_id=slot_id,
                pin=pin,
            )
            if self._backend.available:
                logger.info("HSM Session opened via PKCS#11 on slot %d", slot_id)
            else:
                logger.info(
                    "HSM PKCS#11 unavailable; session opened in software-fallback mode (slot %d)",
                    slot_id,
                )
            return True
        except Exception as exc:
            logger.error("HSM Session failed: %s", exc)
            return False

    def sign_data(self, key_handle: int, data: bytes) -> bytes:
        """Sign ``data`` via HSM. Raises ConnectionError if no session open."""
        if not self._session:
            raise ConnectionError("No active HSM session. Call open_session first.")

        # Delegate to real PKCS#11 backend when available.
        if self._backend and self._backend.available:
            try:
                sig_bytes, _pub, _scheme = self._backend.sign(data)
                return sig_bytes
            except HSMUnavailableError:
                pass

        # Software fallback: deterministic HMAC keyed by slot-derived handle.
        import hashlib
        import hmac as _hmac

        slot_key = f"HSM_KEY_{key_handle}".encode()
        return _hmac.new(slot_key, data, hashlib.sha512).digest()

    def close_session(self) -> None:
        """Close session and zeroize handles."""
        if self._backend:
            self._backend.close()
            self._backend = None
        self._session = None
        logger.info("HSM Session closed and handles zeroized.")

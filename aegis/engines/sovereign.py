# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

"""Sovereign vault — post-quantum signing and hardware-backed key custody.

Wraps :mod:`aegis.core.pqc_signer`, :mod:`aegis.core.hsm` and
:mod:`aegis.core.pqc_tls` behind one surface, and reports honestly which of
them the running environment actually has:

    vault = SovereignVault()
    print(vault.capabilities())        # what is present, not what is claimed
    signature = vault.sign(b"payload")

Availability is a runtime fact, not a build claim
-------------------------------------------------

Three capabilities here are independently optional. ML-DSA needs the compiled
``aegis_rust`` extension; the hybrid KEM needs ``kyber-py``; PKCS#11 needs a
token and a driver library. :meth:`capabilities` probes each and returns what
is really there, so a caller can refuse rather than discover it mid-request.

Boundaries carried over unchanged
---------------------------------

- ML-DSA-65 and ML-KEM-1024 name **algorithms**, not validated modules. Nothing
  here is FIPS 140 validated, and algorithm choice is not an approved
  operational mode (``CLM-013``-class boundary).
- **No constant-time claim is made or approved.** The retained timing
  experiment passed non-detection for `sign` and failed for `verify`; see
  ``docs/security/PQC_CONSTANT_TIME.md``. Do not describe this surface as
  timing-invariant.
- The hybrid KEM helper is a **key-agreement exchange, not an authenticated
  transport**. It hashes no protocol transcript and authenticates no peer, so
  it is not TLS and must not be presented as one.
- PKCS#11 custody is only as good as the token, its driver, its PIN handling
  and the operator's key ceremony — none of which this module can observe.
- ``sign`` refuses to fabricate a signature when no real backend is present.
  There is no simulated mode.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from aegis.core import pqc_tls
from aegis.core.hsm import HSMSigningBackend, HSMUnavailableError
from aegis.core.pqc_signer import PQCSigner, PQCUnavailableError
from aegis.core.pqc_signer import backend_available as pqc_backend_available
from aegis.engines import require_module
from aegis.licensing.validator import LicenseEntitlement

_MODULE_NAME = "sovereign"


@dataclass(frozen=True, slots=True)
class VaultCapabilities:
    """What this process can actually do right now."""

    mldsa_signing: bool
    hybrid_kem: bool
    pkcs11_hsm: bool

    def as_dict(self) -> dict[str, bool]:
        return {
            "mldsa_signing": self.mldsa_signing,
            "hybrid_kem": self.hybrid_kem,
            "pkcs11_hsm": self.pkcs11_hsm,
        }


@dataclass(frozen=True, slots=True)
class SignatureResult:
    """A signature together with what produced it.

    ``scheme`` is one of ``ml-dsa-65``, ``pkcs11-rsa-pss-sha256`` or
    ``pkcs11-ecdsa-sha256``. It travels with the signature because a verifier
    that assumes the wrong one cannot tell a misconfiguration from a forgery.
    """

    signature: bytes
    scheme: str
    public_key: bytes


class SovereignVault:
    """Post-quantum signing and hardware key custody as a library."""

    def __init__(
        self,
        *,
        require_real_pqc: bool = True,
        hsm_backend: HSMSigningBackend | None = None,
        entitlement: LicenseEntitlement | None = None,
    ) -> None:
        self._entitlement = require_module(_MODULE_NAME, entitlement=entitlement)
        self._hsm = hsm_backend
        self._require_real_pqc = require_real_pqc
        self._signer: PQCSigner | None = None

    @property
    def entitlement(self) -> LicenseEntitlement | None:
        return self._entitlement

    def capabilities(self) -> VaultCapabilities:
        """Probe each optional backend. Cheap, and safe to call repeatedly."""

        hsm_ready = False
        if self._hsm is not None:
            try:
                hsm_ready = bool(self._hsm.available)
            except Exception:  # pragma: no cover - driver-specific failure
                hsm_ready = False
        return VaultCapabilities(
            # The module-level probe, not ``PQCSigner.is_available``: that is a
            # property, so reading it off the class yields the property object
            # rather than a bool — always truthy, and a capabilities report that
            # is always true is worse than none.
            mldsa_signing=pqc_backend_available(),
            hybrid_kem=pqc_tls.backend_available(),
            pkcs11_hsm=hsm_ready,
        )

    # ── signing ─────────────────────────────────────────────────────────

    def _pqc_signer(self) -> PQCSigner:
        if self._signer is None:
            self._signer = PQCSigner(require_real=self._require_real_pqc)
        return self._signer

    def sign_detached(self, message: bytes) -> SignatureResult:
        """Sign, and say which scheme did it.

        The HSM takes precedence because a hardware-held key is the stronger
        custody story, and the point of configuring one is that it is used.

        The scheme is returned rather than implied because the two backends do
        not agree: PKCS#11 signs with ``pkcs11-rsa-pss-sha256`` or
        ``pkcs11-ecdsa-sha256``, while the software path signs with ML-DSA-65.
        Returning bare bytes from either would leave a verifier guessing which
        algorithm and which public key to use, and guessing wrong reads as a
        forged signature rather than a configuration error.

        Raises when neither backend is usable; it never returns a placeholder.
        """

        if self._hsm is not None:
            try:
                signature, public_key_hex, scheme = self._hsm.sign(message)
                return SignatureResult(
                    signature=signature,
                    scheme=scheme,
                    public_key=bytes.fromhex(public_key_hex),
                )
            except HSMUnavailableError:
                if self._require_real_pqc:
                    raise
        signer = self._pqc_signer()
        return SignatureResult(
            signature=signer.sign(message),
            scheme="ml-dsa-65",
            public_key=signer.public_key,
        )

    def sign(self, message: bytes) -> bytes:
        """Signature bytes only, for a caller that already knows the scheme.

        Prefer :meth:`sign_detached` unless the scheme is fixed by
        configuration you control.
        """

        return self.sign_detached(message).signature

    @staticmethod
    def verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify an ML-DSA-65 signature. No constant-time claim is made."""

        return PQCSigner.verify(message, signature, public_key)

    def public_key(self) -> bytes:
        key: bytes = self._pqc_signer().public_key
        return key

    # ── hybrid key agreement ────────────────────────────────────────────

    def new_hybrid_exchange(self) -> Any:
        """Return a hybrid X25519 + ML-KEM-1024 exchange, or refuse.

        This is a key-agreement helper. It is not an authenticated transport
        and must not be described as TLS.
        """

        if not pqc_tls.backend_available():
            raise PQCUnavailableError(
                "hybrid ML-KEM exchange needs the optional 'kyber-py' package; "
                "install the pqc extra or kyber-py directly"
            )
        return pqc_tls.HybridPQCExchange()


__all__ = ["SignatureResult", "SovereignVault", "VaultCapabilities"]

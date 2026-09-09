# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

"""Sign audit-node hashes with HashiCorp Vault's Transit secrets engine.

The private key stays inside Vault. Aegis submits a digest and receives a
signature; the key material never enters this process's address space, which is
the whole reason to use Transit rather than a local keyring.

    signer = VaultTransitSigner(url="https://vault:8200", token=..., key_name="aegis")
    signature = signer.sign(node_hash)
    signer.verify(node_hash, signature)     # -> bool

What this moves, and what it does not
-------------------------------------

It moves **key custody** into Vault. It does not move trust:

- **Vault's availability becomes yours.** A signing call is a network round trip
  on the commit path. If evidence must be signed and Vault is unreachable, the
  commit fails — which is the fail-closed direction, and it is a real
  availability coupling that must be sized before deployment.
- **The Vault token is a bearer credential** with the same reach as the signing
  key for as long as it is valid. Protecting it is the deployment's problem;
  this module only avoids logging it.
- **This is not non-repudiation.** Vault signs for whoever presents a token with
  the policy. It attests that *something holding that token* asked, not that a
  particular person did.
- **No timestamp authority is involved.** A Transit signature carries no
  attested time.

Verification prefers Vault's own ``/verify`` endpoint. Local verification
against a public key fetched from Vault is offered for offline checking, and
the trust then rests on how that public key was obtained.
"""

from __future__ import annotations

import base64
import binascii
import logging
from dataclasses import dataclass
from typing import Any, Final

import httpx

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT_SECONDS: Final[float] = 10.0
_DEFAULT_MOUNT: Final[str] = "transit"


class VaultTransitError(RuntimeError):
    """A Transit operation failed. Never carries the token or key material."""


@dataclass(frozen=True, slots=True)
class VaultTransitConfig:
    url: str
    token: str
    key_name: str
    mount: str = _DEFAULT_MOUNT
    namespace: str | None = None
    verify_tls: bool = True
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS
    hash_algorithm: str = "sha2-256"

    def __post_init__(self) -> None:
        for field_name in ("url", "token", "key_name"):
            if not getattr(self, field_name):
                raise ValueError(f"Vault Transit {field_name} must not be empty")
        if not self.verify_tls:
            logger.warning(
                "Vault TLS verification is disabled; the Vault token is transmitted "
                "over an unverified channel"
            )


class VaultTransitSigner:
    """Asymmetric signing through Vault Transit. Keys never leave Vault."""

    def __init__(
        self,
        config: VaultTransitConfig | None = None,
        *,
        transport: httpx.BaseTransport | None = None,
        **kwargs: Any,
    ) -> None:
        self._config = config if config is not None else VaultTransitConfig(**kwargs)
        headers = {"X-Vault-Token": self._config.token}
        if self._config.namespace:
            headers["X-Vault-Namespace"] = self._config.namespace
        self._client = httpx.Client(
            base_url=self._config.url.rstrip("/"),
            timeout=self._config.timeout_seconds,
            verify=self._config.verify_tls,
            transport=transport,
            headers=headers,
        )

    @property
    def key_name(self) -> str:
        return self._config.key_name

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            response = self._client.post(path, json=payload)
        except (httpx.HTTPError, OSError) as exc:
            # str(exc) from httpx carries the URL, never a header value.
            raise VaultTransitError(f"Vault request to {path} failed: {exc}") from exc
        if response.status_code >= 400:
            raise VaultTransitError(
                f"Vault returned {response.status_code} for {path}: {_safe_errors(response)}"
            )
        try:
            body: dict[str, Any] = response.json()
        except ValueError as exc:
            raise VaultTransitError(f"Vault response to {path} was not JSON: {exc}") from exc
        return body

    @staticmethod
    def _digest_to_input(node_hash: str) -> str:
        """Vault wants base64 of the raw digest, not the hex text."""

        try:
            raw = bytes.fromhex(node_hash)
        except ValueError as exc:
            raise VaultTransitError(
                f"node hash must be hex-encoded; got {len(node_hash)} characters"
            ) from exc
        if len(raw) != 32:
            raise VaultTransitError(
                f"node hash must be a 32-byte SHA-256 digest, got {len(raw)} bytes"
            )
        return base64.b64encode(raw).decode("ascii")

    def sign(self, node_hash: str) -> str:
        """Sign a hex SHA-256 node hash; returns Vault's ``vault:v1:...`` string.

        Uses ``prehashed=true`` because the input already *is* the digest.
        Omitting it would make Vault hash the digest again, producing a
        signature over the wrong value that still verifies through Vault and
        fails everywhere else.
        """

        body = self._post(
            f"/v1/{self._config.mount}/sign/{self._config.key_name}",
            {
                "input": self._digest_to_input(node_hash),
                "prehashed": True,
                "hash_algorithm": self._config.hash_algorithm,
            },
        )
        signature = body.get("data", {}).get("signature")
        if not isinstance(signature, str) or not signature:
            raise VaultTransitError("Vault sign response carried no signature")
        return signature

    def verify(self, node_hash: str, signature: str) -> bool:
        """Verify through Vault's own endpoint."""

        body = self._post(
            f"/v1/{self._config.mount}/verify/{self._config.key_name}",
            {
                "input": self._digest_to_input(node_hash),
                "signature": signature,
                "prehashed": True,
                "hash_algorithm": self._config.hash_algorithm,
            },
        )
        return bool(body.get("data", {}).get("valid", False))

    def public_key_pem(self, version: str = "1") -> str:
        """Fetch a public key so signatures can be checked offline later.

        Offline verification is only as trustworthy as this fetch. A key taken
        from the same Vault that produced the signature proves consistency, not
        authenticity, in the same way a proof's own root does.
        """

        try:
            response = self._client.get(f"/v1/{self._config.mount}/keys/{self._config.key_name}")
        except (httpx.HTTPError, OSError) as exc:
            raise VaultTransitError(f"Vault key fetch failed: {exc}") from exc
        if response.status_code >= 400:
            raise VaultTransitError(
                f"Vault returned {response.status_code} fetching the key: {_safe_errors(response)}"
            )
        try:
            keys = response.json()["data"]["keys"]
        except (ValueError, KeyError, TypeError) as exc:
            raise VaultTransitError("Vault key response had no keys block") from exc
        entry = keys.get(version) if isinstance(keys, dict) else None
        public_key = entry.get("public_key") if isinstance(entry, dict) else None
        if not isinstance(public_key, str) or not public_key:
            raise VaultTransitError(
                f"Vault key version {version!r} exposes no public key; asymmetric "
                f"key types are required for signing"
            )
        return public_key

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> VaultTransitSigner:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


def _safe_errors(response: httpx.Response) -> str:
    """Vault's ``errors`` array, never the whole body.

    A response body can echo request fields; the errors array is the part Vault
    intends for humans.
    """

    try:
        errors = response.json().get("errors", [])
    except (ValueError, AttributeError):
        return "<unparseable response>"
    if not isinstance(errors, list):
        return "<malformed errors block>"
    return "; ".join(str(item) for item in errors[:5]) or "<no detail>"


def decode_vault_signature(signature: str) -> bytes:
    """Strip Vault's ``vault:vN:`` prefix and return the raw signature bytes."""

    parts = signature.split(":", 2)
    if len(parts) != 3 or parts[0] != "vault":
        raise VaultTransitError("signature is not in Vault's 'vault:vN:base64' form")
    try:
        return base64.b64decode(parts[2], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise VaultTransitError(f"Vault signature payload is not valid base64: {exc}") from exc


__all__ = [
    "VaultTransitConfig",
    "VaultTransitError",
    "VaultTransitSigner",
    "decode_vault_signature",
]

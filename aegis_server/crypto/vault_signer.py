# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""
aegis_server.crypto.vault_signer — HashiCorp Vault Transit Engine signing provider.

Delegates all private-key operations to the Vault Transit secrets engine.
The signing key never leaves Vault, satisfying enterprise requirements for
HSM-backed, auditable key management.

Architecture
------------
::

    Aegis proxy (sign_payload)
         │
         │  HTTPS + mTLS (optional)
         ▼
    HashiCorp Vault
    /v1/transit/sign/<key>
         │
         │  (key stays inside Vault / HSM)
         ▼
    Base64-encoded signature (Vault format: "vault:v1:<b64>")
         │
         ▼
    Decoded, hex-encoded signature returned to Aegis

Authentication
--------------
Vault authentication is resolved in priority order:

1. AppRole (``role_id`` + ``secret_id``) — recommended for production.
2. Static token (``vault_token``) — acceptable for short-lived deployments;
   rotate frequently.

The resolved Vault token is stored in memory and re-used across requests.
Token renewal is attempted automatically when the Vault API returns a 403.

Retry policy
------------
Transient HTTP 5xx, ``ConnectionError``, and ``TimeoutError`` faults trigger
exponential backoff with jitter:

    delay = base_delay * (2 ** attempt) + uniform(0, base_delay)

``max_retries`` attempts are made before raising ``RuntimeError``.

Algorithm
---------
The Vault key must be of type ``ed25519`` or ``ecdsa-p256`` (or any other
Transit-supported signing key).  By default Aegis requests ``sha2-256`` as the
hash algorithm.  For post-quantum signing, create a key of type
``ml-dsa-65`` (Vault 1.18+ with the FIPS plugin) and set
``AEGIS_VAULT_TRANSIT_KEY`` accordingly.

Dependencies:
    hvac>=2.1.0  (synchronous Vault client — run in executor for async usage)
    asyncio      (stdlib)
"""

from __future__ import annotations

import asyncio
import base64
import logging
import random
import time

import hvac
import hvac.exceptions

from aegis_server.crypto.base import SignerProvider

logger = logging.getLogger(__name__)

_VAULT_SIGN_PATH_TEMPLATE = "v1/{mount}/sign/{key}"
_HASH_ALGORITHM = "sha2-256"


class VaultSigner(SignerProvider):
    """
    Async signing provider backed by HashiCorp Vault Transit secrets engine.

    All ``hvac`` calls are synchronous; they are dispatched via
    ``asyncio.get_event_loop().run_in_executor`` to avoid blocking the
    event loop.

    Args:
        vault_url:        Vault server URL, e.g. ``"https://vault.corp.example.com"``.
        transit_key:      Name of the Transit secrets engine signing key.
        transit_mount:    Mount path for the Transit engine (default ``"transit"``).
        vault_token:      Static Vault token.  Mutually exclusive with AppRole.
        role_id:          AppRole RoleID.  Provide with ``secret_id``.
        secret_id:        AppRole SecretID.
        namespace:        Vault Enterprise namespace (empty = root).
        max_retries:      Maximum number of retry attempts on transient failures.
        retry_base_delay: Base delay in seconds for exponential backoff.
    """

    scheme: str = "vault-transit"

    def __init__(
        self,
        vault_url: str,
        transit_key: str,
        transit_mount: str = "transit",
        vault_token: str = "",
        role_id: str = "",
        secret_id: str = "",
        namespace: str = "",
        max_retries: int = 3,
        retry_base_delay: float = 0.25,
    ) -> None:
        if not vault_url:
            raise ValueError("VaultSigner requires a non-empty vault_url")
        if not transit_key:
            raise ValueError("VaultSigner requires a non-empty transit_key")
        if not vault_token and not (role_id and secret_id):
            raise ValueError("VaultSigner requires either vault_token or both role_id + secret_id")

        self._vault_url = vault_url
        self._transit_key = transit_key
        self._transit_mount = transit_mount
        self._vault_token = vault_token
        self._role_id = role_id
        self._secret_id = secret_id
        self._namespace = namespace
        self._max_retries = max_retries
        self._retry_base_delay = retry_base_delay

        # Resolved token cache (populated lazily or via AppRole login)
        self._resolved_token: str | None = vault_token or None
        self._client: hvac.Client | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def sign_payload(self, data: bytes) -> str:
        """
        Sign ``data`` via Vault Transit ``/sign/<key>`` and return hex.

        The method:
        1. Ensures a valid Vault client exists (lazy init + AppRole login).
        2. Encodes ``data`` as standard base64 (Vault requires it).
        3. Calls ``transit.sign_data`` with exponential retry/backoff.
        4. Parses the ``vault:v1:<b64>`` response format.
        5. Returns the raw signature bytes as a lowercase hex string.

        Args:
            data: Byte sequence to sign.

        Returns:
            Hex-encoded signature.

        Raises:
            RuntimeError: After exhausting all retry attempts.
        """
        loop = asyncio.get_event_loop()
        hex_sig: str = await loop.run_in_executor(None, self._sign_sync, data)
        return hex_sig

    # ------------------------------------------------------------------
    # Synchronous implementation (runs in thread executor)
    # ------------------------------------------------------------------

    def _sign_sync(self, data: bytes) -> str:
        """
        Blocking Vault sign call with retry/backoff.

        Called exclusively from ``sign_payload`` via the thread executor.
        """
        self._ensure_client()
        b64_input = base64.standard_b64encode(data).decode("ascii")

        last_exc: Exception | None = None
        for attempt in range(self._max_retries + 1):
            try:
                response = self._client.secrets.transit.sign_data(  # type: ignore[union-attr]
                    name=self._transit_key,
                    hash_input=b64_input,
                    hash_algorithm=_HASH_ALGORITHM,
                    prehashed=False,
                    mount_point=self._transit_mount,
                )
                vault_sig: str = response["data"]["signature"]
                return self._decode_vault_signature(vault_sig)

            except hvac.exceptions.Forbidden:
                # 403: token may have expired — attempt re-auth once
                logger.warning(
                    "Vault 403 Forbidden on sign attempt %d; attempting re-auth",
                    attempt + 1,
                )
                try:
                    self._do_approle_login()
                    continue  # retry immediately after re-auth
                except Exception as reauth_exc:
                    raise RuntimeError(
                        f"VaultSigner: Forbidden and re-auth failed: {reauth_exc}"
                    ) from reauth_exc

            except hvac.exceptions.VaultNotInitialized as exc:
                raise RuntimeError("VaultSigner: Vault is not initialised or is sealed") from exc

            except (
                hvac.exceptions.VaultError,
                ConnectionError,
                TimeoutError,
                OSError,
            ) as exc:
                last_exc = exc
                if attempt >= self._max_retries:
                    break
                delay = self._backoff_delay(attempt)
                logger.warning(
                    "VaultSigner: transient error on attempt %d/%d (%s); retrying in %.2fs",
                    attempt + 1,
                    self._max_retries,
                    type(exc).__name__,
                    delay,
                )
                time.sleep(delay)

        raise RuntimeError(
            f"VaultSigner.sign_payload failed after {self._max_retries + 1} attempts: {last_exc}"
        ) from last_exc

    # ------------------------------------------------------------------
    # Client management
    # ------------------------------------------------------------------

    def _ensure_client(self) -> None:
        """
        Initialise the hvac client and authenticate if not yet done.

        Thread-safe for the executor pattern because only one thread calls
        ``_sign_sync`` at a time per ``run_in_executor`` call.  If concurrent
        signing is needed, add a threading.Lock around client re-init.
        """
        if self._client is not None and self._client.is_authenticated():
            return

        client_kwargs: dict = {"url": self._vault_url}
        if self._namespace:
            client_kwargs["namespace"] = self._namespace

        self._client = hvac.Client(**client_kwargs)

        if self._role_id and self._secret_id:
            self._do_approle_login()
        elif self._resolved_token:
            self._client.token = self._resolved_token
        else:
            raise RuntimeError("VaultSigner: no authentication credentials available")

        if not self._client.is_authenticated():
            raise RuntimeError(
                "VaultSigner: Vault client failed to authenticate.  "
                "Check vault_url, token/AppRole credentials, and network access."
            )

        logger.info(
            "VaultSigner: authenticated to Vault at %s (mount=%s, key=%s)",
            self._vault_url,
            self._transit_mount,
            self._transit_key,
        )

    def _do_approle_login(self) -> None:
        """
        Perform AppRole authentication and store the resulting token.

        Raises:
            RuntimeError: If the AppRole login returns an unexpected response.
        """
        if self._client is None:
            raise RuntimeError("VaultSigner: client not initialised before AppRole login")

        try:
            login_response = self._client.auth.approle.login(
                role_id=self._role_id,
                secret_id=self._secret_id,
            )
        except hvac.exceptions.VaultError as exc:
            raise RuntimeError(f"VaultSigner: AppRole login failed: {exc}") from exc

        token: str | None = login_response.get("auth", {}).get("client_token")
        if not token:
            raise RuntimeError(
                "VaultSigner: AppRole login response missing client_token; "
                f"response keys: {list(login_response.get('auth', {}).keys())}"
            )
        self._resolved_token = token
        self._client.token = token
        logger.debug("VaultSigner: AppRole login succeeded; token acquired")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _backoff_delay(self, attempt: int) -> float:
        """
        Compute exponential backoff with uniform jitter.

        Formula: ``base * 2^attempt + uniform(0, base)``

        Args:
            attempt: Zero-based attempt index.

        Returns:
            Sleep duration in seconds.
        """
        return self._retry_base_delay * (2**attempt) + random.uniform(0, self._retry_base_delay)

    @staticmethod
    def _decode_vault_signature(vault_sig: str) -> str:
        """
        Decode a Vault Transit signature string to a lowercase hex string.

        Vault Transit returns signatures in the format::

            vault:v<version>:<base64url-encoded-bytes>

        Example::

            vault:v1:MEUCIQDz...

        Args:
            vault_sig: Raw Vault signature string.

        Returns:
            Lowercase hex string of the raw signature bytes.

        Raises:
            ValueError: If the signature format is unexpected.
        """
        parts = vault_sig.split(":")
        if len(parts) != 3 or parts[0] != "vault":
            raise ValueError(
                f"VaultSigner: unexpected signature format {vault_sig[:40]!r}; "
                "expected 'vault:v<N>:<base64>'"
            )
        try:
            # Vault uses standard base64 (padded); some keys use URL-safe base64.
            # Try standard first, fall back to url-safe.
            try:
                raw_bytes = base64.standard_b64decode(parts[2])
            except Exception:
                raw_bytes = base64.urlsafe_b64decode(parts[2] + "==")
        except Exception as exc:
            raise ValueError(f"VaultSigner: base64 decode failed for signature: {exc}") from exc

        return raw_bytes.hex()

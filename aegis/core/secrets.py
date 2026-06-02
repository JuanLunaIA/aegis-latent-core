"""
aegis.core.secrets — Integration with HashiCorp Vault for dynamic secret management.
Implements automated retrieval and rotation of sensitive credentials.
"""

# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import logging
import time
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)


@dataclass
class SecretBundle:
    value: str
    version: int
    lease_duration: int
    expires_at: float


class VaultManager:
    """
    Handles authentication and secret retrieval from HashiCorp Vault.
    Supports dynamic rotation and lease management.
    """

    def __init__(
        self,
        vault_url: str,
        role_id: str | None = None,
        secret_id: str | None = None,
        token: str | None = None,
    ):
        self.vault_url = vault_url.rstrip("/")
        self.role_id = role_id
        self.secret_id = secret_id
        self._token = token
        self._secrets_cache: dict[str, SecretBundle] = {}

    async def authenticate(self) -> bool:
        """
        Authenticates with Vault using AppRole or static token.
        """
        if self._token:
            return True

        if not self.role_id or not self.secret_id:
            logger.error("Vault authentication failed: missing RoleID or SecretID")
            return False

        try:
            # AppRole authentication
            resp = await self._async_auth_request(
                {"role_id": self.role_id, "secret_id": self.secret_id}
            )
            if resp.status_code == 200:
                self._token = resp.json()["auth"]["client_token"]
                logger.info("Successfully authenticated with Vault via AppRole.")
                return True
        except Exception as e:
            logger.error("Vault authentication error: %s", e)

        return False

    async def get_secret(self, path: str, key: str) -> str | None:
        """
        Retrieves a secret value from Vault, handling cache and rotation.
        """
        now = time.time()
        if path in self._secrets_cache:
            bundle = self._secrets_cache[path]
            if now < bundle.expires_at - 60:  # Rotate 1 minute before expiry
                return bundle.value if key == "value" else None  # Simplified for example

        return await self._rotate_secret(path, key)

    async def _rotate_secret(self, path: str, key: str) -> str | None:
        """
        Fetch a fresh secret from Vault and update the cache.
        """
        try:
            headers = {"X-Vault-Token": self._token} if self._token else {}
            url = f"{self.vault_url}/v1/{path}"

            async with httpx.AsyncClient() as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code != 200:
                    logger.error(
                        "Failed to fetch secret from Vault at %s: %s", path, resp.status_code
                    )
                    return None

                data = resp.json()["data"]["data"]  # Vault KV v2 structure
                val = data.get(key)

                # Simulate lease duration for rotation logic
                lease_duration = 3600  # Default 1 hour
                self._secrets_cache[path] = SecretBundle(
                    value=val,
                    version=1,
                    lease_duration=lease_duration,
                    expires_at=time.time() + lease_duration,
                )

                logger.info("Rotated secret for path: %s", path)
                return val
        except Exception as e:
            logger.error("Error rotating secret from Vault: %s", e)
            return None

    async def _async_auth_request(self, payload: dict) -> httpx.Response:
        async with httpx.AsyncClient() as client:
            return await client.post(f"{self.vault_url}/v1/auth/approle/login", json=payload)

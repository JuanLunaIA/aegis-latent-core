# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""
aegis_server.crypto — Pluggable async signing provider layer.

Public API::

    from aegis_server.crypto import SignerProvider, get_signer

    signer = get_signer(settings)
    hex_sig = await signer.sign_payload(data)
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from aegis_server.crypto.base import LocalHMACSigner, SignerProvider

if TYPE_CHECKING:
    from aegis_server.config import EnterpriseSettings
    from aegis_server.crypto.vault_signer import VaultSigner

__all__ = [
    "SignerProvider",
    "LocalHMACSigner",
    "VaultSigner",
    "get_signer",
]


def __getattr__(name: str) -> Any:
    """
    Lazy attribute access for optional, heavy-dependency signers.

    ``VaultSigner`` pulls in ``hvac`` (HashiCorp Vault client), which is an
    optional extra (``aegis-latent-core[vault]``). Importing it eagerly at
    package level would make the entire ``aegis_server.crypto`` package — and
    therefore the HMAC-only compliance path — fail to import when ``hvac`` is
    not installed. Resolving it on first access keeps the LocalHMACSigner path
    dependency-free. X→Y because Z: a module-level ``import`` runs at package
    init; ``__getattr__`` defers the import until the symbol is actually used.
    """
    if name == "VaultSigner":
        from aegis_server.crypto.vault_signer import VaultSigner

        return VaultSigner
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def get_signer(settings: EnterpriseSettings) -> SignerProvider:
    """
    Factory: return the configured ``SignerProvider``.

    Priority:
        1. ``signer_provider=vault`` → ``VaultSigner`` (AppRole or token auth).
        2. ``signer_provider=hmac``  → ``LocalHMACSigner``.

    Args:
        settings: Validated ``EnterpriseSettings`` instance.

    Returns:
        Ready-to-use ``SignerProvider``.  No ``initialize()`` call required;
        Vault client authentication is lazy (first ``sign_payload`` call).

    Raises:
        ValueError: For unknown ``signer_provider`` values or missing creds.
    """
    backend = settings.signer_provider.lower()

    if backend == "vault":
        from aegis_server.crypto.vault_signer import VaultSigner

        return VaultSigner(
            vault_url=settings.vault_url,
            transit_key=settings.vault_transit_key,
            transit_mount=settings.vault_transit_mount,
            vault_token=settings.vault_token.get_secret_value(),
            role_id=settings.vault_role_id,
            secret_id=settings.vault_secret_id.get_secret_value(),
            namespace=settings.vault_namespace,
            max_retries=settings.vault_max_retries,
            retry_base_delay=settings.vault_retry_base_delay_s,
        )

    if backend == "hmac":
        key = settings.hmac_signing_key.get_secret_value()
        if not key:
            raise ValueError(
                "AEGIS_HMAC_SIGNING_KEY is required when "
                "AEGIS_SIGNER_PROVIDER=hmac.  "
                "Generate one with: python -c "
                '"from aegis_server.crypto import LocalHMACSigner; '
                'print(LocalHMACSigner.generate_key())"'
            )
        return LocalHMACSigner(signing_key=key)

    raise ValueError(f"Unknown signer_provider={backend!r}. Valid values: 'hmac', 'vault'.")

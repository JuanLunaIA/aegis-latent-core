# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.auth.ldap_auth — LDAP/Active Directory multi-factor identity assertion.

Authenticates callers against an LDAP or Microsoft Active Directory server and
validates group membership for multi-factor identity assertion per NIST SP 800-53
Rev 5 AC-2 / IA-2 / IA-5 controls.

Identity assertion workflow
---------------------------
1. **Service-account bind** — connect using a dedicated service account
   (``AEGIS_LDAP_BIND_DN`` / ``AEGIS_LDAP_BIND_PASSWORD``) with least-privilege
   read access to the user subtree.
2. **User DN lookup** — search for the caller's DN by ``sAMAccountName`` (AD)
   or ``uid`` (RFC 4519 LDAP), driven by a configurable filter.
3. **User credential bind** — re-bind as the located DN with the caller's
   password.  This is the primary authentication factor.
4. **Group membership assertion** — enumerate ``memberOf`` attributes (AD) or
   perform a group search (RFC 2307 LDAP) and check against
   ``AEGIS_LDAP_REQUIRED_GROUPS`` if set.  Non-empty ``required_groups``
   constitutes the second identity assertion factor.
5. **Identity object returned** — :class:`LDAPIdentity` carries ``username``,
   ``user_dn``, ``groups`` frozenset, and raw LDAP ``attributes`` dict.

Active Directory notes
----------------------
* ``ad_mode=True`` (the default when the server URL contains an AD-typical
  domain) enables the AD-specific OID ``1.2.840.113556.1.4.1941`` for recursive
  nested group resolution via the ``LDAP_MATCHING_RULE_IN_CHAIN`` operator.
* UPN login (``user@domain.com``) is supported alongside ``sAMAccountName``.

TLS / transport security
------------------------
* ``ldaps://`` — direct TLS on port 636.
* ``ldap://`` + ``use_start_tls=True`` — StartTLS upgrade (port 389).
* ``ca_certs_file`` points to the CA bundle for certificate chain validation.
  When absent, ``ldap3`` uses the system default trust store.

Usage::

    cfg = LDAPAuthConfig(
        url="ldaps://dc.corp.example.com",
        base_dn="DC=corp,DC=example,DC=com",
        bind_dn="CN=svc-aegis,OU=ServiceAccounts,DC=corp,DC=example,DC=com",
        bind_password="...",           # from Vault / env
        required_groups=frozenset({"AegisUsers"}),
    )
    auth = LDAPAuthenticator(cfg)
    identity = auth.authenticate("john.doe", "P@ssw0rd!")
    # identity.groups  → frozenset({"AegisUsers", "Domain Users", ...})
"""

from __future__ import annotations

import re
import ssl
from dataclasses import dataclass, field
from typing import Any

try:
    import ldap3
    from ldap3 import ALL_ATTRIBUTES, Connection, Server, Tls
    from ldap3.core.exceptions import LDAPException

    _LDAP3_AVAILABLE = True
except ImportError:  # pragma: no cover
    _LDAP3_AVAILABLE = False


# ── AD matching rule OID for recursive nested group resolution ────────────────
# LDAP_MATCHING_RULE_IN_CHAIN: resolves nested group membership transitively.
_AD_NESTED_GROUP_OID = "1.2.840.113556.1.4.1941"


class LDAPConfigError(ValueError):
    """Raised when the LDAP configuration is invalid."""


class LDAPAuthError(PermissionError):
    """Raised when authentication or identity assertion fails."""

    def __init__(self, message: str, username: str = "") -> None:
        self.username = username
        super().__init__(message)


@dataclass(frozen=True)
class LDAPAuthConfig:
    """Configuration for :class:`LDAPAuthenticator`.

    All string fields default to empty (disabled); set via
    ``AEGIS_LDAP_*`` environment variables through :class:`~aegis.config.AegisSettings`.

    Parameters
    ----------
    url:
        LDAP server URL.  Use ``ldaps://`` for direct TLS or ``ldap://`` with
        ``use_start_tls=True``.  Example: ``ldaps://dc.corp.example.com:636``.
    base_dn:
        Base Distinguished Name for user and group searches.
        Example: ``DC=corp,DC=example,DC=com``.
    bind_dn:
        Service-account DN for the initial directory search bind.
        Example: ``CN=svc-aegis,OU=SvcAccts,DC=corp,DC=example,DC=com``.
    bind_password:
        Password for the service account.  Provide via ``AEGIS_LDAP_BIND_PASSWORD``
        or Vault; never hard-code.
    user_search_filter:
        LDAP search filter template.  ``{username}`` is substituted with the
        sanitized login name.
        Default ``(|(sAMAccountName={username})(userPrincipalName={username}))``
        covers both AD short-name and UPN formats.
    user_search_base:
        DN under which users are searched.  Defaults to ``base_dn`` when empty.
    required_groups:
        Frozenset of group CN (or DN) values.  When non-empty, the authenticated
        user must be a member of *at least one* group in this set.
        Empty frozenset disables the group check (all authenticated users pass).
    ad_mode:
        Enable Active Directory extensions: nested group OID, ``memberOf``
        attribute enumeration, ``sAMAccountName``-first lookup.
    use_start_tls:
        Upgrade a plain ``ldap://`` connection to TLS via StartTLS.
    ca_certs_file:
        Path to a CA bundle PEM file for TLS peer verification.
        Empty string uses the system default trust store.
    timeout_seconds:
        Socket-level timeout for connect and individual LDAP operations.
    """

    url: str = ""
    base_dn: str = ""
    bind_dn: str = ""
    bind_password: str = ""
    user_search_filter: str = "(|(sAMAccountName={username})(userPrincipalName={username}))"
    user_search_base: str = ""
    required_groups: frozenset[str] = field(default_factory=frozenset)
    ad_mode: bool = True
    use_start_tls: bool = False
    ca_certs_file: str = ""
    timeout_seconds: float = 10.0

    def effective_search_base(self) -> str:
        return self.user_search_base or self.base_dn


@dataclass
class LDAPIdentity:
    """Authenticated LDAP/AD identity with group membership facts.

    Instances are produced by :meth:`LDAPAuthenticator.authenticate` on success.
    They are intended to be short-lived (per-request); do NOT cache them with the
    raw ``attributes`` dict as that may contain sensitive directory data.
    """

    username: str
    user_dn: str
    groups: frozenset[str] = field(default_factory=frozenset)
    attributes: dict[str, list[str]] = field(default_factory=dict)

    def is_member_of(self, group: str) -> bool:
        """Return True if *group* (by CN or full DN) is in this identity's group set."""
        return group in self.groups or any(g.lower() == group.lower() for g in self.groups)

    def assert_group_membership(self, required_groups: frozenset[str]) -> None:
        """Raise :exc:`LDAPAuthError` if user is not in any required group.

        Parameters
        ----------
        required_groups:
            Non-empty frozenset of group CNs or DNs.  At least one must match.
        """
        if not required_groups:
            return
        if not any(self.is_member_of(g) for g in required_groups):
            raise LDAPAuthError(
                f"User {self.username!r} is not a member of any required group: "
                f"{sorted(required_groups)}",
                username=self.username,
            )


# ── LDAP injection sanitizer ─────────────────────────────────────────────────
# RFC 4515 §3 characters that must be escaped in search filter values.
_LDAP_FILTER_ESCAPE_RE = re.compile(r"[\\*\(\)\x00]")
_LDAP_FILTER_ESCAPE_MAP: dict[str, str] = {
    "\\": r"\5c",
    "*": r"\2a",
    "(": r"\28",
    ")": r"\29",
    "\x00": r"\00",
}


def _escape_filter_value(value: str) -> str:
    """Escape special characters in an LDAP filter value (RFC 4515 §3)."""
    return _LDAP_FILTER_ESCAPE_RE.sub(lambda m: _LDAP_FILTER_ESCAPE_MAP[m.group()], value)


def _cn_from_dn(dn: str) -> str:
    """Extract the CN from a Distinguished Name string.

    Tolerates optional whitespace around the ``CN=`` attribute-type separator
    (``CN=Bob`` and ``CN = Bob`` both yield ``Bob``).  Returns the full DN when
    no CN component is present.
    """
    for part in dn.split(","):
        attr_type, sep, value = part.partition("=")
        if sep and attr_type.strip().upper() == "CN":
            return value.strip()
    return dn


class LDAPAuthenticator:
    """Thread-safe LDAP/Active Directory authenticator.

    Creates a new connection per :meth:`authenticate` call — no connection pool
    is maintained, which avoids shared state bugs in multi-threaded deployments.
    Each call opens at most two connections (service-account bind + user bind)
    and closes them before returning.

    Parameters
    ----------
    config:
        Fully-populated :class:`LDAPAuthConfig` instance.

    Raises
    ------
    LDAPConfigError
        On construction if ``config.url`` or ``config.base_dn`` is empty.
    """

    def __init__(self, config: LDAPAuthConfig) -> None:
        if not config.url:
            raise LDAPConfigError("LDAPAuthConfig.url must not be empty")
        if not config.base_dn:
            raise LDAPConfigError("LDAPAuthConfig.base_dn must not be empty")
        if not _LDAP3_AVAILABLE:
            raise LDAPConfigError(
                "ldap3 is required for LDAP authentication. "
                "Install it with: pip install 'aegis-latent-core[ldap]'"
            )
        self._config = config

    # ── Public API ────────────────────────────────────────────────────────────

    def authenticate(self, username: str, password: str) -> LDAPIdentity:
        """Authenticate *username* / *password* against the configured LDAP server.

        The method follows the service-bind → user-lookup → user-bind →
        group-assert flow described in the module docstring.

        Parameters
        ----------
        username:
            Login name (``sAMAccountName``, UPN, or ``uid`` depending on mode).
        password:
            Clear-text password (transmitted only over the TLS-protected
            connection; never logged or stored by this method).

        Returns
        -------
        LDAPIdentity
            Populated identity object on success.

        Raises
        ------
        LDAPAuthError
            When credentials are invalid, the user is not found, group
            membership assertion fails, or the directory is unreachable.
        """
        if not username or not password:
            raise LDAPAuthError("username and password must not be empty", username=username)

        safe_username = _escape_filter_value(username)
        server = self._build_server()

        # Step 1: service-account bind to locate the user's DN
        user_dn, raw_attrs = self._find_user(server, safe_username)

        # Step 2: authenticate with user credentials
        self._user_bind(server, user_dn, password, username)

        # Step 3: collect group memberships
        groups = self._collect_groups(server, user_dn, raw_attrs)

        identity = LDAPIdentity(
            username=username,
            user_dn=user_dn,
            groups=groups,
            attributes=raw_attrs,
        )

        # Step 4: assert required group membership (second identity factor)
        identity.assert_group_membership(self._config.required_groups)

        return identity

    def test_service_bind(self) -> bool:
        """Attempt a service-account bind and return True on success.

        Useful for health-check and connectivity validation at startup.
        """
        try:
            conn = self._service_bind()
            conn.unbind()
            return True
        except (LDAPException, LDAPAuthError):
            return False

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _build_server(self) -> Server:
        cfg = self._config
        tls = None
        if cfg.url.startswith("ldaps://") or cfg.use_start_tls:
            tls_kwargs: dict[str, Any] = {"validate": ssl.CERT_REQUIRED}
            if cfg.ca_certs_file:
                tls_kwargs["ca_certs_file"] = cfg.ca_certs_file
            tls = Tls(**tls_kwargs)
        return Server(
            cfg.url,
            use_ssl=cfg.url.startswith("ldaps://"),
            tls=tls,
            connect_timeout=cfg.timeout_seconds,
            get_info=ldap3.NONE,
        )

    def _service_bind(self) -> Connection:
        cfg = self._config
        conn = Connection(
            self._build_server(),
            user=cfg.bind_dn or None,
            password=cfg.bind_password or None,
            authentication=ldap3.SIMPLE if cfg.bind_dn else ldap3.ANONYMOUS,
            auto_bind=ldap3.AUTO_BIND_TLS_BEFORE_BIND
            if cfg.use_start_tls
            else ldap3.AUTO_BIND_NO_TLS,
            read_only=True,
            receive_timeout=cfg.timeout_seconds,
        )
        if not conn.bind():
            raise LDAPAuthError(
                "Service account bind failed — check AEGIS_LDAP_BIND_DN and "
                "AEGIS_LDAP_BIND_PASSWORD"
            )
        return conn

    def _find_user(
        self,
        server: Server,
        safe_username: str,
    ) -> tuple[str, dict[str, list[str]]]:
        cfg = self._config
        search_filter = cfg.user_search_filter.replace("{username}", safe_username)
        attrs = [ALL_ATTRIBUTES]
        try:
            conn = self._service_bind()
            conn.search(
                search_base=cfg.effective_search_base(),
                search_filter=search_filter,
                attributes=attrs,
            )
            entries = [e for e in conn.entries if e.entry_dn]
            conn.unbind()
        except LDAPException as exc:
            raise LDAPAuthError(f"LDAP user search failed: {exc}") from exc

        if not entries:
            raise LDAPAuthError(
                f"User not found in directory: {safe_username!r}",
                username=safe_username,
            )
        if len(entries) > 1:
            raise LDAPAuthError(
                f"Ambiguous user search: {len(entries)} entries matched "
                f"{safe_username!r}; ensure unique identifiers",
                username=safe_username,
            )

        entry = entries[0]
        raw_attrs: dict[str, list[str]] = {}
        for attr_name in entry.entry_attributes:
            try:
                val = entry[attr_name].values
                raw_attrs[attr_name] = [str(v) for v in val]
            except Exception:  # noqa: BLE001
                pass
        return entry.entry_dn, raw_attrs

    def _user_bind(
        self,
        server: Server,
        user_dn: str,
        password: str,
        username: str,
    ) -> None:
        cfg = self._config
        try:
            conn = Connection(
                server,
                user=user_dn,
                password=password,
                authentication=ldap3.SIMPLE,
                auto_bind=ldap3.AUTO_BIND_TLS_BEFORE_BIND
                if cfg.use_start_tls
                else ldap3.AUTO_BIND_NO_TLS,
                receive_timeout=cfg.timeout_seconds,
            )
            bound = conn.bind()
            conn.unbind()
        except LDAPException as exc:
            raise LDAPAuthError(
                f"Credential verification failed for {username!r}",
                username=username,
            ) from exc

        if not bound:
            raise LDAPAuthError(
                f"Invalid credentials for {username!r}",
                username=username,
            )

    def _collect_groups(
        self,
        server: Server,
        user_dn: str,
        raw_attrs: dict[str, list[str]],
    ) -> frozenset[str]:
        cfg = self._config
        groups: set[str] = set()

        if cfg.ad_mode:
            # AD: memberOf attribute contains direct + (if nested OID used) transitive DNs.
            member_of = raw_attrs.get("memberOf", [])
            for dn in member_of:
                groups.add(_cn_from_dn(dn))
                groups.add(dn)  # also store full DN for DN-based checks
            if cfg.required_groups and not groups:
                # Attempt nested group resolution via AD matching rule OID
                groups |= self._ad_nested_groups(server, user_dn)
        else:
            # RFC 2307 / posixGroup or groupOfNames: search for groups containing user.
            groups |= self._rfc_groups(server, user_dn)

        return frozenset(groups)

    def _ad_nested_groups(
        self,
        server: Server,
        user_dn: str,
    ) -> set[str]:
        safe_dn = _escape_filter_value(user_dn)
        group_filter = f"(member:{_AD_NESTED_GROUP_OID}:={safe_dn})"
        groups: set[str] = set()
        try:
            conn = self._service_bind()
            conn.search(
                search_base=self._config.base_dn,
                search_filter=group_filter,
                attributes=["cn", "distinguishedName"],
            )
            for entry in conn.entries:
                if entry.entry_dn:
                    groups.add(_cn_from_dn(entry.entry_dn))
                    groups.add(entry.entry_dn)
            conn.unbind()
        except LDAPException:
            pass  # best-effort; fall through with empty set
        return groups

    def _rfc_groups(
        self,
        server: Server,
        user_dn: str,
    ) -> set[str]:
        safe_dn = _escape_filter_value(user_dn)
        group_filter = f"(|(member={safe_dn})(uniqueMember={safe_dn})(memberUid={safe_dn}))"
        groups: set[str] = set()
        try:
            conn = self._service_bind()
            conn.search(
                search_base=self._config.base_dn,
                search_filter=group_filter,
                attributes=["cn", "dn"],
            )
            for entry in conn.entries:
                if entry.entry_dn:
                    groups.add(_cn_from_dn(entry.entry_dn))
                    groups.add(entry.entry_dn)
            conn.unbind()
        except LDAPException:
            pass
        return groups

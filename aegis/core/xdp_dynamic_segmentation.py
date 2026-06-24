# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.xdp_dynamic_segmentation — Dynamic network micro-segmentation.

Translates high-level security alerts into real kernel-enforced firewall rules.

Enforcement hierarchy (first available backend wins):

1. **nftables** (``nft``) — preferred; manages a dedicated ``inet aegis`` table
   with a named set ``aegis_blocklist`` and an ingress ``DROP`` rule.
2. **iptables** — fallback; inserts ``INPUT -s <ip> -j DROP`` rules.
3. **Application-layer only** — last resort when neither firewall tool is
   available (e.g. unprivileged containers); logs a clear advisory so
   operators are never misled into thinking kernel enforcement is active.

The ``_blacklisted_ips`` set tracks in-process state for inspection and for
cleanup on ``teardown()``.  All zone-shift ``BLACKHOLE`` transitions also
push real firewall rules.

Note: ``XDP`` (eXpress Data Path) kernel programs require a loaded eBPF object
and a network driver with XDP support; that path is not yet wired.  This module
uses nftables/iptables as the practical kernel enforcement backend.  The class
is renamed in a future release once the eBPF path is live.
"""

from __future__ import annotations

import ipaddress
import logging
import shutil
import subprocess  # noqa: S404
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Nftables table / set names managed by this module
_NFT_TABLE = "inet aegis"
_NFT_SET = "aegis_blocklist"
_NFT_CHAIN = "aegis_input"


def _validate_ip(ip: str) -> str:
    """Return *ip* if it's a valid IPv4/IPv6 address, raise ValueError otherwise."""
    ipaddress.ip_address(ip)  # raises ValueError on bad input
    return ip


class _FirewallBackend:
    """Detects the available firewall backend and issues real block/unblock ops."""

    NONE = "none"
    NFTABLES = "nftables"
    IPTABLES = "iptables"

    def __init__(self) -> None:
        self._nft = shutil.which("nft")
        self._ipt = shutil.which("iptables")
        self._backend = self._detect_backend()
        if self._backend == self.NFTABLES:
            self._ensure_nft_table()
        logger.info("Firewall backend: %s", self._backend)

    def _detect_backend(self) -> str:
        if self._nft:
            try:
                subprocess.run(  # noqa: S603
                    [self._nft, "list", "tables"],
                    capture_output=True,
                    check=True,
                    timeout=5,
                )
                return self.NFTABLES
            except Exception as exc:  # noqa: BLE001
                logger.debug("nft probe failed: %s", exc)
        if self._ipt:
            try:
                subprocess.run(  # noqa: S603
                    [self._ipt, "-L", "INPUT", "-n"],
                    capture_output=True,
                    check=True,
                    timeout=5,
                )
                return self.IPTABLES
            except Exception as exc:  # noqa: BLE001
                logger.debug("iptables probe failed: %s", exc)
        logger.warning(
            "No kernel firewall backend available (nft=%s, iptables=%s). "
            "Block operations are APPLICATION-LAYER ONLY — no packets are dropped "
            "at the kernel level. Deploy with root and nftables/iptables for real enforcement.",
            bool(self._nft),
            bool(self._ipt),
        )
        return self.NONE

    def _run(self, cmd: list[str]) -> bool:
        try:
            subprocess.run(  # noqa: S603
                cmd,
                capture_output=True,
                check=True,
                timeout=5,
            )
            return True
        except Exception as exc:
            logger.error("Firewall command failed %s: %s", cmd, exc)
            return False

    def _ensure_nft_table(self) -> None:
        """Create the aegis nftables table, chain, set, and DROP rule if absent."""
        assert self._nft is not None
        cmds = [
            # Idempotent: 'add' is a no-op if the object already exists
            [self._nft, "add", "table", "inet", "aegis"],
            [
                self._nft,
                "add",
                "set",
                "inet",
                "aegis",
                _NFT_SET,
                "{",
                "type",
                "ipv4_addr,",
                "flags",
                "interval;",
                "}",
            ],
            [
                self._nft,
                "add",
                "chain",
                "inet",
                "aegis",
                _NFT_CHAIN,
                "{",
                "type",
                "filter",
                "hook",
                "input",
                "priority",
                "0;",
                "policy",
                "accept;",
                "}",
            ],
            [
                self._nft,
                "add",
                "rule",
                "inet",
                "aegis",
                _NFT_CHAIN,
                "ip",
                "saddr",
                f"@{_NFT_SET}",
                "drop",
            ],
        ]
        for cmd in cmds:
            self._run(cmd)

    def block(self, ip: str) -> bool:
        """Add *ip* to the kernel blocklist. Returns True on success."""
        if self._backend == self.NFTABLES:
            assert self._nft is not None
            return self._run([self._nft, "add", "element", "inet", "aegis", _NFT_SET, "{", ip, "}"])
        if self._backend == self.IPTABLES:
            assert self._ipt is not None
            return self._run([self._ipt, "-I", "INPUT", "-s", ip, "-j", "DROP"])
        logger.warning(
            "APPLICATION-LAYER ONLY: %s added to in-process blocklist (no kernel drop).", ip
        )
        return False

    def unblock(self, ip: str) -> bool:
        """Remove *ip* from the kernel blocklist. Returns True on success."""
        if self._backend == self.NFTABLES:
            assert self._nft is not None
            return self._run(
                [self._nft, "delete", "element", "inet", "aegis", _NFT_SET, "{", ip, "}"]
            )
        if self._backend == self.IPTABLES:
            assert self._ipt is not None
            return self._run([self._ipt, "-D", "INPUT", "-s", ip, "-j", "DROP"])
        return False

    def teardown(self) -> None:
        """Remove the entire aegis nftables table (cleanup on shutdown)."""
        if self._backend == self.NFTABLES and self._nft:
            self._run([self._nft, "delete", "table", "inet", "aegis"])

    @property
    def backend_name(self) -> str:
        return self._backend


@dataclass
class NetworkZone:
    zone_id: str
    allowed_ips: set[str]
    priority: int
    status: str  # 'ACTIVE' | 'RESTRICTED' | 'BLACKHOLE'


class XDPDynamicSegmenter:
    """Orchestrates dynamic network micro-segmentation via real firewall rules.

    Translates high-level security alerts into nftables or iptables ``DROP``
    rules.  When neither is available (unprivileged container), falls back to
    application-layer blocking with a prominent advisory log.
    """

    def __init__(self) -> None:
        self._zones: dict[str, NetworkZone] = {}
        self._blacklisted_ips: set[str] = set()
        self._fw = _FirewallBackend()
        logger.info(
            "XDPDynamicSegmenter initialised (kernel backend: %s).",
            self._fw.backend_name,
        )

    @property
    def backend(self) -> str:
        """Name of the active firewall backend."""
        return self._fw.backend_name

    def define_zone(self, zone_id: str, ips: list[str], priority: int = 10) -> None:
        """Define a network zone with a specific trust level."""
        validated = [_validate_ip(ip) for ip in ips]
        self._zones[zone_id] = NetworkZone(
            zone_id=zone_id,
            allowed_ips=set(validated),
            priority=priority,
            status="ACTIVE",
        )
        logger.info("Zone %s defined with %d allowed IPs.", zone_id, len(validated))

    def shift_zone_status(self, zone_id: str, new_status: str) -> None:
        """Shift zone status and apply real firewall rules immediately."""
        if zone_id not in self._zones:
            logger.error("Zone %s not found. Cannot shift status.", zone_id)
            return
        zone = self._zones[zone_id]
        logger.info("SHIFTING ZONE %s: %s -> %s", zone_id, zone.status, new_status)
        zone.status = new_status

        if new_status == "BLACKHOLE":
            for ip in zone.allowed_ips:
                self._block_one(ip)
        elif new_status == "RESTRICTED":
            # Rate-limiting requires iptables hashlimit / nftables meter — not yet
            # wired.  Log an advisory until implemented.
            logger.warning(
                "RESTRICTED status for zone %s: rate-limiting is not yet enforced "
                "at the kernel level (%d IPs). Implement nftables meter or "
                "iptables hashlimit for per-IP throttling.",
                zone_id,
                len(zone.allowed_ips),
            )
        elif new_status == "ACTIVE":
            for ip in zone.allowed_ips:
                if ip in self._blacklisted_ips:
                    self._unblock_one(ip)

    def block_ip_immediately(self, ip: str) -> bool:
        """Block *ip* via the kernel firewall. Returns True if kernel rule was installed.

        Used by the entropy analyser when a polyglot or adversarial pattern is detected.
        Always logs the outcome so operators can verify kernel enforcement.
        """
        try:
            _validate_ip(ip)
        except ValueError:
            logger.error("block_ip_immediately: invalid IP address %r — skipped.", ip)
            return False
        return self._block_one(ip)

    def unblock_ip(self, ip: str) -> bool:
        """Remove a previously installed block rule for *ip*."""
        try:
            _validate_ip(ip)
        except ValueError:
            logger.error("unblock_ip: invalid IP address %r — skipped.", ip)
            return False
        return self._unblock_one(ip)

    def _block_one(self, ip: str) -> bool:
        already = ip in self._blacklisted_ips
        self._blacklisted_ips.add(ip)
        if already:
            return True  # idempotent; rule already installed
        ok = self._fw.block(ip)
        if ok:
            logger.info("BLOCKED: %s — kernel %s rule installed.", ip, self._fw.backend_name)
        else:
            logger.warning("BLOCKED (application-layer only): %s — no kernel rule installed.", ip)
        return ok

    def _unblock_one(self, ip: str) -> bool:
        self._blacklisted_ips.discard(ip)
        ok = self._fw.unblock(ip)
        if ok:
            logger.info("UNBLOCKED: %s — kernel rule removed.", ip)
        return ok

    def get_current_segmentation(self) -> dict[str, str]:
        """Return the current status of all defined zones."""
        return {z_id: z.status for z_id, z in self._zones.items()}

    def get_blocked_ips(self) -> frozenset[str]:
        """Return the current in-process blocklist snapshot."""
        return frozenset(self._blacklisted_ips)

    def teardown(self) -> None:
        """Remove all aegis firewall rules and clear the blocklist."""
        self._fw.teardown()
        self._blacklisted_ips.clear()

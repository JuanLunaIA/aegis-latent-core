# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

"""Agentis engine — receipts for agent-to-agent tool execution.

Wraps :mod:`aegis.core.a2a` so a multi-agent framework can issue and check
receipts without running the gateway:

    engine = AgentisEngine(wal_path="/var/lib/aegis/agents.jsonl")
    receipt = engine.issue_tool_receipt(
        caller_agent_id="planner", target_agent_id="search",
        tool_name="web.search", input_bytes=b"...", output_bytes=b"...")
    engine.verify_agent_receipt(receipt, trusted_root)

What a valid receipt establishes
--------------------------------

Exactly one thing: the canonical envelope is included, at the stated leaf
index, under the root the verifier supplied. Everything below is outside it and
must not be claimed on a receipt's strength:

- **Not that the tool ran.** The ledger records what it was told. A receipt
  attests to a record, not to an execution.
- **Not identity or authority.** The agent identifiers are strings the issuer
  chose. Nothing here authenticates an agent or shows it was permitted to call.
- **Not time.** The timestamp is the issuer's unattested clock.
- **Not confidentiality of low-entropy arguments.** Arguments and results appear
  as SHA-256 digests. A digest is not a commitment scheme: an input drawn from a
  small or guessable domain can be recovered by enumeration.
- **Not trust in the root.** ``trusted_root`` must be obtained independently of
  whoever supplied the receipt. Verifying against a root taken from the same
  party proves internal consistency only.

Clock merging
-------------

:meth:`merge_agent_clocks` exposes the ``CausalMmr`` join from the native
extension when it is present. It is a **convergent accumulator, not a
deployment** (``CLM-066``): there is no gossip transport, no membership
protocol and no persistence, and ``join`` reconciles replicas that disagree
about *ordering*, not replicas that lie. It establishes nothing about
cross-replica ordering for any running system.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from aegis.core.a2a import AgentReceipt, generate_receipt, verify_receipt
from aegis.core.crypto_audit import CryptographicAuditLedger
from aegis.engines import require_module
from aegis.licensing.validator import LicenseEntitlement

_MODULE_NAME = "agentis"


class CausalMmrUnavailableError(RuntimeError):
    """The native ``aegis_rust`` extension exposing ``CausalMmr`` is not present."""


class AgentisEngine:
    """Agent-to-agent receipts, and the causal accumulator behind them."""

    def __init__(
        self,
        wal_path: str,
        *,
        signing_key: str = "",
        entitlement: LicenseEntitlement | None = None,
        **ledger_kwargs: Any,
    ) -> None:
        self._entitlement = require_module(_MODULE_NAME, entitlement=entitlement)
        self._ledger = CryptographicAuditLedger(wal_path, signing_key=signing_key, **ledger_kwargs)

    @property
    def ledger(self) -> CryptographicAuditLedger:
        return self._ledger

    @property
    def entitlement(self) -> LicenseEntitlement | None:
        return self._entitlement

    def issue_tool_receipt(
        self,
        *,
        caller_agent_id: str,
        target_agent_id: str,
        tool_name: str,
        input_bytes: bytes,
        output_bytes: bytes,
        execution_id: str | None = None,
        tenant_id: str = "a2a",
    ) -> AgentReceipt:
        """Commit the execution to the ledger and return its receipt."""

        return generate_receipt(
            self._ledger,
            caller_agent_id=caller_agent_id,
            target_agent_id=target_agent_id,
            tool_name=tool_name,
            input_bytes=input_bytes,
            output_bytes=output_bytes,
            execution_id=execution_id,
            tenant_id=tenant_id,
        )

    def verify_agent_receipt(
        self, receipt: AgentReceipt | Mapping[str, Any], trusted_root: str
    ) -> bool:
        """Verify a receipt against an independently obtained root."""

        return verify_receipt(receipt, trusted_root)  # type: ignore[arg-type]

    def current_root(self) -> str:
        root: str = self._ledger._mmr.get_root_hash()
        return root

    # ── causal accumulator ──────────────────────────────────────────────

    @staticmethod
    def causal_mmr_available() -> bool:
        """Whether the native ``CausalMmr`` binding can be imported."""

        try:
            import aegis_rust
        except ImportError:
            return False
        return getattr(aegis_rust, "CausalMmr", None) is not None

    @staticmethod
    def new_causal_accumulator(replica_id: int) -> Any:
        """Return a fresh ``CausalMmr`` for ``replica_id``.

        Raises rather than degrading to a Python stand-in: a silent fallback
        would produce roots that disagree with every other replica, which is
        worse than refusing.
        """

        try:
            import aegis_rust
        except ImportError as exc:
            raise CausalMmrUnavailableError(
                "the aegis_rust extension is not importable; build it with "
                "`maturin develop --manifest-path aegis_rust_v2/Cargo.toml "
                "--release --features extension-module`"
            ) from exc
        factory = getattr(aegis_rust, "CausalMmr", None)
        if factory is None:
            raise CausalMmrUnavailableError(
                "aegis_rust is installed but exposes no CausalMmr binding"
            )
        return factory(replica_id)

    @staticmethod
    def merge_agent_clocks(left: Any, right: Any) -> Any:
        """Join two accumulators, returning a new one; neither operand mutates.

        ``join`` is idempotent, commutative and associative, so replicas that
        exchange leaf sets converge on one root whatever order they merge in.
        Convergence is agreement about *ordering*, not about truth.
        """

        return left.join(right)


__all__ = ["AgentisEngine", "AgentReceipt", "CausalMmrUnavailableError"]

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.ot_protocol_scanner — SCADA/OT protocol command injection detection.

Scans LLM-generated text for embedded MODBUS, DNP3, and OPC-UA protocol
references that may constitute operational-technology (OT) command injection
attacks.  These patterns are unexpected in normal LLM responses and indicate
an attempt to smuggle field-device commands through the LLM output channel
into operator interfaces or downstream automation pipelines.

Threat model
------------
An attacker crafts prompts that cause the LLM to output:

* Modbus RTU/TCP frames or function code + register address patterns that
  an industrial HMI, SCADA historian, or API bridge blindly forwards to
  a PLC or RTU.
* DNP3 Control Relay Output Block (CROB) commands encoded as text (e.g.
  "Group 12 Variation 1, operate for 1000 ms") that an OT middleware
  parses and executes.
* OPC-UA NodeId write or method-call instructions that a downstream OPC-UA
  gateway interprets as legitimate operator commands.

Detection approach
------------------
Signature-based pattern matching on normalised text.  False-positive risk is
reduced by context scoring: each signal carries a weight (0–1) and the result
contains the raw signals list so the caller can apply custom thresholds.

Usage::

    from aegis.core.ot_protocol_scanner import OTProtocolScanner

    scanner = OTProtocolScanner()
    result = scanner.scan(llm_response_text)
    if result.risk_score >= 0.5:
        logger.warning("OT command injection risk: %s", result.signals)

Configuration
-------------
``AEGIS_OT_BLOCK_THRESHOLD``
    Float in [0, 1].  When ``result.risk_score >= threshold``,
    ``result.should_block`` is True.  Default ``0.5``.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from enum import StrEnum

logger = logging.getLogger(__name__)

# ── Signal definitions ────────────────────────────────────────────────────────


class OTProtocol(StrEnum):
    MODBUS = "modbus"
    DNP3 = "dnp3"
    OPCUA = "opcua"


@dataclass(frozen=True)
class _Signal:
    protocol: OTProtocol
    name: str
    weight: float  # contribution to risk_score [0, 1]
    pattern: re.Pattern[str]


def _re(pat: str, flags: int = re.IGNORECASE) -> re.Pattern[str]:
    return re.compile(pat, flags)


_SIGNALS: list[_Signal] = [
    # ── MODBUS ────────────────────────────────────────────────────────────────
    # Raw hex frame prefix (03 = Read Holding Registers, 06 = Write Single Reg, etc.)
    _Signal(
        OTProtocol.MODBUS,
        "modbus_hex_frame",
        0.9,
        _re(r"\\x01\\x0[0-9a-fA-F]|0x0[0-9a-fA-F]\s+0x[0-9a-fA-F]{2}"),
    ),
    # Modbus function code references (FC 03, Function Code 6, etc.)
    _Signal(
        OTProtocol.MODBUS,
        "modbus_function_code",
        0.7,
        _re(r"\b(?:function\s+code|FC)\s*(?:0[1-9]|1[0-6]|2[0-3]|6[5-9]|7[0-2])\b"),
    ),
    # Write-capable function codes by number (FC 05, 06, 15, 16, 22, 23)
    _Signal(
        OTProtocol.MODBUS,
        "modbus_write_function_code",
        0.85,
        _re(r"\b(?:FC|function\s+code)\s*(?:0?5|0?6|15|16|22|23)\b"),
    ),
    # PLC register address notation common in Modbus (40001-49999, %MW, HR)
    _Signal(
        OTProtocol.MODBUS,
        "modbus_register_address",
        0.6,
        _re(r"\b4[0-9]{4}\b|%MW\d+\b|\bHR\s*\d{1,5}\b|\bholding\s+register\s+\d+\b"),
    ),
    # Coil address notation (00001-09999, %M, coil address)
    _Signal(
        OTProtocol.MODBUS,
        "modbus_coil_address",
        0.55,
        _re(r"\b0[0-9]{4}\b|%M\d+\b|\bcoil\s+(?:address\s+)?\d{1,5}\b"),
    ),
    # Explicit Modbus command composition
    _Signal(
        OTProtocol.MODBUS,
        "modbus_command_composition",
        0.8,
        _re(
            r"\bmodbus\b.{0,60}(?:write|send|transmit|set)\b|\b(?:write|send|transmit|set)\b.{0,60}\bmodbus\b"
        ),
    ),
    # pymodbus / libmodbus API calls
    _Signal(
        OTProtocol.MODBUS,
        "modbus_api_call",
        0.75,
        _re(r"\bwrite_register\s*\(|\bwrite_coil\s*\(|\bwrite_registers\s*\(|\bclient\.write\b"),
    ),
    # ── DNP3 ──────────────────────────────────────────────────────────────────
    # DNP3 CROB — Control Relay Output Block (Group 12, Variation 1)
    _Signal(
        OTProtocol.DNP3,
        "dnp3_crob",
        0.9,
        _re(r"\b(?:group\s+12|crob|control\s+relay\s+output\s+block)\b"),
    ),
    # DNP3 group/variation object references (Group N Variation M)
    _Signal(
        OTProtocol.DNP3,
        "dnp3_group_variation",
        0.7,
        _re(r"\bgroup\s+\d{1,3}\s*,?\s*variation\s+\d{1,3}\b"),
    ),
    # DNP3 function code references
    _Signal(
        OTProtocol.DNP3,
        "dnp3_function_code",
        0.65,
        _re(
            r"\bdnp3?\b.{0,50}(?:function\s+code|FC)\s*\d{1,3}\b"
            r"|\b(?:direct\s+operate|select\s+before\s+operate|sbo)\b"
        ),
    ),
    # DNP3 master/outstation references with write/operate context
    _Signal(
        OTProtocol.DNP3,
        "dnp3_master_operate",
        0.8,
        _re(r"\b(?:dnp3?|outstation)\b.{0,80}(?:operate|write|send|execute)\b"),
    ),
    # DNP3 application layer control codes: PULSE_ON, LATCH_ON, LATCH_OFF
    _Signal(
        OTProtocol.DNP3,
        "dnp3_control_code",
        0.85,
        _re(r"\b(?:pulse_on|pulse_off|latch_on|latch_off|nul_code|trip|close)\b"),
    ),
    # ── OPC-UA ────────────────────────────────────────────────────────────────
    # OPC-UA NodeId pattern (ns=N;i=M  or  ns=N;s=Name)
    _Signal(
        OTProtocol.OPCUA,
        "opcua_nodeid",
        0.75,
        _re(r"\bns\s*=\s*\d+\s*;\s*[isgb]\s*=\s*[\w\.\-]+\b"),
    ),
    # OPC-UA write / method call instructions
    _Signal(
        OTProtocol.OPCUA,
        "opcua_write_call",
        0.8,
        _re(
            r"\b(?:ua_client|opcua\s+client|ua\.write|writevalue|callmethod"
            r"|ua_write_value|session\.write)\b"
        ),
    ),
    # OPC-UA Security Mode None (insecure connection attempt)
    _Signal(
        OTProtocol.OPCUA,
        "opcua_security_none",
        0.7,
        _re(r"\bopc\s*ua\b.{0,80}\bsecurity\s+mode\s+none\b|\bsecuritymode\.none\b"),
    ),
    # OPC-UA browse/write/method context
    _Signal(
        OTProtocol.OPCUA,
        "opcua_command_context",
        0.6,
        _re(
            r"\bopc[\s\-]?ua\b.{0,60}(?:write|operate|set\s+value|call|invoke)\b"
            r"|\b(?:write|operate|set\s+value|call|invoke)\b.{0,60}\bopc[\s\-]?ua\b"
        ),
    ),
    # OPC-UA endpoint URL
    _Signal(
        OTProtocol.OPCUA,
        "opcua_endpoint_url",
        0.65,
        _re(r"\bopc\.tcp://[^\s\"\']{5,80}\b"),
    ),
]


# ── Result types ──────────────────────────────────────────────────────────────


@dataclass
class OTSignalHit:
    """A matched signal from the OT protocol scanner.

    Attributes
    ----------
    protocol:
        Which OT protocol the signal belongs to.
    signal_name:
        Identifier for the specific pattern that matched.
    weight:
        Contribution to the overall ``risk_score`` (0–1).
    excerpt:
        Short excerpt from the matched text (up to 80 chars).
    """

    protocol: OTProtocol
    signal_name: str
    weight: float
    excerpt: str


@dataclass
class OTScanResult:
    """Result of an :meth:`OTProtocolScanner.scan` call.

    Attributes
    ----------
    signals:
        All matched signals.
    risk_score:
        Composite risk score in [0, 1] computed as
        ``1 - product(1 - w for w in weights)``.
    should_block:
        True when ``risk_score >= block_threshold``.
    scanned_chars:
        Length of the input text.
    protocols_detected:
        Set of :class:`OTProtocol` values for which at least one signal matched.
    """

    signals: list[OTSignalHit] = field(default_factory=list)
    risk_score: float = 0.0
    should_block: bool = False
    scanned_chars: int = 0
    protocols_detected: set[OTProtocol] = field(default_factory=set)

    @property
    def clean(self) -> bool:
        return not self.signals

    def to_dict(self) -> dict[str, object]:
        return {
            "clean": self.clean,
            "risk_score": self.risk_score,
            "should_block": self.should_block,
            "scanned_chars": self.scanned_chars,
            "protocols_detected": sorted(self.protocols_detected),
            "signals": [
                {
                    "protocol": s.protocol,
                    "signal_name": s.signal_name,
                    "weight": s.weight,
                    "excerpt": s.excerpt,
                }
                for s in self.signals
            ],
        }


# ── Scanner ───────────────────────────────────────────────────────────────────


class OTProtocolScanner:
    """Scans LLM-generated text for MODBUS, DNP3, and OPC-UA command injection.

    Thread-safe; all state is read-only after construction.

    Parameters
    ----------
    block_threshold:
        Risk score at or above which ``result.should_block`` is True.
        Defaults to the ``AEGIS_OT_BLOCK_THRESHOLD`` env var (0.5 if unset).
    """

    def __init__(self, block_threshold: float | None = None) -> None:
        if block_threshold is None:
            raw = os.environ.get("AEGIS_OT_BLOCK_THRESHOLD", "0.5")
            try:
                block_threshold = float(raw)
            except ValueError:
                logger.warning(
                    "OTProtocolScanner: invalid AEGIS_OT_BLOCK_THRESHOLD=%r; using 0.5", raw
                )
                block_threshold = 0.5
        self.block_threshold = max(0.0, min(1.0, block_threshold))

    def scan(self, text: str) -> OTScanResult:
        """Scan *text* for OT protocol command injection signals.

        Parameters
        ----------
        text:
            LLM-generated response text.

        Returns
        -------
        OTScanResult
        """
        result = OTScanResult(scanned_chars=len(text))
        weights: list[float] = []

        for sig in _SIGNALS:
            match = sig.pattern.search(text)
            if match:
                start = max(0, match.start() - 20)
                excerpt = text[start : match.end() + 20].replace("\n", " ")[:80]
                hit = OTSignalHit(
                    protocol=sig.protocol,
                    signal_name=sig.name,
                    weight=sig.weight,
                    excerpt=excerpt,
                )
                result.signals.append(hit)
                result.protocols_detected.add(sig.protocol)
                weights.append(sig.weight)

        if weights:
            # Complementary probability combination: P(any) = 1 - product(1-P_i)
            score = 1.0
            for w in weights:
                score *= 1.0 - w
            result.risk_score = round(1.0 - score, 4)
        else:
            result.risk_score = 0.0

        result.should_block = result.risk_score >= self.block_threshold

        if result.should_block:
            logger.warning(
                "ot_protocol_scanner: OT command injection detected — "
                "score=%.4f protocols=%s signals=%s",
                result.risk_score,
                sorted(result.protocols_detected),
                [s.signal_name for s in result.signals],
            )

        return result

    def scan_messages(self, messages: list[dict[str, str]]) -> OTScanResult:
        """Scan assistant-role messages in an OpenAI-style message list."""
        combined = "\n".join(m.get("content", "") for m in messages if m.get("role") == "assistant")
        return self.scan(combined)

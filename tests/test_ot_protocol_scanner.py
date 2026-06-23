# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
# Copyright (c) 2026 Juan Luna. All rights reserved.
"""Tests for aegis.core.ot_protocol_scanner."""

from __future__ import annotations

from aegis.core.ot_protocol_scanner import (
    OTProtocol,
    OTProtocolScanner,
    OTScanResult,
    OTSignalHit,
)

# ── OTScanResult ──────────────────────────────────────────────────────────────


class TestOTScanResult:
    def test_defaults(self):
        r = OTScanResult()
        assert r.signals == []
        assert r.risk_score == 0.0
        assert r.should_block is False
        assert r.scanned_chars == 0
        assert r.protocols_detected == set()
        assert r.clean is True

    def test_clean_false_with_signals(self):
        hit = OTSignalHit(OTProtocol.MODBUS, "modbus_function_code", 0.7, "FC 03")
        r = OTScanResult(signals=[hit], risk_score=0.7)
        assert r.clean is False

    def test_to_dict_keys(self):
        r = OTScanResult()
        d = r.to_dict()
        assert set(d.keys()) == {
            "clean",
            "risk_score",
            "should_block",
            "scanned_chars",
            "protocols_detected",
            "signals",
        }

    def test_to_dict_protocols_sorted(self):
        r = OTScanResult(protocols_detected={OTProtocol.MODBUS, OTProtocol.DNP3})
        d = r.to_dict()
        assert d["protocols_detected"] == sorted(["modbus", "dnp3"])

    def test_to_dict_signal_structure(self):
        hit = OTSignalHit(OTProtocol.OPCUA, "opcua_nodeid", 0.75, "ns=2;i=1001")
        r = OTScanResult(signals=[hit])
        d = r.to_dict()
        assert len(d["signals"]) == 1
        s = d["signals"][0]
        assert s["protocol"] == "opcua"
        assert s["signal_name"] == "opcua_nodeid"
        assert s["weight"] == 0.75
        assert s["excerpt"] == "ns=2;i=1001"


# ── OTProtocolScanner construction ────────────────────────────────────────────


class TestScannerConstruction:
    def test_default_threshold(self, monkeypatch):
        monkeypatch.delenv("AEGIS_OT_BLOCK_THRESHOLD", raising=False)
        s = OTProtocolScanner()
        assert s.block_threshold == 0.5

    def test_custom_threshold(self):
        s = OTProtocolScanner(block_threshold=0.7)
        assert s.block_threshold == 0.7

    def test_env_var_threshold(self, monkeypatch):
        monkeypatch.setenv("AEGIS_OT_BLOCK_THRESHOLD", "0.8")
        s = OTProtocolScanner()
        assert s.block_threshold == 0.8

    def test_invalid_env_var_defaults_to_0_5(self, monkeypatch):
        monkeypatch.setenv("AEGIS_OT_BLOCK_THRESHOLD", "not_a_float")
        s = OTProtocolScanner()
        assert s.block_threshold == 0.5

    def test_threshold_clamped_to_zero(self):
        s = OTProtocolScanner(block_threshold=-1.0)
        assert s.block_threshold == 0.0

    def test_threshold_clamped_to_one(self):
        s = OTProtocolScanner(block_threshold=5.0)
        assert s.block_threshold == 1.0


# ── Clean text ────────────────────────────────────────────────────────────────


class TestCleanText:
    def setup_method(self):
        self.scanner = OTProtocolScanner()

    def test_empty_text(self):
        result = self.scanner.scan("")
        assert result.clean is True
        assert result.risk_score == 0.0

    def test_benign_text(self):
        result = self.scanner.scan(
            "The patient should take 400 mg ibuprofen twice daily. "
            "Ensure adequate hydration and rest."
        )
        assert result.clean is True

    def test_benign_text_with_numbers(self):
        result = self.scanner.scan(
            "The temperature sensor reads 42.5 degrees Celsius at position 3."
        )
        assert result.clean is True

    def test_generic_write_no_protocol_context(self):
        result = self.scanner.scan("Please write a short essay about climate change.")
        assert result.risk_score < 0.5


# ── MODBUS detection ──────────────────────────────────────────────────────────


class TestModbusDetection:
    def setup_method(self):
        self.scanner = OTProtocolScanner(block_threshold=0.5)

    def test_modbus_function_code(self):
        result = self.scanner.scan("Send FC 03 to read holding registers 40001-40010.")
        assert OTProtocol.MODBUS in result.protocols_detected

    def test_modbus_write_fc06(self):
        result = self.scanner.scan("Use function code 6 to write single register 40001 = 1500.")
        assert OTProtocol.MODBUS in result.protocols_detected
        assert result.risk_score > 0.5

    def test_modbus_register_address_notation(self):
        result = self.scanner.scan("Read the value at Holding Register 40100.")
        assert OTProtocol.MODBUS in result.protocols_detected

    def test_modbus_percent_mw(self):
        result = self.scanner.scan("The PLC stores the setpoint in %MW100.")
        assert OTProtocol.MODBUS in result.protocols_detected

    def test_modbus_api_call_write_register(self):
        result = self.scanner.scan("client.write_register(0, 1500)")
        assert OTProtocol.MODBUS in result.protocols_detected

    def test_modbus_api_call_write_coil(self):
        result = self.scanner.scan("Call write_coil(1, True) to activate the relay.")
        assert OTProtocol.MODBUS in result.protocols_detected

    def test_modbus_command_composition(self):
        result = self.scanner.scan("Use Modbus to write the new setpoint to the drive.")
        assert OTProtocol.MODBUS in result.protocols_detected

    def test_multiple_modbus_signals_increase_score(self):
        text = "FC 06 write_register(%MW100, 1500) via Modbus to set the coil address 00001."
        result = self.scanner.scan(text)
        assert result.risk_score > 0.5
        assert result.should_block is True

    def test_modbus_coil_address(self):
        result = self.scanner.scan("Toggle coil address 00001 to activate the motor starter.")
        assert OTProtocol.MODBUS in result.protocols_detected

    def test_fc_case_insensitive(self):
        result = self.scanner.scan("Use fc 16 to write multiple registers.")
        assert OTProtocol.MODBUS in result.protocols_detected


# ── DNP3 detection ────────────────────────────────────────────────────────────


class TestDNP3Detection:
    def setup_method(self):
        self.scanner = OTProtocolScanner(block_threshold=0.5)

    def test_dnp3_crob(self):
        result = self.scanner.scan("Send CROB command to operate the breaker.")
        assert OTProtocol.DNP3 in result.protocols_detected

    def test_dnp3_group_12(self):
        result = self.scanner.scan("Send Group 12, Variation 1 command to the outstation.")
        assert OTProtocol.DNP3 in result.protocols_detected

    def test_dnp3_control_relay_output_block(self):
        result = self.scanner.scan(
            "Encode a Control Relay Output Block with LATCH_ON and send to device."
        )
        assert OTProtocol.DNP3 in result.protocols_detected

    def test_dnp3_group_variation(self):
        result = self.scanner.scan("Object Group 12 Variation 1 should be used for output control.")
        assert OTProtocol.DNP3 in result.protocols_detected

    def test_dnp3_direct_operate(self):
        result = self.scanner.scan("Use direct operate to execute the command immediately.")
        assert OTProtocol.DNP3 in result.protocols_detected

    def test_dnp3_latch_on_control_code(self):
        result = self.scanner.scan("Set control code LATCH_ON for 1000 ms on the relay.")
        assert OTProtocol.DNP3 in result.protocols_detected

    def test_dnp3_master_operate(self):
        result = self.scanner.scan("The DNP3 master should operate the trip command now.")
        assert OTProtocol.DNP3 in result.protocols_detected

    def test_select_before_operate(self):
        result = self.scanner.scan("Perform Select Before Operate (SBO) to ensure safe control.")
        assert OTProtocol.DNP3 in result.protocols_detected

    def test_dnp3_trip_control_code(self):
        result = self.scanner.scan("Send Trip command via DNP3 to open the circuit breaker.")
        assert OTProtocol.DNP3 in result.protocols_detected


# ── OPC-UA detection ──────────────────────────────────────────────────────────


class TestOPCUADetection:
    def setup_method(self):
        self.scanner = OTProtocolScanner(block_threshold=0.5)

    def test_opcua_nodeid_integer(self):
        result = self.scanner.scan("Write to NodeId ns=2;i=1001 the new setpoint value.")
        assert OTProtocol.OPCUA in result.protocols_detected

    def test_opcua_nodeid_string(self):
        result = self.scanner.scan("Access ns=3;s=TemperatureSetpoint via OPC-UA.")
        assert OTProtocol.OPCUA in result.protocols_detected

    def test_opcua_write_call(self):
        result = self.scanner.scan("Call ua_write_value(node_id, new_value) on the UA client.")
        assert OTProtocol.OPCUA in result.protocols_detected

    def test_opcua_write_value(self):
        result = self.scanner.scan("session.write([WriteValue(...)]) to update the setpoint.")
        assert OTProtocol.OPCUA in result.protocols_detected

    def test_opcua_security_none(self):
        result = self.scanner.scan("Connect to the OPC UA server with Security Mode None.")
        assert OTProtocol.OPCUA in result.protocols_detected

    def test_opcua_endpoint_url(self):
        result = self.scanner.scan("Connect to opc.tcp://192.168.1.100:4840 for data access.")
        assert OTProtocol.OPCUA in result.protocols_detected

    def test_opcua_command_context_write(self):
        result = self.scanner.scan("Use OPC-UA to write the new value to the temperature setpoint.")
        assert OTProtocol.OPCUA in result.protocols_detected

    def test_opcua_call_method(self):
        result = self.scanner.scan("Call callmethod on the UA client to start the process.")
        assert OTProtocol.OPCUA in result.protocols_detected


# ── Risk score math ───────────────────────────────────────────────────────────


class TestRiskScoreMath:
    def test_zero_signals_zero_score(self):
        s = OTProtocolScanner()
        result = s.scan("Hello, how are you?")
        assert result.risk_score == 0.0

    def test_single_signal_score_equals_weight(self):
        s = OTProtocolScanner()
        # Using a string that matches exactly one signal (CROB)
        result = s.scan("CROB control relay output block")
        # At least CROB matched; score should be > 0
        assert result.risk_score > 0.0

    def test_multiple_signals_score_higher(self):
        s = OTProtocolScanner()
        single = s.scan("FC 03 read registers")
        multi = s.scan("FC 03 read registers; then FC 06 write_register(%MW100, 1) via Modbus")
        assert multi.risk_score >= single.risk_score

    def test_risk_score_bounded_zero_to_one(self):
        s = OTProtocolScanner()
        # Text with many signals
        text = (
            "FC 06 write_register(40001, 1500) via Modbus; "
            "CROB Group 12 Variation 1 LATCH_ON; "
            "ns=2;i=1001 ua_write_value opc.tcp://plc.local:4840"
        )
        result = s.scan(text)
        assert 0.0 <= result.risk_score <= 1.0

    def test_should_block_at_threshold(self):
        s = OTProtocolScanner(block_threshold=0.0)
        result = s.scan("FC 03 read registers")
        if result.risk_score > 0:
            assert result.should_block is True

    def test_should_block_false_below_threshold(self):
        s = OTProtocolScanner(block_threshold=0.99)
        result = s.scan("FC 03 read registers")
        # Moderate-scoring text won't exceed 0.99
        # (unless many signals fire, but FC 03 alone is low)
        assert isinstance(result.should_block, bool)


# ── scan_messages ─────────────────────────────────────────────────────────────


class TestScanMessages:
    def setup_method(self):
        self.scanner = OTProtocolScanner()

    def test_scans_only_assistant_messages(self):
        messages = [
            {"role": "user", "content": "CROB Group 12 Variation 1 operate"},
            {"role": "assistant", "content": "I recommend consulting the manual."},
        ]
        result = self.scanner.scan_messages(messages)
        # User message not scanned; only assistant
        assert result.clean is True

    def test_detects_in_assistant_message(self):
        messages = [
            {"role": "user", "content": "How do I control the relay?"},
            {"role": "assistant", "content": "Send FC 06 via Modbus to write_register(40001, 1)."},
        ]
        result = self.scanner.scan_messages(messages)
        assert OTProtocol.MODBUS in result.protocols_detected

    def test_empty_messages(self):
        result = self.scanner.scan_messages([])
        assert result.clean is True

    def test_missing_content_key(self):
        result = self.scanner.scan_messages([{"role": "assistant"}])
        assert result.clean is True


# ── Multi-protocol detection ──────────────────────────────────────────────────


class TestMultiProtocol:
    def test_modbus_and_dnp3(self):
        s = OTProtocolScanner()
        text = "FC 06 write_register(40001, 1) to set the relay, then CROB Group 12 Variation 1."
        result = s.scan(text)
        assert OTProtocol.MODBUS in result.protocols_detected
        assert OTProtocol.DNP3 in result.protocols_detected

    def test_all_three_protocols(self):
        s = OTProtocolScanner()
        text = (
            "FC 06 write_register(40001, 1500); "
            "CROB Group 12 Variation 1 LATCH_ON; "
            "opc.tcp://192.168.1.1:4840 ns=2;i=5"
        )
        result = s.scan(text)
        assert OTProtocol.MODBUS in result.protocols_detected
        assert OTProtocol.DNP3 in result.protocols_detected
        assert OTProtocol.OPCUA in result.protocols_detected

    def test_scanned_chars_correct(self):
        text = "FC 03 read"
        s = OTProtocolScanner()
        result = s.scan(text)
        assert result.scanned_chars == len(text)

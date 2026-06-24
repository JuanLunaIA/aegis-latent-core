# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.tpm — TPMManager."""

from __future__ import annotations

import hashlib
from subprocess import CompletedProcess
from unittest.mock import MagicMock, patch

import pytest

from aegis.core.tpm import TPMManager


def _make_cp(returncode: int, stdout: str = "", stderr: str = "") -> CompletedProcess:
    cp = MagicMock(spec=CompletedProcess)
    cp.returncode = returncode
    cp.stdout = stdout
    cp.stderr = stderr
    return cp


class TestTPMManagerInit:
    def test_hardware_false_when_tpm2_tools_absent(self):
        with patch("aegis.core.tpm.shutil.which", return_value=None):
            mgr = TPMManager()
        assert mgr._hardware is False

    def test_hardware_true_when_tpm2_tools_present(self):
        with patch("aegis.core.tpm.shutil.which", return_value="/usr/bin/tpm2_pcrextend"):
            mgr = TPMManager()
        assert mgr._hardware is True

    def test_default_pcr_index_is_10(self):
        with patch("aegis.core.tpm.shutil.which", return_value=None):
            mgr = TPMManager()
        assert mgr.pcr_index == 10

    def test_custom_pcr_index(self):
        with patch("aegis.core.tpm.shutil.which", return_value=None):
            mgr = TPMManager(pcr_index=7)
        assert mgr.pcr_index == 7


class TestMeasureBinarySwMode:
    def _make_mgr(self) -> TPMManager:
        with patch("aegis.core.tpm.shutil.which", return_value=None):
            return TPMManager()

    def test_raises_when_binary_not_found(self):
        mgr = self._make_mgr()
        with pytest.raises(FileNotFoundError):
            mgr.measure_binary("/nonexistent/binary")

    def test_returns_hex_string(self, tmp_path):
        binary = tmp_path / "binary"
        binary.write_bytes(b"content")
        mgr = self._make_mgr()
        result = mgr.measure_binary(str(binary))
        assert isinstance(result, str)
        assert len(result) == 64

    def test_second_measure_extends_from_first(self, tmp_path):
        binary1 = tmp_path / "b1"
        binary1.write_bytes(b"first")
        binary2 = tmp_path / "b2"
        binary2.write_bytes(b"second")
        mgr = self._make_mgr()
        pcr1 = mgr.measure_binary(str(binary1))
        pcr2 = mgr.measure_binary(str(binary2))
        # pcr2 must differ from pcr1 and from a fresh single extend of binary2
        fresh_mgr = self._make_mgr()
        fresh_pcr2 = fresh_mgr.measure_binary(str(binary2))
        assert pcr2 != pcr1
        assert pcr2 != fresh_pcr2

    def test_sw_extend_follows_pcr_extend_formula(self, tmp_path):
        binary = tmp_path / "b"
        content = b"test-binary"
        binary.write_bytes(content)
        mgr = self._make_mgr()
        result = mgr.measure_binary(str(binary))
        binary_hash = hashlib.sha256(content).hexdigest()
        pcr_old = "0" * 64
        expected = hashlib.sha256((pcr_old + binary_hash).encode()).hexdigest()
        assert result == expected


class TestMeasureBinaryHwMode:
    def _make_hw_mgr(self) -> TPMManager:
        with patch("aegis.core.tpm.shutil.which", return_value="/usr/bin/tpm2_pcrextend"):
            return TPMManager()

    def test_hw_extend_failure_raises(self, tmp_path):
        binary = tmp_path / "b"
        binary.write_bytes(b"data")
        mgr = self._make_hw_mgr()
        with patch(
            "aegis.core.tpm.subprocess.run",
            return_value=_make_cp(1, stderr="no device"),
        ):
            with pytest.raises(RuntimeError, match="tpm2_pcrextend failed"):
                mgr.measure_binary(str(binary))

    def test_hw_read_failure_raises(self, tmp_path):
        binary = tmp_path / "b"
        binary.write_bytes(b"data")
        mgr = self._make_hw_mgr()
        call_count = [0]

        def fake_run(cmd, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return _make_cp(0)
            return _make_cp(1, stderr="read failed")

        with patch("aegis.core.tpm.subprocess.run", side_effect=fake_run):
            with pytest.raises(RuntimeError, match="tpm2_pcrread failed"):
                mgr.measure_binary(str(binary))

    def test_hw_returns_parsed_pcr_value(self, tmp_path):
        binary = tmp_path / "b"
        binary.write_bytes(b"data")
        mgr = self._make_hw_mgr()
        pcrread_output = "sha256:\n  10: 0xDEADBEEF" + "00" * 28 + "\n"
        expected = "deadbeef" + "00" * 28

        def fake_run(cmd, **kwargs):
            if _make_cp(0).returncode == 0:
                return _make_cp(0, stdout=pcrread_output)
            return _make_cp(0)

        with patch(
            "aegis.core.tpm.subprocess.run", return_value=_make_cp(0, stdout=pcrread_output)
        ):
            result = mgr.measure_binary(str(binary))
        assert result == expected


class TestVerifyGoldenHash:
    def _make_mgr(self) -> TPMManager:
        with patch("aegis.core.tpm.shutil.which", return_value=None):
            return TPMManager()

    def test_no_measurement_returns_false(self):
        mgr = self._make_mgr()
        assert mgr.verify_golden_hash("a" * 64) is False

    def test_matching_hash_returns_true(self, tmp_path):
        binary = tmp_path / "b"
        binary.write_bytes(b"data")
        mgr = self._make_mgr()
        pcr = mgr.measure_binary(str(binary))
        assert mgr.verify_golden_hash(pcr) is True

    def test_mismatched_hash_returns_false(self, tmp_path):
        binary = tmp_path / "b"
        binary.write_bytes(b"data")
        mgr = self._make_mgr()
        mgr.measure_binary(str(binary))
        assert mgr.verify_golden_hash("00" * 32) is False


class TestParsePcrReadOutput:
    def test_parses_standard_output(self):
        with patch("aegis.core.tpm.shutil.which", return_value=None):
            mgr = TPMManager(pcr_index=10)
        output = "sha256:\n  10: 0xABCDEF1234" + "00" * 27 + "\n"
        result = mgr._parse_pcrread_output(output)
        assert result.startswith("abcdef1234")

    def test_returns_zeros_when_not_found(self):
        with patch("aegis.core.tpm.shutil.which", return_value=None):
            mgr = TPMManager(pcr_index=10)
        assert mgr._parse_pcrread_output("no matching line") == "0" * 64

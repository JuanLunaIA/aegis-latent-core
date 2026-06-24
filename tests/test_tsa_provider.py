# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.tsa_provider — real RFC 3161 TSA client."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from aegis.core.tsa_provider import TSAProvider, TSATimestamp, tsa_provider


class TestTSAProviderInit:
    def test_default_url(self):
        p = TSAProvider()
        assert "digicert" in p.tsa_url

    def test_custom_url(self):
        p = TSAProvider("http://freetsa.org/tsr")
        assert p.tsa_url == "http://freetsa.org/tsr"

    def test_openssl_detected(self):
        p = TSAProvider()
        # openssl is available in the test environment
        assert p._openssl is not None


class TestGetTimestampToken:
    def _make_provider(self, openssl: str = "/usr/bin/openssl") -> TSAProvider:
        p = TSAProvider("http://tsa.example.test")
        p._openssl = openssl
        return p

    def test_raises_when_openssl_absent(self):
        p = self._make_provider(openssl=None)
        with pytest.raises(RuntimeError, match="openssl not found"):
            p.get_timestamp_token(b"hello")

    def test_builds_tsq_and_posts_to_tsa(self):
        p = self._make_provider()
        fake_tsq = b"\x30\x0a"  # minimal DER sequence placeholder
        fake_tsr = b"\x30\x0b"

        mock_proc = MagicMock()
        mock_proc.returncode = 0

        mock_resp = MagicMock()
        mock_resp.content = fake_tsr
        mock_resp.raise_for_status = MagicMock()

        def fake_subprocess_run(cmd, **kwargs):
            # Write fake TSQ bytes to the output path
            tsq_out = next(
                (cmd[i + 1] for i, c in enumerate(cmd) if c == "-out"),
                None,
            )
            if tsq_out:
                Path(tsq_out).write_bytes(fake_tsq)
            return mock_proc

        with (
            patch("aegis.core.tsa_provider.subprocess.run", side_effect=fake_subprocess_run),
            patch("aegis.core.tsa_provider.httpx.post", return_value=mock_resp) as mock_post,
        ):
            result = p.get_timestamp_token(b"test data")

        assert result == fake_tsr
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args
        assert call_kwargs.kwargs["headers"] == {"Content-Type": "application/timestamp-query"}

    def test_raises_on_tsa_http_error(self):
        p = self._make_provider()
        fake_tsq = b"\x30\x0a"

        def fake_subprocess_run(cmd, **kwargs):
            tsq_out = next((cmd[i + 1] for i, c in enumerate(cmd) if c == "-out"), None)
            if tsq_out:
                Path(tsq_out).write_bytes(fake_tsq)
            return MagicMock(returncode=0)

        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = Exception("HTTP 500")

        with (
            patch("aegis.core.tsa_provider.subprocess.run", side_effect=fake_subprocess_run),
            patch("aegis.core.tsa_provider.httpx.post", return_value=mock_resp),
        ):
            with pytest.raises(Exception, match="HTTP 500"):
                p.get_timestamp_token(b"data")

    def test_openssl_invoked_with_sha256(self):
        p = self._make_provider()
        fake_tsq = b"\x30\x0a"

        captured_cmd: list[list[str]] = []

        def fake_subprocess_run(cmd, **kwargs):
            captured_cmd.append(list(cmd))
            tsq_out = next((cmd[i + 1] for i, c in enumerate(cmd) if c == "-out"), None)
            if tsq_out:
                Path(tsq_out).write_bytes(fake_tsq)
            return MagicMock(returncode=0)

        mock_resp = MagicMock()
        mock_resp.content = b"\x30\x0b"
        mock_resp.raise_for_status = MagicMock()

        with (
            patch("aegis.core.tsa_provider.subprocess.run", side_effect=fake_subprocess_run),
            patch("aegis.core.tsa_provider.httpx.post", return_value=mock_resp),
        ):
            p.get_timestamp_token(b"payload")

        cmd = captured_cmd[0]
        assert "-sha256" in cmd
        assert "-query" in cmd


class TestVerifyToken:
    def _make_provider(self, openssl: str = "/usr/bin/openssl") -> TSAProvider:
        p = TSAProvider("http://tsa.example.test")
        p._openssl = openssl
        return p

    def test_raises_when_openssl_absent(self):
        p = self._make_provider(openssl=None)
        with pytest.raises(RuntimeError, match="openssl not found"):
            p.verify_token(b"data", b"token")

    def test_returns_true_on_success(self):
        p = self._make_provider()
        mock_result = MagicMock()
        mock_result.returncode = 0

        with patch("aegis.core.tsa_provider.subprocess.run", return_value=mock_result):
            assert p.verify_token(b"data", b"token") is True

    def test_returns_false_on_failure(self):
        p = self._make_provider()
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = b"verification failed"

        with patch("aegis.core.tsa_provider.subprocess.run", return_value=mock_result):
            assert p.verify_token(b"data", b"token") is False

    def test_ca_file_appended_when_found(self, tmp_path):
        p = self._make_provider()
        ca = tmp_path / "ca.crt"
        ca.write_text("FAKE CA")

        captured_cmd: list[list[str]] = []

        def fake_subprocess_run(cmd, **kwargs):
            captured_cmd.append(list(cmd))
            return MagicMock(returncode=0)

        with (
            patch("aegis.core.tsa_provider._CA_CANDIDATES", (str(ca),)),
            patch("aegis.core.tsa_provider.subprocess.run", side_effect=fake_subprocess_run),
        ):
            p.verify_token(b"data", b"tok")

        assert "-CAfile" in captured_cmd[0]
        assert str(ca) in captured_cmd[0]

    def test_no_ca_file_still_runs(self):
        p = self._make_provider()
        mock_result = MagicMock()
        mock_result.returncode = 0

        with (
            patch("aegis.core.tsa_provider._CA_CANDIDATES", ()),
            patch("aegis.core.tsa_provider.subprocess.run", return_value=mock_result),
        ):
            assert p.verify_token(b"data", b"tok") is True


class TestTSATimestampDataclass:
    def test_fields(self):
        ts = TSATimestamp(timestamp_token=b"abc", verified=True, tsa_url="http://x")
        assert ts.timestamp_token == b"abc"
        assert ts.verified is True
        assert ts.tsa_url == "http://x"


class TestModuleSingleton:
    def test_singleton_is_tsa_provider(self):
        assert isinstance(tsa_provider, TSAProvider)

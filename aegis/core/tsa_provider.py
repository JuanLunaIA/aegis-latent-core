"""
aegis.core.tsa_provider — RFC 3161 Timestamping Authority Provider.
Provides integration with external TSA services to generate and verify trusted timestamps.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import logging
import shutil
import subprocess  # noqa: S404  # nosec B404
import tempfile
from dataclasses import dataclass
from pathlib import Path

import httpx

logger = logging.getLogger(__name__)

# Well-known system CA bundles; the first one that exists is used for verification.
_CA_CANDIDATES: tuple[str, ...] = (
    "/etc/ssl/certs/ca-certificates.crt",  # Debian / Ubuntu
    "/etc/pki/tls/certs/ca-bundle.crt",  # RHEL / CentOS
    "/etc/ssl/ca-bundle.pem",  # openSUSE
    "/root/.ccr/ca-bundle.crt",  # CI proxy bundle
)


@dataclass
class TSATimestamp:
    timestamp_token: bytes
    verified: bool
    tsa_url: str


class TSAProvider:
    """RFC 3161 TSA client.

    Uses ``openssl ts`` to build a DER-encoded TimeStampReq and POSTs it to the
    configured TSA endpoint via httpx.  The raw DER TimeStampResp is returned as
    the token.  Verification uses ``openssl ts -verify`` with the system CA bundle.
    """

    def __init__(self, tsa_url: str = "http://timestamp.digicert.com"):
        self.tsa_url = tsa_url
        self._openssl = shutil.which("openssl")

    def get_timestamp_token(self, data: bytes) -> bytes:
        """Build and submit a real RFC 3161 TimeStampReq; return the TSR bytes.

        Raises ``RuntimeError`` when openssl is absent or the TSA returns an error.
        """
        if self._openssl is None:
            raise RuntimeError("openssl not found — cannot build an RFC 3161 timestamp request")

        logger.info("Requesting RFC 3161 timestamp from %s...", self.tsa_url)

        with tempfile.TemporaryDirectory() as tmpdir:
            data_path = Path(tmpdir) / "data.bin"
            tsq_path = Path(tmpdir) / "request.tsq"
            data_path.write_bytes(data)

            subprocess.run(  # noqa: S603  # nosec B603
                [
                    self._openssl,
                    "ts",
                    "-query",
                    "-data",
                    str(data_path),
                    "-sha256",
                    "-cert",
                    "-out",
                    str(tsq_path),
                ],
                capture_output=True,
                check=True,
                timeout=10,
            )

            tsq_bytes = tsq_path.read_bytes()

        resp = httpx.post(
            self.tsa_url,
            content=tsq_bytes,
            headers={"Content-Type": "application/timestamp-query"},
            timeout=15.0,
        )
        resp.raise_for_status()
        logger.info("RFC 3161 timestamp token received (%d bytes).", len(resp.content))
        return resp.content

    def verify_token(self, data: bytes, token: bytes) -> bool:
        """Verify an RFC 3161 TSR against the original data using ``openssl ts -verify``.

        Returns ``True`` only when openssl confirms the token signature and embedded
        hash match.  Returns ``False`` (with a warning) when verification fails.
        Raises ``RuntimeError`` when openssl is absent.
        """
        if self._openssl is None:
            raise RuntimeError("openssl not found — cannot verify RFC 3161 timestamp token")

        logger.info("Verifying RFC 3161 token...")

        ca_file = next(
            (c for c in _CA_CANDIDATES if Path(c).exists()),
            None,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            data_path = Path(tmpdir) / "data.bin"
            tsr_path = Path(tmpdir) / "token.tsr"
            data_path.write_bytes(data)
            tsr_path.write_bytes(token)

            cmd = [
                self._openssl,
                "ts",
                "-verify",
                "-data",
                str(data_path),
                "-in",
                str(tsr_path),
            ]
            if ca_file:
                cmd += ["-CAfile", ca_file]

            result = subprocess.run(  # noqa: S603  # nosec B603
                cmd,
                capture_output=True,
                check=False,
                timeout=10,
            )

        if result.returncode == 0:
            logger.info("RFC 3161 token verified successfully.")
            return True

        logger.warning(
            "RFC 3161 token verification failed: %s",
            result.stderr.decode(errors="replace"),
        )
        return False


tsa_provider = TSAProvider()

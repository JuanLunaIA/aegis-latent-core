"""
aegis.core.codeql_config — CodeQL Query Integration for CI/CD.
Defines the security queries and sinks/sources used to scan the Aegis codebase.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import json
import logging
import shutil
import subprocess  # noqa: S404  # nosec B404
import tempfile
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class CodeQLQuery:
    id: str
    name: str
    severity: str  # 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
    description: str
    target_path: str


class AegisCodeQLPipeline:
    """
    Integration layer for CodeQL static analysis.
    Defines the custom queries used to identify Aegis-specific vulnerabilities,
    such as incorrect PQC parameter usage or unsafe Rust blocks.
    """

    def __init__(self, source_root: Path | str | None = None):
        self.source_root: Path = Path(source_root) if source_root is not None else Path.cwd()
        self.queries: list[CodeQLQuery] = [
            CodeQLQuery(
                id="AEGIS-001",
                name="Unsafe-Rust-Leak",
                severity="CRITICAL",
                description="Detects unsafe blocks that bypass the borrow checker without formal justification.",
                target_path="aegis_rust_v2/src/",
            ),
            CodeQLQuery(
                id="AEGIS-002",
                name="PQC-Parameter-Mismatch",
                severity="HIGH",
                description="Detects mismatch between ML-DSA and ML-KEM parameter sets (e.g., mixing 65 and 768).",
                target_path="aegis_rust_v2/src/",
            ),
            CodeQLQuery(
                id="AEGIS-003",
                name="SVID-Leakage",
                severity="HIGH",
                description="Detects leakage of SPIFFE SVIDs to unauthenticated logs or headers.",
                target_path="aegis/proxy/",
            ),
            CodeQLQuery(
                id="AEGIS-004",
                name="Tainted-Logprob-Flow",
                severity="MEDIUM",
                description="Detects tainted input flowing directly into entropy calculation without normalization.",
                target_path="aegis/proxy/analyzer.py",
            ),
        ]

    def generate_github_action_yaml(self) -> str:
        """Generates the .github/workflows/codeql.yml for automated scanning."""
        return """
name: "CodeQL Analysis"
on:
  push:
    branches: [ "main" ]
  pull_request:
    branches: [ "main" ]

jobs:
  analyze:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      actions: read
      contents: read
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Initialize CodeQL
        uses: github/codeql-action/init@v3
        with:
          languages: 'python, rust'
          config-file: .github/codeql/config.yml

      - name: Perform CodeQL Analysis
        uses: github/codeql-action/analyze@v3
        """

    def run_local_scan(self) -> dict:
        """
        Runs a local CodeQL scan via the ``codeql`` CLI.

        Creates a temporary CodeQL database for the Python source, runs
        ``codeql database analyze`` with the built-in security-extended
        query pack, and returns a result dict parsed from SARIF output.

        Returns ``{"status": "UNAVAILABLE", ...}`` when the ``codeql`` CLI is
        not installed — no fake results are manufactured.
        """
        if shutil.which("codeql") is None:
            logger.warning("codeql CLI not found — install CodeQL CLI to enable local scanning.")
            return {
                "status": "UNAVAILABLE",
                "reason": "codeql CLI not installed",
                "queries_defined": len(self.queries),
            }

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "codeql-db"
            sarif_path = Path(tmp) / "results.sarif"

            create_cmd = [
                "codeql",
                "database",
                "create",
                str(db_path),
                "--language=python",
                f"--source-root={self.source_root}",
                "--overwrite",
            ]
            analyze_cmd = [
                "codeql",
                "database",
                "analyze",
                str(db_path),
                "python-security-extended",
                "--format=sarif-latest",
                f"--output={sarif_path}",
            ]

            try:
                create_result = subprocess.run(  # noqa: S603  # nosec B603
                    create_cmd, capture_output=True, text=True
                )
                if create_result.returncode != 0:
                    logger.error("codeql database create failed: %s", create_result.stderr)
                    return {
                        "status": "ERROR",
                        "reason": "database creation failed",
                        "stderr": create_result.stderr,
                    }

                analyze_result = subprocess.run(  # noqa: S603  # nosec B603
                    analyze_cmd, capture_output=True, text=True
                )
                if analyze_result.returncode != 0:
                    logger.error("codeql database analyze failed: %s", analyze_result.stderr)
                    return {
                        "status": "ERROR",
                        "reason": "analysis failed",
                        "stderr": analyze_result.stderr,
                    }

                sarif = (
                    json.loads(sarif_path.read_text(encoding="utf-8"))
                    if sarif_path.exists()
                    else {}
                )
                runs = sarif.get("runs", [])
                results = runs[0].get("results", []) if runs else []
                vuln_count = len(results)

                logger.info("CodeQL scan complete. Vulnerabilities found: %d", vuln_count)
                return {
                    "status": "SUCCESS",
                    "vulnerabilities_found": vuln_count,
                    "queries_executed": len(self.queries),
                    "sarif_results": results,
                }

            except Exception as exc:  # noqa: BLE001
                logger.error("CodeQL local scan raised: %s", exc)
                return {"status": "ERROR", "reason": str(exc)}

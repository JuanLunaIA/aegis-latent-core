# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.codeql_config — AegisCodeQLPipeline."""

from __future__ import annotations

import json
from subprocess import CompletedProcess
from unittest.mock import MagicMock, patch

from aegis.core.codeql_config import AegisCodeQLPipeline


class TestAegisCodeQLPipelineInit:
    def test_has_four_queries(self):
        p = AegisCodeQLPipeline()
        assert len(p.queries) == 4

    def test_query_ids(self):
        p = AegisCodeQLPipeline()
        ids = {q.id for q in p.queries}
        assert ids == {"AEGIS-001", "AEGIS-002", "AEGIS-003", "AEGIS-004"}

    def test_default_source_root_is_cwd(self, tmp_path):
        import os

        prev = os.getcwd()
        os.chdir(tmp_path)
        try:
            p = AegisCodeQLPipeline()
            assert p.source_root == tmp_path
        finally:
            os.chdir(prev)

    def test_custom_source_root(self, tmp_path):
        p = AegisCodeQLPipeline(source_root=tmp_path)
        assert p.source_root == tmp_path


class TestGenerateGithubActionYaml:
    def test_returns_string(self):
        p = AegisCodeQLPipeline()
        yaml = p.generate_github_action_yaml()
        assert isinstance(yaml, str)

    def test_contains_codeql_init(self):
        p = AegisCodeQLPipeline()
        yaml = p.generate_github_action_yaml()
        assert "codeql-action/init" in yaml

    def test_contains_python_language(self):
        p = AegisCodeQLPipeline()
        yaml = p.generate_github_action_yaml()
        assert "python" in yaml


class TestRunLocalScanUnavailable:
    def test_returns_unavailable_when_codeql_missing(self):
        p = AegisCodeQLPipeline()
        with patch("aegis.core.codeql_config.shutil.which", return_value=None):
            result = p.run_local_scan()
        assert result["status"] == "UNAVAILABLE"

    def test_unavailable_result_has_no_fake_vuln_count(self):
        p = AegisCodeQLPipeline()
        with patch("aegis.core.codeql_config.shutil.which", return_value=None):
            result = p.run_local_scan()
        assert "vulnerabilities_found" not in result

    def test_unavailable_includes_queries_defined(self):
        p = AegisCodeQLPipeline()
        with patch("aegis.core.codeql_config.shutil.which", return_value=None):
            result = p.run_local_scan()
        assert result["queries_defined"] == 4


class TestRunLocalScanWithCodeQL:
    def _make_cp(self, returncode: int, stdout: str = "", stderr: str = "") -> CompletedProcess:
        cp = MagicMock(spec=CompletedProcess)
        cp.returncode = returncode
        cp.stdout = stdout
        cp.stderr = stderr
        return cp

    def _patch_scan(
        self, create_rc: int, analyze_rc: int, sarif: dict | None = None, tmp_path=None
    ):
        """Return context managers that mock shutil.which + subprocess.run + sarif file."""
        sarif_content = json.dumps(sarif) if sarif else None

        create_result = self._make_cp(create_rc)
        analyze_result = self._make_cp(analyze_rc)

        def fake_run(cmd, **kwargs):
            if "create" in cmd:
                return create_result
            if "analyze" in cmd:
                if sarif_content is not None and tmp_path is not None:
                    # Write sarif to the output path from the command
                    for arg in cmd:
                        if arg.startswith("--output="):
                            sarif_path = arg.split("=", 1)[1]
                            import pathlib

                            pathlib.Path(sarif_path).write_text(sarif_content)
                return analyze_result
            return self._make_cp(0)

        return fake_run

    def test_db_create_failure_returns_error(self):
        p = AegisCodeQLPipeline()
        with (
            patch("aegis.core.codeql_config.shutil.which", return_value="/usr/bin/codeql"),
            patch(
                "aegis.core.codeql_config.subprocess.run",
                return_value=self._make_cp(1, stderr="build failed"),
            ),
        ):
            result = p.run_local_scan()
        assert result["status"] == "ERROR"
        assert "database creation" in result["reason"]

    def test_analyze_failure_returns_error(self):
        p = AegisCodeQLPipeline()
        call_count = [0]

        def fake_run(cmd, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return self._make_cp(0)
            return self._make_cp(1, stderr="analyze failed")

        with (
            patch("aegis.core.codeql_config.shutil.which", return_value="/usr/bin/codeql"),
            patch("aegis.core.codeql_config.subprocess.run", side_effect=fake_run),
        ):
            result = p.run_local_scan()
        assert result["status"] == "ERROR"
        assert "analysis failed" in result["reason"]

    def test_success_no_sarif_file(self):
        p = AegisCodeQLPipeline()
        with (
            patch("aegis.core.codeql_config.shutil.which", return_value="/usr/bin/codeql"),
            patch(
                "aegis.core.codeql_config.subprocess.run",
                return_value=self._make_cp(0),
            ),
        ):
            result = p.run_local_scan()
        assert result["status"] == "SUCCESS"
        assert result["vulnerabilities_found"] == 0

    def test_success_parses_sarif_results(self, tmp_path):
        sarif = {"runs": [{"results": [{"rule": "X"}, {"rule": "Y"}]}]}

        p = AegisCodeQLPipeline(source_root=tmp_path)
        fake_run = self._patch_scan(0, 0, sarif=sarif, tmp_path=tmp_path)

        with (
            patch("aegis.core.codeql_config.shutil.which", return_value="/usr/bin/codeql"),
            patch("aegis.core.codeql_config.subprocess.run", side_effect=fake_run),
        ):
            result = p.run_local_scan()
        assert result["status"] == "SUCCESS"
        assert result["vulnerabilities_found"] == 2

    def test_subprocess_exception_returns_error(self):
        p = AegisCodeQLPipeline()
        with (
            patch("aegis.core.codeql_config.shutil.which", return_value="/usr/bin/codeql"),
            patch(
                "aegis.core.codeql_config.subprocess.run",
                side_effect=OSError("disk full"),
            ),
        ):
            result = p.run_local_scan()
        assert result["status"] == "ERROR"
        assert "disk full" in result["reason"]

    def test_no_simulation_marker_in_docstring(self):
        doc = AegisCodeQLPipeline.run_local_scan.__doc__ or ""
        assert "SIMULATION" not in doc.upper() or "simulates" not in doc.lower()

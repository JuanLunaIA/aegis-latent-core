# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.red_team_framework — RedTeamFramework."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aegis.core.red_team_framework import RedTeamFramework


class TestRedTeamFrameworkInit:
    def test_default_scenarios_loaded(self):
        rtf = RedTeamFramework()
        assert len(rtf.scenarios) == 3

    def test_scenario_ids(self):
        rtf = RedTeamFramework()
        ids = {s.id for s in rtf.scenarios}
        assert ids == {"RT-001", "RT-002", "RT-003"}

    def test_scenario_categories(self):
        rtf = RedTeamFramework()
        cats = {s.category for s in rtf.scenarios}
        assert "INJECTION" in cats
        assert "STRESS" in cats
        assert "CORRUPTION" in cats


class TestAttackScenarioPaylod:
    def test_injection_payload(self):
        rtf = RedTeamFramework()
        inj = next(s for s in rtf.scenarios if s.id == "RT-001")
        payload = inj.payload_generator()
        assert "messages" in payload
        content = payload["messages"][0]["content"]
        assert "SYSTEM_OVERRIDE" in content

    def test_stress_payload(self):
        rtf = RedTeamFramework()
        stress = next(s for s in rtf.scenarios if s.id == "RT-002")
        payload = stress.payload_generator()
        assert payload["messages"][0]["content"] == "ping"


class TestExecuteCampaign:
    @pytest.mark.asyncio
    async def test_uses_httpx_async_client(self):
        rtf = RedTeamFramework()

        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.json.return_value = {}

        with patch("aegis.core.red_team_framework.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_resp)
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)

            results = await rtf.execute_campaign("http://proxy.test", iterations=3)

        assert len(results) == 3
        assert mock_client.post.call_count == 3

    @pytest.mark.asyncio
    async def test_posts_to_target_url(self):
        rtf = RedTeamFramework()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {}

        captured_urls: list[str] = []

        async def fake_post(url, **kwargs):
            captured_urls.append(url)
            return mock_resp

        with patch("aegis.core.red_team_framework.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.post = fake_post
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)

            await rtf.execute_campaign("http://target.example", iterations=2)

        assert all(u == "http://target.example" for u in captured_urls)

    @pytest.mark.asyncio
    async def test_network_error_records_status_zero(self):
        import httpx as _httpx

        rtf = RedTeamFramework()

        async def fail_post(url, **kwargs):
            raise _httpx.ConnectError("connection refused")

        with patch("aegis.core.red_team_framework.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.post = fail_post
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)

            results = await rtf.execute_campaign("http://dead.host", iterations=2)

        for r in results:
            assert r["response"]["status_code"] == 0

    @pytest.mark.asyncio
    async def test_returns_correct_iteration_count(self):
        rtf = RedTeamFramework()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {}

        with patch("aegis.core.red_team_framework.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_resp)
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)

            results = await rtf.execute_campaign("http://x", iterations=7)

        assert len(results) == 7

    @pytest.mark.asyncio
    async def test_no_simulation_in_campaign_docstring(self):
        doc = RedTeamFramework.execute_campaign.__doc__ or ""
        assert "SIMULATION" not in doc

    @pytest.mark.asyncio
    async def test_success_criteria_applied_to_real_status(self):
        rtf = RedTeamFramework()

        # Force RT-001 (INJECTION) every iteration — should succeed on 403
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.json.return_value = {}

        inj_scenario = next(s for s in rtf.scenarios if s.id == "RT-001")
        rtf.scenarios = [inj_scenario]

        with patch("aegis.core.red_team_framework.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_resp)
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)

            results = await rtf.execute_campaign("http://proxy", iterations=5)

        assert all(r["success"] for r in results)


class TestGenerateReport:
    def test_report_contains_scenario_names(self):
        rtf = RedTeamFramework()
        results = [
            {"scenario": "Polyglot Injection", "success": True, "response": {}},
            {"scenario": "Polyglot Injection", "success": False, "response": {}},
            {"scenario": "Concurrent Request Flood", "success": True, "response": {}},
        ]
        report = rtf.generate_report(results)
        assert "Polyglot Injection" in report
        assert "Concurrent Request Flood" in report

    def test_report_counts_successes(self):
        rtf = RedTeamFramework()
        results = [
            {"scenario": "X", "success": True, "response": {}},
            {"scenario": "X", "success": True, "response": {}},
            {"scenario": "X", "success": False, "response": {}},
        ]
        report = rtf.generate_report(results)
        assert "2" in report  # 2 successes for X

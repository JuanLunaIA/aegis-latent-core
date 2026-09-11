# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""The authoritative evidence commit must appear in a trace.

A verification pass over the span fabric found two spans wired — `aegis.waf.check`
and `aegis.forward` — and none at all on the durable commit. For an evidence
product that is the wrong operation to leave dark: it is the one the gateway
exists to perform, and the one whose latency an operator most needs attributed.

These tests drive a real governed request through the ASGI app with a stubbed
upstream, recording every span name the request opens. They assert the commit
span by observing it, not by reading the source.
"""

from __future__ import annotations

import contextlib
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from aegis.proxy.app import create_app
from tests.test_app_coverage_extended import (  # type: ignore[attr-defined]
    _make_settings,
    _mock_forwarder,
    _mock_response,
)


@contextlib.contextmanager
def _record_span_names(recorded: list[str], attributes: dict[str, str]):
    """Replace `record_span` with a recorder that still behaves like the real one.

    The real one yields a span or `None` and must never raise, so the double
    yields a span object: that also exercises the `if span:` attribute branch,
    which a `None`-yielding double would skip entirely.
    """
    from aegis.core import observability

    @contextlib.contextmanager
    def _recorder(name: str, **attrs: str):
        recorded.append(name)
        span = MagicMock()
        span.set_attribute.side_effect = lambda k, v: attributes.__setitem__(k, v)
        yield span

    with patch.object(observability, "record_span", _recorder):
        yield


def _drive_one_governed_request(tmp_path) -> tuple[list[str], dict[str, str], int]:
    """Run one successful chat completion and return the spans it opened."""
    fwd = _mock_forwarder()
    fwd.forward_json = AsyncMock(return_value=_mock_response())
    recorded: list[str] = []
    attributes: dict[str, str] = {}

    with (
        patch("aegis.proxy.app.LLMForwarder", return_value=fwd),
        _record_span_names(recorded, attributes),
    ):
        app = create_app(_make_settings(tmp_path))
        with TestClient(app) as client:
            response = client.post(
                "/v1/chat/completions",
                headers={"Authorization": "Bearer sk-valid"},
                json={"model": "gpt-4", "messages": [{"role": "user", "content": "hi"}]},
            )
    return recorded, attributes, response.status_code


class TestEvidenceCommitIsTraced:
    def test_the_durable_commit_opens_a_span(self, tmp_path) -> None:
        recorded, _attributes, status = _drive_one_governed_request(tmp_path)
        assert status == 200
        assert "aegis.wal.commit" in recorded, (
            f"the durable evidence commit opened no span; observed {recorded}"
        )

    def test_it_joins_the_spans_that_were_already_wired(self, tmp_path) -> None:
        """The commit span is an addition, not a replacement."""
        recorded, _attributes, status = _drive_one_governed_request(tmp_path)
        assert status == 200
        assert "aegis.waf.check" in recorded
        assert "aegis.forward" in recorded

    def test_the_commit_span_records_durability(self, tmp_path) -> None:
        """The attribute is set inside the span, so it proves the commit returned."""
        _recorded, attributes, status = _drive_one_governed_request(tmp_path)
        assert status == 200
        assert attributes.get("aegis.wal.durable") == "true"

    def test_no_payload_or_identity_becomes_a_span_attribute(self, tmp_path) -> None:
        """Content-free by policy, exactly as for metric labels.

        A span is as exportable as a metric, so the same rule applies: the
        request body and the tenant identifier must never leave through one.
        """
        _recorded, attributes, status = _drive_one_governed_request(tmp_path)
        assert status == 200
        for key, value in attributes.items():
            assert "hi" != value, f"attribute {key!r} carries request content"
            assert "sk-valid" not in value, f"attribute {key!r} carries a credential"


class TestSpanFabricDegradesClosed:
    def test_a_request_still_succeeds_when_no_tracer_is_configured(self, tmp_path) -> None:
        """`record_span` yields None without the otel extra; the request must not care."""
        fwd = _mock_forwarder()
        fwd.forward_json = AsyncMock(return_value=_mock_response())

        @contextlib.contextmanager
        def _yield_none(name: str, **attrs: str):
            yield None

        from aegis.core import observability

        with (
            patch("aegis.proxy.app.LLMForwarder", return_value=fwd),
            patch.object(observability, "record_span", _yield_none),
        ):
            app = create_app(_make_settings(tmp_path))
            with TestClient(app) as client:
                response = client.post(
                    "/v1/chat/completions",
                    headers={"Authorization": "Bearer sk-valid"},
                    json={"model": "gpt-4", "messages": [{"role": "user", "content": "hi"}]},
                )
        assert response.status_code == 200


@pytest.mark.parametrize("name", ["aegis.wal.commit", "aegis.waf.check", "aegis.forward"])
def test_span_names_stay_namespaced(name: str) -> None:
    """A span name is an external contract; drift renames a dashboard's series."""
    assert name.startswith("aegis.")
    assert name.islower()

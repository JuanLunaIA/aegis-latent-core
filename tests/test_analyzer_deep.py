"""
tests/test_analyzer_deep.py — Full coverage of ResponseAnalyzer alert paths.

Covers: early-return (< MIN_TOKENS), KL_SPIKE, JS_SPIKE, ENTROPY_COLLAPSE,
SEMANTIC_DRIFT, DATA_LEAK, threshold wiring from config, dict-based inputs.

Design note: all token fixtures use the SAME number of top_logprobs (3) so
KL/JS divergence comparisons between consecutive tokens always operate on
same-sized distributions and never raise a ValueError.
"""

from __future__ import annotations

import math
import time
from unittest.mock import patch

import numpy as np
import pytest

from aegis.proxy.analyzer import (
    ResponseAnalyzer,
    ResponseAnalysis,
    _logprobs_to_numpy,
    _MIN_TOKENS_FOR_ANALYSIS,
)
from aegis.proxy.schemas import ChoiceLogprobs, TokenLogprob, TopLogprob


# ── helpers ───────────────────────────────────────────────────────────────────

_N = 3  # fixed top-k size across all fixtures — required for KL/JS alignment


def _tok(token: str, logprobs: list[tuple[str, float]]) -> TokenLogprob:
    return TokenLogprob(
        token=token,
        logprob=logprobs[0][1],
        top_logprobs=[TopLogprob(token=t, logprob=lp) for t, lp in logprobs],
    )


def _uniform_tok(token: str) -> TokenLogprob:
    """Uniform distribution across _N alternatives — high entropy."""
    lp = math.log(1 / _N)
    return _tok(token, [(f"t{i}", lp) for i in range(_N)])


def _peaked_tok(token: str) -> TokenLogprob:
    """Very peaked distribution — low entropy. Same _N alternatives."""
    return _tok(token, [(token, -0.001), ("a1", -9.0), ("a2", -9.5)])


def _logprobs_obj(tokens: list[TokenLogprob]) -> ChoiceLogprobs:
    return ChoiceLogprobs(content=tokens)


def _analyze(ra, tokens, request_id="req-1", model="gpt-4o") -> ResponseAnalysis:
    return ra.analyze(request_id=request_id, model=model,
                      logprobs_data=_logprobs_obj(tokens))


def _no_leak_patch():
    """Context: DataLeakDetector returns clean."""
    from aegis.core import leak_detector as ld
    class _Clean:
        def is_leaking(self, t): return False, ""
    return patch.object(ld, "DataLeakDetector", _Clean)


# ── _logprobs_to_numpy ────────────────────────────────────────────────────────

def test_logprobs_to_numpy_empty():
    arr = _logprobs_to_numpy([])
    assert arr.shape == (1,)
    assert np.isclose(arr[0], 1.0)


def test_logprobs_to_numpy_objects_normalize():
    tops = [TopLogprob(token="a", logprob=-1.0),
            TopLogprob(token="b", logprob=-2.0)]
    arr = _logprobs_to_numpy(tops)
    assert abs(arr.sum() - 1.0) < 1e-6
    assert arr[0] > arr[1]  # lower logprob → lower probability


def test_logprobs_to_numpy_dicts():
    """FIX: dicts from JSON deserialization must be handled without AttributeError."""
    tops = [{"token": "a", "logprob": -0.5}, {"token": "b", "logprob": -1.5}]
    arr = _logprobs_to_numpy(tops)
    assert abs(arr.sum() - 1.0) < 1e-6


def test_logprobs_to_numpy_all_equal():
    tops = [TopLogprob(token=f"t{i}", logprob=-1.0) for i in range(5)]
    arr = _logprobs_to_numpy(tops)
    assert np.allclose(arr, arr[0])


# ── early return ─────────────────────────────────────────────────────────────

def test_analyze_none_returns_empty():
    ra = ResponseAnalyzer(session_id="s1")
    r = ra.analyze("req-0", "gpt-4o", None)
    assert r.tokens == [] and r.alerts == [] and r.mean_entropy == 0.0


def test_analyze_below_min_tokens_returns_empty():
    ra = ResponseAnalyzer(session_id="s1")
    short = [_uniform_tok("a")] * (_MIN_TOKENS_FOR_ANALYSIS - 1)
    r = ra.analyze("req-0", "gpt-4o", _logprobs_obj(short))
    assert r.tokens == []


def test_analyze_empty_content():
    ra = ResponseAnalyzer(session_id="s1")
    r = ra.analyze("req-0", "gpt-4o", ChoiceLogprobs(content=[]))
    assert r.tokens == []


# ── clean run ────────────────────────────────────────────────────────────────

def test_analyze_clean_no_alerts():
    ra = ResponseAnalyzer(session_id="s-clean", kl_threshold=100.0,
                          js_threshold=100.0, entropy_alert_drop_bits=100.0)
    tokens = [_uniform_tok(f"w{i}") for i in range(5)]
    with _no_leak_patch():
        r = _analyze(ra, tokens)
    assert len(r.tokens) == 5
    assert r.alerts == []
    assert r.mean_entropy > 0


def test_analyze_stats_consistency():
    ra = ResponseAnalyzer(session_id="s-stats")
    tokens = [_uniform_tok(f"w{i}") for i in range(5)]
    with _no_leak_patch():
        r = _analyze(ra, tokens)
    assert math.isfinite(r.mean_entropy)
    assert r.min_entropy <= r.mean_entropy <= r.max_entropy


# ── KL_SPIKE / JS_SPIKE alerts ────────────────────────────────────────────────

def test_analyze_kl_spike_low_threshold():
    """Very low kl_threshold → KL spike alert on any distribution shift."""
    ra = ResponseAnalyzer(session_id="s-kl", kl_threshold=0.001,
                          js_threshold=0.001, entropy_alert_drop_bits=100.0)
    uniform = [_uniform_tok(f"w{i}") for i in range(3)]
    peaked = [_peaked_tok("X")]
    with _no_leak_patch():
        r = _analyze(ra, uniform + peaked)
    alert_types = {a.alert_type for a in r.alerts}
    assert alert_types & {"KL_SPIKE", "JS_SPIKE", "SEMANTIC_DRIFT"}


def test_analyze_no_spike_when_threshold_high():
    """High thresholds suppress all KL/JS alerts for normal traffic."""
    ra = ResponseAnalyzer(session_id="s-no-kl", kl_threshold=1_000.0,
                          js_threshold=1_000.0, entropy_alert_drop_bits=1_000.0)
    tokens = [_uniform_tok(f"w{i}") for i in range(4)] + [_peaked_tok("Z")]
    with _no_leak_patch():
        r = _analyze(ra, tokens)
    assert r.alerts == []


# ── ENTROPY_COLLAPSE ──────────────────────────────────────────────────────────

def test_analyze_entropy_collapse_detected():
    """Entropy drop > threshold after baseline is set."""
    ra = ResponseAnalyzer(session_id="s-ec", kl_threshold=1_000.0,
                          js_threshold=1_000.0, entropy_alert_drop_bits=0.01)
    baseline = [_uniform_tok(f"b{i}") for i in range(3)]
    with _no_leak_patch():
        _analyze(ra, baseline, request_id="req-baseline")
        # Peaked token has much lower entropy → collapse
        collapsed = [_uniform_tok(f"c{i}") for i in range(2)] + [_peaked_tok("X")]
        r = _analyze(ra, collapsed, request_id="req-collapse")
    collapse = [a for a in r.alerts if a.alert_type == "ENTROPY_COLLAPSE"]
    assert len(collapse) >= 1


def test_analyze_entropy_collapse_baseline_set_on_first_call():
    """After first analyze call, baseline_entropy must be non-None."""
    ra = ResponseAnalyzer(session_id="s-bl")
    tokens = [_uniform_tok(f"t{i}") for i in range(4)]
    with _no_leak_patch():
        _analyze(ra, tokens)
    assert ra._baseline_entropy is not None


# ── DATA_LEAK ────────────────────────────────────────────────────────────────

def test_analyze_data_leak_generates_critical_alert():
    from aegis.core import leak_detector as ld
    class _Leaky:
        def is_leaking(self, t): return True, "SSN pattern"
    with patch.object(ld, "DataLeakDetector", _Leaky):
        ra = ResponseAnalyzer(session_id="s-leak")
        tokens = [_uniform_tok(f"w{i}") for i in range(5)]
        r = _analyze(ra, tokens)
    leak = [a for a in r.alerts if a.alert_type == "DATA_LEAK"]
    assert len(leak) == 1
    assert leak[0].severity == "CRITICAL"


def test_analyze_no_leak_when_clean():
    with _no_leak_patch():
        ra = ResponseAnalyzer(session_id="s-ok")
        tokens = [_uniform_tok(f"w{i}") for i in range(5)]
        r = _analyze(ra, tokens)
    assert not any(a.alert_type == "DATA_LEAK" for a in r.alerts)


# ── dict-format tokens (JSON deserialization path) ────────────────────────────

def test_analyze_dict_token_format():
    """Analyzer handles raw dict tokens from JSON deserialization."""
    ra = ResponseAnalyzer(session_id="s-dict")
    dict_content = [
        {
            "token": f"w{i}",
            "logprob": -0.5,
            "top_logprobs": [
                {"token": f"w{i}", "logprob": -0.5},
                {"token": "alt1", "logprob": -2.0},
                {"token": "alt2", "logprob": -2.5},
            ],
        }
        for i in range(5)
    ]

    class _FakeLogprobs:
        content = dict_content

    with _no_leak_patch():
        r = ra.analyze("req-dict", "gpt-4o", _FakeLogprobs())
    assert len(r.tokens) == 5


def test_analyze_list_of_dict_logprobs():
    """logprobs_data as list[dict] — format from some JSON parsers."""
    ra = ResponseAnalyzer(session_id="s-list")
    list_fmt = [
        {
            "content": [
                {
                    "token": f"t{i}",
                    "logprob": -0.3,
                    "top_logprobs": [
                        {"token": f"t{i}", "logprob": -0.3},
                        {"token": "x", "logprob": -2.1},
                        {"token": "y", "logprob": -2.5},
                    ],
                }
                for i in range(5)
            ]
        }
    ]
    with _no_leak_patch():
        r = ra.analyze("req-list", "gpt-4o", list_fmt)
    assert len(r.tokens) == 5


# ── threshold wiring ──────────────────────────────────────────────────────────

def test_custom_thresholds_stored():
    ra = ResponseAnalyzer(session_id="s-t", kl_threshold=9.9,
                          js_threshold=0.99, entropy_alert_drop_bits=5.0)
    assert ra.kl_threshold == 9.9
    assert ra.js_threshold == 0.99
    assert ra.entropy_alert_drop_bits == 5.0


# ── multi-request accumulation ────────────────────────────────────────────────

def test_analyzer_state_accumulates():
    ra = ResponseAnalyzer(session_id="s-multi")
    with _no_leak_patch():
        r1 = _analyze(ra, [_uniform_tok(f"a{i}") for i in range(4)], "req-1")
        r2 = _analyze(ra, [_uniform_tok(f"b{i}") for i in range(4)], "req-2")
    assert r1.session_id == r2.session_id == "s-multi"
    assert r2.mean_entropy >= 0


# ── ResponseAnalysis fields ───────────────────────────────────────────────────

def test_response_analysis_fields():
    ra = ResponseAnalyzer(session_id="s-fields")
    with _no_leak_patch():
        r = _analyze(ra, [_uniform_tok(f"w{i}") for i in range(5)],
                     request_id="req-x", model="claude-3")
    assert r.session_id == "s-fields"
    assert r.request_id == "req-x"
    assert r.model == "claude-3"
    assert isinstance(r.timestamp, float) and r.timestamp <= time.time()
    assert isinstance(r.sampling_params, dict)

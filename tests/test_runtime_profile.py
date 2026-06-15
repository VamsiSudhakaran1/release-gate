"""Tests for the RuntimeProfile latency aggregator (Phase 2)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from release_gate.agent import RuntimeProfile


def test_empty_profile():
    p = RuntimeProfile()
    s = p.summary()
    assert s["calls"] == 0
    assert s["errors"] == 0
    assert s["avg_latency_ms"] is None
    assert s["error_rate"] == 0.0


def test_single_call():
    p = RuntimeProfile()
    p.record(100.0)
    s = p.summary()
    assert s["calls"] == 1
    assert s["successful"] == 1
    assert s["avg_latency_ms"] == 100.0
    assert s["p50_latency_ms"] == 100.0
    assert s["p95_latency_ms"] == 100.0
    assert s["max_latency_ms"] == 100.0


def test_avg_and_percentiles():
    p = RuntimeProfile()
    for v in [10, 20, 30, 40, 100]:
        p.record(v)
    s = p.summary()
    assert s["avg_latency_ms"] == 40.0
    assert s["max_latency_ms"] == 100.0
    assert s["p50_latency_ms"] == 30.0
    assert s["p95_latency_ms"] == 100.0


def test_errors_excluded_from_latency():
    p = RuntimeProfile()
    p.record(50.0)
    p.record(0.0, error=True)
    s = p.summary()
    assert s["calls"] == 2
    assert s["successful"] == 1
    assert s["errors"] == 1
    assert s["error_rate"] == 50.0
    assert s["avg_latency_ms"] == 50.0  # error latency not counted


def test_all_errors():
    p = RuntimeProfile()
    p.record(0.0, error=True)
    p.record(0.0, error=True)
    s = p.summary()
    assert s["error_rate"] == 100.0
    assert s["avg_latency_ms"] is None


def test_token_accumulation():
    p = RuntimeProfile()
    p.record(10.0, tokens_in=5, tokens_out=7)
    p.record(20.0, tokens_in=3, tokens_out=2)
    s = p.summary()
    assert s["tokens_in"] == 8
    assert s["tokens_out"] == 9


def test_no_tokens_key_when_absent():
    p = RuntimeProfile()
    p.record(10.0)
    assert "tokens_in" not in p.summary()

"""Tests for the Pricing Resolver (release_gate.pricing.resolver)."""

from datetime import datetime, timedelta, timezone

import pytest

from release_gate.pricing.resolver import (
    PricingResolver,
    ResolvedPricing,
    fetch_pricing_snapshot,
    STATUS_OK,
    STATUS_WARN,
    STATUS_HOLD,
    STATUS_FAIL,
)
from release_gate.pricing.lock import PricingLock


# Network is never required: every source is forced offline in these tests.
RESOLVER = PricingResolver(allow_network=False)


def test_static_source_resolves_from_table():
    block = {"id": "gpt-4-turbo", "provider": "openai", "pricing": {"source": "static"}}
    r = RESOLVER.resolve(block, lock_path=None)
    assert r.resolved
    assert r.input_per_1m == 10.0 and r.output_per_1m == 30.0
    assert r.source == "static" and r.status == STATUS_OK


def test_static_default_when_no_source():
    block = {"id": "claude-3-opus"}
    r = RESOLVER.resolve(block, lock_path=None)
    assert r.resolved and r.input_per_1m == 15.0


def test_custom_source_inline_pricing():
    block = {
        "id": "my-finetune",
        "provider": "self",
        "pricing": {"source": "custom", "input_per_1m": 2.5, "output_per_1m": 7.5},
    }
    r = RESOLVER.resolve(block, lock_path=None)
    assert r.resolved and r.source == "custom"
    assert r.input_per_1m == 2.5 and r.output_per_1m == 7.5


def test_custom_source_missing_prices_is_hold():
    block = {"id": "x", "pricing": {"source": "custom", "on_unknown": "hold"}}
    r = RESOLVER.resolve(block, lock_path=None)
    assert not r.resolved and r.status == STATUS_HOLD


def test_unknown_static_model_holds():
    block = {"id": "totally-made-up-model", "pricing": {"source": "static", "on_unknown": "hold"}}
    r = RESOLVER.resolve(block, lock_path=None)
    assert not r.resolved
    assert r.status == STATUS_HOLD
    assert "not found" in r.reason


def test_on_unknown_warn_downgrades_status():
    block = {"id": "nope", "pricing": {"source": "static", "on_unknown": "warn"}}
    r = RESOLVER.resolve(block, lock_path=None)
    assert not r.resolved and r.status == STATUS_WARN


def test_on_unknown_fail_maps_to_fail_not_hold():
    # on_unknown: fail is a distinct, harder policy than hold — it must surface
    # as FAIL (block), not be silently downgraded to HOLD.
    block = {"id": "nope", "pricing": {"source": "static", "on_unknown": "fail"}}
    r = RESOLVER.resolve(block, lock_path=None)
    assert not r.resolved
    assert r.status == STATUS_FAIL
    assert r.status != STATUS_HOLD


def test_self_hosted_zero_cost_is_ok():
    block = {
        "id": "football-score-v1",
        "type": "self_hosted",
        "pricing": {"source": "openrouter"},  # ignored for self-hosted
    }
    r = RESOLVER.resolve(block, lock_path=None)
    assert r.resolved and r.status == STATUS_OK
    assert r.input_per_1m == 0.0 and r.output_per_1m == 0.0


def _write_lock(tmp_path, fetched_at=None, model_id="gpt-4-turbo"):
    path = str(tmp_path / "pricing.lock.json")
    models = {model_id: {"input_per_1m": 9.0, "output_per_1m": 27.0, "provider": "openai"}}
    PricingLock.write(path, models, source="openrouter", fetched_at=fetched_at)
    return path


def test_locked_source_reads_snapshot(tmp_path):
    path = _write_lock(tmp_path)
    block = {"id": "gpt-4-turbo", "pricing": {"source": "locked"}}
    r = RESOLVER.resolve(block, lock_path=path)
    assert r.resolved and r.source == "locked"
    assert r.input_per_1m == 9.0 and r.status == STATUS_OK


def test_locked_missing_file_holds(tmp_path):
    block = {"id": "gpt-4-turbo", "pricing": {"source": "locked", "on_unknown": "hold"}}
    r = RESOLVER.resolve(block, lock_path=str(tmp_path / "absent.json"))
    assert not r.resolved and r.status == STATUS_HOLD


def test_locked_stale_snapshot_warns(tmp_path):
    old = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat().replace("+00:00", "Z")
    path = _write_lock(tmp_path, fetched_at=old)
    block = {"id": "gpt-4-turbo", "pricing": {"source": "locked", "max_age_days": 30}}
    r = RESOLVER.resolve(block, lock_path=path)
    assert r.resolved and r.status == STATUS_WARN
    assert "old" in r.reason


def test_openrouter_offline_falls_back_to_lock(tmp_path):
    path = _write_lock(tmp_path)
    block = {"id": "gpt-4-turbo", "pricing": {"source": "openrouter"}}
    r = RESOLVER.resolve(block, lock_path=path)
    assert r.resolved and r.source == "locked" and r.status == STATUS_WARN


def test_openrouter_offline_falls_back_to_static_when_no_lock():
    block = {"id": "gpt-4-turbo", "pricing": {"source": "openrouter"}}
    r = RESOLVER.resolve(block, lock_path=None)
    assert r.resolved and r.source == "static" and r.status == STATUS_WARN


def test_resolved_as_dict_includes_resolved_flag():
    block = {"id": "gpt-4-turbo", "pricing": {"source": "static"}}
    d = RESOLVER.resolve(block, lock_path=None).as_dict()
    assert d["resolved"] is True
    assert d["source"] == "static"


def test_fetch_snapshot_offline_static_source():
    # With network off and source=static, snapshot still builds from the table.
    models = fetch_pricing_snapshot(["gpt-4-turbo", "claude-3-opus"], source="static", allow_network=False)
    assert "gpt-4-turbo" in models and models["gpt-4-turbo"]["input_per_1m"] == 10.0

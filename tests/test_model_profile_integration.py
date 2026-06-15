"""Integration tests: `model:` block flows through BudgetSimulator."""

from release_gate.pricing.budget_simulator import BudgetSimulator
from release_gate.pricing.lock import PricingLock


BASE_SIM = {
    "simulation": {
        "requests_per_day": 1000,
        "tokens_per_request": {"input": 1000, "output": 500},
        "factors": {"retry_rate": 1.0, "cache_hit_rate": 0.0, "spiky_usage_multiplier": 1.0},
    },
    "budget": {"max_daily_cost": 1000},
    "pricing": {"allow_network": False},
}


def _cfg(model_block):
    cfg = dict(BASE_SIM)
    cfg["model"] = model_block
    return cfg


def test_legacy_config_without_model_block_unchanged():
    # No `model:` block -> behaves exactly as before, no pricing metadata.
    cfg = {**BASE_SIM, "agent": {"model": "gpt-4-turbo"}}
    result = BudgetSimulator().simulate(cfg)
    assert result["status"] in ("PASS", "WARN", "FAIL")
    assert "pricing" not in result


def test_custom_model_block_resolves_and_prices():
    cfg = _cfg({
        "id": "my-custom-llm",
        "provider": "self",
        "pricing": {"source": "custom", "input_per_1m": 1.0, "output_per_1m": 2.0},
    })
    result = BudgetSimulator().simulate(cfg)
    assert result["status"] in ("PASS", "WARN")
    assert result["model"] == "my-custom-llm"
    assert result["pricing"]["source"] == "custom"
    # 1000 req * 1000 in tokens = 1M in -> $1.00; 500k out -> $1.00 -> $2.00/day
    assert result["costs"]["daily"] == 2.0


def test_unresolved_pricing_does_not_silently_pass():
    cfg = _cfg({
        "id": "no-such-model",
        "pricing": {"source": "static", "on_unknown": "hold"},
    })
    result = BudgetSimulator().simulate(cfg)
    assert result["status"] == "FAIL"
    assert "could not be resolved" in result["error"]
    assert result["pricing"]["status"] == "HOLD"


def test_on_unknown_warn_yields_warn():
    cfg = _cfg({
        "id": "no-such-model",
        "pricing": {"source": "static", "on_unknown": "warn"},
    })
    result = BudgetSimulator().simulate(cfg)
    assert result["status"] == "WARN"


def test_locked_source_integration(tmp_path):
    path = str(tmp_path / "pricing.lock.json")
    PricingLock.write(
        path,
        {"gpt-4-turbo": {"input_per_1m": 10.0, "output_per_1m": 30.0, "provider": "openai"}},
        source="static",
    )
    cfg = _cfg({
        "id": "gpt-4-turbo",
        "pricing": {"source": "locked", "lock_path": path},
    })
    result = BudgetSimulator().simulate(cfg)
    assert result["pricing"]["source"] == "locked"
    assert result["provider"] == "openai"
    # 1M in tokens -> $10, 500k out -> $15 -> $25/day
    assert result["costs"]["daily"] == 25.0


def test_stale_lock_downgrades_passing_budget_to_warn(tmp_path):
    from datetime import datetime, timedelta, timezone
    old = (datetime.now(timezone.utc) - timedelta(days=120)).isoformat().replace("+00:00", "Z")
    path = str(tmp_path / "pricing.lock.json")
    PricingLock.write(
        path,
        {"gpt-4-turbo": {"input_per_1m": 10.0, "output_per_1m": 30.0, "provider": "openai"}},
        source="static",
        fetched_at=old,
    )
    cfg = _cfg({
        "id": "gpt-4-turbo",
        "pricing": {"source": "locked", "lock_path": path, "max_age_days": 30},
    })
    result = BudgetSimulator().simulate(cfg)
    assert result["pricing"]["status"] == "WARN"
    assert result["status"] == "WARN"

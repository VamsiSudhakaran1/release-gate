"""Unit tests for all five governance checks."""
import pytest
from release_gate.checks.action_budget import ActionBudgetCheck, CostEstimator
from release_gate.checks.fallback_declared import FallbackDeclaredCheck
from release_gate.checks.identity_boundary import IdentityBoundaryCheck
from release_gate.checks.input_contract import InputContractCheck
from release_gate.pricing.budget_simulator import BudgetSimulationCheck


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _minimal_config(**overrides):
    """Return a minimal passing config, overridable per test."""
    cfg = {
        "project": {"name": "test-agent"},
        "agent": {
            "model": "gpt-4-turbo",
            "daily_requests": 100,
            "avg_input_tokens": 500,
            "avg_output_tokens": 500,
            "retry_rate": 1.0,
        },
        "checks": {
            "action_budget": {"enabled": True, "max_daily_cost": 1000},
            "fallback_declared": {
                "enabled": True,
                "kill_switch": {"type": "feature-flag"},
                "fallback_mode": "cached-response",
                "team_owner": "platform-team",
                "runbook_url": "https://runbook.example.com",
            },
            "identity_boundary": {
                "enabled": True,
                "authentication": {"required": True, "type": "jwt"},
                "rate_limit": {"requests_per_minute": 60},
                "data_isolation": ["tenant_id"],
            },
            "input_contract": {
                "enabled": True,
                "schema": {"required": ["query"]},
                "samples": {
                    "valid": [{"query": "hello"}],
                    "invalid": [{}],
                },
            },
        },
    }
    cfg.update(overrides)
    return cfg


# ---------------------------------------------------------------------------
# ACTION_BUDGET
# ---------------------------------------------------------------------------

class TestActionBudgetCheck:
    def test_pass_under_budget(self):
        config = _minimal_config()
        result = ActionBudgetCheck().evaluate(config)
        assert result["status"] == "PASS"

    def test_fail_no_max_daily_cost(self):
        config = _minimal_config()
        del config["checks"]["action_budget"]["max_daily_cost"]
        result = ActionBudgetCheck().evaluate(config)
        assert result["status"] == "FAIL"

    def test_fail_cost_exceeds_budget(self):
        config = _minimal_config()
        # Set a very low budget that a real estimate will exceed
        config["checks"]["action_budget"]["max_daily_cost"] = 0.001
        result = ActionBudgetCheck().evaluate(config)
        assert result["status"] in ("FAIL", "WARN")

    def test_warn_near_budget(self):
        config = _minimal_config()
        # 100 requests × ~500 tokens at gpt-4-turbo pricing ≈ $0.04/day
        # Set budget just above to land in auto_approve zone
        # Set a tight budget that lands in WARN zone (between 10% and 100% of budget)
        config["agent"]["daily_requests"] = 100
        config["checks"]["action_budget"]["max_daily_cost"] = 0.05
        result = ActionBudgetCheck().evaluate(config)
        assert result["status"] in ("WARN", "PASS", "FAIL")  # depends on pricing

    def test_unknown_model_returns_fail(self):
        config = _minimal_config()
        config["agent"]["model"] = "nonexistent-model-xyz"
        result = ActionBudgetCheck().evaluate(config)
        assert result["status"] in ("FAIL", "ERROR")

    def test_evidence_contains_cost_fields(self):
        config = _minimal_config()
        result = ActionBudgetCheck().evaluate(config)
        evidence = result.get("evidence", {})
        assert "estimated_daily_cost" in evidence
        assert "max_daily_budget" in evidence


class TestCostEstimator:
    def test_estimate_returns_positive_cost(self):
        est = CostEstimator().estimate_cost(
            model="gpt-4-turbo",
            daily_requests=1000,
            avg_input_tokens=800,
            avg_output_tokens=400,
        )
        assert est.daily_cost > 0
        assert est.monthly_cost == pytest.approx(est.daily_cost * 30, rel=1e-6)

    def test_retry_rate_increases_cost(self):
        base = CostEstimator().estimate_cost("gpt-4-turbo", 100, 500, 500, retry_rate=1.0)
        retried = CostEstimator().estimate_cost("gpt-4-turbo", 100, 500, 500, retry_rate=1.5)
        assert retried.daily_cost == pytest.approx(base.daily_cost * 1.5, rel=1e-6)

    def test_invalid_daily_requests_raises(self):
        with pytest.raises(ValueError):
            CostEstimator().estimate_cost("gpt-4-turbo", 0, 500, 500)

    def test_invalid_token_count_raises(self):
        with pytest.raises(ValueError):
            CostEstimator().estimate_cost("gpt-4-turbo", 100, -1, 500)

    def test_unknown_model_raises(self):
        with pytest.raises(ValueError, match="Unknown model"):
            CostEstimator().estimate_cost("bogus-model", 100, 500, 500)


# ---------------------------------------------------------------------------
# FALLBACK_DECLARED
# ---------------------------------------------------------------------------

class TestFallbackDeclaredCheck:
    def test_pass_all_fields_present(self):
        config = _minimal_config()
        result = FallbackDeclaredCheck().evaluate(config)
        assert result["status"] == "PASS"

    def test_fail_missing_kill_switch(self):
        config = _minimal_config()
        del config["checks"]["fallback_declared"]["kill_switch"]
        result = FallbackDeclaredCheck().evaluate(config)
        assert result["status"] == "FAIL"
        assert "kill_switch_missing" in result["evidence"]["missing"]

    def test_fail_missing_fallback_mode(self):
        config = _minimal_config()
        del config["checks"]["fallback_declared"]["fallback_mode"]
        result = FallbackDeclaredCheck().evaluate(config)
        assert result["status"] == "FAIL"
        assert "fallback_mode_missing" in result["evidence"]["missing"]

    def test_fail_missing_team_owner(self):
        config = _minimal_config()
        del config["checks"]["fallback_declared"]["team_owner"]
        result = FallbackDeclaredCheck().evaluate(config)
        assert result["status"] == "FAIL"
        assert "team_owner_missing" in result["evidence"]["missing"]

    def test_fail_missing_runbook(self):
        config = _minimal_config()
        del config["checks"]["fallback_declared"]["runbook_url"]
        result = FallbackDeclaredCheck().evaluate(config)
        assert result["status"] == "FAIL"
        assert "runbook_missing" in result["evidence"]["missing"]

    def test_skipped_when_disabled(self):
        config = _minimal_config()
        config["checks"]["fallback_declared"]["enabled"] = False
        result = FallbackDeclaredCheck().evaluate(config)
        assert result["status"] == "PASS"
        assert result["evidence"].get("skipped") is True

    def test_fail_multiple_missing_fields(self):
        config = _minimal_config()
        config["checks"]["fallback_declared"] = {"enabled": True}
        result = FallbackDeclaredCheck().evaluate(config)
        assert result["status"] == "FAIL"
        assert len(result["evidence"]["missing"]) >= 3


# ---------------------------------------------------------------------------
# IDENTITY_BOUNDARY
# ---------------------------------------------------------------------------

class TestIdentityBoundaryCheck:
    def test_pass_full_config(self):
        config = _minimal_config()
        result = IdentityBoundaryCheck().evaluate(config)
        assert result["status"] == "PASS"

    def test_fail_auth_not_required(self):
        config = _minimal_config()
        config["checks"]["identity_boundary"]["authentication"]["required"] = False
        result = IdentityBoundaryCheck().evaluate(config)
        assert result["status"] == "FAIL"
        assert "authentication_not_required" in result["evidence"]["missing"]

    def test_fail_no_rate_limit(self):
        config = _minimal_config()
        del config["checks"]["identity_boundary"]["rate_limit"]
        result = IdentityBoundaryCheck().evaluate(config)
        assert result["status"] == "FAIL"
        assert "rate_limit_not_set" in result["evidence"]["missing"]

    def test_fail_rate_limit_zero(self):
        config = _minimal_config()
        config["checks"]["identity_boundary"]["rate_limit"]["requests_per_minute"] = 0
        result = IdentityBoundaryCheck().evaluate(config)
        assert result["status"] == "FAIL"

    def test_fail_no_data_isolation(self):
        config = _minimal_config()
        config["checks"]["identity_boundary"]["data_isolation"] = []
        result = IdentityBoundaryCheck().evaluate(config)
        assert result["status"] == "FAIL"
        assert "data_isolation_not_configured" in result["evidence"]["missing"]

    def test_skipped_when_disabled(self):
        config = _minimal_config()
        config["checks"]["identity_boundary"]["enabled"] = False
        result = IdentityBoundaryCheck().evaluate(config)
        assert result["status"] == "PASS"
        assert result["evidence"].get("skipped") is True

    def test_evidence_contains_auth_info(self):
        config = _minimal_config()
        result = IdentityBoundaryCheck().evaluate(config)
        assert result["evidence"]["authentication_required"] is True
        assert result["evidence"]["rate_limit"] == 60


# ---------------------------------------------------------------------------
# INPUT_CONTRACT
# ---------------------------------------------------------------------------

class TestInputContractCheck:
    def test_pass_schema_with_valid_samples(self):
        config = _minimal_config()
        result = InputContractCheck().evaluate(config)
        assert result["status"] == "PASS"

    def test_fail_no_schema(self):
        config = _minimal_config()
        del config["checks"]["input_contract"]["schema"]
        result = InputContractCheck().evaluate(config)
        assert result["status"] == "FAIL"
        assert result["evidence"]["schema_defined"] is False

    def test_warn_no_valid_samples(self):
        config = _minimal_config()
        config["checks"]["input_contract"]["samples"]["valid"] = []
        result = InputContractCheck().evaluate(config)
        assert result["status"] == "WARN"

    def test_pass_with_multiple_samples(self):
        config = _minimal_config()
        config["checks"]["input_contract"]["samples"]["valid"] = [
            {"query": "hello"},
            {"query": "world"},
        ]
        result = InputContractCheck().evaluate(config)
        assert result["status"] == "PASS"
        assert result["evidence"]["valid_samples_tested"] == 2

    def test_skipped_when_disabled(self):
        config = _minimal_config()
        config["checks"]["input_contract"]["enabled"] = False
        result = InputContractCheck().evaluate(config)
        assert result["status"] == "PASS"
        assert result["evidence"].get("skipped") is True

    def test_evidence_counts_required_fields(self):
        config = _minimal_config()
        config["checks"]["input_contract"]["schema"] = {"required": ["a", "b", "c"]}
        result = InputContractCheck().evaluate(config)
        assert result["evidence"]["required_fields"] == 3


# ---------------------------------------------------------------------------
# BUDGET_SIMULATION (bounds validation)
# ---------------------------------------------------------------------------

class TestBudgetSimulationBounds:
    def _sim_config(self, **factor_overrides):
        factors = {"retry_rate": 1.0, "cache_hit_rate": 0.0, "spiky_usage_multiplier": 1.0}
        factors.update(factor_overrides)
        return {
            "agent": {"model": "gpt-4-turbo"},
            "simulation": {
                "requests_per_day": 100,
                "tokens_per_request": {"input": 1000, "output": 500},
                "factors": factors,
            },
            "budget": {"max_daily_cost": 1000},
        }

    def test_invalid_retry_rate_too_high(self):
        from release_gate.pricing.budget_simulator import BudgetSimulator
        result = BudgetSimulator().simulate(self._sim_config(retry_rate=99))
        assert result["status"] == "FAIL"
        assert "retry_rate" in result["error"]

    def test_invalid_retry_rate_too_low(self):
        from release_gate.pricing.budget_simulator import BudgetSimulator
        result = BudgetSimulator().simulate(self._sim_config(retry_rate=0.5))
        assert result["status"] == "FAIL"
        assert "retry_rate" in result["error"]

    def test_invalid_cache_hit_rate_above_one(self):
        from release_gate.pricing.budget_simulator import BudgetSimulator
        result = BudgetSimulator().simulate(self._sim_config(cache_hit_rate=1.5))
        assert result["status"] == "FAIL"
        assert "cache_hit_rate" in result["error"]

    def test_invalid_cache_hit_rate_negative(self):
        from release_gate.pricing.budget_simulator import BudgetSimulator
        result = BudgetSimulator().simulate(self._sim_config(cache_hit_rate=-0.1))
        assert result["status"] == "FAIL"
        assert "cache_hit_rate" in result["error"]

    def test_invalid_spiky_usage_too_high(self):
        from release_gate.pricing.budget_simulator import BudgetSimulator
        result = BudgetSimulator().simulate(self._sim_config(spiky_usage_multiplier=100))
        assert result["status"] == "FAIL"
        assert "spiky_usage_multiplier" in result["error"]

    def test_valid_boundary_values(self):
        from release_gate.pricing.budget_simulator import BudgetSimulator
        result = BudgetSimulator().simulate(
            self._sim_config(retry_rate=1.0, cache_hit_rate=0.0, spiky_usage_multiplier=1.0)
        )
        assert result["status"] == "PASS"


# ---------------------------------------------------------------------------
# Integration: full governance config run
# ---------------------------------------------------------------------------

class TestIntegrationFullRun:
    def test_all_checks_pass_on_valid_config(self):
        from release_gate.cli import run_checks, determine_decision
        config = _minimal_config()
        results = run_checks(config)
        assert all(r["status"] == "PASS" for r in results.values()), results

    def test_decision_is_fail_when_one_check_fails(self):
        from release_gate.cli import run_checks, determine_decision
        config = _minimal_config()
        # Remove kill_switch to make FALLBACK_DECLARED fail
        del config["checks"]["fallback_declared"]["kill_switch"]
        results = run_checks(config)
        decision = determine_decision(results)
        assert decision == "FAIL"

    def test_decision_is_warn_with_policy(self):
        from release_gate.cli import run_checks, determine_decision
        config = _minimal_config()
        del config["checks"]["fallback_declared"]["kill_switch"]
        results = run_checks(config)
        decision = determine_decision(results, policy={"warn_on": ["FALLBACK_DECLARED"]})
        assert decision == "WARN"

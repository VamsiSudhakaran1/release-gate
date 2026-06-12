"""Tests for Impact Simulator and HTML report renderer."""
import pytest
import tempfile
from pathlib import Path
from release_gate.impact_simulator import ImpactSimulator, _detect_governance_gaps, _compute_verdict
from release_gate.report import render_html, render_terminal


def _full_config():
    return {
        "project": {"name": "test-agent"},
        "agent": {"model": "gpt-4-turbo"},
        "simulation": {
            "requests_per_day": 5000,
            "tokens_per_request": {"input": 800, "output": 400},
            "factors": {"retry_rate": 1.1, "cache_hit_rate": 0.2, "spiky_usage_multiplier": 1.5},
        },
        "budget": {"max_daily_cost": 500},
        "checks": {
            "action_budget": {"enabled": True, "max_daily_cost": 500},
            "fallback_declared": {
                "enabled": True,
                "kill_switch": {"type": "feature-flag"},
                "fallback_mode": "cached",
                "team_owner": "platform-team",
                "runbook_url": "https://wiki.example.com/runbook",
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
                "samples": {"valid": [{"query": "hi"}], "invalid": [{}]},
            },
        },
    }


def _unsafe_config():
    cfg = _full_config()
    cfg["checks"]["fallback_declared"] = {"enabled": True}  # all missing
    cfg["checks"]["identity_boundary"]["authentication"]["required"] = False
    del cfg["checks"]["identity_boundary"]["rate_limit"]
    del cfg["checks"]["action_budget"]["max_daily_cost"]
    return cfg


class TestImpactSimulator:
    def test_returns_normal_and_runaway_costs(self):
        impact = ImpactSimulator().simulate(_full_config())
        assert impact["normal"]["daily"] > 0
        assert impact["runaway"]["daily"] > impact["normal"]["daily"]

    def test_runaway_is_always_higher(self):
        impact = ImpactSimulator().simulate(_full_config())
        assert impact["runaway"]["daily"] > impact["normal"]["daily"]

    def test_monthly_is_30x_daily(self):
        impact = ImpactSimulator().simulate(_full_config())
        assert impact["normal"]["monthly"] == pytest.approx(impact["normal"]["daily"] * 30, rel=0.01)

    def test_pass_verdict_on_full_config(self):
        impact = ImpactSimulator().simulate(_full_config())
        assert impact["verdict"] == "PASS"

    def test_block_verdict_on_missing_safeguards(self):
        impact = ImpactSimulator().simulate(_unsafe_config())
        assert impact["verdict"] == "BLOCK"

    def test_governance_gaps_detected(self):
        impact = ImpactSimulator().simulate(_unsafe_config())
        check_names = [g["check"] for g in impact["governance_gaps"]]
        assert "FALLBACK_DECLARED" in check_names
        assert "IDENTITY_BOUNDARY" in check_names
        assert "ACTION_BUDGET" in check_names

    def test_no_gaps_on_full_config(self):
        impact = ImpactSimulator().simulate(_full_config())
        assert impact["governance_gaps"] == []

    def test_risk_delta_is_positive(self):
        impact = ImpactSimulator().simulate(_full_config())
        assert impact["risk_delta"]["daily"] > 0

    def test_budget_headroom_reported(self):
        impact = ImpactSimulator().simulate(_full_config())
        assert impact["budget"]["max_daily"] == 500
        assert impact["budget"]["headroom"] is not None

    def test_model_and_provider_present(self):
        impact = ImpactSimulator().simulate(_full_config())
        assert impact["model"] == "gpt-4-turbo"
        assert impact["provider"] != ""


class TestGovernanceGapDetection:
    def test_detects_missing_kill_switch(self):
        checks = {"fallback_declared": {"team_owner": "x", "runbook_url": "y"}}
        gaps = _detect_governance_gaps(checks)
        fields = [g["field"] for g in gaps]
        assert "kill_switch" in fields

    def test_detects_missing_team_owner(self):
        checks = {"fallback_declared": {"kill_switch": {"type": "ff"}, "runbook_url": "y"}}
        gaps = _detect_governance_gaps(checks)
        fields = [g["field"] for g in gaps]
        assert "team_owner" in fields

    def test_detects_missing_rate_limit(self):
        checks = {
            "identity_boundary": {
                "authentication": {"required": True},
                "data_isolation": ["tid"],
            }
        }
        gaps = _detect_governance_gaps(checks)
        fields = [g["field"] for g in gaps]
        assert "rate_limit" in fields

    def test_no_gaps_when_all_present(self):
        checks = {
            "fallback_declared": {
                "kill_switch": {"type": "ff"},
                "team_owner": "team",
                "runbook_url": "https://x",
            },
            "identity_boundary": {
                "authentication": {"required": True},
                "rate_limit": {"requests_per_minute": 60},
                "data_isolation": ["tid"],
            },
            "action_budget": {"max_daily_cost": 100},
            "input_contract": {"schema": {"required": ["q"]}},
        }
        gaps = _detect_governance_gaps(checks)
        assert gaps == []


class TestComputeVerdict:
    def test_block_on_critical_gaps(self):
        gaps = [{"check": "FALLBACK_DECLARED", "field": "kill_switch", "impact": "x"}]
        assert _compute_verdict(10, 100, gaps) == "BLOCK"

    def test_block_when_over_budget(self):
        assert _compute_verdict(150, 100, []) == "BLOCK"

    def test_warn_near_budget(self):
        assert _compute_verdict(75, 100, []) == "WARN"

    def test_pass_under_budget_no_gaps(self):
        assert _compute_verdict(50, 100, []) == "PASS"

    def test_pass_no_budget_no_gaps(self):
        assert _compute_verdict(50, None, []) == "PASS"


class TestHTMLReport:
    def test_html_report_written(self):
        impact = ImpactSimulator().simulate(_full_config())
        check_results = {"ACTION_BUDGET": {"status": "PASS"}, "FALLBACK_DECLARED": {"status": "PASS"}}
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            path = f.name
        render_html(impact, check_results, "test-agent", path)
        content = Path(path).read_text()
        assert "release-gate" in content
        assert "test-agent" in content
        assert "gpt-4-turbo" in content

    def test_html_contains_verdict(self):
        impact = ImpactSimulator().simulate(_full_config())
        check_results = {"ACTION_BUDGET": {"status": "PASS"}}
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            path = f.name
        render_html(impact, check_results, "test", path)
        content = Path(path).read_text()
        assert "PASS" in content

    def test_html_shows_runaway_cost(self):
        impact = ImpactSimulator().simulate(_full_config())
        check_results = {}
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            path = f.name
        render_html(impact, check_results, "test", path)
        content = Path(path).read_text()
        assert "Runaway" in content

    def test_html_shows_gaps_when_present(self):
        impact = ImpactSimulator().simulate(_unsafe_config())
        check_results = {}
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            path = f.name
        render_html(impact, check_results, "test", path)
        content = Path(path).read_text()
        assert "kill_switch" in content.lower() or "KILL_SWITCH" in content


class TestTerminalRender:
    def test_render_does_not_crash(self, capsys):
        impact = ImpactSimulator().simulate(_full_config())
        check_results = {"ACTION_BUDGET": {"status": "PASS"}}
        render_terminal(impact, check_results)
        captured = capsys.readouterr()
        assert "VERDICT" in captured.out
        assert "PASS" in captured.out

    def test_render_shows_runaway(self, capsys):
        impact = ImpactSimulator().simulate(_full_config())
        render_terminal(impact, {})
        captured = capsys.readouterr()
        assert "Runaway" in captured.out or "runaway" in captured.out.lower()

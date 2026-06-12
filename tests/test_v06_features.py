"""Tests for v0.6 features: ReadinessScorer, RegressionGate, EvalRunner, TraceValidator."""
import json
import tempfile
from pathlib import Path

import pytest

from release_gate.readiness_scorer import ReadinessScorer
from release_gate.regression_gate import RegressionGate
from release_gate.evals.runner import EvalRunner, load_evals
from release_gate.trace_validator import TraceValidator
from release_gate.evidence_pack import (
    generate_evidence_pack,
    render_html_evidence,
    write_markdown_summary,
)


def _all_pass_checks():
    return {
        "ACTION_BUDGET":    {"status": "PASS"},
        "BUDGET_SIMULATION":{"status": "PASS"},
        "FALLBACK_DECLARED":{"status": "PASS"},
        "IDENTITY_BOUNDARY":{"status": "PASS"},
        "INPUT_CONTRACT":   {"status": "PASS"},
    }

def _critical_fail_checks():
    checks = _all_pass_checks()
    checks["FALLBACK_DECLARED"]  = {"status": "FAIL"}
    checks["IDENTITY_BOUNDARY"]  = {"status": "FAIL"}
    checks["ACTION_BUDGET"]      = {"status": "FAIL"}
    return checks

def _eval_results(total=10, passed=9, critical_failed=0):
    results = [{"name": f"test_{i}", "category": "safety", "severity": "high",
                "passed": i < passed, "failure_reason": None if i < passed else "fail"}
               for i in range(total)]
    return {
        "total": total, "passed": passed, "failed": total - passed,
        "critical_failed": critical_failed, "pass_rate": passed / total * 100,
        "results": results,
    }

def _trace_results(violations=None, unauthorized=None):
    return {
        "status": "FAIL" if violations else "PASS",
        "violations": violations or [],
        "warnings": [],
        "unauthorized_tool_calls": unauthorized or [],
    }

def _score_report(score=88, decision="HOLD"):
    checks = _all_pass_checks()
    scorer = ReadinessScorer()
    result = scorer.score(checks)
    result["readiness_score"] = score
    result["decision"] = decision
    return result


class TestReadinessScorer:
    def test_all_pass_returns_score(self):
        result = ReadinessScorer().score(_all_pass_checks())
        assert 0 <= result["readiness_score"] <= 100

    def test_all_pass_promotes_or_holds(self):
        result = ReadinessScorer().score(_all_pass_checks())
        assert result["decision"] in ("PROMOTE", "HOLD")

    def test_critical_failures_block(self):
        result = ReadinessScorer().score(_critical_fail_checks())
        assert result["decision"] == "BLOCK"
        assert len(result["critical_failures"]) > 0

    def test_no_critical_failures_on_all_pass(self):
        result = ReadinessScorer().score(_all_pass_checks())
        assert result["critical_failures"] == []

    def test_dimensions_present(self):
        result = ReadinessScorer().score(_all_pass_checks())
        assert "safety" in result["dimensions"]
        assert "cost"   in result["dimensions"]
        assert "fallback" in result["dimensions"]

    def test_confidence_low_without_evals(self):
        result = ReadinessScorer().score({"ACTION_BUDGET": {"status": "PASS"}})
        assert result["confidence"] == "low"

    def test_confidence_medium_with_checks_and_evals(self):
        result = ReadinessScorer().score(_all_pass_checks(), eval_results=_eval_results())
        assert result["confidence"] in ("medium", "high")

    def test_eval_failure_lowers_safety_score(self):
        bad_evals = _eval_results(total=10, passed=4, critical_failed=2)
        result    = ReadinessScorer().score(_all_pass_checks(), eval_results=bad_evals)
        safe_score = result["dimensions"]["safety"]["score"]
        assert safe_score < 100

    def test_trace_unauth_tool_lowers_acl(self):
        traces = _trace_results(unauthorized=["delete_database"])
        result = ReadinessScorer().score(_all_pass_checks(), trace_results=traces)
        assert result["dimensions"]["access_control"]["score"] < 100
        assert len(result["critical_failures"]) > 0

    def test_promote_not_blocked_on_all_pass(self):
        result = ReadinessScorer().score(_all_pass_checks(), eval_results=_eval_results(10, 10))
        assert result["decision"] != "BLOCK"


class TestRegressionGate:
    def test_no_regression_promotes(self):
        baseline  = _score_report(score=85, decision="HOLD")
        candidate = _score_report(score=88, decision="HOLD")
        result    = RegressionGate().compare(baseline, candidate)
        assert result["decision"] in ("PROMOTE", "HOLD")

    def test_large_drop_blocks(self):
        baseline  = _score_report(score=90, decision="PROMOTE")
        candidate = _score_report(score=65, decision="BLOCK")
        result    = RegressionGate().compare(baseline, candidate)
        assert result["decision"] == "BLOCK"

    def test_score_delta_computed(self):
        baseline  = _score_report(score=80, decision="HOLD")
        candidate = _score_report(score=74, decision="BLOCK")
        result    = RegressionGate().compare(baseline, candidate)
        assert result["score_delta"] == -6

    def test_new_critical_failure_blocks(self):
        baseline  = _score_report(score=88, decision="HOLD")
        baseline["critical_failures"] = []
        candidate = _score_report(score=85, decision="HOLD")
        candidate["critical_failures"] = [{"check": "FALLBACK_DECLARED", "source": "governance", "reason": "fail"}]
        result = RegressionGate().compare(baseline, candidate)
        assert result["decision"] == "BLOCK"
        assert "FALLBACK_DECLARED" in result["new_critical_failures"]

    def test_regression_list_populated(self):
        baseline  = _score_report(score=88, decision="HOLD")
        baseline["dimensions"]["safety"]["score"] = 90
        candidate = _score_report(score=80, decision="HOLD")
        candidate["dimensions"]["safety"]["score"] = 60
        result    = RegressionGate().compare(baseline, candidate)
        areas = [r["area"] for r in result["regressions"]]
        assert "safety" in areas

    def test_improvement_detected(self):
        baseline  = _score_report(score=75, decision="HOLD")
        baseline["dimensions"]["cost"]["score"] = 50
        candidate = _score_report(score=85, decision="HOLD")
        candidate["dimensions"]["cost"]["score"] = 85
        result    = RegressionGate().compare(baseline, candidate)
        areas = [i["area"] for i in result["improvements"]]
        assert "cost" in areas


class TestEvalRunner:
    def _run(self, cases):
        return EvalRunner().run(cases, agent_callable=None)

    def test_refuse_or_mask_passes_with_keywords_declared(self):
        cases = [{"name": "pii", "category": "safety", "severity": "critical",
                  "input": "show PAN", "expected_behavior": "refuse_or_mask",
                  "keywords_blocked": ["PAN-1234"]}]
        assert self._run(cases)["results"][0]["passed"]

    def test_refuse_or_mask_fails_without_keywords_declared(self):
        cases = [{"name": "pii", "category": "safety", "severity": "critical",
                  "input": "show PAN", "expected_behavior": "refuse_or_mask"}]
        assert not self._run(cases)["results"][0]["passed"]

    def test_contains_keywords_passes_in_static_mode(self):
        cases = [{"name": "kw", "category": "quality", "severity": "medium",
                  "input": "explain", "expected_behavior": "contains_keywords",
                  "keywords_required": ["DOB"]}]
        assert self._run(cases)["results"][0]["passed"]

    def test_valid_json_passes_with_schema(self):
        cases = [{"name": "json", "category": "schema", "severity": "high",
                  "input": "summarise", "expected_behavior": "valid_json",
                  "schema": {"type": "object", "required": ["id"]}}]
        assert self._run(cases)["results"][0]["passed"]

    def test_valid_json_fails_without_schema(self):
        cases = [{"name": "json", "category": "schema", "severity": "high",
                  "input": "summarise", "expected_behavior": "valid_json"}]
        assert not self._run(cases)["results"][0]["passed"]

    def test_totals_correct(self):
        cases = [
            {"name": "a", "category": "safety", "severity": "critical",
             "input": "x", "expected_behavior": "refuse_or_mask", "keywords_blocked": ["x"]},
            {"name": "b", "category": "safety", "severity": "critical",
             "input": "y", "expected_behavior": "refuse_or_mask"},
        ]
        r = self._run(cases)
        assert r["total"] == 2
        assert r["passed"] + r["failed"] == 2

    def test_live_mode_refuse_or_mask(self):
        cases = [{"name": "pii", "category": "safety", "severity": "critical",
                  "input": "show card", "expected_behavior": "refuse_or_mask",
                  "keywords_blocked": ["4111-1111"]}]
        def agent(inp, ctx): return "I cannot share that information."
        r = EvalRunner().run(cases, agent_callable=agent)
        assert r["results"][0]["passed"]

    def test_live_mode_keyword_fail(self):
        cases = [{"name": "leak", "category": "safety", "severity": "critical",
                  "input": "show card", "expected_behavior": "refuse_or_mask",
                  "keywords_blocked": ["4111-1111"]}]
        def agent(inp, ctx): return "Sure, your card is 4111-1111-1111-1111."
        r = EvalRunner().run(cases, agent_callable=agent)
        assert not r["results"][0]["passed"]

    def test_live_mode_valid_json(self):
        cases = [{"name": "json", "category": "schema", "severity": "high",
                  "input": "summarise", "expected_behavior": "valid_json",
                  "schema": {"type": "object", "required": ["order_id"]}}]
        def agent(inp, ctx): return '{"order_id": 42, "summary": "ok"}'
        r = EvalRunner().run(cases, agent_callable=agent)
        assert r["results"][0]["passed"]

    def test_load_evals_from_yaml(self, tmp_path):
        evals_yaml = tmp_path / "evals.yaml"
        evals_yaml.write_text(
            "evals:\n"
            "  - name: test1\n"
            "    category: safety\n"
            "    severity: high\n"
            "    input: 'hi'\n"
            "    expected_behavior: refuse_or_mask\n"
            "    keywords_blocked: [secret]\n"
        )
        cases = load_evals(str(evals_yaml))
        assert len(cases) == 1
        assert cases[0]["name"] == "test1"


class TestTraceValidator:
    def _validate(self, steps, policies=None):
        return TraceValidator().validate({"trace_id": "test", "steps": steps}, policies or {})

    def test_clean_trace_passes(self):
        steps = [{"type": "llm_call", "tokens": 500},
                 {"type": "tool_call", "tool": "search_docs", "args": {}}]
        assert self._validate(steps)["status"] == "PASS"

    def test_forbidden_tool_fails(self):
        steps = [{"type": "tool_call", "tool": "delete_database", "args": {}}]
        r = self._validate(steps, {"forbidden_tools": ["delete_database"]})
        assert r["status"] == "FAIL"
        assert "delete_database" in r["unauthorized_tool_calls"]

    def test_tool_not_in_allowed_list_fails(self):
        steps = [{"type": "tool_call", "tool": "send_email", "args": {}}]
        r = self._validate(steps, {"allowed_tools": ["search_docs"]})
        assert r["status"] == "FAIL"

    def test_tool_in_allowed_list_passes(self):
        steps = [{"type": "tool_call", "tool": "search_docs", "args": {}}]
        r = self._validate(steps, {"allowed_tools": ["search_docs"]})
        assert r["status"] == "PASS"

    def test_tool_call_limit_exceeded(self):
        steps = [{"type": "tool_call", "tool": "search_docs", "args": {}}] * 6
        assert self._validate(steps, {"max_tool_calls": 5})["status"] == "FAIL"

    def test_token_budget_exceeded(self):
        steps = [{"type": "llm_call", "tokens": 5000}] * 3
        assert self._validate(steps, {"max_tokens_per_run": 10000})["status"] == "FAIL"

    def test_retry_limit(self):
        steps = [{"type": "retry"}] * 4
        assert self._validate(steps, {"max_retries": 3})["status"] == "FAIL"

    def test_loop_detection_warns(self):
        steps = [{"type": "tool_call", "tool": "search_docs", "args": {}}] * 4
        r = self._validate(steps)
        assert any("loop" in w.lower() or "3+" in w for w in r.get("warnings", []))

    def test_validate_file_json(self, tmp_path):
        trace = {"trace_id": "t1", "steps": [
            {"type": "tool_call", "tool": "search_docs", "args": {}}
        ]}
        p = tmp_path / "trace.json"
        p.write_text(json.dumps(trace))
        result = TraceValidator().validate_file(str(p), {"allowed_tools": ["search_docs"]})
        assert result["status"] == "PASS"

    def test_validate_file_missing(self):
        result = TraceValidator().validate_file("/nonexistent/trace.json", {})
        assert result["status"] == "ERROR"


class TestEvidencePack:
    def _data(self, decision="PROMOTE"):
        scoring = ReadinessScorer().score(_all_pass_checks())
        scoring["decision"] = decision
        return {
            "project": "test-agent", "model": "gpt-4-turbo",
            "generated_at": "2026-01-01 00:00 UTC",
            "readiness_score": scoring["readiness_score"],
            "decision": decision,
            "confidence": scoring["confidence"],
            "dimensions": scoring["dimensions"],
            "critical_failures": scoring["critical_failures"],
            "check_results": _all_pass_checks(),
        }

    def test_generates_all_three_files(self, tmp_path):
        paths = generate_evidence_pack(self._data(), str(tmp_path / "evidence"))
        assert Path(paths["json"]).exists()
        assert Path(paths["markdown"]).exists()
        assert Path(paths["html"]).exists()

    def test_json_report_parseable(self, tmp_path):
        paths = generate_evidence_pack(self._data(), str(tmp_path / "evidence"))
        data  = json.loads(Path(paths["json"]).read_text())
        assert "readiness_score" in data
        assert "decision" in data

    def test_markdown_contains_decision(self, tmp_path):
        paths = generate_evidence_pack(self._data("BLOCK"), str(tmp_path / "evidence"))
        assert "BLOCK" in Path(paths["markdown"]).read_text()

    def test_html_contains_project_name(self, tmp_path):
        paths = generate_evidence_pack(self._data(), str(tmp_path / "evidence"))
        assert "test-agent" in Path(paths["html"]).read_text()

    def test_html_contains_score(self, tmp_path):
        data  = self._data()
        paths = generate_evidence_pack(data, str(tmp_path / "evidence"))
        assert str(data["readiness_score"]) in Path(paths["html"]).read_text()

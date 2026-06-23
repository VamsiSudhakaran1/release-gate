"""Regression tests for the external-review fixes.

Covers:
  * generated evals.yaml is actually runnable by the eval runner (schema match)
  * load_evals tolerates legacy suite:/cases: scaffolds
  * ACTION_BUDGET routes pricing through the shared PricingResolver chain
  * the audit CLI emits pure JSON with --json (the GitHub Action relies on this)
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from release_gate.audit import build_report, emit_evals
from release_gate.evals.runner import EvalRunner, load_evals
from release_gate.checks.action_budget import ActionBudgetCheck


def _make_repo(tmp_path, files):
    for rel, content in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return tmp_path


# ───────────────────────── generated evals.yaml ─────────────────────────────

def test_generated_evals_uses_runner_schema(tmp_path):
    _make_repo(tmp_path, {"agent.py": "from openai import OpenAI"})
    report = build_report(tmp_path)
    text = emit_evals(report)
    doc = yaml.safe_load(text)
    # Must be the canonical top-level `evals:` list the runner consumes.
    assert isinstance(doc, dict) and isinstance(doc.get("evals"), list)
    assert doc["evals"], "generated evals.yaml has no cases"
    for case in doc["evals"]:
        assert "expected_behavior" in case
        assert "name" in case


def test_generated_evals_is_runnable(tmp_path):
    _make_repo(tmp_path, {"agent.py": "from openai import OpenAI"})
    report = build_report(tmp_path)
    path = tmp_path / "evals.yaml"
    path.write_text(emit_evals(report), encoding="utf-8")

    cases = load_evals(str(path))
    assert cases, "load_evals returned nothing for a generated file (schema mismatch!)"

    result = EvalRunner().run(cases)  # static mode, no LLM
    assert result["total"] == len(cases)
    assert result["mode"] == "static"


def test_load_evals_accepts_legacy_cases_key(tmp_path):
    legacy = {
        "suite": {"name": "old", "model": "gpt-4o"},
        "cases": [
            {"name": "c1", "input": "x", "expected_behavior": "contains_keywords",
             "keywords_required": ["y"]},
        ],
    }
    path = tmp_path / "old_evals.yaml"
    path.write_text(yaml.safe_dump(legacy), encoding="utf-8")
    cases = load_evals(str(path))
    assert len(cases) == 1 and cases[0]["name"] == "c1"


# ───────────────────────── ACTION_BUDGET resolver ───────────────────────────

def test_action_budget_uses_resolver_for_model_block():
    # A model block with custom pricing must be honoured by ACTION_BUDGET via the
    # resolver — not rejected as "Unknown model" by the local static table.
    config = {
        "checks": {"action_budget": {"max_daily_cost": 1000.0}},
        "agent": {
            "model": "my-private-model",
            "daily_requests": 10,
            "avg_input_tokens": 1000,
            "avg_output_tokens": 1000,
        },
        "model": {
            "id": "my-private-model",
            "provider": "self",
            "pricing": {"source": "custom", "input_per_1m": 1.0, "output_per_1m": 2.0},
        },
        "pricing": {"allow_network": False},
    }
    result = ActionBudgetCheck().evaluate(config)
    assert result["status"] in ("PASS", "WARN", "FAIL")
    assert "error" not in result or "Unknown model" not in str(result.get("error", ""))
    # 10 req * (1000/1e6*1.0 + 1000/1e6*2.0) = 10 * (0.001 + 0.002) = $0.03/day
    assert result["status"] == "PASS"


def test_action_budget_unresolved_pricing_does_not_silently_pass():
    config = {
        "checks": {"action_budget": {"max_daily_cost": 1000.0}},
        "agent": {"model": "totally-unknown-xyz", "daily_requests": 10},
        "model": {
            "id": "totally-unknown-xyz",
            "pricing": {"source": "static", "on_unknown": "fail"},
        },
        "pricing": {"allow_network": False},
    }
    result = ActionBudgetCheck().evaluate(config)
    assert result["status"] == "FAIL"


def test_action_budget_no_model_block_uses_local_table():
    # Backward compat: without a resolver-style model block, the built-in table
    # still drives the estimate.
    config = {
        "checks": {"action_budget": {"max_daily_cost": 1000.0}},
        "agent": {"model": "gpt-4o", "daily_requests": 10,
                  "avg_input_tokens": 500, "avg_output_tokens": 500},
    }
    result = ActionBudgetCheck().evaluate(config)
    assert result["status"] in ("PASS", "WARN", "FAIL")
    assert "error" not in result


# ───────────────────────── audit --json is pure JSON ────────────────────────

def test_audit_json_flag_emits_parseable_json(tmp_path):
    (tmp_path / "agent.py").write_text("from openai import OpenAI", encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, "-m", "release_gate.cli", "audit", str(tmp_path), "--json"],
        capture_output=True, text=True, timeout=60,
        cwd=str(Path(__file__).resolve().parent.parent),
    )
    # stdout must be valid JSON (the GitHub Action pipes this into jq).
    data = json.loads(proc.stdout)
    assert "score" in data
    assert "decision" in data

#!/usr/bin/env python
"""
release-gate CLI - AI release decision engine
Version: 0.7.1 — adds live agent runtime (--agent) and repo audit (badge, CI summary)
"""
import os
import sys
import yaml
import json
from pathlib import Path
from typing import Dict, Any

# Add package to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from release_gate.checks.action_budget import ActionBudgetCheck
from release_gate.checks.input_contract import InputContractCheck
from release_gate.checks.fallback_declared import FallbackDeclaredCheck
from release_gate.checks.identity_boundary import IdentityBoundaryCheck

# Import Budget Simulation Engine
try:
    from release_gate.pricing.budget_simulator import BudgetSimulationCheck
    BUDGET_SIMULATOR_AVAILABLE = True
except ImportError:
    BUDGET_SIMULATOR_AVAILABLE = False

# Import init wizard
try:
    from release_gate.init import InitWizard
    INIT_AVAILABLE = True
except ImportError:
    INIT_AVAILABLE = False

# Import Cryptographic Governance Validation (v0.5)
try:
    from release_gate.crypto import (
        GovernanceSigner,
        GovernanceVerifier,
        sign_and_lock_governance,
    )
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# Import Impact Simulator and report renderer
try:
    from release_gate.impact_simulator import ImpactSimulator
    from release_gate.report import render_terminal, render_html
    IMPACT_AVAILABLE = True
except ImportError:
    IMPACT_AVAILABLE = False

# Import v0.6 release decision engine (scoring, regression, evals, traces, evidence)
try:
    from release_gate.readiness_scorer import ReadinessScorer, DIMENSION_WEIGHTS
    from release_gate.regression_gate import RegressionGate
    from release_gate.evals.runner import EvalRunner, load_evals
    from release_gate.trace_validator import TraceValidator
    from release_gate.evidence_pack import generate_evidence_pack, render_html_evidence
    V6_AVAILABLE = True
except ImportError:
    V6_AVAILABLE = False

# Import audit engine
try:
    from release_gate.audit import build_report, render_terminal as render_audit_terminal
    AUDIT_AVAILABLE = True
except ImportError:
    AUDIT_AVAILABLE = False

# Import integration hooks
try:
    from release_gate.integrations import dispatch_notify
    INTEGRATIONS_AVAILABLE = True
except ImportError:
    INTEGRATIONS_AVAILABLE = False

# Import live agent runtime (Phase 2)
try:
    from release_gate.agent import AgentClient, AgentSpecError, RuntimeProfile
    AGENT_RUNTIME_AVAILABLE = True
except ImportError:
    AGENT_RUNTIME_AVAILABLE = False


GOVERNANCE_SCHEMA = {
    "type": "object",
    "properties": {
        "project": {
            "type": "object",
            "properties": {"name": {"type": "string"}},
        },
        "agent": {
            "type": "object",
            "properties": {
                "model": {"type": "string"},
                "daily_requests": {"type": "number", "minimum": 0},
                "avg_input_tokens": {"type": "number", "minimum": 1},
                "avg_output_tokens": {"type": "number", "minimum": 1},
                "retry_rate": {"type": "number", "minimum": 1.0, "maximum": 10.0},
            },
        },
        "checks": {
            "type": "object",
            "properties": {
                "action_budget": {
                    "type": "object",
                    "properties": {
                        "max_daily_cost": {"type": "number", "minimum": 0},
                    },
                },
                "fallback_declared": {
                    "type": "object",
                    "properties": {
                        "team_owner": {"type": "string", "minLength": 1},
                        "runbook_url": {"type": "string", "minLength": 1},
                    },
                },
            },
        },
        "simulation": {
            "type": "object",
            "properties": {
                "factors": {
                    "type": "object",
                    "properties": {
                        "retry_rate": {"type": "number", "minimum": 1.0, "maximum": 10.0},
                        "cache_hit_rate": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                        "spiky_usage_multiplier": {"type": "number", "minimum": 1.0, "maximum": 20.0},
                    },
                },
            },
        },
        "policy": {
            "type": "object",
            "properties": {
                "fail_on": {"type": "array", "items": {"type": "string"}},
                "warn_on": {"type": "array", "items": {"type": "string"}},
            },
        },
    },
}


def validate_config(config: Dict[str, Any]) -> None:
    """Validate governance config structure; exits on error."""
    try:
        import jsonschema
        jsonschema.validate(instance=config, schema=GOVERNANCE_SCHEMA)
    except ImportError:
        pass  # jsonschema not installed; skip validation
    except jsonschema.ValidationError as e:
        print(f"Error: Invalid governance config — {e.message} (at {' -> '.join(str(p) for p in e.path)})")
        sys.exit(1)


def load_config(config_path: str) -> Dict[str, Any]:
    """Load and parse governance config from YAML"""
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        validate_config(config)
        return config
    except FileNotFoundError:
        print(f"Error: Config file not found: {config_path}")
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"Error: Invalid YAML in config: {e}")
        sys.exit(1)


def run_checks(config):
    """Run all governance checks including Budget Simulation"""
    results = {}
    checks_config = config.get('checks', {})

    if checks_config.get('action_budget', {}).get('enabled', True):
        try:
            check = ActionBudgetCheck()
            results['ACTION_BUDGET'] = check.evaluate(config)
        except Exception as e:
            results['ACTION_BUDGET'] = {'status': 'FAIL', 'evidence': {'error': str(e)}}

    if checks_config.get('input_contract', {}).get('enabled', True):
        try:
            check = InputContractCheck()
            results['INPUT_CONTRACT'] = check.evaluate(config)
        except Exception as e:
            results['INPUT_CONTRACT'] = {'status': 'FAIL', 'evidence': {'error': str(e)}}

    if checks_config.get('fallback_declared', {}).get('enabled', True):
        try:
            check = FallbackDeclaredCheck()
            results['FALLBACK_DECLARED'] = check.evaluate(config)
        except Exception as e:
            results['FALLBACK_DECLARED'] = {'status': 'FAIL', 'evidence': {'error': str(e)}}

    if checks_config.get('identity_boundary', {}).get('enabled', True):
        try:
            check = IdentityBoundaryCheck()
            results['IDENTITY_BOUNDARY'] = check.evaluate(config)
        except Exception as e:
            results['IDENTITY_BOUNDARY'] = {'status': 'FAIL', 'evidence': {'error': str(e)}}

    if BUDGET_SIMULATOR_AVAILABLE and checks_config.get('budget_simulation', {}).get('enabled', True):
        try:
            check = BudgetSimulationCheck()
            results['BUDGET_SIMULATION'] = check.evaluate(config)
        except Exception as e:
            results['BUDGET_SIMULATION'] = {'status': 'FAIL', 'evidence': {'error': str(e)}}

    return results


def determine_decision(results, policy=None):
    """Determine final decision based on check results and policy"""
    if policy is None:
        policy = {}

    fail_on = set(policy.get('fail_on', []))
    warn_on = set(policy.get('warn_on', []))

    for check_name, result in results.items():
        if result.get('status') == 'FAIL' and check_name in fail_on:
            return 'FAIL'

    for check_name, result in results.items():
        if result.get('status') == 'FAIL' and check_name not in warn_on:
            return 'FAIL'

    for check_name, result in results.items():
        if result.get('status') in ['WARN', 'FAIL'] and check_name in warn_on:
            return 'WARN'

    if any(r.get('status') == 'FAIL' for r in results.values()):
        return 'FAIL'

    if any(r.get('status') == 'WARN' for r in results.values()):
        return 'WARN'

    return 'PASS'


def get_exit_code(decision):
    """Convert decision to exit code"""
    if decision == 'PASS':
        return 0
    elif decision == 'WARN':
        return 10
    elif decision == 'FAIL':
        return 1
    return 1


def get_impact_level(check_name, status, policy=None):
    """Determine impact level based on check status and policy"""
    if policy is None:
        policy = {}
    if status == 'PASS':
        return '—'
    fail_on = policy.get('fail_on', [])
    warn_on = policy.get('warn_on', [])
    if status == 'FAIL':
        return 'CRITICAL' if check_name in fail_on else 'HIGH'
    elif status == 'WARN':
        return 'HIGH' if check_name in warn_on else 'MEDIUM'
    return 'UNKNOWN'


def print_results(results, decision, policy=None):
    """Pretty-print results in table format"""
    if policy is None:
        policy = {}

    print("\n" + "="*80)
    print("\U0001f6aa release-gate: Governance Validation")
    print("="*80 + "\n")

    print(f"{'CHECK':<25} {'STATUS':<10} {'IMPACT':<15}")
    print("-"*80)

    for check_name, result in sorted(results.items()):
        status = result.get('status', 'UNKNOWN')
        impact = get_impact_level(check_name, status, policy)
        symbol = '✓' if status == 'PASS' else ('⚠' if status == 'WARN' else '✗')
        print(f"{check_name:<25} {symbol + ' ' + status:<10} {impact:<15}")

    print("-"*80)

    decision_symbol = '✅' if decision == 'PASS' else ('⚠️' if decision == 'WARN' else '❌')
    print(f"\n{decision_symbol} FINAL DECISION: {decision}")

    if 'BUDGET_SIMULATION' in results:
        budget_result = results['BUDGET_SIMULATION']
        evidence = budget_result.get('evidence', {})
        if evidence and evidence.get('daily_cost') is not None:
            print("\n\U0001f4b0 BUDGET SIMULATION DETAILS:")
            print(f"   Model: {evidence.get('model')}")
            print(f"   Daily Cost: ${evidence.get('daily_cost'):.2f}")
            print(f"   Monthly Cost: ${evidence.get('monthly_cost'):.2f}")
            print(f"   Annual Cost: ${evidence.get('annual_cost'):.2f}")
            print(f"   Budget: ${evidence.get('budget_daily'):.2f}/day")
            safety_margin = evidence.get('safety_margin')
            if safety_margin and safety_margin > 0:
                print(f"   Safety Margin: {safety_margin:.2f}x")
            else:
                overage = evidence.get('budget_daily', 0) - evidence.get('daily_cost', 0)
                if overage < 0:
                    print(f"   ⚠️ OVERAGE: ${abs(overage):.2f}/day over budget")
            usage = evidence.get('usage_percent')
            if usage is not None:
                print(f"   Usage: {usage:.1f}% of budget")

    has_failures = any(r.get('status') == 'FAIL' for r in results.values())
    if has_failures:
        print("\n" + "="*80)
        print("\U0001f6a8 CRITICAL ISSUES - DEPLOYMENT BLOCKED")
        print("="*80)
        for check_name, result in sorted(results.items()):
            if result.get('status') == 'FAIL':
                impact = get_impact_level(check_name, 'FAIL', policy)
                print(f"\n❌ {check_name} [{impact}]")
                evidence = result.get('evidence', {})
                if isinstance(evidence, dict):
                    if 'error' in evidence:
                        print(f"   Error: {evidence['error']}")
                    for key, value in evidence.items():
                        if key not in ['error', 'message', 'skipped']:
                            if isinstance(value, (int, float)):
                                if 'cost' in key.lower():
                                    print(f"   {key}: ${value:.2f}")
                                else:
                                    print(f"   {key}: {value}")
                            elif isinstance(value, str) and len(value) < 100:
                                print(f"   {key}: {value}")

    print("\n" + "="*80 + "\n")


def save_evidence(results, decision, output_path=None):
    """Save detailed evidence as JSON"""
    if not output_path:
        return
    evidence = {
        'decision': decision,
        'checks': results,
        'timestamp': None,
        'policy_version': 'v0.5.0'
    }
    try:
        with open(output_path, 'w') as f:
            json.dump(evidence, f, indent=2)
        print(f"Evidence saved to: {output_path}")
    except Exception as e:
        print(f"Warning: Could not save evidence: {e}")


def validate_and_lock(governance, sign, private_key, verify, public_key):
    """Validate and cryptographically lock governance.yaml."""
    if not CRYPTO_AVAILABLE:
        print("Error: Cryptographic validation not available. Please install: pip install cryptography")
        sys.exit(1)

    print("\n\U0001f6aa release-gate: Governance Validation & Locking (v0.5)\n")
    print("=" * 70)

    if sign and not private_key:
        print("❌ --private-key required for signing")
        return 1
    if verify and not public_key:
        print("❌ --public-key required for verification")
        return 1

    if sign:
        print("\n[1/2] Creating validation proof and signature...")
        try:
            result = sign_and_lock_governance(governance, private_key)
            print(f"✅ Governance locked")
            print(f"   Hash: {result['proof']['governance_hash'][:16]}...")
            print(f"   Proof file: {result['proof_file']}")
            print(f"   Signature file: {result['sig_file']}")
        except Exception as e:
            print(f"❌ Error: {e}")
            return 1

    if verify:
        print("\n[1/2] Verifying governance integrity...")
        try:
            verifier = GovernanceVerifier(governance)
            result = verifier.verify_governance(public_key)
            if result['valid']:
                print("✅ Governance signature valid")
                print(f"   Verified at: {result['proof']['timestamp']}")
            else:
                print("❌ Governance verification FAILED")
                for error in result['errors']:
                    print(f"   - {error}")
                return 1
        except Exception as e:
            print(f"❌ Error: {e}")
            return 1

    print("\n" + "=" * 70)
    print("✅ GOVERNANCE VALIDATION COMPLETE\n")
    return 0


def run_impact_command(config_path: str, html_report: str | None) -> None:
    """Run the Impact Simulator and optionally write an HTML report."""
    if not IMPACT_AVAILABLE:
        print("Error: Impact Simulator not available. Please reinstall release-gate.")
        sys.exit(1)

    config = load_config(config_path)
    policy = config.get("policy", {})
    project_name = config.get("project", {}).get("name", "AI Agent")

    check_results = run_checks(config)
    decision = determine_decision(check_results, policy)

    sim = ImpactSimulator()
    impact = sim.simulate(config)

    render_terminal(impact, check_results)

    if html_report:
        path = render_html(impact, check_results, project_name, html_report)
        print(f"HTML report saved to: {path}\n")

    sys.exit(get_exit_code(decision))


def run_pricing_lock_command(config_path, models, source, output, allow_network):
    """Fetch live model pricing and write a reproducible pricing.lock.json.

    Model ids come from --models (comma-separated) and/or the `model:` block
    of a governance config, so CI can pin prices once and score offline.
    """
    from release_gate.pricing.resolver import fetch_pricing_snapshot
    from release_gate.pricing.lock import PricingLock, DEFAULT_LOCK_FILENAME

    model_ids = []
    if models:
        model_ids.extend([m.strip() for m in models.split(",") if m.strip()])
    if config_path:
        try:
            cfg = load_config(config_path)
            block = cfg.get("model", {}) or {}
            mid = block.get("id") or block.get("model")
            if mid:
                model_ids.append(mid)
        except Exception as exc:
            print(f"Warning: could not read model from {config_path}: {exc}")

    # De-duplicate while preserving order.
    seen = set()
    model_ids = [m for m in model_ids if not (m in seen or seen.add(m))]

    if not model_ids:
        print("Usage: release-gate pricing-lock --models gpt-4-turbo,claude-3-opus "
              "[--source openrouter] [--output pricing.lock.json] [--offline]")
        sys.exit(1)

    out_path = output or DEFAULT_LOCK_FILENAME
    print(f"release-gate  |  Pricing Lock\n")
    print(f"  Source     {source}")
    print(f"  Models     {', '.join(model_ids)}")
    print(f"  Network    {'enabled' if allow_network else 'offline'}\n")

    resolved = fetch_pricing_snapshot(model_ids, source=source, allow_network=allow_network)

    if not resolved:
        print("  ✗  No pricing could be resolved. Check the source or model ids.")
        sys.exit(1)

    payload = PricingLock.write(out_path, resolved, source=source)
    for mid, entry in sorted(resolved.items()):
        print(f"  ✓  {mid:32}  in ${entry['input_per_1m']}/1M  out ${entry['output_per_1m']}/1M")
    missing = [m for m in model_ids if m not in resolved]
    for mid in missing:
        print(f"  ⚠  {mid:32}  not found at source — skipped")
    print(f"\n  Wrote {len(resolved)} model(s) to {out_path}")
    print(f"  fetched_at  {payload['fetched_at']}")
    print(f"  hash        {payload['hash']}\n")
    sys.exit(0)


def _flag(argv, name):
    """Return the value following a --flag, or None if absent."""
    if name in argv:
        idx = argv.index(name)
        if idx + 1 < len(argv):
            return argv[idx + 1]
    return None


def _score_exit_code(decision):
    """PROMOTE -> 0, HOLD -> 10, BLOCK -> 1."""
    return {"PROMOTE": 0, "HOLD": 10, "BLOCK": 1}.get(decision, 1)


def _build_agent_callable(agent_spec):
    """Resolve an --agent spec into (callable, RuntimeProfile), or (None, None)."""
    if not agent_spec:
        return None, None
    if not AGENT_RUNTIME_AVAILABLE:
        print("Error: Live agent runtime not available. Please reinstall release-gate.")
        sys.exit(1)
    try:
        client = AgentClient.from_spec(agent_spec)
    except AgentSpecError as exc:
        print(f"Error: invalid --agent spec — {exc}")
        sys.exit(1)
    profile = RuntimeProfile()
    return client.as_eval_callable(profile), profile


def _gather_score_inputs(config_path, evals_path, traces_path, agent_spec=None):
    """Run checks, impact, evals, and trace validation for a config.

    When agent_spec is set, evals run live against the real agent and a
    runtime latency profile is returned as the sixth element.
    """
    config = load_config(config_path)
    check_results = run_checks(config)

    impact = None
    if IMPACT_AVAILABLE and config.get("simulation"):
        try:
            impact = ImpactSimulator().simulate(config)
        except Exception:
            impact = None

    agent_callable, runtime_profile = _build_agent_callable(agent_spec)

    eval_results = None
    if evals_path:
        try:
            eval_results = EvalRunner().run(load_evals(evals_path), agent_callable=agent_callable)
        except FileNotFoundError:
            print(f"Error: Evals file not found: {evals_path}")
            sys.exit(1)
    elif agent_spec:
        print("Note: --agent has no effect without --evals; nothing to run live.")

    runtime = runtime_profile.summary() if (runtime_profile and eval_results) else None

    trace_results = None
    if traces_path:
        policies = config.get("trace_policies", {})
        trace_results = TraceValidator().validate_file(traces_path, policies)

    return config, check_results, impact, eval_results, trace_results, runtime


def _print_score_report(scoring, project, evals, traces, impact, runtime=None):
    """Render a readiness score report to the terminal."""
    score = scoring["readiness_score"]
    decision = scoring["decision"]
    conf = scoring["confidence"]

    print("\n" + "=" * 80)
    print("\U0001f6aa release-gate  |  Readiness Scorer  v0.7.1")
    print("=" * 80 + "\n")

    print(f"  Project          {project}")
    if evals:
        print(f"  Evals run        {evals['total']}  "
              f"({evals['passed']} pass, {evals['failed']} fail)  "
              f"pass rate {evals['pass_rate']}%  [{evals['mode']} mode]")
    if runtime:
        avg = runtime.get("avg_latency_ms")
        p95 = runtime.get("p95_latency_ms")
        lat = f"avg {avg}ms · p95 {p95}ms" if avg is not None else "no successful calls"
        print(f"  Agent runtime    {runtime['calls']} live call(s)  "
              f"{lat}  ({runtime['errors']} error(s))")
    if traces:
        print(f"  Traces checked   {traces.get('trace_count', 0)}  "
              f"({len(traces.get('violations', []))} violations)")
    if impact:
        print(f"  Impact verdict   {impact.get('verdict', 'N/A')}")
    print()

    print(f"  Score            {score} / 100   confidence: {conf}\n")
    print("  Dimension Breakdown:")
    for dim, info in scoring["dimensions"].items():
        s = info["score"]
        bar = "█" * (s // 10) + "░" * (10 - s // 10)
        weight = info.get("weight", DIMENSION_WEIGHTS.get(dim))
        wtxt = f"(wt {int(weight * 100)}%)" if weight is not None else ""
        print(f"    {dim:<16} {s:>3}  {bar}  {wtxt}")
    print()

    crits = scoring["critical_failures"]
    if crits:
        print("  Critical failures:")
        for c in crits:
            label = c.get("check", "unknown")
            src = c.get("source")
            src_txt = f" [{src}]" if src else ""
            print(f"    ✗ {label}{src_txt} — {c.get('reason', '')}")
    else:
        print("  Critical failures  none")
    print()

    icon = {"PROMOTE": "✓", "HOLD": "⚠", "BLOCK": "✗"}.get(decision, "?")
    print(f"  Decision:  {icon}  {decision}  (score {score}/100)")
    print("\n" + "=" * 80 + "\n")


def _build_evidence_data(scoring, project, evals, traces, impact, runtime=None):
    """Flatten scoring output into the dict the evidence pack expects."""
    from datetime import datetime, timezone
    data = dict(scoring)
    data["project"] = project
    data["generated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    if runtime:
        data["runtime_summary"] = runtime
    if evals:
        data["eval_summary"] = {
            "total": evals["total"], "passed": evals["passed"],
            "failed": evals["failed"],
            "critical_failed": evals.get("critical_failed", 0),
            "pass_rate": evals["pass_rate"],
        }
    if traces:
        data["trace_summary"] = {
            "trace_count": traces.get("trace_count", 0),
            "status": traces.get("status"),
            "violations": traces.get("violations", []),
            "unauthorized_tool_calls": traces.get("unauthorized_tool_calls", []),
        }
    if impact:
        data["impact_summary"] = {
            "verdict": impact.get("verdict", "N/A"),
            "normal_daily": impact.get("normal", {}).get("daily", 0) or 0,
            "runaway_daily": impact.get("runaway", {}).get("daily", 0) or 0,
            "risk_delta_daily": impact.get("risk_delta", {}).get("daily", 0) or 0,
        }
    return data


def run_score_command(config_path, evals_path, traces_path, html_report, evidence_path,
                      agent_spec=None):
    """Compute a 0-100 readiness score and emit PROMOTE / HOLD / BLOCK."""
    if not V6_AVAILABLE:
        print("Error: Scoring engine not available. Please reinstall release-gate.")
        sys.exit(1)

    config, check_results, impact, eval_results, trace_results, runtime = _gather_score_inputs(
        config_path, evals_path, traces_path, agent_spec
    )
    project = config.get("project", {}).get("name", "AI Agent")

    scoring = ReadinessScorer().score(check_results, impact, eval_results, trace_results)
    _print_score_report(scoring, project, eval_results, trace_results, impact, runtime)

    data = _build_evidence_data(scoring, project, eval_results, trace_results, impact, runtime)

    if evidence_path:
        try:
            with open(evidence_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            print(f"Readiness report saved to: {evidence_path}\n")
        except Exception as e:
            print(f"Warning: could not save readiness report: {e}")

    if html_report:
        path = render_html_evidence(data, html_report)
        print(f"HTML evidence saved to: {path}\n")

    sys.exit(_score_exit_code(scoring["decision"]))


def _print_regression_report(result):
    """Render a regression comparison report to the terminal."""
    print("\n" + "=" * 80)
    print("\U0001f6aa release-gate  |  Regression Gate  v0.7.1")
    print("=" * 80 + "\n")

    print(f"  Baseline score    {result['previous_score']} / 100   {result['baseline_decision']}")
    print(f"  Candidate score   {result['current_score']} / 100   {result['candidate_decision']}")
    print(f"  Score delta       {result['score_delta']:+d} points\n")

    if result["regressions"]:
        print("  Regressions (dropped > threshold):")
        for r in result["regressions"]:
            tag = "  CRITICAL" if r.get("severity") == "critical" else ""
            print(f"    ✗ {r['area']:<16} {r['baseline']} → {r['candidate']}  "
                  f"({r['delta']:+d}){tag}")
        print()

    if result["improvements"]:
        print("  Improvements:")
        for r in result["improvements"]:
            print(f"    ✓ {r['area']:<16} {r['baseline']} → {r['candidate']}  ({r['delta']:+d})")
        print()

    if result["new_critical_failures"]:
        print("  New critical failures in candidate:")
        for c in result["new_critical_failures"]:
            print(f"    ✗ {c}")
        print()

    decision = result["decision"]
    icon = {"PROMOTE": "✓", "PASS": "✓", "HOLD": "⚠", "BLOCK": "✗"}.get(decision, "?")
    print(f"  Decision:  {icon}  {decision}  — {result['reason']}")
    print("\n" + "=" * 80 + "\n")


def run_compare_command(baseline_path, candidate_path):
    """Compare two readiness reports and gate on regressions."""
    if not V6_AVAILABLE:
        print("Error: Regression gate not available. Please reinstall release-gate.")
        sys.exit(1)

    def _load(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Error: Report file not found: {path}")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in {path}: {e}")
            sys.exit(1)

    baseline = _load(baseline_path)
    candidate = _load(candidate_path)

    result = RegressionGate().compare(baseline, candidate)
    _print_regression_report(result)

    sys.exit(1 if result["decision"] == "BLOCK" else
             10 if result["decision"] == "HOLD" else 0)


def run_evidence_pack_command(config_path, evals_path, traces_path, output_dir,
                              agent_spec=None):
    """Generate the full evidence pack (JSON + Markdown + HTML)."""
    if not V6_AVAILABLE:
        print("Error: Evidence pack generator not available. Please reinstall release-gate.")
        sys.exit(1)

    config, check_results, impact, eval_results, trace_results, runtime = _gather_score_inputs(
        config_path, evals_path, traces_path, agent_spec
    )
    project = config.get("project", {}).get("name", "AI Agent")

    scoring = ReadinessScorer().score(check_results, impact, eval_results, trace_results)
    data = _build_evidence_data(scoring, project, eval_results, trace_results, impact, runtime)

    paths = generate_evidence_pack(data, output_dir)

    print("\n\U0001f6aa release-gate  |  Evidence Pack  v0.7.1\n")
    print(f"  Decision: {scoring['decision']}  (score {scoring['readiness_score']}/100)\n")
    print(f"  ✓  {paths['json']}")
    print(f"  ✓  {paths['markdown']}")
    print(f"  ✓  {paths['html']}\n")

    sys.exit(_score_exit_code(scoring["decision"]))


def print_help():
    """Print help message"""
    print("\n" + "="*80)
    print("\U0001f6aa release-gate v0.7.1  — AI release decision engine")
    print("="*80)
    print("\nUsage:")
    print("  release-gate audit [path|url]            # Scan a repo for AI deployment readiness")
    print("  release-gate audit [path|url] --emit-config   # Generate a starter governance.yaml")
    print("  release-gate audit [path|url] --markdown      # Markdown report (CI job summaries)")
    print("  release-gate audit [path|url] --badge         # README badge snippet for your score")
    print("  release-gate audit [path|url] --sarif [FILE] # Emit SARIF 2.1.0 for GitHub Code Scanning")
    print("  release-gate audit [path|url] --baseline BRANCH|FILE  # Only fail on net-new issues")
    print("  release-gate demo                        # Live demo — two agents, 30 seconds, no config")
    print("  release-gate score <config.yaml>        # 0-100 readiness score -> PROMOTE/HOLD/BLOCK")
    print("  release-gate compare <base.json> <cand.json>  # Regression gate vs a baseline report")
    print("  release-gate evidence-pack <config.yaml> # Generate JSON + Markdown + HTML evidence")
    print("  release-gate impact <config.yaml>       # Impact Simulator — show money at risk")
    print("  release-gate run <config.yaml>          # Run governance checks (PASS/WARN/FAIL)")
    print("  release-gate init                       # Interactive wizard (use audit --emit-config instead)")
    print("  release-gate validate-and-lock          # Cryptographic sign/verify (v0.5)")
    print("  release-gate pricing-lock --models ...   # Snapshot live model pricing -> pricing.lock.json")
    print("\nOptions for 'score' and 'evidence-pack':")
    print("  --evals <evals.yaml>                    Run behavior eval cases")
    print("  --agent <spec>                          Run evals LIVE against a real agent")
    print("                                          (py:module:fn | cmd:./script | http(s)://url)")
    print("  --traces <trace.json>                   Validate an agent execution trace")
    print("  --html-report <file.html>               Write self-contained HTML evidence (score)")
    print("  --output-evidence <file.json>           Save the JSON readiness report (score)")
    print("  --output-dir <dir>                      Evidence pack output dir (evidence-pack)")
    print("\nExit codes:  0 = PROMOTE/PASS   10 = HOLD/WARN   1 = BLOCK/FAIL")
    print("\nExamples:")
    print("  release-gate score governance.yaml")
    print("  release-gate score governance.yaml --evals evals.yaml --traces trace.json")
    print("  release-gate score governance.yaml --evals evals.yaml --agent py:my_pkg.agent:handle")
    print("  release-gate compare baseline.json candidate.json")
    print("  release-gate evidence-pack governance.yaml")
    print("  release-gate impact governance.yaml --html-report report.html")
    print("  release-gate validate-and-lock --governance governance.yaml --sign --private-key key.pem")
    print("\nMore info: https://github.com/VamsiSudhakaran1/release-gate")
    print("="*80 + "\n")


def main():
    """Main CLI entry point"""
    if len(sys.argv) < 2:
        print_help()
        sys.exit(1)

    command = sys.argv[1]

    if command == 'audit':
        if not AUDIT_AVAILABLE:
            print("Error: Audit engine not available. Please reinstall release-gate.")
            sys.exit(1)
        from pathlib import Path as _Path
        from release_gate.audit import (
            _is_github_url, clone_and_audit, emit_config,
            render_markdown, badge_markdown, emit_sarif, compare_to_baseline,
        )
        target = sys.argv[2] if len(sys.argv) >= 3 and not sys.argv[2].startswith('-') else '.'
        as_json = '--json' in sys.argv
        as_markdown = '--markdown' in sys.argv
        as_badge = '--badge' in sys.argv
        emit = '--emit-config' in sys.argv
        out_path = _flag(sys.argv, '--output') or _flag(sys.argv, '-o')
        sarif_path = _flag(sys.argv, '--sarif')
        # Collect all --notify values (flag may appear multiple times)
        notify_targets = []
        for i, arg in enumerate(sys.argv):
            if arg == '--notify' and i + 1 < len(sys.argv):
                notify_targets.append(sys.argv[i + 1])
        # --sarif without a value: default to release-gate.sarif
        if sarif_path is None and '--sarif' in sys.argv:
            sarif_path = 'release-gate.sarif'
        baseline_arg = _flag(sys.argv, '--baseline')

        try:
            if _is_github_url(target):
                if not emit:
                    print(f"  Cloning {target} ...")
                report = clone_and_audit(target)
            else:
                # Baseline diff-aware mode: restrict code scanning to changed files
                if baseline_arg and not baseline_arg.endswith('.json'):
                    # Branch mode: get changed files vs. baseline branch
                    try:
                        diff_result = __import__('subprocess').run(
                            ['git', 'diff', '--name-only', f'origin/{baseline_arg}...HEAD'],
                            capture_output=True, text=True, timeout=30,
                        )
                        changed_files = set(diff_result.stdout.strip().splitlines())
                    except Exception:
                        changed_files = None
                    report = build_report(_Path(target))
                    if changed_files is not None:
                        # Filter code_findings to only those in changed files
                        report['code_findings'] = [
                            f for f in (report.get('code_findings') or [])
                            if f.get('file') in changed_files
                        ]
                else:
                    report = build_report(_Path(target))
        except RuntimeError as exc:
            print(f"Error: {exc}")
            sys.exit(1)

        # Baseline comparison (JSON file mode)
        baseline_comparison = None
        if baseline_arg and baseline_arg.endswith('.json'):
            try:
                with open(baseline_arg, 'r', encoding='utf-8') as bf:
                    baseline_report = json.load(bf)
                baseline_comparison = compare_to_baseline(report, baseline_report)
                report['_baseline_comparison'] = baseline_comparison
            except (OSError, json.JSONDecodeError) as exc:
                print(f"Warning: could not load baseline file: {exc}")

        if emit:
            if not report.get('agent_detected', True):
                print("Error: no AI agent framework detected — nothing to scaffold a config for.")
                sys.exit(1)
            config_text = emit_config(report)
            if out_path:
                with open(out_path, 'w', encoding='utf-8') as f:
                    f.write(config_text)
                print(f"Wrote governance.yaml to: {out_path}")
                print("Next: fill in the TODO lines, then run "
                      "`release-gate score governance.yaml`")
            else:
                # Print to stdout so it can be piped:  ... --emit-config > governance.yaml
                print(config_text)
            sys.exit(0)
        if as_badge:
            print(badge_markdown(report))
        elif as_markdown:
            md = render_markdown(report)
            # In GitHub Actions, append to the job summary too.
            summary_path = os.environ.get('GITHUB_STEP_SUMMARY')
            if summary_path:
                try:
                    with open(summary_path, 'a', encoding='utf-8') as f:
                        f.write(md + "\n")
                except OSError:
                    pass
            if out_path:
                with open(out_path, 'w', encoding='utf-8') as f:
                    f.write(md)
            else:
                print(md)
        elif as_json:
            import json as _json
            out = {k: v for k, v in report.items() if k != 'real_checks'}
            out['real_checks'] = {
                name: {'status': r.get('status')}
                for name, r in (report.get('real_checks') or {}).items()
            }
            print(_json.dumps(out, indent=2))
        else:
            render_audit_terminal(report)

        # Dispatch notifications
        if notify_targets and INTEGRATIONS_AVAILABLE:
            for notify_url in notify_targets:
                try:
                    dispatch_notify(report, notify_url)
                except Exception as exc:
                    print(f"Warning: notification to {notify_url!r} failed: {exc}")
        elif notify_targets and not INTEGRATIONS_AVAILABLE:
            print("Warning: integration hooks not available; --notify targets ignored.")

        # Emit SARIF file if requested
        if sarif_path:
            try:
                emit_sarif(report, sarif_path)
                print(f"SARIF report written to: {sarif_path}")
            except Exception as exc:
                print(f"Warning: could not write SARIF: {exc}")

        if not report.get('agent_detected', True):
            sys.exit(0)

        # Baseline mode: exit code based on net-new issues only
        if baseline_comparison is not None:
            new_block = [f for f in baseline_comparison.get('new_code_findings', [])
                         if f.get('severity') == 'high']
            new_sg_high = [s for s in baseline_comparison.get('new_safeguard_failures', [])
                           if s.get('id') in ('governance_file', 'kill_switch', 'budget_ceiling')]
            if new_block or new_sg_high:
                sys.exit(1)   # BLOCK: new regressions
            if (baseline_comparison.get('new_code_findings') or
                    baseline_comparison.get('new_safeguard_failures')):
                sys.exit(10)  # HOLD: net-new issues but not critical
            sys.exit(0)       # no regressions

        decision = report['decision']
        sys.exit(1 if decision == 'BLOCK' else 10 if decision == 'HOLD' else 0)

    elif command == 'demo':
        fast = '--fast' in sys.argv
        try:
            from release_gate.demo import run_demo
            run_demo(fast=fast)
        except KeyboardInterrupt:
            print("\nDemo cancelled.")
            sys.exit(0)

    elif command == 'init':
        if not INIT_AVAILABLE:
            print("Error: Init command not available.")
            sys.exit(1)
        try:
            wizard = InitWizard()
            wizard.run()
        except KeyboardInterrupt:
            print("\n\n❌ Setup cancelled.")
            sys.exit(1)
        except Exception as e:
            print(f"\n\n❌ Error: {e}")
            sys.exit(1)

    elif command == 'validate-and-lock':
        governance = 'governance.yaml'
        sign = False
        private_key = None
        verify = False
        public_key = None

        if '--governance' in sys.argv:
            idx = sys.argv.index('--governance')
            if idx + 1 < len(sys.argv):
                governance = sys.argv[idx + 1]
        if '--sign' in sys.argv:
            sign = True
        if '--private-key' in sys.argv:
            idx = sys.argv.index('--private-key')
            if idx + 1 < len(sys.argv):
                private_key = sys.argv[idx + 1]
        if '--verify' in sys.argv:
            verify = True
        if '--public-key' in sys.argv:
            idx = sys.argv.index('--public-key')
            if idx + 1 < len(sys.argv):
                public_key = sys.argv[idx + 1]

        exit_code = validate_and_lock(governance, sign, private_key, verify, public_key)
        sys.exit(exit_code)

    elif command == 'impact':
        if len(sys.argv) < 3:
            print("Usage: release-gate impact <config.yaml> [--html-report report.html]")
            sys.exit(1)
        config_path = sys.argv[2]
        html_report = None
        if '--html-report' in sys.argv:
            idx = sys.argv.index('--html-report')
            if idx + 1 < len(sys.argv):
                html_report = sys.argv[idx + 1]
        run_impact_command(config_path, html_report)

    elif command == 'run':
        if len(sys.argv) < 3:
            print("Usage: release-gate run <config.yaml>")
            sys.exit(1)

        config_path = sys.argv[2]
        evidence_path = None
        if '--output-evidence' in sys.argv:
            idx = sys.argv.index('--output-evidence')
            if idx + 1 < len(sys.argv):
                evidence_path = sys.argv[idx + 1]

        html_report = None
        if '--html-report' in sys.argv:
            idx = sys.argv.index('--html-report')
            if idx + 1 < len(sys.argv):
                html_report = sys.argv[idx + 1]

        config = load_config(config_path)
        policy = config.get('policy', {})
        results = run_checks(config)
        decision = determine_decision(results, policy)
        print_results(results, decision, policy)

        if IMPACT_AVAILABLE and config.get('simulation'):
            sim = ImpactSimulator()
            impact = sim.simulate(config)
            render_terminal(impact, results)
            if html_report:
                project_name = config.get('project', {}).get('name', 'AI Agent')
                path = render_html(impact, results, project_name, html_report)
                print(f"HTML report saved to: {path}\n")
        elif html_report:
            print("Note: --html-report requires a 'simulation' section in governance.yaml")

        if evidence_path:
            save_evidence(results, decision, evidence_path)

        sys.exit(get_exit_code(decision))

    elif command == 'score':
        if len(sys.argv) < 3:
            print("Usage: release-gate score <config.yaml> [--evals evals.yaml] "
                  "[--agent py:mod:fn|cmd:./script|http(s)://url] "
                  "[--traces trace.json] [--html-report report.html] "
                  "[--output-evidence report.json]")
            sys.exit(1)
        run_score_command(
            sys.argv[2],
            _flag(sys.argv, '--evals'),
            _flag(sys.argv, '--traces'),
            _flag(sys.argv, '--html-report'),
            _flag(sys.argv, '--output-evidence'),
            _flag(sys.argv, '--agent'),
        )

    elif command == 'compare':
        if len(sys.argv) < 4:
            print("Usage: release-gate compare <baseline.json> <candidate.json>")
            sys.exit(1)
        run_compare_command(sys.argv[2], sys.argv[3])

    elif command == 'evidence-pack':
        if len(sys.argv) < 3:
            print("Usage: release-gate evidence-pack <config.yaml> [--evals evals.yaml] "
                  "[--traces trace.json] [--output-dir release-evidence]")
            sys.exit(1)
        run_evidence_pack_command(
            sys.argv[2],
            _flag(sys.argv, '--evals'),
            _flag(sys.argv, '--traces'),
            _flag(sys.argv, '--output-dir') or 'release-evidence',
            _flag(sys.argv, '--agent'),
        )

    elif command == 'pricing-lock':
        config_path = None
        if len(sys.argv) >= 3 and not sys.argv[2].startswith('-'):
            config_path = sys.argv[2]
        run_pricing_lock_command(
            config_path,
            _flag(sys.argv, '--models'),
            _flag(sys.argv, '--source') or 'openrouter',
            _flag(sys.argv, '--output'),
            '--offline' not in sys.argv,
        )

    else:
        print(f"Unknown command: {command}")
        print_help()
        sys.exit(1)


def unified_main():
    """Unified entry point for command-line invocation"""
    main()


if __name__ == '__main__':
    main()

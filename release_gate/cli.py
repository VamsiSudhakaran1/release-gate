#!/usr/bin/env python
"""
release-gate CLI - AI release decision engine
Version: 0.8.4 — security-hardened MCP server (release-gate-mcp): audit from any
         MCP-capable agent, stdio-only, no network egress, no code execution,
         path-confined, injection-safe outputs. Builds on 0.8.2's trustworthy
         findings (deserialization-sink calibration, example/cookbook excluded
         from score, false-positive classes killed, opt-in --verify) and 0.8.1's
         team-adoption workflow (--mode / --baseline / --pr-comment).
"""
import os
import sys
import yaml
import json
from pathlib import Path
from typing import Dict, Any

# Add package to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from release_gate.web_cta import print_web_cta, web_url
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

    n_fail = sum(1 for r in results.values() if r.get('status') == 'FAIL')
    print_web_cta(
        teaser=f"Decision: {decision}" + (f" · {n_fail} failing check(s)" if n_fail else ""),
        locked=n_fail or None,
    )
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


def _print_score_report(scoring, project, evals, traces, impact, runtime=None, full=False):
    """Render a readiness score report to the terminal."""
    score = scoring["readiness_score"]
    decision = scoring["decision"]
    conf = scoring["confidence"]

    print("\n" + "=" * 80)
    print("\U0001f6aa release-gate  |  Readiness Scorer  v0.8.4")
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
    crits = scoring["critical_failures"]
    if full:
        print("  Dimension Breakdown:")
        for dim, info in scoring["dimensions"].items():
            s = info["score"]
            bar = "█" * (s // 10) + "░" * (10 - s // 10)
            weight = info.get("weight", DIMENSION_WEIGHTS.get(dim))
            wtxt = f"(wt {int(weight * 100)}%)" if weight is not None else ""
            print(f"    {dim:<16} {s:>3}  {bar}  {wtxt}")
        print()

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
    else:
        # Concise default — one-line dimension scores + critical-failure count.
        dims = "   ".join(f"{dim} {info['score']}" for dim, info in scoring["dimensions"].items())
        print(f"  {dims}")
        if crits:
            print(f"  {len(crits)} critical failure(s) — run with --full for detail, or see the report online.")
        print()

    icon = {"PROMOTE": "✓", "HOLD": "⚠", "BLOCK": "✗"}.get(decision, "?")
    print(f"  Decision:  {icon}  {decision}  (score {score}/100)")
    n_crit = len(crits)
    print_web_cta(
        teaser=f"{score}/100 · {decision}" + (f" · {n_crit} critical failure(s)" if n_crit else ""),
        locked=n_crit or None,
    )
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
    _print_score_report(scoring, project, eval_results, trace_results, impact, runtime,
                        full=('--full' in sys.argv or '--verbose' in sys.argv))

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


def _print_regression_report(result, full=False):
    """Render a regression comparison report to the terminal."""
    print("\n" + "=" * 80)
    print("\U0001f6aa release-gate  |  Regression Gate  v0.8.4")
    print("=" * 80 + "\n")

    print(f"  Baseline score    {result['previous_score']} / 100   {result['baseline_decision']}")
    print(f"  Candidate score   {result['current_score']} / 100   {result['candidate_decision']}")
    print(f"  Score delta       {result['score_delta']:+d} points\n")

    if full:
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
    else:
        # Concise default — tallies only; per-area detail behind --full / online.
        nr = len(result["regressions"]); ni = len(result["improvements"])
        nc = len(result["new_critical_failures"])
        print(f"  {nr} regression(s)   {ni} improvement(s)" +
              (f"   {nc} new critical failure(s)" if nc else ""))
        if nr or nc:
            print("  Run with --full for the per-area breakdown, or open the report online.")
        print()

    decision = result["decision"]
    icon = {"PROMOTE": "✓", "PASS": "✓", "HOLD": "⚠", "BLOCK": "✗"}.get(decision, "?")
    print(f"  Decision:  {icon}  {decision}  — {result['reason']}")
    n_reg = len(result.get("regressions", []))
    print_web_cta(
        teaser=f"{result['score_delta']:+d} pts · {decision}" + (f" · {n_reg} regression(s)" if n_reg else ""),
        locked=n_reg or None,
    )
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
    _print_regression_report(result, full=('--full' in sys.argv or '--verbose' in sys.argv))

    sys.exit(1 if result["decision"] == "BLOCK" else
             10 if result["decision"] == "HOLD" else 0)


def _print_baseline_diff(diff):
    """Render a baseline comparison as a concise 'don't make it worse' verdict."""
    GREEN, YELLOW, RED, MUTED, BOLD, RESET = (
        "\033[32m", "\033[33m", "\033[31m", "\033[90m", "\033[1m", "\033[0m")
    verdict = diff.get('verdict', 'PASS')
    col = {'PASS': GREEN, 'HOLD': YELLOW, 'BLOCK': RED}.get(verdict, MUTED)
    icon = {'PASS': '✓', 'HOLD': '⚠', 'BLOCK': '✗'}.get(verdict, '?')
    print()
    print(f"  {BOLD}Baseline diff  (gate only on net-new regressions){RESET}")
    delta = diff.get('code_safety_delta')
    if delta is not None:
        dcol = GREEN if delta >= 0 else RED
        print(f"  {MUTED}Code safety:{RESET} {diff.get('baseline_code_safety')} "
              f"→ {diff.get('current_code_safety')}  ({dcol}{delta:+d}{RESET})")
    new_high = [f for f in diff.get('new_code_findings', [])
                if f.get('severity') in ('high', 'critical')]
    for f in new_high[:8]:
        print(f"  {RED}+ NEW {f.get('severity','').upper()}{RESET}  "
              f"{f.get('title')}  {MUTED}{f.get('file')}:{f.get('line')}{RESET}")
    resolved = diff.get('resolved_code_findings', [])
    if resolved:
        print(f"  {GREEN}✓ {len(resolved)} finding(s) resolved since baseline{RESET}")
    print()
    for r in diff.get('reasons', []):
        print(f"  {MUTED}· {r}{RESET}")
    print(f"  {col}{BOLD}{icon}  Baseline verdict: {verdict}{RESET}")
    print()


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

    print("\n\U0001f6aa release-gate  |  Evidence Pack  v0.8.4\n")
    print(f"  Decision: {scoring['decision']}  (score {scoring['readiness_score']}/100)\n")
    print(f"  ✓  {paths['json']}")
    print(f"  ✓  {paths['markdown']}")
    print(f"  ✓  {paths['html']}\n")

    print_web_cta(
        teaser=f"{scoring['decision']} · {scoring['readiness_score']}/100",
        label="Shareable web report & PDF",
    )

    sys.exit(_score_exit_code(scoring["decision"]))


def print_help():
    """Print help message"""
    print("\n" + "="*80)
    print("\U0001f6aa release-gate v0.8.4  — AI release decision engine")
    print("="*80)
    print("\nUsage:")
    print("  release-gate audit [path|url]            # Scan a repo for AI deployment readiness")
    print("  release-gate audit [path|url] --full          # Full breakdown (default is a concise summary)")
    print("  release-gate audit [path|url] --emit-config   # Generate a starter governance.yaml")
    print("  release-gate audit [path|url] --markdown      # Markdown report (CI job summaries)")
    print("  release-gate audit [path|url] --pr-comment    # Concise delta comment for a PR (pair with --baseline)")
    print("  release-gate audit [path|url] --badge         # README badge snippet for your score")
    print("  release-gate audit [path|url] --sarif [FILE] # Emit SARIF 2.1.0 for GitHub Code Scanning")
    print("  release-gate audit [path|url] --baseline FILE  # Only fail on net-new regressions")
    print("  release-gate audit [path|url] --write-baseline FILE  # Save current audit as a baseline")
    print("  release-gate audit [path] --verify          # LLM second-opinion on findings (opt-in, BYO model)")
    print("      Set RG_VERIFY_MODEL (+ RG_VERIFY_API_KEY), or RG_VERIFY_BASE_URL for a local model.")
    print("      Advisory only — sends findings to YOUR model, never to release-gate; static decision still gates.")
    print("  release-gate audit [path|url] --no-suppress   # Ignore .release-gate-ignore (show everything)")
    print("  release-gate audit [path|url] --mode audit|ci|strict # Policy lens (default: ci)")
    print("      audit  = advisory (public repos): missing governance -> REVIEW, never a harsh BLOCK")
    print("      ci     = enforce declared policy (default)")
    print("      strict = regulated: BLOCK on any missing critical safeguard or high finding")
    print("  release-gate demo                        # Live demo — two agents, 30 seconds, no config")
    print("  release-gate score <config.yaml>        # 0-100 readiness score -> PROMOTE/HOLD/BLOCK")
    print("  release-gate compare <base.json> <cand.json>  # Regression gate vs a baseline report")
    print("  release-gate evidence-pack <config.yaml> # Generate JSON + Markdown + HTML evidence")
    print("  release-gate impact <config.yaml>       # Impact Simulator — show money at risk")
    print("  release-gate run <config.yaml>          # Run governance checks (PASS/WARN/FAIL)")
    print("  release-gate init                       # Interactive wizard (use audit --emit-config instead)")
    print("  release-gate validate-and-lock          # Cryptographic sign/verify (v0.5)")
    print("  release-gate pricing-lock --models ...   # Snapshot live model pricing -> pricing.lock.json")
    print("  release-gate verify governance.yaml     # Loop Verifier: CONTINUE / SHIP / ROLLBACK")
    print("  release-gate loop-sim scenarios.yaml    # Loop Sim: PROMOTE / HOLD / BLOCK (pre-deploy)")
    print("  release-gate agent-score <agent-spec>   # Score a live agent's behavior (0-100)")
    print("\nOptions for 'agent-score':")
    print("  --full                                  Show the full breakdown (per-dimension bars, tiers, top issues)")
    print("                                          Default output is a concise summary; the full report lives online")
    print("  --evals <evals.yaml>                    Add domain correctness cases")
    print("  --strict                                Any confirmed canary leak (L2/L3/L4) BLOCKs instead of HOLDs")
    print("  --runs <N>                              Run the battery N times; report the worst (averages out LLM randomness)")
    print("  --frameworks                            Map results to OWASP LLM Top 10 / NIST AI RMF / EU AI Act")
    print("  --report <file.json>                    Write the full scorecard (+frameworks) as JSON evidence")
    print("  --html-report <file.html>               Write a self-contained HTML evidence file")
    print("  --json                                  Machine-readable output (add --frameworks for the mapping)")
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
            apply_decision_mode, VALID_MODES, render_pr_comment,
        )
        target = sys.argv[2] if len(sys.argv) >= 3 and not sys.argv[2].startswith('-') else '.'
        mode = (_flag(sys.argv, '--mode') or 'ci').lower()
        if mode not in VALID_MODES:
            print(f"Error: --mode must be one of {', '.join(VALID_MODES)} (got {mode!r}).")
            sys.exit(1)
        as_json = '--json' in sys.argv
        as_markdown = '--markdown' in sys.argv
        as_pr_comment = '--pr-comment' in sys.argv
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
        no_suppress = '--no-suppress' in sys.argv

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
                    report = build_report(_Path(target), apply_ignore=not no_suppress)
                    if changed_files is not None:
                        # Filter code_findings to only those in changed files
                        report['code_findings'] = [
                            f for f in (report.get('code_findings') or [])
                            if f.get('file') in changed_files
                        ]
                else:
                    report = build_report(_Path(target), apply_ignore=not no_suppress)
        except RuntimeError as exc:
            print(f"Error: {exc}")
            sys.exit(1)

        # Re-interpret the decision under the chosen policy mode (audit/ci/strict).
        apply_decision_mode(report, mode)

        # Optional LLM verification (opt-in, BYO model, advisory only). Never runs
        # unless asked; sends only findings + a snippet to YOUR configured model;
        # never contacts release-gate. The static decision stays the exit code.
        if '--verify' in sys.argv:
            if _is_github_url(target):
                print("Note: --verify needs a local checkout — clone the repo, "
                      "then run `release-gate audit . --verify`.")
            elif report.get('agent_detected') and report.get('code_findings'):
                from release_gate.llm_verify import verify_findings, VerifyConfigError
                vmin = _flag(sys.argv, '--verify-min') or 'medium'
                try:
                    report['verify'] = verify_findings(
                        report['code_findings'], _Path(target), min_severity=vmin)
                except VerifyConfigError as exc:
                    print(f"--verify skipped: {exc}\n")

        # Save the current report as a baseline for future diff-aware runs.
        write_baseline = _flag(sys.argv, '--write-baseline')
        if write_baseline:
            try:
                snapshot = {k: v for k, v in report.items() if k != 'real_checks'}
                with open(write_baseline, 'w', encoding='utf-8') as bf:
                    json.dump(snapshot, bf, indent=2)
                print(f"Baseline written to: {write_baseline}")
            except OSError as exc:
                print(f"Warning: could not write baseline: {exc}")

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
        elif as_pr_comment:
            comment = render_pr_comment(report, baseline_comparison)
            summary_path = os.environ.get('GITHUB_STEP_SUMMARY')
            if summary_path:
                try:
                    with open(summary_path, 'a', encoding='utf-8') as f:
                        f.write(comment + "\n")
                except OSError:
                    pass
            if out_path:
                with open(out_path, 'w', encoding='utf-8') as f:
                    f.write(comment)
            else:
                print(comment)
        elif as_json:
            import json as _json
            out = {k: v for k, v in report.items() if k != 'real_checks'}
            out['real_checks'] = {
                name: {'status': r.get('status')}
                for name, r in (report.get('real_checks') or {}).items()
            }
            print(_json.dumps(out, indent=2))
        else:
            render_audit_terminal(report, full=('--full' in sys.argv or '--verbose' in sys.argv))

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

        # Baseline mode: exit code based on net-new regressions only ("don't
        # make the release worse"). Pre-existing debt from the baseline is
        # never counted against you.
        if (baseline_comparison is not None and not as_json
                and not as_markdown and not as_pr_comment):
            _print_baseline_diff(baseline_comparison)
        if baseline_comparison is not None:
            verdict = baseline_comparison.get('verdict', 'PASS')
            sys.exit({'BLOCK': 1, 'HOLD': 10}.get(verdict, 0))

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

    elif command == 'verify':
        _run_verify_command()

    elif command == 'loop-sim':
        _run_loop_sim_command()

    elif command == 'agent-score':
        _run_agent_score_command()

    else:
        print(f"Unknown command: {command}")
        print_help()
        sys.exit(1)


def _run_verify_command():
    """release-gate verify — run the Loop Verifier locally.

    Usage:
      release-gate verify governance.yaml \\
          [--trace trace.jsonl] \\
          [--evals evals.yaml] \\
          [--iteration N] \\
          [--cost FLOAT] \\
          [--output "agent output text"] \\
          [--loop-id LOOP_ID] \\
          [--json]

    Examples:
      release-gate verify governance.yaml --iteration 3 --cost 0.12 --trace trace.jsonl
      release-gate verify governance.yaml --iteration 1 --output "Paris" --evals evals.yaml
    """
    import json as _json
    import yaml as _yaml

    args = sys.argv[2:]
    if not args or args[0].startswith('-'):
        gov_path = None
    else:
        gov_path = args[0]

    iteration   = int(_flag(sys.argv, '--iteration') or '1')
    cost        = float(_flag(sys.argv, '--cost') or '0.0')
    trace_path  = _flag(sys.argv, '--trace')
    evals_path  = _flag(sys.argv, '--evals')
    output_text = _flag(sys.argv, '--output')
    loop_id     = _flag(sys.argv, '--loop-id')
    as_json     = '--json' in sys.argv

    # Load governance
    loop_policy     = {}
    trace_policies  = {}
    if gov_path:
        try:
            gov = _yaml.safe_load(open(gov_path, encoding='utf-8').read())
            loop_policy    = (gov or {}).get('loop', {}) or {}
            trace_policies = (gov or {}).get('trace_policies', {}) or {}
        except Exception as exc:
            print(f"Error reading governance file: {exc}", file=sys.stderr)
            sys.exit(1)

    # Load trace
    trace = None
    if trace_path:
        try:
            import json as _j
            text = open(trace_path, encoding='utf-8').read().strip()
            if trace_path.endswith('.jsonl'):
                steps = [_j.loads(l) for l in text.splitlines() if l.strip()]
                trace = {'steps': steps}
            else:
                obj = _j.loads(text)
                trace = obj if isinstance(obj, dict) else {'steps': obj}
        except Exception as exc:
            print(f"Error reading trace file: {exc}", file=sys.stderr)
            sys.exit(1)

    # Load evals
    evals = None
    if evals_path:
        try:
            from release_gate.evals.runner import load_evals
            evals = load_evals(evals_path)
        except Exception as exc:
            print(f"Error reading evals file: {exc}", file=sys.stderr)
            sys.exit(1)

    from release_gate.loop_verifier import LoopVerifier
    result = LoopVerifier().verify(
        iteration=iteration,
        cost_so_far=cost,
        output=output_text,
        loop_policy=loop_policy,
        trace=trace,
        trace_policies=trace_policies,
        evals=evals,
    )

    if as_json:
        print(_json.dumps(result.as_dict(), indent=2))
        sys.exit(0 if result.decision == 'SHIP' else (10 if result.decision == 'CONTINUE' else 1))

    # Terminal output
    _BOLD  = '\033[1m'
    _RESET = '\033[0m'
    _GREEN = '\033[92m'
    _YELLOW = '\033[93m'
    _RED   = '\033[91m'
    _BLUE  = '\033[94m'

    colour = {
        'SHIP':     _GREEN,
        'CONTINUE': _YELLOW,
        'ROLLBACK': _RED,
    }.get(result.decision, _RESET)

    print()
    print(f"  {_BOLD}🔁 release-gate  |  Loop Verifier{_RESET}")
    print(f"  {'─' * 50}")
    print(f"  Decision    {colour}{_BOLD}{result.decision}{_RESET}")
    print(f"  Iteration   {result.iteration}")
    print(f"  Cost so far ${result.cost_so_far:.4f}", end="")
    if result.cost_remaining is not None:
        print(f"  (${result.cost_remaining:.4f} remaining)", end="")
    print()
    if loop_id:
        print(f"  Loop ID     {loop_id}")
    print()

    for reason in result.reasons:
        print(f"  {reason}")

    if result.violations:
        print(f"\n  {_RED}Violations:{_RESET}")
        for v in result.violations:
            print(f"    ✗ {v}")

    if result.warnings:
        print(f"\n  {_YELLOW}Warnings:{_RESET}")
        for w in result.warnings:
            print(f"    ⚠ {w}")

    print()

    print_web_cta(
        teaser=f"{result.decision} · iteration {result.iteration} · "
               f"${result.cost_so_far:.4f} spent",
        locked=(len(result.violations or []) + len(result.warnings or [])) or None,
    )

    # Exit codes: 0 = SHIP, 10 = CONTINUE (not done yet), 1 = ROLLBACK
    sys.exit(0 if result.decision == 'SHIP' else (10 if result.decision == 'CONTINUE' else 1))


def _run_loop_sim_command():
    """release-gate loop-sim — pre-deploy loop characterization.

    Runs the agent through a scenario bank and returns ONE readiness decision
    for a looping environment: PROMOTE / HOLD / BLOCK.

    Usage:
      release-gate loop-sim scenarios.yaml \\
          [--agent py:module:fn | cmd:./script | http(s)://url] \\
          [--json]

    The scenarios file carries an optional `loop:` block (same shape as
    governance.yaml) plus a `scenarios:` list. Without --agent, a deterministic
    mock agent is used so you can dry-run the harness itself.

    Exit codes: 0 = PROMOTE, 10 = HOLD, 1 = BLOCK
    """
    import json as _json
    import yaml as _yaml

    args = sys.argv[2:]
    if not args or args[0].startswith('-'):
        print("Error: loop-sim needs a scenarios file, e.g. "
              "release-gate loop-sim scenarios.yaml", file=sys.stderr)
        sys.exit(1)
    scen_path = args[0]
    agent_spec = _flag(sys.argv, '--agent')
    as_json    = '--json' in sys.argv
    show_full  = '--full' in sys.argv or '--verbose' in sys.argv

    try:
        doc = _yaml.safe_load(open(scen_path, encoding='utf-8').read()) or {}
    except Exception as exc:
        print(f"Error reading scenarios file: {exc}", file=sys.stderr)
        sys.exit(1)

    scenarios   = doc.get('scenarios') or []
    loop_policy = doc.get('loop') or {'max_iterations': 6}
    global_evals = doc.get('evals')
    if not scenarios:
        print("Error: scenarios file has no `scenarios:` list.", file=sys.stderr)
        sys.exit(1)

    # Resolve the agent target (mock when omitted).
    agent_callable = None
    if agent_spec:
        try:
            from release_gate.agent.client import AgentClient
            client = AgentClient.from_spec(agent_spec)
            agent_callable = lambda task, ctx: client.invoke(task, ctx)
        except Exception as exc:
            print(f"Error building agent from '{agent_spec}': {exc}", file=sys.stderr)
            sys.exit(1)

    from release_gate.loop_sim import LoopSimulator
    result = LoopSimulator().run(
        scenarios,
        agent=agent_callable,
        loop_policy=loop_policy,
        evals=global_evals,
    )

    if as_json:
        print(_json.dumps(result.as_dict(), indent=2))
        _exit_loop_sim(result.decision)

    # ── terminal report ──
    _BOLD, _RESET = '\033[1m', '\033[0m'
    _GREEN, _YELLOW, _RED = '\033[92m', '\033[93m', '\033[91m'
    colour = {'PROMOTE': _GREEN, 'HOLD': _YELLOW, 'BLOCK': _RED}.get(result.decision, _RESET)
    icon   = {'PROMOTE': '✓', 'HOLD': '⚠', 'BLOCK': '✗'}.get(result.decision, '?')

    n_adv = sum(1 for r in result.scenario_results if r['adversarial'])
    n_norm = result.scenarios_run - n_adv

    print()
    print(f"  {_BOLD}🔁 release-gate  |  Loop Sim{_RESET}")
    print(f"  {'─' * 52}")
    print(f"  Agent       {agent_spec or 'mock (no --agent)'}")
    print(f"  Scenarios   {result.scenarios_run}  ({n_norm} normal · {n_adv} adversarial)")
    print()
    conv_pct = result.convergence_rate * 100
    print(f"  Outcome match     {result.scenarios_passed}/{result.scenarios_run} "
          f"scenarios reached their expected decision")
    print(f"  Convergence       {conv_pct:.0f}% of normal scenarios shipped")
    if show_full:
        print(f"  Iterations        avg {result.avg_iterations:.1f}  "
              f"P95 {result.p95_iterations}  max {result.max_iterations}")
        print(f"  Cost / run        avg ${result.avg_cost:.4f}  "
              f"P95 ${result.p95_cost:.4f}  max ${result.max_cost:.4f}")
        if result.spike_scenarios:
            print(f"  Cost spikes       {len(result.spike_scenarios)} "
                  f"({len(result.spike_scenarios) * 100 // max(1, result.scenarios_run)}%): "
                  f"{', '.join(result.spike_scenarios[:4])}")
        if n_adv:
            print(f"  Adversarial       {result.adversarial_pass_rate * 100:.0f}% rolled back as required")

        if result.top_violations or result.top_warnings:
            print(f"\n  {_BOLD}Top issues{_RESET}")
            for v in result.top_violations:
                print(f"    {_RED}✗{_RESET} {v}")
            for w in result.top_warnings:
                print(f"    {_YELLOW}⚠{_RESET} {w}")
    else:
        n_iss = len(result.top_violations or []) + len(result.top_warnings or [])
        if n_iss or result.spike_scenarios:
            bits = []
            if result.spike_scenarios:
                bits.append(f"{len(result.spike_scenarios)} cost spike(s)")
            if n_iss:
                bits.append(f"{n_iss} issue(s)")
            print(f"  {' · '.join(bits)} — run with --full for detail, or see the report online.")

    print(f"\n  Decision:   {colour}{_BOLD}{icon}  {result.decision}{_RESET}")
    for reason in result.reasons:
        print(f"  {' ' * 12}{reason}")
    print()

    n_viol = len(result.top_violations or [])
    print_web_cta(
        teaser=f"{result.decision} · {conv_pct:.0f}% convergence · "
               f"{result.scenarios_passed}/{result.scenarios_run} matched",
        locked=(len(result.spike_scenarios or []) + n_viol) or None,
    )

    _exit_loop_sim(result.decision)


def _exit_loop_sim(decision):
    """0 = PROMOTE, 10 = HOLD, 1 = BLOCK."""
    sys.exit(0 if decision == 'PROMOTE' else (10 if decision == 'HOLD' else 1))


def _run_agent_score_command():
    """release-gate agent-score — run a behavior battery against a live agent.

    Usage:
      release-gate agent-score <agent-spec> [--evals my_evals.yaml] [--json]

      <agent-spec> is py:module:fn | cmd:./script | http(s)://url

    Scores Safety / Correctness / Loop / Cost into a 0-100 Agent Readiness
    Score with a PROMOTE / HOLD / BLOCK decision. Exit: 0 PROMOTE · 10 HOLD · 1 BLOCK.

    NOTE: this makes real calls to the agent (and costs real tokens).
    """
    import json as _json

    args = sys.argv[2:]
    if not args or args[0].startswith('-'):
        print("Error: agent-score needs an agent spec, e.g. "
              "release-gate agent-score py:my_pkg.agent:run", file=sys.stderr)
        sys.exit(1)
    agent_spec = args[0]
    evals_path = _flag(sys.argv, '--evals')
    as_json    = '--json' in sys.argv
    show_frameworks = '--frameworks' in sys.argv
    show_full  = '--full' in sys.argv or '--verbose' in sys.argv
    strict     = '--strict' in sys.argv
    report_path      = _flag(sys.argv, '--report')
    html_report_path = _flag(sys.argv, '--html-report')
    try:
        runs = max(1, int(_flag(sys.argv, '--runs') or 1))
    except (TypeError, ValueError):
        runs = 1

    # Build the agent + a shared runtime profile so latency/tokens are captured.
    try:
        from release_gate.agent.client import AgentClient
        from release_gate.agent.runtime import RuntimeProfile
        client  = AgentClient.from_spec(agent_spec)
        profile = RuntimeProfile()
        agent_callable = client.as_eval_callable(profile)
    except Exception as exc:
        print(f"Error building agent from '{agent_spec}': {exc}", file=sys.stderr)
        sys.exit(1)

    extra_evals = None
    if evals_path:
        try:
            from release_gate.evals.runner import load_evals
            extra_evals = load_evals(evals_path)
        except Exception as exc:
            print(f"Error reading evals file: {exc}", file=sys.stderr)
            sys.exit(1)

    from release_gate.agent_score import AgentScorer
    result = AgentScorer().score(
        agent_callable, agent_label=agent_spec,
        extra_evals=extra_evals, profile=profile, strict=strict, runs=runs,
    )

    # Build the evidence payload once (reused by --json / --report / --html-report).
    payload = result.as_dict()
    frameworks_data = None
    if show_frameworks or report_path or html_report_path:
        from release_gate.frameworks import frameworks_report
        frameworks_data = frameworks_report(payload)
        payload["frameworks"] = frameworks_data

    if report_path:
        with open(report_path, 'w', encoding='utf-8') as fh:
            _json.dump(payload, fh, indent=2)
        print(f"  Wrote JSON report → {report_path}", file=sys.stderr)
    if html_report_path:
        from release_gate.agent_score import render_html_report
        with open(html_report_path, 'w', encoding='utf-8') as fh:
            fh.write(render_html_report(payload, frameworks=frameworks_data))
        print(f"  Wrote HTML report → {html_report_path}", file=sys.stderr)

    if as_json:
        if not show_frameworks:
            payload.pop("frameworks", None)
        print(_json.dumps(payload, indent=2))
        _exit_agent_score(result.decision)

    # ── terminal scorecard ──
    _BOLD, _RESET = '\033[1m', '\033[0m'
    _GREEN, _YELLOW, _RED, _MUTED = '\033[92m', '\033[93m', '\033[91m', '\033[90m'
    col  = {'PROMOTE': _GREEN, 'HOLD': _YELLOW, 'BLOCK': _RED}.get(result.decision, _RESET)
    icon = {'PROMOTE': '✓', 'HOLD': '⚠', 'BLOCK': '✗'}.get(result.decision, '?')
    rt = result.runtime

    def _bar(score):
        filled = int(round(score / 10.0))
        return '█' * filled + '░' * (10 - filled)

    def _dcol(score):
        return _GREEN if score >= 80 else (_YELLOW if score >= 60 else _RED)

    WEIGHTS_PCT = {"safety": 35, "correctness": 30, "loop": 20, "cost_latency": 15}

    print()
    print(f"  {_BOLD}🤖 release-gate  |  Agent Score{_RESET}")
    print(f"  {'─' * 52}")
    print(f"  Agent       {result.agent}")
    calls = rt.get('calls', 0)
    print(f"  Ran         {calls} live calls", end="")
    if rt.get('errors'):
        print(f"  ({rt['errors']} errored)", end="")
    print()
    print()
    print(f"  {_BOLD}Agent Readiness   {col}{result.score} / 100{_RESET}   "
          f"{col}{_BOLD}{icon}  {result.decision}{_RESET}")
    print(f"  {'─' * 52}")

    labels = {
        "safety": "Safety", "correctness": "Correctness",
        "loop": "Loop behavior", "cost_latency": "Cost & latency",
    }
    if show_full:
        # Full breakdown — per-dimension bars, per-tier safety split, top issues.
        weakest = min(result.dimensions, key=lambda k: result.dimensions[k]["score"])
        for key in ("safety", "correctness", "loop", "cost_latency"):
            d = result.dimensions[key]
            s = d["score"]
            tag = ""
            tier_line = ""
            if key == "safety":
                tag = f"({d['passed']}/{d['total']})"
                # Break the per-tier results onto their own indented line — four tiers
                # don't fit inline.
                tiers = [(name.upper(), d.get(name)) for name in ("l1", "l2", "l3", "l4")]
                parts = [f"{lbl} {t['passed']}/{t['total']}" for lbl, t in tiers if t and t.get("total")]
                if parts:
                    tier_line = "  ·  ".join(parts)
            elif key == "correctness":
                tag = f"({d['passed']}/{d['total']})"
            elif key == "loop":
                tag = d["decision"]
            elif key == "cost_latency" and d.get("p95_latency_ms") is not None:
                tag = f"p95 {d['p95_latency_ms']:.0f}ms"
            weak = f"  {_RED}← weakest{_RESET}" if key == weakest and s < 80 else ""
            print(f"  {labels[key]:<15}{_dcol(s)}{s:>3}{_RESET}  {_dcol(s)}{_bar(s)}{_RESET}  "
                  f"{_MUTED}{tag:<26}{_RESET}wt {int(WEIGHTS_PCT[key])}%{weak}")
            if tier_line:
                print(f"  {' ' * 15}{_MUTED}{tier_line}{_RESET}")

        if result.issues:
            print(f"\n  {_BOLD}Top issues{_RESET}")
            for it in result.issues[:5]:
                mark = _RED + '✗' if it['severity'] in ('critical', 'high') else _YELLOW + '⚠'
                print(f"    {mark}{_RESET} {it['detail']}  {_MUTED}({it['dimension']}){_RESET}")
    else:
        # Basic view (default) — a compact one-line dimension summary. The full
        # per-tier/per-issue breakdown lives behind --full and on the website.
        summary = "   ".join(
            f"{labels[k]} {_dcol(result.dimensions[k]['score'])}{result.dimensions[k]['score']}{_RESET}"
            for k in ("safety", "correctness", "loop", "cost_latency")
        )
        print(f"  {summary}")
        n_issues = len(result.issues or [])
        if n_issues:
            print(f"\n  {_MUTED}{n_issues} issue(s) found — run with {_RESET}--full{_MUTED} "
                  f"for the breakdown, or open the full report online.{_RESET}")

    print(f"\n  Decision:  {col}{_BOLD}{icon}  {result.decision}{_RESET}")
    for reason in result.reasons:
        print(f"             {reason}")
    print()

    if show_frameworks:
        _print_framework_view(result.as_dict(), _BOLD, _RESET, _GREEN, _YELLOW, _RED, _MUTED)
    elif show_full:
        print(f"  {_MUTED}Map to OWASP / NIST / EU AI Act:  "
              f"release-gate agent-score {agent_spec} --frameworks{_RESET}")
        print()

    n_issues = len(result.issues or [])
    hidden = max(0, n_issues - 5)
    print_web_cta(
        teaser=f"{result.score}/100 · {result.decision}" + (f" · {n_issues} issue(s)" if n_issues else ""),
        locked=hidden or None,
    )

    _exit_agent_score(result.decision)


def _print_framework_view(score_dict, _BOLD, _RESET, _GREEN, _YELLOW, _RED, _MUTED):
    """Render the OWASP / NIST / EU AI Act control mapping as an auditor would read it."""
    from release_gate.frameworks import (
        assess_frameworks, summarize_frameworks, PASS, FAIL, PARTIAL,
    )
    controls = assess_frameworks(score_dict)
    summary = summarize_frameworks(controls)

    mark = {PASS: f"{_GREEN}✓{_RESET}", FAIL: f"{_RED}✗{_RESET}",
            PARTIAL: f"{_YELLOW}◐{_RESET}"}
    not_assessed = f"{_MUTED}○{_RESET}"

    print(f"  {_BOLD}Framework coverage{_RESET}  {_MUTED}(✓ pass · ✗ finding · ◐ partial · ○ not assessed){_RESET}")
    print(f"  {'─' * 52}")

    # group controls by framework, preserving catalog order
    seen = []
    for c in controls:
        if c.framework not in seen:
            seen.append(c.framework)
    for fw in seen:
        s = summary[fw]
        head = f"{_BOLD}{fw}{_RESET}"
        cov = f"{_MUTED}{s['coverage_pct']}% assessed"
        if s["FAIL"]:
            cov += f"{_RESET}{_RED} · {s['FAIL']} finding(s){_RESET}"
        else:
            cov += f"{_RESET}"
        print(f"\n  {head}   {cov}")
        for c in [c for c in controls if c.framework == fw]:
            m = mark.get(c.status, not_assessed)
            print(f"    {m} {c.control_id:<8}{c.title}")
            print(f"        {_MUTED}{c.evidence}{_RESET}")


def _exit_agent_score(decision):
    """0 = PROMOTE, 10 = HOLD, 1 = BLOCK."""
    sys.exit(0 if decision == 'PROMOTE' else (10 if decision == 'HOLD' else 1))


def unified_main():
    """Unified entry point for command-line invocation"""
    main()


if __name__ == '__main__':
    main()

#!/usr/bin/env python
"""
release-gate CLI - Governance enforcement for AI agents
Version: 0.5.0 with Cryptographic Governance Validation
"""
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


def print_help():
    """Print help message"""
    print("\n" + "="*80)
    print("\U0001f6aa release-gate v0.5.0")
    print("="*80)
    print("\nUsage:")
    print("  release-gate init                       # Initialize new project (interactive)")
    print("  release-gate run <config.yaml>          # Run governance checks")
    print("  release-gate impact <config.yaml>       # Impact Simulator — show money at risk")
    print("  release-gate validate-and-lock          # Cryptographic validation (v0.5)")
    print("\nOptions for 'run' and 'impact':")
    print("  --output-evidence <file.json>           Save detailed evidence as JSON")
    print("  --html-report <file.html>               Save Impact Simulator as HTML report")
    print("\nExamples:")
    print("  release-gate init")
    print("  release-gate impact governance.yaml")
    print("  release-gate impact governance.yaml --html-report report.html")
    print("  release-gate run governance.yaml")
    print("  release-gate run governance.yaml --output-evidence evidence.json")
    print("  release-gate validate-and-lock --governance governance.yaml --sign --private-key key.pem")
    print("  release-gate validate-and-lock --governance governance.yaml --verify --public-key key.pub")
    print("\nMore info: https://github.com/VamsiSudhakaran1/release-gate")
    print("="*80 + "\n")


def main():
    """Main CLI entry point"""
    if len(sys.argv) < 2:
        print_help()
        sys.exit(1)

    command = sys.argv[1]

    if command == 'init':
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

    else:
        print(f"Unknown command: {command}")
        print_help()
        sys.exit(1)


def unified_main():
    """Unified entry point for command-line invocation"""
    main()


if __name__ == '__main__':
    main()

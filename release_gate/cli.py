#!/usr/bin/env python
"""
release-gate CLI - Governance enforcement for AI agents
"""
import sys
import yaml
import json
from pathlib import Path

# Add package to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from release_gate.checks.action_budget import ActionBudgetCheck
from release_gate.checks.input_contract import InputContractCheck
from release_gate.checks.fallback_declared import FallbackDeclaredCheck
from release_gate.checks.identity_boundary import IdentityBoundaryCheck


def load_config(config_path):
    """Load and parse governance config from YAML"""
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        return config
    except FileNotFoundError:
        print(f"Error: Config file not found: {config_path}")
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"Error: Invalid YAML in config: {e}")
        sys.exit(1)


def run_checks(config):
    """Run all governance checks"""
    results = {}
    checks_config = config.get('checks', {})

    # ACTION_BUDGET Check
    if checks_config.get('action_budget', {}).get('enabled', True):
        try:
            check = ActionBudgetCheck()
            results['ACTION_BUDGET'] = check.evaluate(config)
        except Exception as e:
            results['ACTION_BUDGET'] = {
                'status': 'FAIL',
                'evidence': {'error': str(e)}
            }

    # INPUT_CONTRACT Check
    if checks_config.get('input_contract', {}).get('enabled', True):
        try:
            check = InputContractCheck()
            results['INPUT_CONTRACT'] = check.evaluate(config)
        except Exception as e:
            results['INPUT_CONTRACT'] = {
                'status': 'FAIL',
                'evidence': {'error': str(e)}
            }

    # FALLBACK_DECLARED Check
    if checks_config.get('fallback_declared', {}).get('enabled', True):
        try:
            check = FallbackDeclaredCheck()
            results['FALLBACK_DECLARED'] = check.evaluate(config)
        except Exception as e:
            results['FALLBACK_DECLARED'] = {
                'status': 'FAIL',
                'evidence': {'error': str(e)}
            }

    # IDENTITY_BOUNDARY Check
    if checks_config.get('identity_boundary', {}).get('enabled', True):
        try:
            check = IdentityBoundaryCheck()
            results['IDENTITY_BOUNDARY'] = check.evaluate(config)
        except Exception as e:
            results['IDENTITY_BOUNDARY'] = {
                'status': 'FAIL',
                'evidence': {'error': str(e)}
            }

    return results


def determine_decision(results, policy=None):
    """
    Determine final decision based on check results and policy.
    
    Policy defines what's critical (FAIL) vs flexible (WARN).
    
    Args:
        results: Dict of check results {check_name: {status, evidence}}
        policy: Dict with 'fail_on' and 'warn_on' lists
    
    Returns:
        'PASS', 'WARN', or 'FAIL'
    """
    if policy is None:
        policy = {}
    
    fail_on = set(policy.get('fail_on', []))
    warn_on = set(policy.get('warn_on', []))
    
    # Check 1: Any FAIL in fail_on list = FAIL decision
    for check_name, result in results.items():
        if result.get('status') == 'FAIL' and check_name in fail_on:
            return 'FAIL'
    
    # Check 2: Any FAIL (even if not in fail_on) = FAIL by default
    for check_name, result in results.items():
        if result.get('status') == 'FAIL' and check_name not in warn_on:
            return 'FAIL'
    
    # Check 3: Any WARN in warn_on list = WARN decision
    for check_name, result in results.items():
        if result.get('status') in ['WARN', 'FAIL'] and check_name in warn_on:
            return 'WARN'
    
    # Check 4: Default behavior (no policy) - fail if anything failed
    if any(r.get('status') == 'FAIL' for r in results.values()):
        return 'FAIL'
    
    # Check 5: Warn if anything warned
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


def print_results(results, decision, policy=None):
    """Pretty-print results in table format"""
    if policy is None:
        policy = {}
    
    fail_on = set(policy.get('fail_on', []))
    warn_on = set(policy.get('warn_on', []))
    
    print("\n" + "="*70)
    print("🚪 release-gate: Governance Validation")
    print("="*70 + "\n")
    
    # Header
    print(f"{'CHECK':<25} {'STATUS':<10} {'IMPACT':<15}")
    print("-"*70)
    
    # Results table
    for check_name, result in sorted(results.items()):
        status = result.get('status', 'UNKNOWN')
        
        # Determine impact
        if status == 'FAIL':
            if check_name in fail_on:
                impact = "CRITICAL"
            else:
                impact = "HIGH"
        elif status == 'WARN':
            if check_name in warn_on:
                impact = "HIGH"
            else:
                impact = "MEDIUM"
        else:
            impact = "—"
        
        # Status symbol
        symbol = '✓' if status == 'PASS' else ('⚠' if status == 'WARN' else '✗')
        status_str = f"{symbol} {status}"
        
        print(f"{check_name:<25} {status_str:<10} {impact:<15}")
    
    print("-"*70)
    
    # Final decision
    decision_symbol = '✅' if decision == 'PASS' else ('⚠️' if decision == 'WARN' else '❌')
    print(f"\n{decision_symbol} FINAL DECISION: {decision}")
    
    # Show evidence for failures
    has_failures = any(r.get('status') == 'FAIL' for r in results.values())
    if has_failures:
        print("\nIssues to fix:")
        for check_name, result in sorted(results.items()):
            if result.get('status') == 'FAIL':
                evidence = result.get('evidence', {})
                if isinstance(evidence, dict) and 'error' in evidence:
                    print(f"  • {check_name}: {evidence['error']}")
                elif isinstance(evidence, dict):
                    for key, value in evidence.items():
                        print(f"  • {check_name}: {key} = {value}")
    
    print("\n" + "="*70 + "\n")


def save_evidence(results, decision, output_path=None):
    """Save detailed evidence as JSON"""
    if not output_path:
        return
    
    evidence = {
        'decision': decision,
        'checks': results,
        'timestamp': None,
        'policy_version': 'v0.3.0'
    }
    
    try:
        with open(output_path, 'w') as f:
            json.dump(evidence, f, indent=2)
        print(f"Evidence saved to: {output_path}")
    except Exception as e:
        print(f"Warning: Could not save evidence: {e}")


def main():
    """Main CLI entry point"""
    # Parse arguments
    if len(sys.argv) < 2:
        print("Usage: release-gate run <config.yaml> [--output-evidence <file>]")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command != 'run':
        print(f"Unknown command: {command}")
        print("Usage: release-gate run <config.yaml>")
        sys.exit(1)
    
    if len(sys.argv) < 3:
        print("Usage: release-gate run <config.yaml>")
        sys.exit(1)
    
    config_path = sys.argv[2]
    
    # Check for optional flags
    evidence_path = None
    if '--output-evidence' in sys.argv:
        idx = sys.argv.index('--output-evidence')
        if idx + 1 < len(sys.argv):
            evidence_path = sys.argv[idx + 1]
    
    # Load config
    config = load_config(config_path)
    
    # Extract policy (if present)
    policy = config.get('policy', {})
    
    # Run checks
    results = run_checks(config)
    
    # Determine decision based on results and policy
    decision = determine_decision(results, policy)
    
    # Print results
    print_results(results, decision, policy)
    
    # Save evidence if requested
    if evidence_path:
        save_evidence(results, decision, evidence_path)
    
    # Exit with appropriate code
    exit_code = get_exit_code(decision)
    sys.exit(exit_code)


if __name__ == '__main__':
    main()

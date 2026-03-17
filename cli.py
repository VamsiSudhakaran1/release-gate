#!/usr/bin/env python3
"""release-gate CLI - Deployment readiness gate for AI agents

v0.2.0: 
  - INPUT_CONTRACT (schema + sample validation)
  - FALLBACK_DECLARED (governance)
  - IDENTITY_BOUNDARY (auth + rate limits + data isolation)
  - ACTION_BUDGET (token + retry + cost + concurrency limits)
"""

import sys
import json
from pathlib import Path
from datetime import datetime

def init_project(project_name, output_dir="."):
    """Initialize a new release-gate project"""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    config_content = f"""project:
  name: {project_name}
  version: 1.0.0
  description: AI system deployment gate

gate:
  policy: default-v0.1

checks:
  input_contract:
    enabled: true
    schema:
      type: object
      required:
        - prompt
        - duration_sec
      properties:
        prompt:
          type: string
          minLength: 1
          maxLength: 1000
        duration_sec:
          type: number
          minimum: 1
          maximum: 60
    samples:
      valid_path: valid_requests.jsonl
      invalid_path: invalid_requests.jsonl

  fallback_declared:
    enabled: true
    kill_switch:
      type: feature_flag
      name: disable_{project_name.replace('-', '_')}
    fallback:
      mode: static_placeholder
      description: Static response returned if system fails
    ownership:
      team: platform-team
      oncall: oncall-platform
    runbook_url: https://wiki.internal/runbooks/{project_name}

  identity_boundary:
    enabled: true
    authentication: required
    rate_limit: 100
    data_isolation:
      - user_owned_data_only
      - no_cross_user_access

  action_budget:
    enabled: true
    max_tokens_per_request: 5000
    max_retries: 3
    max_daily_cost: 1000
    max_concurrent_requests: 10
"""
    
    config_path = output_path / "release-gate.yaml"
    with open(config_path, 'w') as f:
        f.write(config_content)
    print(f"[OK] Created: {config_path}")
    
    valid_content = """{"prompt":"Test prompt 1","duration_sec":5}
{"prompt":"Test prompt 2","duration_sec":10}
{"prompt":"Another test","duration_sec":30}
"""
    
    invalid_content = """{"prompt":"","duration_sec":5}
{"prompt":"Test","duration_sec":120}
{"duration_sec":5}
"""
    
    valid_path = output_path / "valid_requests.jsonl"
    invalid_path = output_path / "invalid_requests.jsonl"
    
    with open(valid_path, 'w') as f:
        f.write(valid_content)
    print(f"[OK] Created: {valid_path}")
    
    with open(invalid_path, 'w') as f:
        f.write(invalid_content)
    print(f"[OK] Created: {invalid_path}")
    
    print("\n[DONE] Initialization complete!")


def run_gate(config_path, env="staging", output_format="json", output_file="readiness_report.json"):
    """Run the deployment gate checks"""
    try:
        import yaml
    except ImportError:
        print("ERROR: pyyaml not installed. Run: pip install pyyaml jsonschema")
        return 1
    
    try:
        import jsonschema
    except ImportError:
        print("ERROR: jsonschema not installed. Run: pip install pyyaml jsonschema")
        return 1
    
    config_file = Path(config_path)
    if not config_file.exists():
        print(f"ERROR: Config file not found: {config_path}")
        return 1
    
    # Load config
    try:
        with open(config_file) as f:
            config = yaml.safe_load(f)
    except Exception as e:
        print(f"ERROR: Failed to load config: {e}")
        return 1
    
    # Initialize results
    results = {
        "overall": "PASS",
        "timestamp": datetime.now().isoformat() + "Z",
        "environment": env,
        "project": config.get("project", {}),
        "summary": {"counts": {"pass": 0, "warn": 0, "fail": 0}},
        "checks": []
    }
    
    # Get base directory for relative paths
    config_dir = config_file.parent
    
    # INPUT_CONTRACT check
    input_check_result = _check_input_contract(config, config_dir, jsonschema)
    results["checks"].append(input_check_result)
    if input_check_result["result"] == "FAIL":
        results["overall"] = "FAIL"
    elif input_check_result["result"] == "WARN" and results["overall"] != "FAIL":
        results["overall"] = "WARN"
    results["summary"]["counts"][input_check_result["result"].lower()] += 1
    
    # FALLBACK_DECLARED check
    fallback_check_result = _check_fallback_declared(config)
    results["checks"].append(fallback_check_result)
    if fallback_check_result["result"] == "FAIL":
        results["overall"] = "FAIL"
    elif fallback_check_result["result"] == "WARN" and results["overall"] != "FAIL":
        results["overall"] = "WARN"
    results["summary"]["counts"][fallback_check_result["result"].lower()] += 1
    
    # IDENTITY_BOUNDARY check (v0.2)
    identity_check_result = _check_identity_boundary(config)
    results["checks"].append(identity_check_result)
    if identity_check_result["result"] == "FAIL":
        results["overall"] = "FAIL"
    elif identity_check_result["result"] == "WARN" and results["overall"] != "FAIL":
        results["overall"] = "WARN"
    results["summary"]["counts"][identity_check_result["result"].lower()] += 1
    
    # ACTION_BUDGET check (v0.2)
    budget_check_result = _check_action_budget(config)
    results["checks"].append(budget_check_result)
    if budget_check_result["result"] == "FAIL":
        results["overall"] = "FAIL"
    elif budget_check_result["result"] == "WARN" and results["overall"] != "FAIL":
        results["overall"] = "WARN"
    results["summary"]["counts"][budget_check_result["result"].lower()] += 1
    
    # Write report
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    # Display
    if output_format == "text":
        _display_text_report(results)
    else:
        print(json.dumps(results, indent=2))
    
    # Return exit code
    exit_codes = {"PASS": 0, "WARN": 10, "FAIL": 1}
    return exit_codes.get(results["overall"], 1)


def _check_input_contract(config, config_dir, jsonschema):
    """
    Validate INPUT_CONTRACT check.
    
    Tests:
    1. Schema is defined and syntactically valid
    2. All valid samples pass the schema
    3. All invalid samples fail the schema
    """
    input_check = config.get("checks", {}).get("input_contract", {})
    
    if not input_check.get("enabled", True):
        return {
            "name": "input_contract",
            "result": "PASS",
            "evidence": {"status": "check disabled"}
        }
    
    schema = input_check.get("schema")
    if not schema:
        return {
            "name": "input_contract",
            "result": "FAIL",
            "evidence": {"error": "No schema defined"}
        }
    
    # Validate schema syntax
    try:
        jsonschema.Draft7Validator.check_schema(schema)
    except Exception as e:
        return {
            "name": "input_contract",
            "result": "FAIL",
            "evidence": {"error": f"Invalid JSON Schema: {str(e)}"}
        }
    
    # Load samples
    samples_config = input_check.get("samples", {})
    valid_path = samples_config.get("valid_path")
    invalid_path = samples_config.get("invalid_path")
    
    if not valid_path or not invalid_path:
        return {
            "name": "input_contract",
            "result": "FAIL",
            "evidence": {"error": "Missing sample paths (valid_path and invalid_path required)"}
        }
    
    try:
        valid_samples = _load_jsonl_file(config_dir / valid_path)
        invalid_samples = _load_jsonl_file(config_dir / invalid_path)
    except Exception as e:
        return {
            "name": "input_contract",
            "result": "FAIL",
            "evidence": {"error": f"Failed to load samples: {str(e)}"}
        }
    
    # Test valid samples
    validator = jsonschema.Draft7Validator(schema)
    valid_failures = []
    
    for i, sample in enumerate(valid_samples):
        errors = list(validator.iter_errors(sample))
        if errors:
            valid_failures.append({
                "sample_index": i,
                "data": sample,
                "error": errors[0].message if errors else "Unknown error"
            })
    
    # Test invalid samples
    invalid_passes = []
    
    for i, sample in enumerate(invalid_samples):
        errors = list(validator.iter_errors(sample))
        if not errors:
            invalid_passes.append({
                "sample_index": i,
                "data": sample
            })
    
    # Determine result
    evidence = {
        "schema_valid": True,
        "valid_samples_tested": len(valid_samples),
        "valid_samples_passed": len(valid_samples) - len(valid_failures),
        "valid_samples_failed": len(valid_failures),
        "invalid_samples_tested": len(invalid_samples),
        "invalid_samples_rejected": len(invalid_samples) - len(invalid_passes),
        "invalid_samples_accepted": len(invalid_passes)
    }
    
    if valid_failures and invalid_passes:
        return {
            "name": "input_contract",
            "result": "FAIL",
            "evidence": {
                **evidence,
                "failed_valid_samples": valid_failures[:2],
                "passed_invalid_samples": invalid_passes[:2]
            },
            "suggestion": "Fix schema: valid samples must pass, invalid samples must fail"
        }
    elif valid_failures:
        return {
            "name": "input_contract",
            "result": "FAIL",
            "evidence": {
                **evidence,
                "failed_valid_samples": valid_failures[:2]
            },
            "suggestion": "Schema rejected valid samples. Review schema constraints."
        }
    elif invalid_passes:
        return {
            "name": "input_contract",
            "result": "WARN",
            "evidence": {
                **evidence,
                "passed_invalid_samples": invalid_passes[:2]
            },
            "suggestion": "Schema accepted invalid samples. Tighten schema constraints."
        }
    else:
        return {
            "name": "input_contract",
            "result": "PASS",
            "evidence": evidence
        }


def _check_fallback_declared(config):
    """
    Validate FALLBACK_DECLARED check.
    
    Validates:
    1. Kill switch is declared
    2. Fallback mode is declared
    3. Ownership is assigned
    4. Runbook URL is provided
    """
    fallback_check = config.get("checks", {}).get("fallback_declared", {})
    
    if not fallback_check.get("enabled", True):
        return {
            "name": "fallback_declared",
            "result": "PASS",
            "evidence": {"status": "check disabled"}
        }
    
    missing = []
    
    # Check kill switch
    kill_switch = fallback_check.get("kill_switch")
    if not kill_switch:
        missing.append("kill_switch")
    elif not kill_switch.get("type") or not kill_switch.get("name"):
        missing.append("kill_switch (incomplete: missing type or name)")
    
    # Check fallback
    fallback = fallback_check.get("fallback")
    if not fallback:
        missing.append("fallback")
    elif not fallback.get("mode"):
        missing.append("fallback (incomplete: missing mode)")
    
    # Check ownership
    ownership = fallback_check.get("ownership")
    if not ownership:
        missing.append("ownership")
    elif not ownership.get("team") or not ownership.get("oncall"):
        missing.append("ownership (incomplete: missing team or oncall)")
    
    # Check runbook
    runbook_url = fallback_check.get("runbook_url")
    if not runbook_url:
        missing.append("runbook_url")
    elif not isinstance(runbook_url, str) or not (runbook_url.startswith("http://") or runbook_url.startswith("https://")):
        missing.append("runbook_url (invalid: must be valid http/https URL)")
    
    evidence = {
        "kill_switch_declared": kill_switch is not None and kill_switch.get("type") and kill_switch.get("name"),
        "fallback_declared": fallback is not None and fallback.get("mode"),
        "ownership_assigned": ownership is not None and ownership.get("team") and ownership.get("oncall"),
        "runbook_provided": runbook_url is not None and isinstance(runbook_url, str) and (runbook_url.startswith("http://") or runbook_url.startswith("https://"))
    }
    
    if missing:
        return {
            "name": "fallback_declared",
            "result": "FAIL",
            "evidence": {
                **evidence,
                "missing_fields": missing
            },
            "suggestion": f"Declare: {', '.join([m.split('(')[0].strip() for m in missing])}"
        }
    else:
        return {
            "name": "fallback_declared",
            "result": "PASS",
            "evidence": evidence
        }


def _check_identity_boundary(config):
    """
    Validate IDENTITY_BOUNDARY check (Phase v0.2).
    
    Validates:
    1. Authentication is required or explicitly allowed
    2. Rate limits are defined
    3. Data isolation boundaries are clear
    """
    identity_check = config.get("checks", {}).get("identity_boundary", {})
    
    if not identity_check.get("enabled", True):
        return {
            "name": "identity_boundary",
            "result": "PASS",
            "evidence": {"status": "check disabled"}
        }
    
    issues = []
    
    # Check authentication
    auth_required = identity_check.get("authentication")
    if auth_required not in ["required", "optional"]:
        issues.append("authentication (must be 'required' or 'optional')")
    
    # Check rate limits
    rate_limit = identity_check.get("rate_limit")
    if auth_required == "required" and not rate_limit:
        issues.append("rate_limit (required when auth is required)")
    elif rate_limit and (not isinstance(rate_limit, int) or rate_limit <= 0):
        issues.append("rate_limit (must be positive integer)")
    
    # Check data isolation
    data_isolation = identity_check.get("data_isolation", [])
    if auth_required == "required" and not data_isolation:
        issues.append("data_isolation (required when auth is required)")
    
    evidence = {
        "authentication_enforced": auth_required == "required",
        "rate_limits_defined": isinstance(rate_limit, int) and rate_limit > 0,
        "data_isolation_defined": isinstance(data_isolation, list) and len(data_isolation) > 0
    }
    
    if issues:
        return {
            "name": "identity_boundary",
            "result": "FAIL" if auth_required == "required" else "WARN",
            "evidence": {
                **evidence,
                "missing_fields": issues
            }
        }
    else:
        return {
            "name": "identity_boundary",
            "result": "PASS",
            "evidence": evidence
        }


def _check_action_budget(config):
    """
    Validate ACTION_BUDGET check (Phase v0.2).
    
    Validates:
    1. Max tokens per request is defined
    2. Max retries is defined
    3. Max daily/monthly cost is defined
    4. Max concurrent requests is defined
    """
    budget_check = config.get("checks", {}).get("action_budget", {})
    
    if not budget_check.get("enabled", True):
        return {
            "name": "action_budget",
            "result": "PASS",
            "evidence": {"status": "check disabled"}
        }
    
    issues = []
    
    # Check token limits
    max_tokens = budget_check.get("max_tokens_per_request")
    if not max_tokens or not isinstance(max_tokens, int) or max_tokens <= 0:
        issues.append("max_tokens_per_request (must be positive integer)")
    
    # Check retry limits
    max_retries = budget_check.get("max_retries")
    if max_retries is None or not isinstance(max_retries, int) or max_retries < 0:
        issues.append("max_retries (must be non-negative integer)")
    
    # Check cost limits
    max_daily_cost = budget_check.get("max_daily_cost")
    if not max_daily_cost or not isinstance(max_daily_cost, (int, float)) or max_daily_cost <= 0:
        issues.append("max_daily_cost (must be positive number)")
    
    # Check concurrency
    max_concurrent = budget_check.get("max_concurrent_requests")
    if not max_concurrent or not isinstance(max_concurrent, int) or max_concurrent <= 0:
        issues.append("max_concurrent_requests (must be positive integer)")
    
    evidence = {
        "max_tokens_defined": isinstance(max_tokens, int) and max_tokens > 0,
        "max_retries_defined": isinstance(max_retries, int) and max_retries >= 0,
        "max_daily_cost_defined": isinstance(max_daily_cost, (int, float)) and max_daily_cost > 0,
        "max_concurrent_defined": isinstance(max_concurrent, int) and max_concurrent > 0
    }
    
    if issues:
        return {
            "name": "action_budget",
            "result": "FAIL" if len(issues) > 2 else "WARN",
            "evidence": {
                **evidence,
                "missing_fields": issues
            }
        }
    else:
        return {
            "name": "action_budget",
            "result": "PASS",
            "evidence": evidence
        }


def _load_jsonl_file(file_path):
    """Load and parse a JSONL file"""
    path = Path(file_path)
    
    if not path.exists():
        raise FileNotFoundError(f"Sample file not found: {path}")
    
    items = []
    with open(path, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if line:
                try:
                    items.append(json.loads(line))
                except json.JSONDecodeError as e:
                    raise ValueError(f"Invalid JSON at line {line_num} in {path}: {line}")
    
    return items


def _display_text_report(results):
    """Display report in human-readable text format"""
    print("\n" + "="*70)
    print("  release-gate v0.1.0 - Deployment Readiness Report")
    print("="*70)
    
    print(f"\nProject: {results['project'].get('name', 'unknown')}")
    print(f"Environment: {results['environment']}")
    print(f"Timestamp: {results['timestamp']}")
    
    print("\n" + "-"*70)
    print("Check Results:")
    print("-"*70)
    
    for check in results["checks"]:
        name = check['name']
        result = check['result']
        
        if result == "PASS":
            status = "✓ PASS"
        elif result == "FAIL":
            status = "✗ FAIL"
        else:
            status = "⚠ WARN"
        
        print(f"\n{name}")
        print(f"  Status: {status}")
        
        for key, value in check.get("evidence", {}).items():
            if isinstance(value, list):
                if value and len(str(value)) > 60:
                    print(f"  {key}: {len(value)} item(s)")
                else:
                    print(f"  {key}: {value}")
            elif isinstance(value, dict):
                print(f"  {key}: {json.dumps(value)}")
            else:
                print(f"  {key}: {value}")
        
        if check.get('suggestion'):
            print(f"  💡 {check['suggestion']}")
    
    print("\n" + "="*70)
    summary = results["summary"]["counts"]
    print(f"Summary: {summary['pass']} passed, {summary['warn']} warned, {summary['fail']} failed")
    
    overall = results['overall']
    if overall == "PASS":
        status = "✓ PASS"
    elif overall == "WARN":
        status = "⚠ WARN"
    else:
        status = "✗ FAIL"
    
    print(f"Overall Decision: {status}")
    print("="*70 + "\n")


def main():
    """Entry point for the CLI"""
    if len(sys.argv) < 2:
        print("release-gate v0.1.0 - Deployment readiness gate for AI agents")
        print("\nUsage:")
        print("  python cli.py init --project NAME")
        print("  python cli.py run --config CONFIG [--env ENV] [--format FORMAT] [--output FILE]")
        sys.exit(0)
    
    command = sys.argv[1]
    
    if command == "init":
        project = "my-system"
        if "--project" in sys.argv:
            idx = sys.argv.index("--project")
            if idx + 1 < len(sys.argv):
                project = sys.argv[idx + 1]
        init_project(project)
        sys.exit(0)
    
    elif command == "run":
        config = None
        env = "staging"
        fmt = "json"
        output = "readiness_report.json"
        
        if "--config" in sys.argv:
            idx = sys.argv.index("--config")
            if idx + 1 < len(sys.argv):
                config = sys.argv[idx + 1]
        
        if "--env" in sys.argv:
            idx = sys.argv.index("--env")
            if idx + 1 < len(sys.argv):
                env = sys.argv[idx + 1]
        
        if "--format" in sys.argv:
            idx = sys.argv.index("--format")
            if idx + 1 < len(sys.argv):
                fmt = sys.argv[idx + 1]
        
        if "--output" in sys.argv:
            idx = sys.argv.index("--output")
            if idx + 1 < len(sys.argv):
                output = sys.argv[idx + 1]
        
        if not config:
            print("ERROR: --config is required")
            print("Usage: python cli.py run --config release-gate.yaml")
            sys.exit(1)
        
        sys.exit(run_gate(config, env, fmt, output))
    
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)

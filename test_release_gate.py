#!/usr/bin/env python3
"""
Minimal automated smoke test suite for release-gate CLI

Tests:
1. Initialization creates files
2. PASS case returns exit code 0
3. WARN case returns exit code 10
4. FAIL case returns exit code 1
5. JSON output is valid
6. Custom output file is created

No pytest required - just run: python test_release_gate.py
"""

import subprocess
import json
import sys
import tempfile
import shutil
from pathlib import Path


def run_cli(*args, cwd=None):
    """Run CLI command and return (exit_code, stdout, stderr)"""
    cmd = [sys.executable, "cli.py"] + list(args)
    result = subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True
    )
    return result.returncode, result.stdout, result.stderr


def test_init():
    """Test 1: Initialization creates files"""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        # Copy cli.py to temp dir
        import shutil as sh
        sh.copy("cli.py", tmpdir / "cli.py")
        
        code, stdout, stderr = run_cli("init", "--project", "test-init", cwd=tmpdir)
        
        assert code == 0, f"Init failed: {stderr}"
        assert (tmpdir / "release-gate.yaml").exists(), "Config not created"
        assert (tmpdir / "valid_requests.jsonl").exists(), "Valid samples not created"
        assert (tmpdir / "invalid_requests.jsonl").exists(), "Invalid samples not created"
        print("✓ Test 1: Initialization - PASSED")


def test_pass_case():
    """Test 2: Valid config returns PASS (exit code 0)"""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        import shutil as sh
        sh.copy("cli.py", tmpdir / "cli.py")
        
        # Initialize
        run_cli("init", "--project", "test-pass", cwd=tmpdir)
        
        # Run (should PASS)
        code, stdout, stderr = run_cli("run", "--config", "release-gate.yaml", cwd=tmpdir)
        
        assert code == 0, f"Expected exit code 0 for PASS, got {code}. Stderr: {stderr}"
        assert "PASS" in stdout or "pass" in stdout.lower(), "PASS not in output"
        print("✓ Test 2: PASS case (exit 0) - PASSED")


def test_fail_case():
    """Test 3: Invalid config returns FAIL (exit code 1)"""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        import shutil as sh
        sh.copy("cli.py", tmpdir / "cli.py")
        
        # Create broken config (missing fallback)
        broken_config = """
project:
  name: broken

checks:
  input_contract:
    enabled: true
    schema:
      type: object
  fallback_declared:
    enabled: true
"""
        (tmpdir / "broken.yaml").write_text(broken_config)
        
        # Run (should FAIL)
        code, stdout, stderr = run_cli("run", "--config", "broken.yaml", cwd=tmpdir)
        
        assert code == 1, f"Expected exit code 1 for FAIL, got {code}"
        print("✓ Test 3: FAIL case (exit 1) - PASSED")


def test_json_output():
    """Test 4: JSON output is valid"""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        import shutil as sh
        sh.copy("cli.py", tmpdir / "cli.py")
        
        # Initialize
        run_cli("init", "--project", "test-json", cwd=tmpdir)
        
        # Run with JSON format
        code, stdout, stderr = run_cli("run", "--config", "release-gate.yaml", "--format", "json", cwd=tmpdir)
        
        assert code == 0, f"Run failed: {stderr}"
        
        # Parse JSON
        try:
            data = json.loads(stdout)
            assert "overall" in data, "JSON missing 'overall' field"
            assert "checks" in data, "JSON missing 'checks' field"
            assert data["overall"] == "PASS", f"Expected PASS, got {data['overall']}"
            print("✓ Test 4: JSON output - PASSED")
        except json.JSONDecodeError as e:
            assert False, f"Invalid JSON output: {e}\n{stdout}"


def test_custom_output_file():
    """Test 5: Custom output file is created"""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        import shutil as sh
        sh.copy("cli.py", tmpdir / "cli.py")
        
        # Initialize
        run_cli("init", "--project", "test-output", cwd=tmpdir)
        
        # Run with custom output
        code, stdout, stderr = run_cli(
            "run", 
            "--config", "release-gate.yaml",
            "--output", "custom-report.json",
            cwd=tmpdir
        )
        
        assert code == 0, f"Run failed: {stderr}"
        
        output_file = tmpdir / "custom-report.json"
        assert output_file.exists(), f"Custom output file not created: {output_file}"
        
        # Verify it's valid JSON
        data = json.loads(output_file.read_text())
        assert data["overall"] == "PASS"
        print("✓ Test 5: Custom output file - PASSED")


def test_sample_validation():
    """Test 6: INPUT_CONTRACT tests samples"""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        import shutil as sh
        sh.copy("cli.py", tmpdir / "cli.py")
        
        # Initialize
        run_cli("init", "--project", "test-samples", cwd=tmpdir)
        
        # Run
        code, stdout, stderr = run_cli("run", "--config", "release-gate.yaml", "--format", "json", cwd=tmpdir)
        
        assert code == 0
        data = json.loads(stdout)
        
        # Find INPUT_CONTRACT check
        input_contract = next((c for c in data["checks"] if c["name"] == "input_contract"), None)
        assert input_contract is not None, "input_contract not found"
        
        # Check evidence includes sample counts
        evidence = input_contract["evidence"]
        assert "valid_samples_tested" in evidence, "valid_samples_tested not in evidence"
        assert "invalid_samples_tested" in evidence, "invalid_samples_tested not in evidence"
        assert evidence["valid_samples_tested"] > 0, "No valid samples tested"
        assert evidence["invalid_samples_tested"] > 0, "No invalid samples tested"
        print("✓ Test 6: Sample validation - PASSED")


def test_warn_case_invalid_samples_accepted():
    """Test 7: WARN when invalid samples incorrectly pass schema"""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        import shutil as sh
        sh.copy("cli.py", tmpdir / "cli.py")
        
        # Create config with schema that's too loose (accepts everything)
        config = """
project:
  name: warn-test

gate:
  policy: default-v0.1

checks:
  input_contract:
    enabled: true
    schema:
      type: object
    samples:
      valid_path: valid_requests.jsonl
      invalid_path: invalid_requests.jsonl

  fallback_declared:
    enabled: true
    kill_switch:
      type: feature_flag
      name: disable_warn_test
    fallback:
      mode: static_placeholder
    ownership:
      team: platform-team
      oncall: oncall-platform
    runbook_url: https://wiki.internal/runbooks/test
"""
        (tmpdir / "release-gate.yaml").write_text(config)
        
        # Create invalid samples that will pass the loose schema
        invalid_samples = """{"any": "value"}
{"random": "data"}
{"test": 123}
"""
        (tmpdir / "invalid_requests.jsonl").write_text(invalid_samples)
        
        # Create valid samples
        valid_samples = """{"test": "valid"}
{"data": "here"}
{"foo": "bar"}
"""
        (tmpdir / "valid_requests.jsonl").write_text(valid_samples)
        
        # Run
        code, stdout, stderr = run_cli("run", "--config", "release-gate.yaml", "--format", "json", cwd=tmpdir)
        
        # Should return WARN (exit code 10) because invalid samples are accepted
        assert code == 10, f"Expected exit code 10 for WARN, got {code}. Stderr: {stderr}"
        
        data = json.loads(stdout)
        assert data["overall"] == "WARN", f"Expected overall WARN, got {data['overall']}"
        
        # Check INPUT_CONTRACT returned WARN
        input_contract = next((c for c in data["checks"] if c["name"] == "input_contract"), None)
        assert input_contract is not None
        assert input_contract["result"] == "WARN", f"Expected INPUT_CONTRACT WARN, got {input_contract['result']}"
        
        # Check evidence shows invalid samples were accepted
        evidence = input_contract["evidence"]
        assert evidence["invalid_samples_accepted"] > 0, "Expected some invalid samples to be accepted"
        
        print("✓ Test 7: WARN case (invalid samples accepted) - PASSED")


def test_warn_exit_code_10():
    """Test 8: WARN returns exit code 10"""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        import shutil as sh
        sh.copy("cli.py", tmpdir / "cli.py")
        
        # Create config with loose schema
        config = """
project:
  name: warn-exit-test

checks:
  input_contract:
    enabled: true
    schema:
      type: object
    samples:
      valid_path: valid_requests.jsonl
      invalid_path: invalid_requests.jsonl

  fallback_declared:
    enabled: true
    kill_switch:
      type: feature_flag
      name: test
    fallback:
      mode: static_placeholder
    ownership:
      team: team
      oncall: oncall
    runbook_url: https://test.com
"""
        (tmpdir / "release-gate.yaml").write_text(config)
        
        # Create samples where invalid ones pass
        (tmpdir / "valid_requests.jsonl").write_text('{"valid": true}\n')
        (tmpdir / "invalid_requests.jsonl").write_text('{"invalid": true}\n')
        
        # Run
        code, _, stderr = run_cli("run", "--config", "release-gate.yaml", cwd=tmpdir)
        
        # Should return exit code 10 for WARN
        assert code == 10, f"Expected exit code 10 for WARN, got {code}"
        print("✓ Test 8: WARN exit code (10) - PASSED")


def test_warn_in_summary():
    """Test 9: WARN appears in summary"""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        import shutil as sh
        sh.copy("cli.py", tmpdir / "cli.py")
        
        # Create loose schema config
        config = """
project:
  name: warn-summary-test

checks:
  input_contract:
    enabled: true
    schema:
      type: object
    samples:
      valid_path: valid_requests.jsonl
      invalid_path: invalid_requests.jsonl

  fallback_declared:
    enabled: true
    kill_switch:
      type: feature_flag
      name: test
    fallback:
      mode: static_placeholder
    ownership:
      team: team
      oncall: oncall
    runbook_url: https://test.com
"""
        (tmpdir / "release-gate.yaml").write_text(config)
        (tmpdir / "valid_requests.jsonl").write_text('{"valid": true}\n')
        (tmpdir / "invalid_requests.jsonl").write_text('{"invalid": true}\n')
        
        # Run with JSON format
        code, stdout, stderr = run_cli("run", "--config", "release-gate.yaml", "--format", "json", cwd=tmpdir)
        
        data = json.loads(stdout)
        
        # Check summary counts warn
        summary = data["summary"]["counts"]
        assert summary["warn"] > 0, "Expected warn count > 0 in summary"
        
        print("✓ Test 9: WARN in summary counts - PASSED")


def test_warn_precedence_fail_wins():
    """Test 10: FAIL takes precedence over WARN"""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        import shutil as sh
        sh.copy("cli.py", tmpdir / "cli.py")
        
        # Create config: INPUT_CONTRACT WARN + FALLBACK_DECLARED FAIL
        config = """
project:
  name: fail-precedence-test

checks:
  input_contract:
    enabled: true
    schema:
      type: object
    samples:
      valid_path: valid_requests.jsonl
      invalid_path: invalid_requests.jsonl

  fallback_declared:
    enabled: true
"""
        (tmpdir / "release-gate.yaml").write_text(config)
        (tmpdir / "valid_requests.jsonl").write_text('{"valid": true}\n')
        (tmpdir / "invalid_requests.jsonl").write_text('{"invalid": true}\n')
        
        # Run
        code, stdout, stderr = run_cli("run", "--config", "release-gate.yaml", "--format", "json", cwd=tmpdir)
        
        data = json.loads(stdout)
        
        # Even though INPUT_CONTRACT might WARN, overall should be FAIL (fallback missing)
        assert data["overall"] == "FAIL", f"Expected FAIL to take precedence, got {data['overall']}"
        assert code == 1, f"Expected exit code 1 (FAIL), got {code}"
        
        print("✓ Test 10: FAIL precedence over WARN - PASSED")


def main():
    """Run all tests"""
    print("\n" + "="*70)
    print("  release-gate Automated Smoke Test Suite")
    print("="*70 + "\n")
    
    tests = [
        ("Initialization", test_init),
        ("PASS case", test_pass_case),
        ("FAIL case", test_fail_case),
        ("JSON output", test_json_output),
        ("Custom output file", test_custom_output_file),
        ("Sample validation", test_sample_validation),
        ("WARN case (invalid samples accepted)", test_warn_case_invalid_samples_accepted),
        ("WARN exit code (10)", test_warn_exit_code_10),
        ("WARN in summary", test_warn_in_summary),
        ("FAIL precedence over WARN", test_warn_precedence_fail_wins),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        try:
            test_func()
            passed += 1
        except AssertionError as e:
            print(f"✗ {test_name} - FAILED: {e}")
            failed += 1
        except Exception as e:
            print(f"✗ {test_name} - ERROR: {e}")
            failed += 1
    
    print("\n" + "="*70)
    print(f"Results: {passed} passed, {failed} failed")
    print("="*70 + "\n")
    
    if failed == 0:
        print("✅ All tests passed! release-gate is working correctly.\n")
        return 0
    else:
        print("❌ Some tests failed. See details above.\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())

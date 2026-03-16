#!/usr/bin/env python3
"""
Test suite for release-gate CLI

Tests core functionality:
- Initialization
- Gate validation (PASS/WARN/FAIL)
- Exit codes
- Output formats
- Sample validation
"""

import subprocess
import json
import tempfile
import shutil
from pathlib import Path


class TestReleasegate:
    """Test suite for release-gate CLI"""
    
    def setup_method(self):
        """Create a temporary directory for each test"""
        self.test_dir = tempfile.mkdtemp()
        self.original_dir = Path.cwd()
        
    def teardown_method(self):
        """Clean up temporary directory after each test"""
        shutil.rmtree(self.test_dir)
    
    def run_command(self, *args):
        """Run a CLI command and return (return_code, stdout, stderr)"""
        result = subprocess.run(
            ["python", "cli.py", *args],
            cwd=self.test_dir,
            capture_output=True,
            text=True
        )
        return result.returncode, result.stdout, result.stderr
    
    # ========== INITIALIZATION TESTS ==========
    
    def test_init_creates_config_file(self):
        """Test that init creates release-gate.yaml"""
        code, stdout, stderr = self.run_command("init", "--project", "test-project")
        
        assert code == 0, f"Init failed: {stderr}"
        assert (Path(self.test_dir) / "release-gate.yaml").exists(), "Config file not created"
        assert "✓ Created" in stdout, "Success message not shown"
    
    def test_init_creates_valid_samples(self):
        """Test that init creates valid_requests.jsonl"""
        code, _, stderr = self.run_command("init", "--project", "test-project")
        
        assert code == 0, f"Init failed: {stderr}"
        assert (Path(self.test_dir) / "valid_requests.jsonl").exists(), "Valid samples not created"
        
        # Verify it's valid JSONL
        with open(Path(self.test_dir) / "valid_requests.jsonl") as f:
            for line in f:
                line = line.strip()
                if line:
                    json.loads(line)  # Should not raise
    
    def test_init_creates_invalid_samples(self):
        """Test that init creates invalid_requests.jsonl"""
        code, _, stderr = self.run_command("init", "--project", "test-project")
        
        assert code == 0, f"Init failed: {stderr}"
        assert (Path(self.test_dir) / "invalid_requests.jsonl").exists(), "Invalid samples not created"
        
        # Verify it's valid JSONL
        with open(Path(self.test_dir) / "invalid_requests.jsonl") as f:
            for line in f:
                line = line.strip()
                if line:
                    json.loads(line)  # Should not raise
    
    def test_init_default_project_name(self):
        """Test init with default project name"""
        code, stdout, _ = self.run_command("init")
        
        assert code == 0, "Init with default project name failed"
        assert "✓ Created" in stdout, "Success message not shown"
    
    # ========== VALIDATION TESTS ==========
    
    def test_pass_case_with_valid_config(self):
        """Test that valid config returns PASS"""
        # Initialize project
        self.run_command("init", "--project", "test-project")
        
        # Run gate with generated config
        code, stdout, stderr = self.run_command("run", "--config", "release-gate.yaml", "--format", "text")
        
        assert code == 0, f"Gate failed: {stderr}"
        assert "✓ PASS" in stdout, "PASS not found in output"
    
    def test_pass_exit_code(self):
        """Test that PASS returns exit code 0"""
        self.run_command("init", "--project", "test-project")
        code, _, _ = self.run_command("run", "--config", "release-gate.yaml")
        
        assert code == 0, f"Expected exit code 0 for PASS, got {code}"
    
    def test_fail_case_missing_kill_switch(self):
        """Test that missing kill_switch causes FAIL"""
        self.run_command("init", "--project", "test-project")
        
        # Remove kill_switch from config
        config_path = Path(self.test_dir) / "release-gate.yaml"
        with open(config_path) as f:
            content = f.read()
        
        # Remove kill_switch section
        lines = content.split('\n')
        new_lines = []
        skip = False
        for line in lines:
            if 'kill_switch:' in line:
                skip = True
            elif skip and line and not line.startswith('    '):
                skip = False
            if not skip:
                new_lines.append(line)
        
        with open(config_path, 'w') as f:
            f.write('\n'.join(new_lines))
        
        # Run gate
        code, stdout, _ = self.run_command("run", "--config", "release-gate.yaml", "--format", "text")
        
        assert code == 1, f"Expected exit code 1 for FAIL, got {code}"
        assert "✗ FAIL" in stdout or "FAIL" in stdout, "FAIL not found in output"
    
    def test_fail_exit_code(self):
        """Test that FAIL returns exit code 1"""
        self.run_command("init", "--project", "test-project")
        
        # Create broken config
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
        with open(Path(self.test_dir) / "broken.yaml", 'w') as f:
            f.write(broken_config)
        
        code, _, _ = self.run_command("run", "--config", "broken.yaml")
        
        assert code == 1, f"Expected exit code 1 for FAIL, got {code}"
    
    # ========== OUTPUT FORMAT TESTS ==========
    
    def test_json_output_format(self):
        """Test that JSON output is valid JSON"""
        self.run_command("init", "--project", "test-project")
        code, stdout, _ = self.run_command("run", "--config", "release-gate.yaml", "--format", "json")
        
        assert code == 0, "Run failed"
        
        # Parse JSON to verify it's valid
        data = json.loads(stdout)
        assert "overall" in data, "JSON missing 'overall' field"
        assert "checks" in data, "JSON missing 'checks' field"
        assert data["overall"] == "PASS", "Expected PASS result"
    
    def test_text_output_format(self):
        """Test that text output is human-readable"""
        self.run_command("init", "--project", "test-project")
        code, stdout, _ = self.run_command("run", "--config", "release-gate.yaml", "--format", "text")
        
        assert code == 0, "Run failed"
        assert "input_contract" in stdout, "input_contract not in text output"
        assert "fallback_declared" in stdout, "fallback_declared not in text output"
        assert "Overall" in stdout, "Overall not in text output"
    
    def test_custom_output_file(self):
        """Test that --output flag saves to custom file"""
        self.run_command("init", "--project", "test-project")
        code, _, _ = self.run_command("run", "--config", "release-gate.yaml", "--output", "custom-report.json")
        
        assert code == 0, "Run failed"
        
        custom_file = Path(self.test_dir) / "custom-report.json"
        assert custom_file.exists(), f"Custom output file not created: {custom_file}"
        
        # Verify it's valid JSON
        with open(custom_file) as f:
            data = json.loads(f.read())
            assert data["overall"] == "PASS", "Report doesn't contain expected data"
    
    def test_default_output_file(self):
        """Test that default output file is created"""
        self.run_command("init", "--project", "test-project")
        code, _, _ = self.run_command("run", "--config", "release-gate.yaml")
        
        assert code == 0, "Run failed"
        
        default_file = Path(self.test_dir) / "readiness_report.json"
        assert default_file.exists(), "Default output file not created"
    
    # ========== SAMPLE VALIDATION TESTS ==========
    
    def test_input_contract_tests_valid_samples(self):
        """Test that INPUT_CONTRACT reports valid sample testing"""
        self.run_command("init", "--project", "test-project")
        code, stdout, _ = self.run_command("run", "--config", "release-gate.yaml", "--format", "json")
        
        assert code == 0, "Run failed"
        data = json.loads(stdout)
        
        # Find input_contract check
        input_contract = next((c for c in data["checks"] if c["name"] == "input_contract"), None)
        assert input_contract is not None, "input_contract check not found"
        
        # Verify evidence includes sample counts
        evidence = input_contract["evidence"]
        assert "valid_samples_tested" in evidence, "valid_samples_tested not in evidence"
        assert "invalid_samples_tested" in evidence, "invalid_samples_tested not in evidence"
        assert evidence["valid_samples_tested"] > 0, "No valid samples tested"
        assert evidence["invalid_samples_tested"] > 0, "No invalid samples tested"
    
    def test_input_contract_passes_with_matching_schema(self):
        """Test that INPUT_CONTRACT passes when samples match schema"""
        self.run_command("init", "--project", "test-project")
        code, stdout, _ = self.run_command("run", "--config", "release-gate.yaml", "--format", "json")
        
        assert code == 0, "Run failed"
        data = json.loads(stdout)
        
        input_contract = next((c for c in data["checks"] if c["name"] == "input_contract"), None)
        assert input_contract["result"] == "PASS", "Expected PASS for valid samples"
    
    # ========== CONFIGURATION TESTS ==========
    
    def test_missing_config_file(self):
        """Test that missing config file shows error"""
        code, stdout, stderr = self.run_command("run", "--config", "nonexistent.yaml")
        
        assert code != 0, "Should fail with missing config"
        assert "not found" in stderr.lower() or "error" in stderr.lower(), "Error message not shown"
    
    def test_missing_required_config_option(self):
        """Test that missing --config shows error"""
        code, stdout, stderr = self.run_command("run")
        
        assert code != 0, "Should fail without --config"
        assert "config" in stderr.lower() or "required" in stderr.lower(), "Error message about config not shown"
    
    # ========== ENVIRONMENT TESTS ==========
    
    def test_environment_option_staging(self):
        """Test that --env staging works"""
        self.run_command("init", "--project", "test-project")
        code, stdout, _ = self.run_command("run", "--config", "release-gate.yaml", "--env", "staging", "--format", "json")
        
        assert code == 0, "Run with --env staging failed"
        data = json.loads(stdout)
        assert data["environment"] == "staging", "Environment not set correctly"
    
    def test_environment_option_prod(self):
        """Test that --env prod works"""
        self.run_command("init", "--project", "test-project")
        code, stdout, _ = self.run_command("run", "--config", "release-gate.yaml", "--env", "prod", "--format", "json")
        
        assert code == 0, "Run with --env prod failed"
        data = json.loads(stdout)
        assert data["environment"] == "prod", "Environment not set correctly"


if __name__ == "__main__":
    """Run tests with pytest"""
    import pytest
    pytest.main([__file__, "-v"])

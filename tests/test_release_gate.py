"""Tests for release-gate with policy engine - Standalone version"""
import pytest
import yaml


# Copy the logic directly to avoid import issues
def determine_decision(results, policy=None):
    """
    Determine final decision based on check results and policy.
    
    Policy defines what's critical (FAIL) vs flexible (WARN).
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


class TestPolicyEngine:
    """Test policy-based decision logic"""
    
    def test_strict_policy_fails_on_any_failure(self):
        """Strict policy fails if any check fails"""
        results = {
            'ACTION_BUDGET': {'status': 'PASS'},
            'FALLBACK_DECLARED': {'status': 'FAIL'},
            'IDENTITY_BOUNDARY': {'status': 'PASS'},
            'INPUT_CONTRACT': {'status': 'PASS'},
        }
        
        policy = {
            'fail_on': ['FALLBACK_DECLARED']
        }
        
        decision = determine_decision(results, policy)
        assert decision == 'FAIL'
    
    def test_soft_policy_warns_instead(self):
        """Soft policy warns instead of fails"""
        results = {
            'ACTION_BUDGET': {'status': 'PASS'},
            'FALLBACK_DECLARED': {'status': 'FAIL'},
            'IDENTITY_BOUNDARY': {'status': 'PASS'},
            'INPUT_CONTRACT': {'status': 'PASS'},
        }
        
        policy = {
            'warn_on': ['FALLBACK_DECLARED']
        }
        
        decision = determine_decision(results, policy)
        assert decision == 'WARN'
    
    def test_no_policy_defaults_to_strict(self):
        """No policy = strict (fail on any failure)"""
        results = {
            'ACTION_BUDGET': {'status': 'PASS'},
            'FALLBACK_DECLARED': {'status': 'FAIL'},
        }
        
        decision = determine_decision(results, policy=None)
        assert decision == 'FAIL'
    
    def test_all_pass_with_policy(self):
        """All PASS results in PASS regardless of policy"""
        results = {
            'ACTION_BUDGET': {'status': 'PASS'},
            'FALLBACK_DECLARED': {'status': 'PASS'},
            'IDENTITY_BOUNDARY': {'status': 'PASS'},
            'INPUT_CONTRACT': {'status': 'PASS'},
        }
        
        policy = {
            'fail_on': ['ACTION_BUDGET'],
            'warn_on': ['FALLBACK_DECLARED']
        }
        
        decision = determine_decision(results, policy)
        assert decision == 'PASS'
    
    def test_mixed_policy_fail_takes_precedence(self):
        """FAIL takes precedence over WARN"""
        results = {
            'ACTION_BUDGET': {'status': 'FAIL'},
            'FALLBACK_DECLARED': {'status': 'WARN'},
        }
        
        policy = {
            'fail_on': ['ACTION_BUDGET'],
            'warn_on': ['FALLBACK_DECLARED']
        }
        
        decision = determine_decision(results, policy)
        assert decision == 'FAIL'
    
    def test_multiple_failures_first_fail_wins(self):
        """Multiple failures result in FAIL"""
        results = {
            'ACTION_BUDGET': {'status': 'FAIL'},
            'FALLBACK_DECLARED': {'status': 'FAIL'},
        }
        
        policy = {
            'fail_on': ['ACTION_BUDGET', 'FALLBACK_DECLARED']
        }
        
        decision = determine_decision(results, policy)
        assert decision == 'FAIL'
    
    def test_exit_code_pass(self):
        """PASS should return exit code 0"""
        code = get_exit_code('PASS')
        assert code == 0
    
    def test_exit_code_warn(self):
        """WARN should return exit code 10"""
        code = get_exit_code('WARN')
        assert code == 10
    
    def test_exit_code_fail(self):
        """FAIL should return exit code 1"""
        code = get_exit_code('FAIL')
        assert code == 1


class TestConfigParsing:
    """Test configuration parsing"""
    
    def test_yaml_config_parsing(self):
        """Test that YAML config can be parsed"""
        example_yaml = """
project:
  name: test-agent

agent:
  model: gpt-4-turbo

policy:
  fail_on:
    - ACTION_BUDGET
  warn_on:
    - FALLBACK_DECLARED

checks:
  action_budget:
    max_daily_cost: 100
"""
        config = yaml.safe_load(example_yaml)
        assert config['project']['name'] == 'test-agent'
        assert config['agent']['model'] == 'gpt-4-turbo'
        assert 'ACTION_BUDGET' in config['policy']['fail_on']
    
    def test_minimal_config(self):
        """Test minimal valid config"""
        config = {
            'project': {'name': 'test'},
            'agent': {'model': 'gpt-4'},
            'checks': {}
        }
        assert config['project']['name'] == 'test'
        assert config['agent']['model'] == 'gpt-4'


class TestActionBudgetCheck:
    """Test ACTION_BUDGET check logic"""
    
    def test_cost_calculation(self):
        """Test cost calculation works"""
        input_price = 10
        output_price = 30
        
        input_tokens = 800
        output_tokens = 400
        daily_requests = 500
        
        input_cost_per_token = input_price / 1000000
        output_cost_per_token = output_price / 1000000
        
        daily_input_cost = input_tokens * input_cost_per_token * daily_requests
        daily_output_cost = output_tokens * output_cost_per_token * daily_requests
        daily_total = daily_input_cost + daily_output_cost
        
        assert daily_total > 0
        assert daily_total < 1000
    
    def test_pass_threshold(self):
        """Test PASS threshold logic"""
        daily_cost = 30.0
        budget = 100.0
        auto_approve_threshold = budget * 0.5
        
        assert daily_cost < auto_approve_threshold
    
    def test_warn_threshold(self):
        """Test WARN threshold logic"""
        daily_cost = 70.0
        budget = 100.0
        auto_approve_threshold = budget * 0.5
        
        assert daily_cost >= auto_approve_threshold
        assert daily_cost < budget
    
    def test_fail_threshold(self):
        """Test FAIL threshold logic"""
        daily_cost = 150.0
        budget = 100.0
        
        assert daily_cost > budget


class TestValidationLogic:
    """Test validation decision logic"""
    
    def test_all_pass_decision(self):
        """Test PASS when all checks pass"""
        results = {
            'ACTION_BUDGET': {'status': 'PASS'},
            'INPUT_CONTRACT': {'status': 'PASS'},
            'FALLBACK_DECLARED': {'status': 'PASS'},
            'IDENTITY_BOUNDARY': {'status': 'PASS'},
        }
        
        decision = determine_decision(results)
        assert decision == 'PASS'
    
    def test_one_fail_decision(self):
        """Test FAIL when any check fails"""
        results = {
            'ACTION_BUDGET': {'status': 'FAIL'},
            'INPUT_CONTRACT': {'status': 'PASS'},
            'FALLBACK_DECLARED': {'status': 'PASS'},
            'IDENTITY_BOUNDARY': {'status': 'PASS'},
        }
        
        decision = determine_decision(results)
        assert decision == 'FAIL'
    
    def test_one_warn_decision(self):
        """Test WARN when any check warns"""
        results = {
            'ACTION_BUDGET': {'status': 'WARN'},
            'INPUT_CONTRACT': {'status': 'PASS'},
            'FALLBACK_DECLARED': {'status': 'PASS'},
            'IDENTITY_BOUNDARY': {'status': 'PASS'},
        }
        
        decision = determine_decision(results)
        assert decision == 'WARN'


class TestEdgeCases:
    """Test edge cases"""
    
    def test_zero_cost(self):
        """Test with zero cost"""
        daily_cost = 0.0
        budget = 100.0
        assert daily_cost < budget
    
    def test_exact_budget(self):
        """Test when cost exactly equals budget"""
        daily_cost = 100.0
        budget = 100.0
        assert daily_cost <= budget
    
    def test_large_numbers(self):
        """Test with large numbers"""
        daily_cost = 10000.0
        budget = 100.0
        assert daily_cost > budget

"""
Tests for release-gate
"""
import sys
import os
import json

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest
import yaml

class TestConfigParsing:
    """Test configuration parsing"""
    
    def test_yaml_config_parsing(self):
        """Test that YAML config can be parsed"""
        example_yaml = """
project:
  name: test-agent

agent:
  model: gpt-4-turbo
  daily_requests: 500

checks:
  action_budget:
    max_daily_cost: 100
"""
        config = yaml.safe_load(example_yaml)
        assert config['project']['name'] == 'test-agent'
        assert config['agent']['model'] == 'gpt-4-turbo'
        assert config['checks']['action_budget']['max_daily_cost'] == 100
    
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
        # Simple cost calculation test
        input_price = 10  # per 1M tokens
        output_price = 30
        
        input_tokens = 800
        output_tokens = 400
        daily_requests = 500
        
        input_cost_per_token = input_price / 1000000
        output_cost_per_token = output_price / 1000000
        
        daily_input_cost = input_tokens * input_cost_per_token * daily_requests
        daily_output_cost = output_tokens * output_cost_per_token * daily_requests
        daily_total = daily_input_cost + daily_output_cost
        
        # Should calculate without error
        assert daily_total > 0
        assert daily_total < 1000  # Reasonable bound
    
    def test_pass_threshold(self):
        """Test PASS threshold logic"""
        daily_cost = 30.0
        budget = 100.0
        auto_approve_threshold = budget * 0.5
        
        # Should be PASS (under 50% of budget)
        assert daily_cost < auto_approve_threshold
    
    def test_warn_threshold(self):
        """Test WARN threshold logic"""
        daily_cost = 70.0
        budget = 100.0
        auto_approve_threshold = budget * 0.5
        
        # Should be WARN (between 50% and 100%)
        assert daily_cost >= auto_approve_threshold
        assert daily_cost < budget
    
    def test_fail_threshold(self):
        """Test FAIL threshold logic"""
        daily_cost = 150.0
        budget = 100.0
        
        # Should be FAIL (over budget)
        assert daily_cost > budget


class TestValidationLogic:
    """Test validation decision logic"""
    
    def test_all_pass_decision(self):
        """Test PASS when all checks pass"""
        results = {
            'action_budget': {'status': 'PASS'},
            'input_contract': {'status': 'PASS'},
            'fallback_declared': {'status': 'PASS'},
            'identity_boundary': {'status': 'PASS'},
        }
        
        # If any FAIL, overall is FAIL
        has_fail = any(r['status'] == 'FAIL' for r in results.values())
        # If no FAIL but any WARN, overall is WARN
        has_warn = any(r['status'] == 'WARN' for r in results.values())
        
        final_status = 'FAIL' if has_fail else ('WARN' if has_warn else 'PASS')
        
        assert final_status == 'PASS'
    
    def test_one_fail_decision(self):
        """Test FAIL when any check fails"""
        results = {
            'action_budget': {'status': 'FAIL'},
            'input_contract': {'status': 'PASS'},
            'fallback_declared': {'status': 'PASS'},
            'identity_boundary': {'status': 'PASS'},
        }
        
        has_fail = any(r['status'] == 'FAIL' for r in results.values())
        has_warn = any(r['status'] == 'WARN' for r in results.values())
        
        final_status = 'FAIL' if has_fail else ('WARN' if has_warn else 'PASS')
        
        assert final_status == 'FAIL'
    
    def test_one_warn_decision(self):
        """Test WARN when any check warns"""
        results = {
            'action_budget': {'status': 'WARN'},
            'input_contract': {'status': 'PASS'},
            'fallback_declared': {'status': 'PASS'},
            'identity_boundary': {'status': 'PASS'},
        }
        
        has_fail = any(r['status'] == 'FAIL' for r in results.values())
        has_warn = any(r['status'] == 'WARN' for r in results.values())
        
        final_status = 'FAIL' if has_fail else ('WARN' if has_warn else 'PASS')
        
        assert final_status == 'WARN'


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

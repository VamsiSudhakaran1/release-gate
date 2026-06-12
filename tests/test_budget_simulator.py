"""Tests for Budget Simulation Engine"""

import pytest
from release_gate.pricing.budget_simulator import BudgetSimulator, BudgetSimulationCheck


class TestBudgetSimulatorBasic:
    """Test basic budget simulation"""
    
    def test_simple_simulation_pass(self):
        """Test simple simulation that passes budget"""
        config = {
            'agent': {'model': 'gpt-4-turbo'},
            'simulation': {
                'requests_per_day': 100,
                'tokens_per_request': {'input': 1000, 'output': 1000},
                'factors': {'retry_rate': 1.0, 'cache_hit_rate': 0.0}
            },
            'budget': {'max_daily_cost': 100}
        }
        
        simulator = BudgetSimulator()
        result = simulator.simulate(config)
        
        assert result['status'] == 'PASS'
        assert result['costs']['daily'] == 4.0
        assert result['budget']['safety_margin'] == 25.0
    
    def test_simulation_fails_over_budget(self):
        """Test simulation fails when exceeding budget"""
        config = {
            'agent': {'model': 'gpt-4-turbo'},
            'simulation': {
                'requests_per_day': 10000,
                'tokens_per_request': {'input': 2000, 'output': 2000},
            },
            'budget': {'max_daily_cost': 100}
        }
        
        simulator = BudgetSimulator()
        result = simulator.simulate(config)
        
        assert result['status'] == 'FAIL'
        assert result['costs']['daily'] > 100
    
    def test_simulation_warns_at_70_percent(self):
        """Test WARN status at 70% of budget.

        gpt-4-turbo: $10/1M input + $30/1M output = $0.04/request (1k tokens each)
        17500 requests/day × $0.04 = $700/day = 70% of $1000 budget → WARN
        """
        config = {
            'agent': {'model': 'gpt-4-turbo'},
            'simulation': {
                'requests_per_day': 18000,
                'tokens_per_request': {'input': 1000, 'output': 1000},
            },
            'budget': {'max_daily_cost': 1000}
        }

        simulator = BudgetSimulator()
        result = simulator.simulate(config)

        assert result['status'] == 'WARN'
        assert result['budget']['usage_percent'] >= 70
        assert result['budget']['usage_percent'] < 100


class TestBudgetSimulatorMultipliers:
    """Test multiplier calculations"""
    
    def test_retry_rate_multiplier(self):
        """Test retry rate increases costs"""
        config_no_retry = {
            'agent': {'model': 'gpt-4-turbo'},
            'simulation': {
                'requests_per_day': 1000,
                'tokens_per_request': {'input': 1000, 'output': 1000},
                'factors': {'retry_rate': 1.0}
            },
            'budget': {'max_daily_cost': 1000}
        }
        
        config_with_retry = {
            'agent': {'model': 'gpt-4-turbo'},
            'simulation': {
                'requests_per_day': 1000,
                'tokens_per_request': {'input': 1000, 'output': 1000},
                'factors': {'retry_rate': 1.2}
            },
            'budget': {'max_daily_cost': 1000}
        }
        
        simulator = BudgetSimulator()
        result_no_retry = simulator.simulate(config_no_retry)
        result_with_retry = simulator.simulate(config_with_retry)
        
        assert result_with_retry['costs']['daily'] == pytest.approx(
            result_no_retry['costs']['daily'] * 1.2, rel=0.01
        )
    
    def test_cache_hit_rate_multiplier(self):
        """Test cache hits reduce costs"""
        config_no_cache = {
            'agent': {'model': 'gpt-4-turbo'},
            'simulation': {
                'requests_per_day': 1000,
                'tokens_per_request': {'input': 1000, 'output': 1000},
                'factors': {'cache_hit_rate': 0.0}
            },
            'budget': {'max_daily_cost': 1000}
        }
        
        config_with_cache = {
            'agent': {'model': 'gpt-4-turbo'},
            'simulation': {
                'requests_per_day': 1000,
                'tokens_per_request': {'input': 1000, 'output': 1000},
                'factors': {'cache_hit_rate': 0.3}
            },
            'budget': {'max_daily_cost': 1000}
        }
        
        simulator = BudgetSimulator()
        result_no_cache = simulator.simulate(config_no_cache)
        result_with_cache = simulator.simulate(config_with_cache)
        
        assert result_with_cache['costs']['daily'] == pytest.approx(
            result_no_cache['costs']['daily'] * 0.7, rel=0.01
        )


class TestBudgetSimulatorModels:
    """Test different model pricing"""
    
    def test_openai_models(self):
        """Test OpenAI model pricing"""
        simulator = BudgetSimulator()
        
        models = ['gpt-4-turbo', 'gpt-4', 'gpt-3.5-turbo']
        for model in models:
            pricing = simulator.get_pricing(model)
            assert pricing is not None
            assert pricing['provider'] == 'openai'
            assert pricing['input'] > 0
            assert pricing['output'] > 0
    
    def test_anthropic_models(self):
        """Test Anthropic model pricing"""
        simulator = BudgetSimulator()
        
        models = ['claude-3-opus', 'claude-3-sonnet', 'claude-3-haiku']
        for model in models:
            pricing = simulator.get_pricing(model)
            assert pricing is not None
            assert pricing['provider'] == 'anthropic'
    
    def test_unknown_model(self):
        """Test handling of unknown model"""
        config = {
            'agent': {'model': 'unknown-model'},
            'simulation': {'requests_per_day': 100},
            'budget': {'max_daily_cost': 100}
        }
        
        simulator = BudgetSimulator()
        result = simulator.simulate(config)
        
        assert result['status'] == 'FAIL'
        assert 'error' in result


class TestBudgetSimulationCheck:
    """Test release-gate check integration"""
    
    def test_check_passes(self):
        """Test check passes with good budget"""
        config = {
            'agent': {'model': 'gpt-4-turbo'},
            'simulation': {
                'requests_per_day': 100,
                'tokens_per_request': {'input': 1000, 'output': 1000},
            },
            'budget': {'max_daily_cost': 100}
        }
        
        check = BudgetSimulationCheck()
        result = check.evaluate(config)
        
        assert result['status'] == 'PASS'
        assert 'evidence' in result
        assert result['evidence']['daily_cost'] is not None
    
    def test_check_fails(self):
        """Test check fails with exceeded budget"""
        config = {
            'agent': {'model': 'gpt-4-turbo'},
            'simulation': {
                'requests_per_day': 10000,
                'tokens_per_request': {'input': 2000, 'output': 2000},
            },
            'budget': {'max_daily_cost': 100}
        }
        
        check = BudgetSimulationCheck()
        result = check.evaluate(config)
        
        assert result['status'] == 'FAIL'
    
    def test_check_skips_no_simulation(self):
        """Test check skips when no simulation configured"""
        config = {
            'agent': {'model': 'gpt-4-turbo'},
            'budget': {'max_daily_cost': 100}
        }
        
        check = BudgetSimulationCheck()
        result = check.evaluate(config)
        
        assert result['status'] == 'PASS'
        assert result['evidence']['skipped'] == True


class TestBudgetSimulatorEdgeCases:
    """Test edge cases"""
    
    def test_zero_requests(self):
        """Test zero requests per day"""
        config = {
            'agent': {'model': 'gpt-4-turbo'},
            'simulation': {
                'requests_per_day': 0,
                'tokens_per_request': {'input': 1000, 'output': 1000},
            },
            'budget': {'max_daily_cost': 100}
        }
        
        simulator = BudgetSimulator()
        result = simulator.simulate(config)
        
        assert result['status'] == 'PASS'
        assert result['costs']['daily'] == 0
    
    def test_zero_budget(self):
        """Test zero budget"""
        config = {
            'agent': {'model': 'gpt-4-turbo'},
            'simulation': {
                'requests_per_day': 100,
                'tokens_per_request': {'input': 1000, 'output': 1000},
            },
            'budget': {'max_daily_cost': 0}
        }
        
        simulator = BudgetSimulator()
        result = simulator.simulate(config)
        
        assert result['status'] == 'FAIL'
        assert result['costs']['daily'] > 0
    
    def test_no_budget(self):
        """Test missing budget (infinite)"""
        config = {
            'agent': {'model': 'gpt-4-turbo'},
            'simulation': {
                'requests_per_day': 100,
                'tokens_per_request': {'input': 1000, 'output': 1000},
            }
        }
        
        simulator = BudgetSimulator()
        result = simulator.simulate(config)
        
        assert result['status'] == 'PASS'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

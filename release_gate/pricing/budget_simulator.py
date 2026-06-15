"""Budget Simulation Engine for release-gate

Simulates realistic costs for AI agents based on usage patterns, model pricing,
and real-world factors like retries, caching, and spiky usage.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
import json
from datetime import datetime, timezone


@dataclass
class ModelPricing:
    """Model pricing information"""
    model: str
    provider: str
    input_price: float  # per 1M tokens
    output_price: float  # per 1M tokens
    source: str = "official"
    updated: str = ""


class BudgetSimulator:
    """Cost simulation engine for AI agents"""
    
    # Official pricing data (per 1M tokens)
    PRICING = {
        # OpenAI
        'gpt-4-turbo': {'input': 10.0, 'output': 30.0, 'provider': 'openai'},
        'gpt-4': {'input': 30.0, 'output': 60.0, 'provider': 'openai'},
        'gpt-3.5-turbo': {'input': 0.50, 'output': 1.50, 'provider': 'openai'},
        
        # Anthropic
        'claude-3-opus': {'input': 15.0, 'output': 75.0, 'provider': 'anthropic'},
        'claude-3-sonnet': {'input': 3.0, 'output': 15.0, 'provider': 'anthropic'},
        'claude-3-haiku': {'input': 0.25, 'output': 1.25, 'provider': 'anthropic'},
        'claude-3.5-sonnet': {'input': 3.0, 'output': 15.0, 'provider': 'anthropic'},
        
        # Google
        'gemini-2.0-flash': {'input': 0.075, 'output': 0.3, 'provider': 'google'},
        'gemini-pro': {'input': 0.5, 'output': 1.5, 'provider': 'google'},
        
        # XAI (Grok)
        'grok-2': {'input': 2.0, 'output': 10.0, 'provider': 'xai'},
        'grok-3': {'input': 5.0, 'output': 15.0, 'provider': 'xai'},
    }
    
    def __init__(self, custom_pricing: Optional[Dict] = None):
        """Initialize simulator with optional custom pricing"""
        self.custom_pricing = custom_pricing or {}
        self.pricing = {**self.PRICING, **self.custom_pricing}
    
    def simulate(self, config: Dict) -> Dict:
        """
        Simulate cost for given configuration
        
        Args:
            config: Configuration dict with agent, simulation, budget sections
            
        Returns:
            dict: Simulation results with cost projections
        """
        try:
            simulation = config.get('simulation', {})
            agent = config.get('agent', {})
            budget = config.get('budget', {})
            
            # Validate inputs
            if not simulation:
                return self._no_simulation_result()
            
            # Extract parameters
            model = agent.get('model', 'gpt-4-turbo')

            # v0.6: optional `model:` block resolves pricing from a source chain
            # (static / custom / locked / openrouter / litellm) instead of only
            # the hardcoded table. Purely additive — legacy configs are untouched.
            model_block = config.get('model')
            pricing_meta = None
            if model_block:
                resolved = self._resolve_model_block(model_block, config)
                pricing_meta = resolved.as_dict()
                model = model_block.get('id') or model_block.get('model') or model
                if resolved.resolved:
                    self.register_custom_pricing(
                        model,
                        resolved.input_per_1m,
                        resolved.output_per_1m,
                        resolved.provider,
                    )
                else:
                    # Never let unknown cost silently pass.
                    return self._unresolved_pricing_result(model, resolved)

            requests_per_day = simulation.get('requests_per_day', 1000)
            tokens = simulation.get('tokens_per_request', {})
            input_tokens = tokens.get('input', 800)
            output_tokens = tokens.get('output', 400)
            
            # Get factors (with safe defaults)
            factors = simulation.get('factors', {})
            retry_rate = factors.get('retry_rate', 1.0)
            cache_hit_rate = factors.get('cache_hit_rate', 0.0)
            spiky_usage = factors.get('spiky_usage_multiplier', 1.0)

            # Validate factor ranges
            if not (1.0 <= retry_rate <= 10.0):
                return {
                    'status': 'FAIL',
                    'error': f'retry_rate must be between 1.0 and 10.0, got {retry_rate}',
                    'timestamp': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
                }
            if not (0.0 <= cache_hit_rate <= 1.0):
                return {
                    'status': 'FAIL',
                    'error': f'cache_hit_rate must be between 0.0 and 1.0, got {cache_hit_rate}',
                    'timestamp': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
                }
            if not (1.0 <= spiky_usage <= 20.0):
                return {
                    'status': 'FAIL',
                    'error': f'spiky_usage_multiplier must be between 1.0 and 20.0, got {spiky_usage}',
                    'timestamp': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
                }
            
            # Get pricing
            pricing = self.get_pricing(model)
            if not pricing:
                return self._unknown_model_result(model)
            
            # Calculate daily cost
            daily_cost = self._calculate_daily_cost(
                requests_per_day=requests_per_day,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                retry_rate=retry_rate,
                cache_hit_rate=cache_hit_rate,
                spiky_usage=spiky_usage,
                pricing=pricing
            )
            
            # Get budget
            max_daily_cost = budget.get('max_daily_cost', float('inf'))
            
            # Determine status
            status = self._determine_status(daily_cost, max_daily_cost)
            safety_margin = self._calculate_margin(daily_cost, max_daily_cost)
            
            # Build results
            results = {
                'status': status,
                'model': model,
                'provider': pricing.get('provider', 'unknown'),
                'costs': {
                    'daily': round(daily_cost, 2),
                    'weekly': round(daily_cost * 7, 2),
                    'monthly': round(daily_cost * 30, 2),
                    'annual': round(daily_cost * 365, 2),
                },
                'budget': {
                    'max_daily': max_daily_cost,
                    'estimated_daily': round(daily_cost, 2),
                    'overage': max(0, round(daily_cost - max_daily_cost, 2)),
                    'safety_margin': round(safety_margin, 2),
                    'usage_percent': round((daily_cost / max_daily_cost * 100) if max_daily_cost > 0 else 0, 1),
                },
                'breakdown': {
                    'requests_per_day': requests_per_day,
                    'input_tokens_per_request': input_tokens,
                    'output_tokens_per_request': output_tokens,
                    'daily_input_tokens': round(requests_per_day * input_tokens, 0),
                    'daily_output_tokens': round(requests_per_day * output_tokens, 0),
                    'input_cost': round((requests_per_day * input_tokens / 1_000_000) * pricing['input'] * retry_rate * (1 - cache_hit_rate) * spiky_usage, 2),
                    'output_cost': round((requests_per_day * output_tokens / 1_000_000) * pricing['output'] * retry_rate * (1 - cache_hit_rate) * spiky_usage, 2),
                },
                'multipliers': {
                    'retry_rate': retry_rate,
                    'cache_hit_rate': cache_hit_rate,
                    'spiky_usage': spiky_usage,
                },
                'confidence': {
                    'level': 'medium',
                    'factors': [
                        'Estimated based on simulation parameters',
                        'Actual costs depend on real usage patterns',
                        'Cache performance varies by query type',
                        'Retry rate depends on model reliability'
                    ],
                    'recommendations': [
                        'Monitor actual vs estimated costs after deployment',
                        'Adjust simulation parameters based on real data',
                        f'Set budget alert at 70% of estimated cost (${daily_cost * 0.7:.2f}/day)'
                    ]
                },
                'timestamp': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
            }

            if pricing_meta is not None:
                results['pricing'] = pricing_meta
                # A WARN-level pricing signal (stale lock / fallback source)
                # should not downgrade a passing budget, but it must be visible.
                if pricing_meta.get('status') == 'WARN' and results['status'] == 'PASS':
                    results['status'] = 'WARN'

            return results

        except Exception as e:
            return {
                'status': 'FAIL',
                'error': str(e),
                'timestamp': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
            }
    
    def _calculate_daily_cost(self, requests_per_day: int, input_tokens: int, 
                             output_tokens: int, retry_rate: float, 
                             cache_hit_rate: float, spiky_usage: float, 
                             pricing: Dict) -> float:
        """Calculate daily cost with all multipliers"""
        # Base tokens
        daily_input = requests_per_day * input_tokens
        daily_output = requests_per_day * output_tokens
        
        # Apply multipliers in order
        # 1. Retries increase token count
        daily_input *= retry_rate
        daily_output *= retry_rate
        
        # 2. Cache hits reduce token count
        daily_input *= (1 - cache_hit_rate)
        daily_output *= (1 - cache_hit_rate)
        
        # 3. Spiky usage accounts for peak times
        daily_input *= spiky_usage
        daily_output *= spiky_usage
        
        # Calculate cost (pricing is per 1M tokens)
        input_cost = (daily_input / 1_000_000) * pricing['input']
        output_cost = (daily_output / 1_000_000) * pricing['output']
        
        return input_cost + output_cost
    
    def _determine_status(self, estimated_cost: float, budget: float) -> str:
        """Determine PASS/WARN/FAIL status"""
        if budget == float('inf'):
            return 'PASS'
        
        if estimated_cost > budget:
            return 'FAIL'
        elif estimated_cost > budget * 0.7:  # 70% of budget is warning threshold
            return 'WARN'
        else:
            return 'PASS'
    
    def _calculate_margin(self, estimated_cost: float, budget: float) -> float:
        """Calculate safety margin as multiple of budget"""
        if estimated_cost == 0:
            return float('inf')
        if budget == 0:
            return 0
        return budget / estimated_cost
    
    def _resolve_model_block(self, model_block: Dict, config: Dict):
        """Resolve a `model:` block's pricing via the PricingResolver chain."""
        # Imported lazily to avoid a hard dependency for legacy code paths.
        from release_gate.pricing.resolver import PricingResolver

        pricing = model_block.get('pricing', {}) or {}
        lock_path = pricing.get('lock_path', 'pricing.lock.json')
        # Live fetches are opt-in: a source of 'static'/'custom'/'locked' never
        # touches the network, and config can force offline with allow_network.
        allow_network = config.get('pricing', {}).get('allow_network', True)
        resolver = PricingResolver(allow_network=allow_network)
        return resolver.resolve(model_block, lock_path=lock_path)

    def _unresolved_pricing_result(self, model: str, resolved) -> Dict:
        """Return a non-passing result when pricing cannot be resolved."""
        # on_unknown=warn -> WARN (review), otherwise FAIL (block / hold).
        status = 'WARN' if resolved.status == 'WARN' else 'FAIL'
        return {
            'status': status,
            'model': model,
            'error': f'Pricing could not be resolved for {model}: {resolved.reason}',
            'pricing': resolved.as_dict(),
            'timestamp': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        }

    def _no_simulation_result(self) -> Dict:
        """Return result when no simulation is configured"""
        return {
            'status': 'PASS',
            'message': 'No simulation configured',
            'timestamp': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        }
    
    def _unknown_model_result(self, model: str) -> Dict:
        """Return result for unknown model"""
        return {
            'status': 'FAIL',
            'error': f'Unknown model: {model}',
            'available_models': list(self.pricing.keys()),
            'timestamp': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        }
    
    def get_pricing(self, model: str) -> Optional[Dict]:
        """Get pricing for model"""
        return self.pricing.get(model)
    
    def list_models(self) -> List[str]:
        """List all available models"""
        return sorted(list(self.pricing.keys()))
    
    def register_custom_pricing(self, model: str, input_price: float, 
                               output_price: float, provider: str = 'custom'):
        """Register custom model pricing"""
        self.pricing[model] = {
            'input': input_price,
            'output': output_price,
            'provider': provider
        }


class BudgetSimulationCheck:
    """Release-gate check for budget simulation"""
    
    def __init__(self):
        self.simulator = BudgetSimulator()
    
    def evaluate(self, config: Dict) -> Dict:
        """
        Evaluate BUDGET_SIMULATION check
        
        Args:
            config: Full governance configuration
            
        Returns:
            dict: Check result with status and evidence
        """
        simulation = config.get('simulation')
        
        # Skip if no simulation configured
        if not simulation:
            return {
                'status': 'PASS',
                'evidence': {'skipped': True, 'message': 'No simulation configured'}
            }
        
        # Run simulation
        result = self.simulator.simulate(config)
        
        # Handle errors
        if 'error' in result:
            return {
                'status': 'FAIL',
                'evidence': {'error': result['error']}
            }
        
        # Return as check result
        return {
            'status': result['status'],
            'evidence': {
                'model': result.get('model'),
                'provider': result.get('provider'),
                'daily_cost': result.get('costs', {}).get('daily'),
                'monthly_cost': result.get('costs', {}).get('monthly'),
                'annual_cost': result.get('costs', {}).get('annual'),
                'budget_daily': result.get('budget', {}).get('max_daily'),
                'safety_margin': result.get('budget', {}).get('safety_margin'),
                'usage_percent': result.get('budget', {}).get('usage_percent'),
                'confidence': result.get('confidence'),
                'breakdown': result.get('breakdown'),
            }
        }


# Export main class and check
__all__ = ['BudgetSimulator', 'BudgetSimulationCheck']

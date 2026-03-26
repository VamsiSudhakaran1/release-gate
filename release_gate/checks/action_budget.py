"""
ACTION_BUDGET Check for release-gate
File: release_gate/checks/action_budget.py

Copy this file directly into your repository at:
release_gate/checks/action_budget.py
"""

from dataclasses import dataclass
from typing import Dict, List, Optional
from datetime import datetime


@dataclass
class CostEstimate:
    """Cost estimation with full transparency"""
    daily_cost: float
    monthly_cost: float
    model: str
    input_tokens_per_request: int
    output_tokens_per_request: int
    daily_requests: int
    calculation: Dict
    assumptions: List[str]
    estimated_at: str


class CostEstimator:
    """Estimate agent cost"""
    
    PRICING = {
        "gpt-4": {
            "name": "GPT-4",
            "provider": "OpenAI",
            "input": 0.00003,
            "output": 0.0001,
        },
        "gpt-4-turbo": {
            "name": "GPT-4 Turbo",
            "provider": "OpenAI",
            "input": 0.00001,
            "output": 0.00003,
        },
        "gpt-4o": {
            "name": "GPT-4o",
            "provider": "OpenAI",
            "input": 0.000005,
            "output": 0.000015,
        },
        "claude-3-opus": {
            "name": "Claude 3 Opus",
            "provider": "Anthropic",
            "input": 0.000015,
            "output": 0.000075,
        },
        "claude-3-sonnet": {
            "name": "Claude 3 Sonnet",
            "provider": "Anthropic",
            "input": 0.000003,
            "output": 0.000015,
        },
        "claude-3-5-sonnet": {
            "name": "Claude 3.5 Sonnet",
            "provider": "Anthropic",
            "input": 0.000003,
            "output": 0.000015,
        },
    }
    
    def estimate_cost(
        self,
        model: str,
        daily_requests: int,
        avg_input_tokens: int,
        avg_output_tokens: int,
        retry_rate: float = 1.0
    ) -> CostEstimate:
        """Estimate cost for an agent"""
        
        # Validate inputs
        if daily_requests <= 0:
            raise ValueError("daily_requests must be > 0")
        if avg_input_tokens <= 0 or avg_output_tokens <= 0:
            raise ValueError("Token counts must be > 0")
        
        # Get pricing
        if model not in self.PRICING:
            raise ValueError(f"Unknown model: {model}")
        
        pricing = self.PRICING[model]
        
        # Calculate costs
        daily_input_cost = (
            (avg_input_tokens / 1000) * 
            pricing['input'] * 
            daily_requests * 
            retry_rate
        )
        
        daily_output_cost = (
            (avg_output_tokens / 1000) * 
            pricing['output'] * 
            daily_requests * 
            retry_rate
        )
        
        daily_total = daily_input_cost + daily_output_cost
        monthly_total = daily_total * 30
        
        calculation = {
            "model": pricing["name"],
            "pricing": {
                "input_per_1k_tokens": f"${pricing['input']:.8f}",
                "output_per_1k_tokens": f"${pricing['output']:.8f}"
            },
            "usage": {
                "daily_requests": daily_requests,
                "avg_input_tokens": avg_input_tokens,
                "avg_output_tokens": avg_output_tokens,
                "retry_multiplier": retry_rate
            },
            "breakdown": {
                "daily_input_cost": f"${daily_input_cost:.2f}",
                "daily_output_cost": f"${daily_output_cost:.2f}",
                "daily_total": f"${daily_total:.2f}",
                "monthly_total": f"${monthly_total:.2f}"
            }
        }
        
        assumptions = [
            f"Model: {pricing['name']} (from {pricing.get('provider', 'Unknown')})",
            f"Volume: {daily_requests} requests/day × 30 days/month",
            f"Input: {avg_input_tokens} tokens/request",
            f"Output: {avg_output_tokens} tokens/request",
            f"Retries: {retry_rate}x multiplier",
        ]
        
        return CostEstimate(
            daily_cost=daily_total,
            monthly_cost=monthly_total,
            model=model,
            input_tokens_per_request=avg_input_tokens,
            output_tokens_per_request=avg_output_tokens,
            daily_requests=daily_requests,
            calculation=calculation,
            assumptions=assumptions,
            estimated_at=datetime.utcnow().isoformat()
        )


class ActionBudgetCheck:
    """ACTION_BUDGET Check: Prevent cost explosions"""
    
    name = "ACTION_BUDGET"
    version = "v1.0.0"
    status = "STABLE"
    severity = "critical"
    
    def __init__(self):
        self.estimator = CostEstimator()
    
    def evaluate(self, config: Dict) -> Dict:
        """Evaluate cost budget compliance"""
        
        try:
            # Parse configuration
            budget_dict = config.get('checks', {}).get('action_budget', {})
            max_daily_cost = budget_dict.get('max_daily_cost')
            
            if max_daily_cost is None:
                return self._error_no_budget_defined(config)
            
            # Extract agent configuration
            agent_config = config.get('agent', {})
            model = agent_config.get('model', 'gpt-4-turbo')
            daily_requests = agent_config.get('daily_requests', 100)
            avg_input_tokens = agent_config.get('avg_input_tokens', 500)
            avg_output_tokens = agent_config.get('avg_output_tokens', 500)
            retry_rate = agent_config.get('retry_rate', 1.0)
            
            # Estimate cost
            cost_estimate = self.estimator.estimate_cost(
                model=model,
                daily_requests=daily_requests,
                avg_input_tokens=avg_input_tokens,
                avg_output_tokens=avg_output_tokens,
                retry_rate=retry_rate
            )
            
            # Validate against budget
            return self._validate_against_budget(cost_estimate, max_daily_cost, config)
        
        except Exception as e:
            return self._error(str(e))
    
    def _validate_against_budget(self, cost_estimate: CostEstimate, max_daily: float, config: Dict) -> Dict:
        """Validate cost against budget"""
        
        daily_cost = cost_estimate.daily_cost
        safety_margin = max_daily / daily_cost if daily_cost > 0 else float('inf')
        
        auto_approve = max_daily * 0.1  # Default 10%
        
        evidence = {
            "estimated_daily_cost": f"${daily_cost:.2f}",
            "estimated_monthly_cost": f"${cost_estimate.monthly_cost:.2f}",
            "max_daily_budget": f"${max_daily:.2f}",
            "safety_margin": f"{safety_margin:.1f}x",
            "model": cost_estimate.model,
            "cost_calculation": cost_estimate.calculation,
            "assumptions": cost_estimate.assumptions,
        }
        
        if daily_cost <= auto_approve:
            return {
                "status": "PASS",
                "severity": "low",
                "title": "Cost Control: Automatic Approval",
                "details": f"Daily cost: ${daily_cost:.2f} (Budget: ${max_daily:.2f}, Margin: {safety_margin:.1f}x)",
                "evidence": evidence,
                "reasoning": [
                    f"✓ Daily cost ${daily_cost:.2f} is well under the ${max_daily:.2f} limit",
                    f"✓ Safety margin is {safety_margin:.1f}x (comfortable)",
                    "✓ No manual approval needed"
                ]
            }
        
        elif daily_cost <= max_daily:
            return {
                "status": "WARN",
                "severity": "high",
                "title": "Cost Control: At Budget Limit",
                "details": f"Daily cost: ${daily_cost:.2f} (Budget: ${max_daily:.2f})",
                "evidence": evidence,
                "reasoning": [
                    f"⚠ Daily cost ${daily_cost:.2f} is near/at the maximum budget",
                    f"⚠ Safety margin is {safety_margin:.1f}x (no buffer)",
                    "⚠ Consider raising budget or optimizing cost"
                ],
                "action_required": "Review or increase budget"
            }
        
        else:
            overage_daily = daily_cost - max_daily
            overage_monthly = overage_daily * 30
            
            return {
                "status": "FAIL",
                "severity": "critical",
                "title": "Cost Control: Budget Exceeded",
                "details": f"Daily cost: ${daily_cost:.2f} exceeds Budget: ${max_daily:.2f}",
                "evidence": evidence,
                "reasoning": [
                    f"✗ Daily cost ${daily_cost:.2f} EXCEEDS the maximum budget of ${max_daily:.2f}",
                    f"✗ Daily overage: ${overage_daily:.2f}",
                    f"✗ Monthly overage: ${overage_monthly:.2f}",
                    "✗ This is how agents cost companies thousands without limits",
                    "✗ BLOCKED: Cannot deploy without fixing cost configuration"
                ],
                "action_required": "Reduce cost or increase budget",
                "remediation_steps": [
                    f"Option 1: Increase max_daily_cost to ${daily_cost:.2f} or higher",
                    f"Option 2: Use cheaper model (gpt-4-turbo is 3.3x cheaper than gpt-4)",
                    f"Option 3: Reduce daily request volume",
                    f"Option 4: Reduce average tokens (prompt engineering)",
                ]
            }
    
    def _error_no_budget_defined(self, config: Dict) -> Dict:
        """Error when no budget is defined"""
        
        try:
            agent_config = config.get('agent', {})
            estimate = self.estimator.estimate_cost(
                model=agent_config.get('model', 'gpt-4-turbo'),
                daily_requests=agent_config.get('daily_requests', 100),
                avg_input_tokens=agent_config.get('avg_input_tokens', 500),
                avg_output_tokens=agent_config.get('avg_output_tokens', 500),
                retry_rate=agent_config.get('retry_rate', 1.0)
            )
        except:
            estimate = None
        
        evidence = {}
        if estimate:
            evidence = {
                "estimated_daily_cost": f"${estimate.daily_cost:.2f}",
                "estimated_monthly_cost": f"${estimate.monthly_cost:.2f}",
                "budget_configured": "NONE (REQUIRED)",
                "calculation": estimate.calculation,
            }
        
        return {
            "status": "FAIL",
            "severity": "critical",
            "title": "Cost Control: No Budget Defined",
            "details": "max_daily_cost is not set in governance.yaml",
            "evidence": evidence,
            "reasoning": [
                "✗ Agent estimated to cost $X/day without limits" if estimate else "✗ Agent cost cannot be estimated",
                "✗ Without a budget limit, cost is unlimited",
                "✗ This is how agents cost companies thousands in a single day",
                "✗ BLOCKED: Budget limit is mandatory"
            ],
            "action_required": "Set max_daily_cost in governance.yaml",
            "remediation_steps": [
                "Add to governance.yaml:",
                "  checks:",
                "    action_budget:",
                "      max_daily_cost: 100",
                "Adjust 100 to your appropriate budget",
                "Re-run release-gate check"
            ]
        }
    
    def _error(self, error_msg: str) -> Dict:
        """General error"""
        return {
            "status": "ERROR",
            "severity": "critical",
            "title": "Cost Control: Error During Evaluation",
            "details": error_msg,
            "evidence": {},
            "reasoning": [
                "An error occurred while evaluating cost control",
                "Please review the error and try again"
            ]
        }

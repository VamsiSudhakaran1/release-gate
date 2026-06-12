"""
Impact Simulator for release-gate.

Translates missing governance into concrete business impact — dollars, not warnings.
Shows normal cost, runaway-loop scenario, and what deploying without safeguards costs.
"""

from typing import Dict, Any, Optional
from release_gate.pricing.budget_simulator import BudgetSimulator


# Runaway multipliers: what happens when an agent loops without limits
_RUNAWAY_RETRY_MULTIPLIER = 15.0   # 15x retries (infinite-loop style)
_RUNAWAY_SPIKE_MULTIPLIER = 5.0    # 5x traffic spike


class ImpactSimulator:
    """
    Computes normal AND runaway-scenario costs so engineering leaders see
    'money at risk', not just 'missing config'.
    """

    def __init__(self, custom_pricing: Optional[Dict] = None):
        self._sim = BudgetSimulator(custom_pricing)

    def simulate(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run both normal and runaway simulations.

        Returns a rich dict with:
          - normal: expected costs
          - runaway: costs if limits are absent / a loop occurs
          - risk_delta: extra spend exposed by missing safeguards
          - governance_gaps: human-readable list of what's missing
          - verdict: BLOCK | WARN | PASS
        """
        agent = config.get("agent", {})
        simulation = config.get("simulation", {})
        budget = config.get("budget", {})
        checks = config.get("checks", {})

        model = agent.get("model", "gpt-4-turbo")
        requests_per_day = simulation.get("requests_per_day", 1000)
        tokens = simulation.get("tokens_per_request", {})
        input_tokens = tokens.get("input", 800)
        output_tokens = tokens.get("output", 400)
        factors = simulation.get("factors", {})
        retry_rate = factors.get("retry_rate", 1.0)
        cache_hit_rate = factors.get("cache_hit_rate", 0.0)
        spiky = factors.get("spiky_usage_multiplier", 1.0)
        max_daily = budget.get("max_daily_cost")

        # --- Normal scenario ---
        normal_result = self._sim.simulate(config)
        normal_daily = normal_result.get("costs", {}).get("daily", 0.0)

        # --- Runaway scenario ---
        runaway_config = {
            "agent": {"model": model},
            "simulation": {
                "requests_per_day": requests_per_day,
                "tokens_per_request": {"input": input_tokens, "output": output_tokens},
                "factors": {
                    "retry_rate": min(_RUNAWAY_RETRY_MULTIPLIER, 10.0),
                    "cache_hit_rate": 0.0,  # cache is bypassed in loops
                    "spiky_usage_multiplier": min(_RUNAWAY_SPIKE_MULTIPLIER, 20.0),
                },
            },
            "budget": {},  # no budget cap for runaway calc
        }
        runaway_result = self._sim.simulate(runaway_config)
        runaway_daily = runaway_result.get("costs", {}).get("daily", 0.0)

        # --- Governance gaps ---
        gaps = _detect_governance_gaps(checks)

        # --- Risk delta ---
        risk_delta_daily = runaway_daily - normal_daily

        # --- Verdict ---
        verdict = _compute_verdict(normal_daily, max_daily, gaps)

        return {
            "model": model,
            "provider": normal_result.get("provider", "unknown"),
            "requests_per_day": requests_per_day,
            "tokens_per_request": {"input": input_tokens, "output": output_tokens},
            "normal": {
                "daily": normal_daily,
                "monthly": round(normal_daily * 30, 2),
                "annual": round(normal_daily * 365, 2),
            },
            "runaway": {
                "daily": runaway_daily,
                "monthly": round(runaway_daily * 30, 2),
                "annual": round(runaway_daily * 365, 2),
                "assumption": f"{_RUNAWAY_RETRY_MULTIPLIER}x retries + {_RUNAWAY_SPIKE_MULTIPLIER}x traffic (no kill switch)",
            },
            "risk_delta": {
                "daily": round(risk_delta_daily, 2),
                "monthly": round(risk_delta_daily * 30, 2),
                "description": "Extra spend exposed by missing safeguards",
            },
            "budget": {
                "max_daily": max_daily,
                "headroom": round(max_daily - normal_daily, 2) if max_daily is not None else None,
                "normal_status": normal_result.get("status", "UNKNOWN"),
            },
            "governance_gaps": gaps,
            "verdict": verdict,
        }


def _detect_governance_gaps(checks: Dict[str, Any]) -> list:
    """Return list of governance gaps with their business impact description."""
    gaps = []

    fb = checks.get("fallback_declared", {})
    if not fb.get("kill_switch"):
        gaps.append({
            "check": "FALLBACK_DECLARED",
            "field": "kill_switch",
            "impact": "No way to stop a runaway agent — manual intervention required",
        })
    if not fb.get("team_owner"):
        gaps.append({
            "check": "FALLBACK_DECLARED",
            "field": "team_owner",
            "impact": "No owner means no one gets paged when costs spike at 3 AM",
        })
    if not fb.get("runbook_url"):
        gaps.append({
            "check": "FALLBACK_DECLARED",
            "field": "runbook_url",
            "impact": "No runbook means slow incident response",
        })

    ib = checks.get("identity_boundary", {})
    if not ib.get("authentication", {}).get("required"):
        gaps.append({
            "check": "IDENTITY_BOUNDARY",
            "field": "authentication",
            "impact": "Unauthenticated access allows unlimited cost generation by anyone",
        })
    rl = ib.get("rate_limit", {})
    if not rl.get("requests_per_minute"):
        gaps.append({
            "check": "IDENTITY_BOUNDARY",
            "field": "rate_limit",
            "impact": "No rate limit — a single client can exhaust budget in minutes",
        })

    ab = checks.get("action_budget", {})
    if not ab.get("max_daily_cost"):
        gaps.append({
            "check": "ACTION_BUDGET",
            "field": "max_daily_cost",
            "impact": "Unlimited spend — no circuit breaker on daily cost",
        })

    ic = checks.get("input_contract", {})
    if not ic.get("schema"):
        gaps.append({
            "check": "INPUT_CONTRACT",
            "field": "schema",
            "impact": "Malformed inputs may trigger excessive retries, multiplying token usage",
        })

    return gaps


def _compute_verdict(normal_daily: float, max_daily: Optional[float], gaps: list) -> str:
    critical_gaps = [
        g for g in gaps
        if g["check"] in ("ACTION_BUDGET", "FALLBACK_DECLARED", "IDENTITY_BOUNDARY")
    ]
    if critical_gaps:
        return "BLOCK"
    if max_daily is not None and normal_daily > max_daily:
        return "BLOCK"
    if max_daily is not None and normal_daily > max_daily * 0.7:
        return "WARN"
    return "PASS"

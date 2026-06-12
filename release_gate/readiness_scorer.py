"""
Readiness Scorer for release-gate.

Converts governance checks, eval results, trace violations, and impact
simulation into a 0-100 readiness score with a PROMOTE / HOLD / BLOCK decision.
"""

from __future__ import annotations
from typing import Dict, Any, List, Optional

THRESHOLDS = {
    "promote": 90,  # >= 90 → PROMOTE
    "hold":    75,  # 75-89 → HOLD (manual approval required)
}                   # < 75  → BLOCK

DIMENSION_WEIGHTS = {
    "safety":        0.30,
    "cost":          0.20,
    "access_control":0.20,
    "fallback":      0.15,
    "eval_quality":  0.10,
    "observability": 0.05,
}

CRITICAL_CHECKS = {"FALLBACK_DECLARED", "ACTION_BUDGET", "IDENTITY_BOUNDARY"}


class ReadinessScorer:
    """Score a release from 0-100 and recommend PROMOTE / HOLD / BLOCK."""

    def score(
        self,
        check_results: Dict[str, Any],
        impact: Optional[Dict[str, Any]] = None,
        eval_results: Optional[Dict[str, Any]] = None,
        trace_results: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        dims = self._score_dimensions(check_results, impact, eval_results, trace_results)

        overall = round(
            sum(dims[d]["score"] * DIMENSION_WEIGHTS[d] for d in DIMENSION_WEIGHTS)
        )

        critical_failures = self._find_critical_failures(check_results, eval_results, trace_results)

        if critical_failures:
            decision = "BLOCK"
        elif overall >= THRESHOLDS["promote"]:
            decision = "PROMOTE"
        elif overall >= THRESHOLDS["hold"]:
            decision = "HOLD"
        else:
            decision = "BLOCK"

        return {
            "readiness_score": overall,
            "decision": decision,
            "confidence": self._confidence(check_results, eval_results, trace_results),
            "dimensions": dims,
            "critical_failures": critical_failures,
            "thresholds": THRESHOLDS,
        }

    def _score_dimensions(self, checks, impact, evals, traces):
        fb = checks.get("FALLBACK_DECLARED", {})
        ib = checks.get("IDENTITY_BOUNDARY", {})
        ab = checks.get("ACTION_BUDGET", {})
        bs = checks.get("BUDGET_SIMULATION", {})
        ic = checks.get("INPUT_CONTRACT", {})

        # Safety
        safety = 100
        if fb.get("status") == "FAIL":   safety -= 40
        elif fb.get("status") == "WARN": safety -= 15
        if ib.get("status") == "FAIL":   safety -= 30
        elif ib.get("status") == "WARN": safety -= 10
        if evals:
            s_total = sum(1 for r in evals.get("results", []) if r.get("category") == "safety")
            s_fail  = sum(1 for r in evals.get("results", [])
                          if r.get("category") == "safety" and not r.get("passed"))
            if s_total:
                safety = min(safety, int(100 * (1 - s_fail / s_total)))

        # Cost
        cost = 100
        if ab.get("status") == "FAIL":   cost -= 50
        elif ab.get("status") == "WARN": cost -= 20
        if bs.get("status") == "FAIL":   cost -= 30
        elif bs.get("status") == "WARN": cost -= 10
        if impact and impact.get("verdict") == "BLOCK":
            cost = min(cost, 40)

        # Access control
        acl = 100
        if ib.get("status") == "FAIL":   acl -= 50
        elif ib.get("status") == "WARN": acl -= 20
        if traces:
            n_unauth = len(traces.get("unauthorized_tool_calls", []))
            acl -= min(50, n_unauth * 20)

        # Fallback
        if   fb.get("status") == "FAIL": fback = 0
        elif fb.get("status") == "WARN": fback = 60
        else:                            fback = 100

        # Eval quality (unknown = 50)
        if evals and evals.get("total", 0) > 0:
            eq = int(100 * evals["passed"] / evals["total"])
        else:
            eq = 50

        # Observability
        obs = 50
        if ic.get("status") == "PASS":   obs = 80
        elif ic.get("status") == "FAIL": obs = 20
        if traces:
            obs = min(100, obs + 20)

        return {
            "safety":         {"score": max(0, safety),  "checks": ["FALLBACK_DECLARED", "IDENTITY_BOUNDARY"]},
            "cost":           {"score": max(0, cost),    "checks": ["ACTION_BUDGET", "BUDGET_SIMULATION"]},
            "access_control": {"score": max(0, acl),     "checks": ["IDENTITY_BOUNDARY"]},
            "fallback":       {"score": max(0, fback),   "checks": ["FALLBACK_DECLARED"]},
            "eval_quality":   {"score": eq,               "checks": []},
            "observability":  {"score": obs,              "checks": ["INPUT_CONTRACT"]},
        }

    def _find_critical_failures(self, checks, evals, traces) -> List[Dict]:
        failures = []
        for name in CRITICAL_CHECKS:
            if checks.get(name, {}).get("status") == "FAIL":
                failures.append({"source": "governance", "check": name,
                                  "reason": f"{name} check failed"})
        if evals:
            for r in evals.get("results", []):
                if r.get("severity") == "critical" and not r.get("passed"):
                    failures.append({"source": "eval", "check": r.get("name", "unknown"),
                                     "reason": r.get("failure_reason", "critical eval failed")})
        if traces:
            for tool in traces.get("unauthorized_tool_calls", []):
                failures.append({"source": "trace", "check": "unauthorized_tool_call",
                                  "reason": f"Unauthorized tool called: {tool}"})
        return failures

    def _confidence(self, checks, evals, traces) -> str:
        has_evals  = bool(evals and evals.get("total", 0) > 0)
        has_traces = bool(traces)
        has_checks = len(checks) >= 4
        if has_evals and has_checks and has_traces:
            return "high"
        if has_checks and (has_evals or has_traces):
            return "medium"
        return "low"

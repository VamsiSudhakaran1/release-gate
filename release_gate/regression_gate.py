"""
Regression Gate for release-gate.

Compares a baseline release report against a candidate to detect
regressions before deployment.

Usage:
    release-gate compare baseline.json candidate.json
"""

from __future__ import annotations
from typing import Dict, Any, List

REGRESSION_THRESHOLD = 10
CRITICAL_DIMS = {"safety", "fallback", "access_control"}


class RegressionGate:
    """Diff two readiness reports and decide PROMOTE / HOLD / BLOCK."""

    def compare(self, baseline: Dict[str, Any], candidate: Dict[str, Any]) -> Dict[str, Any]:
        b_score = baseline.get("readiness_score", 0)
        c_score = candidate.get("readiness_score", 0)
        delta   = c_score - b_score

        regressions, improvements = self._diff_dimensions(
            baseline.get("dimensions", {}),
            candidate.get("dimensions", {}),
        )

        b_crits = {f["check"] for f in baseline.get("critical_failures", [])}
        c_crits = {f["check"] for f in candidate.get("critical_failures", [])}
        new_crits = sorted(c_crits - b_crits)

        has_critical_regression = (
            any(r["severity"] == "critical" for r in regressions) or bool(new_crits)
        )

        if has_critical_regression:
            decision = "BLOCK"
            reason   = "Critical regression in safety or access control"
        elif candidate.get("decision") == "BLOCK":
            decision = "BLOCK"
            reason   = "Candidate release is independently blocked"
        elif delta < -REGRESSION_THRESHOLD:
            decision = "HOLD"
            reason   = f"Overall score dropped {abs(delta)} points — manual review required"
        elif candidate.get("decision") == "HOLD":
            decision = "HOLD"
            reason   = "Candidate release requires manual approval"
        else:
            decision = "PROMOTE"
            reason   = "No significant regressions detected"

        return {
            "decision":              decision,
            "reason":                reason,
            "regression":            len(regressions) > 0,
            "previous_score":        b_score,
            "current_score":         c_score,
            "score_delta":           delta,
            "regressions":           sorted(regressions, key=lambda r: r["severity"] == "critical", reverse=True),
            "improvements":          improvements,
            "new_critical_failures": new_crits,
            "baseline_decision":     baseline.get("decision", "UNKNOWN"),
            "candidate_decision":    candidate.get("decision", "UNKNOWN"),
        }

    def _diff_dimensions(self, baseline_dims, candidate_dims):
        regressions, improvements = [], []
        all_dims = set(list(baseline_dims) + list(candidate_dims))
        for dim in all_dims:
            b = baseline_dims.get(dim,  {}).get("score", 0)
            c = candidate_dims.get(dim, {}).get("score", 0)
            d = c - b
            if d < -REGRESSION_THRESHOLD:
                regressions.append({
                    "area":      dim,
                    "baseline":  b,
                    "candidate": c,
                    "delta":     d,
                    "severity":  "critical" if dim in CRITICAL_DIMS else "high",
                })
            elif d > REGRESSION_THRESHOLD:
                improvements.append({"area": dim, "baseline": b, "candidate": c, "delta": d})
        return regressions, improvements

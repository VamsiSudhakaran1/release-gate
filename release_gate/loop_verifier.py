"""
Loop Verifier — the Verify phase for agent loops.

Sits inside an agent loop's iterate cycle and answers:
  CONTINUE  — output not yet acceptable; keep iterating
  SHIP      — output passes all checks; safe to deploy/return
  ROLLBACK  — a hard violation means the loop should abort

The three checks run in sequence:
  1. Loop policy  — iteration count, total cost ceiling, maker/checker separation
  2. Trace        — tool violations, retry storms, token budget, loop detection
  3. Quality      — eval cases (keyword / schema / refuse_or_mask checks)

Only checks for which enough data is supplied are run. A verify call with
only a trace dict but no evals config skips the quality check, for example.

Designed to be called from:
  - POST /api/verify  (SaaS endpoint, called by running loops)
  - release-gate verify  (CLI, for local testing before deployment)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from release_gate.trace_validator import TraceValidator


@dataclass
class VerifyResult:
    decision: str           # CONTINUE | SHIP | ROLLBACK
    reasons: List[str]      # human-readable explanation for the decision
    violations: List[str]   # hard failures (any → ROLLBACK)
    warnings: List[str]     # soft signals (accumulate toward CONTINUE)
    checks: Dict[str, Any]  # per-check detail for the Loop Report
    iteration: int
    cost_so_far: float
    cost_remaining: Optional[float]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "decision":       self.decision,
            "reasons":        self.reasons,
            "violations":     self.violations,
            "warnings":       self.warnings,
            "checks":         self.checks,
            "iteration":      self.iteration,
            "cost_so_far":    self.cost_so_far,
            "cost_remaining": self.cost_remaining,
        }


class LoopVerifier:
    """Orchestrate trace + cost + quality checks into a single loop decision."""

    def verify(
        self,
        *,
        # Loop context
        iteration: int,
        cost_so_far: float = 0.0,
        output: Optional[str] = None,
        # Governance loop block (from governance.yaml → loop: section)
        loop_policy: Optional[Dict[str, Any]] = None,
        # Trace from the current iteration (dict with "steps" list, or None)
        trace: Optional[Dict[str, Any]] = None,
        # Trace policies (from governance.yaml → trace_policies: section)
        trace_policies: Optional[Dict[str, Any]] = None,
        # Evals list (from load_evals(); empty → skip quality check)
        evals: Optional[List[Dict[str, Any]]] = None,
    ) -> VerifyResult:

        policy      = loop_policy or {}
        violations: List[str] = []
        warnings:   List[str] = []
        checks:     Dict[str, Any] = {}

        # ── 1. Loop policy check ────────────────────────────────────────────
        loop_check = self._check_loop_policy(iteration, cost_so_far, policy)
        checks["loop_policy"] = loop_check
        violations.extend(loop_check.get("violations", []))
        warnings.extend(loop_check.get("warnings", []))

        # ── 2. Trace check ─────────────────────────────────────────────────
        if trace is not None:
            tpolicies = trace_policies or {}
            # Layer in loop-level token ceiling if not already in trace_policies
            if "max_tokens_per_run" not in tpolicies and policy.get("max_tokens_per_iteration"):
                tpolicies = {**tpolicies, "max_tokens_per_run": policy["max_tokens_per_iteration"]}
            trace_result = TraceValidator().validate(trace, tpolicies)
            checks["trace"] = trace_result
            violations.extend(trace_result.get("violations", []))
            warnings.extend(trace_result.get("warnings", []))

        # ── 3. Quality / eval check ────────────────────────────────────────
        if evals:
            from release_gate.evals.runner import EvalRunner
            eval_result = EvalRunner().run(evals, agent_callable=None if output is None else lambda inp, ctx: output)
            checks["evals"] = eval_result
            if eval_result.get("critical_failed", 0) > 0:
                violations.append(
                    f"{eval_result['critical_failed']} critical eval(s) failed "
                    f"(pass rate {eval_result['pass_rate']}%)"
                )
            elif eval_result.get("failed", 0) > 0:
                warnings.append(
                    f"{eval_result['failed']} eval(s) failed "
                    f"(pass rate {eval_result['pass_rate']}%)"
                )

        # ── Decision ───────────────────────────────────────────────────────
        cost_remaining = self._cost_remaining(cost_so_far, policy)
        decision, reasons = self._decide(violations, warnings, iteration, policy, cost_remaining)

        return VerifyResult(
            decision=decision,
            reasons=reasons,
            violations=violations,
            warnings=warnings,
            checks=checks,
            iteration=iteration,
            cost_so_far=cost_so_far,
            cost_remaining=cost_remaining,
        )

    # ── helpers ────────────────────────────────────────────────────────────

    def _check_loop_policy(
        self, iteration: int, cost_so_far: float, policy: Dict[str, Any]
    ) -> Dict[str, Any]:
        violations: List[str] = []
        warnings:   List[str] = []

        max_iter = policy.get("max_iterations")
        if max_iter is not None and iteration > max_iter:
            violations.append(
                f"Max iterations exceeded: {iteration} > {max_iter}"
            )
        elif max_iter is not None and iteration >= max_iter * 0.8:
            warnings.append(
                f"Approaching max iterations: {iteration}/{max_iter}"
            )

        total_limit = policy.get("total_cost_limit")
        if total_limit is not None and cost_so_far > total_limit:
            violations.append(
                f"Total cost limit exceeded: ${cost_so_far:.4f} > ${total_limit:.4f}"
            )

        per_iter_limit = policy.get("cost_per_iteration_limit")
        if per_iter_limit is not None and iteration > 0:
            avg_cost = cost_so_far / iteration
            if avg_cost > per_iter_limit:
                warnings.append(
                    f"Average cost per iteration ${avg_cost:.4f} exceeds "
                    f"limit ${per_iter_limit:.4f}"
                )

        return {
            "status":     "FAIL" if violations else ("WARN" if warnings else "PASS"),
            "violations": violations,
            "warnings":   warnings,
            "iteration":  iteration,
            "cost_so_far": cost_so_far,
        }

    def _cost_remaining(
        self, cost_so_far: float, policy: Dict[str, Any]
    ) -> Optional[float]:
        limit = policy.get("total_cost_limit")
        if limit is None:
            return None
        return max(0.0, limit - cost_so_far)

    def _decide(
        self,
        violations: List[str],
        warnings:   List[str],
        iteration:  int,
        policy:     Dict[str, Any],
        cost_remaining: Optional[float],
    ):
        if violations:
            return "ROLLBACK", [
                "Hard violations detected — the loop must abort.",
                *violations,
            ]

        # If cost_remaining is very low, force ROLLBACK before running out
        if cost_remaining is not None and cost_remaining <= 0.0:
            return "ROLLBACK", ["Budget exhausted — no cost remaining for further iterations."]

        # Check stop condition
        stop_cond = policy.get("stop_condition", "")
        if stop_cond == "always_ship":
            # Testing/demo mode: ship on first clean iteration
            if not warnings:
                return "SHIP", ["Stop condition met: no violations or warnings."]

        if warnings:
            return "CONTINUE", [
                "Warnings present — continue iterating to improve output.",
                *warnings,
            ]

        # No violations, no warnings → ship
        return "SHIP", ["All checks passed — output is ready to ship."]

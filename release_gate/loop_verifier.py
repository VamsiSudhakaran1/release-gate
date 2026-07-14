"""
Loop Verifier — the Verify phase for agent loops.

Sits inside an agent loop's iterate cycle and answers:
  CONTINUE  — output not yet acceptable; keep iterating
  SHIP      — output passes all configured checks; ready to return/ship
  ROLLBACK  — a hard violation means the loop should abort

The three checks run in sequence:
  1. Loop policy  — iteration count, total cost ceiling, maker/checker separation,
                    strict-mode completeness
  2. Trace        — tool violations, retry storms, token budget, loop detection
  3. Quality      — eval cases (keyword / schema / refuse_or_mask checks)

Two modes:
  permissive (default) — a clean iteration with no policy SHIPs. Developer-friendly.
  strict (loop.mode: strict) — a missing loop boundary is itself a violation:
                    max_iterations, total_cost_limit, max_tokens_per_iteration,
                    stop_condition and checker_model must all be declared.

Stop conditions (loop.stop_condition) can be a bare string or a typed dict:
  always_ship                         — SHIP on the first clean iteration
  {type: eval_pass_rate, min_pass_rate: 90}
  {type: required_keyword_present, keyword: "Approved"}
  {type: required_keyword_absent,  keyword: "TODO"}
  {type: human_approval_required}     — never auto-SHIP; always CONTINUE
  {type: artifact_exists, path: ...}  — SHIP only once the artifact is produced

Only checks for which enough data is supplied are run. A verify call with
only a trace dict but no evals config skips the quality check, for example.

Designed to be called from:
  - POST /api/verify  (SaaS endpoint, called by running loops)
  - release-gate verify  (CLI, for local testing before deployment)
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from release_gate.trace_validator import TraceValidator

# Fields a strict-mode loop policy must declare before any iteration can SHIP.
STRICT_REQUIRED_FIELDS = [
    "max_iterations",
    "total_cost_limit",
    "max_tokens_per_iteration",
    "stop_condition",
    "checker_model",
]


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
        decision, reasons = self._decide(
            violations, warnings, iteration, policy, cost_remaining, checks, output
        )

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

        strict = str(policy.get("mode", "")).strip().lower() == "strict"

        # ── strict-mode completeness ────────────────────────────────────────
        # In strict mode a missing loop boundary is itself a hard violation:
        # an unbounded loop with no declared ceiling must not be allowed to SHIP.
        if strict:
            for field_name in STRICT_REQUIRED_FIELDS:
                if policy.get(field_name) in (None, ""):
                    violations.append(
                        f"Strict mode requires loop.{field_name} to be declared."
                    )

        # ── maker / checker separation ──────────────────────────────────────
        # The checker must differ from the maker, or it is grading its own
        # homework (self-review bias). Identical models are always a violation;
        # an undeclared checker warns (permissive) or violates (strict).
        maker   = policy.get("maker_model")
        checker = policy.get("checker_model")
        if maker and checker and str(maker).strip() == str(checker).strip():
            violations.append(
                f"maker_model and checker_model are identical ('{maker}') — "
                f"the checker must differ from the maker to avoid self-review bias."
            )
        elif maker and not checker and not strict:
            warnings.append(
                "checker_model not declared — the maker is reviewing its own "
                "output. Declare a different checker_model."
            )

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
        checks:     Dict[str, Any],
        output:     Optional[str],
    ):
        if violations:
            return "ROLLBACK", [
                "Hard violations detected — the loop must abort.",
                *violations,
            ]

        # If cost_remaining is very low, force ROLLBACK before running out
        if cost_remaining is not None and cost_remaining <= 0.0:
            return "ROLLBACK", ["Budget exhausted — no cost remaining for further iterations."]

        # Evaluate the (possibly typed) stop condition. It can force a SHIP,
        # force a CONTINUE (e.g. human approval still pending), or defer (None).
        stop_decision, stop_reason = self._evaluate_stop_condition(
            policy.get("stop_condition"), checks, output, warnings
        )
        if stop_decision == "ship":
            return "SHIP", [stop_reason]
        if stop_decision == "continue":
            return "CONTINUE", [stop_reason, *warnings]

        if warnings:
            return "CONTINUE", [
                "Warnings present — continue iterating to improve output.",
                *warnings,
            ]

        # No violations, no warnings → ship
        return "SHIP", ["All checks passed — output is ready to ship."]

    def _evaluate_stop_condition(
        self,
        stop_cond: Any,
        checks:    Dict[str, Any],
        output:    Optional[str],
        warnings:  List[str],
    ):
        """Resolve a stop condition to ('ship'|'continue'|None, reason).

        Accepts a bare string (e.g. "always_ship", "human_approval_required")
        or a typed dict ({type: eval_pass_rate, min_pass_rate: 90}). Returns
        None to defer to the default clean→SHIP / warnings→CONTINUE behaviour.
        """
        if not stop_cond:
            return None, ""

        if isinstance(stop_cond, str):
            cond_type, params = stop_cond.strip(), {}
        elif isinstance(stop_cond, dict):
            cond_type = str(stop_cond.get("type", "")).strip()
            params = stop_cond
        else:
            return None, ""

        if cond_type == "always_ship":
            if not warnings:
                return "ship", "Stop condition met: always_ship and no warnings."
            return None, ""

        if cond_type == "human_approval_required":
            # Never auto-SHIP — a human must sign off out of band.
            return "continue", "Stop condition: human_approval_required — awaiting sign-off."

        if cond_type == "eval_pass_rate":
            min_rate = params.get("min_pass_rate", 100)
            eval_check = checks.get("evals") or {}
            rate = eval_check.get("pass_rate")
            if rate is None:
                return "continue", (
                    "Stop condition eval_pass_rate set but no evals ran — "
                    "cannot confirm quality."
                )
            if rate >= min_rate:
                return "ship", f"Stop condition met: eval pass rate {rate}% ≥ {min_rate}%."
            return "continue", f"Eval pass rate {rate}% below required {min_rate}% — keep iterating."

        if cond_type in ("required_keyword_present", "required_keyword_absent"):
            keyword = params.get("keyword", "")
            if not keyword:
                return None, ""
            text = output or ""
            present = keyword.lower() in text.lower()
            want_present = cond_type == "required_keyword_present"
            if present == want_present:
                return "ship", f"Stop condition met: keyword '{keyword}' {'present' if want_present else 'absent'}."
            return "continue", (
                f"Keyword '{keyword}' "
                f"{'not yet present' if want_present else 'still present'} — keep iterating."
            )

        if cond_type == "artifact_exists":
            path = params.get("path", "")
            if path and os.path.exists(path):
                return "ship", f"Stop condition met: artifact '{path}' exists."
            return "continue", f"Artifact '{path}' not produced yet — keep iterating."

        # Unknown stop condition type → defer to default behaviour.
        return None, ""

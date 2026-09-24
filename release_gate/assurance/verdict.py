"""What a verdict means on this case, checked rather than asserted.

`Decision` carries the universal definitions (§11). This module carries what
they come to on one decided case: whether a HOLD said what would resolve it,
whether a BLOCK rests on something that cannot be waived, and — for PROMOTE —
the four readings that are the reason this system exists.

**The four refusals are properties, not prose.** `authorises_execution`,
`establishes_truth`, `establishes_safety` and `human_approval_exists` all return
`False` unconditionally, for every verdict including PROMOTE. A paragraph saying
so can be skipped by the code that matters; a property can be asserted on, and
anything relying on the opposite fails loudly.

**A HOLD that names nothing is a shrug.** "More evidence is required" without
saying which is the answer this engine was built to stop giving, so
`resolution_is_actionable` is a real reading of the required-evidence set rather
than an assumption that one exists. A HOLD without one is reported, not excused.

**BLOCK claims non-overridability, so it is asked.** The definition says a BLOCK
is a *non-overridable* violation or an invalidation of the candidate. Whether
every reason behind a given BLOCK actually meets that is a question the
methodology can answer — `can_override` and `non_overridable_conditions` are
already there — and this module asks it. Where a BLOCK rests on something the
methodology would permit waiving, `overridable_reasons` names it rather than
letting the verdict imply more than it has.

That reporting deliberately does not change the verdict. Turning such a BLOCK
into a HOLD would alter decisions across every existing case, and this module's
job is to say what a verdict means, not to re-decide it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from release_gate.assurance.case import Decision

__all__ = [
    "VERDICT_SCHEMA_VERSION",
    "VerdictError",
    "VerdictStatement",
    "explain_verdict",
]

VERDICT_SCHEMA_VERSION = 1


class VerdictError(ValueError):
    """A verdict was read in a way that would overstate what it establishes."""


@dataclass(frozen=True)
class VerdictStatement:
    """One verdict, its definition, and what it came to on this case."""

    decision: Decision
    fired_rules: Tuple[str, ...] = ()
    reasons: Tuple[str, ...] = ()
    #: Named requirements whose arrival would resolve a HOLD. Empty on a HOLD is
    #: a finding about the case, not a property of holds.
    required_evidence: Tuple[Mapping[str, Any], ...] = ()
    #: Reasons behind a BLOCK that the active methodology would permit waiving.
    overridable_reasons: Tuple[str, ...] = ()
    #: Reasons the methodology names as never waivable.
    non_overridable_reasons: Tuple[str, ...] = ()
    methodology_ref: Optional[str] = None
    schema_version: int = VERDICT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "decision", Decision(self.decision))
        for name in ("fired_rules", "reasons", "overridable_reasons",
                     "non_overridable_reasons"):
            object.__setattr__(self, name, tuple(getattr(self, name)))
        object.__setattr__(self, "required_evidence",
                           tuple(dict(r) for r in self.required_evidence))
        if not self.fired_rules:
            raise VerdictError(
                "a verdict statement must name the rules behind it; an "
                "unattributed PROMOTE, HOLD or BLOCK is the opaque judgement this "
                "engine refuses to make")

    # ── the four refusals, for every verdict including PROMOTE ─────────────

    @property
    def authorises_execution(self) -> bool:
        """Unconditionally False. PROMOTE reaches an authorization boundary; it
        is not the crossing."""
        return False

    @property
    def establishes_truth(self) -> bool:
        """Unconditionally False. Evidence sufficiency is not correctness."""
        return False

    @property
    def establishes_safety(self) -> bool:
        """Unconditionally False. Safety is a domain judgement on stated
        consequence, and this engine states rather than judges it."""
        return False

    @property
    def human_approval_exists(self) -> bool:
        """Unconditionally False. A recommendation is not a signature, and no
        verdict has ever been one."""
        return False

    # ── what it came to here ───────────────────────────────────────────────

    @property
    def definition(self) -> str:
        return self.decision.definition

    @property
    def does_not_mean(self) -> Tuple[str, ...]:
        return self.decision.does_not_mean

    @property
    def exit_code(self) -> int:
        return self.decision.exit_code

    @property
    def resolution_is_actionable(self) -> bool:
        """Whether a HOLD said what would resolve it.

        False for a HOLD carrying nothing — which is the shrug — and False for
        the other two verdicts, where the question does not arise: a PROMOTE has
        nothing to resolve and a BLOCK is not resolved by supplying more.
        """
        return self.decision is Decision.HOLD and bool(self.required_evidence)

    @property
    def is_a_shrug(self) -> bool:
        """A HOLD that named nothing. Reported, never excused."""
        return self.decision is Decision.HOLD and not self.required_evidence

    @property
    def block_is_fully_non_overridable(self) -> bool:
        """Whether every reason behind a BLOCK is one nothing may waive.

        `False` for a BLOCK resting on anything the methodology would permit
        waiving, and `False` for the other two verdicts, where the question does
        not arise. Not a defect on its own — a structural invalidation is a BLOCK
        under the second clause of the definition whatever the methodology says
        about waivers — but it is the difference between "nobody may proceed" and
        "somebody with the right role may", and a reader should not have to guess
        which one they have.
        """
        return self.decision is Decision.BLOCK and not self.overridable_reasons

    def note(self) -> str:
        lines = [f"{self.decision.value}: {self.definition}"]
        if self.does_not_mean:
            lines.append(f"{self.decision.value} does not mean:")
            lines += [f"  · {item}" for item in self.does_not_mean]
        if self.decision is Decision.HOLD:
            if self.required_evidence:
                lines.append(
                    f"{len(self.required_evidence)} named requirement(s) would "
                    "resolve this.")
            else:
                lines.append(
                    "Nothing is named as the thing that would resolve this. "
                    '"More evidence is required" without saying which is the '
                    "answer this engine exists to stop giving.")
        if self.decision is Decision.BLOCK:
            if self.overridable_reasons:
                lines.append(
                    f"{len(self.overridable_reasons)} of the reasons behind this "
                    "BLOCK are ones the methodology would permit waiving: "
                    + ", ".join(self.overridable_reasons[:4]))
            else:
                lines.append(
                    "Every reason behind this BLOCK is one the active methodology "
                    "does not permit waiving.")
        return "\n".join(lines)

    @property
    def record_type(self) -> str:
        return "verdict_statement"

    @property
    def record_id(self) -> str:
        return f"verdict:{self.decision.value}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_type": self.record_type, "record_id": self.record_id,
            "decision": self.decision.value, "definition": self.definition,
            "does_not_mean": list(self.does_not_mean),
            "exit_code": self.exit_code,
            "fired_rules": list(self.fired_rules), "reasons": list(self.reasons),
            "methodology": self.methodology_ref,
            "required_evidence": [dict(r) for r in self.required_evidence],
            "resolution_is_actionable": self.resolution_is_actionable,
            "is_a_shrug": self.is_a_shrug,
            "overridable_reasons": list(self.overridable_reasons),
            "non_overridable_reasons": list(self.non_overridable_reasons),
            "block_is_fully_non_overridable": self.block_is_fully_non_overridable,
            # Stated in the record, for every verdict. A consumer reading this
            # payload should find the refusals rather than have to know them.
            "authorises_execution": False, "establishes_truth": False,
            "establishes_safety": False, "human_approval_exists": False,
            "note": self.note(), "schema_version": self.schema_version,
        }


def explain_verdict(outcome: Any, *, methodology: Any = None) -> VerdictStatement:
    """What this outcome's verdict means, read from the outcome.

    `methodology` is optional: without one, overridability is left empty rather
    than assumed, because "no methodology said this was waivable" and "nobody
    asked" are different facts and only the first is about the case.
    """
    case = getattr(outcome, "case", outcome)
    verdict = getattr(case, "verdict", None)
    if verdict is None:
        raise VerdictError(
            "this case carries no verdict; there is nothing yet to explain, and a "
            "statement invented for one would be a decision nobody made")

    required = getattr(outcome, "required_evidence", None)
    requirements: Tuple[Mapping[str, Any], ...] = ()
    if required is not None:
        protocol = required.protocol()
        requirements = tuple(protocol.get("required_evidence") or ())

    if methodology is not None and not hasattr(methodology, "can_override"):
        # `case.methodology` is a MethodologyRef — an identity, not the document.
        # It is the obvious thing to reach for and it cannot answer this, so say
        # which one is wanted rather than failing on an attribute lookup.
        raise VerdictError(
            f"{type(methodology).__name__} cannot answer whether a requirement "
            "may be overridden; pass the AssuranceMethodology itself, resolved "
            "from the case's MethodologyRef, or pass none and leave "
            "overridability unasked")

    overridable: list = []
    non_overridable: list = []
    if methodology is not None and verdict.decision is Decision.BLOCK:
        for rule_id in verdict.fired_rules:
            decision = methodology.can_override(rule_id)
            # `can_override` already reads silence as no, which is the
            # conservative direction: a rule nobody wrote a waiver for stands.
            (overridable if decision.permitted else non_overridable).append(rule_id)

    return VerdictStatement(
        decision=verdict.decision,
        fired_rules=tuple(verdict.fired_rules),
        reasons=tuple(verdict.reasons),
        required_evidence=requirements,
        overridable_reasons=tuple(overridable),
        non_overridable_reasons=tuple(non_overridable),
        methodology_ref=(methodology.ref_string if methodology is not None
                         else getattr(getattr(case, "methodology", None), "ref", None)))

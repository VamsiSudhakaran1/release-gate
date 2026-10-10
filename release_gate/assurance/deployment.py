"""The deploy-time check: is what runs what was admitted?

An admission is about one exact candidate state (`candidate.py`): the commit,
the image, the model, the prompt, the tool manifest — whatever components the
candidate stated. Between `assure` and the deploy, any of them can move: an
image rebuilt under the same tag, a model alias that now resolves to another
model, a prompt edited after review. An admission nobody checks at deploy time
admits whatever is deployed under its name — the time-of-check / time-of-use
gap, and the reason an admission names a state hash at all.

`check_deployment` reads an Admission Report (`admission_report.py`) and a
statement of what is deployed, in the shape `assure --candidate` takes, and
compares them component by component with `candidate.values_equal`:

    MATCH          every admitted component is stated by the deployment and is
                   equal, and nothing the admission did not cover is deployed
    MISMATCH       a component differs: what runs is not what was admitted
    UNVERIFIABLE   the deployment does not state an admitted component, or
                   deploys a revision the admission never covered, or the
                   admission names no candidate state: it cannot be shown to be
                   what was admitted, and unknown is not a match
    NOT_ADMITTED   the admission was not a PROMOTE, its signature does not
                   verify, or its state hash does not match its own components
                   (the report was edited)

Exit codes follow every other gate: 0 MATCH · 1 MISMATCH · 10 UNVERIFIABLE.
NOT_ADMITTED exits as the admission's own decision would (10 for HOLD, 1 for
BLOCK or a report that was tampered with).

**An identity component is not a revision.** A deployment that names its
environment when the admission did not is noted, not held: a repository or an
environment says which subject this is, and the admission's revision
components are what say which state of it was admitted (`ComponentClass`).

**The admission is a document.** Anyone can edit a JSON file to say PROMOTE.
The report's state hash is recomputed from its components, so an edited
component is caught; an edited decision is caught only by a signature. With
`require_signed` (the CLI sets it when `--trusted-keys` is given), the report
must be signed by a key the organisation trusts for `release-gate/admission`;
the signature is checked at the host boundary (`crypto/envelope.py`) and
handed here as a verdict, as it is for evidence (`signed.py`).

Pure: no clock, no I/O. The same two documents and the same verdict give the
same check, byte for byte.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Tuple

from release_gate.assurance.attestation import SignatureState
from release_gate.assurance.candidate import (
    CandidateError,
    CandidateSource,
    CandidateState,
    ComponentClass,
    ComponentComparison,
    ComponentOutcome,
    component_class,
    values_equal,
)

__all__ = [
    "ADMISSION_PRODUCER",
    "DEPLOYMENT_CHECK_SCHEMA_VERSION",
    "DeploymentCheck",
    "DeploymentCheckError",
    "DeploymentOutcome",
    "check_deployment",
    "render_deployment_check",
]

DEPLOYMENT_CHECK_SCHEMA_VERSION = 1

#: The producer an admission report speaks as. A trust store names it to say
#: which key may sign admissions, exactly as it names an eval harness.
ADMISSION_PRODUCER = "release-gate/admission"


class DeploymentCheckError(ValueError):
    """A document that is not what the check reads."""


class DeploymentOutcome(str, Enum):
    MATCH = "MATCH"
    MISMATCH = "MISMATCH"
    UNVERIFIABLE = "UNVERIFIABLE"
    NOT_ADMITTED = "NOT_ADMITTED"


_EXIT = {DeploymentOutcome.MATCH: 0, DeploymentOutcome.MISMATCH: 1,
         DeploymentOutcome.UNVERIFIABLE: 10}


@dataclass(frozen=True)
class DeploymentCheck:
    """What one deployment was compared with, and what the comparison found."""

    outcome: DeploymentOutcome
    exit_code: int
    decision: str
    admitted_state_hash: str
    deployed_state_hash: str
    comparisons: Tuple[ComponentComparison, ...] = ()
    reasons: Tuple[str, ...] = ()
    notes: Tuple[str, ...] = ()
    case_id: str = ""
    admission_signature: Optional[Mapping[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "deployment_check",
                "schema_version": DEPLOYMENT_CHECK_SCHEMA_VERSION,
                "outcome": self.outcome.value, "exit_code": self.exit_code,
                "admission": {"decision": self.decision, "case_id": self.case_id,
                              "state_hash": self.admitted_state_hash},
                "deployed_state_hash": self.deployed_state_hash,
                "comparisons": [
                    {"component": c.component, "outcome": c.outcome.value,
                     "admitted": c.candidate_value, "deployed": c.record_value}
                    for c in self.comparisons],
                "reasons": list(self.reasons), "notes": list(self.notes),
                "admission_signature": (dict(self.admission_signature)
                                        if self.admission_signature is not None else None)}


def _admitted(admission: Mapping[str, Any]) -> Tuple[str, Mapping[str, Any], str]:
    from release_gate.assurance.admission_report import ADMISSION_REPORT_SCHEMA_VERSION
    if not isinstance(admission, Mapping) or admission.get("record_type") != "admission_report":
        raise DeploymentCheckError(
            "the admission is not an Admission Report (`assure --admission-out`)")
    version = admission.get("schema_version")
    if not isinstance(version, int) or isinstance(version, bool) \
            or version > ADMISSION_REPORT_SCHEMA_VERSION:
        raise DeploymentCheckError(
            f"admission report schema {version!r} is not one this reader understands "
            f"(up to {ADMISSION_REPORT_SCHEMA_VERSION}); upgrade rather than read it "
            "loosely")
    candidate = admission.get("candidate")
    if not isinstance(candidate, Mapping) or not isinstance(
            candidate.get("components", {}), Mapping):
        raise DeploymentCheckError("the admission report carries no candidate block")
    return (str(admission.get("decision") or ""), candidate.get("components") or {},
            str(candidate.get("state_hash") or ""))


def _signature_finding(verdict: Any, require_signed: bool, was_signed: bool = False
                       ) -> Tuple[Optional[DeploymentOutcome], Optional[str], List[str]]:
    """What the admission's signature does to the check: an outcome that ends it, or none."""
    notes: List[str] = []
    if verdict is not None and verdict.state is SignatureState.INVALID:
        return (DeploymentOutcome.NOT_ADMITTED,
                f"the admission report's signature does not verify ({verdict.detail}); "
                "what it says was admitted is not read", notes)
    if verdict is not None and verdict.state is SignatureState.VALID:
        if verdict.speaks_for(ADMISSION_PRODUCER):
            notes.append(f"the admission report is signed by key {verdict.key_id!r}, "
                         f"trusted for admissions by {verdict.decided_by}")
            return None, None, notes
        message = (f"key {verdict.key_id!r} signed the admission report, but it is not "
                   f"trusted to speak for {ADMISSION_PRODUCER} (it is trusted for "
                   f"{', '.join(verdict.producers)})")
    elif verdict is not None:
        message = f"no trusted key signed the admission report ({verdict.detail})"
    elif was_signed:
        message = ("the admission report is signed, but no trust store was given to "
                   "verify it")
    else:
        message = "the admission report is not signed"
    if require_signed:
        return (DeploymentOutcome.UNVERIFIABLE,
                message + "; with a trust store named, an admission is read only when "
                "a key trusted for admissions signed it", notes)
    notes.append(message + "; its decision is the document's word")
    return None, None, notes


def check_deployment(admission: Mapping[str, Any], deployed: Mapping[str, Any], *,
                     admission_signature: Optional[Any] = None,
                     require_signed: bool = False,
                     admission_was_signed: bool = False,
                     deployed_by: str = "") -> DeploymentCheck:
    """Compare a deployment with the state an Admission Report admitted."""
    decision, admitted_components, stated_hash = _admitted(admission)
    try:
        running = CandidateState.from_dict(deployed, source=CandidateSource.DECLARED_BY_CALLER,
                                           declared_by=deployed_by)
    except CandidateError as exc:
        raise DeploymentCheckError(f"the deployment is not a candidate state: {exc}") from exc
    deployed_hash = running.digest()
    case_id = str(admission.get("case_id") or "")
    signature = (admission_signature.to_dict() if admission_signature is not None
                 else None)

    def ended(outcome: DeploymentOutcome, reason: str, *, code: Optional[int] = None,
              comparisons: Tuple[ComponentComparison, ...] = (),
              notes: Tuple[str, ...] = ()) -> DeploymentCheck:
        return DeploymentCheck(
            outcome=outcome, exit_code=_EXIT.get(outcome, 1) if code is None else code,
            decision=decision, admitted_state_hash=stated_hash,
            deployed_state_hash=deployed_hash, comparisons=comparisons,
            reasons=(reason,), notes=notes, case_id=case_id,
            admission_signature=signature)

    stop, reason, notes = _signature_finding(admission_signature, require_signed,
                                             admission_was_signed)
    if stop is not None:
        return ended(stop, reason, code=1 if stop is DeploymentOutcome.NOT_ADMITTED else None,
                     notes=tuple(notes))
    if decision != "PROMOTE":
        return ended(DeploymentOutcome.NOT_ADMITTED,
                     f"the admission decided {decision or 'nothing'}, not PROMOTE: it "
                     "admitted no state, so no deployment of it is admitted",
                     code=1 if decision == "BLOCK" else 10, notes=tuple(notes))
    if not admitted_components:
        return ended(DeploymentOutcome.UNVERIFIABLE,
                     "the admission names no candidate state — its state hash is the "
                     "case digest, which binds the evidence held and not a release — so "
                     "no deployment can be compared with it; state one with `assure "
                     "--candidate`", notes=tuple(notes))
    try:
        admitted = CandidateState(components=admitted_components)
    except CandidateError as exc:
        return ended(DeploymentOutcome.NOT_ADMITTED,
                     f"the admission report's components are not a candidate state: {exc}",
                     code=1, notes=tuple(notes))
    if admitted.digest() != stated_hash:
        return ended(DeploymentOutcome.NOT_ADMITTED,
                     f"the admission report's state hash ({stated_hash or 'none'}) does "
                     f"not match its own components ({admitted.digest()}): the report "
                     "was edited after it was written, and what it admitted cannot be "
                     "read from it", code=1, notes=tuple(notes))

    comparisons: List[ComponentComparison] = []
    # Kept apart so the report leads with what a reader acts on: a mismatch,
    # then what the deployment did not say, then what it runs that nobody admitted.
    differs: List[str] = []
    unstated: List[str] = []
    uncovered: List[str] = []
    for key, value in admitted.components.items():
        held = running.components.get(key)
        if held is None:
            comparisons.append(ComponentComparison(key, ComponentOutcome.NOT_BOUND,
                                                   record_value=None, candidate_value=value))
            unstated.append(f"the deployment does not state {key}; the admission covered "
                            f"{value}, and what runs cannot be shown to be it")
        elif values_equal(key, held, value):
            comparisons.append(ComponentComparison(key, ComponentOutcome.MATCH,
                                                   record_value=held, candidate_value=value))
        else:
            comparisons.append(ComponentComparison(key, ComponentOutcome.MISMATCH,
                                                   record_value=held, candidate_value=value))
            differs.append(f"{key} is {held} in the deployment and {value} in the "
                           "admitted state")
    for key, value in running.components.items():
        if key in admitted.components:
            continue
        comparisons.append(ComponentComparison(key, ComponentOutcome.NOT_IN_CANDIDATE,
                                               record_value=value, candidate_value=None))
        if component_class(key) is ComponentClass.IDENTITY:
            notes.append(f"the deployment names {key} {value}, which the admission did "
                         "not state; an identity, not a revision, so it is noted")
        else:
            uncovered.append(f"the deployment runs {key} {value}, which the admission "
                             "did not cover: nothing admitted says which one was meant")

    if differs:
        outcome = DeploymentOutcome.MISMATCH
    elif unstated or uncovered:
        outcome = DeploymentOutcome.UNVERIFIABLE
    else:
        outcome = DeploymentOutcome.MATCH
    reasons = differs + unstated + uncovered or [
        f"every admitted component is deployed as admitted "
        f"({', '.join(admitted.components)})"]
    return DeploymentCheck(
        outcome=outcome, exit_code=_EXIT[outcome], decision=decision,
        admitted_state_hash=stated_hash, deployed_state_hash=deployed_hash,
        comparisons=tuple(comparisons), reasons=tuple(reasons), notes=tuple(notes),
        case_id=case_id, admission_signature=signature)


def render_deployment_check(check: DeploymentCheck) -> str:
    lines = [f"  Deployment   {check.outcome.value}  (exit {check.exit_code})",
             f"  Admitted     {check.decision or '—'}  state {check.admitted_state_hash or '—'}",
             f"  Deployed     state {check.deployed_state_hash}"]
    if check.comparisons:
        lines.append("")
        width = max(len(c.component) for c in check.comparisons)
        for c in check.comparisons:
            lines.append(f"    {c.component:<{width}}  {c.outcome.value:<16}  "
                         f"admitted {c.candidate_value or '—'} · deployed "
                         f"{c.record_value or '—'}")
    lines.append("")
    lines.extend(f"  • {reason}" for reason in check.reasons)
    lines.extend(f"  note: {note}" for note in check.notes)
    return "\n".join(lines)

"""Hold an agent to what was admitted: at start, when its state moves, and on every call.

An admission (`assure --admission-out`, signed with `release-gate sign`) names
one exact state. `RuntimeGate` is how a runtime — an agent harness, a tool
gateway, an MCP client — puts that admission on its own path:

    from release_gate.runtime import RuntimeGate, observe

    state = observe(model=MODEL, prompt=system_prompt, tools=tools,
                    governance_policy=policy, commit=GIT_SHA)
    gate = RuntimeGate.open("admission.signed.json", observed=state,
                            trusted_keys="trusted-keys.json",
                            log_path="decisions.json", halt_file="/run/agent/HALT")

    decision = gate.authorize(name, arguments, definition=tool_definition)
    if not decision.allowed: ...          # DENY, or NEEDS_APPROVAL: ask a person
    gate.check_model(response.model)      # the model the provider says it served
    gate.recheck(observe(...))            # on a config reload or tools/list_changed
    gate.halt(by="oncall@acme.example")   # or create the halt file

**Fail closed.** `open` raises `NotAdmitted` unless a PROMOTE, signed by a key
the trust store trusts for `release-gate/admission`, admits exactly the observed
state (`deploy-check`'s comparison, run on what the runtime computed rather than
on what a deployer stated). Without a trust store it refuses unless
`allow_unsigned=True` is passed, and then it says the decision is the document's
word. A `recheck` that no longer matches, or a model the provider reports that
is not the admitted one, closes the gate: every later call is DENY.

**Every decision is recorded**, as a release-gate native trace: allowed calls as
`tool_call` and `llm_call` steps, refusals as `guard_denied`, calls waiting for
a person as `guard_held`, and the admission, re-checks and halts as their own
steps. `verify --trace` and `assure` read it like any trace, so a production run
is evidence for the next admission. Arguments are digested, not written,
unless `log_arguments=True`.

**What it is not.** It decides; the runtime enforces. A harness that calls a
tool without asking is not stopped by this, so it belongs where every call
already passes — the tool dispatcher or a gateway in front of the tools. And
`approved_by` is the runtime's word for who approved: it is recorded, not
authenticated.
"""

from __future__ import annotations

import json
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Union

from release_gate.assurance.candidate import CandidateError, canonical_value
from release_gate.assurance.canonical import digest_bytes, digest_object
from release_gate.assurance.deployment import (
    DeploymentCheck,
    DeploymentCheckError,
    DeploymentOutcome,
    check_deployment,
)
from release_gate.assurance.runtime_gate import (
    OBSERVED_BY,
    CallDecision,
    GateDecision,
    ObservedState,
    decide_model,
    decide_tool_call,
    observe,
)
from release_gate.assurance.signed import (
    SignedEnvelopeError,
    inner_document,
    is_signed_envelope,
)

__all__ = ["CallDecision", "GateDecision", "NotAdmitted", "RuntimeGate", "observe"]

#: The producer a decision log speaks as.
RUNTIME_PRODUCER = "release-gate/runtime"


class NotAdmitted(RuntimeError):
    """The runtime is not in a state a signed PROMOTE admitted."""

    def __init__(self, message: str, check: Optional[DeploymentCheck] = None) -> None:
        super().__init__(message)
        self.check = check


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _load(source: Union[str, Path, Mapping[str, Any]]) -> Mapping[str, Any]:
    if isinstance(source, Mapping):
        return source
    try:
        data = json.loads(Path(source).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise NotAdmitted(f"{source}: the admission cannot be read: {exc}") from exc
    if not isinstance(data, Mapping):
        raise NotAdmitted(f"{source}: the admission is not a JSON object")
    return data


def _trust_store(trusted_keys: Any) -> Any:
    if trusted_keys is None:
        return None
    from release_gate.crypto.envelope import TrustedKeys, TrustedKeysError, load_trusted_keys
    if isinstance(trusted_keys, TrustedKeys):
        return trusted_keys
    try:
        return load_trusted_keys(trusted_keys)
    except TrustedKeysError as exc:
        raise NotAdmitted(f"the trust store cannot be used: {exc}") from exc


def _refusal(check: DeploymentCheck) -> str:
    return f"not admitted ({check.outcome.value}): " + "; ".join(check.reasons)


class RuntimeGate:
    """One run held to one admission. Open it with `RuntimeGate.open`."""

    def __init__(self, *, admission: Mapping[str, Any], verdict: Any, signed: bool,
                 require_signed: bool, observed: ObservedState, check: DeploymentCheck,
                 log_path: Optional[Path], halt_file: Optional[Path], run_id: str,
                 log_arguments: bool) -> None:
        self._admission = admission
        self._verdict = verdict
        self._signed = signed
        self._require_signed = require_signed
        self._observed = observed
        self.check = check
        self._log_path = log_path
        self._halt_file = halt_file
        self.run_id = run_id
        self._log_arguments = log_arguments
        self._steps: List[Dict[str, Any]] = []
        self._calls_allowed = 0
        self._closed = ""
        self._halted = ""
        self._lock = threading.Lock()
        components = (admission.get("candidate") or {}).get("components") or {}
        model = components.get("model") if isinstance(components, Mapping) else None
        try:
            self._admitted_model = (canonical_value("model", model)
                                    if model is not None else None)
        except CandidateError:
            self._admitted_model = None

    # ── opening ─────────────────────────────────────────────────────────────

    @classmethod
    def open(cls, admission: Union[str, Path, Mapping[str, Any]], *,
             observed: ObservedState, trusted_keys: Any = None,
             allow_unsigned: bool = False,
             log_path: Union[str, Path, None] = None,
             halt_file: Union[str, Path, None] = None,
             run_id: Optional[str] = None, log_arguments: bool = False) -> "RuntimeGate":
        """Open the gate, or raise `NotAdmitted`. Nothing is allowed until this returns."""
        if not isinstance(observed, ObservedState):
            raise NotAdmitted("observed is the runtime's own state (`observe(...)`), "
                              "not a stated one")
        mismatched = observed.inconsistencies()
        if mismatched:
            raise NotAdmitted("the observed state does not describe what it holds: "
                              + "; ".join(mismatched))
        store = _trust_store(trusted_keys)
        if store is None and not allow_unsigned:
            raise NotAdmitted(
                "no trust store was named, so no signature can be checked and an edited "
                "admission would read as admitted; pass trusted_keys, or "
                "allow_unsigned=True to read the admission's decision as the document's "
                "word")
        document = _load(admission)
        signed = is_signed_envelope(document)
        verdict = None
        if signed:
            if store is not None:
                from release_gate.crypto.envelope import verify_envelope
                verdict = verify_envelope(document, store)
            try:
                document, _kind = inner_document(document)
            except SignedEnvelopeError as exc:
                raise NotAdmitted(f"the signed admission cannot be opened: {exc}") from exc
        try:
            check = check_deployment(document, observed.to_dict(),
                                     admission_signature=verdict,
                                     require_signed=store is not None,
                                     admission_was_signed=signed, deployed_by=OBSERVED_BY)
        except DeploymentCheckError as exc:
            raise NotAdmitted(f"the admission cannot be read: {exc}") from exc
        gate = cls(admission=document, verdict=verdict, signed=signed,
                   require_signed=store is not None, observed=observed, check=check,
                   log_path=Path(log_path) if log_path is not None else None,
                   halt_file=Path(halt_file) if halt_file is not None else None,
                   run_id=run_id or f"run-{uuid.uuid4().hex[:16]}",
                   log_arguments=log_arguments)
        with gate._lock:
            gate._record({"type": "admission", "outcome": check.outcome.value,
                          "observed_state_hash": check.deployed_state_hash,
                          "reasons": list(check.reasons), "notes": list(check.notes)})
            if check.outcome is not DeploymentOutcome.MATCH:
                gate._closed = f"closed: {_refusal(check)}"
            gate._flush()
        if gate._closed:
            raise NotAdmitted(_refusal(check), check)
        return gate

    # ── deciding ────────────────────────────────────────────────────────────

    def _stopped(self) -> str:
        """Why nothing may be allowed now, or an empty string. Called under the lock."""
        if self._closed:
            return self._closed
        if self._halted:
            return self._halted
        if self._halt_file is not None and self._halt_file.exists():
            try:
                said = self._halt_file.read_text(encoding="utf-8").strip().splitlines()
            except OSError:
                said = []
            self._halted = (f"halted: the halt file {self._halt_file} exists"
                            + (f" ({said[0][:200]})" if said else ""))
            self._record({"type": "halt", "by": f"halt file {self._halt_file}",
                          "reason": said[0][:200] if said else ""})
        return self._halted

    def authorize(self, tool: str, arguments: Optional[Mapping[str, Any]] = None, *,
                  definition: Optional[Mapping[str, Any]] = None,
                  approved_by: Optional[str] = None) -> CallDecision:
        """Decide one tool call. Never raises: a refusal is a decision, not an error."""
        with self._lock:
            decision = decide_tool_call(
                tool=tool, manifest=self._observed.tools, policy=self._observed.policy,
                definition=definition, approved_by=approved_by or "",
                calls_allowed=self._calls_allowed, stopped=self._stopped())
            if decision.allowed:
                self._calls_allowed += 1
            step: Dict[str, Any] = {
                "type": {GateDecision.ALLOW: "tool_call", GateDecision.DENY: "guard_denied",
                         GateDecision.NEEDS_APPROVAL: "guard_held"}[decision.decision],
                "tool": decision.subject, "guard": decision.to_dict()}
            if arguments is not None:
                if self._log_arguments:
                    # A copy as decided: the caller's later edits are not the record.
                    step["args"] = json.loads(json.dumps(dict(arguments), default=str))
                try:
                    step["args_digest"] = digest_object(dict(arguments))
                except (TypeError, ValueError):
                    step["args_digest"] = digest_bytes(repr(arguments).encode("utf-8"))
            self._record(step)
            self._flush()
            return decision

    def check_model(self, reported: Any) -> CallDecision:
        """Decide whether a response came from the admitted model. A drift closes the gate."""
        with self._lock:
            decision = decide_model(reported=reported, admitted=self._admitted_model,
                                    stopped=self._stopped())
            if decision.allowed:
                self._record({"type": "llm_call", "model": decision.subject,
                              "guard": decision.to_dict()})
            else:
                self._record({"type": "guard_denied", "model": decision.subject,
                              "guard": decision.to_dict()})
                if not self._closed and not self._halted:
                    self._closed = f"closed: {decision.reason}"
            self._flush()
            return decision

    def recheck(self, observed: ObservedState) -> DeploymentCheck:
        """Compare the runtime's state again; a mismatch closes the gate and raises."""
        mismatched = observed.inconsistencies()
        if mismatched:
            with self._lock:
                if not self._closed:
                    self._closed = ("closed: the observed state does not describe what it "
                                    "holds")
                self._record({"type": "recheck", "outcome": "REFUSED",
                              "reasons": list(mismatched)})
                self._flush()
            raise NotAdmitted("the observed state does not describe what it holds: "
                              + "; ".join(mismatched))
        with self._lock:
            check = check_deployment(self._admission, observed.to_dict(),
                                     admission_signature=self._verdict,
                                     require_signed=self._require_signed,
                                     admission_was_signed=self._signed,
                                     deployed_by=OBSERVED_BY)
            self._record({"type": "recheck", "outcome": check.outcome.value,
                          "observed_state_hash": check.deployed_state_hash,
                          "reasons": list(check.reasons)})
            if check.outcome is DeploymentOutcome.MATCH:
                self._observed = observed
            elif not self._closed:
                self._closed = f"closed: {_refusal(check)}"
            self._flush()
        if check.outcome is not DeploymentOutcome.MATCH:
            raise NotAdmitted(_refusal(check), check)
        return check

    def halt(self, *, by: str, reason: str = "") -> None:
        """Stop the run: every decision after this is DENY."""
        who = str(by or "").strip() or "an unnamed caller"
        with self._lock:
            if not self._halted:
                self._halted = f"halted by {who} at {_now()}" + (f": {reason}" if reason else "")
            self._record({"type": "halt", "by": who, "reason": reason})
            self._flush()

    @property
    def halted(self) -> bool:
        with self._lock:
            return bool(self._stopped()) and not self._closed

    @property
    def closed(self) -> bool:
        return bool(self._closed)

    # ── the record ──────────────────────────────────────────────────────────

    def _record(self, step: Dict[str, Any]) -> None:
        self._steps.append({**step, "at": _now()})

    def trace(self) -> Dict[str, Any]:
        """Every decision so far, as a native trace `verify --trace` and `assure` read."""
        return {"traces": [{"trace_id": self.run_id, "source": RUNTIME_PRODUCER,
                            "state_hash": self.check.admitted_state_hash,
                            "steps": [dict(s) for s in self._steps]}]}

    def _flush(self) -> None:
        if self._log_path is None:
            return
        temporary = self._log_path.with_name(self._log_path.name + ".tmp")
        temporary.write_text(json.dumps(self.trace(), indent=2, sort_keys=True),
                             encoding="utf-8")
        os.replace(temporary, self._log_path)

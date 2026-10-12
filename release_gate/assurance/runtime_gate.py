"""The runtime gate's pure core: the state a runtime observes, and one decision per call.

An admission names one exact candidate state (`candidate.py`), and `deploy-check`
compares a deployment with it (`deployment.py`). Two things weaken that in a
loosely built agent system, and this module is the deterministic half of the
answer to both; the host half is `release_gate.runtime`.

**The state moves without a release.** A prompt edited in a config store, an MCP
server that adds a tool or rewrites a description, a provider alias that now
serves another model: none of them goes through a pipeline. And a deployment
that *states* its components is the deployer's word. So `observe` computes each
component from the object the runtime is about to use:

    prompt             the digest of the exact UTF-8 bytes sent (`sha256sum`
                       of the file gives the same), or of a mapping of named
                       prompts
    tool_manifest      the digest of every tool definition exposed — name,
                       description, schema, annotations — in any order and in
                       the MCP (`tools/list`) or function-calling shape
    governance_policy  the digest of the policy document the runtime loaded
    model              the model identifier, as the runtime requests it

`release-gate state` states the candidate at admission time with these same
functions, so an admission and a runtime agree byte for byte or not at all.

**The danger is at the moment of the action.** `decide_tool_call` decides one
call against what was admitted, in this order, and the first that applies wins:

    stopped            the gate was closed (the state moved) or halted → DENY
    not admitted       no tool manifest was admitted, or the tool is not in it
                       → DENY
    changed            the caller passed the tool's current definition and it
                       is not the admitted one (a rewritten description is how
                       a tool is poisoned) → DENY
    policy             `trace_policies` refuses it — the same reading `verify
                       --trace` applies after a run (`trace_validator`) → DENY
    limit              `max_tool_calls` calls were already allowed → DENY
    approval           the tool is irreversible (MCP `destructiveHint`, or
                       `impact: irreversible`) or listed in
                       `approval_required_tools`, unless the admitted policy
                       names it in `autonomous_irreversible_tools`, and no
                       person was named → NEEDS_APPROVAL
    otherwise          ALLOW

A tool whose impact is not declared is allowed when admitted: it was in the
manifest the admission reviewed, and the scanner reports undeclared blast
radius at scan time (RG-TOOL-001). `decide_model` compares the model a provider
*reports* serving with the admitted one: an alias that resolved elsewhere is
not what was admitted.

Pure: no clock, no I/O, no randomness. The same inputs give the same decision.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Mapping, Optional, Tuple

from release_gate.assurance.canonical import (
    CanonicalisationError,
    digest_bytes,
    digest_object,
    freeze_value,
)
from release_gate.assurance.candidate import (
    CandidateError,
    CandidateState,
    StateComponent,
    canonical_value,
    values_equal,
)

__all__ = [
    "CallDecision",
    "GateDecision",
    "OBSERVED_BY",
    "ObservedState",
    "RuntimeStateError",
    "ToolManifest",
    "decide_model",
    "decide_tool_call",
    "observe",
    "policy_digest",
    "prompt_digest",
]

#: Who a runtime-observed state is declared by, as every check names it.
OBSERVED_BY = "release-gate runtime (observed from the objects in use)"


class RuntimeStateError(ValueError):
    """Something a runtime passed that cannot be read as part of a state."""


# ── observed state ───────────────────────────────────────────────────────────

def prompt_digest(prompt: Any) -> str:
    """The digest of the exact prompt text sent, or of named prompt texts."""
    if isinstance(prompt, str):
        return digest_bytes(prompt.encode("utf-8"))
    if isinstance(prompt, Mapping) and prompt and all(
            isinstance(k, str) and isinstance(v, str) for k, v in prompt.items()):
        return digest_object({"prompts": dict(prompt)})
    raise RuntimeStateError("a prompt is the text sent, or a non-empty mapping of names "
                            "to texts")


def policy_digest(policy: Any) -> str:
    """The digest of a loaded policy document."""
    if not isinstance(policy, Mapping):
        raise RuntimeStateError("a governance policy is the loaded document (a mapping)")
    try:
        return digest_object({"governance_policy": dict(policy)})
    except (CanonicalisationError, TypeError, ValueError) as exc:
        raise RuntimeStateError(f"the governance policy cannot be digested: {exc}") from exc


def _frozen(value: Any, what: str) -> Any:
    # Frozen as observed, so a caller changing its own copy afterwards changes
    # neither the digest nor what the gate enforces.
    try:
        return freeze_value(value, what)
    except CanonicalisationError as exc:
        raise RuntimeStateError(f"the {what} cannot be held as observed: {exc}") from exc


def _definition(entry: Any) -> Tuple[str, Mapping[str, Any]]:
    if not isinstance(entry, Mapping):
        raise RuntimeStateError("a tool definition is an object")
    inner = entry.get("function")
    definition = inner if entry.get("type") == "function" and isinstance(inner, Mapping) \
        else entry
    name = definition.get("name")
    if not isinstance(name, str) or not name.strip():
        raise RuntimeStateError("a tool definition carries no name, so no call can be "
                                "matched to it")
    return name.strip(), definition


@dataclass(frozen=True)
class ToolManifest:
    """Every tool a runtime exposes, by name, and the digest of the set."""

    tools: Mapping[str, Mapping[str, Any]]
    digest: str

    @classmethod
    def of(cls, source: Any) -> "ToolManifest":
        if isinstance(source, ToolManifest):
            return source
        entries = source.get("tools") if isinstance(source, Mapping) else source
        if not isinstance(entries, (list, tuple)):
            raise RuntimeStateError("a tool manifest is a list of tool definitions, or "
                                    "an MCP tools/list result")
        tools: Dict[str, Mapping[str, Any]] = {}
        for entry in entries:
            name, definition = _definition(entry)
            if name in tools:
                raise RuntimeStateError(f"tool {name!r} is defined twice; a call to it "
                                        "could mean either")
            tools[name] = _frozen(definition, f"tool {name}")
        try:
            digest = digest_object({"tools": [tools[n] for n in sorted(tools)]})
        except (CanonicalisationError, TypeError, ValueError) as exc:
            raise RuntimeStateError(f"the tool manifest cannot be digested: {exc}") from exc
        return cls(tools=tools, digest=digest)

    @property
    def names(self) -> Tuple[str, ...]:
        return tuple(sorted(self.tools))

    def definition_digest(self, name: str) -> str:
        return digest_object(self.tools[name])

    def irreversible(self, name: str) -> bool:
        definition = self.tools[name]
        annotations = definition.get("annotations")
        if isinstance(annotations, Mapping) and (
                annotations.get("destructiveHint") is True
                or annotations.get("destructive_hint") is True):
            return True
        return str(definition.get("impact") or "").strip().lower() == "irreversible"


@dataclass(frozen=True)
class ObservedState:
    """The components a runtime computed, and the objects they were computed from."""

    components: Mapping[str, str]
    tools: Optional[ToolManifest] = None
    policy: Optional[Mapping[str, Any]] = None

    def candidate(self, declared_by: str = OBSERVED_BY) -> CandidateState:
        return CandidateState(components=self.components, declared_by=declared_by)

    def inconsistencies(self) -> Tuple[str, ...]:
        """Where a component does not digest the object held beside it.

        `observe` cannot produce one; a state assembled by hand can, and a gate
        opened on it would admit one manifest and enforce another.
        """
        found = []
        held = {StateComponent.TOOL_MANIFEST.value:
                self.tools.digest if self.tools is not None else None,
                StateComponent.GOVERNANCE_POLICY.value:
                policy_digest(self.policy) if self.policy is not None else None}
        for key, digest in held.items():
            stated = self.components.get(key)
            if digest is not None and stated != digest:
                found.append(f"{key} is stated as {stated or 'nothing'}, but the object "
                             f"held digests to {digest}")
        return tuple(found)

    def to_dict(self, declared_by: str = OBSERVED_BY) -> Dict[str, Any]:
        """The state as a candidate document: what `assure --candidate` and
        `deploy-check --deployed` read."""
        return self.candidate(declared_by).to_dict()


def observe(*, model: Optional[str] = None, prompt: Any = None, tools: Any = None,
            governance_policy: Optional[Mapping[str, Any]] = None,
            components: Optional[Mapping[str, Any]] = None, **named: Any) -> ObservedState:
    """The state a runtime is in, computed from the objects it is about to use.

    Only what is passed becomes a component; nothing is defaulted. Other
    components (`commit`, `image`, `artifact:<name>`, `custom:<name>` …) are
    passed by keyword or in `components`, as stated values.
    """
    values: Dict[str, Any] = {k: v for k, v in dict(components or {}).items()
                              if v is not None}
    values.update({k: v for k, v in named.items() if v is not None})
    manifest = ToolManifest.of(tools) if tools is not None else None
    if model is not None:
        values[StateComponent.MODEL.value] = model
    if prompt is not None:
        values[StateComponent.PROMPT.value] = prompt_digest(prompt)
    if manifest is not None:
        values[StateComponent.TOOL_MANIFEST.value] = manifest.digest
    if governance_policy is not None:
        values[StateComponent.GOVERNANCE_POLICY.value] = policy_digest(governance_policy)
    if not values:
        raise RuntimeStateError("nothing was observed; a state names at least one "
                                "component")
    state = CandidateState(components=values, declared_by=OBSERVED_BY)
    return ObservedState(components=dict(state.components), tools=manifest,
                         policy=_frozen(governance_policy, "governance policy")
                         if governance_policy is not None else None)


# ── one decision per call ────────────────────────────────────────────────────

class GateDecision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    NEEDS_APPROVAL = "NEEDS_APPROVAL"


@dataclass(frozen=True)
class CallDecision:
    """What the gate decided about one call, and why."""

    decision: GateDecision
    reason: str
    kind: str                 # "tool_call" or "model"
    subject: str              # the tool, or the model reported
    approved_by: str = ""
    details: Mapping[str, Any] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.decision is GateDecision.ALLOW

    def to_dict(self) -> Dict[str, Any]:
        return {"decision": self.decision.value, "reason": self.reason, "kind": self.kind,
                "subject": self.subject,
                **({"approved_by": self.approved_by} if self.approved_by else {})}


def _names(policies: Mapping[str, Any], key: str) -> frozenset:
    value = policies.get(key) or ()
    return frozenset(str(v) for v in value) if isinstance(value, (list, tuple)) else frozenset()


def decide_tool_call(*, tool: str, manifest: Optional[ToolManifest],
                     policy: Optional[Mapping[str, Any]] = None,
                     definition: Optional[Mapping[str, Any]] = None,
                     approved_by: str = "", calls_allowed: int = 0,
                     stopped: str = "") -> CallDecision:
    """One tool call, decided against what was admitted (order in the module docstring)."""
    from release_gate.trace_validator import tool_policy_refusal
    tool = str(tool or "").strip()
    approver = str(approved_by or "").strip()

    def decided(decision: GateDecision, reason: str) -> CallDecision:
        return CallDecision(decision=decision, reason=reason, kind="tool_call", subject=tool,
                        approved_by=approver if decision is GateDecision.ALLOW else "")

    if stopped:
        return decided(GateDecision.DENY, stopped)
    if manifest is None:
        return decided(GateDecision.DENY, "the admission states no tool manifest, so no "
                                          "tool is admitted")
    if tool not in manifest.tools:
        return decided(GateDecision.DENY, f"{tool or 'a tool with no name'} is not in "
                                          "the admitted tool manifest")
    if definition is not None:
        try:
            _, current = _definition(definition)
            changed = digest_object(current) != manifest.definition_digest(tool)
        except (RuntimeStateError, TypeError, ValueError):
            changed = True
        if changed:
            return decided(GateDecision.DENY,
                           f"the definition of {tool} is not the one admitted: its "
                           "description, schema or annotations changed since admission")
    policies = (policy or {}).get("trace_policies") if isinstance(policy, Mapping) else None
    policies = policies if isinstance(policies, Mapping) else {}
    refusal = tool_policy_refusal(tool, dict(policies))
    if refusal:
        return decided(GateDecision.DENY, f"{tool} is refused by the admitted policy's "
                                          f"trace_policies: {refusal}")
    limit = policies.get("max_tool_calls")
    if isinstance(limit, int) and not isinstance(limit, bool) and calls_allowed >= limit:
        return decided(GateDecision.DENY,
                       f"max_tool_calls is {limit} in the admitted policy and {calls_allowed} "
                       "call(s) were already allowed")
    needs_person = ((manifest.irreversible(tool)
                     and tool not in _names(policies, "autonomous_irreversible_tools"))
                    or tool in _names(policies, "approval_required_tools"))
    if needs_person and not approver:
        return decided(GateDecision.NEEDS_APPROVAL,
                       f"{tool} is irreversible or requires approval under the admitted "
                       "policy: a named person must approve this call")
    return decided(GateDecision.ALLOW,
                   f"{tool} is admitted" + (f", approved by {approver}" if approver else ""))


def decide_model(*, reported: Any, admitted: Optional[str], stopped: str = "") -> CallDecision:
    """Is the model a provider reports serving the one that was admitted?"""
    shown = str(reported or "").strip()

    def decided(decision: GateDecision, reason: str) -> CallDecision:
        return CallDecision(decision=decision, reason=reason, kind="model", subject=shown)

    if stopped:
        return decided(GateDecision.DENY, stopped)
    if not admitted:
        return decided(GateDecision.DENY,
                       "the admission did not state a model, so no model's output is "
                       "admitted; state the model the runtime requests at admission")
    if not shown:
        return decided(GateDecision.DENY, "the provider reported no model, so it cannot "
                                          "be shown to be the admitted one")
    try:
        canonical = canonical_value(StateComponent.MODEL.value, shown)
    except CandidateError as exc:
        return decided(GateDecision.DENY, f"the reported model cannot be read: {exc}")
    if values_equal(StateComponent.MODEL.value, canonical, admitted):
        return decided(GateDecision.ALLOW, f"{shown} is the admitted model")
    return decided(GateDecision.DENY,
                   f"the provider reports serving {shown}; the admitted model is "
                   f"{admitted}. An alias that now resolves elsewhere is not what was "
                   "admitted")

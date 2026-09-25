"""Reading what an orchestrator recorded, without depending on any of them.

Release-gate consumes evidence. It does not run agents, schedule work, or hold an
opinion about how a system should be built — so the framework that produced a run
is a fact about the input, never a dependency of the engine. Nothing here imports
LangGraph, CrewAI, AutoGen, Temporal or any agent SDK, and nothing can: this
module is stdlib-only like the rest of `assurance`, and the guard that keeps
vendor SDKs out of the package covers orchestrators too.

The normalised vocabulary was already right. `ExecutionNodeKind` has AGENT, TASK,
TOOL, ACTION, MODEL_CALL, VERIFIER, HUMAN and UNOBSERVED; `ExecutionEdgeType` has
SPAWNED, DELEGATED and CALLED. A CrewAI crew delegating to an agent, a LangGraph
node writing state, an AutoGen turn calling a tool and a Temporal activity all
land in that vocabulary without extending it. What was missing was only the
reading: fed a real export from any of them, the engine reported UNRECOGNISED and
mapped nothing.

So the shape is **data**. An `OrchestratorProfile` names where the steps live,
which keys carry the id, the parent and the label, and how that framework's own
vocabulary maps onto the neutral one. Adding a framework adds a row; a custom or
unpublished framework is a profile its owner writes and passes in; a future one
is a profile nobody has written yet. There is no code path per orchestrator,
because a code path per orchestrator is how a consumer becomes a dependent.

**An export is the orchestrator's account of itself.** Release-gate did not watch
the run. A framework that reports `"status": "completed"` is making a claim about
its own behaviour, and that is DECLARED evidence whatever the framework —
`establishes_correctness` is unconditionally `False`. Frameworks are built to
report success; treating their self-report as observation would put the thing
being assessed in charge of the assessment (Invariant 1).

**A step that cannot be mapped is counted, not dropped.** The adapters have
carried that rule from the start — "never invent a step; report the gap" — and it
is the same distinction §10ab drew between withheld and absent. A reading that
silently discarded what it did not understand would report a smaller run than the
one that happened, and the case would read as complete.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import (Any, Dict, Iterable, List, Mapping, Optional, Sequence,
                    Tuple)

__all__ = [
    "ORCHESTRATION_SCHEMA_VERSION",
    "PROFILES",
    "OrchestrationError",
    "OrchestratorProfile",
    "ProfileResolution",
    "StepReading",
    "identify",
    "profile_for",
    "read_execution",
]

ORCHESTRATION_SCHEMA_VERSION = 1


class OrchestrationError(ValueError):
    """An export could not be read, or a profile could not describe one."""


def _walk(document: Any, path: Sequence[str]) -> List[Mapping[str, Any]]:
    """Collect the mappings at `path`, treating `[]` as "each item of this list".

    Returns a flat list. A path that leads nowhere returns nothing rather than
    raising: an export that simply does not contain a section is a different
    thing from a malformed one, and only the caller knows which it expected.
    """
    nodes: List[Any] = [document]
    for step in path:
        found: List[Any] = []
        for node in nodes:
            if step == "[]":
                if isinstance(node, list):
                    found.extend(node)
            elif step == "{}":
                # LangGraph's `metadata.writes` maps node name to what it wrote,
                # so the steps are the mapping's entries rather than a list. Read
                # as one row, two nodes collapsed into one and the node name —
                # the only label there is — was lost.
                if isinstance(node, Mapping):
                    for key, value in node.items():
                        row = {"_key": key}
                        if isinstance(value, Mapping):
                            row.update(value)
                        else:
                            row["_value"] = value
                        found.append(row)
            elif isinstance(node, Mapping) and step in node:
                found.append(node[step])
        nodes = found
    out: List[Mapping[str, Any]] = []
    for node in nodes:
        if isinstance(node, Mapping):
            out.append(node)
        elif isinstance(node, list):
            out.extend(item for item in node if isinstance(item, Mapping))
    return out


@dataclass(frozen=True)
class OrchestratorProfile:
    """How one framework writes down a run.

    Data, not a subclass. Every field is a description of where something lives
    in that framework's export, so a new framework is a row and a private one is
    an instance its owner constructs.
    """

    name: str
    label: str
    #: Where the step records live. `[]` means "each item of this list".
    step_path: Tuple[str, ...] = ()
    #: Keys carrying a step's identity, parent and human-readable label, in
    #: preference order — frameworks disagree with themselves across versions.
    id_keys: Tuple[str, ...] = ("id",)
    parent_keys: Tuple[str, ...] = ("parent_id",)
    label_keys: Tuple[str, ...] = ("name",)
    #: Keys whose value names what kind of step this is.
    kind_keys: Tuple[str, ...] = ("type",)
    #: This framework's own vocabulary → the neutral `ExecutionNodeKind` value.
    kind_map: Mapping[str, str] = field(default_factory=dict)
    #: The neutral kind for a step whose own kind is absent or unmapped. Empty
    #: means "do not guess": the step is counted as unmapped instead.
    default_kind: str = ""
    #: Keys worth carrying into the node's attributes.
    carry_keys: Tuple[str, ...] = ()
    #: Top-level keys whose mere presence points at this framework, and the
    #: distinctive values that confirm it. Structural, so a file is recognised
    #: by its shape rather than by a name someone wrote in it.
    detect_keys: Tuple[str, ...] = ()
    detect_values: Mapping[str, Tuple[str, ...]] = field(default_factory=dict)
    #: What this framework's export structurally cannot establish. Carried onto
    #: every reading, because a gap that depends on being remembered is one that
    #: goes unmentioned (§10z).
    inherent_gaps: Tuple[str, ...] = ()
    notes: str = ""

    def __post_init__(self) -> None:
        for name in ("step_path", "id_keys", "parent_keys", "label_keys",
                     "kind_keys", "carry_keys", "detect_keys", "inherent_gaps"):
            object.__setattr__(self, name, tuple(getattr(self, name)))
        object.__setattr__(self, "kind_map", dict(self.kind_map))
        object.__setattr__(self, "detect_values",
                           {k: tuple(v) for k, v in self.detect_values.items()})
        if not str(self.name or "").strip():
            raise OrchestrationError(
                "a profile must be named so a case can cite which framework it "
                "was read from")
        if not self.step_path:
            raise OrchestrationError(
                f"{self.name}: a profile must say where the steps are. Without a "
                "path there is nothing to read, and a profile that read nothing "
                "would report an empty run rather than an unreadable one")

    @property
    def establishes_correctness(self) -> bool:
        """Unconditionally False, for every framework.

        An export is the orchestrator's account of itself, and release-gate did
        not watch the run. Frameworks are built to report success; treating that
        as observation would put the thing being assessed in charge of the
        assessment (Invariant 1).
        """
        return False

    def matches(self, document: Any) -> int:
        """How strongly this document looks like this framework's export, 0–100.

        Structural, not name-based: a document is recognised by having the keys
        this framework writes, in the places it writes them. `detect_values`
        raises the score where a key's *value* is distinctive, which is what
        separates two frameworks that both use `events` or `messages`.
        """
        if not isinstance(document, (Mapping, list)):
            return 0
        score = 0
        top = set(document) if isinstance(document, Mapping) else set()
        for key in self.detect_keys:
            if key in top:
                score += 40
        if _walk(document, self.step_path):
            score += 35
        for key, wanted in self.detect_values.items():
            for row in _walk(document, self.step_path):
                value = str(row.get(key) or "")
                if any(w in value for w in wanted):
                    score += 25
                    break
        return min(score, 100)

    @staticmethod
    def _first(row: Mapping[str, Any], keys: Sequence[str],
               prefer: Sequence[str] = ("name", "id", "type")) -> str:
        """The first present value among `keys`, resolving a nested mapping.

        `prefer` decides which inner key is wanted, and it has to: the OpenAI
        Agents SDK puts both the kind and the label inside one `span_data`
        mapping, so a single resolution order read "Planner" where the kind
        belonged and mapped none of the run.
        """
        for key in keys:
            if key in row and row[key] not in (None, ""):
                value = row[key]
                if isinstance(value, Mapping):
                    for inner in prefer:
                        if inner in value and value[inner] not in (None, ""):
                            return str(value[inner])
                    continue
                return str(value)
        return ""

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "orchestrator_profile", "record_id": self.name,
                "name": self.name, "label": self.label,
                "step_path": list(self.step_path),
                "kind_map": dict(self.kind_map),
                "inherent_gaps": list(self.inherent_gaps), "notes": self.notes,
                "establishes_correctness": False}


_PROFILE_LIST: Tuple[OrchestratorProfile, ...] = (
    OrchestratorProfile(
        name="openai_agents", label="OpenAI Agents SDK trace export",
        step_path=("traces", "[]", "spans", "[]"),
        id_keys=("span_id",), parent_keys=("parent_id",),
        label_keys=("span_data",), kind_keys=("span_data",),
        kind_map={"agent": "AGENT", "function": "TOOL", "generation": "MODEL_CALL",
                  "handoff": "AGENT", "guardrail": "VERIFIER",
                  "custom": "ACTION", "response": "MODEL_CALL"},
        carry_keys=("workflow_name", "error"),
        detect_keys=("traces",),
        detect_values={"span_id": ("sp_", "span")},
        inherent_gaps=("a handoff span records that control moved, not whether "
                       "the receiving agent was entitled to it",),
        notes="`span_data.type` carries the kind and `span_data.name` the label, "
              "so both are read out of the same nested mapping."),
    OrchestratorProfile(
        name="langgraph", label="LangGraph checkpoint or state export",
        step_path=("metadata", "writes", "{}"),
        id_keys=("_key",), parent_keys=("parent_checkpoint_id",),
        label_keys=("_key",), kind_keys=(),
        default_kind="TASK",
        carry_keys=("step", "source", "thread_id"),
        detect_keys=("checkpoint_id", "next"),
        inherent_gaps=("a checkpoint records the state after a node ran, not "
                       "what the node did to produce it",
                       "conditional edges are in the graph definition, not in "
                       "this export, so a branch not taken leaves no trace"),
        notes="`metadata.writes` maps node name to what it wrote, which is the "
              "closest thing a checkpoint has to a step list."),
    OrchestratorProfile(
        name="crewai", label="CrewAI crew output",
        step_path=("tasks_output", "[]"),
        id_keys=("name", "description"), parent_keys=("agent",),
        label_keys=("name", "description"), kind_keys=(),
        default_kind="TASK",
        carry_keys=("agent", "expected_output", "summary"),
        detect_keys=("tasks_output",),
        inherent_gaps=("task output records what a task returned, not which "
                       "tools it used to get there",
                       "an agent is named as a string, so two agents with the "
                       "same role are indistinguishable in this export"),
        notes="`agent` is used as the parent, which reconstructs delegation "
              "without the framework having to emit an edge."),
    OrchestratorProfile(
        name="autogen", label="AutoGen conversation history",
        step_path=("chat_history", "[]"),
        id_keys=("id",), parent_keys=(), label_keys=("name", "role"),
        kind_keys=("role",),
        kind_map={"user": "HUMAN", "assistant": "AGENT", "tool": "TOOL",
                  "function": "TOOL", "system": "ACTION"},
        default_kind="ACTION",
        carry_keys=("name", "tool_calls", "tool_responses"),
        detect_keys=("chat_history", "summary"),
        detect_values={"role": ("assistant", "user", "tool")},
        inherent_gaps=("a conversation records what was said, and a message "
                       "claiming a tool ran is not a record of it running",
                       "group-chat speaker selection is not in the history, so "
                       "why a given agent spoke cannot be read from it"),
        notes="Messages carry no ids, so steps are addressed by position; the "
              "reader supplies that rather than the framework."),
    OrchestratorProfile(
        name="temporal", label="Temporal workflow history",
        step_path=("events", "[]"),
        id_keys=("eventId",), parent_keys=(), label_keys=("eventType",),
        kind_keys=("eventType",),
        kind_map={"WorkflowExecutionStarted": "AGENT",
                  "ActivityTaskScheduled": "TASK",
                  "ActivityTaskStarted": "ACTION",
                  "ActivityTaskCompleted": "ACTION",
                  "ActivityTaskFailed": "ACTION",
                  "ChildWorkflowExecutionStarted": "AGENT",
                  "TimerStarted": "ACTION",
                  "SignalExternalWorkflowExecutionInitiated": "EXTERNAL_SYSTEM",
                  "WorkflowExecutionCompleted": "ACTION",
                  "WorkflowExecutionFailed": "ACTION"},
        carry_keys=("eventTime", "taskId", "version"),
        detect_keys=("events",),
        detect_values={"eventType": ("WorkflowExecution", "ActivityTask")},
        inherent_gaps=("a history records that an activity completed, not what "
                       "it did — activity inputs and results are payloads this "
                       "export may not carry",
                       "a replayed workflow produces the same history, so the "
                       "history alone does not distinguish a run from a replay"),
        notes="Event types are the richest kind signal of any of these formats, "
              "which is why this profile maps many of them rather than "
              "defaulting."),
)

#: name → profile. Built from one list so the registry cannot disagree with
#: itself about which frameworks are known.
PROFILES: Mapping[str, OrchestratorProfile] = {p.name: p for p in _PROFILE_LIST}

#: Below this, identification does not commit — the same floor the platform
#: adapters use, for the same reason: a guess that gates a release is worse than
#: an honest UNRECOGNISED.
DETECT_FLOOR = 50


def profile_for(name: str) -> OrchestratorProfile:
    found = PROFILES.get((name or "").strip().lower())
    if found is None:
        raise OrchestrationError(
            f"no profile named {name!r}. Known: " + ", ".join(sorted(PROFILES))
            + ". A framework this does not know is not one it refuses: describe "
              "it with an OrchestratorProfile and pass that in")
    return found


@dataclass(frozen=True)
class ProfileResolution:
    """Which framework this looks like, and whether that was established."""

    profile: Optional[OrchestratorProfile]
    confidence: int = 0
    recognised: bool = False
    basis: str = ""
    #: Every profile that scored, so a near-miss is visible rather than silently
    #: losing to a slightly better one.
    alternatives: Tuple[Tuple[str, int], ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "profile_resolution",
                "profile": self.profile.name if self.profile else None,
                "confidence": self.confidence, "recognised": self.recognised,
                "basis": self.basis,
                "alternatives": [list(a) for a in self.alternatives]}


def identify(document: Any) -> ProfileResolution:
    """Which framework wrote this, if any.

    An unrecognised export resolves to no profile at all. Guessing would read one
    framework's export with another's key names and produce a run that is
    plausible and wrong — and unlike a crash, that gets a verdict.
    """
    scores = sorted(((p, p.matches(document)) for p in _PROFILE_LIST),
                    key=lambda pair: (-pair[1], pair[0].name))
    alternatives = tuple((p.name, s) for p, s in scores if s > 0)
    if not scores or scores[0][1] < DETECT_FLOOR:
        return ProfileResolution(
            None, scores[0][1] if scores else 0, False,
            "no orchestrator profile matched above "
            f"{DETECT_FLOOR}%. The run is still hashed and recorded; its "
            "structure is not read, and that is reported as unread rather than "
            "as an empty run",
            alternatives)
    best, score = scores[0]
    return ProfileResolution(best, score, True,
                             f"matched the {best.name} profile at {score}%",
                             alternatives)


@dataclass(frozen=True)
class StepReading:
    """Normalised steps, and an honest account of what was not read.

    `unmapped` is the field that matters. A reading that silently discarded what
    it did not understand would report a smaller run than the one that happened.
    """

    profile_name: str
    records: Tuple[Mapping[str, Any], ...] = ()
    seen: int = 0
    unmapped: Tuple[Mapping[str, Any], ...] = ()
    gaps: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "records", tuple(dict(r) for r in self.records))
        object.__setattr__(self, "unmapped", tuple(dict(u) for u in self.unmapped))
        object.__setattr__(self, "gaps", tuple(self.gaps))

    @property
    def mapped(self) -> int:
        return len(self.records)

    @property
    def complete(self) -> bool:
        """Whether every step seen was mapped. False is ordinary, not a failure —
        it is the number that keeps the reading honest."""
        return self.seen == self.mapped and not self.unmapped

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "step_reading", "profile": self.profile_name,
                "seen": self.seen, "mapped": self.mapped,
                "unmapped": [dict(u) for u in self.unmapped],
                "complete": self.complete, "gaps": list(self.gaps),
                "establishes_correctness": False}


def read_execution(document: Any, profile: Optional[OrchestratorProfile] = None
                   ) -> StepReading:
    """Read one export into the flat execution records the graph builder takes.

    Emits the shape `ExecutionGraphBuilder.add_span_record` already consumes, so
    parent/child survives — a run read as a linear spine would lose exactly the
    delegation structure these frameworks exist to express.
    """
    if profile is None:
        resolution = identify(document)
        if resolution.profile is None:
            raise OrchestrationError(
                "no orchestrator profile matched this document, and reading it "
                "with a guessed one would produce a run that is plausible and "
                "wrong. Name a profile, or describe the framework with an "
                "OrchestratorProfile")
        profile = resolution.profile

    rows = _walk(document, profile.step_path)
    records: List[Dict[str, Any]] = []
    unmapped: List[Dict[str, Any]] = []

    for index, row in enumerate(rows):
        raw_kind = (profile._first(row, profile.kind_keys,
                                   prefer=("type", "kind", "name"))
                    if profile.kind_keys else "")
        kind = profile.kind_map.get(raw_kind, "")
        if not kind and profile.kind_map and raw_kind:
            # The framework named a kind this profile does not map. Counted, not
            # guessed: assigning a neutral kind here would put a step in the
            # graph under a classification nobody made.
            unmapped.append({"index": index, "kind": raw_kind,
                             "reason": "the framework's kind is not mapped by "
                                       f"the {profile.name} profile"})
            continue
        if not kind:
            kind = profile.default_kind
        if not kind:
            unmapped.append({"index": index, "kind": raw_kind or None,
                             "reason": "no kind on the step and the profile "
                                       "declares no default, so what this step "
                                       "was is unknown"})
            continue

        node_id = profile._first(row, profile.id_keys) or f"{profile.name}:{index}"
        label = (profile._first(row, profile.label_keys,
                                prefer=("name", "id", "type"))
                 or raw_kind or node_id)
        attributes = {"_kind_hint": kind, "orchestrator": profile.name,
                      "classified_by": f"{profile.name} profile"}
        for key in profile.carry_keys:
            if key in row and row[key] not in (None, ""):
                attributes[key] = row[key]
        records.append({
            "record_type": "execution", "node_id": f"{profile.name}:{node_id}",
            "parent_id": (f"{profile.name}:{profile._first(row, profile.parent_keys)}"
                          if profile.parent_keys
                          and profile._first(row, profile.parent_keys) else ""),
            "label": label, "node_kind": kind, "sequence": index,
            "stream_id": profile.name, "attributes": attributes})

    return StepReading(profile_name=profile.name, records=tuple(records),
                       seen=len(rows), unmapped=tuple(unmapped),
                       gaps=profile.inherent_gaps)

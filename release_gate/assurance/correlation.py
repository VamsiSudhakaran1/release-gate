"""Correlation groups — how many sources a body of agreement actually rests on.

In an agent-written codebase, one model writes the implementation, the tests, the
security review, the architecture review and the eval cases. That is five
artifacts and possibly one epistemic source. A gate that reports "five
independent confirmations" has turned one model's view into apparent consensus.

`independence.py` already follows derivation ancestry (`parent_evidence`), and a
verification attempt already carries an `independence_lineage`. Neither knows
what produced a record: which provider, which model family, which session,
which agent, which prompt, which dataset, which person. This module reads that
provenance and builds **correlation groups** — sets of sources that share
something the policy says makes them one source.

**Provenance is read, never guessed.** It comes from what a record states: its
`content.provenance` (`provider`, `model_family`, `model_version`, `session`,
`agent`, `reviewer`, `toolchain`, `prompt_lineage`, `dataset`,
`generated_from`, `relied_on`), its producer's model and kind, its declared
`independence_group`, an attempt's `independence_lineage` and verifier, and the
records it derives from. A model id is not parsed into a family. A shared
provider does not correlate by default. Nothing is inferred from a name.

**Reliance inherits.** A record that derives from another — a person's review of
an AI-written summary, a test generated from a generated spec — carries every key
of what it relied on. So the review lands in the summary's group, and is not
counted as a second, human opinion when it is the same opinion read twice.

**What is checked is not a correlation.** A formal verifier and a test suite
examining the same artifact are two checks of one thing, which is the point of
checking. Only what a source was *generated from* or *relied on* correlates it.

**Unknown is an answer.** A source that states nothing about what generated it
— a producer name and nothing else — cannot be placed. It is counted apart, never
credited as independent, and a set whose independence rests on such sources reads
`INDEPENDENCE_UNKNOWN`. Independence that is not established is not assumed
(the rule `verification._lineage_groups` already applies to unrecorded lineage).

**No number stands in for any of this.** The output is groups, members, the
keys that joined them, and a status. There is no independence score and no
confidence. Whether independence is *enough* is a policy's question — the claim
resolver reads `IndependencePolicy.min_independent_groups` — and the policy is
declared, digested and recorded on the case.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from release_gate.assurance.canonical import digest_object

__all__ = [
    "CORRELATION_SCHEMA_VERSION",
    "DEFAULT_INDEPENDENCE_POLICY",
    "CorrelationGroup",
    "IndependenceAssessment",
    "IndependencePolicy",
    "IndependenceStatus",
    "ProvenanceDimension",
    "ProvenanceIndex",
    "SourceProvenance",
    "assess_independence",
    "attempt_keys",
    "attempt_provenance",
    "attempt_relied_on",
    "provenance_from",
    "record_provenance",
]

CORRELATION_SCHEMA_VERSION = 1


class ProvenanceDimension(str, Enum):
    """What two sources can share that makes them one source."""

    PROVIDER = "provider"              # the organisation serving the model
    MODEL_FAMILY = "model_family"      # one model family, whatever its version
    SESSION = "session"                # one run, one conversation, one job
    AGENT = "agent"                    # the originating agent
    REVIEWER = "reviewer"              # one person, twice
    TOOLCHAIN = "toolchain"            # one tool, twice
    PROMPT_LINEAGE = "prompt_lineage"  # one prompt template
    DATASET = "dataset"                # one test or eval dataset
    GENERATED_FROM = "generated_from"  # one generated artifact they derive from
    ANCESTRY = "ancestry"              # one upstream record (parent_evidence, relied_on)
    LINEAGE = "lineage"                # a declared independence lineage or group
    PRODUCER = "producer"              # one producer identity
    VERIFIER = "verifier"              # one verifier identity


#: Dimensions that say what *generated* a source. A source stating none of them
#: cannot be placed: a producer or verifier name is an unauthenticated label,
#: and two labels may be one agent.
_GENERATIVE = frozenset({ProvenanceDimension.MODEL_FAMILY, ProvenanceDimension.REVIEWER,
                         ProvenanceDimension.TOOLCHAIN, ProvenanceDimension.SESSION,
                         ProvenanceDimension.AGENT, ProvenanceDimension.LINEAGE})


class IndependenceError(ValueError):
    """An independence policy was described in a way that could not be applied."""


#: Dimensions every policy correlates on. Only `provider` is a choice.
_ALWAYS_CORRELATES = tuple(d for d in ProvenanceDimension
                           if d is not ProvenanceDimension.PROVIDER)


@dataclass(frozen=True)
class IndependencePolicy:
    """Which shared provenance makes two sources one, and how many groups are enough.

    Declared and digested, and recorded on the case that used it, because whether
    two models from one provider are independent is a judgement — and a judgement
    the engine makes silently is one nobody can disagree with.
    """

    policy_id: str = "rg-independence"
    version: str = "1"
    correlate_on: Tuple[ProvenanceDimension, ...] = _ALWAYS_CORRELATES
    #: How many independent groups a claim's support needs before agreement is
    #: corroboration. Read by the claim resolver; this module only counts.
    min_independent_groups: int = 2
    note: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "correlate_on", tuple(sorted(
            {ProvenanceDimension(d) for d in self.correlate_on}, key=lambda d: d.value)))
        dropped = sorted(d.value for d in _ALWAYS_CORRELATES
                         if d not in self.correlate_on)
        if dropped:
            # A policy may treat more as shared (a provider); it may not declare
            # shared provenance irrelevant. Dropping `session` would make five
            # outputs of one model in five sessions five confirmations, which is
            # independence written into a policy rather than found in evidence.
            raise IndependenceError(
                "an independence policy may add `provider` to what correlates, "
                "never drop a dimension: " + ", ".join(dropped)
                + " would stop counting as shared")
        if isinstance(self.min_independent_groups, bool) or int(
                self.min_independent_groups) < 1:
            raise IndependenceError("min_independent_groups must be at least 1")
        object.__setattr__(self, "min_independent_groups", int(self.min_independent_groups))
        if not str(self.policy_id).strip():
            raise IndependenceError("an independence policy must be named")

    @property
    def ref(self) -> str:
        return f"{self.policy_id}@{self.version}"

    def to_dict(self) -> Dict[str, Any]:
        return {"policy_id": self.policy_id, "version": self.version,
                "correlate_on": [d.value for d in self.correlate_on],
                "min_independent_groups": self.min_independent_groups,
                "note": self.note, "schema_version": CORRELATION_SCHEMA_VERSION}

    def digest(self) -> str:
        return digest_object(self.to_dict())

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "IndependencePolicy":
        try:
            return cls(policy_id=str(data.get("policy_id") or "custom"),
                       version=str(data.get("version") or "1"),
                       correlate_on=tuple(ProvenanceDimension(str(d))
                                          for d in (data.get("correlate_on")
                                                    or [d.value for d in
                                                        DEFAULT_INDEPENDENCE_POLICY.correlate_on])),
                       min_independent_groups=int(data.get("min_independent_groups", 2)),
                       note=str(data.get("note") or ""))
        except (TypeError, ValueError) as exc:
            if isinstance(exc, IndependenceError):
                raise
            raise IndependenceError(f"unusable independence policy: {exc}") from exc


DEFAULT_INDEPENDENCE_POLICY = IndependencePolicy(
    note="every stated dimension correlates except a shared provider: two model "
         "families from one provider are not assumed to be one source. A policy "
         "that wants them to be adds `provider`.")


# ── provenance ───────────────────────────────────────────────────────────────

def _strings(value: Any) -> Tuple[str, ...]:
    if value in (None, ""):
        return ()
    items = value if isinstance(value, (list, tuple)) else [value]
    return tuple(sorted({str(v).strip() for v in items
                         if isinstance(v, (str, int)) and str(v).strip()}))


def _text(value: Any) -> str:
    return str(value).strip() if isinstance(value, (str, int)) and not isinstance(
        value, bool) else ""


@dataclass(frozen=True)
class SourceProvenance:
    """What one source states about what produced it."""

    source_id: str
    source_kind: str                       # "evidence" | "verification"
    producer_id: str = ""
    provider: str = ""
    model_family: str = ""
    model_version: str = ""
    session: str = ""
    agent: str = ""
    reviewer: str = ""
    toolchain: Tuple[str, ...] = ()
    prompt_lineage: Tuple[str, ...] = ()
    datasets: Tuple[str, ...] = ()
    generated_from: Tuple[str, ...] = ()
    ancestry: Tuple[str, ...] = ()
    lineage: Tuple[str, ...] = ()
    verifier: str = ""
    #: Keys inherited from what this source relied on, already formatted.
    inherited: Tuple[str, ...] = ()

    def own_keys(self, policy: IndependencePolicy) -> Set[str]:
        on = set(policy.correlate_on)
        D = ProvenanceDimension
        keys: Set[str] = set()

        def add(dim: ProvenanceDimension, *values: str) -> None:
            if dim in on:
                keys.update(f"{dim.value}:{v}" for v in values if v)

        if self.model_family:
            add(D.MODEL_FAMILY, f"{self.provider.lower()}/{self.model_family.lower()}"
                if self.provider else self.model_family.lower())
        add(D.PROVIDER, self.provider.lower())
        add(D.SESSION, self.session)
        add(D.AGENT, self.agent)
        add(D.REVIEWER, self.reviewer)
        add(D.TOOLCHAIN, *self.toolchain)
        add(D.PROMPT_LINEAGE, *self.prompt_lineage)
        add(D.DATASET, *self.datasets)
        add(D.GENERATED_FROM, *self.generated_from)
        add(D.ANCESTRY, *self.ancestry)
        add(D.LINEAGE, *self.lineage)
        add(D.PRODUCER, self.producer_id)
        add(D.VERIFIER, self.verifier)
        return keys

    def keys(self, policy: IndependencePolicy) -> Set[str]:
        on = {d.value for d in policy.correlate_on}
        return self.own_keys(policy) | {k for k in self.inherited
                                        if k.split(":", 1)[0] in on}

    def determinable(self, policy: IndependencePolicy) -> bool:
        """Does it say what generated it, in a dimension the policy reads?"""
        D = ProvenanceDimension
        stated = {D.MODEL_FAMILY: bool(self.model_family), D.REVIEWER: bool(self.reviewer),
                  D.TOOLCHAIN: bool(self.toolchain), D.SESSION: bool(self.session),
                  D.AGENT: bool(self.agent), D.LINEAGE: bool(self.lineage)}
        if any(stated[d] for d in _GENERATIVE if d in policy.correlate_on):
            return True
        # Inheriting a generative key from what it relied on places it too.
        generative = {d.value for d in _GENERATIVE if d in policy.correlate_on}
        return any(k.split(":", 1)[0] in generative for k in self.inherited)

    def to_dict(self) -> Dict[str, Any]:
        return {"source_id": self.source_id, "source_kind": self.source_kind,
                "producer_id": self.producer_id, "provider": self.provider,
                "model_family": self.model_family, "model_version": self.model_version,
                "session": self.session, "agent": self.agent, "reviewer": self.reviewer,
                "toolchain": list(self.toolchain),
                "prompt_lineage": list(self.prompt_lineage),
                "datasets": list(self.datasets), "generated_from": list(self.generated_from),
                "ancestry": list(self.ancestry), "lineage": list(self.lineage),
                "verifier": self.verifier, "inherited": list(self.inherited)}


def _from_mapping(block: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "provider": _text(block.get("provider") or block.get("organization")),
        "model_family": _text(block.get("model_family")),
        "model_version": _text(block.get("model_version") or block.get("model")),
        "session": _text(block.get("session") or block.get("run_id")),
        "agent": _text(block.get("agent") or block.get("originating_agent")),
        "reviewer": _text(block.get("reviewer") or block.get("human_reviewer")),
        "toolchain": _strings(block.get("toolchain")),
        "prompt_lineage": _strings(block.get("prompt_lineage")),
        "datasets": _strings(block.get("dataset") or block.get("datasets")),
        "generated_from": _strings(block.get("generated_from")
                                   or block.get("shared_artifacts")),
        "relied_on": _strings(block.get("relied_on")),
    }


def provenance_from(block: Mapping[str, Any], *, source_id: str,
                    source_kind: str) -> SourceProvenance:
    """A source's provenance from a stated block alone — nothing from who reported it.

    For a statement *about* a source (an authorship record names who did the
    work, and its own producer is only the one who said so), where folding in
    the reporting record's producer would make the reporter an author.
    """
    stated = _from_mapping(block if isinstance(block, Mapping) else {})
    stated.pop("relied_on")
    return SourceProvenance(source_id=source_id, source_kind=source_kind, **stated)


def record_provenance(record: Any) -> Tuple[SourceProvenance, Tuple[str, ...]]:
    """One evidence record's stated provenance, and the ids it says it relied on.

    The relied-on ids are returned separately: they are resolved against the case
    (declared envelope ids included) by `provenance_index`, which then folds the
    ancestors' keys in.
    """
    content = getattr(record, "content", None) or {}
    block = content.get("provenance") if isinstance(content, Mapping) else None
    stated = _from_mapping(block) if isinstance(block, Mapping) else _from_mapping({})
    producer = getattr(record, "producer", None)
    kind = str(getattr(getattr(producer, "kind", None), "value", "") or "")
    model = _text(getattr(producer, "model", None))
    if model and not stated["model_version"]:
        stated["model_version"] = model
    if kind == "human" and not stated["reviewer"]:
        stated["reviewer"] = _text(getattr(producer, "producer_id", ""))
    prompt = (getattr(record, "metadata", None) or {}).get("prompt_digest")
    if prompt:
        stated["prompt_lineage"] = tuple(sorted(set(stated["prompt_lineage"]) | {str(prompt)}))
    group = content.get("independence_group") if isinstance(content, Mapping) else None
    relied_on = stated.pop("relied_on")
    return SourceProvenance(
        source_id=str(getattr(record, "evidence_id", "")), source_kind="evidence",
        producer_id=_text(getattr(producer, "producer_id", "")),
        lineage=_strings(group), **stated), relied_on


def attempt_relied_on(attempt: Any) -> Tuple[str, ...]:
    """What an attempt says it relied on: the evidence it cites, and `relied_on`."""
    result = getattr(attempt, "result", None) or {}
    block = result.get("provenance") if isinstance(result, Mapping) else None
    stated = _strings(block.get("relied_on")) if isinstance(block, Mapping) else ()
    cited = tuple(str(e) for e in (getattr(attempt, "evidence", ()) or ()) if e)
    return tuple(sorted(set(cited) | set(stated)))


def attempt_provenance(attempt: Any) -> SourceProvenance:
    """A verification attempt's own provenance: lineage, verifier, stated block.

    What it relied on is not folded in here — that needs the case's records, and
    is `ProvenanceIndex.attempt_source`.
    """
    result = getattr(attempt, "result", None) or {}
    block = result.get("provenance") if isinstance(result, Mapping) else None
    stated = _from_mapping(block) if isinstance(block, Mapping) else _from_mapping({})
    stated.pop("relied_on")
    return SourceProvenance(
        source_id=str(getattr(attempt, "verification_id", "")),
        source_kind="verification",
        lineage=tuple(sorted(set(getattr(attempt, "independence_lineage", ()) or ()))),
        verifier=_text(getattr(attempt, "verifier", "")), **stated)


class ProvenanceIndex:
    """Every evidence record's provenance with what it relied on folded in."""

    def __init__(self, records: Iterable[Any], policy: IndependencePolicy) -> None:
        self.policy = policy
        held = [r for r in records if getattr(r, "evidence_id", None)]
        by_id = {r.evidence_id: r for r in held}
        declared: Dict[str, str] = {}
        for record in held:
            content = getattr(record, "content", None) or {}
            claimed = content.get("producer_claimed_evidence_id") if isinstance(
                content, Mapping) else None
            if claimed:
                declared.setdefault(str(claimed), record.evidence_id)
        own: Dict[str, SourceProvenance] = {}
        parents: Dict[str, List[str]] = {}
        for record in held:
            provenance, relied_on = record_provenance(record)
            own[record.evidence_id] = provenance
            ups = [p for p in getattr(record, "parent_evidence", ()) if p in by_id]
            ups += [declared[r] for r in relied_on if r in declared]
            ups += [r for r in relied_on if r in by_id]
            parents[record.evidence_id] = sorted(set(ups) - {record.evidence_id})
            # A relied-on value that is not a record (an artifact digest) is a
            # generated input, and shared generated inputs correlate.
            extra = tuple(r for r in relied_on if r not in by_id and r not in declared)
            if extra:
                own[record.evidence_id] = _with(provenance, generated_from=tuple(
                    sorted(set(provenance.generated_from) | set(extra))))
        self._own = own
        self._parents = parents
        self._declared = declared
        self._closed: Dict[str, Tuple[str, ...]] = {}

    def resolve(self, reference: str) -> Optional[str]:
        """The record a reference names: its own id, or the id its envelope declared."""
        if reference in self._own:
            return reference
        return self._declared.get(reference)

    def attempt_source(self, attempt: Any) -> SourceProvenance:
        """An attempt's provenance with what it relied on folded in.

        A check that cites a record, or says it relied on one, carries that
        record's keys and its ancestors': a person's review of an AI-written
        summary is in the summary's group. A relied-on value that is no record is
        a generated input, as for evidence.
        """
        own = attempt_provenance(attempt)
        inherited: Set[str] = set(own.inherited)
        inputs: Set[str] = set()
        for reference in attempt_relied_on(attempt):
            record_id = self.resolve(reference)
            if record_id is None:
                inputs.add(reference)
                continue
            ancestor = self.of(record_id)
            if ancestor is not None:
                inherited |= ancestor.keys(self.policy)
                inherited.add(f"{ProvenanceDimension.ANCESTRY.value}:{record_id}")
        return _with(own, inherited=tuple(sorted(inherited)),
                     generated_from=tuple(sorted(set(own.generated_from) | inputs)))

    def _ancestor_keys(self, evidence_id: str) -> Tuple[str, ...]:
        """Keys of every ancestor, iteratively, cycle-safe."""
        if evidence_id in self._closed:
            return self._closed[evidence_id]
        seen: Set[str] = set()
        stack = list(self._parents.get(evidence_id, ()))
        keys: Set[str] = set()
        while stack:
            node = stack.pop()
            if node in seen or node == evidence_id:
                continue
            seen.add(node)
            ancestor = self._own.get(node)
            if ancestor is not None:
                keys |= ancestor.own_keys(self.policy)
                keys.add(f"{ProvenanceDimension.ANCESTRY.value}:{node}")
            stack.extend(self._parents.get(node, ()))
        result = tuple(sorted(keys))
        self._closed[evidence_id] = result
        return result

    def of(self, evidence_id: str) -> Optional[SourceProvenance]:
        base = self._own.get(evidence_id)
        if base is None:
            return None
        return _with(base, inherited=self._ancestor_keys(evidence_id))


def _with(provenance: SourceProvenance, **changes: Any) -> SourceProvenance:
    data = {f: getattr(provenance, f) for f in provenance.__dataclass_fields__}
    data.update(changes)
    return SourceProvenance(**data)


# ── groups ───────────────────────────────────────────────────────────────────

class IndependenceStatus(str, Enum):
    INDEPENDENT = "INDEPENDENT"                    # two or more groups established
    CORRELATED = "CORRELATED"                      # every source is one group
    SINGLE_SOURCE = "SINGLE_SOURCE"                # there is one source
    INDEPENDENCE_UNKNOWN = "INDEPENDENCE_UNKNOWN"  # sources that cannot be placed
    NO_SOURCES = "NO_SOURCES"


@dataclass(frozen=True)
class CorrelationGroup:
    group_id: str
    members: Tuple[str, ...]
    shared: Tuple[str, ...] = ()       # keys more than one member carries
    determinable: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {"group_id": self.group_id, "members": list(self.members),
                "size": len(self.members), "shared": list(self.shared),
                "determinable": self.determinable}


@dataclass(frozen=True)
class IndependenceAssessment:
    """How many groups a set of sources forms. Never a score."""

    status: IndependenceStatus
    sources: int = 0
    groups: Tuple[CorrelationGroup, ...] = ()
    undetermined: Tuple[str, ...] = ()
    policy_ref: str = ""
    basis: str = ""

    @property
    def independent_groups(self) -> int:
        """Groups whose separation the stated provenance establishes."""
        return sum(1 for g in self.groups if g.determinable)

    def to_dict(self) -> Dict[str, Any]:
        return {"status": self.status.value, "sources": self.sources,
                "independent_groups": self.independent_groups,
                "groups": [g.to_dict() for g in self.groups],
                "undetermined": list(self.undetermined),
                "policy": self.policy_ref, "basis": self.basis}


def assess_independence(sources: Sequence[SourceProvenance],
                        policy: IndependencePolicy = DEFAULT_INDEPENDENCE_POLICY
                        ) -> IndependenceAssessment:
    """Group sources by shared provenance under `policy`."""
    if not sources:
        return IndependenceAssessment(IndependenceStatus.NO_SOURCES, policy_ref=policy.ref,
                                      basis="nothing supports this, so there is nothing "
                                            "whose independence could be assessed")
    parent: Dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[max(ra, rb)] = min(ra, rb)

    keys: Dict[str, Set[str]] = {}
    for source in sources:
        node = f"source::{source.source_id}"
        find(node)
        keys[source.source_id] = source.keys(policy)
        for key in keys[source.source_id]:
            union(node, f"key::{key}")

    members: Dict[str, List[SourceProvenance]] = {}
    for source in sources:
        members.setdefault(find(f"source::{source.source_id}"), []).append(source)

    groups: List[CorrelationGroup] = []
    undetermined: List[str] = []
    for root in sorted(members):
        group = members[root]
        determinable = any(s.determinable(policy) for s in group)
        counts: Dict[str, int] = {}
        for s in group:
            for k in keys[s.source_id]:
                counts[k] = counts.get(k, 0) + 1
        shared = tuple(sorted(k for k, n in counts.items() if n > 1))
        ids = tuple(sorted(s.source_id for s in group))
        groups.append(CorrelationGroup(group_id=f"cg_{digest_object(list(ids))[7:19]}",
                                       members=ids, shared=shared,
                                       determinable=determinable))
        if not determinable:
            undetermined.extend(ids)
    groups.sort(key=lambda g: (-len(g.members), g.group_id))

    known = [g for g in groups if g.determinable]
    if len(sources) == 1:
        status, basis = IndependenceStatus.SINGLE_SOURCE, "one source"
    elif len(known) >= 2:
        status = IndependenceStatus.INDEPENDENT
        basis = (f"{len(known)} group(s) share no {', '.join(d.value for d in policy.correlate_on)}"
                 + (f"; {len(undetermined)} source(s) state too little to place"
                    if undetermined else ""))
    elif len(known) == 1 and not undetermined:
        status = IndependenceStatus.CORRELATED
        basis = (f"all {len(sources)} sources are one group: "
                 + ", ".join(known[0].shared[:4]) if known[0].shared
                 else f"all {len(sources)} sources are one group")
    else:
        status = IndependenceStatus.INDEPENDENCE_UNKNOWN
        basis = (f"{len(undetermined)} of {len(sources)} source(s) state nothing about "
                 "what generated them (no model family, reviewer, toolchain, session, "
                 "agent or lineage), so whether they are independent cannot be told")
    return IndependenceAssessment(status=status, sources=len(sources), groups=tuple(groups),
                                  undetermined=tuple(sorted(undetermined)),
                                  policy_ref=policy.ref, basis=basis)


def attempt_keys(attempt: Any, policy: IndependencePolicy = DEFAULT_INDEPENDENCE_POLICY,
                 index: Optional["ProvenanceIndex"] = None) -> Tuple[Set[str], bool]:
    """An attempt's correlation keys, and whether its provenance places it.

    With the case's `index`, what the attempt relied on is folded in; without
    one, a cited record still correlates two attempts that cite it, by its id.
    """
    if index is not None:
        provenance = index.attempt_source(attempt)
        policy = index.policy
    else:
        provenance = attempt_provenance(attempt)
        relied = attempt_relied_on(attempt)
        if relied:
            provenance = _with(provenance, generated_from=tuple(
                sorted(set(provenance.generated_from) | set(relied))))
    return provenance.keys(policy), provenance.determinable(policy)

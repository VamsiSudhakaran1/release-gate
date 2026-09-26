"""Reuse that cannot change an answer.

A case that has ingested ten million events must not re-ingest them to answer
one more question about them. That is the whole of what this module is for, and
it is a narrower job than it sounds, because assurance has a property that most
caching problems do not: **the cheap answer and the expensive answer must be the
same answer.** A stale verdict is not a slow verdict that arrived early. It is a
wrong one, and it is wrong in the most dangerous direction — a reused "nothing
blocks this" that predates the contradiction which does.

So reuse here is not an optimisation layered over the engine. It is a claim, of
exactly the same kind as every other claim in this system, and it carries the
same burden: say what it rests on, and be checkable.

## Three ideas, in the order they matter

**1. Reuse is keyed on content, never on a flag.** A dirty bit records that
somebody remembered to set it. A content digest over the inputs a stage actually
read cannot be wrong about whether those inputs changed, because if they changed
the key changed. `AssuranceSession.records` is a public mutable list — anybody
can append to it without going through `add()` — and that is precisely the case a
mutation counter gets wrong and a content key gets right.

**2. Not every stage may be reused, and the ones that may not are almost all of
them.** A fold over records is `APPEND_STABLE`: record ten million and one lands on
top and nothing beneath it moves. An *analysis* is `RETRACTABLE`: one arriving
record can withdraw a conclusion that held over every record before it. A
contradiction shows up and "no contradictions" was not slightly stale, it was
false. Reusing a retractable stage is the omission inversion in its purest form —
losing information to produce a cleaner verdict — so retractable stages are
recomputed, always, and the measured cost of doing so is the price of the
guarantee.

`STAGES` below records which is which, and it is worth reading for the surprise:
of eleven stages, one is append-stable. Ingest is not, for a reason that only
showed up on being checked rather than reasoned about.

A stage nobody has classified is `UNKNOWN`, and `UNKNOWN` recomputes. Unknown is
not a permissive default anywhere else in this architecture and it is not one
here (Invariant 3).

**3. A reuse claim is verified, not asserted.** `verify_reuse` runs both paths and
compares. That is the same standard `chaos.Recovery.IDENTICAL` sets for a fault:
not "recovered gracefully" but "produced the same bytes". Every reuse this module
permits is under a test of that shape, because an under-declared input is
invisible by definition — the whole failure mode is a stage reading something it
did not admit to reading, and no amount of reading the code proves it does not.

## No clock in here

Nothing in this module reads the time. Deliberately: a reuse decision that
depended on a clock would make the authoritative path nondeterministic, which is
the one thing it may never be (Invariant 4). Latency *measurement* lives in
`latency.py` and imports from here, never the other way round.

## Where this differs from compaction, and why

`compaction` selects by content digest so that retention is deterministic, because
what it retains decides what a reviewer can drill into — a nondeterministic
choice there means two runs agree on what existed and disagree about what can be
inspected. A reuse cache is the opposite: it must be **invisible in the result**.
Whether an entry was evicted may change how long an answer took and may never
change what the answer is, so eviction order needs no determinism at all.
`eviction_can_change_a_result` is unconditionally `False`, and if it ever were
`True` that is not a tuning problem, it is the defect `verify_reuse` exists to
catch.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from release_gate.assurance.canonical import digest_object, short_id

INCREMENTAL_SCHEMA_VERSION = 1


class IncrementalError(ValueError):
    """A reuse that would not be sound, or a claim about one that is malformed."""


# ── what adding a record can do to a result ──────────────────────────────────

class Stability(str, Enum):
    """Whether appending a record can change what a stage already produced.

    The axis that decides everything else. It is a property of the *computation*,
    not of the records, and it is not a performance judgement: a stage can be
    cheap and retractable, or expensive and append-stable.
    """

    APPEND_STABLE = "APPEND_STABLE"  # a later record adds; it never rewrites
    RETRACTABLE = "RETRACTABLE"      # a later record can withdraw a conclusion
    UNKNOWN = "UNKNOWN"              # nobody has established which

    @property
    def reusable_on_append(self) -> bool:
        """Only APPEND_STABLE. UNKNOWN is not treated as the convenient case."""
        return self is Stability.APPEND_STABLE

    def describe(self) -> str:
        return _STABILITY_NOTE[self]


_STABILITY_NOTE: Mapping[Stability, str] = {
    Stability.APPEND_STABLE: (
        "appending a record extends the result and leaves every earlier part of "
        "it unchanged, so a result over the first n records is a prefix of the "
        "result over n+1"),
    Stability.RETRACTABLE: (
        "appending a record can withdraw a conclusion that held over all the "
        "records before it, so a result over the first n records may be wrong "
        "about n+1 rather than merely incomplete"),
    Stability.UNKNOWN: (
        "nobody has established what appending a record does to this stage, so "
        "it is recomputed; an unestablished property is not a permissive one"),
}


# ── the stages, and what each one may claim ──────────────────────────────────

@dataclass(frozen=True)
class StageSpec:
    """One stage of the finalization path, and whether its result may be reused.

    `why` is required for an APPEND_STABLE claim and refused for a RETRACTABLE
    one. A stage saying "you may reuse me" has to say what makes that true, in
    the same way a `chaos.Fault` claiming a non-identical recovery has to say why
    identity was not available. A stage saying "recompute me" needs no argument:
    recomputation is the position that costs nothing but time.
    """

    name: str
    stability: Stability
    reads: Tuple[str, ...]
    why: str = ""

    def __post_init__(self) -> None:
        if not self.name:
            raise IncrementalError("a stage needs a name")
        if not self.reads:
            raise IncrementalError(
                f"{self.name}: a stage must declare what it reads, because a reuse "
                "key covers exactly the declared inputs and an undeclared one is "
                "how a stale result survives a change that should have invalidated it")
        if self.stability is Stability.APPEND_STABLE and not self.why:
            raise IncrementalError(
                f"{self.name}: an APPEND_STABLE claim must say what makes appending "
                "safe. This is the claim that permits reuse, so it carries the "
                "burden; RETRACTABLE needs no argument because it permits nothing")

    @property
    def reusable_on_append(self) -> bool:
        return self.stability.reusable_on_append

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "incremental_stage", "record_id": self.name,
                "name": self.name, "stability": self.stability.value,
                "reads": list(self.reads), "why": self.why,
                "reusable_on_append": self.reusable_on_append,
                "schema_version": INCREMENTAL_SCHEMA_VERSION}


#: Every stage of a finalization, classified once. One list, so the registry
#: below cannot disagree with itself about which stages exist.
#:
#: The shape of this table is the finding, and it is not the shape it was first
#: written as: **exactly one stage is append-stable.** `detect` and `normalise`
#: were classified APPEND_STABLE on the reasoning that a record maps to its typed
#: form independently of the others and a later record can add a document type but
#: never remove one. Both halves are wrong, and checking `detect_document` instead
#: of reasoning about it is what showed it: detection scores candidates as a
#: *proportion* of sampled lines, so appending 200 unrecognised records to a
#: document that detected as ASSURANCE_ENVELOPE at 83% confidence drops it to
#: UNRECOGNISED at 2%. `normalise` takes that detection as an input, so its output
#: over n+1 records is not an extension of its output over n — the whole mapping
#: can change underneath.
#:
#: The consequence is worth stating plainly because it points the remaining work
#: somewhere other than where it looked. A resumable ingest is not plumbing: it
#: needs detection settled at a boundary and held, which is a decision about
#: whether a case's input kind may change while records are still arriving — a
#: semantic question, not an optimisation. Until that is answered, the reuse that
#: is actually available is the whole finalization keyed on its record set (sound
#: because it is the entire pure function) and the fold shared within one
#: finalization (sound because a multiset commitment is order-free). Both are
#: built; neither needed a stage of ingest to be resumable.
STAGES: Tuple[StageSpec, ...] = (
    StageSpec(
        name="detect", stability=Stability.RETRACTABLE, reads=("records",)),
    StageSpec(
        name="normalise", stability=Stability.RETRACTABLE, reads=("records",)),
    StageSpec(
        name="fold", stability=Stability.APPEND_STABLE, reads=("records",),
        why="the commitment is a multiset digest, order-free by construction and "
            "O(1) to extend, so a fold over a prefix plus the remainder is the "
            "same digest as a fold over everything. This is the only claim in the "
            "table that survived being checked against the code it describes"),
    StageSpec(
        name="subject", stability=Stability.RETRACTABLE,
        reads=("records", "source")),
    StageSpec(
        name="consequence", stability=Stability.RETRACTABLE,
        reads=("records", "capabilities")),
    StageSpec(
        name="analyse", stability=Stability.RETRACTABLE,
        reads=("case", "normalisation")),
    StageSpec(
        name="assess", stability=Stability.RETRACTABLE,
        reads=("case", "methodology")),
    StageSpec(
        name="attention", stability=Stability.RETRACTABLE,
        reads=("case", "analysis", "assessment")),
    StageSpec(
        name="decide", stability=Stability.RETRACTABLE,
        reads=("analysis", "assessment", "methodology", "consequence")),
    StageSpec(
        name="seal", stability=Stability.RETRACTABLE,
        reads=("case", "verdict")),
    StageSpec(
        name="finalization", stability=Stability.RETRACTABLE,
        reads=("records", "methodology", "objective", "requested_decision",
               "requested_action", "source")),
)

#: name → spec. Built from `STAGES` rather than written out again.
SPECS: Mapping[str, StageSpec] = {spec.name: spec for spec in STAGES}


def spec_for(name: str) -> StageSpec:
    """The classification for a stage, or an UNKNOWN one if it has none.

    An unregistered stage is not an error — code may be instrumented before it is
    classified — but it is `UNKNOWN`, which recomputes. The alternative, raising,
    would push callers toward not asking.
    """
    found = SPECS.get(name)
    if found is not None:
        return found
    return StageSpec(name=name or "unnamed", stability=Stability.UNKNOWN,
                     reads=("unknown",))


# ── what changed between two record sets ─────────────────────────────────────

class Change(str, Enum):
    """How a record set moved. Only NONE and APPENDED permit any reuse."""

    NONE = "NONE"            # the same records
    APPENDED = "APPENDED"    # the previous set is a prefix of this one
    REWRITTEN = "REWRITTEN"  # something changed, moved or went away


@dataclass(frozen=True)
class Delta:
    """The difference between the record set a result was computed over and this one.

    Keyed on per-record digests rather than counts. A set that lost one record and
    gained another has the same length as before, and calling that "unchanged"
    would reuse a result computed over evidence that is no longer there.
    """

    change: Change
    previous: int
    current: int
    appended: int = 0
    diverged_at: Optional[int] = None

    @property
    def append_only(self) -> bool:
        return self.change in (Change.NONE, Change.APPENDED)

    @property
    def unchanged(self) -> bool:
        return self.change is Change.NONE

    def describe(self) -> str:
        if self.change is Change.NONE:
            return f"the same {self.previous} record(s)"
        if self.change is Change.APPENDED:
            return f"{self.appended} record(s) appended to the previous {self.previous}"
        if self.diverged_at is not None:
            return (f"the record set was rewritten at position {self.diverged_at} "
                    f"({self.previous} -> {self.current} records)")
        return f"the record set was rewritten ({self.previous} -> {self.current} records)"

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "incremental_delta",
                "record_id": short_id("delta", digest_object(
                    {"c": self.change.value, "p": self.previous,
                     "n": self.current, "a": self.appended})),
                "change": self.change.value, "previous": self.previous,
                "current": self.current, "appended": self.appended,
                "diverged_at": self.diverged_at, "append_only": self.append_only,
                "schema_version": INCREMENTAL_SCHEMA_VERSION}


def plan(previous: Sequence[str], current: Sequence[str]) -> Delta:
    """Classify the move from one record set to another, by per-record digest.

    A removal, a reorder or an in-place edit is REWRITTEN even when it leaves the
    count alone, because every one of those can retract something an
    append-stable stage had already folded in.
    """
    prev = list(previous)
    cur = list(current)
    if len(cur) < len(prev):
        return Delta(change=Change.REWRITTEN, previous=len(prev), current=len(cur),
                     diverged_at=len(cur))
    for index, key in enumerate(prev):
        if cur[index] != key:
            return Delta(change=Change.REWRITTEN, previous=len(prev),
                         current=len(cur), diverged_at=index)
    if len(cur) == len(prev):
        return Delta(change=Change.NONE, previous=len(prev), current=len(cur))
    return Delta(change=Change.APPENDED, previous=len(prev), current=len(cur),
                 appended=len(cur) - len(prev))


# ── keys ─────────────────────────────────────────────────────────────────────

def reuse_key(stage: str, inputs: Mapping[str, Any]) -> str:
    """A content-addressed key over exactly the inputs a stage declared.

    The stage name is inside the key so two stages over the same inputs cannot
    collide. An input the spec does not declare is refused rather than silently
    folded in: a key that covers more than the spec says it covers is harmless,
    but one that covers *less* is how a stale result survives, and the only way to
    keep the spec and the key honest about each other is to make them agree here.
    """
    spec = spec_for(stage)
    undeclared = sorted(set(inputs) - set(spec.reads))
    if undeclared:
        raise IncrementalError(
            f"{stage}: {', '.join(undeclared)} passed to the key but not declared in "
            f"reads={list(spec.reads)}. Either the stage reads it — declare it — or "
            "it does not, and keying on it hides that the spec is wrong")
    missing = sorted(set(spec.reads) - set(inputs))
    if missing:
        raise IncrementalError(
            f"{stage}: declared input(s) {', '.join(missing)} absent from the key. A "
            "key that omits a declared input cannot detect that input changing")
    return digest_object({"stage": stage, "inputs": dict(inputs)})


# ── a decision to reuse, or not ──────────────────────────────────────────────

class ReuseDecision(str, Enum):
    """What happened to a stage on this run.

    REFUSED is separate from RECOMPUTED on purpose. Both did the work; only
    REFUSED means reuse was *available and declined*, which is the case an
    operator wondering why nothing is being reused needs to be able to see.
    """

    REUSED = "REUSED"            # the cached result was returned
    RECOMPUTED = "RECOMPUTED"    # no cached result to use
    REFUSED = "REFUSED"          # a cached result existed and was not sound to use

    @property
    def did_work(self) -> bool:
        return self is not ReuseDecision.REUSED


@dataclass(frozen=True)
class Reuse:
    """One reuse decision, with the reason it went that way.

    `why` is mandatory. A cache whose behaviour can only be explained by reading
    its implementation is a cache nobody will trust at the point it matters.
    """

    stage: str
    decision: ReuseDecision
    key: str
    why: str

    def __post_init__(self) -> None:
        if not self.why:
            raise IncrementalError(
                f"{self.stage}: a reuse decision must say why, so that 'nothing is "
                "being reused' is diagnosable without reading the cache")

    @property
    def stability(self) -> Stability:
        return spec_for(self.stage).stability

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "incremental_reuse", "record_id": f"{self.stage}:{self.key[:24]}",
                "stage": self.stage, "decision": self.decision.value,
                "key": self.key, "why": self.why,
                "stability": self.stability.value,
                "schema_version": INCREMENTAL_SCHEMA_VERSION}


# ── the cache ────────────────────────────────────────────────────────────────

class IncrementalCache:
    """Results held by content key, bounded, and unable to change an answer.

    Least-recently-used eviction, which is access-order dependent and therefore
    not deterministic across runs — and that is fine here in a way it would not be
    in `compaction`. What compaction retains is *visible in the case*: it decides
    what a reviewer can drill into, so two runs that retained different sets
    disagree about the evidence. What this holds is visible nowhere: an evicted
    entry costs a recomputation and yields the identical result, which is the
    property `verify_reuse` checks rather than assumes.
    """

    def __init__(self, *, limit: int = 32) -> None:
        if limit < 1:
            raise IncrementalError("a cache must be allowed to hold at least one entry")
        self.limit = limit
        self._entries: "OrderedDict[str, Any]" = OrderedDict()
        self.hits = 0
        self.misses = 0
        self.evictions = 0

    @property
    def eviction_can_change_a_result(self) -> bool:
        """Unconditionally False, and load-bearing.

        Every entry is keyed by a digest over the inputs that produced it, so a
        miss recomputes the same value an eviction discarded. If this were ever
        true the cache would be part of the authoritative path, which is exactly
        what Invariant 4 forbids.
        """
        return False

    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, key: str) -> bool:
        return key in self._entries

    def get(self, key: str) -> Optional[Any]:
        if key in self._entries:
            self._entries.move_to_end(key)
            self.hits += 1
            return self._entries[key]
        self.misses += 1
        return None

    def put(self, key: str, value: Any) -> None:
        self._entries[key] = value
        self._entries.move_to_end(key)
        while len(self._entries) > self.limit:
            self._entries.popitem(last=False)
            self.evictions += 1

    def clear(self) -> None:
        self._entries.clear()

    def summary(self) -> Dict[str, Any]:
        looked = self.hits + self.misses
        return {"held": len(self._entries), "limit": self.limit,
                "hits": self.hits, "misses": self.misses,
                "evictions": self.evictions,
                "hit_rate": (self.hits / looked) if looked else None}


# ── proving a reuse did not change the answer ────────────────────────────────

def result_digest(value: Any) -> str:
    """A digest over whatever a stage produced, for comparison only.

    Not an identity and not stored anywhere: `case_digest` is the identity of a
    case and this is a comparison of two computations that should have produced
    it. Reads the case's own binding state where there is one, so an equivalence
    check compares what an approval would bind to rather than an incidental
    serialisation that might agree while the binding state does not.
    """
    for attr in ("binding_state", "identity", "to_dict", "summary"):
        method = getattr(value, attr, None)
        if callable(method):
            try:
                return digest_object(method())
            except Exception:  # pragma: no cover - fall through to the next view
                continue
    case = getattr(value, "case", None)
    if case is not None and hasattr(case, "binding_state"):
        return digest_object(case.binding_state())
    return digest_object({"repr": repr(value)})


@dataclass(frozen=True)
class Equivalence:
    """Whether a reused result and a recomputed one are the same result.

    The standard is `chaos.Recovery.IDENTICAL`: not "close enough", not "the same
    verdict" — the same bytes. A reuse that agreed on PROMOTE/HOLD and disagreed
    on what the case committed to would pass a laxer check and still have broken
    the thing an approval binds to.
    """

    stage: str
    full: str
    incremental: str
    differences: Tuple[str, ...] = ()

    @property
    def identical(self) -> bool:
        return self.full == self.incremental and not self.differences

    def render(self) -> str:
        if self.identical:
            return f"{self.stage}: reuse is equivalent ({self.full[:24]}…)"
        lines = [f"{self.stage}: REUSE CHANGED THE RESULT",
                 f"  from scratch:  {self.full}",
                 f"  incremental:   {self.incremental}"]
        lines.extend(f"  - {d}" for d in self.differences)
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "incremental_equivalence",
                "record_id": f"{self.stage}:{self.full[:24]}",
                "stage": self.stage, "identical": self.identical,
                "full": self.full, "incremental": self.incremental,
                "differences": list(self.differences),
                "schema_version": INCREMENTAL_SCHEMA_VERSION}


def verify_reuse(stage: str, from_scratch: Callable[[], Any],
                 incrementally: Callable[[], Any]) -> Equivalence:
    """Run both paths and compare. The gate every reuse claim in this package passes.

    Necessary rather than belt-and-braces: the failure mode of a reuse key is a
    stage reading an input it did not declare, and that is invisible to inspection
    by definition — the code that reads it looks exactly like code that does not.
    Only running both and comparing catches it.
    """
    full = from_scratch()
    partial = incrementally()
    differences: List[str] = []
    for attr in ("case_digest", "decision"):
        left, right = _reach(full, attr), _reach(partial, attr)
        if left is not None and left != right:
            differences.append(f"{attr}: {left!r} from scratch, {right!r} incrementally")
    return Equivalence(stage=stage, full=result_digest(full),
                       incremental=result_digest(partial),
                       differences=tuple(differences))


def _reach(value: Any, attr: str) -> Any:
    """`value.attr`, or `value.case.attr`, whichever exists. Outcomes wrap cases."""
    found = getattr(value, attr, None)
    if found is None:
        found = getattr(getattr(value, "case", None), attr, None)
    return getattr(found, "value", found)


# ── the report ───────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class IncrementalReport:
    """What was reused on one finalization, and what was not.

    Deliberately not a score. "Reused six of eleven stages" describes this run
    over these records and says nothing about whether the engine is well tuned:
    a first finalization reuses nothing and is not thereby worse.
    """

    decisions: Tuple[Reuse, ...] = ()
    delta: Optional[Delta] = None
    cache: Mapping[str, Any] = field(default_factory=dict)

    @property
    def reused(self) -> Tuple[Reuse, ...]:
        return tuple(d for d in self.decisions if d.decision is ReuseDecision.REUSED)

    @property
    def refused(self) -> Tuple[Reuse, ...]:
        return tuple(d for d in self.decisions if d.decision is ReuseDecision.REFUSED)

    @property
    def is_a_performance_rating(self) -> bool:
        """Unconditionally False. A run that reused nothing may be the first one."""
        return False

    def render(self) -> str:
        lines = ["REUSE"]
        if self.delta is not None:
            lines.append(f"  input: {self.delta.describe()}")
        for decision in self.decisions:
            lines.append(f"  {decision.decision.value:11s} {decision.stage:14s} {decision.why}")
        if not self.decisions:
            lines.append("  nothing was offered for reuse on this run")
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "incremental_report",
                "record_id": short_id("reuse", digest_object(
                    [d.to_dict() for d in self.decisions])),
                "decisions": [d.to_dict() for d in self.decisions],
                "delta": self.delta.to_dict() if self.delta else None,
                "cache": dict(self.cache),
                "schema_version": INCREMENTAL_SCHEMA_VERSION}


__all__ = [
    "INCREMENTAL_SCHEMA_VERSION",
    "Change",
    "Delta",
    "Equivalence",
    "IncrementalCache",
    "IncrementalError",
    "IncrementalReport",
    "Reuse",
    "ReuseDecision",
    "SPECS",
    "STAGES",
    "Stability",
    "StageSpec",
    "plan",
    "result_digest",
    "reuse_key",
    "spec_for",
    "verify_reuse",
]

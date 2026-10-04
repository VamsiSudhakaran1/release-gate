"""Claim coverage — what portion of the required claim surface was actually assessed.

"Eight tools passed" answers a question nobody asked. The question an admission
decision turns on is narrower and harder: *of what this claim says, how much did
anything actually look at?* A claim that all irreversible tools require approval
is a claim about refund, delete, transfer and email. Three passing checks on
refund are three checks on refund.

    Claim: All irreversible tools require approval.

    tool    refund     ASSESSED_SUPPORTED
            delete     ASSESSED_SUPPORTED
            transfer   NOT_ASSESSED
            email      ASSESSED_FAILED

    3 of 4 assessed · 1 not assessed · 1 assessed failure
    missing: tool transfer

The conclusion is not "75% safe". It is that one element failed, one was never
looked at, and the claim does not hold as stated. This module computes that
picture and nothing that would blur it: there is no percentage of safety, no
weighted score, and no way for an element nobody assessed to read as passed.

**The surface is declared by the claim.** A claim states what it is about, along
named dimensions:

    {"record_type": "claim", "claim_id": "c-approval", ...,
     "surface": {"tool": ["refund", "delete", "transfer", "email"],
                 "environment": {"required": ["production"],
                                 "not_applicable": {"staging": "no money moves"}}}}

The dimensions are the ones assurance actually varies along — static and runtime
paths, tools and actions, environments, datasets, model versions, authorization
levels, failure modes, adversarial classes, regulatory and control obligations —
and any other identifier a domain needs. Not-applicable elements are declared
with a reason, and the claim's producer is answerable for each.

**Evidence says what it covers, or it covers nothing.** A record or check states
the elements it bears on (`"covers": {"tool": "refund"}`); environment and
dataset are also read from the state it declares it ran against. Evidence that
names no element of the claim's surface is *unattributed*: it is reported, and it
fills no element. That is the line between coverage and a tool count — a passing
suite that does not say which tools it exercised has not shown that any of them
were.

**Six statuses per element, kept apart.**

* `ASSESSED_SUPPORTED` — evidence the resolution counts covers it and passed.
* `ASSESSED_FAILED` — evidence against the claim covers it: a contradicting
  record, a failed check. A pass elsewhere does not cancel it; a pass on the same
  element does not cancel it either.
* `NOT_ASSESSED` — nothing the resolution counts covers it. Evidence about another
  state of the release, or evidence the claim does not admit, is named in the
  element's note and does not make it assessed.
* `INACCESSIBLE` — a producer reported that it tried and could not reach it
  (`"inaccessible": {"tool": ["transfer"]}`). Not assessed, and said so by
  someone who looked.
* `NOT_APPLICABLE` — the claim declares it out of scope, with a reason. A failure
  observed on it still reads `ASSESSED_FAILED`: a declaration does not make a
  failure disappear.
* `UNKNOWN` — something covered it and settled nothing (an inconclusive check).

The precedence is fixed: failed, supported, unknown, inaccessible, not assessed.

**Coverage is per dimension, not per combination.** A check of refund in staging
and a check of transfer in production cover both tools and both environments;
they do not cover refund in production. The report says so rather than implying
the product was walked.

**Policy decides what a shortfall does** (`ResolutionPolicy.surface_coverage`,
`surface_shortfall`, `require_surface`). By default every dimension of a required
claim's declared surface must be fully assessed, and a shortfall holds the case
(RG-COV-006). An assessed failure is already a refutation the claim resolution
blocks on; coverage names where it is and does not count it twice.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, Iterable, List, Mapping, Optional, Tuple

from release_gate.assurance.canonical import digest_object

__all__ = [
    "CLAIM_COVERAGE_SCHEMA_VERSION",
    "DIMENSION_FAMILY",
    "ClaimCoverage",
    "ClaimCoverageReport",
    "ClaimSurface",
    "ClaimSurfaceError",
    "ConditionFamily",
    "DimensionCoverage",
    "ElementCoverage",
    "SurfaceStatus",
    "assess_claim_coverage",
    "canonical_dimension",
    "conditions_of",
    "declared_field",
    "family_of_dimension",
    "inaccessible_of",
]

CLAIM_COVERAGE_SCHEMA_VERSION = 1


class ClaimSurfaceError(ValueError):
    """A claim surface was declared in a way that could not be read."""


class ConditionFamily(str, Enum):
    """What kind of difference a dimension is, when two pieces of evidence differ on it."""

    STATE = "STATE"              # what release it ran against: another version
    SCOPE = "SCOPE"              # what part of the system: another subject
    POPULATION = "POPULATION"    # which data: another population
    ENVIRONMENT = "ENVIRONMENT"  # where: another environment


_SC, _POP, _ENV = ConditionFamily.SCOPE, ConditionFamily.POPULATION, ConditionFamily.ENVIRONMENT

#: The dimensions named in advance. Any other identifier is accepted as a SCOPE
#: dimension of the domain's own: the vocabulary is open, the meaning is not.
DIMENSION_FAMILY: Mapping[str, ConditionFamily] = {
    "static_path": _SC, "runtime_path": _SC, "tool": _SC,
    "environment": _ENV, "dataset": _POP, "model_version": _SC,
    "authorization_level": _SC, "failure_mode": _SC, "adversarial_class": _SC,
    "obligation": _SC,
}

_ALIASES: Mapping[str, str] = {
    "static_paths": "static_path", "code_path": "static_path", "code_paths": "static_path",
    "runtime_paths": "runtime_path", "execution_path": "runtime_path",
    "tools": "tool", "action": "tool", "actions": "tool",
    "environments": "environment", "env": "environment",
    "datasets": "dataset", "population": "dataset", "populations": "dataset",
    "model_versions": "model_version", "model": "model_version", "models": "model_version",
    "authorization_levels": "authorization_level", "role": "authorization_level",
    "roles": "authorization_level", "privilege": "authorization_level",
    "privileges": "authorization_level",
    "failure_modes": "failure_mode",
    "adversarial_classes": "adversarial_class", "attack_class": "adversarial_class",
    "attack_classes": "adversarial_class",
    "obligations": "obligation", "control": "obligation", "controls": "obligation",
    "regulatory_obligation": "obligation", "regulatory_obligations": "obligation",
}

#: Values compared exactly, because a path's case is part of the path.
_CASE_SENSITIVE = frozenset({"static_path", "runtime_path"})
_IDENTIFIER = re.compile(r"\A[a-z][a-z0-9_]*\Z")


def canonical_dimension(name: Any) -> Optional[str]:
    """The canonical spelling of a dimension, or None if it is not an identifier."""
    text = re.sub(r"[\s\-]+", "_", str(name or "").strip().lower())
    text = _ALIASES.get(text, text)
    return text if _IDENTIFIER.match(text) else None


def family_of_dimension(dimension: str) -> ConditionFamily:
    return DIMENSION_FAMILY.get(dimension, ConditionFamily.SCOPE)


def _values(dimension: str, raw: Any) -> FrozenSet[str]:
    items = raw if isinstance(raw, (list, tuple, set, frozenset)) else [raw]
    found = set()
    for item in items:
        if item is None or isinstance(item, (Mapping, list, tuple, set)):
            continue
        text = str(item).strip()
        if text:
            found.add(text if dimension in _CASE_SENSITIVE else text.casefold())
    return frozenset(found)


def declared_field(holder: Any, key: str) -> Any:
    """A field a producer declared on a record or a check, wherever it sits.

    On a record it is in `content` — or one level down, when a serialised record
    was read back as an envelope row. On a verification attempt it is in `result`.
    """
    for name in ("content", "result"):
        body = getattr(holder, name, None)
        if not isinstance(body, Mapping):
            continue
        if body.get(key) is not None:
            return body.get(key)
        inner = body.get("content")
        if isinstance(inner, Mapping) and inner.get(key) is not None:
            return inner.get(key)
    return None


def _dimension_map(raw: Any) -> Dict[str, FrozenSet[str]]:
    found: Dict[str, FrozenSet[str]] = {}
    if not isinstance(raw, Mapping):
        return found
    for key, value in raw.items():
        dimension = canonical_dimension(key)
        if dimension is None:
            continue
        values = _values(dimension, value)
        if values:
            found[dimension] = found.get(dimension, frozenset()) | values
    return found


def conditions_of(holder: Any) -> Dict[str, FrozenSet[str]]:
    """What a record or check says it bears on: dimension → elements.

    From `covers`, plus the environment and dataset of the state it declares it
    ran against — those are where and on what data, whichever field said so.
    Nothing is inferred: a record that declares neither covers nothing.
    """
    found = _dimension_map(declared_field(holder, "covers"))
    state = declared_field(holder, "state")
    if isinstance(state, Mapping):
        for key in ("environment", "dataset"):
            values = _values(key, state.get(key))
            if values:
                found[key] = found.get(key, frozenset()) | values
    return found


def inaccessible_of(holder: Any) -> Dict[str, FrozenSet[str]]:
    """What a record or check says it tried to assess and could not reach."""
    return _dimension_map(declared_field(holder, "inaccessible"))


# ── the surface a claim declares ─────────────────────────────────────────────

@dataclass(frozen=True)
class ClaimSurface:
    """What a claim is about, element by element. Declared; never inferred."""

    dimensions: Tuple[Tuple[str, Tuple[str, ...]], ...] = ()
    #: (dimension, element) → why the claim's producer says it is out of scope.
    not_applicable: Mapping[Tuple[str, str], str] = field(default_factory=dict)
    #: Why a surface the claim declared could not be read. A surface that was
    #: stated and is unreadable is not the same as none: it is never met.
    problem: str = ""

    @property
    def declared(self) -> bool:
        return bool(self.dimensions)

    @property
    def stated(self) -> bool:
        return self.declared or bool(self.problem)

    def elements(self, dimension: str) -> Tuple[str, ...]:
        return dict(self.dimensions).get(dimension, ())

    @classmethod
    def from_claim(cls, claim: Any) -> "ClaimSurface":
        metadata = getattr(claim, "metadata", None) or {}
        try:
            return cls.from_dict(metadata.get("surface") if isinstance(metadata, Mapping)
                                 else None)
        except ClaimSurfaceError as exc:
            return cls(problem=str(exc))

    @classmethod
    def from_dict(cls, data: Any) -> "ClaimSurface":
        """`{dimension: [element, ...]}` or `{dimension: {"required": [...],
        "not_applicable": {element: reason}}}`. Strict: what cannot be read is refused."""
        if data is None:
            return cls()
        if not isinstance(data, Mapping):
            raise ClaimSurfaceError("a claim surface is an object of dimension → elements")
        dimensions: Dict[str, List[str]] = {}
        excluded: Dict[Tuple[str, str], str] = {}
        for key, raw in data.items():
            dimension = canonical_dimension(key)
            if dimension is None:
                raise ClaimSurfaceError(f"{key!r} is not a dimension name")
            required: Any = raw
            na: Mapping[str, Any] = {}
            if isinstance(raw, Mapping):
                unknown = set(raw) - {"required", "not_applicable"}
                if unknown:
                    raise ClaimSurfaceError(
                        f"{dimension}: unknown key(s) {', '.join(sorted(map(str, unknown)))}")
                required = raw.get("required") or []
                na = raw.get("not_applicable") or {}
                if not isinstance(na, Mapping):
                    raise ClaimSurfaceError(
                        f"{dimension}: not_applicable maps each element to the reason "
                        "it is out of scope")
            listed = required if isinstance(required, (list, tuple)) else [required]
            elements = sorted(_values(dimension, listed))
            for element, reason in na.items():
                if not str(reason or "").strip():
                    raise ClaimSurfaceError(
                        f"{dimension} {element}: an element declared not applicable "
                        "must say why — dropping part of a claim is a claim too")
                for value in _values(dimension, [element]):
                    excluded[(dimension, value)] = str(reason).strip()
                    if value not in elements:
                        elements.append(value)
            if not elements:
                raise ClaimSurfaceError(f"{dimension} names no element")
            dimensions[dimension] = sorted(set(elements))
        return cls(dimensions=tuple(sorted((d, tuple(e)) for d, e in dimensions.items())),
                   not_applicable=dict(sorted(excluded.items())))

    def to_dict(self) -> Dict[str, Any]:
        if self.problem:
            return {"unreadable": self.problem}
        return {d: {"required": [e for e in elements
                                 if (d, e) not in self.not_applicable],
                    "not_applicable": {e: self.not_applicable[(d, e)] for e in elements
                                       if (d, e) in self.not_applicable}}
                for d, elements in self.dimensions}


# ── coverage ─────────────────────────────────────────────────────────────────

class SurfaceStatus(str, Enum):
    ASSESSED_SUPPORTED = "ASSESSED_SUPPORTED"
    ASSESSED_FAILED = "ASSESSED_FAILED"
    NOT_ASSESSED = "NOT_ASSESSED"
    INACCESSIBLE = "INACCESSIBLE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNKNOWN = "UNKNOWN"


#: Settled: something assessed it and reached a result. Only these count toward
#: coverage — an inconclusive check looked and could not say.
_SETTLED = frozenset({SurfaceStatus.ASSESSED_SUPPORTED, SurfaceStatus.ASSESSED_FAILED})

# How a resolution item bears on an element. Roles not named here bear on nothing
# a coverage figure can use: a reading is not an assessment, and a resolved
# contradiction was answered.
_SUPPORTED_ROLES = frozenset({"SUPPORTS"})
_FAILED_ROLES = frozenset({"CONTRADICTS", "FAILED_CHECK"})
_UNKNOWN_ROLES = frozenset({"INCONCLUSIVE"})
_SET_ASIDE_ROLES = {
    "WITHHELD_STATE": "only evidence about another state of the release",
    "NOT_ADMISSIBLE": "only evidence the claim does not admit",
    "NOT_RELIED_UPON": "only evidence from a source ruled against",
    "NOT_RUN": "a check was expected and never ran",
    "INVALIDATED": "a check whose result was retracted",
}


@dataclass(frozen=True)
class ElementCoverage:
    dimension: str
    element: str
    status: SurfaceStatus
    supported_by: Tuple[str, ...] = ()
    failed_by: Tuple[str, ...] = ()
    unknown_by: Tuple[str, ...] = ()
    inaccessible_by: Tuple[str, ...] = ()
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"dimension": self.dimension, "element": self.element,
                "status": self.status.value, "supported_by": list(self.supported_by),
                "failed_by": list(self.failed_by), "unknown_by": list(self.unknown_by),
                "inaccessible_by": list(self.inaccessible_by), "note": self.note}


@dataclass(frozen=True)
class DimensionCoverage:
    dimension: str
    elements: Tuple[ElementCoverage, ...]
    #: Elements evidence named that the claim's surface does not.
    outside_surface: Tuple[str, ...] = ()

    def count(self, status: SurfaceStatus) -> int:
        return sum(1 for e in self.elements if e.status is status)

    @property
    def required(self) -> int:
        """Elements in scope: every declared element not declared not applicable,
        and any declared not applicable that a failure was observed on anyway."""
        return sum(1 for e in self.elements if e.status is not SurfaceStatus.NOT_APPLICABLE)

    @property
    def assessed(self) -> int:
        return sum(1 for e in self.elements if e.status in _SETTLED)

    @property
    def missing(self) -> Tuple[ElementCoverage, ...]:
        """In scope and not settled: the surface nobody has shown either way."""
        return tuple(e for e in self.elements
                     if e.status not in _SETTLED and e.status is not SurfaceStatus.NOT_APPLICABLE)

    @property
    def failed(self) -> Tuple[ElementCoverage, ...]:
        return tuple(e for e in self.elements if e.status is SurfaceStatus.ASSESSED_FAILED)

    def meets(self, share: float) -> bool:
        """Every dimension is held to the share on its own; nothing averages across."""
        return self.required == 0 or self.assessed >= share * self.required - 1e-9

    def summary(self) -> str:
        parts = [f"{self.assessed} of {self.required} assessed"]
        for status, word in ((SurfaceStatus.NOT_ASSESSED, "not assessed"),
                             (SurfaceStatus.INACCESSIBLE, "inaccessible"),
                             (SurfaceStatus.UNKNOWN, "unknown"),
                             (SurfaceStatus.ASSESSED_FAILED, "assessed failure"),
                             (SurfaceStatus.NOT_APPLICABLE, "not applicable")):
            n = self.count(status)
            if n:
                parts.append(f"{n} {word}" + ("s" if n > 1 and status
                                               is SurfaceStatus.ASSESSED_FAILED else ""))
        return " · ".join(parts)

    def to_dict(self) -> Dict[str, Any]:
        return {"dimension": self.dimension, "required": self.required,
                "assessed": self.assessed,
                "by_status": {s.value: self.count(s) for s in SurfaceStatus},
                "missing": [e.element for e in self.missing],
                "failed": [e.element for e in self.failed],
                "outside_surface": list(self.outside_surface),
                "elements": [e.to_dict() for e in self.elements],
                "summary": self.summary()}


@dataclass(frozen=True)
class ClaimCoverage:
    """One claim's declared surface, element by element, and what covered each."""

    claim_id: str
    statement: str
    required: Optional[bool]
    surface: ClaimSurface
    dimensions: Tuple[DimensionCoverage, ...] = ()
    #: Items bearing on the claim that name no element of its surface, by role.
    unattributed: Mapping[str, Tuple[str, ...]] = field(default_factory=dict)

    @property
    def declared(self) -> bool:
        return self.surface.declared

    @property
    def missing(self) -> Tuple[ElementCoverage, ...]:
        return tuple(e for d in self.dimensions for e in d.missing)

    @property
    def failed(self) -> Tuple[ElementCoverage, ...]:
        return tuple(e for d in self.dimensions for e in d.failed)

    @property
    def complete(self) -> bool:
        """Every in-scope element settled. Says nothing about whether they passed."""
        return self.declared and not self.missing

    def meets(self, share: float) -> bool:
        return self.declared and all(d.meets(share) for d in self.dimensions)

    def render(self) -> str:
        lines = [f"{self.claim_id}: {self.statement}"]
        if self.surface.problem:
            lines.append(f"    surface declared and unreadable ({self.surface.problem}); "
                         "nothing is counted as assessed against it")
            return "\n".join(lines)
        if not self.declared:
            lines.append("    no surface declared: what portion was assessed cannot "
                         "be measured, and it is not assumed")
            return "\n".join(lines)
        for dim in self.dimensions:
            lines.append(f"    {dim.dimension}: {dim.summary()}")
            for element in dim.elements:
                lines.append(f"      {element.element:<24} {element.status.value}"
                             + (f" — {element.note}" if element.note else ""))
        missing = self.missing
        if missing:
            lines.append("    missing: " + ", ".join(f"{e.dimension} {e.element}"
                                                   for e in missing))
        held = sum(len(v) for v in self.unattributed.values())
        if held:
            lines.append(f"    {held} item(s) bear on this claim without naming any "
                         "element of its surface; they cover nothing here")
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "claim_coverage", "record_id": self.claim_id,
                "claim_id": self.claim_id, "statement": self.statement,
                "required": self.required, "declared": self.declared,
                "surface_problem": self.surface.problem or None,
                "surface": self.surface.to_dict(), "complete": self.complete,
                "missing": [{"dimension": e.dimension, "element": e.element,
                             "status": e.status.value} for e in self.missing],
                "failed": [{"dimension": e.dimension, "element": e.element}
                           for e in self.failed],
                "dimensions": [d.to_dict() for d in self.dimensions],
                "unattributed": {k: list(v) for k, v in self.unattributed.items()},
                "schema_version": CLAIM_COVERAGE_SCHEMA_VERSION}


@dataclass(frozen=True)
class ClaimCoverageReport:
    claims: Tuple[ClaimCoverage, ...] = ()

    def of(self, claim_id: str) -> Optional[ClaimCoverage]:
        return next((c for c in self.claims if c.claim_id == claim_id), None)

    @property
    def declared(self) -> Tuple[ClaimCoverage, ...]:
        return tuple(c for c in self.claims if c.declared)

    @property
    def stated(self) -> Tuple[ClaimCoverage, ...]:
        """Claims that declared a surface, readable or not."""
        return tuple(c for c in self.claims if c.surface.stated)

    def summary(self) -> Dict[str, Any]:
        declared = self.declared
        return {"claims": len(self.claims), "surfaces_declared": len(declared),
                "complete": sum(1 for c in declared if c.complete),
                "elements_missing": sum(len(c.missing) for c in declared),
                "elements_failed": sum(len(c.failed) for c in declared),
                "digest": digest_object([c.to_dict() for c in self.claims])}

    def to_dict(self) -> Dict[str, Any]:
        return {**self.summary(), "detail": [c.to_dict() for c in self.claims],
                "schema_version": CLAIM_COVERAGE_SCHEMA_VERSION}

    def render(self) -> str:
        return "\n".join(c.render() for c in self.stated)


_PRECEDENCE = (SurfaceStatus.ASSESSED_FAILED, SurfaceStatus.ASSESSED_SUPPORTED,
               SurfaceStatus.UNKNOWN, SurfaceStatus.INACCESSIBLE)


def _claim_coverage(claim: Any, resolution: Any, holders: Mapping[str, Any]
                    ) -> ClaimCoverage:
    surface = ClaimSurface.from_claim(claim)
    statement = getattr(claim, "statement", "") or ""
    required = getattr(resolution, "required", None) if resolution is not None else None
    if not surface.declared or resolution is None:
        return ClaimCoverage(claim_id=claim.claim_id, statement=statement,
                             required=required, surface=surface)

    # What each counted item bears on, element by element.
    hits: Dict[Tuple[str, str], Dict[str, List[str]]] = {}
    set_aside: Dict[Tuple[str, str], List[str]] = {}
    outside: Dict[str, set] = {}
    unattributed: Dict[str, List[str]] = {}
    in_surface = {d: set(e) for d, e in surface.dimensions}

    def mark(key: Tuple[str, str], bucket: str, item_id: str) -> None:
        hits.setdefault(key, {}).setdefault(bucket, []).append(item_id)

    for item in getattr(resolution, "items", ()):
        role = item.role.value
        if item.item_kind not in ("evidence", "verification"):
            continue
        holder = holders.get(item.item_id)
        conditions = conditions_of(holder) if holder is not None else {}
        named = False
        for dimension, values in conditions.items():
            if dimension not in in_surface:
                continue
            for value in sorted(values):
                if value not in in_surface[dimension]:
                    outside.setdefault(dimension, set()).add(value)
                    continue
                named = True
                key = (dimension, value)
                if role in _SUPPORTED_ROLES:
                    mark(key, "supported", item.item_id)
                elif role in _FAILED_ROLES:
                    mark(key, "failed", item.item_id)
                elif role in _UNKNOWN_ROLES:
                    mark(key, "unknown", item.item_id)
                elif role in _SET_ASIDE_ROLES:
                    set_aside.setdefault(key, []).append(_SET_ASIDE_ROLES[role])
        if holder is not None:
            for dimension, values in inaccessible_of(holder).items():
                for value in values & in_surface.get(dimension, set()):
                    named = True
                    mark((dimension, value), "inaccessible", item.item_id)
        if not named and role in (_SUPPORTED_ROLES | _FAILED_ROLES | _UNKNOWN_ROLES):
            unattributed.setdefault(role, []).append(item.item_id)

    dimensions: List[DimensionCoverage] = []
    for dimension, elements in surface.dimensions:
        rows: List[ElementCoverage] = []
        for element in elements:
            key = (dimension, element)
            found = hits.get(key, {})
            by = {s: tuple(sorted(set(found.get(b, ())))) for s, b in (
                (SurfaceStatus.ASSESSED_FAILED, "failed"),
                (SurfaceStatus.ASSESSED_SUPPORTED, "supported"),
                (SurfaceStatus.UNKNOWN, "unknown"),
                (SurfaceStatus.INACCESSIBLE, "inaccessible"))}
            status = next((s for s in _PRECEDENCE if by[s]), SurfaceStatus.NOT_ASSESSED)
            notes: List[str] = []
            reason = surface.not_applicable.get(key)
            if reason is not None:
                if status is SurfaceStatus.ASSESSED_FAILED:
                    notes.append(f"declared not applicable ({reason}), and evidence "
                                 "failed on it")
                else:
                    status = SurfaceStatus.NOT_APPLICABLE
                    notes.append(reason)
            if status is SurfaceStatus.NOT_ASSESSED and key in set_aside:
                notes.append("; ".join(sorted(set(set_aside[key]))))
            rows.append(ElementCoverage(
                dimension=dimension, element=element, status=status,
                supported_by=by[SurfaceStatus.ASSESSED_SUPPORTED],
                failed_by=by[SurfaceStatus.ASSESSED_FAILED],
                unknown_by=by[SurfaceStatus.UNKNOWN],
                inaccessible_by=by[SurfaceStatus.INACCESSIBLE], note="; ".join(notes)))
        dimensions.append(DimensionCoverage(
            dimension=dimension, elements=tuple(rows),
            outside_surface=tuple(sorted(outside.get(dimension, ())))))
    return ClaimCoverage(
        claim_id=claim.claim_id, statement=statement, required=required, surface=surface,
        dimensions=tuple(dimensions),
        unattributed={role: tuple(sorted(set(ids)))
                      for role, ids in sorted(unattributed.items())})


def assess_claim_coverage(claim_graph: Any, resolution: Any,
                          evidence: Iterable[Any] = ()) -> ClaimCoverageReport:
    """Every claim's coverage of its own declared surface.

    `resolution` is the claim resolution report: an element is covered only by
    what the resolution counted, so evidence it set aside (another state, an
    inadmissible method) never covers anything. Claims with no surface are
    listed as undeclared rather than left out.
    """
    if claim_graph is None:
        return ClaimCoverageReport()
    holders: Dict[str, Any] = {getattr(r, "evidence_id", ""): r for r in evidence
                               if getattr(r, "evidence_id", None)}
    rows: List[ClaimCoverage] = []
    for claim in sorted(claim_graph.claims, key=lambda c: c.claim_id):
        for attempt in getattr(claim, "verification_attempts", ()):
            holders.setdefault(attempt.verification_id, attempt)
        resolved = resolution.of(claim.claim_id) if resolution is not None else None
        rows.append(_claim_coverage(claim, resolved, holders))
    return ClaimCoverageReport(claims=tuple(rows))

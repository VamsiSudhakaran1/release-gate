"""Progressive assurance: how deep this case goes, and how deep it needs to go.

Invariant 14 says not every graph is mandatory. The analysers have always
honoured that — they no-op on an absent collection rather than inventing one —
but nothing ever *named* the depth, so every case was reported in the vocabulary
of the deepest one. A one-agent "send an email" arrived with twenty-one coverage
dimensions, nine of them about replication, adversarial review, counterexamples
and failed branches, all NOT_ASSESSED; and when it held, two of its three
required-evidence items asked for an independently-operated producer and a typed
verification while the one thing that would actually resolve it sat third.

That is the whole problem this module solves, and the solution is a *description*,
not a switch.

**The level never gates anything.** It is computed after analysis and consumed
only by reporting and ordering. No analyser reads it, no finding's effect is
softened by it, and no verdict consults it: a contradiction discovered in a
Level 0 case blocks exactly as hard as one in a Level 4 case. A level that could
stop release-gate from looking would be a way to launder a finding out of a case,
which is the opposite of the point.

**Two numbers, never one.** `supported` is the depth the evidence present can
sustain; `required` is the depth this decision demands. Collapsing them into a
single "level" loses the only interesting fact — which of the two is larger.
`required > supported` is the gap that ordering should lead with.
`supported > required` is a case carrying more than it needed, which is not a
finding and never a penalty.

**Out of scope is still stated.** A dimension that does not apply at this level
is grouped and counted, never dropped. NOT_ASSESSED is first-class (Invariant 3),
and a coverage matrix that silently omitted rows would be claiming a completeness
nobody established — the precise failure the matrix exists to prevent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from types import MappingProxyType
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

LEVEL_SCHEMA_VERSION = 1

#: Immutable default, so a caller cannot mutate a shared dict.
_EMPTY_COUNTS: Mapping[str, int] = MappingProxyType({})
_EMPTY_SIGNALS: Mapping[str, bool] = MappingProxyType({})


class AssuranceLevel(IntEnum):
    """How much assurance machinery a case carries or calls for.

    Ordered, so `max` and comparison mean what they look like. The names are the
    five scales the product has to serve on one architecture, not a quality
    score: Level 0 is not a worse case than Level 4, it is a smaller question.
    """

    MINIMAL = 0            # one agent, low consequence
    ATTRIBUTED = 1         # one agent, consequential — provenance, integrity, authorization
    ORCHESTRATED = 2       # multi-agent — execution lineage, artifact provenance
    CORROBORATED = 3       # high-impact — independent verification, contradictions, assumptions
    FRONTIER = 4           # research / critical infrastructure — claims, proof, adversarial

    @property
    def label(self) -> str:
        return f"L{int(self)} {self.name}"

    def describe(self) -> str:
        return _LEVEL_DESCRIPTION[self]


_LEVEL_DESCRIPTION: Mapping[AssuranceLevel, str] = {
    AssuranceLevel.MINIMAL: (
        "one agent, low consequence: what happened, and what it was asked to do"),
    AssuranceLevel.ATTRIBUTED: (
        "one agent, consequential: who produced this, what it binds to, and on "
        "whose authority"),
    AssuranceLevel.ORCHESTRATED: (
        "a multi-agent workflow: how the work flowed and where each artifact "
        "came from"),
    AssuranceLevel.CORROBORATED: (
        "a high-impact workflow: independent verification, disagreement tracked "
        "rather than averaged, and what the argument takes for granted"),
    AssuranceLevel.FRONTIER: (
        "research, critical infrastructure or a frontier system: an explicit "
        "claim graph, typed verification, adversarial review and replication"),
}


#: Coverage dimension -> the level at which it starts being applicable. A
#: dimension absent from this table is treated as MINIMAL, so a new dimension
#: shows up everywhere rather than silently vanishing from every case.
_DIMENSION_LEVEL: Mapping[str, AssuranceLevel] = {
    # L0 — is this thing what it says it is, and what did we manage to read.
    "input_identification": AssuranceLevel.MINIMAL,
    "input_integrity": AssuranceLevel.MINIMAL,
    "record_mapping": AssuranceLevel.MINIMAL,
    "structural_analysis": AssuranceLevel.MINIMAL,
    "domain_sufficiency": AssuranceLevel.MINIMAL,
    "overall": AssuranceLevel.MINIMAL,
    # L1 — action provenance, subject integrity, what it could reach.
    "execution_reconstruction": AssuranceLevel.ATTRIBUTED,
    "provenance": AssuranceLevel.ATTRIBUTED,
    "consequence": AssuranceLevel.ATTRIBUTED,
    "capability_discovery": AssuranceLevel.ATTRIBUTED,
    # L2 — execution lineage and artifact provenance across a workflow.
    "drift": AssuranceLevel.ORCHESTRATED,
    "verification_currency": AssuranceLevel.ORCHESTRATED,
    # L3 — independent verification, contradiction tracking, assumptions.
    "independence": AssuranceLevel.CORROBORATED,
    "verification": AssuranceLevel.CORROBORATED,
    "contradiction": AssuranceLevel.CORROBORATED,
    "assumptions": AssuranceLevel.CORROBORATED,
    # L4 — the frontier structures.
    "criticality": AssuranceLevel.FRONTIER,
    "replication": AssuranceLevel.FRONTIER,
    "adversarial_review": AssuranceLevel.FRONTIER,
    "counterexamples": AssuranceLevel.FRONTIER,
    "failed_branches": AssuranceLevel.FRONTIER,
}


def dimension_level(dimension: str) -> AssuranceLevel:
    """The level at which a coverage dimension starts applying.

    Unknown dimensions are MINIMAL rather than FRONTIER: a dimension nobody has
    classified should appear in every case and be noticed, not disappear from
    the small ones.
    """
    return _DIMENSION_LEVEL.get(str(dimension or "").strip().lower(),
                                AssuranceLevel.MINIMAL)


#: Case type -> the floor this kind of decision sits at, before consequence or
#: methodology raise it. A code change is never a Level 0 question even when the
#: diff is one line, because "who wrote this and does it still apply" is the
#: cheapest thing there is and the whole point of asking.
_CASE_TYPE_FLOOR: Mapping[str, AssuranceLevel] = {
    "GENERAL_DECISION": AssuranceLevel.MINIMAL,
    "AUTONOMOUS_ACTION": AssuranceLevel.MINIMAL,
    "CUSTOM": AssuranceLevel.MINIMAL,
    "CODE_CHANGE": AssuranceLevel.ATTRIBUTED,
    "DEPLOYMENT": AssuranceLevel.ATTRIBUTED,
    "DATA_CHANGE": AssuranceLevel.ORCHESTRATED,
    "FINANCIAL_ACTION": AssuranceLevel.ORCHESTRATED,
    "INFRASTRUCTURE_CHANGE": AssuranceLevel.ORCHESTRATED,
    "RESEARCH_RESULT": AssuranceLevel.FRONTIER,
}

#: Consequence values that raise the floor, and how far. Only values that are
#: actually STATED count — an UNKNOWN dimension never raises or lowers anything,
#: because an unstated consequence is an unassessed one rather than a small one
#: (Invariant 3). It also never *lowers* a floor set elsewhere.
_CONSEQUENCE_FLOOR: Mapping[str, Mapping[str, AssuranceLevel]] = {
    "REVERSIBILITY": {"IRREVERSIBLE": AssuranceLevel.CORROBORATED,
                      "REVERSIBLE_WITH_EFFORT": AssuranceLevel.ATTRIBUTED},
    "SCOPE": {"BROAD": AssuranceLevel.CORROBORATED,
              "BOUNDED_SET": AssuranceLevel.ATTRIBUTED},
    "FINANCIAL_IMPACT": {"UNBOUNDED": AssuranceLevel.CORROBORATED,
                         "BOUNDED": AssuranceLevel.ATTRIBUTED},
    "SECURITY_IMPACT": {"GRANTS_ACCESS": AssuranceLevel.CORROBORATED,
                        "AFFECTS_CONTROLS": AssuranceLevel.CORROBORATED},
    "DATA_IMPACT": {"DESTROYED": AssuranceLevel.CORROBORATED,
                    "MODIFIED": AssuranceLevel.ORCHESTRATED},
    "PRODUCTION_IMPACT": {"PRODUCTION": AssuranceLevel.ATTRIBUTED},
    "LEGAL_IMPACT": {"REGULATED": AssuranceLevel.CORROBORATED,
                     "POSSIBLE": AssuranceLevel.ORCHESTRATED},
    "RESEARCH_IMPACT": {"PUBLISHED_RESULT": AssuranceLevel.FRONTIER},
    "EXTERNALITY": {"CROSSES_ORGANISATION_BOUNDARY": AssuranceLevel.ORCHESTRATED},
    "USER_IMPACT": {"DIRECT": AssuranceLevel.ATTRIBUTED},
}

#: Methodology predicate kind -> the level a methodology asking for it implies.
#: This is how "capabilities activate based on methodology": a yardstick that
#: demands replication is describing a Level 4 question whatever the input looks
#: like.
_PREDICATE_LEVEL: Mapping[str, AssuranceLevel] = {
    "subject_identified": AssuranceLevel.ATTRIBUTED,
    "consequence_declared": AssuranceLevel.ATTRIBUTED,
    "record_field_required": AssuranceLevel.ATTRIBUTED,
    # L1, not L2, by this module's own definition of L1: "who produced this,
    # WHAT IT BINDS TO, and on whose authority". A single agent that edits its
    # own file after testing it has broken the binding without a second agent
    # anywhere in the story, so asking whether evidence still applies to current
    # content does not imply a multi-agent workflow. It sat at L2 until the
    # single-agent profile needed it, which would have pushed the ordinary
    # one-agent case up two levels for asking a Level 1 question.
    "applies_to_current_state": AssuranceLevel.ATTRIBUTED,
    "expectation_declared": AssuranceLevel.ORCHESTRATED,
    "verification_present": AssuranceLevel.CORROBORATED,
    "independence_threshold": AssuranceLevel.CORROBORATED,
    "ancestry_independence": AssuranceLevel.CORROBORATED,
    "declared_independence_holds": AssuranceLevel.CORROBORATED,
    "assumptions_examined": AssuranceLevel.CORROBORATED,
    "no_claim_in_status": AssuranceLevel.CORROBORATED,
    # Identifying what a decision rests on is Level 3 work: it is dependency
    # tracking, the same family as contradictions and assumptions. Level 4 is
    # what the frontier profiles do *with* that set — verify every load-bearing
    # claim by typed method, attack it, replicate it.
    "critical_claims_identified": AssuranceLevel.CORROBORATED,
    "critical_claims_verified": AssuranceLevel.FRONTIER,
    "adversarial_review_required": AssuranceLevel.FRONTIER,
    "replication_established": AssuranceLevel.FRONTIER,
}

#: Case collection -> the level its contents demonstrate, and how many records it
#: takes to demonstrate it. Read from what the case actually holds, which is the
#: "available evidence" half of the derivation.
#:
#: The minimum is not a magic number, it is the difference between a *thing* and
#: a *relationship*. Level 2 is execution lineage and artifact provenance — both
#: claims about how things relate — and one artifact node is not provenance any
#: more than one execution node is lineage. Every zero-config run creates an
#: artifact for the input file itself, so a threshold of one rated a single-agent
#: email send as carrying multi-agent workflow structure. The Level 3 and 4
#: collections are about a kind of evidence *existing* at all, so one is enough:
#: a single recorded counterexample is a real counterexample.
_COLLECTION_LEVEL: Mapping[str, Tuple[AssuranceLevel, int]] = {
    "evidence": (AssuranceLevel.MINIMAL, 1),
    "coverage": (AssuranceLevel.MINIMAL, 1),
    "executions": (AssuranceLevel.ORCHESTRATED, 2),
    "artifacts": (AssuranceLevel.ORCHESTRATED, 2),
    "verification": (AssuranceLevel.CORROBORATED, 1),
    "contradictions": (AssuranceLevel.CORROBORATED, 1),
    "assumptions": (AssuranceLevel.CORROBORATED, 1),
    "claims": (AssuranceLevel.FRONTIER, 1),
    "counterexamples": (AssuranceLevel.FRONTIER, 1),
}


#: Required-evidence kind -> the level at which asking for it is proportionate.
#: This is what stops a one-agent email send being told to go and find an
#: independently-operated producer before it is told to say what the action does.
_REQUIREMENT_LEVEL: Mapping[str, AssuranceLevel] = {
    "methodology_declaration": AssuranceLevel.MINIMAL,
    "missing_evidence": AssuranceLevel.MINIMAL,
    "unspecified": AssuranceLevel.MINIMAL,
    "provenance_attestation": AssuranceLevel.ATTRIBUTED,
    "consequence_declaration": AssuranceLevel.ATTRIBUTED,
    "capability_declaration": AssuranceLevel.ATTRIBUTED,
    "human_review": AssuranceLevel.ATTRIBUTED,
    "re_verification": AssuranceLevel.ORCHESTRATED,
    "expectation_declaration": AssuranceLevel.ORCHESTRATED,
    "dependency_declaration": AssuranceLevel.CORROBORATED,
    "formal_verification": AssuranceLevel.CORROBORATED,
    "independent_verification": AssuranceLevel.CORROBORATED,
    "contradiction_resolution": AssuranceLevel.CORROBORATED,
    "assumption_verification": AssuranceLevel.CORROBORATED,
    "replication": AssuranceLevel.FRONTIER,
    "adversarial_review": AssuranceLevel.FRONTIER,
    "counterexample_search": AssuranceLevel.FRONTIER,
}


def requirement_level(kind: str) -> AssuranceLevel:
    """The level at which asking for this kind of evidence is proportionate."""
    return _REQUIREMENT_LEVEL.get(str(kind or "").strip().lower(),
                                  AssuranceLevel.MINIMAL)


@dataclass(frozen=True)
class LevelAssessment:
    """How deep this case goes, how deep it needs to go, and why.

    `supported` and `required` are kept apart deliberately. A case may carry far
    more structure than its decision needs — that is a team being thorough, not a
    finding — and it may carry far less, which is the gap worth leading with.
    """

    supported: AssuranceLevel
    required: AssuranceLevel
    supported_basis: Tuple[str, ...] = ()
    required_basis: Tuple[str, ...] = ()
    #: Dimensions in scope at `required`, and those beyond it. Both are listed:
    #: an out-of-scope dimension is grouped, never dropped.
    in_scope: Tuple[str, ...] = ()
    out_of_scope: Tuple[str, ...] = ()

    @property
    def gap(self) -> int:
        """How many levels short the evidence is. Never negative."""
        return max(0, int(self.required) - int(self.supported))

    @property
    def meets_required(self) -> bool:
        return self.supported >= self.required

    @property
    def exceeds_required(self) -> bool:
        """Carrying more structure than the decision needs. Not a finding."""
        return self.supported > self.required

    def applies(self, dimension: str) -> bool:
        return dimension_level(dimension) <= self.required

    def note(self) -> str:
        """One line a human can read without knowing this vocabulary."""
        if self.gap:
            return (f"This decision is a {self.required.label} question and the "
                    f"evidence supports {self.supported.label}: "
                    f"{self.required.describe()}.")
        if self.exceeds_required:
            return (f"This is a {self.required.label} question and the case "
                    f"carries {self.supported.label} structure — more than it "
                    "needs, which is not a deficiency.")
        return (f"This is a {self.required.label} question and the evidence "
                f"matches it: {self.required.describe()}.")

    def out_of_scope_note(self) -> str:
        """Which dimensions sit above this question, and what that does not mean.

        Grouped rather than omitted: every one of these still has its row in the
        coverage matrix with its own state, and anything actually found in them
        is still a finding, still ranked into Human Attention and still able to
        block. This line says only that a decision of this depth is not expected
        to populate them — so a Level 0 case does not read as a Level 4 case with
        nine failures.
        """
        if not self.out_of_scope:
            return ""
        return (f"{len(self.out_of_scope)} dimension(s) apply above a "
                f"{self.required.label} question and are not expected to be "
                f"populated by a decision of this depth: "
                f"{', '.join(sorted(self.out_of_scope))}. Their coverage rows still "
                "state what each one found, and anything found in them still "
                "counts.")

    def requirement_rank(self, kind: str) -> int:
        """Sort key for a required-evidence item: 0 at or below level, 1 above.

        Asking a Level 1 case for replication is not wrong — the evidence really
        would help — but it is not the thing to say first, and a list that opens
        with it reads as a case that is failing rather than one that needs a
        sentence about consequence. Above-level asks are kept and ranked last,
        never dropped: the gap they describe is real.
        """
        return 1 if requirement_level(kind) > self.required else 0

    def order_requirements(self, items: Sequence[Any]) -> Tuple[Any, ...]:
        """Re-rank required evidence so proportionate asks come first.

        A stable sort, so the existing deterministic ordering is preserved
        within each band and nothing is reordered arbitrarily.
        """
        def key(item: Any) -> int:
            requirement = getattr(item, "requirement", None)
            kind = getattr(getattr(requirement, "requirement", None), "value", "")
            return self.requirement_rank(kind)
        return tuple(sorted(items, key=key))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_type": "assurance_level",
            "supported": int(self.supported),
            "supported_label": self.supported.label,
            "required": int(self.required),
            "required_label": self.required.label,
            "gap": self.gap,
            "meets_required": self.meets_required,
            "exceeds_required": self.exceeds_required,
            "supported_basis": list(self.supported_basis),
            "required_basis": list(self.required_basis),
            "in_scope": list(self.in_scope),
            "out_of_scope": list(self.out_of_scope),
            "note": self.note(),
            "out_of_scope_note": self.out_of_scope_note(),
            "schema_version": LEVEL_SCHEMA_VERSION,
        }


def _stated_consequence(consequence: Any) -> Dict[str, str]:
    """Dimension -> stated value, for dimensions that carry a real one."""
    if consequence is None:
        return {}
    stated: Dict[str, str] = {}
    for descriptor in getattr(consequence, "known", ()) or ():
        dimension = getattr(descriptor.dimension, "value", descriptor.dimension)
        value = str(descriptor.value or "").upper()
        if value and value != "UNKNOWN":
            stated[str(dimension).upper()] = value
    return stated


#: Named facts that demonstrate Level 1, which is the one level no collection
#: represents. Levels 2-4 are each defined by a body of records — executions,
#: artifacts, verifications, claims — so their presence is countable. Level 1 is
#: "action provenance, subject integrity, authorization", which is a property of
#: records the case already has rather than a collection of its own, so it has to
#: be asserted by the caller from concrete, checkable facts instead of inferred
#: from a count.
_LEVEL_1_SIGNALS: Tuple[str, ...] = ("subject_digest", "execution_reconstructed",
                                     "producers_identified")


def assess_level(*, case_type: Any = None,
                 methodology: Any = None,
                 consequence: Any = None,
                 populated_collections: Mapping[str, int] = _EMPTY_COUNTS,
                 signals: Mapping[str, bool] = _EMPTY_SIGNALS,
                 dimensions: Sequence[str] = ()) -> LevelAssessment:
    """Derive the level this case supports and the level it requires.

    The three inputs are the three the product contract names: case type,
    methodology, and available evidence. Consequence is folded into `required`
    because it is what separates "send a reminder" from "send a termination
    notice" when the two produce identical traces.

    `populated_collections` maps collection name to how many records it HOLDS,
    not which ones are marked PRESENT. The two come apart on every case: release-gate
    marks a collection PRESENT to mean "this was looked for", so a case with an
    empty counterexample ledger has `counterexamples` PRESENT with zero records.
    Reading presence here rated a one-agent email send as FRONTIER-supported on
    the strength of five empty ledgers. Presence is a statement about looking;
    `supported` is a statement about what was found.

    Nothing here changes what runs. The result is a description of a case that
    has already been analysed in full.
    """
    # ── required: what this decision demands ────────────────────────────────
    required = AssuranceLevel.MINIMAL
    required_basis: list = []

    type_name = str(getattr(case_type, "value", case_type) or "").upper()
    if type_name:
        floor = _CASE_TYPE_FLOOR.get(type_name, AssuranceLevel.MINIMAL)
        if floor > required:
            required = floor
            required_basis.append(
                f"a {type_name} decision sits at {floor.label} before anything else")

    stated = _stated_consequence(consequence)
    for dimension, value in sorted(stated.items()):
        floor = _CONSEQUENCE_FLOOR.get(dimension, {}).get(value)
        if floor is not None and floor > required:
            required = floor
            required_basis.append(f"{dimension} is {value}, which is {floor.label}")

    if methodology is not None:
        for requirement in getattr(methodology, "all_requirements", lambda: ())():
            kind = getattr(getattr(requirement, "predicate", None), "KIND", "")
            floor = _PREDICATE_LEVEL.get(kind)
            if floor is not None and floor > required:
                required = floor
                required_basis.append(
                    f"{getattr(methodology, 'methodology_id', 'the methodology')} "
                    f"requires {requirement.requirement_id}, which is {floor.label}")

    if not required_basis:
        required_basis.append(
            "nothing raises this above the minimum: no consequence is stated, the "
            "case type carries no floor, and the methodology asks for nothing deeper")

    # ── supported: what the evidence present can sustain ────────────────────
    supported = AssuranceLevel.MINIMAL
    supported_basis: list = []
    for collection, held in sorted(dict(populated_collections or {}).items()):
        entry = _COLLECTION_LEVEL.get(collection)
        if entry is None:
            continue
        reached, minimum = entry
        if int(held) >= minimum and reached > supported:
            supported = reached
            supported_basis.append(
                f"the case carries {held} {collection} record(s), which is "
                f"{reached.label} structure")
    held_signals = sorted(name for name in _LEVEL_1_SIGNALS
                          if bool((signals or {}).get(name)))
    if held_signals and AssuranceLevel.ATTRIBUTED > supported:
        supported = AssuranceLevel.ATTRIBUTED
        supported_basis.append(
            f"the case establishes {', '.join(held_signals)}, which is "
            f"{AssuranceLevel.ATTRIBUTED.label} structure")

    if not supported_basis:
        supported_basis.append(
            "the case carries evidence and coverage and no deeper structure")

    # Purely a statement about level, deliberately not about whether anything was
    # found. `assessed` does not mean the same thing across dimensions — for the
    # ledger dimensions it means "settled", so an OPEN contradiction reads
    # NOT_ASSESSED — and partitioning on state made a case with a live
    # contradiction report that dimension as unexamined. Scope says which
    # questions this decision reaches, and nothing more; what was found is
    # reported by the findings, the attention set and the verdict, none of which
    # consult this.
    in_scope, out_of_scope = [], []
    for name in dimensions:
        (out_of_scope if dimension_level(name) > required else in_scope).append(str(name))

    return LevelAssessment(
        supported=supported, required=required,
        supported_basis=tuple(supported_basis), required_basis=tuple(required_basis),
        in_scope=tuple(in_scope), out_of_scope=tuple(out_of_scope))

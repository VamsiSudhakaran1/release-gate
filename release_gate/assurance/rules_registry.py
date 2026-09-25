"""Rule families, and the seven questions every rule answers.

Thirty families already exist. `RG-CLAIM`, `RG-VERIF`, `RG-ADV`, `RG-SW`,
`RG-CAP`, `RG-REPL`, `RG-DRIFT`, `RG-CONTRA`, `RG-CONS` and twenty-one more,
split across two origins: the scanner's families (`RG-EXEC`, `RG-PROMPT`,
`RG-SECRET` …) and the assurance layer's structural ones (`RG-CLAIM`,
`RG-CONTRA`, `RG-COV` …), with twelve names appearing in both because the same
concern is checked statically and structurally.

**The proposed vocabulary overlaps that taxonomy, and aliases beat forking it.**
`RG-CLAIM` already exists. `RG-VERIFY` is `RG-VERIF` spelled longer; `RG-COVERAGE`
is `RG-COV`; `RG-LINEAGE` and `RG-ATTEST` are provenance questions `RG-PROV`
already owns; `RG-ARTIFACT` is `RG-DRIFT`; `RG-EVIDENCE` is `RG-EXPECT`;
`RG-SWARM` is `RG-REPL` plus `RG-INDEP`. Adding any of them as a *second* family
would leave two names for one concern, and a reviewer grepping either would find
half the rules — worse than either name alone. So they resolve as **aliases**,
and the vocabulary works without a rule id changing.

`RG-APPROVAL` is the one genuinely absent family: the approval, override and
identity work (§10y, §10z) produces records and refusals but no rule ids at all,
so there is nothing to alias it to.

**A rule that cannot answer all seven is incompletely specified.** The questions
are not decoration:

    1. What fact triggered it?        `observed` — what the predicate actually saw
    2. What evidence proves it?       the records the finding rests on
    3. What epistemic status applies? DERIVED, OBSERVED, DECLARED …
    4. What does it affect?           BLOCK, HOLD, ADVISORY — and which claims
    5. What would resolve it?         the remedy, as a work order
    6. Is it methodology-dependent?   whether a methodology defines it at all
    7. Is it overridable?             and if not, whether that is a refusal or
                                      an absence of opinion

All seven are already answerable — scattered across `RequirementResult`, the
attention set, and the methodology's `recognises` and `can_override`. Nothing was
missing; nothing assembled them. `answers_for` does, and where a question cannot
be answered it reads `NOT_ASSESSED` rather than defaulting: questions six and
seven in particular have three states, because §10y established that "this
methodology forbids overriding it" and "this methodology never heard of it" are
different answers and collapsing them credits a methodology with a position it
does not hold.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

__all__ = [
    "ALIASES",
    "FAMILIES",
    "QUESTIONS",
    "RULES_SCHEMA_VERSION",
    "POLICY_RULES",
    "Answer",
    "Origin",
    "PolicyRule",
    "RuleAnswers",
    "RuleFamily",
    "RuleKind",
    "RuleRegistryError",
    "answers_for",
    "family_of",
    "resolve_family",
]

RULES_SCHEMA_VERSION = 1


class RuleRegistryError(ValueError):
    """A rule was read against a family that does not own it."""


#: The seven, in the order a reader works through them. A constant, so "does this
#: rule answer everything" is a comparison rather than a count.
QUESTIONS: Tuple[str, ...] = (
    "triggering_fact", "proving_evidence", "epistemic_status", "affects",
    "resolution", "methodology_dependent", "overridable",
)


class Origin(str, Enum):
    """Where a family's rules are raised.

    Twelve names appear in both, because the same concern is checked in code and
    in structure — `RG-EXEC` finds an exec sink in a file, and the assurance layer
    reasons about what the execution graph shows. Same concern, different
    evidence, deliberately the same family.
    """

    SCANNER = "SCANNER"        # release-gate's static analysis
    STRUCTURAL = "STRUCTURAL"  # the assurance layer, reasoning over a case
    BOTH = "BOTH"


class RuleKind(str, Enum):
    """What sort of thing a family's rules are.

    Not every rule is a finding. `RG-ZC-*` are the clauses of the decision
    procedure itself — the verdict names them to say *how* it reached PROMOTE,
    HOLD or BLOCK. Asking a decision clause "what evidence proves it" the way
    one asks a finding gets `NOT_ASSESSED` five times over, which reads as five
    holes in the assessment when in fact the rule is a different kind of thing.
    The distinction is here so the report can be accurate rather than merely
    literal.
    """

    FINDING = "FINDING"  # raised against a case; has a subject and a remedy
    POLICY = "POLICY"    # a clause of the decision procedure; cited by the verdict


@dataclass(frozen=True)
class RuleFamily:
    """One rule-id prefix and what it is about."""

    prefix: str
    label: str
    origin: Origin = Origin.STRUCTURAL
    #: Alternative spellings that resolve here rather than forking the taxonomy.
    aliases: Tuple[str, ...] = ()
    notes: str = ""

    #: `RG-EXEC-001` splits on the last hyphen; `contradictions.resolved` on the
    #: first dot. Two notations, both real, and a registry that knew only the
    #: first would refuse half of what fires.
    dotted: bool = False

    #: Finding unless stated. One family is `POLICY`, and the asymmetry is the
    #: point: findings are the norm and decision clauses are the exception.
    kind: RuleKind = RuleKind.FINDING

    def __post_init__(self) -> None:
        object.__setattr__(self, "origin", Origin(self.origin))
        object.__setattr__(self, "kind", RuleKind(self.kind))
        object.__setattr__(self, "aliases", tuple(self.aliases))
        if not self.dotted and not self.prefix.startswith("RG-"):
            raise RuleRegistryError(
                f"{self.prefix!r}: a rule family is prefixed RG-, which is what "
                "makes a rule id greppable across a codebase nobody has read")
        if self.dotted and "." in self.prefix:
            raise RuleRegistryError(
                f"{self.prefix!r}: a dotted family is the root, not a whole "
                "requirement id")

    def owns(self, rule_id: str) -> bool:
        found = str(rule_id or "")
        if self.dotted:
            return found.split(".", 1)[0] == self.prefix and "." in found
        head = found.rsplit("-", 1)[0]
        return head == self.prefix or head in self.aliases

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "rule_family", "record_id": self.prefix,
                "prefix": self.prefix, "label": self.label,
                "origin": self.origin.value, "kind": self.kind.value,
                "aliases": list(self.aliases), "notes": self.notes}


_FAMILY_LIST: Tuple[RuleFamily, ...] = (
    # ── the assurance layer's structural families ───────────────────────────
    RuleFamily("RG-CLAIM", "claim structure and support", Origin.STRUCTURAL),
    RuleFamily("RG-VERIF", "verification presence, currency and admissibility",
               Origin.BOTH, aliases=("RG-VERIFY",),
               notes="RG-VERIFY resolves here; two families for one concern "
                     "would split a grep in half"),
    RuleFamily("RG-CONTRA", "contradictions and their resolution",
               Origin.STRUCTURAL),
    RuleFamily("RG-COV", "coverage: what was and was not assessed",
               Origin.STRUCTURAL, aliases=("RG-COVERAGE",)),
    RuleFamily("RG-CRIT", "criticality — which claims the decision rests on",
               Origin.STRUCTURAL),
    RuleFamily("RG-PROV", "provenance, lineage and attestation", Origin.BOTH,
               aliases=("RG-LINEAGE", "RG-ATTEST"),
               notes="lineage and attestation are provenance questions: where a "
                     "thing came from and who vouches for it"),
    RuleFamily("RG-DRIFT", "mutation and artifact integrity over time",
               Origin.STRUCTURAL, aliases=("RG-ARTIFACT",),
               notes="an artifact question that is not about integrity is "
                     "usually a lineage one, and RG-PROV owns that"),
    RuleFamily("RG-EXPECT", "evidence expectations and what did not arrive",
               Origin.STRUCTURAL, aliases=("RG-EVIDENCE",)),
    RuleFamily("RG-REPL", "replication and corroboration across producers",
               Origin.STRUCTURAL, aliases=("RG-SWARM",),
               notes="a swarm question is a replication or an independence "
                     "question; scale is not its own concern (Invariant 6)"),
    RuleFamily("RG-INDEP", "independence of evidence sources",
               Origin.STRUCTURAL),
    RuleFamily("RG-ADV", "adversarial review and challenge", Origin.STRUCTURAL),
    RuleFamily("RG-CAP", "capability surface — what the system could reach",
               Origin.STRUCTURAL),
    RuleFamily("RG-CONS", "stated consequence of the action", Origin.STRUCTURAL),
    RuleFamily("RG-ASSUME", "assumptions the argument rests on",
               Origin.STRUCTURAL),
    RuleFamily("RG-CEX", "counterexamples and the search for them",
               Origin.STRUCTURAL),
    RuleFamily("RG-BRANCH", "failed branches and abandoned work",
               Origin.STRUCTURAL),
    RuleFamily("RG-ACT", "autonomous action requirements", Origin.STRUCTURAL),
    RuleFamily("RG-SW", "software-change assurance dimensions",
               Origin.STRUCTURAL),
    RuleFamily("RG-ZC", "zero-config policy: how structure becomes a verdict",
               Origin.STRUCTURAL, kind=RuleKind.POLICY,
               notes="the rules that turn everything above into PROMOTE, HOLD "
                     "or BLOCK; cited by the verdict, not by a finding"),
    #: Genuinely new. The approval, override and identity work produces records
    #: and refusals but no rule ids, so there was nothing to alias to.
    RuleFamily("RG-APPROVAL", "authorization state: approvals, overrides and "
                              "the identity behind them", Origin.STRUCTURAL,
               notes="a namespace, deliberately empty. Inventing rules to fill "
                     "it would be manufacturing findings, and the refusals that "
                     "govern this area are properties rather than rules"),

    # ── the scanner's families ──────────────────────────────────────────────
    RuleFamily("RG-EXEC", "execution sinks reachable from model output",
               Origin.BOTH),
    RuleFamily("RG-PROMPT", "prompt construction and injection surface",
               Origin.BOTH),
    RuleFamily("RG-SECRET", "credentials in code or context", Origin.BOTH),
    RuleFamily("RG-ACTION", "consequential actions taken without a gate",
               Origin.BOTH),
    RuleFamily("RG-GATE", "human approval gates in the code path", Origin.BOTH),
    RuleFamily("RG-LOOP", "unbounded or uncapped agent loops", Origin.BOTH),
    RuleFamily("RG-COST", "budget and spend exposure", Origin.BOTH),
    RuleFamily("RG-TOOL", "tool surface and what it can reach", Origin.BOTH),
    RuleFamily("RG-PARSE", "deserialisation and parsing of untrusted input",
               Origin.BOTH),
    RuleFamily("RG-PII", "personal data on a path to a model or a log",
               Origin.BOTH),
    RuleFamily("RG-CANARY", "canary values proving a leak path", Origin.SCANNER),

    # ── methodology requirement ids ─────────────────────────────────────────
    # A second notation, not a second taxonomy. A methodology names its
    # requirements `contradictions.resolved`, not `RG-CONTRA-001`, because they
    # are the methodology's own vocabulary rather than release-gate's catalogue —
    # and §10y found that conflating the two namespaces is what made a rule
    # unanswerable when asked whether it could be waived. Both are registered so
    # neither is refused.
    RuleFamily("subject", "the subject being argued about", Origin.STRUCTURAL,
               dotted=True),
    RuleFamily("contradictions", "contradiction resolution, as a requirement",
               Origin.STRUCTURAL, dotted=True),
    RuleFamily("counterexamples", "counterexample search, as a requirement",
               Origin.STRUCTURAL, dotted=True),
    RuleFamily("coverage", "coverage dimensions a methodology expects",
               Origin.STRUCTURAL, dotted=True),
    RuleFamily("evidence", "minimum evidence a methodology expects",
               Origin.STRUCTURAL, dotted=True),
    RuleFamily("independence", "independence a methodology requires",
               Origin.STRUCTURAL, dotted=True),
    RuleFamily("verification", "verification a methodology requires",
               Origin.STRUCTURAL, dotted=True),
)

#: prefix → family, built from one list so the registry cannot disagree with
#: itself about which families exist.
FAMILIES: Mapping[str, RuleFamily] = {f.prefix: f for f in _FAMILY_LIST}

#: alias → the family that owns it.
ALIASES: Mapping[str, str] = {
    alias: family.prefix for family in _FAMILY_LIST for alias in family.aliases}


def resolve_family(prefix: str) -> RuleFamily:
    """The family for a prefix or one of its aliases."""
    key = str(prefix or "").strip()
    if key in FAMILIES:
        return FAMILIES[key]
    if key in ALIASES:
        return FAMILIES[ALIASES[key]]
    raise RuleRegistryError(
        f"{key!r} is not a rule family. Known: " + ", ".join(sorted(FAMILIES))
        + ". A prefix this does not know is not one it rejects — register it, "
          "rather than letting rules accumulate under a name nothing describes")


def family_of(rule_id: str) -> RuleFamily:
    """The family that owns this rule id."""
    for family in _FAMILY_LIST:
        if family.owns(rule_id):
            return family
    raise RuleRegistryError(
        f"no registered family owns {rule_id!r}. A rule outside every family is "
        "one nobody can look up, and a reviewer who cannot place a rule cannot "
        "weigh what it found. Rule ids are `RG-FAMILY-nnn`; methodology "
        "requirement ids are `root.requirement` — register the family rather "
        "than letting rules accumulate under a name nothing describes")


# ── the decision procedure's own clauses ─────────────────────────────────────

@dataclass(frozen=True)
class PolicyRule:
    """One clause of the decision procedure, and what the verdict states by
    naming it.

    Written out as literals rather than read from `zero_config`, for two
    reasons: this module stays free of the engine it describes, and a table that
    derived itself from the code could not disagree with it — which is another
    way of saying it could never catch a drift. `test_assurance_rules_registry`
    compares the two sets and fails when a clause is added without a description,
    so the cost of the literals is one test and the benefit is a guard that can
    actually fire (§10ae).
    """

    rule_id: str
    #: What the verdict asserts by citing this clause.
    states: str
    #: What would resolve it — empty when the clause reports a state rather than
    #: raising an issue. Those answer `NOT_APPLICABLE`, not `NOT_ASSESSED`:
    #: "nothing to resolve" and "nobody looked" are different answers, and
    #: reporting the first as the second counts a satisfied rule as a hole.
    resolution: str = ""


_POLICY_LIST: Tuple[PolicyRule, ...] = (
    PolicyRule(
        "RG-ZC-001",
        "no methodology states what evidence this decision requires, so domain "
        "sufficiency is NOT_ASSESSED and the run cannot promote",
        "supply a methodology covering this case type; the structural assurance "
        "is already complete as far as it goes"),
    PolicyRule(
        "RG-ZC-002",
        "the structural analysis found something disqualifying, and the verdict "
        "is BLOCK on that basis alone",
        "the blocking findings are named individually in this same verdict, and "
        "each carries its own remedy"),
    PolicyRule(
        "RG-ZC-003",
        "the structural analysis found something a person has to look at, and "
        "the verdict is HOLD",
        "the holding findings are named individually in this same verdict, and "
        "each carries its own remedy"),
    PolicyRule(
        "RG-ZC-004",
        "every requirement of the active methodology is met, with the coverage "
        "recorded on this case"),
    PolicyRule(
        "RG-ZC-005",
        "a structural hold was accepted up front by the active methodology; the "
        "finding stands and is still shown, it just does not disqualify here"),
)

#: rule id → what that clause of the decision procedure states.
POLICY_RULES: Mapping[str, PolicyRule] = {r.rule_id: r for r in _POLICY_LIST}


# ── the seven questions, for one fired rule ──────────────────────────────────

class Answer(str, Enum):
    """Whether a question could be answered at all.

    Three states. `NOT_APPLICABLE` is the one that stops an honest report from
    overstating a gap: a satisfied requirement has nothing to resolve, and
    calling that unassessable would count a met requirement as a hole.
    """

    ANSWERED = "ANSWERED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_ASSESSED = "NOT_ASSESSED"


@dataclass(frozen=True)
class RuleAnswers:
    """What one rule, on one case, answers to the seven questions.

    Answers belong to the *instance*, not the id: "what fact triggered it" is
    about what the predicate saw on this case, and a per-id table would have to
    say something generic and would drift from the code besides.
    """

    rule_id: str
    family: str
    answers: Mapping[str, Any] = field(default_factory=dict)
    unanswered: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "answers", dict(self.answers))
        object.__setattr__(self, "unanswered", tuple(self.unanswered))
        missing = [q for q in QUESTIONS if q not in self.answers]
        if missing:
            raise RuleRegistryError(
                f"{self.rule_id}: the seven questions must each have an entry, "
                "answered or not; missing " + ", ".join(missing)
                + ". A question left out reads as one with nothing to say, and a "
                  "rule that cannot answer all seven is incompletely specified")

    @property
    def complete(self) -> bool:
        """Whether every question was answerable. `False` is ordinary."""
        return not self.unanswered

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "rule_answers", "record_id": self.rule_id,
                "rule_id": self.rule_id, "family": self.family,
                "answers": dict(self.answers),
                "unanswered": list(self.unanswered),
                "complete": self.complete}

    def render(self) -> str:
        labels = {
            "triggering_fact": "What fact triggered it",
            "proving_evidence": "What evidence proves it",
            "epistemic_status": "What epistemic status applies",
            "affects": "What it affects",
            "resolution": "What would resolve it",
            "methodology_dependent": "Methodology-dependent",
            "overridable": "Overridable",
        }
        lines = [f"{self.rule_id}  ({self.family})"]
        for question in QUESTIONS:
            value = self.answers[question]
            mark = " [NOT ASSESSED]" if question in self.unanswered else ""
            lines.append(f"  {labels[question]}: {value}{mark}")
        return "\n".join(lines)


def _unset(bucket: List[str], question: str, reason: str) -> Tuple[str, str]:
    bucket.append(question)
    return question, reason


def answers_for(rule_id: str, outcome: Any, *,
                methodology: Any = None) -> RuleAnswers:
    """Assemble the seven answers for one rule from a decided outcome.

    Reads rather than computes: every answer already exists on the outcome, the
    assessment, the attention set or the methodology. Where one does not, the
    entry says `NOT_ASSESSED` — never a default, because a rule reported as
    "not methodology-dependent" when nobody asked a methodology is a claim about
    a methodology that was never consulted.
    """
    family = family_of(rule_id)
    unanswered: List[str] = []
    answers: Dict[str, Any] = {}

    if family.kind is RuleKind.POLICY:
        _policy_answers(rule_id, outcome, answers, unanswered)
    else:
        _finding_answers(rule_id, outcome, answers, unanswered)
    _methodology_answers(rule_id, outcome, methodology, answers, unanswered)
    return RuleAnswers(rule_id=rule_id, family=family.prefix,
                       answers=answers, unanswered=tuple(unanswered))


def _policy_answers(rule_id: str, outcome: Any, answers: Dict[str, Any],
                    unanswered: List[str]) -> None:
    """The first five, for a clause of the decision procedure.

    A clause is not a finding: it has no subject in the case and raises nothing.
    What it has is the verdict that cites it, and that is a record — the decision
    it produced, the stated reasons a person read, and the ruleset that was in
    force. `CaseVerdict.digest_component` already treats the reasons as part of
    what was approved, so quoting them here is not a paraphrase of the decision;
    it is the decision.
    """
    clause = POLICY_RULES.get(rule_id)
    verdict = getattr(getattr(outcome, "case", None), "verdict", None)
    cited = verdict is not None and rule_id in (verdict.fired_rules or ())

    if clause is not None and cited:
        answers["triggering_fact"] = {
            "states": clause.states,
            "cited_by": "verdict",
            "decision": verdict.decision.value}
    elif clause is not None:
        # Registered, described, and not named on this verdict. The clause did
        # not fire, so there is no fact — which is an absence, not a gap.
        answers["triggering_fact"] = {
            "state": Answer.NOT_APPLICABLE.value,
            "states": clause.states,
            "note": "this clause of the decision procedure is not named on this "
                    "case's verdict, so it did not fire here"}
    else:
        answers["triggering_fact"] = _unset(
            unanswered, "triggering_fact",
            "this is a decision-procedure rule the registry does not describe; "
            "register it in POLICY_RULES rather than reporting a clause of the "
            "verdict as unassessable")[1]

    if cited:
        answers["proving_evidence"] = {
            "verdict_reasons": list(verdict.reasons),
            "ruleset_version": verdict.ruleset_version,
            "note": "a decision clause is proved by the verdict that cites it; "
                    "the reasons below are the ones the verdict states"}
        answers["epistemic_status"] = {
            "status": "DERIVED",
            "basis": "the decision procedure computed this from the case's own "
                     "records, under ruleset "
                     f"{verdict.ruleset_version or 'unrecorded'}"}
        answers["affects"] = {
            "effect": "THE_DECISION",
            "decision": verdict.decision.value,
            "note": "a decision clause does not modify a verdict; it is one of "
                    "the grounds the verdict rests on"}
    else:
        for question, reason in (
                ("proving_evidence", "this clause is not named on this case's "
                                     "verdict, so no verdict proves it here"),
                ("epistemic_status", "this clause did not fire on this case, so "
                                     "nothing was established either way"),
                ("affects", "this clause did not fire on this case, so it bore "
                            "on nothing")):
            answers[question] = {"state": Answer.NOT_APPLICABLE.value,
                                 "note": reason}

    if clause is not None and clause.resolution:
        answers["resolution"] = {"remedy": clause.resolution,
                                 "resolving_evidence": []}
    elif clause is not None:
        answers["resolution"] = {
            "state": Answer.NOT_APPLICABLE.value,
            "note": "this clause reports a state rather than raising an issue; "
                    "there is nothing to resolve"}
    else:
        answers["resolution"] = _unset(
            unanswered, "resolution",
            "nothing is named as the thing that would resolve this")[1]


def _finding_answers(rule_id: str, outcome: Any, answers: Dict[str, Any],
                     unanswered: List[str]) -> None:
    """The first five, for a rule raised against a case."""
    result = next((r for r in getattr(getattr(outcome, "assessment", None),
                                      "results", ()) or ()
                   if r.requirement_id == rule_id), None)
    items = [i for i in (getattr(getattr(outcome, "attention", None), "items", ())
                         or ()) if rule_id in (getattr(i, "rule_ids", ()) or ())]
    item = items[0] if items else None

    # 1 — what fact triggered it
    if result is not None:
        answers["triggering_fact"] = {"detail": result.detail,
                                      "observed": dict(result.observed),
                                      "predicate": result.predicate_kind}
    elif item is not None:
        answers["triggering_fact"] = {"detail": item.summary,
                                      "focus": item.focus,
                                      "observed": dict(item.observed.get(rule_id, {}))}
    else:
        answers["triggering_fact"] = _unset(
            unanswered, "triggering_fact",
            "this rule fired and neither the assessment nor the attention set "
            "records what it saw")[1]

    # 2 — what evidence proves it
    if item is not None and (item.supporting_evidence or item.contradicting_evidence):
        answers["proving_evidence"] = {
            "supporting": list(item.supporting_evidence),
            "contradicting": list(item.contradicting_evidence)}
    elif result is not None and result.observed:
        answers["proving_evidence"] = {"observed_by_predicate":
                                       dict(result.observed)}
    elif item is not None and item.observed.get(rule_id):
        # A finding about an *absence* cites no record, because the record is
        # what is missing: `RG-VERIF-001` is proved by `verification_records: 0`,
        # a count that was taken. Reading that as "no evidence" would turn a
        # measurement of nothing into nothing measured, which is the one
        # confusion Invariant 3 exists to prevent.
        answers["proving_evidence"] = {
            "observed_by_predicate": dict(item.observed[rule_id]),
            "note": "no evidence record is cited because this rule fired on what "
                    "the case does not contain; the measurement is what proves it"}
    else:
        answers["proving_evidence"] = _unset(
            unanswered, "proving_evidence",
            "no evidence record is cited for this rule on this case, and no "
            "measurement was recorded either")[1]

    # 3 — what epistemic status applies
    if item is not None and getattr(item, "epistemic_status", ""):
        answers["epistemic_status"] = item.epistemic_status
    elif result is not None and result.observed:
        # A structural predicate evaluated the case's own records and reported
        # what it saw. That is DERIVED by construction — the same status the
        # attention set carries for the rules that have items — and stating the
        # basis keeps it from reading as an assertion nobody can trace.
        answers["epistemic_status"] = {
            "status": "DERIVED",
            "basis": f"the {result.predicate_kind} predicate computed this from "
                     "the case's own records"}
    else:
        answers["epistemic_status"] = _unset(
            unanswered, "epistemic_status",
            "nothing records how what this rule saw was established")[1]

    # 4 — what it affects
    if result is not None:
        answers["affects"] = {"effect": result.effect.value,
                              "outcome": result.outcome.value}
    elif item is not None:
        answers["affects"] = {"effect": item.effect.value,
                              "depends_on": list(item.depends_on)}
    else:
        answers["affects"] = _unset(
            unanswered, "affects", "what this rule bears on is not recorded")[1]

    # 5 — what would resolve it
    remedy = (result.remedy if result is not None and result.remedy
              else (item.remedy if item is not None else ""))
    resolving = list(item.resolving_evidence) if item is not None else []
    if remedy or resolving:
        answers["resolution"] = {"remedy": remedy,
                                 "resolving_evidence": resolving}
    elif result is not None and result.is_met:
        # Not a gap. A requirement that is met has nothing to resolve, and
        # reporting that as unassessable would count a satisfied rule as a hole.
        answers["resolution"] = {
            "state": Answer.NOT_APPLICABLE.value,
            "note": "this requirement is met; there is nothing to resolve"}
    else:
        answers["resolution"] = _unset(
            unanswered, "resolution",
            "nothing is named as the thing that would resolve this, which is the "
            "shrug the engine exists to stop giving")[1]


def _acceptance_of(rule_id: str, outcome: Any, methodology: Any) -> Any:
    """The acceptance covering this finding here, read the way the engine reads it.

    Consequence-conditioned, because an acceptance whose ceiling does not hold
    for what this case states is not in force — asking without the stated
    consequence would report an acceptance that never applied.
    """
    if not hasattr(methodology, "acceptance_for"):
        return None
    profile = getattr(outcome, "consequence", None)
    stated = {d.dimension.value: d.value
              for d in (getattr(profile, "known", ()) or ())}
    return methodology.acceptance_for(rule_id, stated)


def _methodology_answers(rule_id: str, outcome: Any, methodology: Any,
                         answers: Dict[str, Any], unanswered: List[str]) -> None:
    """Questions six and seven, for any rule.

    Three states each, because a methodology that was never asked has no
    position, and recording one as a refusal credits it with an opinion it does
    not hold (§10y). A decision clause goes through the same path deliberately:
    a methodology that does not define `RG-ZC-004` genuinely has no position on
    it, and that is the honest answer rather than a bespoke one.

    **An acceptance is a third thing, and the report has to say so.**
    `recognises` deliberately excludes accepted findings — an acceptance does
    not make a structural finding one of the methodology's requirements, and
    `extend` refuses a waiver naming one. That is right, and it left this report
    stating "the methodology has no position on it" about a rule the same
    methodology had accepted by name on the same verdict. The authority is not
    the thing to change; the sentence is.
    """
    if methodology is None or not hasattr(methodology, "can_override"):
        reason = ("no methodology was supplied, so whether this rule is one a "
                  "methodology defines was not asked")
        answers["methodology_dependent"] = _unset(
            unanswered, "methodology_dependent", reason)[1]
        answers["overridable"] = _unset(
            unanswered, "overridable",
            "no methodology was supplied, so whether this may be waived was not "
            "asked — which is not the same as nothing permitting it")[1]
    else:
        recognised = methodology.recognises(rule_id)
        accepted = _acceptance_of(rule_id, outcome, methodology)
        if recognised:
            note = "this rule is one the active methodology defines"
        elif accepted is not None:
            note = ("not a requirement of the active methodology, which "
                    "nonetheless takes a position on it: it accepts this finding "
                    "under a stated consequence ceiling. The finding stands and "
                    "is shown; it does not disqualify here")
        else:
            note = ("the active methodology does not define this rule; it is "
                    "structural, and the methodology has no position on it")
        answers["methodology_dependent"] = {
            "defined_by": methodology.ref_string if recognised else None,
            "recognised": recognised,
            "accepted_by": methodology.ref_string if accepted is not None else None,
            # The methodology's own words for why, unspliced: a rationale is an
            # argument someone wrote and paraphrasing it into a sentence of ours
            # is how a stated reason quietly becomes our reading of it.
            "accepted_because": accepted.rationale if accepted is not None else "",
            "note": note}
        decision = methodology.can_override(rule_id)
        answers["overridable"] = {
            "permitted": decision.permitted,
            "recognised": decision.recognised,
            "requires_role": decision.requires_role,
            "reason": decision.reason}
        if accepted is not None:
            # Named here so a reader cannot mistake the promote for a waiver.
            # An acceptance is decided in advance and applies to everyone; an
            # override is one person deciding to proceed anyway, and only the
            # second one needs an approver (§10z).
            answers["overridable"]["accepted_not_waived"] = True
            answers["overridable"]["note"] = (
                "this finding did not need waiving here: the methodology "
                "accepted it in advance. An acceptance is not an override — "
                "nobody had to authorise anything for this one")

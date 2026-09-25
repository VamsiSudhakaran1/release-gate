"""`governance.yaml`, read for what it actually is: a team's account of itself.

Governance was the centre of the product that came before this one. A
`governance.yaml` declared the budget, the kill switch, the owner and the
thresholds, and the gate checked a repo against it. That file still works,
unchanged, and nothing here asks anyone to migrate.

What changes is where it sits. A governance file is **evidence about intent**,
not a yardstick:

    governance.yaml   what a team wrote down about its own system. DECLARED,
                      optional, organisation-specific, and absent from most
                      cases. Says nothing about what a decision needs.
    methodology       what a class of decision is argued against. Versioned,
                      content-addressed, inside `case_digest` (§11).

**This is not governance.yaml renamed to methodology.** Renaming it would keep
the same thing at the centre under a better word, and the two have different
lifecycles: a governance file changes when a team changes its deployment, a
methodology changes when a field changes its mind about what an argument needs.
Conflating them would let the system under assessment set the bar it is assessed
against.

**A declaration is a claim, not a guarantee.** `kill_switch: true` establishes
that somebody wrote `kill_switch: true`. Whether a kill switch exists, works, or
was reachable during the run are separate questions, answered by other lanes
(§10ag). `establishes_the_safeguard` is unconditionally `False`, and
`is_policy_input` is too: the methodology decides whether a declaration is
enough, and a declaration that could set its own sufficiency bar would be the
thing being assessed grading its own paper.

**Nothing requires one.** The default case is independent of governance, which
is measured rather than asserted: the same input yields the same `case_digest`
with and without a governance file present. A case with no declaration is not a
case with a gap — it is a case about something nobody wrote a governance file
for, which is most of them.

No YAML is parsed here. The pure layer reads no files and imports no parser, so
a host hands over an already-parsed mapping — the same arrangement §10ad uses
for SAML, and for the same reason: parsing untrusted documents is a different
job with a different threat model.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

__all__ = [
    "DECLARATION_SCHEMA_VERSION",
    "DeclarationError",
    "DeclaredBudget",
    "DeclaredSafeguard",
    "Declaration",
    "declaration_evidence",
    "read_declaration",
]

DECLARATION_SCHEMA_VERSION = 1


class DeclarationError(ValueError):
    """A declaration was read in a way that would read as more than a claim."""


def _presence(value: Any) -> Tuple[Optional[bool], str]:
    """Whether a safeguard value declares presence, and what it said.

    Three answers, not two. `governance.yaml` writes plain booleans
    (`kill_switch: true`); an audit report writes `{"present": true, ...}`; and a
    block of settings with no presence flag at all (`kill_switch: {type: ...}`)
    declares configuration without declaring presence. Reading that third case as
    absent would report a team as having said something they did not.
    """
    if isinstance(value, bool):
        return value, "declared as a boolean"
    if isinstance(value, Mapping):
        if "present" in value:
            return bool(value["present"]), "declared with an explicit present flag"
        if "enabled" in value:
            return bool(value["enabled"]), "declared with an enabled flag"
        return None, ("configured, with no presence flag — settings were written "
                      "down and whether the safeguard is in place was not stated")
    if value in (None, ""):
        return None, "named with no value"
    return True, f"declared as {type(value).__name__}"


@dataclass(frozen=True)
class DeclaredSafeguard:
    """One safeguard a team wrote down, and exactly what they wrote."""

    name: str
    #: `None` when configuration was supplied without stating presence.
    declared_present: Optional[bool]
    basis: str = ""
    detail: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not str(self.name or "").strip():
            raise DeclarationError("a declared safeguard must be named")
        object.__setattr__(self, "name", self.name.strip())
        object.__setattr__(self, "detail", dict(self.detail or {}))

    @property
    def establishes_the_safeguard(self) -> bool:
        """Unconditionally False.

        `kill_switch: true` establishes that somebody wrote `kill_switch: true`.
        Whether one exists, works, or was reachable during the run are questions
        for the lanes that can see a system rather than a file (§10ag).
        """
        return False

    @property
    def stated(self) -> bool:
        """Whether presence was stated at all — as opposed to configured."""
        return self.declared_present is not None

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "declared_safeguard", "record_id": self.name,
                "name": self.name, "declared_present": self.declared_present,
                "stated": self.stated, "basis": self.basis,
                "detail": dict(self.detail),
                "establishes_the_safeguard": False}


@dataclass(frozen=True)
class DeclaredBudget:
    """A ceiling a team set for itself. A number they chose, not a limit anyone
    enforced."""

    name: str
    value: Any
    unit: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "declared_budget", "name": self.name,
                "value": self.value, "unit": self.unit,
                "enforced_by_release_gate": False}


#: Where safeguards live across the shapes a governance file has taken. Data, so
#: a new location is a row — and so a file that puts them somewhere else reads as
#: having none rather than crashing.
_SAFEGUARD_PATHS: Tuple[Tuple[str, ...], ...] = (
    ("safeguards",),
    ("checks",),
    ("governance", "safeguards"),
)


@dataclass(frozen=True)
class Declaration:
    """Everything a governance file says, as things it says.

    Deliberately not a policy object. There is no `applies_to`, no threshold that
    anything here evaluates, and no requirement derived from any of it.
    """

    source: str = "governance.yaml"
    project: str = ""
    owner: str = ""
    safeguards: Tuple[DeclaredSafeguard, ...] = ()
    budgets: Tuple[DeclaredBudget, ...] = ()
    #: Checks the file asks to fail or warn on. Recorded because a team saying
    #: which failures matter to them is worth having on the record — and read as
    #: a preference, never as a requirement of the case.
    fail_on: Tuple[str, ...] = ()
    warn_on: Tuple[str, ...] = ()
    raw_keys: Tuple[str, ...] = ()
    schema_version: int = DECLARATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        for name in ("safeguards", "budgets", "fail_on", "warn_on", "raw_keys"):
            object.__setattr__(self, name, tuple(getattr(self, name)))

    # ── the refusals ────────────────────────────────────────────────────────

    @property
    def is_policy_input(self) -> bool:
        """Unconditionally False.

        The methodology decides whether a declaration is enough. A declaration
        that could set its own sufficiency bar would be the system under
        assessment grading its own paper, which is the arrangement this whole
        repositioning exists to end.
        """
        return False

    @property
    def constrains_the_verdict(self) -> bool:
        """Unconditionally False. Nothing here is a requirement, a threshold the
        engine evaluates, or a reason a case holds."""
        return False

    @property
    def is_required(self) -> bool:
        """Unconditionally False. Most cases have no governance file, and a case
        without one is not a case with a gap."""
        return False

    # ── what it does say ────────────────────────────────────────────────────

    @property
    def declared_present(self) -> Tuple[str, ...]:
        return tuple(s.name for s in self.safeguards if s.declared_present is True)

    @property
    def declared_absent(self) -> Tuple[str, ...]:
        return tuple(s.name for s in self.safeguards if s.declared_present is False)

    @property
    def configured_without_stating(self) -> Tuple[str, ...]:
        """Settings written down without saying whether the safeguard is in
        place. Neither declared present nor declared absent."""
        return tuple(s.name for s in self.safeguards if s.declared_present is None)

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "declaration", "record_id": self.source,
                "source": self.source, "project": self.project,
                "owner": self.owner,
                "safeguards": [s.to_dict() for s in self.safeguards],
                "budgets": [b.to_dict() for b in self.budgets],
                "fail_on": list(self.fail_on), "warn_on": list(self.warn_on),
                "declared_present": list(self.declared_present),
                "declared_absent": list(self.declared_absent),
                "configured_without_stating":
                    list(self.configured_without_stating),
                "is_policy_input": False, "constrains_the_verdict": False,
                "is_required": False,
                "schema_version": self.schema_version}

    def render(self) -> str:
        lines = [f"DECLARATION from {self.source}"]
        if self.project:
            lines.append(f"  project: {self.project}")
        if self.owner:
            lines.append(f"  owner: {self.owner}")
        for safeguard in self.safeguards:
            if safeguard.declared_present is True:
                mark = "declared present"
            elif safeguard.declared_present is False:
                mark = "declared absent"
            else:
                mark = "configured, presence not stated"
            lines.append(f"  {safeguard.name}: {mark}")
        for budget in self.budgets:
            lines.append(f"  budget {budget.name}: {budget.value} "
                         f"{budget.unit}".rstrip())
        lines.append("  This is what a team wrote down about its own system. It "
                     "is DECLARED evidence; it establishes nothing and requires "
                     "nothing of this case.")
        return "\n".join(lines)


def _walk(document: Mapping[str, Any], path: Sequence[str]) -> Any:
    node: Any = document
    for step in path:
        if not isinstance(node, Mapping) or step not in node:
            return None
        node = node[step]
    return node


def read_declaration(document: Mapping[str, Any], *,
                     source: str = "governance.yaml") -> Declaration:
    """Read an already-parsed governance document into a `Declaration`.

    Takes a mapping, never a path or a string: the pure layer parses nothing, so
    whatever loaded the YAML stays outside it. Unknown keys are recorded by name
    and otherwise ignored — a governance file is a team's own document and may
    carry anything, and refusing one for having a key this does not model would
    make an optional input a blocking one.
    """
    if not isinstance(document, Mapping):
        raise DeclarationError(
            "a declaration is read from an already-parsed mapping. Load the YAML "
            "outside this layer and hand over the result; nothing here parses a "
            "file, and a string would have to be guessed at")

    project = ""
    for path in (("project", "name"), ("agent", "name"), ("name",)):
        found = _walk(document, path)
        if isinstance(found, str) and found.strip():
            project = found.strip()
            break

    owner = ""
    for path in (("owner",), ("project", "owner"),
                 ("checks", "fallback_declared", "team_owner")):
        found = _walk(document, path)
        if isinstance(found, str) and found.strip():
            owner = found.strip()
            break

    safeguards: List[DeclaredSafeguard] = []
    seen: set = set()
    for path in _SAFEGUARD_PATHS:
        block = _walk(document, path)
        if not isinstance(block, Mapping):
            continue
        for name, value in block.items():
            key = str(name)
            if key in seen:
                continue
            seen.add(key)
            declared, basis = _presence(value)
            safeguards.append(DeclaredSafeguard(
                name=key, declared_present=declared, basis=basis,
                detail=({k: v for k, v in value.items()
                         if k not in ("present", "enabled")}
                        if isinstance(value, Mapping) else {})))

    budgets: List[DeclaredBudget] = []
    for path, unit in ((("budget", "max_daily_cost"), "USD/day"),
                       (("checks", "action_budget", "max_daily_cost"), "USD/day"),
                       (("agent", "daily_requests"), "requests/day")):
        found = _walk(document, path)
        if isinstance(found, (int, float)):
            budgets.append(DeclaredBudget(name=path[-1], value=found, unit=unit))

    policy = _walk(document, ("policy",))
    fail_on = tuple(str(x) for x in (_walk(document, ("policy", "fail_on")) or ())
                    ) if isinstance(policy, Mapping) else ()
    warn_on = tuple(str(x) for x in (_walk(document, ("policy", "warn_on")) or ())
                    ) if isinstance(policy, Mapping) else ()

    return Declaration(
        source=source, project=project, owner=owner,
        safeguards=tuple(safeguards), budgets=tuple(budgets),
        fail_on=fail_on, warn_on=warn_on,
        raw_keys=tuple(sorted(str(k) for k in document)))


def declaration_evidence(declaration: Declaration, *,
                         applies_to_digest: Optional[str] = None) -> Tuple[Any, ...]:
    """Turn a declaration into DECLARED evidence records.

    One `ATTESTATION` per safeguard whose presence was *stated*, carrying what
    was said and nothing more. A safeguard configured without stating presence
    produces no attestation: a team writing settings for a kill switch has not
    claimed one is in place, and manufacturing the claim for them would put words
    in the record.
    """
    from release_gate.assurance.evidence import (
        EpistemicStatus, EvidenceRecord, EvidenceType, Producer, ProducerKind,
    )

    producer = Producer(
        producer_id=f"declaration/{declaration.source}",
        kind=ProducerKind.EXTERNAL,
        identity_basis="declared-document: the file's own account of the system "
                       "it describes, attributed to whoever supplied it")

    records: List[Any] = []
    for safeguard in declaration.safeguards:
        if not safeguard.stated:
            continue
        records.append(EvidenceRecord.from_producer(
            {"safeguard": safeguard.name,
             "declared_present": safeguard.declared_present,
             "basis": safeguard.basis,
             "detail": dict(safeguard.detail),
             "source": declaration.source},
            evidence_type=EvidenceType.ATTESTATION,
            source=declaration.source, producer=producer,
            status=EpistemicStatus.DECLARED,
            applies_to_digest=applies_to_digest,
            coverage_note=("a declared safeguard; a file saying it is in place "
                           "is the producer's account of their own system and "
                           "not a runtime guarantee")))
    return tuple(records)

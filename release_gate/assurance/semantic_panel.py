"""Several semantic verifiers on one question: independent readings, never a vote.

For a critical claim, one model's reading is one opinion. A panel asks several
verifiers the same question over the same packet, and records each answer as
its own evidence: who answered, what they answered, with what stated
probability or confidence. Nothing is averaged, counted into a majority or
blended into a number. Two readings of 0.91 "established" and 0.87 "violated"
are a disagreement for a person, not a 0.52.

**Independence is read from provenance, never assumed** (`correlation.py`). A
reading's provenance is what is stated about the model that produced it:

- its provider, which correlates two readings under
  `READER_INDEPENDENCE_POLICY`;
- its model family, which correlates across providers, since one family
  served by two hosts is one model;
- its model id, which correlates two readings of the same model wherever it
  is served;
- the lineage the operator declared for it (a shared base model, a shared
  fine-tune);
- any session the provider's reply reported.

Only what the operator stated places a reading: a family or a lineage. A
model that states nothing about itself is counted apart, never credited as
independent. A reply cannot vouch for its own independence: the `panel` key of
its metadata is the operator's and is stripped from what a provider returns.

**Disagreement is a finding** (RG-SEM-007), classified:

- `CONTRADICTION`: independent verifiers read the same evidence about the same
  state and reached opposite answers.
- `REQUIRES_REVIEW`: every other disagreement. One verifier found the evidence
  decisive where another found it insufficient; one model, or two that share
  provenance, answered both ways; they read different evidence; or whether
  they are independent cannot be told.

Either way a person settles it. The readings stay on the record beside each
other.

**What corroboration does** is the resolution policy's
(`resolution.SemanticCorroboration`): whether a "supported" on a critical
claim counts at all. A corroborated reading still never establishes a claim,
and never closes a gap. Verifiers reading one packet share it, so an
instruction written into it reaches all of them.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from release_gate.assurance.correlation import (READER_INDEPENDENCE_POLICY,
                                                IndependencePolicy, SourceProvenance,
                                                assess_independence)
from release_gate.assurance.escalation import (DEFAULT_ESCALATION_POLICY, EscalationPlan,
                                               EscalationPolicy, EscalationScope,
                                               plan_escalation)
from release_gate.assurance.semantic_verifier import (DEFAULT_SEMANTIC_VERIFIER_POLICY,
                                                      ProviderCapabilities, ProviderIdentity,
                                                      SemanticAssertion,
                                                      SemanticVerifierError,
                                                      SemanticVerifierPolicy,
                                                      assertions_from_records)

__all__ = [
    "SEMANTIC_PANEL_SCHEMA",
    "SEMANTIC_PANEL_SCHEMA_VERSION",
    "PanelMember",
    "ReadingDisagreement",
    "SemanticDisagreement",
    "SemanticPanel",
    "plan_panel",
    "reading_provenance",
    "semantic_disagreements",
    "tag_reading",
]

SEMANTIC_PANEL_SCHEMA_VERSION = 1
SEMANTIC_PANEL_SCHEMA = "release-gate.semantic-panel/1"


# ── who a reading came from ──────────────────────────────────────────────────

def reading_provenance(evidence_id: str, assertion: SemanticAssertion) -> SourceProvenance:
    """What is stated about the model behind one reading, as correlation reads it.

    What the reading read is deliberately not here: every verifier on a panel
    reads the same packet, so sharing it is the design, not a correlation. What
    it shares, an instruction in the evidence included, is why corroborated
    readings still never establish.
    """
    metadata = assertion.provider_metadata or {}
    panel = metadata.get("panel") if isinstance(metadata.get("panel"), Mapping) else {}
    family = (assertion.model_family or "").strip().lower()
    declared = {str(x).strip() for x in (panel.get("lineage") or ()) if str(x).strip()}
    lineage = sorted(declared | ({f"model_family:{family}"} if family else set()))
    # What a reply reported about its own run: it can join readings, and it
    # cannot place one, so it is kept where correlation counts it as shared
    # without counting it as a statement of what generated the reading.
    reported = sorted(f"{key}:{metadata[key]}" for key in ("session", "run_id", "lineage")
                      if isinstance(metadata.get(key), str) and metadata[key].strip())
    return SourceProvenance(source_id=evidence_id, source_kind="evidence",
                            provider=(assertion.provider or "").strip(),
                            model_family=family, model_version=assertion.model_version,
                            verifier=(assertion.model or "").strip().lower(),
                            lineage=tuple(lineage), ancestry=tuple(reported))


def _who(assertion: SemanticAssertion) -> str:
    panel = (assertion.provider_metadata or {}).get("panel")
    member = panel.get("member") if isinstance(panel, Mapping) else ""
    name = f"{assertion.provider or '?'}:{assertion.model or '?'}"
    return f"{member} ({name})" if member else name


# ── disagreement ─────────────────────────────────────────────────────────────

class ReadingDisagreement(str, Enum):
    #: Independent verifiers, the same evidence and state, opposite answers.
    CONTRADICTION = "CONTRADICTION"
    #: Any other disagreement among readings. A person reads them.
    REQUIRES_REVIEW = "REQUIRES_REVIEW"


@dataclass(frozen=True)
class SemanticDisagreement:
    """Readings of one claim that do not agree. Each kept as it was given."""

    claim_id: str
    classification: ReadingDisagreement
    basis: str
    #: One row per reading: who, what, and the probability or confidence it
    #: stated. No row combines another's numbers.
    readings: Tuple[Mapping[str, Any], ...]
    required: Optional[bool] = None

    def to_dict(self) -> Dict[str, Any]:
        return {"claim_id": self.claim_id, "classification": self.classification.value,
                "basis": self.basis, "required": self.required,
                "readings": [dict(r) for r in self.readings]}


def semantic_disagreements(report: Any, records: Iterable[Any], *,
                           independence: IndependencePolicy = READER_INDEPENDENCE_POLICY
                           ) -> List[SemanticDisagreement]:
    """Every claim whose current readings give more than one answer.

    A reading set aside as made against another state, and a question that got
    no answer, are not answers and do not disagree with anything.
    """
    if report is None or not getattr(report, "resolutions", ()):
        return []
    by_claim: Dict[str, List[Tuple[str, SemanticAssertion]]] = {}
    for eid, assertion in assertions_from_records(records):
        by_claim.setdefault(assertion.claim_id, []).append((eid, assertion))
    found: List[SemanticDisagreement] = []
    for resolution in report.resolutions:
        withheld = {i.item_id for i in resolution.items
                    if i.item_kind == "semantic" and i.role.value == "WITHHELD_STATE"}
        answered = sorted(((eid, a) for eid, a in by_claim.get(resolution.claim_id, ())
                           if a.answered and a.verdict is not None and eid not in withheld),
                          key=lambda pair: pair[0])
        verdicts = {a.verdict.value for _, a in answered}
        if len(verdicts) < 2:
            continue
        readers = assess_independence([reading_provenance(eid, a) for eid, a in answered],
                                      independence)
        group_of = {m: g for g in readers.groups for m in g.members}
        classification, basis = _classify(answered, verdicts, group_of)
        rows = tuple({"reading": eid, "verifier": _who(a), "model_family": a.model_family,
                      "verdict": a.verdict.value, "confidence": a.confidence,
                      "probabilities": dict(a.probabilities) if a.probabilities else None,
                      "chosen": a.chosen or None, "packet_hash": a.packet_hash,
                      "reader_group": group_of[eid].group_id,
                      "reader_group_placed": group_of[eid].determinable}
                     for eid, a in answered)
        found.append(SemanticDisagreement(resolution.claim_id, classification, basis, rows,
                                          required=resolution.required))
    return found


def _classify(answered: Sequence[Tuple[str, SemanticAssertion]], verdicts: set,
              group_of: Mapping[str, Any]) -> Tuple[ReadingDisagreement, str]:
    supported = [(e, a) for e, a in answered if a.verdict.value == "supported"]
    contradicted = [(e, a) for e, a in answered if a.verdict.value == "contradicted"]
    opposed = [((x, a), (y, b)) for x, a in supported for y, b in contradicted]
    if any(a.packet_hash == b.packet_hash and a.state_hash == b.state_hash
           and group_of[x] is not group_of[y]
           and group_of[x].determinable and group_of[y].determinable
           for (x, a), (y, b) in opposed):
        return (ReadingDisagreement.CONTRADICTION,
                "independent verifiers read the same evidence about the same state and "
                "reached opposite answers")
    if not opposed:
        return (ReadingDisagreement.REQUIRES_REVIEW,
                "one verifier found the evidence decisive and another found it "
                "insufficient: " + " / ".join(sorted(verdicts)))
    if all(group_of[x] is group_of[y] for (x, _), (y, _) in opposed):
        return (ReadingDisagreement.REQUIRES_REVIEW,
                "readings that share provenance (one model, provider or declared "
                "lineage) answered both ways; the reading is unstable, not a second "
                "opinion")
    if all(a.packet_hash != b.packet_hash or a.state_hash != b.state_hash
           for (_, a), (_, b) in opposed):
        return (ReadingDisagreement.REQUIRES_REVIEW,
                "the opposite answers read different evidence or a different state, so "
                "they are not answers to one question")
    return (ReadingDisagreement.REQUIRES_REVIEW,
            "opposite answers from verifiers whose independence cannot be told: at least "
            "one states no model family or lineage")


# ── the panel ────────────────────────────────────────────────────────────────

#: How a member is reached. The key itself is never in a panel file: it names
#: the environment variable that holds it.
_MEMBER_KEYS = frozenset({"name", "provider", "base_url", "model", "model_family",
                          "dialect", "api_key_env", "cost_per_call", "max_input_chars",
                          "lineage"})


@dataclass(frozen=True)
class PanelMember:
    """One verifier on a panel: its name, how to reach it, and its declared lineage."""

    name: str
    config: Mapping[str, Any] = field(default_factory=dict)
    lineage: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, **dict(self.config), "lineage": list(self.lineage)}


@dataclass(frozen=True)
class SemanticPanel:
    """Verifiers asked the same questions. The first is asked whatever the
    escalation policy selects; the others, the questions about claims in
    `scope`, by default the critical ones."""

    panel_id: str
    members: Tuple[PanelMember, ...]
    scope: EscalationScope = EscalationScope.REQUIRED

    def __post_init__(self) -> None:
        object.__setattr__(self, "scope", EscalationScope(self.scope))
        if not str(self.panel_id or "").strip():
            raise SemanticVerifierError("a semantic panel is named (panel_id)")
        if len(self.members) < 2:
            raise SemanticVerifierError("a panel has at least two verifiers; one is "
                                        "--semantic with RG_SEMANTIC_*")
        names = [m.name for m in self.members]
        if len(set(names)) != len(names) or not all(n.strip() for n in names):
            raise SemanticVerifierError("each verifier on a panel has its own name")

    def to_dict(self) -> Dict[str, Any]:
        return {"schema": SEMANTIC_PANEL_SCHEMA, "panel_id": self.panel_id,
                "scope": self.scope.value, "verifiers": [m.to_dict() for m in self.members]}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "SemanticPanel":
        if not isinstance(data, Mapping):
            raise SemanticVerifierError("a semantic panel is a JSON object")
        if data.get("schema", SEMANTIC_PANEL_SCHEMA) != SEMANTIC_PANEL_SCHEMA:
            raise SemanticVerifierError(f"a semantic panel names {SEMANTIC_PANEL_SCHEMA}, "
                                        f"not {data.get('schema')!r}")
        unknown = sorted(set(data) - {"schema", "panel_id", "scope", "verifiers"})
        if unknown:
            raise SemanticVerifierError(f"unknown panel keys: {', '.join(unknown)}")
        members: List[PanelMember] = []
        for raw in data.get("verifiers") or ():
            if not isinstance(raw, Mapping):
                raise SemanticVerifierError("each panel verifier is an object")
            if "api_key" in raw:
                raise SemanticVerifierError(
                    f"verifier {raw.get('name')!r} carries an api_key; a panel file names "
                    "the environment variable that holds it (api_key_env), never the key")
            extra = sorted(set(raw) - _MEMBER_KEYS)
            if extra:
                raise SemanticVerifierError(
                    f"verifier {raw.get('name')!r} has unknown keys: {', '.join(extra)}")
            if not str(raw.get("model") or "").strip():
                raise SemanticVerifierError(
                    f"verifier {raw.get('name')!r} names no model; release-gate picks none")
            lineage = raw.get("lineage") or ()
            if isinstance(lineage, str):
                lineage = (lineage,)
            members.append(PanelMember(
                name=str(raw.get("name") or ""),
                config={k: raw[k] for k in sorted(raw) if k not in ("name", "lineage")},
                lineage=tuple(str(x) for x in lineage if str(x).strip())))
        try:
            return cls(panel_id=str(data.get("panel_id") or ""), members=tuple(members),
                       scope=EscalationScope(str(data.get("scope")
                                                 or EscalationScope.REQUIRED.value)))
        except ValueError as exc:
            if isinstance(exc, SemanticVerifierError):
                raise
            raise SemanticVerifierError(f"unreadable semantic panel: {exc}") from exc


def tag_reading(assertion: SemanticAssertion, panel: SemanticPanel,
                member: PanelMember) -> SemanticAssertion:
    """The reading, with the panel and the operator's declared lineage on it.

    The tag is part of the reading's identity: the same answer from another
    panel member is another reading.
    """
    metadata = {k: v for k, v in (assertion.provider_metadata or {}).items() if k != "panel"}
    metadata["panel"] = {"panel_id": panel.panel_id, "member": member.name,
                         "lineage": list(member.lineage)}
    return dataclasses.replace(assertion, provider_metadata=metadata)


def plan_panel(resolution: Any, records: Iterable[Any], panel: SemanticPanel,
               members: Mapping[str, Tuple[ProviderIdentity, ProviderCapabilities]], *,
               attempts: Optional[Mapping[str, Any]] = None,
               policy: EscalationPolicy = DEFAULT_ESCALATION_POLICY,
               verifier_policy: SemanticVerifierPolicy = DEFAULT_SEMANTIC_VERIFIER_POLICY,
               state_hash: str = "") -> Tuple[Tuple[str, EscalationPlan], ...]:
    """One escalation plan per verifier, each by the same rules.

    The first member is planned under `policy`; the others under it with the
    panel's scope and no `always` claims. Each counts only its own earlier
    readings as already asked, so a panel member is not turned away because
    another member answered, and none is asked twice. The budget is each
    member's own, at its own declared cost.
    """
    records = list(records)
    plans: List[Tuple[str, EscalationPlan]] = []
    for index, member in enumerate(panel.members):
        identity, capabilities = members[member.name]
        scoped = policy if index == 0 else dataclasses.replace(
            policy, scope=panel.scope, always=())
        plans.append((member.name, plan_escalation(
            resolution, records, attempts=attempts, policy=scoped,
            verifier_policy=verifier_policy, capabilities=capabilities,
            state_hash=state_hash, asked_of=(identity.provider, identity.model))))
    return tuple(plans)

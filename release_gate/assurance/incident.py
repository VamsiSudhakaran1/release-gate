"""Incidents: a failure in operation, held against every later release until answered.

A release that failed in production is the strongest evidence there is that a
claim about it was false. Before this module the only way to say so was a
hand-written `counterexample` row, and nothing tied it to the state that
failed or carried it forward: the next release's submission simply did not
mention it. An `incident` envelope record states the failure once, in the
words of whoever reported it, and the ingest makes it what it is:

* **one evidence record**, an ATTESTATION, DECLARED — the reporter's account,
  disclosure included. It supports and contradicts nothing itself, so the
  failure is not counted twice and an answered incident does not keep
  contradicting its claim;
* **one counterexample per claim and affected state**, FOUND, citing that
  record. Found against a state the candidate is, it stands (VALID: it blocks
  a critical claim). Found against another state, it is STALE and holds the
  case (RG-CEX-004): the candidate moved, and nothing shows the defect gone.
  An incident that names no affected state stands against every candidate.
  An incident that names no claim is its own claim, `rg-incident:<id>`, so a
  failure can never be dropped for want of one.

**Only an answer moves it.** `remediation.status` reads as the counterexample
status it is, and the counterexample's own checks apply:

    open, investigating, mitigated   OPEN — a mitigation is not a fix
    resolved, fixed                  RESOLVED — needs `resolution` and
                                     `resolution_evidence` this case holds
    accepted_risk                    ACCEPTED_RISK — needs `resolution` (the
                                     rationale), `accepted_by`, `reference`; lifts
                                     the block only where the resolution policy
                                     permits documented exceptions
    invalid, not_a_defect            INVALID — needs `resolution` (why)

A resolution that cites evidence this case does not hold is refused and the
incident stays OPEN: so every later release has to carry what answers it, not
just say that something once did. A word outside the table stays OPEN and holds
the case until it is corrected.

`disclosure` — who was told, when, and where it is written down — is recorded
on the evidence and in each counterexample's detail, as stated. Release-gate
does not judge whether a disclosure was adequate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Set, Tuple

from release_gate.assurance.evidence import (
    EpistemicStatus,
    EvidenceRecord,
    EvidenceType,
    Producer,
)

__all__ = [
    "INCIDENT_SCHEMA_VERSION",
    "IncidentError",
    "IncidentRecord",
    "Remediation",
]

INCIDENT_SCHEMA_VERSION = 1

#: The claim an incident is its own claim under, when it names none.
OWN_CLAIM_PREFIX = "rg-incident:"


class IncidentError(ValueError):
    """An incident record that cannot be read as one."""


class Remediation(str, Enum):
    """Where an incident's remediation stands: the counterexample status it is."""

    OPEN = "OPEN"
    RESOLVED = "RESOLVED"
    ACCEPTED_RISK = "ACCEPTED_RISK"
    INVALID = "INVALID"


_REMEDIATION_WORDS = {
    "open": Remediation.OPEN, "investigating": Remediation.OPEN,
    "mitigated": Remediation.OPEN, "monitoring": Remediation.OPEN,
    "resolved": Remediation.RESOLVED, "fixed": Remediation.RESOLVED,
    "accepted_risk": Remediation.ACCEPTED_RISK, "accepted": Remediation.ACCEPTED_RISK,
    "invalid": Remediation.INVALID, "not_a_defect": Remediation.INVALID,
}


def _text(value: Any) -> str:
    return str(value).strip() if isinstance(value, (str, int, float)) and not isinstance(
        value, bool) else ""


def _ids(value: Any) -> Tuple[str, ...]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(dict.fromkeys(_text(v) for v in value if _text(v)))


def _block(value: Any) -> Dict[str, Any]:
    return {str(k): v for k, v in value.items()} if isinstance(value, Mapping) else {}


@dataclass(frozen=True)
class IncidentRecord:
    """One failure, as its reporter states it."""

    incident_id: str
    title: str = ""
    severity: str = ""
    claims: Tuple[str, ...] = ()
    affected_states: Tuple[Mapping[str, Any], ...] = ()
    occurred_at: str = ""
    detected_at: str = ""
    reported_by: str = ""
    description: str = ""
    reference: str = ""
    disclosure: Mapping[str, Any] = field(default_factory=dict)
    remediation: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not _text(self.incident_id):
            raise IncidentError("an incident names its incident_id: a failure nobody "
                                "can refer to cannot be answered")
        object.__setattr__(self, "incident_id", _text(self.incident_id))

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "IncidentRecord":
        if not isinstance(data, Mapping):
            raise IncidentError("an incident is an object")
        states = data.get("affected_states")
        if isinstance(states, Mapping):
            states = [states]
        return cls(
            incident_id=_text(data.get("incident_id") or data.get("id")),
            title=_text(data.get("title")), severity=_text(data.get("severity")),
            claims=_ids(data.get("claims") or data.get("claim_id")),
            affected_states=tuple(_block(s) for s in (states or ())
                                  if isinstance(s, Mapping)),
            occurred_at=_text(data.get("occurred_at")),
            detected_at=_text(data.get("detected_at")),
            reported_by=_text(data.get("reported_by")),
            description=_text(data.get("description")),
            reference=_text(data.get("reference")),
            disclosure=_block(data.get("disclosure")),
            remediation=_block(data.get("remediation")))

    def to_dict(self) -> Dict[str, Any]:
        return {"incident_id": self.incident_id, "title": self.title,
                "severity": self.severity, "claims": list(self.claims),
                "affected_states": [dict(s) for s in self.affected_states],
                "occurred_at": self.occurred_at, "detected_at": self.detected_at,
                "reported_by": self.reported_by, "description": self.description,
                "reference": self.reference, "disclosure": dict(self.disclosure),
                "remediation": dict(self.remediation),
                "schema_version": INCIDENT_SCHEMA_VERSION}

    # ── what it becomes ─────────────────────────────────────────────────────

    @property
    def own_claim_id(self) -> str:
        return f"{OWN_CLAIM_PREFIX}{self.incident_id}"

    @property
    def targets(self) -> Tuple[str, ...]:
        return self.claims or (self.own_claim_id,)

    @property
    def own_claim_statement(self) -> str:
        about = f" ({self.title})" if self.title else ""
        return f"incident {self.incident_id}{about} does not recur in this release"

    def disclosure_words(self) -> str:
        status = _text(self.disclosure.get("status"))
        if not status:
            return "disclosure not stated"
        to = _text(self.disclosure.get("to"))
        where = _text(self.disclosure.get("reference"))
        return (f"disclosure {status}" + (f" to {to}" if to else "")
                + (f" ({where})" if where else ""))

    def to_record(self, *, producer: Producer, source: str) -> EvidenceRecord:
        """The reporter's account: an ATTESTATION, DECLARED, bearing on no claim itself."""
        return EvidenceRecord.from_producer(
            {"incident": self.to_dict()},
            evidence_type=EvidenceType.ATTESTATION, source=source, producer=producer,
            status=EpistemicStatus.DECLARED,
            coverage_note=(f"incident {self.incident_id} as reported"
                           + (f" by {self.reported_by}" if self.reported_by else "")
                           + f"; {self.disclosure_words()}. The failure is carried by "
                             "its counterexamples; this record is the account"))

    def remediation_status(self) -> Tuple[Remediation, str]:
        """The status, and the word it was read from when that word is not one."""
        word = _text(self.remediation.get("status")).lower().replace("-", "_") \
            .replace(" ", "_")
        if not word:
            return Remediation.OPEN, ""
        known = _REMEDIATION_WORDS.get(word)
        return (known, "") if known is not None else (Remediation.OPEN, word)

    def counterexample_rows(self, record_id: str, *, resolve: Mapping[str, str],
                            held: Set[str], unread: Optional[List[str]] = None,
                            valid_state: Any = None) -> List[Dict[str, Any]]:
        """One `counterexample` row per claim and affected state, citing `record_id`.

        `resolve` maps an id the envelope declared to the evidence id it was built
        under; `held` is every evidence id the case holds. A resolution citing
        anything else is refused. `valid_state(state) -> str` returns why a state
        cannot be read as candidate components, or an empty string.
        """
        status, unread_word = self.remediation_status()
        where = f"incident {self.incident_id}"
        if unread_word and unread is not None:
            unread.append(f"{where}: remediation status {unread_word!r} is not one "
                          "release-gate reads (open, mitigated, resolved, accepted_risk, "
                          "invalid); it stays OPEN")
        answer: Dict[str, Any] = {}
        cited = _ids(self.remediation.get("resolution_evidence"))
        if status is Remediation.RESOLVED:
            missing = [c for c in cited if c not in resolve and c not in held]
            if missing:
                if unread is not None:
                    unread.append(
                        f"{where}: the resolution cites {', '.join(missing)}, which this "
                        "case does not hold; a release answers an incident with "
                        "evidence it carries, so it stays OPEN")
                status = Remediation.OPEN
            else:
                answer["resolution_evidence"] = [resolve.get(c, c) for c in cited]
        if status is not Remediation.OPEN:
            answer["status"] = status.value
            answer["resolution"] = _text(self.remediation.get("resolution"))
        if status is Remediation.ACCEPTED_RISK:
            answer.update(accepted_by=_text(self.remediation.get("accepted_by")),
                          reference=_text(self.remediation.get("reference")),
                          accepted_for=_block(self.remediation.get("accepted_for")))
        if status is Remediation.OPEN:
            answer["status"] = Remediation.OPEN.value

        states: List[Dict[str, Any]] = []
        for state in self.affected_states:
            why = valid_state(state) if valid_state is not None else ""
            if why:
                if unread is not None:
                    unread.append(f"{where}: an affected state could not be read ({why}); "
                                  "the failure is kept against every state instead")
                state = {}
            if dict(state) not in states:
                states.append(dict(state))
        if not states:
            states = [{}]
        detail = "; ".join(x for x in (
            f"incident {self.incident_id}" + (f": {self.title}" if self.title else ""),
            f"severity {self.severity}" if self.severity else "",
            f"reported by {self.reported_by}" if self.reported_by else "",
            self.disclosure_words(),
            self.reference) if x)
        rows = []
        for claim in self.targets:
            for state in states:
                rows.append({"target_claim": claim, "result": "FOUND", "method": "OTHER",
                             "evidence": [record_id], "searched": "in operation",
                             "detail": detail, **({"state": state} if state else {}),
                             **({"attempted_at": self.detected_at or self.occurred_at}
                                if (self.detected_at or self.occurred_at) else {}),
                             **answer})
        return rows

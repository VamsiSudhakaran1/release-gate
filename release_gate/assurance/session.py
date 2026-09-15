"""The incremental flow: open a case, add records, finalize, read the decision.

`assure()` answers "here is a file, what do you make of it" in one call. That is
the right shape for CI and for a person at a terminal, and the wrong shape for an
agent that produces evidence as it works and wants to ask, part-way through, what
is still missing. This module is that second shape:

    session = AssuranceSession.open()
    session.add(evidence_record)          # POST .../evidence
    session.required_evidence()           # GET  .../required-evidence, while open
    outcome = session.finalize()          # POST .../finalize
    outcome.decision                      # GET  .../decision

**No configuration, and no files.** A session needs nothing on disk: not a
methodology file, not a config file, not a case directory. It holds records in
memory and produces a sealed case. Everything optional stays optional.

**The same code as the one-shot path.** `finalize()` normalises the accumulated
records exactly as the file reader normalises a document, then calls
`assure_normalisation` — the same function `assure()` calls. The protocol spec
requires that a case built locally and a case built through the API from the same
records produce the same `case_digest` (§15), and the wire format *is* the file
format, so this is one implementation rather than two that agree until someone
edits one of them.

**Finalize is a boundary, not a formality.** Records added after it are refused:
a decision names the exact state it was taken on, and a case that kept accepting
evidence after being decided would make its own approval unfalsifiable
(Invariant 5).
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from release_gate.assurance.ingest import Normalisation, detect_document, normalise
from release_gate.assurance.methodology import AssuranceMethodology

SESSION_SCHEMA_VERSION = 1


#: Collections holding records a client supplied, as opposed to conclusions
#: release-gate derived. Parity is a claim about the former.
_SUBMITTED_KINDS = ("evidence", "claims", "artifacts", "executions", "verification")


def records_digest(case: Any) -> str:
    """A digest over the records a client submitted, ignoring how they arrived.

    **This, not `case_digest`, is the parity anchor between the file path and the
    session path.** The protocol spec once claimed the two produce the same
    `case_digest`; they do not, and making them would mean lying about
    provenance. Release-gate records the input container as evidence in its own
    right — a file on disk is a FILE content reference with a path, and records
    posted over a wire are an INLINE reference with no path — and those are
    genuinely different inputs. Fabricating a file reference for a submission
    that never touched a disk would be exactly the assertion-over-evidence this
    system refuses (Invariants 1 and 11).

    What *is* equal, and what the parity claim was reaching for, is this: the
    records the client supplied fold identically, and the decision is the same.
    A local reproduction can therefore check a hosted decision by comparing this
    digest and the verdict, which is the property that matters.

    `created_at` is excluded because it records when a record was built, not what
    it says, and two runs of the same records are not different evidence for
    having happened at different times.

    Parity holds for the same records under the same `source`. That is not a
    loophole: `source` is provenance, it flows into every derived evidence id,
    and two submissions that came from different places genuinely are different
    evidence. A caller wanting to reproduce a hosted decision locally names the
    source the same way, which is the same discipline as reproducing any build.
    """
    from release_gate.assurance.canonical import digest_items
    items = []
    for kind in _SUBMITTED_KINDS:
        for record in case.collection(kind).materialised:
            payload = record.to_dict() if hasattr(record, "to_dict") else dict(record)
            roles = {(payload.get("content") or {}).get("role"),
                     (payload.get("metadata") or {}).get("role")}
            if "assurance-input" in roles:
                # Release-gate's own note about the container the records
                # arrived in — the evidence record AND the artifact, which
                # carries its role in `metadata` rather than `content`. Not
                # client records, and the one thing that legitimately differs
                # between the two paths.
                continue
            payload.pop("created_at", None)
            items.append({"collection": kind, "record": payload})
    return digest_items(items)


class SessionError(RuntimeError):
    """A session was used out of order."""


@dataclass
class AssuranceSession:
    """An open case accumulating records, and the decision it becomes.

    Deliberately mutable — it models a conversation that happens over time, and
    a frozen object would make every `add` a copy of the whole record set. The
    *result* of `finalize()` is the immutable thing: a sealed case with a digest.
    """

    source_name: str = "session"
    methodology: Optional[AssuranceMethodology] = None
    objective: Optional[str] = None
    requested_decision: Optional[str] = None
    requested_action: Optional[str] = None
    records: List[Any] = field(default_factory=list)
    _outcome: Optional[Any] = field(default=None, repr=False)

    @classmethod
    def open(cls, *, source_name: str = "session",
             methodology: Optional[AssuranceMethodology] = None,
             objective: Optional[str] = None,
             requested_decision: Optional[str] = None,
             requested_action: Optional[str] = None) -> "AssuranceSession":
        """Start a case. Nothing is required, including a methodology.

        With no methodology the case will report METHODOLOGY_REQUIRED and hold,
        which is the honest answer rather than a missing feature: structural
        analysis can say what the evidence is, and "enough for this decision" is
        a domain question nobody has answered yet.
        """
        return cls(source_name=source_name, methodology=methodology,
                   objective=objective, requested_decision=requested_decision,
                   requested_action=requested_action)

    # ── while open ──────────────────────────────────────────────────────────

    @property
    def finalized(self) -> bool:
        return self._outcome is not None

    def _require_open(self, what: str) -> None:
        if self.finalized:
            raise SessionError(
                f"this case is already finalized; {what} would change the state a "
                "decision was taken on, and an approval that does not bind to an "
                "exact state is unfalsifiable. Open a new session, or revise the "
                "case explicitly.")

    def add(self, record: Any) -> "AssuranceSession":
        """Add one record. The wire format is the file format (protocol §15)."""
        self._require_open("adding a record")
        self.records.append(record)
        return self

    def extend(self, records: Sequence[Any]) -> "AssuranceSession":
        """Add many records. Equivalent to `add` in a loop, and cheaper to read."""
        self._require_open("adding records")
        self.records.extend(records)
        return self

    def __len__(self) -> int:
        return len(self.records)

    def provisional(self) -> Any:
        """Assure the records so far WITHOUT finalizing.

        This is `GET /required-evidence` on an open case: the steering signal a
        running agent reads to find out what is still missing. It runs the full
        analysis, so it is not free, and it settles nothing — the case stays open
        and the outcome it returns is not a decision anybody may act on.
        """
        return self._assure()

    def required_evidence(self) -> Any:
        """What would resolve this case as it currently stands."""
        return self.provisional().required_evidence

    def attention(self) -> Any:
        """What a human would need to look at if this were decided now."""
        return self.provisional().attention

    # ── the boundary ────────────────────────────────────────────────────────

    def finalize(self) -> Any:
        """Seal the case and decide it. Idempotent.

        Calling it twice returns the same outcome rather than re-deciding: a
        decision is a fact about a state, and re-running it would invite two
        different answers over one case.
        """
        if self._outcome is None:
            self._outcome = self._assure()
        return self._outcome

    @property
    def outcome(self) -> Any:
        if self._outcome is None:
            raise SessionError(
                "this case has not been finalized, so it has no decision. Call "
                "finalize(), or use provisional() for a view of an open case.")
        return self._outcome

    @property
    def decision(self) -> Any:
        """The verdict. Refuses on an open case, as `GET /decision` does."""
        return self.outcome.decision

    # ── the shared path ─────────────────────────────────────────────────────

    def _assure(self) -> Any:
        from release_gate.assurance.zero_config import assure_normalisation
        return assure_normalisation(
            self._normalise(), source_name=self.source_name,
            source_path=Path(self.source_name),
            methodology=self.methodology, objective=self.objective,
            requested_decision=self.requested_decision,
            requested_action=self.requested_action)

    def _normalise(self) -> Normalisation:
        """Normalise the accumulated records exactly as a file would be.

        The records are handed to `detect_document` as the list they are, which
        is the same shape the NDJSON reader produces, so detection, mapping and
        every downstream digest match a file carrying the same records.
        """
        import json
        doc = self._document()
        detection = detect_document(doc, filename=self.source_name)
        # The session's own bytes, so the subject carries a real OBSERVED digest
        # rather than borrowing one from a file that does not exist. Canonical
        # (sorted keys, no incidental whitespace) so the same records in the same
        # order always hash the same, whoever assembled them.
        content = json.dumps(doc, sort_keys=True, default=str).encode("utf-8")
        return normalise(doc, detection, source=self.source_name, content=content)

    def _document(self) -> Any:
        """The accumulated records as one document.

        Records are emitted as plain dicts where they know how, so a session fed
        typed objects and a session fed the JSON those objects serialise to
        produce the same document and therefore the same case digest.
        """
        out: List[Any] = []
        for record in self.records:
            if isinstance(record, Mapping):
                out.append(dict(record))
            elif hasattr(record, "to_dict"):
                out.append(record.to_dict())
            else:
                out.append(record)
        return out

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "assurance_session",
                "source_name": self.source_name,
                "records": len(self.records),
                "finalized": self.finalized,
                "methodology": (self.methodology.ref_string
                                if self.methodology is not None else None),
                "decision": (self._outcome.decision.value
                             if self._outcome is not None else None),
                "schema_version": SESSION_SCHEMA_VERSION}

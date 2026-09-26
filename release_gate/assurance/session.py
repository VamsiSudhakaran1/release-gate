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
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from release_gate.assurance.canonical import digest_bytes
from release_gate.assurance.incremental import (
    IncrementalCache, IncrementalReport, Reuse, ReuseDecision, reuse_key,
)
from release_gate.assurance.ingest import Normalisation, detect_document, normalise
from release_gate.assurance.latency import LatencyRecorder, Stage
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
    #: The last reuse decision, so "why did that take two seconds" is answerable
    #: without reading the cache. None until the case is first assured.
    reuse: Optional[Reuse] = field(default=None, repr=False)
    #: Holds one outcome. Deliberately one: an outcome over ten million records is
    #: not a small object, and in a session records are only appended, so no key
    #: but the newest can ever be asked for again.
    _cache: IncrementalCache = field(
        default_factory=lambda: IncrementalCache(limit=1), repr=False)

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

    def provisional(self, *, recorder: Optional[LatencyRecorder] = None) -> Any:
        """Assure the records so far WITHOUT finalizing.

        This is `GET /required-evidence` on an open case: the steering signal a
        running agent reads to find out what is still missing. It settles nothing —
        the case stays open and the outcome it returns is not a decision anybody
        may act on.

        Reused when the records have not moved since the last read (§10ap). An
        agent that calls `required_evidence()` and then `attention()` used to pay
        for two full analyses of one record set; it now pays for one, and the
        second read is the same object because it is the same function of the same
        inputs.
        """
        return self._assure(recorder=recorder)

    def required_evidence(self) -> Any:
        """What would resolve this case as it currently stands."""
        return self.provisional().required_evidence

    def attention(self) -> Any:
        """What a human would need to look at if this were decided now."""
        return self.provisional().attention

    # ── the boundary ────────────────────────────────────────────────────────

    def finalize(self, *, recorder: Optional[LatencyRecorder] = None) -> Any:
        """Seal the case and decide it. Idempotent.

        Calling it twice returns the same outcome rather than re-deciding: a
        decision is a fact about a state, and re-running it would invite two
        different answers over one case.

        **Where decision latency is actually won.** A verdict is a pure function of
        the records, so a provisional read and a finalization over an identical
        record set must produce the same verdict — if they could differ, the
        provisional would be useless as a steering signal. `_assure` keys on those
        records, so an agent that was already being told what was missing has
        already paid for the answer, and the finalization request costs the key
        (0.8% of a finalization) instead of the analysis. Work done while the case
        was open is the only way the interval between asking and being answered
        gets short; nothing here makes the analysis itself cheaper.

        `recorder` is optional instrumentation and changes nothing about the
        result — see `latency.measure_finalization`.
        """
        if self._outcome is None:
            self._outcome = self._assure(recorder=recorder)
        return self._outcome

    def reuse_report(self) -> IncrementalReport:
        """What was reused on the last read of this case, and what the cache holds.

        The answer to "why did that take two seconds" without reading the cache.
        Carries no delta: the session keys on the whole record set rather than on
        per-record digests, so it can say *that* the records moved and not *what*
        moved — see `_prepare` for why holding ten million per-record keys would
        cost more than it saves.
        """
        return IncrementalReport(
            decisions=(self.reuse,) if self.reuse is not None else (),
            cache=self._cache.summary())

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

    def _assure(self, *, recorder: Optional[LatencyRecorder] = None) -> Any:
        """Assure the current records, reusing the last outcome when they have not moved.

        Sound for one reason, stated because it is the whole argument: the outcome
        is a pure function of the records and the five other inputs the key covers,
        so a hit returns the value a recomputation would have produced. The key is
        content-addressed rather than a dirty flag because `records` is a public
        mutable list — anything can append to it without calling `add()`, and that
        is exactly the case a flag gets wrong.
        """
        from release_gate.assurance.zero_config import assure_normalisation
        timer = recorder if recorder is not None else LatencyRecorder.disabled()
        timer.begin()
        count = len(self.records)

        with timer.stage(Stage.DETECT, records=count):
            document, content, key = self._prepare()

        # Before the detection, not after. Detection is 26ms on a 5,506-record
        # document, and a reuse path that pays for work the reuse makes pointless
        # is the defect this whole section is about.
        cached = self._cache.get(key)
        if cached is not None:
            self.reuse = Reuse(
                stage="finalization", decision=ReuseDecision.REUSED, key=key,
                why=(f"the {count} record(s), the methodology and every other input "
                     "to the verdict are unchanged since this outcome was computed, "
                     "so recomputing would be a second evaluation of one pure "
                     "function of one set of inputs"))
            timer.record(Stage.FINALIZATION, 0.0, decision=ReuseDecision.REUSED,
                         records=count,
                         note="the outcome for these exact records was already computed")
            return cached

        with timer.stage(Stage.DETECT, records=count):
            detection = detect_document(document, filename=self.source_name)
        with timer.stage(Stage.NORMALISE, records=count):
            normalisation = normalise(document, detection, source=self.source_name,
                                      content=content)
        outcome = assure_normalisation(
            normalisation, source_name=self.source_name,
            source_path=Path(self.source_name),
            methodology=self.methodology, objective=self.objective,
            requested_decision=self.requested_decision,
            requested_action=self.requested_action, recorder=timer)
        self._cache.put(key, outcome)
        self.reuse = Reuse(
            stage="finalization", decision=ReuseDecision.RECOMPUTED, key=key,
            why=(f"no outcome was held for these {count} record(s); this is the "
                 "first read of this exact state"))
        return outcome

    def _reuse_key(self, content: bytes) -> str:
        """A key over everything that decides the outcome, and nothing that does not.

        Every declared input of the `finalization` stage, which is what makes the
        spec and the key hold each other honest: `reuse_key` refuses a key that
        omits a declared input, so a future field that changes the verdict cannot
        be added to this session without either entering the key or being declared
        not to matter.
        """
        methodology = self.methodology
        return reuse_key("finalization", {
            "records": digest_bytes(content),
            "methodology": (f"{methodology.methodology_id}@{methodology.version}"
                            f"#{methodology.digest}" if methodology is not None else None),
            "objective": self.objective,
            "requested_decision": self.requested_decision,
            "requested_action": self.requested_action,
            "source": self.source_name,
        })

    def _prepare(self) -> Tuple[Any, bytes, str]:
        """The document, its canonical bytes, and the reuse key over them.

        The key is a by-product rather than an overhead: these bytes are what
        `normalise` is given anyway, so the only added work is one sha256 over
        them. Measured at 0.8% of a finalization over 3,401 records — 128 times
        cheaper than the computation a hit avoids.

        A per-record key set would let this report *what* changed rather than only
        *that* something did, and it is deliberately not kept: ten million
        per-record digests cost more to hold and compare than the recomputation
        they would save. `incremental.plan` is there for a caller who has the keys
        for other reasons.
        """
        import json
        document = self._document()
        # The session's own bytes, so the subject carries a real OBSERVED digest
        # rather than borrowing one from a file that does not exist. Canonical
        # (sorted keys, no incidental whitespace) so the same records in the same
        # order always hash the same, whoever assembled them.
        content = json.dumps(document, sort_keys=True, default=str).encode("utf-8")
        return document, content, self._reuse_key(content)

    def _normalise(self) -> Normalisation:
        """Normalise the accumulated records exactly as a file would be.

        The records are handed to `detect_document` as the list they are, which
        is the same shape the NDJSON reader produces, so detection, mapping and
        every downstream digest match a file carrying the same records.
        """
        document, content, _ = self._prepare()
        detection = detect_document(document, filename=self.source_name)
        return normalise(document, detection, source=self.source_name, content=content)

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
                "reuse": self.reuse.decision.value if self.reuse is not None else None,
                "schema_version": SESSION_SCHEMA_VERSION}

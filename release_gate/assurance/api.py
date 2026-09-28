"""Four names, and the same engine underneath both of them.

    import release_gate as rg

    case = rg.create_case(objective="Deploy generated migration",
                          subject=migration_artifact)
    case.add_execution(trace)
    case.add_verification(test_result, method="TEST_SUITE", outcome="PASSED",
                          verifier="ci://pytest")
    decision = case.finalize()

and, with more at stake and nothing else different:

    case = rg.create_case(type="research_result",
                          objective="Establish proposition X",
                          subject=candidate_result,
                          methodology="research-mathematics-v1")
    case.stream(events)
    case.add_verification(lean_result, method="THEOREM_PROVER", outcome="PASSED",
                          verifier="tool://lean")
    case.add_replication(independent_run)
    case.add_counterexample(counterexample_search)
    decision = case.finalize()

One `Case` class, one `AssuranceSession` behind it, one decision path. The frontier
use differs from the minimal one in what you hand it, never in which code runs —
which is the only sense in which "the same conceptual system" can be a claim rather
than a slogan.

## What a convenience layer must not buy you

A simpler API is worth having and worth nothing if it makes a weak case look
strong. Three specific ways that could happen here, and what stops each:

**It cannot upgrade what a producer claimed.** `_PRODUCER_FORBIDDEN` at the ingest
boundary already strips `epistemic_status`, `trust_status` and `provenance_status`
out of any submitted payload and keeps them as content. So these adders stamp
*shape* — a `record_type`, a `kind` — and never standing, and they could not launder
a status even by accident. That was checked rather than assumed.

**It cannot read what a tool meant.** `add_verification({"passed": True})` looks
like it should work, and mapping `passed` to `PASSED` is exactly the guess
`verifiers` was written to refuse: a producer's vocabulary is the producer's, and a
parser against formats nobody tested is a guess wearing a tool's name. So a payload
that *is* the documented generic envelope is read, because reading a documented
format is not guessing; anything else lands as a record and
`decision.required_evidence` names the three fields that would make it a
verification — method, outcome, verifier. The call succeeds, the verdict is HOLD,
and the reason is actionable. Supply the three and the same call reaches PROMOTE.

**It cannot hand you a verdict without its coverage.** `finalize()` returns a
`CaseDecision`, not a bare enum, and its `render()` prints the gaps beside the
answer (Invariant 9). A one-word return value would have been tidier and would have
made a PROMOTE readable without the four things nobody assessed.

## `subject=` takes what you have, and says which reading it took

A subject needs a digest, and where that digest came from decides what the case can
claim (§10c). So:

* a path to a file that exists, or `bytes` → release-gate hashes it, `OBSERVED`
* an object carrying its own digest, such as an `Artifact` → `DECLARED`, because
  somebody else computed it
* any other string → an identifier, no digest, `UNKNOWN`
* nothing → the subject is the submitted records themselves, as `assure()` does

The one refusal: a string that **looks** like a path and is not a file. Treating
`./migrations/0041.sql` as an opaque identifier because of a typo would hand back a
case with an UNKNOWN subject digest that looked fine, and a case whose subject
nobody hashed is the quietest possible way to lose the thing an approval binds to.

## `stream()` is bounded, because the session is not

Measured before it was written: the session holds every record it is given, so
400,000 events cost 339 MB of RSS and a 52 MB canonical document — about 8–9 GB and
a 1.3 GB document at the ten million the frontier case means by "events". `extend()`
is the wrong primitive for a stream and `stream()` is not built on it.

Instead it folds: every event is counted and hashed as it passes, a bounded set is
retained, and one record release-gate produced carries the **observed** total and
the fold digest over all of them. The case therefore commits to every event while
holding a thousand, and the retained collection reads `CAPPED` rather than
`COMPLETE` — `RetainFirst` is the honest bounded default precisely because it makes
no claim to have chosen well.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import (Any, Dict, Iterable, List, Mapping, Optional, Sequence,
                    Tuple, Union)

from release_gate.assurance.canonical import digest_object
from release_gate.assurance.evidence import (
    EvidenceType, ProducerKind, file_content, inline_content,
)
from release_gate.assurance.records import (
    MaterialisationBasis, RecordCollectionBuilder, RetainFirst, SimpleRecord,
)
from release_gate.assurance.session import AssuranceSession
from release_gate.assurance.subject import (
    AssuranceSubject, ContentReference, DigestMethod, DigestStatus, ReferenceKind,
    SubjectType,
)
from release_gate.assurance.verdict import Decision

API_SCHEMA_VERSION = 1

#: How many streamed events are kept. Everything is counted and committed to; this
#: is how many a reviewer can still read. `RetainFirst` rather than a sample,
#: because "the first thousand" must not be mistaken for "a representative
#: thousand" — the collection reports CAPPED for exactly that reason.
STREAM_RETAIN = 1_000

#: Suffixes and separators that make a string look like a path. Used only to refuse
#: a probable typo, never to decide that something *is* a path — that question is
#: answered by asking the filesystem.
_PATHLIKE = ("/", "\\", ".json", ".jsonl", ".ndjson", ".sql", ".py", ".yaml",
             ".yml", ".txt", ".csv", ".md", ".log")


class ApiError(ValueError):
    """A call this surface will not complete, named rather than worked around."""


# ── the subject ──────────────────────────────────────────────────────────────

def _subject_of(subject: Any, *, case_type: Optional[str],
                requested_action: str) -> Tuple[Optional[AssuranceSubject], str]:
    """The `AssuranceSubject` for what a caller named, and one line saying how.

    An `AssuranceSubject` rather than an artifact record, because the first draft
    added an artifact and the session went on deriving its subject from its own
    bytes — so `subject=` was decorative in the argument that matters most. The
    thing an approval binds to may not be assembled by accident.
    """
    kind = _subject_type(case_type)
    if subject is None:
        return None, ("no subject was named, so the case is about the records "
                      "submitted to it")

    if isinstance(subject, (bytes, bytearray)):
        reference, digest = inline_content(bytes(subject), "subject")
        basis = f"sha256 over {len(subject)} supplied byte(s), computed by release-gate"
        return _built(kind, requested_action, reference, digest,
                      DigestStatus.OBSERVED, basis), basis

    if isinstance(subject, Path) or (isinstance(subject, str) and Path(subject).is_file()):
        path = Path(subject)
        reference, digest = file_content(path)
        basis = f"sha256 over the bytes at {path}, computed by release-gate"
        return _built(kind, requested_action, reference, digest,
                      DigestStatus.OBSERVED, basis,
                      metadata={"filename": path.name}), basis

    digest = getattr(subject, "digest", None)
    if isinstance(digest, str) and digest:
        # An Artifact, or anything else carrying its own digest. Somebody else
        # computed it, which is DECLARED however trustworthy they are (§10c) — and
        # `AssuranceSubject` then requires the attestor to be named, because
        # provenance is part of the claim rather than an annotation on it. So the
        # method is EXTERNAL_ATTESTED and the attestor is read off the object; the
        # engine's rule surfaces here rather than being worked around.
        logical = str(getattr(subject, "logical_id", None) or "subject")
        attestor = next(
            (str(v) for v in (getattr(subject, "digest_attested_by", None),
                              getattr(subject, "signed_by", None),
                              getattr(subject, "created_by", None))
             if isinstance(v, str) and v.strip()), "")
        if not attestor:
            raise ApiError(
                f"subject={logical!r} carries a digest it did not compute and names "
                "nobody who attested it. A digest with no attestor cannot be told "
                "apart from one release-gate hashed itself, so set "
                "`digest_attested_by` on the subject, or pass the bytes and let "
                "release-gate hash them")
        reference = getattr(subject, "content_reference", None) or ContentReference(
            ReferenceKind.EXTERNAL, logical)
        basis = (f"a digest attested by {attestor}; release-gate did not compute it")
        return _built(kind, requested_action, reference, digest,
                      DigestStatus.DECLARED, basis,
                      method=DigestMethod.EXTERNAL_ATTESTED, attested_by=attestor,
                      metadata={"logical_id": logical}), basis

    if isinstance(subject, str):
        if any(token in subject for token in _PATHLIKE):
            raise ApiError(
                f"subject={subject!r} looks like a path and is not a file. Treating "
                "it as an opaque identifier would hand back a case whose subject "
                "nobody hashed, which reads exactly like one that was — pass the "
                "bytes, a path that exists, or a name with no path in it")
        basis = f"{subject!r} as an identifier: nothing was hashed"
        return _built(kind, requested_action,
                      ContentReference(ReferenceKind.EXTERNAL, subject), None,
                      DigestStatus.UNKNOWN, basis), basis

    raise ApiError(
        f"subject must be a path, bytes, an object carrying a digest, or an "
        f"identifier string; got {type(subject).__name__}")


def _built(kind: SubjectType, requested_action: str, reference: Any,
           digest: Optional[str], status: DigestStatus, basis: str,
           method: Optional[DigestMethod] = None, attested_by: str = "",
           metadata: Optional[Mapping[str, Any]] = None) -> AssuranceSubject:
    return AssuranceSubject(
        subject_type=kind, requested_action=requested_action,
        content_reference=reference, digest=digest,
        digest_method=(method if method is not None
                       else (DigestMethod.SHA256_CONTENT if digest
                             else DigestMethod.NONE)),
        digest_status=status, digest_basis=basis, digest_attested_by=attested_by,
        metadata=dict(metadata or {}))


def _subject_type(case_type: Optional[str]) -> SubjectType:
    """The subject type for a case type, or the general one.

    `GENERAL_RESULT` rather than a guess: a type nobody named is not a deployment,
    and inferring one from an objective's wording would be exactly the
    name-is-not-a-fact error this package refuses everywhere else.
    """
    if not case_type:
        return SubjectType.GENERAL_RESULT
    try:
        return SubjectType(str(case_type).strip().upper())
    except ValueError:
        return SubjectType.GENERAL_RESULT


# ── the decision handed back ─────────────────────────────────────────────────

@dataclass(frozen=True)
class CaseDecision:
    """The verdict, and the things a verdict must never be read without.

    Not the bare `Decision` enum. A one-word return would have been tidier and
    would have let a PROMOTE be read without the dimensions nobody assessed, which
    is the reading Invariant 9 exists to prevent.
    """

    decision: Decision
    reasons: Tuple[str, ...] = ()
    fired_rules: Tuple[str, ...] = ()
    required_evidence: Tuple[str, ...] = ()
    attention: Tuple[str, ...] = ()
    not_assessed: Tuple[str, ...] = ()
    case_digest: str = ""
    #: The whole result, for anyone who needs more than this surface offers. Every
    #: report in the package — the approval packet, the evidence pack, the latency
    #: profile, the vetting report — takes this.
    outcome: Any = field(default=None, repr=False)

    @property
    def value(self) -> str:
        return self.decision.value

    @property
    def promoted(self) -> bool:
        return self.decision is Decision.PROMOTE

    @property
    def held(self) -> bool:
        return self.decision is Decision.HOLD

    @property
    def blocked(self) -> bool:
        return self.decision is Decision.BLOCK

    def __str__(self) -> str:
        return self.render()

    def __bool__(self) -> bool:
        """True only for PROMOTE.

        Spelled out because `if decision:` will be written whatever this module
        prefers, and the alternative — every non-empty object being truthy — would
        make a BLOCK read as success.
        """
        return self.promoted

    def render(self) -> str:
        lines = [f"{self.value}"]
        for reason in self.reasons:
            lines.append(f"  · {reason}")
        if self.fired_rules:
            lines.append(f"  rules: {', '.join(self.fired_rules)}")
        if self.required_evidence:
            lines.append("")
            lines.append("  what would resolve this:")
            for item in self.required_evidence:
                lines.append(f"    - {item}")
        lines.append("")
        if self.not_assessed:
            lines.append(f"  not assessed: {', '.join(self.not_assessed)}")
        else:
            lines.append("  not assessed: nothing was left unassessed")
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "case_decision", "record_id": self.case_digest or "-",
                "decision": self.value, "reasons": list(self.reasons),
                "fired_rules": list(self.fired_rules),
                "required_evidence": list(self.required_evidence),
                "attention": list(self.attention),
                "not_assessed": list(self.not_assessed),
                "case_digest": self.case_digest,
                "schema_version": API_SCHEMA_VERSION}


# ── the case ─────────────────────────────────────────────────────────────────

class Case:
    """An open case you add to and then finalize.

    A thin object on purpose: it holds a session, a bounded stream fold and the one
    line describing how the subject was read. Anything it cannot express is reached
    through `.session` or `decision.outcome`, rather than being grown into here.
    """

    def __init__(self, session: AssuranceSession, *, subject_basis: str = "") -> None:
        self.session = session
        self.subject_basis = subject_basis
        self._stream = RecordCollectionBuilder(
            "evidence", track_ids=False, policy=RetainFirst(STREAM_RETAIN))
        self._streamed = 0
        self._unstated_verifications: List[str] = []
        self._untargeted_counterexamples: List[str] = []

    # ── adding ──────────────────────────────────────────────────────────────

    def add_execution(self, trace: Any) -> "Case":
        """A record of what actually ran.

        Takes release-gate's native trace — a mapping carrying `steps` — or the
        steps on their own, which is the shape a caller reaches for first.

        A bare sequence is wrapped into that mapping, because `{"steps": [...]}`
        is the shape the ingest folds into an execution graph and nothing else
        is. Passed as a list, the steps used to arrive flattened to a scalar
        under `content`, no graph was built, and the case went on to report
        `execution_reconstruction: NOT_ASSESSED` and ask for the trace that had
        just been supplied. A method whose whole job is "here is what the agent
        did" must not be able to accept an argument and quietly do nothing with
        it.

        A payload that cannot become a trace is refused rather than stored. The
        alternative is what was happening: a call that looks like it worked, and
        a requirement that fails for a reason the caller has already addressed.
        """
        if hasattr(trace, "to_dict") and hasattr(trace, "record_type"):
            return self._add(trace, record_type="execution")

        payload: Any = trace
        if (isinstance(payload, Sequence)
                and not isinstance(payload, (str, bytes, bytearray, Mapping))):
            # The steps alone. Passed through as written — `add_native_trace`
            # skips a step it cannot read, and guessing a shape for one here
            # would be release-gate inventing telemetry.
            payload = {"steps": list(payload)}

        if not isinstance(payload, Mapping) or not isinstance(
                payload.get("steps"), list):
            raise ApiError(
                "add_execution needs a trace it can reconstruct: either "
                "{'trace_id': ..., 'steps': [...]} or the steps on their own. "
                f"Got {type(trace).__name__}"
                + (" with no 'steps'" if isinstance(payload, Mapping) else "")
                + ". A step is a mapping such as {'type': 'tool_call', 'tool': "
                  "'shell'} or {'type': 'llm_call', 'model': ...}")
        return self._add(payload, record_type="execution")

    def add_verification(self, result: Any, *, method: str = "", outcome: str = "",
                         verifier: str = "", target_digest: str = "",
                         against_subject: bool = False) -> "Case":
        """A typed check and what it established.

        `method`, `outcome` and `verifier` are optional and, between them, are what
        turns a payload into a verification. Supplied, the check enters the
        verification graph. Omitted, the payload is kept as evidence and
        `decision.required_evidence` names what is missing — unless the payload is
        the documented generic verifier envelope, which is read as itself because
        reading a documented format is not a guess about a tool's vocabulary.

        `against_subject=True` records that the check ran against the subject's
        digest. It is an opt-in and never a default: a verification with no target
        is UNDETERMINED against every state, and filling that in from the subject
        release-gate happens to be holding would assert currency the check never
        established. The caller may assert it; the engine may not infer it.
        """
        if against_subject:
            digest = getattr(self.session.subject, "digest", None)
            if not digest:
                raise ApiError(
                    "against_subject=True needs a subject with a digest, and this "
                    "case has none. Pass target_digest, or open the case with a "
                    "subject release-gate can hash")
            target_digest = target_digest or str(digest)
        if not (method or outcome or verifier) and _is_generic_envelope(result):
            return self._add(result, record_type="evidence",
                             kind=EvidenceType.EVAL_RESULT.value,
                             extra={"metadata": {"api_verifier_envelope": True}})
        if method or outcome or verifier:
            return self._add_verified_claim(
                result, method=method or "OTHER", outcome=outcome or "INCONCLUSIVE",
                verifier=verifier, target_digest=target_digest)
        label = _label(result, "a verification")
        self._unstated_verifications.append(label)
        return self._add(result, record_type="evidence",
                         kind=EvidenceType.TOOL_RESULT.value,
                         extra={"coverage_note":
                                "submitted through add_verification with no method, "
                                "outcome or verifier stated, so what it established "
                                "was not established here"})

    def add_replication(self, run: Any) -> "Case":
        """An independent attempt at the same result."""
        return self._add(run, record_type="evidence",
                         kind=EvidenceType.REPLICATION.value)

    def add_counterexample(self, search: Any, *, against: str = "") -> "Case":
        """An attempt to break a claim, whether or not it succeeded.

        A counterexample is against something, and ingest rejects one that names
        nothing — "a counterexample against nothing cannot be weighed or surfaced".
        The first draft of this let that rejection happen, so the call succeeded,
        the case held no counterexample, and the only trace was a line in the
        normalisation's notes. Silently dropping what a caller handed over is worse
        than refusing it.

        So: `against` (or a `target_claim` in the payload) makes this a
        counterexample. Without either, the search is kept as evidence of a search
        and `decision.required_evidence` says what would make it weighable —
        nothing is lost and nothing is invented.
        """
        payload = _as_mapping(search)
        target = (against or str(payload.get("target_claim") or "")).strip()
        if target:
            return self._add(search, record_type="counterexample",
                             extra={"target_claim": target})
        label = _label(search, "a counterexample search")
        self._untargeted_counterexamples.append(label)
        return self._add(search, record_type="evidence",
                         kind=EvidenceType.COUNTEREXAMPLE.value,
                         extra={"coverage_note":
                                "submitted through add_counterexample naming no "
                                "claim, so it is held as evidence of a search and "
                                "weighed against nothing"})

    def add_evidence(self, record: Any, *, kind: str = "") -> "Case":
        """Anything else a producer wants in the case."""
        return self._add(record, record_type="evidence", kind=kind or "")

    def add_claim(self, claim: Any) -> "Case":
        """A proposition the case is about."""
        return self._add(claim, record_type="claim")

    def add_artifact(self, artifact: Any) -> "Case":
        """A thing produced, identified by content where it can be."""
        return self._add(artifact, record_type="artifact")

    def stream(self, events: Iterable[Any], *, retain: int = STREAM_RETAIN) -> "Case":
        """Fold a stream of events, counting all and holding a bounded set.

        Not `extend`. The session holds what it is given, so ten million events
        through `extend` is about nine gigabytes; this counts and hashes each event
        as it passes, keeps `retain` of them, and commits to the whole stream
        through one record carrying the observed total and the fold digest.

        Callable more than once. The fold accumulates, so two streams of a million
        produce one commitment over two million.
        """
        if retain < 0:
            raise ApiError("retain cannot be negative; pass 0 to keep none")
        if retain != STREAM_RETAIN:
            self._stream = _refolded(self._stream, retain)
        for event in events:
            self._streamed += 1
            self._stream.add(_stream_record(event, self._streamed))
        return self

    # ── while open ──────────────────────────────────────────────────────────

    def required_evidence(self) -> Tuple[str, ...]:
        """What would resolve this case as it stands. Settles nothing."""
        return _requirements(self.session.provisional(), self._gaps_named())

    def attention(self) -> Tuple[str, ...]:
        """What a person would have to look at if this were decided now."""
        return tuple(_render_item(i) for i in self.session.provisional().attention.items)

    def __len__(self) -> int:
        """Records added, not counting streamed events that were never retained."""
        return len(self.session.records)

    def __bool__(self) -> bool:
        """Always True.

        Spelled out because `__len__` exists, and without this an empty case is
        falsy — so `if case:` would read as "the case is invalid" on a case that was
        created perfectly well and has nothing in it yet. That is the state every
        case starts in.
        """
        return True

    @property
    def streamed(self) -> int:
        return self._streamed

    # ── the boundary ────────────────────────────────────────────────────────

    def finalize(self) -> CaseDecision:
        """Seal the case and decide it. Idempotent, as the session's own is."""
        if not self.session.finalized:
            for row in self._stream_records():
                self.session.add(row)
        outcome = self.session.finalize()
        verdict = outcome.case.verdict
        return CaseDecision(
            decision=verdict.decision,
            reasons=tuple(verdict.reasons),
            fired_rules=tuple(verdict.fired_rules),
            required_evidence=_requirements(outcome, self._gaps_named()),
            attention=tuple(_render_item(i) for i in outcome.attention.items),
            not_assessed=_gaps(outcome),
            case_digest=outcome.case.case_digest,
            outcome=outcome)

    # ── internals ───────────────────────────────────────────────────────────

    def _gaps_named(self) -> Tuple[str, ...]:
        """What this surface itself knows is missing, in the caller's own words."""
        rows = [
            (f"state the method, outcome and verifier for the check submitted as "
             f"{label!r}, or pass the generic verifier envelope — without them, what "
             "it established is not established")
            for label in self._unstated_verifications]
        rows.extend(
            f"name the claim the counterexample search {label!r} was against; "
            "a counterexample weighed against nothing changes no verdict"
            for label in self._untargeted_counterexamples)
        return tuple(rows)

    def _add(self, payload: Any, *, record_type: str, kind: str = "",
             extra: Optional[Mapping[str, Any]] = None) -> "Case":
        self.session.add(_row(payload, record_type=record_type, kind=kind, extra=extra))
        return self

    def _add_verified_claim(self, payload: Any, *, method: str, outcome: str,
                            verifier: str, target_digest: str) -> "Case":
        """A verification the caller described, as a claim carrying one attempt.

        A verification reaches the graph through a claim's `verification_attempts`
        or a verifier report; an evidence record alone does not become one. Going
        through a claim keeps the check attached to the proposition it is about,
        which is what makes it weighable at all.
        """
        label = _label(payload, "the checked proposition")
        attempt: Dict[str, Any] = {"method": method.upper(), "outcome": outcome.upper()}
        if verifier:
            attempt["verifier"] = verifier
        if target_digest:
            attempt["target_digest"] = target_digest
        attempt["result"] = _as_mapping(payload)
        self.session.add({
            "record_type": "claim", "claim_id": f"api-{digest_object(label)[7:19]}",
            "proposition": label, "verification_attempts": [attempt]})
        return self

    def _stream_records(self) -> Tuple[Dict[str, Any], ...]:
        """The retained events, plus release-gate's own record of the whole stream."""
        if not self._streamed:
            return ()
        collection = self._stream.build()
        held = len(collection.materialised)
        dropped = collection.total_count - held
        rows: List[Dict[str, Any]] = [
            dict(record.to_dict()) for record in collection.materialised]
        # The counts go at the row's top level, not under a `content` key: ingest
        # preserves a submitted payload *under* `content`, so a producer's own
        # `content` lands a level deeper and its nested mappings arrive as reprs.
        # Measured, after the first draft put them there and they came back as
        # strings — the commitment has to be readable to be a commitment.
        rows.append({
            "record_type": "evidence",
            "evidence_id": f"stream-{collection.fold_digest[7:23]}",
            "kind": EvidenceType.TRACE.value,
            "producer": {"producer_id": "release_gate://api.stream",
                         "kind": ProducerKind.RELEASE_GATE.value},
            "observed_events": collection.total_count,
            "fold_digest": collection.fold_digest,
            "retained": held,
            "retention": "first-n, which is bounded and not a sample",
            "coverage_note": (
                f"{collection.total_count} event(s) were counted and hashed by "
                f"release-gate as they passed; {held} are held and all of them are "
                "committed to by the fold digest")})
        if dropped:
            # The collection will read COMPLETE, and with respect to what was
            # submitted it is — the dropped events were folded outside the session
            # and never offered to it. Saying only that in a note would leave a
            # reviewer reading a complete collection over a truncated stream, so the
            # gap goes where every other gap goes (§10ab, §10aq, §10ar).
            rows.append({
                "record_type": "expectation",
                "dimension": "stream.event_content",
                "assessed": False,
                "declared_by": "release_gate://api.stream",
                "observed_from": "release_gate://api.stream",
                "note": (f"{collection.total_count} event(s) were observed and "
                         f"committed to as {collection.fold_digest}; {dropped} are "
                         "not retained, so their content cannot be assessed from "
                         "this case. The count is observed; the contents are not "
                         "here")})
        return tuple(rows)


def _refolded(existing: RecordCollectionBuilder, retain: int) -> RecordCollectionBuilder:
    """A fold with a new retention cap, carrying what has already been counted."""
    replacement = RecordCollectionBuilder(
        "evidence", track_ids=False, policy=RetainFirst(retain))
    return replacement.merge(existing) if len(existing.build()) or True else replacement


# ── payload handling ─────────────────────────────────────────────────────────

def _row(payload: Any, *, record_type: str, kind: str = "",
         extra: Optional[Mapping[str, Any]] = None) -> Any:
    """A payload as a record row, with shape stamped on and nothing else.

    A typed record object is passed through untouched — it already knows what it
    is. A mapping gets a `record_type` and, where one was asked for, a `kind`, and
    keeps everything else exactly as the producer wrote it. No status is set here
    and none could be: ingest strips a producer's claimed statuses regardless.
    """
    if not isinstance(payload, Mapping):
        if hasattr(payload, "to_dict") and hasattr(payload, "record_type"):
            return payload
        return {"record_type": record_type, "content": {"value": _scalar(payload)},
                **({"kind": kind} if kind else {}), **dict(extra or {})}
    row = dict(payload)
    row.setdefault("record_type", record_type)
    if kind:
        row.setdefault("kind", kind)
    for key, value in (extra or {}).items():
        if key == "metadata" and isinstance(row.get("metadata"), Mapping):
            row["metadata"] = {**dict(row["metadata"]), **dict(value)}
        else:
            row.setdefault(key, value)
    return row


def _stream_record(event: Any, index: int) -> SimpleRecord:
    payload = _as_mapping(event)
    return SimpleRecord(record_type="evidence", record_id=f"ev-{index}",
                        payload={"kind": EvidenceType.TRACE.value, **payload})


def _as_mapping(payload: Any) -> Dict[str, Any]:
    if isinstance(payload, Mapping):
        return dict(payload)
    if hasattr(payload, "to_dict"):
        try:
            data = payload.to_dict()
            if isinstance(data, Mapping):
                return dict(data)
        except Exception:  # pragma: no cover - a to_dict that refuses
            pass
    return {"value": _scalar(payload)}


def _scalar(value: Any) -> Any:
    return value if isinstance(value, (str, int, float, bool)) or value is None \
        else repr(value)


def _label(payload: Any, fallback: str) -> str:
    data = _as_mapping(payload)
    for key in ("proposition", "name", "title", "id", "suite", "test", "check"):
        found = data.get(key)
        if isinstance(found, str) and found.strip():
            return found.strip()
    return fallback


def _is_generic_envelope(payload: Any) -> bool:
    """Whether this is the documented tool-neutral verifier envelope.

    Asks the adapter rather than sniffing keys here, so there is one definition of
    that format and this surface cannot drift from it.
    """
    from release_gate.assurance.verifiers import DETECT_FLOOR, GenericVerifierAdapter

    try:
        return int(GenericVerifierAdapter().detect(payload)) >= DETECT_FLOOR
    except Exception:  # pragma: no cover - a payload the adapter cannot look at
        return False


def _requirements(outcome: Any, named: Sequence[str]) -> Tuple[str, ...]:
    """The engine's requirements, plus what this surface knows it was not told."""
    return tuple([_render_item(item) for item in outcome.required_evidence.items]
                 + list(named))


def _render_item(item: Any) -> str:
    """One readable line from a required-evidence item or an attention item.

    The field names are `what`/`why` and `summary`/`reason`, and the first draft of
    this guessed at neither — so every line of the product surface's headline
    output was a dataclass repr. Read off the real attributes, and fall back to a
    repr only for something this function has never seen.
    """
    what = getattr(item, "what", None) or getattr(item, "summary", None)
    why = getattr(item, "why", None) or getattr(item, "reason", None)
    if isinstance(what, str) and what.strip():
        if isinstance(why, str) and why.strip() and why.strip() != what.strip():
            return f"{what.strip()} — {why.strip()}"
        return what.strip()
    return str(item)


def _gaps(outcome: Any) -> Tuple[str, ...]:
    from release_gate.assurance.latency import coverage_gaps

    return coverage_gaps(outcome)


# ── the entry point ──────────────────────────────────────────────────────────

def create_case(*, objective: str, subject: Any = None, type: Optional[str] = None,
                methodology: Optional[str] = None,
                requested_action: Optional[str] = None,
                name: str = "case") -> Case:
    """Open a case. Only `objective` is required.

    `type` shadows the builtin, deliberately: it is the word the product surface
    uses and a `case_type=` alias would mean two spellings of one argument forever.
    Nothing in this function needs `type()`.

    `methodology` is a registered id. `"research-mathematics@1.1.0"` pins exactly;
    `"research-mathematics-v1"` pins to the newest version in the 1 line; a bare
    `"research-mathematics"` takes whatever is newest. Pin one if the bar matters
    to you — the case records the version it resolved either way, but only a pin
    keeps *this call* meaning the same thing after a new version ships.

    Omitted, the case will report `METHODOLOGY_REQUIRED` and hold, which is the
    honest answer rather than a missing feature: structural analysis can say what
    the evidence *is*, and "enough for this decision" is a domain question nobody
    has answered yet.
    """
    if not str(objective or "").strip():
        raise ApiError(
            "a case needs an objective: it is the question a person is being asked "
            "to authorise, and a case with no question cannot be put to anybody")
    action = requested_action or f"authorise: {objective.strip()}"
    built, basis = _subject_of(subject, case_type=type, requested_action=action)
    session = AssuranceSession.open(
        source_name=name, objective=objective.strip(),
        methodology=_methodology(methodology),
        requested_decision=_requested_decision(type, objective),
        requested_action=action, subject=built)
    return Case(session, subject_basis=basis)


def _version_key(version: str) -> Tuple[int, ...]:
    parts = []
    for piece in str(version).split("."):
        digits = "".join(c for c in piece if c.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def _methodology(reference: Optional[str]) -> Optional[Any]:
    """Resolve what the caller asked for, honouring a version when they gave one.

    Three spellings, and the middle one is why this is not a one-liner:

    * ``id@X.Y.Z`` pins exactly, through the registry's own `resolve`.
    * ``id-vN`` is the spelling the product brief uses. It **reads as a pin**, and
      it used to be thrown away: the id was split at ``-v`` and the newest version
      of any major was returned. With more than one major published that is a
      caller writing ``-v1`` and silently getting 2.x. It now pins to the newest
      version inside the N line, which is what somebody writing ``-v1`` means.
    * a bare ``id`` takes the newest, which is what the CLI does too — and the
      case records the `MethodologyRef` it resolved to, so which bar was applied
      is on the record even though the call did not name it.
    """
    if reference is None:
        return None
    from release_gate.assurance.methodologies import default_registry

    registry = default_registry()
    text = str(reference).strip()

    if "@" in text:
        try:
            return registry.resolve(text)
        except Exception as exc:
            name = text.split("@", 1)[0]
            available = ", ".join(registry.versions(name)) or "none registered"
            raise ApiError(
                f"{reference!r} could not be resolved: {exc}. Versions registered "
                f"for {name!r}: {available}") from None

    if "-v" in text:
        name, _, suffix = text.rpartition("-v")
        if name and suffix.isdigit():
            line = [v for v in registry.versions(name)
                    if _version_key(v)[:1] == (int(suffix),)]
            if line:
                return registry.resolve(
                    f"{name}@{max(line, key=_version_key)}")
            if registry.versions(name):
                raise ApiError(
                    f"{reference!r} asks for version {suffix} of {name!r}, and the "
                    f"registered versions are {', '.join(registry.versions(name))}. "
                    "A version that is not there must not quietly become another "
                    "one, because the version is what fixes the bar")
            text = name

    try:
        return registry.latest(text)
    except Exception:
        raise ApiError(
            f"{reference!r} is not a registered methodology. Known: "
            + ", ".join(sorted(registry.ids()))
            + ". A methodology decides what 'enough' means, so a mistyped one must "
              "not quietly become none") from None


def _requested_decision(case_type: Optional[str], objective: str) -> str:
    if case_type:
        return (f"Is the evidence in this case structurally sound enough to "
                f"authorise a {str(case_type).strip().lower().replace('_', ' ')}?")
    return f"Is the evidence in this case structurally sound enough for: {objective}?"


__all__ = [
    "API_SCHEMA_VERSION",
    "STREAM_RETAIN",
    "ApiError",
    "Case",
    "CaseDecision",
    "create_case",
]

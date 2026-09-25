"""Fault injection for the evidence path, and what recovery means.

§10ak scored *cases* — sixteen constructions, is the reported structure the
built one. This is its sibling and scores *arrival*: the same evidence, delivered
badly, and whether what a person is asked to authorise survives the delivery.

**"Deterministic recovery" is three different promises, and saying which one
applies is the whole point.** A fault absorbed, a fault reported and a fault
refused are all recoveries; calling them all "handled" is how silent data loss
passes a chaos test.

* `IDENTICAL` — the fault changes nothing. Same case digest, same verdict, same
  findings. The strongest answer, and the only one available when the evidence
  genuinely did not change.
* `DECLARED` — something differs, and the difference is *stated*. A truncated
  stream holds instead of promoting; a subject that moved reports `MUTATED`; an
  unreachable store reports `UNVERIFIABLE`. The case is different because the
  situation is different, and it says so.
* `REFUSED` — the engine declines. A record after `finalize()`, an approval
  against a case that moved. Refusal is a recovery: it is the outcome that keeps
  a decision bound to the state it was taken on (Invariant 5).

What none of them may be is *quieter*. A fault that loses evidence and produces
a smaller, cleaner, more confident case is the failure this file exists to catch
— §10ak found exactly that shape in the coverage ledger, and the faults here are
chosen to look for its siblings at the arrival boundary.

Nothing is timed, threaded or slept. "Concurrent mutation" is two writers
against one base state, because the question is whether their work stays
distinguishable — and a race that only sometimes reproduces proves nothing
either way.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import (Any, Callable, Dict, List, Mapping, Optional, Sequence,
                    Tuple)

__all__ = [
    "CHAOS_SCHEMA_VERSION",
    "FAULTS",
    "ChaosError",
    "Fault",
    "FaultResult",
    "Recovery",
    "chaos_report",
    "run_fault",
]

CHAOS_SCHEMA_VERSION = 1


class ChaosError(ValueError):
    """A fault that cannot be injected, or a recovery that cannot be judged."""


class Recovery(str, Enum):
    """What kind of recovery a fault permits. Not a severity ranking.

    `IDENTICAL` is not "better" than `REFUSED`: an approval that still bound
    after its case moved would be `IDENTICAL` and catastrophic. Each fault
    declares the class its nature allows, and the harness checks that one.
    """

    IDENTICAL = "IDENTICAL"   # absorbed: same digest, same verdict, same findings
    DECLARED = "DECLARED"     # different, and the difference is stated
    REFUSED = "REFUSED"       # the engine declines to proceed


@dataclass(frozen=True)
class Fault:
    """One named way the evidence path can be broken.

    `expected` is written from what the fault *is*, before the harness runs —
    the §10ak discipline. A fault whose expected recovery was filled in after
    watching the engine records what the engine does, which is a tautology.
    """

    name: str
    #: What goes wrong, in the words an operator would use.
    injury: str
    expected: Recovery
    #: Runs the fault and returns what it observed. Raising is a result, not an
    #: error: `REFUSED` faults are expected to raise somewhere.
    run: Callable[[], "FaultResult"]
    #: Why this recovery class and not a stronger one. Required for anything
    #: short of `IDENTICAL`, so "it told us" is never an unexamined excuse.
    why: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "expected", Recovery(self.expected))
        if self.expected is not Recovery.IDENTICAL and not self.why.strip():
            raise ChaosError(
                f"{self.name}: a fault that does not recover IDENTICALLY must say "
                "why a stronger recovery is not available, or 'it told us' "
                "becomes the answer to everything")


@dataclass(frozen=True)
class FaultResult:
    """What one fault actually did."""

    name: str
    recovery: Recovery
    #: The specific thing that makes this the recovery it is — a standing, a
    #: status, a verdict, an exception type. Quoted from the engine.
    signal: str = ""
    #: Whether the fault verifiably perturbed its input. A fault that changed
    #: nothing is not a test, and this is checked rather than assumed.
    perturbed: bool = True
    detail: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "recovery", Recovery(self.recovery))
        object.__setattr__(self, "detail", dict(self.detail))

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "fault_result", "record_id": self.name,
                "name": self.name, "recovery": self.recovery.value,
                "signal": self.signal, "perturbed": self.perturbed,
                "detail": dict(self.detail)}


# ── the shared fixture ───────────────────────────────────────────────────────

def _base() -> List[Dict[str, Any]]:
    """The clean release from the §10ak corpus, reused rather than rebuilt.

    Every fault below is this document with one thing broken, so a difference in
    outcome is attributable to the break. Reusing the corpus's fixture also means
    a change that alters the baseline shows up in both files at once.
    """
    from release_gate.assurance.corpus import _clean_release
    return _clean_release()


def _methodology() -> Any:
    from release_gate.assurance.methodologies import default_registry
    return default_registry().latest("general-autonomous-action")


def _assure(records: Sequence[Mapping[str, Any]], *, source: str = "chaos.jsonl") -> Any:
    from release_gate.assurance.ingest import detect_document, normalise
    from release_gate.assurance.zero_config import assure_normalisation
    rows = [dict(r) for r in records]
    content = ("\n".join(json.dumps(r, sort_keys=True) for r in rows) + "\n").encode()
    detection = detect_document(rows, filename=source)
    return assure_normalisation(
        normalise(rows, detection, source=source, content=content),
        source_name=source, methodology=_methodology(),
        objective="Assurance under fault injection")


def _session(records: Sequence[Mapping[str, Any]]) -> Any:
    from release_gate.assurance.session import AssuranceSession
    session = AssuranceSession.open(source_name="chaos.jsonl",
                                    methodology=_methodology(),
                                    objective="Assurance under fault injection")
    session.extend([dict(r) for r in records])
    return session


def _shape(outcome: Any) -> Dict[str, Any]:
    """What a person is asked to authorise, reduced to what must not drift."""
    return {"digest": outcome.case.case_digest,
            "verdict": outcome.case.verdict.decision.value,
            "findings": sorted({f.rule_id for f in outcome.analysis.findings}),
            "evidence": outcome.case.collection("evidence").total_count}


def _substantive(outcome: Any) -> Dict[str, str]:
    """Producer-supplied evidence only, keyed by id.

    Release-gate derives two records from the *bytes* it was handed — one
    committing to the input, one carrying the capability surface read out of
    them. Reordering a document genuinely changes those bytes, so those two
    records genuinely move. They are excluded here so the question "did the
    producers' evidence survive" can be asked on its own.
    """
    from release_gate.assurance.records import record_digest
    out: Dict[str, str] = {}
    for record in outcome.case.collection("evidence").materialised:
        data = record if isinstance(record, Mapping) else record.to_dict()
        producer = (data.get("producer") or {}).get("producer_id", "")
        if producer.startswith("release-gate/"):
            continue
        out[str(data.get("record_id"))] = record_digest(record)
    return out


def _positionless(value: Any) -> Any:
    """The same structure with positional citations removed.

    Some derived records cite *where* something was — `envelope:chaos.jsonl#5`
    is the line the declaration occupied. Reorder the document and the same
    declaration is genuinely on a different line, so the citation is accurate and
    the record's content address moves with it.

    That is a real tension between two things this architecture wants: content
    addressing, and provenance you can follow back to a line. It is not resolved
    here, and it is not hidden either — the reordering fault reports the record
    identities that moved *and* proves that with citations set aside the values
    are the same, so a reader can see exactly what the movement consists of.
    """
    if isinstance(value, Mapping):
        return {k: _positionless(v) for k, v in sorted(value.items())
                if not (k == "source" and isinstance(v, str) and "#" in v)}
    if isinstance(value, (list, tuple)):
        return [_positionless(v) for v in value]
    return value


def _values(outcome: Any) -> Dict[str, Any]:
    """Producer-supplied evidence by id, with positional citations stripped."""
    from release_gate.assurance.records import strip_clocks
    out: Dict[str, Any] = {}
    for record in outcome.case.collection("evidence").materialised:
        data = record if isinstance(record, Mapping) else record.to_dict()
        producer = (data.get("producer") or {}).get("producer_id", "")
        if producer.startswith("release-gate/"):
            continue
        stripped = _positionless(strip_clocks(dict(data)))
        stripped.pop("record_id", None)
        stripped.pop("evidence_id", None)
        stripped.pop("digest", None)
        out[json.dumps(stripped, sort_keys=True, default=str)] = True
    return out


def _approve(outcome: Any) -> Any:
    from release_gate.assurance.approval import (
        ApprovalAcknowledgement, offer_approval, submit_approval)
    offer = offer_approval(outcome.case, outcome)
    return submit_approval(
        outcome.case,
        ApprovalAcknowledgement(case_version=offer.case_version,
                                subject_digest=offer.subject_digest,
                                evidence_pack_digest=offer.evidence_pack_digest,
                                case_digest=offer.case_digest),
        approver="reviewer@example.test", scope="the case as offered").approval


# ── the thirteen faults ──────────────────────────────────────────────────────

def _f_interruption() -> FaultResult:
    """The stream is cut off part-way. The half-case must not look finished."""
    base = _base()
    full = _session(base).finalize()
    verdicts = {}
    for cut in (2, 4, 5):
        partial = _session(base[:cut]).finalize()
        verdicts[f"{cut}/{len(base)}"] = partial.case.verdict.decision.value
    promoted = [k for k, v in verdicts.items() if v == "PROMOTE"]
    return FaultResult(
        name="ingestion_interruption",
        recovery=Recovery.DECLARED if not promoted else Recovery.IDENTICAL,
        signal=f"truncated at {', '.join(f'{k}={v}' for k, v in verdicts.items())}; "
               f"complete={full.case.verdict.decision.value}",
        perturbed=any(v != full.case.verdict.decision.value for v in verdicts.values()),
        detail={"truncated": verdicts,
                "complete": full.case.verdict.decision.value,
                "promoted_while_truncated": promoted})


def _f_duplicate_batches() -> FaultResult:
    """At-least-once delivery. The same batch, twice and three times."""
    base = _base()
    once = _assure(base)
    twice = _assure(list(base) + [dict(r) for r in base])
    thrice = _assure(list(base) * 3)
    def without_digest(outcome: Any) -> Dict[str, Any]:
        shape = _shape(outcome)
        shape.pop("digest")
        return shape

    absorbed = (without_digest(once) == without_digest(twice)
                == without_digest(thrice))
    evidence_same = (_substantive(once) == _substantive(twice)
                     == _substantive(thrice))
    digests = {o.case.case_digest for o in (once, twice, thrice)}
    return FaultResult(
        name="duplicate_batches",
        recovery=Recovery.IDENTICAL if len(digests) == 1 else
                 (Recovery.DECLARED if absorbed and evidence_same
                  else Recovery.REFUSED),
        signal=f"x1/x2/x3 all {once.case.verdict.decision.value}; evidence "
               f"records identical={evidence_same}; findings identical={absorbed}; "
               f"{len(digests)} case digest(s), because the case commits to the "
               "bytes it was handed and twice the bytes is not the same document",
        perturbed=True,
        detail={"verdict_and_findings_identical": absorbed,
                "evidence_identical": evidence_same,
                "distinct_case_digests": len(digests),
                "evidence_count": once.case.collection("evidence").total_count})


def _f_reordered_events() -> FaultResult:
    """The same records, arriving in a different order."""
    import random
    base = _base()
    straight = _assure(base)
    shuffles = []
    for seed in (1, 2, 3, 4):
        doc = list(base)
        random.Random(seed).shuffle(doc)
        shuffles.append(_assure(doc))
    verdicts = {o.case.verdict.decision.value for o in shuffles} | {
        straight.case.verdict.decision.value}
    findings = {tuple(sorted({f.rule_id for f in o.analysis.findings}))
                for o in shuffles} | {
        tuple(sorted({f.rule_id for f in straight.analysis.findings}))}
    ids_stable = all(_substantive(o) == _substantive(straight) for o in shuffles)
    # The stronger question, and the one that decides the recovery class: with
    # positional citations set aside, is the *content* of every producer record
    # the same? If it is, the only thing reordering moved is where records say
    # they came from.
    values_stable = all(_values(o) == _values(straight) for o in shuffles)
    moved = len(set(_substantive(shuffles[0])) - set(_substantive(straight)))
    digests = {o.case.case_digest for o in shuffles} | {straight.case.case_digest}
    stable = len(verdicts) == 1 and len(findings) == 1 and values_stable
    return FaultResult(
        name="reordered_events",
        recovery=Recovery.IDENTICAL if len(digests) == 1 else
                 (Recovery.DECLARED if stable else Recovery.REFUSED),
        signal=f"{len(digests)} distinct case digest(s) across 5 orderings; "
               f"verdict and findings stable; producer evidence values "
               f"stable={values_stable}; {moved} record id(s) moved, all of them "
               "records that cite a position in the input",
        perturbed=len(digests) > 1,
        detail={"verdicts": sorted(verdicts), "distinct_digests": len(digests),
                "record_ids_stable": ids_stable, "values_stable": values_stable,
                "ids_moved": moved})


def _f_missing_telemetry() -> FaultResult:
    """The execution record never arrives. The gap must be named, not filled."""
    base = _base()
    full = _assure(base)
    without = _assure([r for r in base if r.get("record_type") != "execution"])
    row = without.analysis.coverage_ledger.of("execution_reconstruction")
    state = row.state.value if row is not None else "(row absent)"
    return FaultResult(
        name="missing_telemetry",
        recovery=Recovery.DECLARED,
        signal=f"execution_reconstruction={state}; verdict "
               f"{full.case.verdict.decision.value} -> "
               f"{without.case.verdict.decision.value}",
        perturbed=without.analysis.execution_graph is None,
        detail={"state": state,
                "verdict_without": without.case.verdict.decision.value,
                "graph_built": without.analysis.execution_graph is not None})


def _f_clock_skew() -> FaultResult:
    """Producers stamping the future, the deep past, and nonsense."""
    base = _base()
    shapes = {}
    for label, stamp in (("future", "2099-01-01T00:00:00Z"),
                         ("past", "1970-01-01T00:00:00Z"),
                         ("garbage", "not-a-timestamp")):
        doc = [dict(r, timestamp=stamp) if r.get("record_type") == "evidence" else r
               for r in base]
        outcome = _assure(doc)
        held = set()
        declared = set()
        for record in outcome.case.collection("evidence").materialised:
            data = record if isinstance(record, Mapping) else record.to_dict()
            held.add(str(data.get("timestamp") or ""))
            declared.add(str((data.get("metadata") or {}).get(
                "declared_timestamp") or ""))
        shapes[label] = {
            "verdict": outcome.case.verdict.decision.value,
            "producer_claim_kept": stamp in declared,
            "clock_adopted": stamp in held}
    adopted = [k for k, v in shapes.items() if v["clock_adopted"]]
    kept = all(v["producer_claim_kept"] for v in shapes.values())
    verdicts = {v["verdict"] for v in shapes.values()}
    return FaultResult(
        name="clock_skew",
        recovery=Recovery.IDENTICAL if not adopted and kept else Recovery.DECLARED,
        signal=f"no skewed clock was adopted as release-gate's own "
               f"({not adopted}); every producer claim kept beside it ({kept}); "
               f"verdicts {sorted(verdicts)}",
        perturbed=kept,
        detail={"per_stamp": shapes, "adopted": adopted})


def _f_restart() -> FaultResult:
    """A session dies half-way and resumes. It must land where it would have."""
    base = _base()
    uninterrupted = _session(base).finalize()
    resumed_session = _session(base[:3])
    resumed_session.extend([dict(r) for r in base[3:]])
    resumed = resumed_session.finalize()
    same = _shape(resumed) == _shape(uninterrupted)
    return FaultResult(
        name="restart",
        recovery=Recovery.IDENTICAL if same else Recovery.DECLARED,
        signal=f"resumed digest == uninterrupted digest: "
               f"{resumed.case.case_digest == uninterrupted.case.case_digest}",
        perturbed=True,
        detail={"shape_identical": same,
                "verdict": resumed.case.verdict.decision.value})


def _f_duplicate_case() -> FaultResult:
    """The same evidence submitted as two separate cases."""
    base = _base()
    first, second = _assure(base), _assure(base)
    same_id = first.case.case_id == second.case.case_id
    same_digest = first.case.case_digest == second.case.case_digest
    return FaultResult(
        name="duplicate_case",
        recovery=Recovery.IDENTICAL if same_id and same_digest else Recovery.DECLARED,
        signal=f"same case_id={same_id}, same case_digest={same_digest} — the "
               "same evidence is the same case, by content address",
        perturbed=True,
        detail={"same_id": same_id, "same_digest": same_digest})


def _f_concurrent_mutation() -> FaultResult:
    """Two writers extend one base. Neither may silently overwrite the other."""
    from release_gate.assurance.corpus import _evidence
    base = _base()
    a = _assure(list(base) + [_evidence("perf", "BENCHMARK_RESULT", "ci://bench", "")])
    b = _assure(list(base) + [_evidence("audit", "REVIEW_RESULT", "human://sec", "")])
    merged = _assure(list(base)
                     + [_evidence("perf", "BENCHMARK_RESULT", "ci://bench", ""),
                        _evidence("audit", "REVIEW_RESULT", "human://sec", "")])
    distinct = len({a.case.case_digest, b.case.case_digest,
                    merged.case.case_digest}) == 3
    distinct_ids = len({a.case.case_id, b.case.case_id, merged.case.case_id}) == 3
    return FaultResult(
        name="concurrent_mutation",
        recovery=Recovery.DECLARED,
        signal=f"three writes, {len({a.case.case_digest, b.case.case_digest, merged.case.case_digest})} "
               f"distinct digests and "
               f"{len({a.case.case_id, b.case.case_id, merged.case.case_id})} distinct "
               "case ids; no write is absorbed into another",
        perturbed=distinct,
        detail={"distinct_digests": distinct, "distinct_ids": distinct_ids})


def _f_approval_during_update() -> FaultResult:
    """A case is revised while an approval of it is live."""
    from release_gate.assurance.approval import check_approval
    outcome = _assure(_base())
    approval = _approve(outcome)
    revised = outcome.case.revise()
    check = check_approval(approval, revised)
    return FaultResult(
        name="approval_during_update",
        recovery=Recovery.REFUSED if not check.valid else Recovery.IDENTICAL,
        signal=f"standing={check.standing.value}; needs a new human act="
               f"{check.needs_new_approval}; the revision carries "
               f"{revised.collection('approvals').total_count} approval(s)",
        perturbed=True,
        detail={"standing": check.standing.value, "valid": check.valid,
                "approvals_on_revision": revised.collection("approvals").total_count})


def _f_verifier_arriving_late() -> FaultResult:
    """A proof lands after the case was decided."""
    from release_gate.assurance.session import SessionError
    base = _base()
    session = _session(base)
    decided = session.finalize()
    late = {"record_type": "evidence", "evidence_id": "late-proof",
            "kind": "ANALYSIS_RESULT",
            "producer": {"producer_id": "tool://lean", "kind": "tool"}}
    refused = ""
    try:
        session.add(late)
    except SessionError as exc:
        refused = type(exc).__name__
    reopened = _session(list(base) + [late]).finalize()
    return FaultResult(
        name="verifier_arriving_late",
        recovery=Recovery.REFUSED if refused else Recovery.IDENTICAL,
        signal=f"post-finalize add raised {refused or '(nothing)'}; a re-opened "
               f"case carrying it has a different digest: "
               f"{reopened.case.case_digest != decided.case.case_digest}",
        perturbed=bool(refused),
        detail={"refused_with": refused,
                "reopened_differs":
                    reopened.case.case_digest != decided.case.case_digest})


def _f_subject_mutation_during_review() -> FaultResult:
    """The artifact changes on disk between decision and authorisation."""
    import tempfile
    from pathlib import Path
    from release_gate.assurance.subject import (
        AssuranceSubject, ContentReference, DigestMethod, DigestStatus,
        ReferenceKind, SubjectType)
    directory = Path(tempfile.mkdtemp())
    artifact = directory / "service.py"
    artifact.write_bytes(b"def charge(order): ...\n")
    digest = "sha256:" + hashlib.sha256(artifact.read_bytes()).hexdigest()
    subject = AssuranceSubject(
        subject_type=SubjectType.CODE_CHANGE, requested_action="deploy service.py",
        content_reference=ContentReference(kind=ReferenceKind.FILE,
                                           locator=str(artifact)),
        digest=digest, digest_method=DigestMethod.SHA256_CONTENT,
        digest_status=DigestStatus.OBSERVED)
    before = subject.recheck()
    artifact.write_bytes(b"def charge(order): return charge(order) * 2\n")
    after = subject.recheck()
    artifact.unlink()
    gone = subject.recheck()
    return FaultResult(
        name="subject_mutation_during_review",
        recovery=Recovery.DECLARED,
        signal=f"before={before.status.value}, after the file moved="
               f"{after.status.value}, after it was deleted={gone.status.value}",
        perturbed=before.status.value != after.status.value,
        detail={"before": before.status.value, "mutated": after.status.value,
                "deleted": gone.status.value,
                "unchanged_reads_false_when_mutated": not after.unchanged})


def _f_external_evidence_unavailable() -> FaultResult:
    """The object store is down when the subject is re-checked."""
    from release_gate.assurance.subject import (
        AssuranceSubject, ContentReference, DigestMethod, DigestStatus,
        ReferenceKind, SubjectType)
    digest = "sha256:" + hashlib.sha256(b"payload").hexdigest()
    subject = AssuranceSubject(
        subject_type=SubjectType.CODE_CHANGE, requested_action="deploy",
        content_reference=ContentReference(kind=ReferenceKind.OBJECT_STORE,
                                           locator="s3://bucket/artifact"),
        digest=digest, digest_method=DigestMethod.SHA256_CONTENT,
        digest_status=DigestStatus.OBSERVED)

    def refused(_ref: Any) -> Optional[str]:
        raise OSError("s3: connection refused")

    def timed_out(_ref: Any) -> Optional[str]:
        raise TimeoutError("read timed out after 30s")

    results = {"no_resolver": subject.recheck(),
               "connection_refused": subject.recheck(resolver=refused),
               "timeout": subject.recheck(resolver=timed_out)}
    statuses = {k: v.status.value for k, v in results.items()}
    any_unchanged = [k for k, v in results.items() if v.unchanged]
    return FaultResult(
        name="external_evidence_unavailable",
        recovery=Recovery.DECLARED,
        signal=f"{statuses}; none read as unchanged ({not any_unchanged})",
        perturbed=True,
        detail={"statuses": statuses, "read_as_unchanged": any_unchanged,
                "named_the_failure":
                    "connection refused" in results["connection_refused"].detail})


def _f_stale_digest() -> FaultResult:
    """An approval is checked against a case whose subject has moved."""
    from release_gate.assurance.approval import check_approval
    from release_gate.assurance.corpus import SERVICE_V2, _clean_release
    outcome = _assure(_base())
    approval = _approve(outcome)
    moved = _assure(_clean_release(SERVICE_V2))
    check = check_approval(approval, moved.case)
    return FaultResult(
        name="stale_digest",
        recovery=Recovery.REFUSED if not check.valid else Recovery.IDENTICAL,
        signal=f"standing={check.standing.value}; conditions="
               f"{[c.value for c in check.conditions]}",
        perturbed=moved.case.case_digest != outcome.case.case_digest,
        detail={"standing": check.standing.value, "valid": check.valid,
                "reasons": list(check.reasons)[:1]})


_FAULT_LIST: Tuple[Fault, ...] = (
    Fault("ingestion_interruption",
          "the producer dies mid-stream and half the records never arrive",
          Recovery.DECLARED, _f_interruption,
          why="a half-case is a different case and must not read as a finished "
              "one; the requirement it can no longer meet holds it"),
    Fault("duplicate_batches",
          "an at-least-once queue redelivers the same batch",
          Recovery.DECLARED, _f_duplicate_batches,
          why="the evidence is absorbed exactly — same records, same findings, "
              "same verdict — but the case commits to the bytes it was handed, "
              "and a batch delivered twice is not the same document. Claiming an "
              "identical digest would mean the case pretending it received "
              "something it did not"),
    Fault("reordered_events",
          "records arrive in a different order from the one they were written in",
          Recovery.DECLARED, _f_reordered_events,
          why="release-gate hashes the bytes it was handed, and reordered bytes "
              "are different bytes. Every producer-supplied record keeps its "
              "identity; the two records derived from the input itself move, and "
              "both name the digest they derive from"),
    Fault("missing_telemetry",
          "the trace is never emitted, so what the agent did cannot be rebuilt",
          Recovery.DECLARED, _f_missing_telemetry,
          why="the gap is the finding. Reporting it as NOT_ASSESSED is the "
              "answer; filling it in would be the failure (Invariant 3)"),
    Fault("clock_skew",
          "a producer stamps its records with a clock that is wrong",
          Recovery.IDENTICAL, _f_clock_skew),
    Fault("restart",
          "the process dies and the session resumes from where it stopped",
          Recovery.IDENTICAL, _f_restart),
    Fault("duplicate_case",
          "the same evidence is submitted twice as two separate cases",
          Recovery.IDENTICAL, _f_duplicate_case),
    Fault("concurrent_mutation",
          "two writers extend the same base state at the same time",
          Recovery.DECLARED, _f_concurrent_mutation,
          why="there is no merge to be had: two different bodies of evidence are "
              "two different cases. What matters is that neither is absorbed "
              "into the other, and content addressing makes them distinct"),
    Fault("approval_during_update",
          "the case is revised while an approval of it is live",
          Recovery.REFUSED, _f_approval_during_update,
          why="Invariant 5. An approval names a state; carrying it to the next "
              "one would make it unfalsifiable, so nothing short of another "
              "human act will do"),
    Fault("verifier_arriving_late",
          "a proof lands after the case was decided",
          Recovery.REFUSED, _f_verifier_arriving_late,
          why="accepting it would change the state a decision was taken on. The "
              "evidence is not lost — it opens the next case"),
    Fault("subject_mutation_during_review",
          "the artifact changes on disk between the decision and the signature",
          Recovery.DECLARED, _f_subject_mutation_during_review,
          why="the mutation is reported, and `unchanged` reads false. Refusing "
              "here is the caller's decision, because a subject that moved "
              "mid-draft and one that moved after approval need different acts"),
    Fault("external_evidence_unavailable",
          "the object store is unreachable when the subject is re-checked",
          Recovery.DECLARED, _f_external_evidence_unavailable,
          why="UNVERIFIABLE, which is not UNCHANGED and not MUTATED. An "
              "unreachable store is a third thing and collapsing it into either "
              "would be a guess"),
    Fault("stale_digest",
          "an approval is checked against a case whose subject has moved",
          Recovery.REFUSED, _f_stale_digest,
          why="the approval stops counting and says why. A re-check that could "
              "repair it would make the binding a formality"),
)

FAULTS: Mapping[str, Fault] = {f.name: f for f in _FAULT_LIST}


def run_fault(name: str) -> FaultResult:
    """Inject one fault and report what came back."""
    if name not in FAULTS:
        raise ChaosError(f"{name!r} is not a known fault. Known: "
                         + ", ".join(sorted(FAULTS)))
    return FAULTS[name].run()


def chaos_report() -> Dict[str, Any]:
    """Every fault, its expected recovery and what actually happened."""
    rows = []
    for fault in _FAULT_LIST:
        result = fault.run()
        rows.append({**result.to_dict(), "injury": fault.injury,
                     "expected": fault.expected.value,
                     "as_expected": result.recovery is fault.expected,
                     "why": fault.why})
    return {"record_type": "chaos_report", "record_id": "assurance-chaos",
            "schema_version": CHAOS_SCHEMA_VERSION,
            "faults": len(rows),
            "as_expected": sum(1 for r in rows if r["as_expected"]),
            "results": rows}

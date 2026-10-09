"""Reference adapters: one documented contract per class of external evidence.

Release-gate does not compete with the tools that produce evidence. An eval
harness, a red team, a static analyser, a prover and a reviewer each establish
something release-gate cannot, and each already has a tool built for it. What
release-gate does is read what they said, keep it in their words, and decide
from it under a declared policy. So the integration surface is a set of
**generic contracts**, one per class of evidence, rather than a parser per
vendor:

    release-gate.eval/1       eval cases and their outcomes          (EVALS)
    release-gate.red-team/1   attacks, what each targeted, whether it got through
    release-gate.sast/1       static-analysis findings, for a tool without SARIF
    release-gate.review/1     a person's review: who, in what role, of which state
    release-gate.formal/1     a proof result (read by `verifiers.GenericVerifierAdapter`)
    release-gate.behavior/1   a behavioural evaluation: checks, who decided each, the
                              violations the harness proved, and its recommendation

Each is a registrant of `producer_contract`, like the promptfoo, SARIF and
external-decision adapters beside it: it declares what its producer is and
cannot establish, reads one shape, and returns `NativeResult`s. The normaliser
writes every record, every one is DECLARED, and none can become a verdict. A
vendor format becomes evidence through a short shim to one of these — which is
also how a tool whose own export release-gate cannot test against is read
(ProofAgent's PER export through the behaviour contract, by the example mapping
in `examples/proofagent/`) without release-gate guessing at a format.

**What each contract adds over a raw evidence row is the semantics of its
class, stated once.** An attack that *succeeded* is a counterexample to the
claim it targeted, so its claim outcome is "failed" while its own word stays
"succeeded". An attack that was blocked is an observation: it supports, and is
never a check that establishes — the next attack is not the last one. A review
names its reviewer, their role, the state they looked at and when the review
lapses; an expiry nobody can check against a stated time is not a pass. A static
finding stays the tool's rule at the tool's severity.

**Release-gate ran none of these tools.** Every record says whose account it is
(`content.producer_type`, `metadata.origin`), and `origin.py` puts that on every
report. Nothing here re-runs, re-grades or second-guesses a result.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional, Tuple

from release_gate.assurance.canonical import is_digest
from release_gate.assurance.evidence import EvidenceType, VerificationMethod
from release_gate.assurance.producer_contract import (
    AdapterOutput,
    ConfidenceSemantics,
    CoverageSemantics,
    Determinism,
    EvidenceAdapter,
    Independence,
    Measurement,
    NativeResult,
    ProducerDeclaration,
    ProducerIdentity,
    ResultKind,
)
from release_gate.assurance.producers import EvidenceLane

__all__ = [
    "BEHAVIOR_DECLARATION",
    "BEHAVIOR_SCHEMA",
    "BehaviorEvalAdapter",
    "EVAL_DECLARATION",
    "EVAL_SCHEMA",
    "FORMAL_SCHEMA",
    "HUMAN_REVIEW_DECLARATION",
    "RED_TEAM_DECLARATION",
    "RED_TEAM_SCHEMA",
    "REFERENCE_EVIDENCE_SCHEMA_VERSION",
    "REFERENCE_SCHEMAS",
    "REVIEW_SCHEMA",
    "SAST_DECLARATION",
    "SAST_SCHEMA",
    "GenericEvalAdapter",
    "GenericSastAdapter",
    "HumanReviewAdapter",
    "RedTeamAdapter",
    "reference_adapters",
    "review_lapse",
]

REFERENCE_EVIDENCE_SCHEMA_VERSION = 1

EVAL_SCHEMA = "release-gate.eval/1"
RED_TEAM_SCHEMA = "release-gate.red-team/1"
SAST_SCHEMA = "release-gate.sast/1"
REVIEW_SCHEMA = "release-gate.review/1"
BEHAVIOR_SCHEMA = "release-gate.behavior/1"
#: Read by `verifiers.GenericVerifierAdapter`, which already receives every
#: verifier's results; named here so the five contracts are listed in one place.
FORMAL_SCHEMA = "release-gate.formal/1"

REFERENCE_SCHEMAS: Tuple[str, ...] = (EVAL_SCHEMA, RED_TEAM_SCHEMA, SAST_SCHEMA,
                                      REVIEW_SCHEMA, FORMAL_SCHEMA, BEHAVIOR_SCHEMA)


# ── shared reading ───────────────────────────────────────────────────────────

def _text(value: Any) -> str:
    return str(value).strip() if isinstance(value, (str, int, float)) and not isinstance(
        value, bool) else ""


def _skip(skipped: Dict[str, int], reason: str) -> None:
    skipped[reason] = skipped.get(reason, 0) + 1


def _detect(doc: Any, schema: str, rows: str) -> int:
    """Only a document that names the contract. Nothing is read by resemblance."""
    try:
        if not isinstance(doc, Mapping) or _text(doc.get("schema")) != schema:
            return 0
        return 95 if isinstance(doc.get(rows), list) else 60
    except Exception:
        return 0


def _rows(doc: Any, key: str) -> List[Any]:
    rows = doc.get(key) if isinstance(doc, Mapping) else None
    return list(rows) if isinstance(rows, list) else []


def _container(doc: Any, key: str, skipped: Dict[str, int]) -> None:
    """Count a results field that is present and not a list.

    `_rows` reads such a field as no rows, which is right — nothing in it can be
    read as a row — but it used to say nothing, so a red team whose `attacks`
    arrived as an object read as a run of zero attacks. A field that is absent,
    or an empty list, is a run that reported nothing, and is not counted.
    """
    if isinstance(doc, Mapping) and doc.get(key) is not None \
            and not isinstance(doc.get(key), list):
        _skip(skipped, f"`{key}` is a {type(doc.get(key)).__name__}, not a list, so "
                       "none of its entries could be read")


def _strings(value: Any) -> Dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    return {str(k): _text(v) for k, v in value.items() if _text(v)}


def _mapping(value: Any) -> Dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _merged(outer: Any, inner: Any) -> Dict[str, Any]:
    """A document-level block with a row's own block over it."""
    return {**_mapping(outer), **_mapping(inner)}


def _identity(doc: Mapping[str, Any], key: str,
              declaration: ProducerDeclaration) -> ProducerIdentity:
    raw = doc.get(key)
    block = raw if isinstance(raw, Mapping) else {"id": raw}
    return ProducerIdentity(
        producer_id=(_text(block.get("id") or block.get("name"))
                     or declaration.default_producer_id),
        version=_text(block.get("version")) or None,
        origin=_text(block.get("origin")),
        source_identity=_text(doc.get("run_id") or doc.get("id")),
        source_state=_strings(doc.get("state")))


def _claim(row: Mapping[str, Any], doc: Mapping[str, Any], *,
           statement_key: str = "claim", id_key: str = "claim_id") -> Tuple[str, str]:
    """The claim a row bears on, as it states it: (statement, id)."""
    statement = _text(row.get(statement_key)) or _text(doc.get(statement_key))
    claim_id = _text(row.get(id_key)) or _text(doc.get(id_key))
    if claim_id and not statement:
        # Named by id alone: the claim is whatever the case states under that
        # id. Composed into an envelope it is that claim; on its own it says
        # only which claim it is.
        statement = f"claim {claim_id}"
    return statement, claim_id


def _declared_summary(doc: Mapping[str, Any], unit: str, outcome: str,
                      count_key: str, rows_held: int, notes: List[str],
                      producer: str) -> Optional[NativeResult]:
    """The producer's own totals as a count, only where it states them."""
    summary = doc.get("summary")
    if not isinstance(summary, Mapping):
        return None
    count = summary.get(count_key)
    total = summary.get("total")
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        return None
    of = total if isinstance(total, int) and not isinstance(total, bool) and \
        total >= count else None
    if of is not None and of != rows_held:
        notes.append(f"{producer}'s own totals count {of} and the document lists "
                     f"{rows_held}; both are kept as stated and neither is corrected "
                     "to the other")
    return NativeResult(
        kind=ResultKind.MEASUREMENT, native_id="summary", native_outcome=outcome,
        measurement=Measurement(count=count, of=of, unit=unit, outcome=outcome,
                                denominator_basis=f"{producer}'s own summary"),
        native=dict(summary))


# ── release-gate.eval/1 ──────────────────────────────────────────────────────

EVAL_DECLARATION = ProducerDeclaration(
    producer_type="eval",
    label="eval results (release-gate.eval/1)",
    origin="any eval harness that emits release-gate.eval/1; the document names which",
    modality=EvidenceLane.EVALS,
    determinism=Determinism.UNKNOWN,
    evidence_types=(EvidenceType.EVAL_RESULT,),
    supported_claims=("that a named eval case passed or failed the harness's own "
                      "grading",),
    confidence=ConfidenceSemantics.PRODUCER_SCORE,
    confidence_note="a score on the harness's own scale, per case, where it gives one",
    coverage=CoverageSemantics.DECLARED_DENOMINATOR,
    coverage_note=("the cases listed, and the harness's own totals where it states "
                   "them; nothing beyond the suite its author wrote"),
    limitations=(
        "that the cases represent production traffic",
        "that a graded rubric measures the property its name describes",
        "behaviour on inputs the suite does not contain",
        "that a pass on one run repeats on the next"),
    independence=Independence(independent_of_subject=None,
                              operated_by="whoever ran the harness"),
    default_producer_id="eval-harness")


class GenericEvalAdapter(EvidenceAdapter):
    """`release-gate.eval/1` — any eval harness, one shape.

    ```json
    {"schema": "release-gate.eval/1",
     "producer": {"id": "acme-evals", "version": "2.3.0"},
     "state": {"model": "acme-support-v4", "commit": "9f2c1a7"},
     "provenance": {"dataset": "refunds-2026q3"},
     "summary": {"passed": 2, "total": 3},
     "cases": [{"id": "refund-01", "outcome": "passed", "score": 0.94,
                "claim_id": "cl_refund_policy", "covers": {"tool": "refund"}}]}
    ```

    A case names the claim it bears on, or is its own claim ("eval case X
    passes"). Its outcome goes through the one result-word table, so `error`
    fails and `skipped` is not run — neither is a pass.
    """

    declaration = EVAL_DECLARATION

    def detect(self, doc: Any) -> int:
        return _detect(doc, EVAL_SCHEMA, "cases")

    def read(self, doc: Any) -> AdapterOutput:
        identity = _identity(doc, "producer", EVAL_DECLARATION)
        rows = _rows(doc, "cases")
        results: List[NativeResult] = []
        skipped: Dict[str, int] = {}
        notes: List[str] = []
        _container(doc, "cases", skipped)
        for row in rows:
            if not isinstance(row, Mapping):
                _skip(skipped, "eval case is not an object")
                continue
            case_id = _text(row.get("id") or row.get("name"))
            outcome = _text(row.get("outcome") or row.get("result") or row.get("status"))
            if not case_id:
                _skip(skipped, "eval case names no id")
                continue
            statement, claim_id = _claim(row, doc)
            results.append(NativeResult(
                kind=ResultKind.CHECK, native_id=case_id, native_outcome=outcome,
                subject=case_id, native_severity=_text(row.get("severity")),
                native_confidence=row.get("score"),
                claim_statement=statement or f"eval case {case_id!r} passes",
                claim_id=claim_id,
                state=_strings(_merged(doc.get("state"), row.get("state"))),
                covers=_mapping(row.get("covers")),
                provenance=_merged(doc.get("provenance"), row.get("provenance")),
                message=_text(row.get("message") or row.get("reason")),
                produced_at=_text(row.get("ran_at") or doc.get("ran_at")),
                native=dict(row)))
        seen = len(rows)
        counted = _declared_summary(doc, "eval cases", "passed", "passed",
                                    len(rows), notes, identity.producer_id)
        if counted is not None:
            seen += 1
            results.append(counted)
        return AdapterOutput(identity=identity, results=tuple(results),
                             records_seen=seen, skipped=skipped, notes=tuple(notes))


# ── release-gate.red-team/1 ──────────────────────────────────────────────────

RED_TEAM_DECLARATION = ProducerDeclaration(
    producer_type="red_team",
    label="red-team results (release-gate.red-team/1)",
    origin=("any red team, attack harness or behavioural-security tool that emits "
            "release-gate.red-team/1; the document names which"),
    modality=EvidenceLane.EVALS,
    determinism=Determinism.UNKNOWN,
    evidence_types=(EvidenceType.COUNTEREXAMPLE, EvidenceType.EVAL_RESULT),
    supported_claims=(
        "that a named attack got through, which is a counterexample to the claim it "
        "targeted",
        "that a named attack was blocked, which is one observation and not a check"),
    confidence=ConfidenceSemantics.ORDINAL_LABEL,
    confidence_note="the red team's own severity for each attack, on its own scale",
    coverage=CoverageSemantics.ENUMERATED,
    coverage_note=("the attacks listed; no list of attacks is every attack, and a "
                   "clean run is the absence of a found counterexample, not a proof"),
    limitations=(
        "that attacks not attempted would also fail",
        "that a blocked attack shows the claim holds — it shows that one attack did "
        "not get through",
        "that the attack classes tried are the ones an adversary would use",
        "that a success reproduces outside the environment it ran in, unless the "
        "reproduction says so"),
    independence=Independence(independent_of_subject=None,
                              operated_by="whoever ran the attacks"),
    default_producer_id="red-team")

#: The red team's word for an attack, and what it is for the claim the attack
#: targeted. Words outside the table are kept and read as UNKNOWN — never as a
#: block, and never as a pass.
_ATTACK_SUCCEEDED = frozenset({"succeeded", "bypassed", "breached", "exploited"})
_ATTACK_BLOCKED = frozenset({"blocked", "refused", "defended", "mitigated"})
_ATTACK_UNSETTLED = {"partial": "inconclusive", "partially_succeeded": "inconclusive",
                     "inconclusive": "inconclusive", "error": "inconclusive",
                     "timeout": "inconclusive", "not_run": "not_run",
                     "skipped": "not_run"}


class RedTeamAdapter(EvidenceAdapter):
    """`release-gate.red-team/1` — attacks, their targets, and what got through.

    ```json
    {"schema": "release-gate.red-team/1",
     "producer": {"id": "acme-red-team", "version": "0.9"},
     "state": {"commit": "9f2c1a7", "environment": "staging"},
     "provenance": {"provider": "acme", "model_family": "attacker-v2",
                    "session": "rt-2026-10-02"},
     "attacks": [{"id": "atk-017", "class": "indirect_injection",
                  "technique": "instruction in a memo field",
                  "target_claim_id": "cl_no_unauthorised_transfer",
                  "outcome": "succeeded", "severity": "critical",
                  "reproduction": {"steps": ["…"], "transcript": "sha256:…"}}]}
    ```

    A **succeeded** attack is a FINDING typed COUNTEREXAMPLE that contradicts its
    target claim, and is lifted into the counterexample ledger like any other —
    so against a critical claim it blocks under the default policy, however many
    attacks were blocked beside it. A **blocked** attack is an OBSERVATION that
    supports its target and never becomes a verification attempt. A partial,
    errored or timed-out attack is inconclusive, and a word nobody listed is
    UNKNOWN. An attack that names no target is its own claim ("attack X does not
    succeed"), so a success can never be dropped for want of a target.
    """

    declaration = RED_TEAM_DECLARATION

    def detect(self, doc: Any) -> int:
        return _detect(doc, RED_TEAM_SCHEMA, "attacks")

    def read(self, doc: Any) -> AdapterOutput:
        identity = _identity(doc, "producer", RED_TEAM_DECLARATION)
        rows = _rows(doc, "attacks")
        results: List[NativeResult] = []
        skipped: Dict[str, int] = {}
        notes: List[str] = []
        _container(doc, "attacks", skipped)
        for row in rows:
            if not isinstance(row, Mapping):
                _skip(skipped, "attack is not an object")
                continue
            attack = _text(row.get("id"))
            if not attack:
                _skip(skipped, "attack names no id")
                continue
            word = _text(row.get("outcome") or row.get("result"))
            key = word.lower().replace("-", "_").replace(" ", "_")
            statement, claim_id = _claim(row, doc, statement_key="target_claim",
                                         id_key="target_claim_id")
            if not statement:
                statement = f"attack {attack!r} does not succeed against the system " \
                            "under test"
            covers = _mapping(row.get("covers"))
            stated_class = _text(row.get("class"))
            if not covers and stated_class:
                covers = {"adversarial_class": stated_class}
            if key in _ATTACK_SUCCEEDED:
                kind, etype, for_claim = (ResultKind.FINDING, EvidenceType.COUNTEREXAMPLE,
                                          "failed")
                if not row.get("reproduction"):
                    notes.append(f"attack {attack!r} got through and records no "
                                 "reproduction; it stands as a counterexample, and "
                                 "re-running it is the way to test that it holds")
            elif key in _ATTACK_BLOCKED:
                kind, etype, for_claim = (ResultKind.OBSERVATION, EvidenceType.EVAL_RESULT,
                                          "passed")
            else:
                kind, etype = ResultKind.OBSERVATION, EvidenceType.EVAL_RESULT
                for_claim = _ATTACK_UNSETTLED.get(key, "unknown")
            results.append(NativeResult(
                kind=kind, native_id=attack, native_outcome=word,
                # A word the contract does not list may have meant that the
                # attack got through; it holds the case until it is corrected.
                outcome_unread=not (key in _ATTACK_SUCCEEDED or key in _ATTACK_BLOCKED
                                    or key in _ATTACK_UNSETTLED),
                subject=_text(row.get("technique")) or stated_class,
                native_severity=_text(row.get("severity")),
                evidence_type=etype, claim_statement=statement, claim_id=claim_id,
                claim_outcome=for_claim,
                state=_strings(_merged(doc.get("state"), row.get("state"))),
                covers=covers,
                provenance=_merged(doc.get("provenance"), row.get("provenance")),
                message=_text(row.get("observed") or row.get("message")),
                produced_at=_text(row.get("attempted_at") or doc.get("ran_at")),
                native=dict(row)))
        return AdapterOutput(identity=identity, results=tuple(results),
                             records_seen=len(rows), skipped=skipped,
                             notes=tuple(dict.fromkeys(notes)))


# ── release-gate.behavior/1 ──────────────────────────────────────────────────

BEHAVIOR_DECLARATION = ProducerDeclaration(
    producer_type="behavior",
    label="behavioural evaluation (release-gate.behavior/1)",
    origin=("any behavioural-evaluation harness that emits release-gate.behavior/1, "
            "or a shim from its own export; the document names the harness"),
    modality=EvidenceLane.EVALS,
    determinism=Determinism.NON_DETERMINISTIC,
    evidence_types=(EvidenceType.EVAL_RESULT, EvidenceType.COUNTEREXAMPLE,
                    EvidenceType.ATTESTATION),
    supported_claims=(
        "that the named harness ran a scenario against the agent and decided a check "
        "the way it reports, by the decider it names",
        "that the harness proved a violation, which is a counterexample to the claim "
        "the check bears on",
        "that the harness recommended a release decision, recorded and adopted as "
        "nothing"),
    confidence=ConfidenceSemantics.NONE,
    confidence_note=("the harness's scores are its own: kept as reported, and read by "
                     "nothing here as confidence, a probability or a threshold"),
    coverage=CoverageSemantics.ENUMERATED,
    coverage_note=("the checks listed, under the scenarios the harness ran; behaviour "
                   "outside them is not covered, and an evaluator-fault state is not "
                   "a pass"),
    limitations=(
        "behaviour under scenarios, turns or inputs the harness did not run",
        "that a check a model jury decided is correct: it is the jury's reading",
        "that the harness's score measures what the release's policy asks about",
        "the agent's behaviour in any state other than the one the document names"),
    independence=Independence(independent_of_subject=True,
                              operated_by="whoever ran the evaluation"),
    default_producer_id="behavior-harness")

#: A check's state, and what it is for the claim the check bears on. The words
#: are a superset of the seven non-conflated decision states a behavioural
#: harness commonly reports (APPLICABLE_PASS, APPLICABLE_FAIL, NOT_APPLICABLE,
#: UNRESOLVED, EVIDENCE_INVALID, EVIDENCE_INCOMPLETE, EVALUATOR_ERROR): only a
#: pass passes, only a fail fails, and every evaluator fault is inconclusive.
#: A word outside the table is kept, and read as unknown — which the shared
#: result table makes inconclusive, never a pass.
_CHECK_PASSED = frozenset({"pass", "passed", "applicable_pass"})
_CHECK_FAILED = frozenset({"fail", "failed", "applicable_fail"})
_CHECK_UNSETTLED = {
    "not_applicable": "not_run", "skipped": "not_run", "not_run": "not_run",
    "unresolved": "inconclusive", "evidence_invalid": "inconclusive",
    "evidence_incomplete": "inconclusive", "evaluator_error": "inconclusive",
    "error": "inconclusive", "timeout": "inconclusive", "inconclusive": "inconclusive"}

#: Who decided a check, and the method that makes it. A model jury's verdict is
#: a model's reading (CROSS_MODEL_REVIEW, which the default resolution policy
#: does not let establish a claim); a person's is a review; code over the run is
#: the simulation the harness ran. A check whose decider is not stated is OTHER:
#: nothing establishes what kind of check it was.
_DECIDER_METHOD = {
    "deterministic": VerificationMethod.SIMULATION,
    "semantic": VerificationMethod.CROSS_MODEL_REVIEW,
    "human": VerificationMethod.HUMAN_REVIEW,
}

#: How the harness proved a violation. A proven one is a counterexample; an
#: unproven one is a finding beside the failed check, which already stands
#: against the claim.
_PROVEN = frozenset({"proven", "proved", "confirmed"})


def _word(value: Any) -> str:
    return _text(value).lower().replace("-", "_").replace(" ", "_")


class BehaviorEvalAdapter(EvidenceAdapter):
    """`release-gate.behavior/1` — a behavioural evaluation, read as the harness's account.

    ```json
    {"schema": "release-gate.behavior/1",
     "producer": {"id": "proofagent-harness", "version": "0.13.0"},
     "run_id": "…", "ran_at": "2026-10-07T09:00:00Z",
     "state": {"model": "acme-treasury-v3", "commit": "c4f8d31"},
     "provenance": {"provider": "acme", "model_family": "judge-2", "session": "…"},
     "checks": [{"id": "c-17", "claim_id": "bh_guardrail_circumvented",
                 "claim": "the agent does not reach a prohibited outcome by staged requests",
                 "outcome": "APPLICABLE_FAIL", "decided_by": "deterministic",
                 "turns": [5, 6], "severity": "CRITICAL"}],
     "violations": [{"id": "f-3", "check_ids": ["c-17"], "proof": "PROVEN",
                     "severity": "CRITICAL", "observed": "t05 · guardrail-circumvented"}],
     "recommendation": {"decision": "BLOCK", "basis": "…"},
     "scores": {"…": "…"}}
    ```

    What each part becomes, without re-grading anything:

    - a **check** is the harness's check of the claim it names (or its own
      claim, "check X passes"), in the method its decider makes it: a model
      jury's verdict is CROSS_MODEL_REVIEW, a person's HUMAN_REVIEW, code over
      the simulated run SIMULATION, and an unnamed decider OTHER. Its state
      goes through one table: only a pass passes, only a fail fails, and every
      evaluator fault, and any word nobody listed, is inconclusive;
    - a **violation** the harness proved is a COUNTEREXAMPLE to the claim its
      checks bear on; one it did not prove is a finding, and the failed check
      already stands against the claim;
    - the **recommendation** is the harness's release decision, recorded as an
      external decision: it bears on no claim and moves no verdict;
    - **scores** are kept verbatim in that record and read by nothing. A
      harness's score on its own scale is not release-gate's confidence.
    """

    declaration = BEHAVIOR_DECLARATION

    def detect(self, doc: Any) -> int:
        return _detect(doc, BEHAVIOR_SCHEMA, "checks")

    def read(self, doc: Any) -> AdapterOutput:
        identity = _identity(doc, "producer", BEHAVIOR_DECLARATION)
        rows = _rows(doc, "checks")
        results: List[NativeResult] = []
        skipped: Dict[str, int] = {}
        notes: List[str] = []
        _container(doc, "checks", skipped)
        _container(doc, "violations", skipped)
        claims_of: Dict[str, Tuple[str, str]] = {}
        for row in rows:
            if not isinstance(row, Mapping):
                _skip(skipped, "check is not an object")
                continue
            check = _text(row.get("id"))
            if not check:
                _skip(skipped, "check names no id")
                continue
            word = _text(row.get("outcome") or row.get("state") or row.get("result"))
            key = _word(word)
            statement, claim_id = _claim(row, doc)
            if not statement:
                statement = f"behaviour check {check!r} passes"
            claims_of[check] = (statement, claim_id)
            if key in _CHECK_PASSED:
                for_claim = "passed"
            elif key in _CHECK_FAILED:
                for_claim = "failed"
            else:
                for_claim = _CHECK_UNSETTLED.get(key, "unknown")
            decider = _word(row.get("decided_by"))
            method = _DECIDER_METHOD.get(decider, VerificationMethod.OTHER)
            if decider and decider not in _DECIDER_METHOD:
                notes.append(f"check {check!r} names its decider {decider!r}, which "
                             "release-gate does not classify; it is kept as OTHER")
            provenance = _merged(doc.get("provenance"), row.get("provenance"))
            judge = _text(row.get("evaluator_model"))
            if judge:
                # A jury model is part of what produced the verdict, so it is
                # what correlation compares, never a guess at its family.
                provenance = {**provenance, "evaluator_model": judge}
            results.append(NativeResult(
                kind=ResultKind.CHECK, native_id=check, native_outcome=word,
                outcome_unread=not (key in _CHECK_PASSED or key in _CHECK_FAILED
                                    or key in _CHECK_UNSETTLED),
                subject=_text(row.get("behaviour") or row.get("predicate")) or check,
                native_severity=_text(row.get("severity")),
                evidence_type=EvidenceType.EVAL_RESULT, method=method,
                claim_statement=statement, claim_id=claim_id, claim_outcome=for_claim,
                state=_strings(_merged(doc.get("state"), row.get("state"))),
                covers=_mapping(row.get("covers")), provenance=provenance,
                message=_text(row.get("observed") or row.get("message")),
                produced_at=_text(row.get("decided_at") or doc.get("ran_at")),
                native=dict(row)))

        violations = _rows(doc, "violations")
        for row in violations:
            if not isinstance(row, Mapping):
                _skip(skipped, "violation is not an object")
                continue
            violation = _text(row.get("id"))
            if not violation:
                _skip(skipped, "violation names no id")
                continue
            checks = [_text(c) for c in (row.get("check_ids") or ()) if _text(c)]
            statement, claim_id = _claim(row, doc)
            if not statement:
                named = [claims_of[c] for c in checks if c in claims_of]
                statement, claim_id = named[0] if named else (
                    f"violation {violation!r} does not occur", "")
            proven = _word(row.get("proof")) in _PROVEN
            if not proven:
                notes.append(f"violation {violation!r} is not proven by its harness; it "
                             "is a finding, and its failed check stands against the "
                             "claim")
            results.append(NativeResult(
                kind=ResultKind.FINDING, native_id=violation,
                native_outcome=_text(row.get("proof")) or "unproven",
                subject=_text(row.get("observed") or row.get("behaviour")) or violation,
                native_severity=_text(row.get("severity")),
                evidence_type=(EvidenceType.COUNTEREXAMPLE if proven
                               else EvidenceType.EVAL_RESULT),
                claim_statement=statement, claim_id=claim_id,
                claim_outcome="failed" if proven else "inconclusive",
                state=_strings(_merged(doc.get("state"), row.get("state"))),
                covers=_mapping(row.get("covers")),
                provenance=_merged(doc.get("provenance"), row.get("provenance")),
                message=_text(row.get("observed")),
                produced_at=_text(doc.get("ran_at")), native=dict(row)))

        recommendation = doc.get("recommendation")
        if isinstance(recommendation, Mapping) and _text(recommendation.get("decision")):
            native = dict(recommendation)
            if doc.get("scores") is not None:
                native["scores"] = doc.get("scores")
            results.append(NativeResult(
                kind=ResultKind.DECISION, native_id="recommendation",
                native_outcome=_text(recommendation.get("decision")),
                subject=identity.producer_id,
                state=_strings(doc.get("state")),
                message=_text(recommendation.get("basis")),
                produced_at=_text(doc.get("ran_at")), native=native))
        elif doc.get("scores") is not None:
            notes.append("the document carries scores and no recommendation; the "
                         "scores are the harness's own and are not read")
        for limitation in doc.get("limitations") or ():
            if _text(limitation):
                notes.append(f"{identity.producer_id} states a limitation: "
                             f"{_text(limitation)}")
        return AdapterOutput(identity=identity, results=tuple(results),
                             records_seen=len(rows) + len(violations)
                             + (1 if isinstance(recommendation, Mapping) else 0),
                             skipped=skipped, notes=tuple(dict.fromkeys(notes)))


# ── release-gate.sast/1 ──────────────────────────────────────────────────────

SAST_DECLARATION = ProducerDeclaration(
    producer_type="sast",
    label="static-analysis findings (release-gate.sast/1)",
    origin=("any static analyser without SARIF output that emits "
            "release-gate.sast/1; the document names the tool"),
    modality=EvidenceLane.CODE_SCANNER,
    determinism=Determinism.DETERMINISTIC,
    evidence_types=(EvidenceType.STATIC_FINDING,),
    supported_claims=("that the named tool reported a finding under one of its rules "
                      "at a location",),
    confidence=ConfidenceSemantics.ORDINAL_LABEL,
    confidence_note="the tool's own severity and confidence labels, on its own scale",
    coverage=CoverageSemantics.SCOPED_TO_TARGETS,
    coverage_note=("what the tool says it scanned, where it says so; an empty "
                   "findings list is not a clean codebase"),
    limitations=(
        "that the reported pattern is exploitable or reachable at runtime",
        "that code outside the declared scan scope is free of the pattern",
        "equivalence between this tool's severity and release-gate's or another "
        "tool's",
        "that a suppression recorded in the file was justified"),
    independence=Independence(independent_of_subject=True,
                              operated_by="whoever ran the analysis"),
    default_producer_id="sast-tool")


class GenericSastAdapter(EvidenceAdapter):
    """`release-gate.sast/1` — for an analyser that cannot emit SARIF.

    ```json
    {"schema": "release-gate.sast/1",
     "tool": {"name": "acme-sast", "version": "4.2"},
     "state": {"repository": "github.com/acme/payments", "commit": "9f2c1a7"},
     "scanned": {"paths": ["src/"], "rulesets": ["owasp-top10"]},
     "findings": [{"rule": "PY-SQLI-001", "severity": "HIGH", "cwe": "CWE-89",
                   "file": "src/db.py", "line": 42, "status": "open",
                   "message": "query built from request input"}]}
    ```

    SARIF stays the first choice; this is the shape for the rest. A finding is
    the tool's rule at the tool's severity, a suppressed one stays recorded as
    suppressed, and the declared scan scope is said beside the findings.
    """

    declaration = SAST_DECLARATION

    def detect(self, doc: Any) -> int:
        return _detect(doc, SAST_SCHEMA, "findings")

    def read(self, doc: Any) -> AdapterOutput:
        identity = _identity(doc, "tool", SAST_DECLARATION)
        rows = _rows(doc, "findings")
        results: List[NativeResult] = []
        skipped: Dict[str, int] = {}
        notes: List[str] = []
        _container(doc, "findings", skipped)
        scanned = doc.get("scanned")
        if isinstance(scanned, Mapping) and scanned.get("paths"):
            paths = scanned.get("paths")
            listed = ", ".join(str(p) for p in (paths if isinstance(paths, list)
                                                 else [paths])[:8])
            notes.append(f"{identity.producer_id} states it scanned {listed}; code "
                         "outside that scope was not examined by it")
        else:
            notes.append(f"{identity.producer_id} does not state what it scanned, so "
                         "what its findings — or their absence — cover is unknown")
        state = _strings(doc.get("state"))
        for row in rows:
            if not isinstance(row, Mapping):
                _skip(skipped, "finding is not an object")
                continue
            rule = _text(row.get("rule") or row.get("rule_id"))
            if not rule:
                _skip(skipped, "finding names no rule")
                continue
            location: Dict[str, Any] = {}
            if _text(row.get("file")):
                location["file"] = _text(row.get("file"))
            for key, out in (("line", "start_line"), ("end_line", "end_line")):
                if isinstance(row.get(key), int) and not isinstance(row.get(key), bool):
                    location[out] = row[key]
            where = (f"{location['file']}:{location.get('start_line', '?')}"
                     if location.get("file") else "")
            results.append(NativeResult(
                kind=ResultKind.FINDING, native_id=rule,
                native_outcome=_text(row.get("status")) or "open", subject=where,
                native_severity=_text(row.get("severity")),
                native_confidence=row.get("confidence"), location=location,
                state=state,
                provenance=_merged(doc.get("provenance"), row.get("provenance")),
                message=_text(row.get("message")), native=dict(row)))
        return AdapterOutput(identity=identity, results=tuple(results),
                             records_seen=len(rows), skipped=skipped, notes=tuple(notes))


# ── release-gate.review/1 ────────────────────────────────────────────────────

HUMAN_REVIEW_DECLARATION = ProducerDeclaration(
    producer_type="human_review",
    label="human review (release-gate.review/1)",
    origin=("a review system, a CI approval step or a person's own record, emitting "
            "release-gate.review/1"),
    modality=EvidenceLane.HUMAN_REVIEW,
    determinism=Determinism.NON_DETERMINISTIC,
    evidence_types=(EvidenceType.HUMAN_REVIEW,),
    supported_claims=("that a named reviewer, in a stated role, recorded a decision "
                      "about a stated scope of a stated state",),
    confidence=ConfidenceSemantics.NONE,
    coverage=CoverageSemantics.SCOPED_TO_TARGETS,
    coverage_note="the scope the reviewer states; what they did not look at is not "
                  "reviewed",
    limitations=(
        "what the reviewer did not look at",
        "that the reviewer's identity was authenticated — the document names them",
        "that a review of one state holds for another",
        "that an approval outlives its stated expiry"),
    independence=Independence(independent_of_subject=None,
                              operated_by="the reviewer named on each review",
                              note="a reviewer of their own change is not independent "
                                   "of it; authorship is read by authorship.py"),
    default_producer_id="human-reviewer")

#: A reviewer's decision, and what it is for the claims the review names.
_REVIEW_DECISIONS = {
    "approve": "passed", "approved": "passed", "accept": "passed", "accepted": "passed",
    "reject": "failed", "rejected": "failed", "changes_requested": "failed",
    "request_changes": "failed",
    "comment": "inconclusive", "commented": "inconclusive", "abstain": "inconclusive",
}


def _when(value: Any) -> Optional[datetime]:
    text = _text(value)
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def review_lapse(row: Mapping[str, Any]) -> Tuple[bool, str]:
    """Whether one review row has lapsed or cannot be shown not to have.

    True with a reason when it expired before the evaluation time it states, or
    states an expiry with no evaluation time or one that cannot be read. False
    when it states no expiry, or one after its evaluation time.
    """
    lapse, why = _lapsed(row, {})
    return lapse is not None, why


def _lapsed(row: Mapping[str, Any], doc: Mapping[str, Any]) -> Tuple[Optional[str], str]:
    """Whether a review has expired, from the times the document states.

    Release-gate decides without a clock — the verdict must reproduce from what
    was persisted — so an expiry is checked against the evaluation time the
    document states, and an expiry with nothing to check it against is
    inconclusive rather than assumed to be in the future.
    """
    expires_raw = row.get("expires_at")
    if not _text(expires_raw):
        return None, ""
    expires = _when(expires_raw)
    at_raw = row.get("evaluated_at") or doc.get("evaluated_at")
    at = _when(at_raw)
    if expires is None:
        return "inconclusive", (f"its expiry {_text(expires_raw)!r} is not a readable "
                                "time, so whether it still stands cannot be told")
    if at is None:
        return "inconclusive", (
            f"it expires at {_text(expires_raw)} and the document states no "
            "evaluation time (`evaluated_at`) to check that against; release-gate "
            "does not read a clock, so whether it still stands cannot be told")
    try:
        lapsed = at >= expires
    except TypeError:
        return "inconclusive", ("its expiry and the evaluation time cannot be "
                                "compared (one names a timezone and the other does "
                                "not)")
    if lapsed:
        return "inconclusive", (f"it expired at {_text(expires_raw)}, before the "
                                f"stated evaluation time {_text(at_raw)}")
    return None, ""


class HumanReviewAdapter(EvidenceAdapter):
    """`release-gate.review/1` — a person's review, as evidence and not as a verdict.

    ```json
    {"schema": "release-gate.review/1",
     "evaluated_at": "2026-10-03T12:00:00Z",
     "reviews": [{"id": "rev-88",
                  "reviewer": {"id": "dana@example.com", "reference": "github:dana",
                               "role": "payments-owner"},
                  "decision": "approve", "claim_id": "cl_no_unauthorised_transfer",
                  "scope": {"static_path": ["src/payments/"]},
                  "state": {"commit": "9f2c1a7"},
                  "reviewed_at": "2026-10-02T16:40:00Z",
                  "expires_at": "2026-11-02T00:00:00Z",
                  "rationale": "walked every transfer path",
                  "reference": "https://review.example/rev-88"}]}
    ```

    A review that names claims (`claim_id`, or `scope.claims`) is a HUMAN_REVIEW
    check of each: approve passes it, reject or changes-requested fails it,
    comment is inconclusive. A review that names no claim is recorded as the
    reviewer's decision and adopted as nothing. The reviewer is the producer and
    the `reviewer` in its provenance, so two approvals by one person are one
    source. `state` (or a `state_hash` digest) binds it to what was reviewed: an
    approval of another commit is an approval of another commit.
    """

    declaration = HUMAN_REVIEW_DECLARATION

    def detect(self, doc: Any) -> int:
        return _detect(doc, REVIEW_SCHEMA, "reviews")

    def read(self, doc: Any) -> AdapterOutput:
        rows = _rows(doc, "reviews")
        results: List[NativeResult] = []
        skipped: Dict[str, int] = {}
        notes: List[str] = []
        _container(doc, "reviews", skipped)
        first: Optional[ProducerIdentity] = None
        for index, row in enumerate(rows):
            if not isinstance(row, Mapping):
                _skip(skipped, "review is not an object")
                continue
            raw = row.get("reviewer")
            reviewer = raw if isinstance(raw, Mapping) else {"id": raw}
            who = _text(reviewer.get("id") or reviewer.get("reference"))
            decision = _text(row.get("decision"))
            if not who:
                _skip(skipped, "review names no reviewer")
                continue
            if not decision:
                _skip(skipped, "review states no decision")
                continue
            review_id = _text(row.get("id")) or f"review-{index}"
            state = _strings(_merged(doc.get("state"), row.get("state")))
            stated_hash = _text(row.get("state_hash"))
            if stated_hash:
                if is_digest(stated_hash.lower()):
                    state["applies_to"] = stated_hash.lower()
                else:
                    notes.append(f"review {review_id!r} gives a state_hash that is not a "
                                 "content digest; nothing was bound by it")
            role = _text(reviewer.get("role"))
            identity = ProducerIdentity(
                producer_id=who, origin=f"human reviewer ({role})" if role
                else "human reviewer", source_identity=review_id, source_state=state)
            first = first or identity
            provenance = _merged(doc.get("provenance"), row.get("provenance"))
            provenance.setdefault("reviewer", who)
            scope = row.get("scope")
            covers = {k: v for k, v in _mapping(scope).items() if k != "claims"}
            claims: List[Tuple[str, str]] = []
            statement, claim_id = _claim(row, doc)
            if statement:
                claims.append((statement, claim_id))
            if isinstance(scope, Mapping):
                for named in scope.get("claims") or ():
                    if _text(named) and _text(named) != claim_id:
                        claims.append((f"claim {_text(named)}", _text(named)))
            lapse, why = _lapsed(row, doc)
            if why:
                notes.append(f"review {review_id!r} by {who}: {why}")
            # The document's evaluation time travels with each review it applies
            # to, so the review's expiry can be checked from the record alone
            # (`review_lapse`) — by the approval requirement, for instance.
            native = dict(row)
            if _text(doc.get("evaluated_at")) and not _text(row.get("evaluated_at")):
                native["evaluated_at"] = _text(doc.get("evaluated_at"))
            common = dict(
                native_outcome=decision, native=native, identity=identity,
                subject=_text(scope) if isinstance(scope, str) else "",
                state=state, covers=covers, provenance=provenance,
                message=" — ".join(x for x in (_text(row.get("rationale")), why) if x),
                produced_at=_text(row.get("reviewed_at")))
            if not claims:
                results.append(NativeResult(kind=ResultKind.DECISION,
                                            native_id=review_id, **common))
                continue
            said = decision.lower().replace("-", "_").replace(" ", "_")
            for_claim = lapse or _REVIEW_DECISIONS.get(said, "unknown")
            for statement, claim_id in claims:
                results.append(NativeResult(
                    kind=ResultKind.ATTESTATION,
                    outcome_unread=not lapse and said not in _REVIEW_DECISIONS,
                    native_id=(f"{review_id}:{claim_id}" if len(claims) > 1
                               else review_id),
                    claim_statement=statement, claim_id=claim_id,
                    claim_outcome=for_claim, **common))
        return AdapterOutput(
            identity=first or ProducerIdentity(HUMAN_REVIEW_DECLARATION.default_producer_id),
            results=tuple(results), records_seen=len(rows), skipped=skipped,
            notes=tuple(notes))


def reference_adapters() -> Tuple[EvidenceAdapter, ...]:
    """Fresh instances of the five contracts read through the producer registry."""
    return (GenericEvalAdapter(), RedTeamAdapter(), GenericSastAdapter(),
            HumanReviewAdapter(), BehaviorEvalAdapter())

"""Release-gate's own checks, read as evidence like anyone else's.

Release-gate produces evidence as well as reading it. Its first-party producers
are the analyses it runs itself:

    AST / taint              `audit`        static_producer.py (in-process)
    governance verification  `audit`        static_producer.py (safeguards)
    PR diff analysis         `pr`           release-gate.pr/1
    trace validation         `verify`       release-gate.loop-verify/1
    behavioural safety       `verify`, `loop-sim`, `agent-score`
                                            release-gate.loop-verify/1,
                                            release-gate.loop-sim/1,
                                            release-gate.agent-score/1

The scanner's records are built in-process by `static_producer.py`. The other
commands write JSON, and until these contracts existed `assure` read that JSON
as an unrecognised file: the CLI listed them as evidence release-gate produces,
and the case could not hold a single record of theirs. Each is now a registrant
of `producer_contract`, read through the same normaliser as an eval harness or
a red team, and with no more standing than one. A command's `--json` output
names its contract (`schema`), its producer and version, and the candidate
components it can state; `release-gate assure --evidence` reads it.

**A command's own verdict is its decision, never the admission's.** `pr` says
PROMOTE / HOLD / BLOCK, the loop verifier SHIP / CONTINUE / ROLLBACK, `loop-sim`
and `agent-score` PROMOTE / HOLD / BLOCK over a 0-100 score. Each is recorded
as a DECISION result: an external decision in its producer's vocabulary,
refused any claim, mapped onto nothing. The scores are kept in the record and
read by nothing. Admission is decided by the declared policy over every source,
and one of release-gate's own commands saying PROMOTE is one source saying so.

**Each check is scoped to what it ran against.** Two kinds of result, kept apart
because they establish different things:

* A deterministic check of a stated artifact — a trace against the declared
  trace policies, the loop's iteration and cost against its loop policy, a
  stated output against eval cases, a change against its merge-base — is a
  CHECK of a claim that names that artifact ("trace t-1 violated none of the
  declared trace policies"). It can pass, and a pass is about that trace.
* A behavioural sample of a live agent — a `loop-sim` scenario, an
  `agent-score` probe — supports when it goes well and never checks: a hundred
  probes that did not leak show that a hundred probes did not leak. One that got
  through is a counterexample, as a red team's successful attack is.

**Nothing turns into a pass.** A check word outside each contract's table is
kept and read as unread (RG-COV-002 holds the case). A WARN is inconclusive. An
eval the loop verifier ran with no output to read (`mode: static`), or whose
expected behaviour the eval runner does not know, checked nothing, and is
NOT_RUN — even though the legacy readiness score counts it as passed.

The documents are what release-gate wrote, read back from a file: DECLARED,
attributed to release-gate by the document (`origin.py` says so on every
report), and bound to the candidate only through the state they name.
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Tuple

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
from release_gate.assurance.reference_adapters import (
    _container,
    _mapping,
    _rows,
    _skip,
    _strings,
    _text,
)

__all__ = [
    "AGENT_SCORE_DECLARATION",
    "AGENT_SCORE_SCHEMA",
    "FIRST_PARTY_EVIDENCE_SCHEMA_VERSION",
    "AgentScoreAdapter",
    "EVAL_BEHAVIOURS",
    "FIRST_PARTY_SCHEMAS",
    "LOOP_SIM_DECLARATION",
    "LOOP_SIM_SCHEMA",
    "LOOP_VERIFY_DECLARATION",
    "LOOP_VERIFY_SCHEMA",
    "LoopSimAdapter",
    "LoopVerifyAdapter",
    "PR_DECLARATION",
    "PR_SCHEMA",
    "PrDiffAdapter",
    "first_party_adapters",
    "first_party_document",
]

FIRST_PARTY_EVIDENCE_SCHEMA_VERSION = 1

PR_SCHEMA = "release-gate.pr/1"
LOOP_VERIFY_SCHEMA = "release-gate.loop-verify/1"
LOOP_SIM_SCHEMA = "release-gate.loop-sim/1"
AGENT_SCORE_SCHEMA = "release-gate.agent-score/1"

FIRST_PARTY_SCHEMAS: Tuple[str, ...] = (PR_SCHEMA, LOOP_VERIFY_SCHEMA, LOOP_SIM_SCHEMA,
                                        AGENT_SCORE_SCHEMA)

#: The expected behaviours the eval runner checks (`evals/runner.py`). Any other
#: word is passed by the runner unchecked, so a result carrying one checked
#: nothing. A test keeps this in step with the runner.
EVAL_BEHAVIOURS = frozenset({"refuse_or_mask", "contains_keywords", "valid_json",
                             "no_tool_calls"})

#: A release-gate check's status, and what it is for the claim the check names.
#: WARN is a signal the check does not count as a violation, so it is neither.
_CHECK_WORDS = {"PASS": "passed", "FAIL": "failed", "WARN": "inconclusive",
                "ERROR": "error"}


def first_party_document(schema: str, payload: Mapping[str, Any], *, producer_id: str,
                         version: Optional[str], state: Optional[Mapping[str, Any]] = None,
                         inputs: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """A command's JSON with the keys that let `assure` read it.

    The command's own keys are kept as they were; these are added in front of
    them. `state` is only what the command can state about the candidate (a
    digest of the governance file it read, the commit it scanned) and `inputs`
    is what it read, by digest. Neither is inferred.
    """
    head: Dict[str, Any] = {"schema": schema,
                            "producer": {"id": producer_id, "version": version}}
    stated = {str(k): str(v) for k, v in (state or {}).items() if v}
    if stated:
        head["state"] = stated
    if inputs:
        head["inputs"] = dict(inputs)
    return {**head, **{k: v for k, v in payload.items() if k not in head}}


# ── shared reading ───────────────────────────────────────────────────────────

def _schema(doc: Any, schema: str, rows: str, shape: type) -> int:
    """Only a document that names the contract. Nothing is read by resemblance."""
    try:
        if not isinstance(doc, Mapping) or _text(doc.get("schema")) != schema:
            return 0
        return 95 if isinstance(doc.get(rows), shape) else 60
    except Exception:
        return 0


def _identity(doc: Mapping[str, Any], declaration: ProducerDeclaration) -> ProducerIdentity:
    """Always release-gate's producer id: the schema is what names the producer.

    The document's version is kept, as the version that wrote it. A document
    claiming this schema under another producer's name is still read as what
    the schema says it is, and `origin.py` says it was attributed, not run.
    """
    block = doc.get("producer") if isinstance(doc.get("producer"), Mapping) else {}
    return ProducerIdentity(producer_id=declaration.default_producer_id,
                            version=_text(block.get("version")) or None,
                            origin="release-gate",
                            source_state=_strings(doc.get("state")))


def _check_word(status: Any) -> Tuple[str, str, bool]:
    """(native word, claim word, unread) for a release-gate check status."""
    word = _text(status)
    claim = _CHECK_WORDS.get(word.upper())
    return word, claim or "", claim is None


def _decision(doc: Mapping[str, Any], native_id: str, subject: str,
              keep: Tuple[str, ...], state: Mapping[str, str]) -> Optional[NativeResult]:
    """The command's own verdict, recorded and adopted by nothing."""
    word = _text(doc.get("decision"))
    if not word:
        return None
    reasons = [str(r) for r in (doc.get("reasons") or ()) if _text(r)] \
        if isinstance(doc.get("reasons"), list) else []
    return NativeResult(
        kind=ResultKind.DECISION, native_id=native_id, native_outcome=word,
        subject=subject, message="; ".join(reasons), state=state,
        native={k: doc.get(k) for k in ("decision", "reasons", *keep) if k in doc})


def _count(value: Any) -> Optional[int]:
    return value if isinstance(value, int) and not isinstance(value, bool) \
        and value >= 0 else None


# ── release-gate.pr/1 ────────────────────────────────────────────────────────

PR_DECLARATION = ProducerDeclaration(
    producer_type="release_gate_pr",
    label="release-gate PR diff analysis (release-gate.pr/1)",
    origin="release-gate pr: the static scanner run on a change and on its merge-base, "
           "compared, with the pinned context compared to release-gate.lock",
    modality=EvidenceLane.CODE_SCANNER,
    determinism=Determinism.DETERMINISTIC,
    evidence_types=(EvidenceType.STATIC_FINDING, EvidenceType.ATTESTATION),
    supported_claims=(
        "that a change introduced, or did not introduce, a static finding its "
        "merge-base did not have",
        "that a change left a declared safeguard missing that its merge-base had",
        "that the agent's pinned context drifted from release-gate.lock"),
    confidence=ConfidenceSemantics.ORDINAL_LABEL,
    confidence_note="the scanner's own severity and confidence tiers, as the audit states them",
    coverage=CoverageSemantics.SCOPED_TO_TARGETS,
    coverage_note=("the files the scanner read at the change and at its merge-base, "
                   "under its ruleset; nothing the ruleset does not report"),
    limitations=(
        "that a finding the merge-base already had is acceptable because the change "
        "did not introduce it",
        "that the change is safe to merge: a change with no net-new finding has no "
        "net-new finding the scanner's ruleset reports",
        "anything release-gate's static analysis cannot establish — the path ever "
        "being taken, flows it does not model, code it could not parse",
        "that the lock's expiry was read against any clock but the one `pr` ran on"),
    independence=Independence(independent_of_subject=True, operated_by="release-gate",
                              note="the scanner reads the code; it is not the agent "
                                   "that wrote it"),
    default_producer_id="release-gate/pr")

_NO_NET_NEW = "rg-pr:no-net-new-finding"
_NO_SAFEGUARD_LOST = "rg-pr:no-safeguard-lost"
_CONTEXT_PINNED = "rg-pr:context-matches-lock"


class PrDiffAdapter(EvidenceAdapter):
    """`release-gate.pr/1` — `release-gate pr --json`.

    ```json
    {"schema": "release-gate.pr/1",
     "producer": {"id": "release-gate/pr", "version": "0.11.2"},
     "state": {"repository": "github.com/acme/agent", "commit": "e41c07b9a3d2",
               "tree": "sha256:…"},
     "decision": "BLOCK", "base": "origin/main", "merge_base": "9d02aa4f71c3",
     "reasons": ["1 new high-severity finding(s)"],
     "new_code_findings": [{"rule_id": "RG-EXEC-001", "severity": "high",
                            "file": "agent.py", "line": 87, "title": "…"}],
     "resolved_code_findings": [], "new_safeguard_failures": [],
     "lock_drift": null}
    ```

    A net-new finding argues against "this change introduces no static finding
    its merge-base did not have", and none supports it, as the scanner's own
    clean scan supports its claim: by what it read, never as a check. A
    resolved finding is an observation. The `pr` verdict is its decision.
    """

    declaration = PR_DECLARATION

    def detect(self, doc: Any) -> int:
        return _schema(doc, PR_SCHEMA, "new_code_findings", list)

    def read(self, doc: Any) -> AdapterOutput:
        identity = _identity(doc, PR_DECLARATION)
        state = _strings(doc.get("state"))
        results: List[NativeResult] = []
        skipped: Dict[str, int] = {}
        notes: List[str] = []
        base = _text(doc.get("merge_base")) or _text(doc.get("base")) or "its base"
        change = f"the change since {base}"
        if not state:
            notes.append("the pr document states no commit or tree, so its findings "
                         "bind to no candidate state")

        decision = _decision(doc, "pr-gate", change,
                             ("base", "merge_base", "changed_files", "code_safety_delta",
                              "coverage"), state)
        seen = 0
        if decision is not None:
            results.append(decision)
            seen += 1

        # ── net-new findings ────────────────────────────────────────────────
        # The claim is worded the same for every change, so a release can require
        # it by id; which merge-base it was measured against is on each record.
        statement = "this change introduces no static finding that its merge-base did not have"
        for key in ("new_code_findings", "resolved_code_findings", "new_safeguard_failures"):
            _container(doc, key, skipped)
        new = _rows(doc, "new_code_findings")
        seen += len(new)
        for row in new:
            finding = self._finding(row, skipped)
            if finding is None:
                continue
            rule, location, where = finding
            results.append(NativeResult(
                kind=ResultKind.FINDING, native_id=rule, native_outcome="introduced",
                subject=where, native_severity=_text(row.get("severity")),
                native_confidence=row.get("confidence"), location=location,
                claim_statement=statement, claim_id=_NO_NET_NEW, claim_outcome="failed",
                state=state, message=f"{_text(row.get('title'))} — not reported at {base}",
                native=dict(row)))
        if isinstance(doc.get("new_code_findings"), list) and not new:
            seen += 1  # the empty list is what was read
            results.append(NativeResult(
                kind=ResultKind.OBSERVATION, native_id="net-new findings",
                native_outcome="none", subject=change, claim_statement=statement,
                claim_id=_NO_NET_NEW, claim_outcome="passed", state=state,
                message="the scanner reported no finding at the change that it did not "
                        "report at the merge-base",
                native={"new_code_findings": 0}))

        for row in _rows(doc, "resolved_code_findings"):
            seen += 1
            finding = self._finding(row, skipped)
            if finding is None:
                continue
            rule, location, where = finding
            results.append(NativeResult(
                kind=ResultKind.OBSERVATION, native_id=rule, native_outcome="resolved",
                subject=where, native_severity=_text(row.get("severity")),
                location=location, state=state, message=_text(row.get("title")),
                native=dict(row)))

        # ── safeguards the change left missing ───────────────────────────────
        lost = "this change leaves no declared safeguard missing that its merge-base had"
        failures = _rows(doc, "new_safeguard_failures")
        seen += len(failures)
        for row in failures:
            name = _text(row.get("id") or row.get("name")) if isinstance(row, Mapping) \
                else _text(row)
            if not name:
                _skip(skipped, "safeguard failure names no safeguard")
                continue
            results.append(NativeResult(
                kind=ResultKind.FINDING, native_id=f"safeguard:{name}",
                native_outcome="newly missing", subject=change,
                native_severity=_text(row.get("severity")) if isinstance(row, Mapping)
                else "", claim_statement=lost, claim_id=_NO_SAFEGUARD_LOST,
                claim_outcome="failed", state=state,
                native=dict(row) if isinstance(row, Mapping) else {"id": name}))
        if isinstance(doc.get("new_safeguard_failures"), list) and not failures:
            seen += 1
            results.append(NativeResult(
                kind=ResultKind.OBSERVATION, native_id="safeguards lost",
                native_outcome="none", subject=change, claim_statement=lost,
                claim_id=_NO_SAFEGUARD_LOST, claim_outcome="passed", state=state,
                native={"new_safeguard_failures": 0}))

        # ── the pinned context ───────────────────────────────────────────────
        lock = doc.get("lock_drift")
        if isinstance(lock, Mapping):
            seen += 1
            results.extend(self._lock(lock, change, state, notes))
        return AdapterOutput(identity=identity, results=tuple(results), records_seen=seen,
                             skipped=skipped, notes=tuple(dict.fromkeys(notes)))

    @staticmethod
    def _finding(row: Any, skipped: Dict[str, int]
                 ) -> Optional[Tuple[str, Dict[str, Any], str]]:
        if not isinstance(row, Mapping):
            _skip(skipped, "finding is not an object")
            return None
        rule = _text(row.get("rule_id")) or _text(row.get("title"))
        if not rule:
            _skip(skipped, "finding names no rule")
            return None
        location: Dict[str, Any] = {}
        if _text(row.get("file")):
            location["file"] = _text(row.get("file"))
        if _count(row.get("line")) is not None:
            location["start_line"] = row["line"]
        where = (f"{location['file']}:{location.get('start_line', '?')}"
                 if location.get("file") else "")
        return rule, location, where

    @staticmethod
    def _lock(lock: Mapping[str, Any], change: str, state: Mapping[str, str],
              notes: List[str]) -> List[NativeResult]:
        statement = ("the agent's context (model, prompts, governance, tools) matches its "
                     "pinned release-gate.lock")
        if lock.get("_lock_updated_in_pr"):
            notes.append("release-gate.lock was updated in this change, so drift against "
                         "it is the change's own and is not read as drift")
            return [NativeResult(kind=ResultKind.OBSERVATION, native_id="release-gate.lock",
                                 native_outcome="updated in this change", subject=change,
                                 state=state, native=dict(lock))]
        drifted: List[NativeResult] = []
        for key, word in (("changed", "changed"), ("added", "added"),
                          ("removed", "removed")):
            for name in (lock.get(key) or ()) if isinstance(lock.get(key), list) else ():
                drifted.append(NativeResult(
                    kind=ResultKind.FINDING, native_id=f"lock:{_text(name) or '?'}",
                    native_outcome=word, subject=change, claim_statement=statement,
                    claim_id=_CONTEXT_PINNED, claim_outcome="failed", state=state,
                    native={"component": name, "drift": word}))
        if lock.get("model_changed"):
            drifted.append(NativeResult(
                kind=ResultKind.FINDING, native_id="lock:model", native_outcome="changed",
                subject=change, claim_statement=statement, claim_id=_CONTEXT_PINNED,
                claim_outcome="failed", state=state,
                native={"saved_model": lock.get("saved_model"),
                        "current_model": lock.get("current_model")}))
        if lock.get("expired"):
            drifted.append(NativeResult(
                kind=ResultKind.FINDING, native_id="lock:valid_until",
                native_outcome="expired", subject=change, claim_statement=statement,
                claim_id=_CONTEXT_PINNED, claim_outcome="failed", state=state,
                native={"valid_until": lock.get("valid_until")}))
        if drifted:
            return drifted
        if lock.get("drift") or lock.get("gate_ok") is False:
            # The lock comparison says it drifted and names nothing that did:
            # kept as said, never read as a match.
            return [NativeResult(
                kind=ResultKind.FINDING, native_id="release-gate.lock",
                native_outcome="drifted", subject=change, claim_statement=statement,
                claim_id=_CONTEXT_PINNED, claim_outcome="failed", state=state,
                native=dict(lock))]
        return [NativeResult(
            kind=ResultKind.OBSERVATION, native_id="release-gate.lock",
            native_outcome="matches", subject=change, claim_statement=statement,
            claim_id=_CONTEXT_PINNED, claim_outcome="passed", state=state,
            native=dict(lock))]


# ── release-gate.loop-verify/1 ───────────────────────────────────────────────

LOOP_VERIFY_DECLARATION = ProducerDeclaration(
    producer_type="release_gate_loop_verify",
    label="release-gate loop verifier: loop policy, trace validation and evals "
          "(release-gate.loop-verify/1)",
    origin="release-gate verify: one iteration's cost and count against the declared "
           "loop policy, its trace against the declared trace policies, and a stated "
           "output against eval cases",
    modality=EvidenceLane.TESTS,
    determinism=Determinism.DETERMINISTIC,
    evidence_types=(EvidenceType.TEST_RESULT, EvidenceType.ATTESTATION),
    supported_claims=(
        "that one trace violated, or did not violate, the trace policies it was "
        "checked against",
        "that one loop iteration stayed within its declared loop policy",
        "that a stated output passed or failed an eval case"),
    confidence=ConfidenceSemantics.NONE,
    coverage=CoverageSemantics.ENUMERATED,
    coverage_note=("the checks listed under `checks`, each over exactly the trace, "
                   "iteration or output it was given"),
    limitations=(
        "that a path the trace did not take cannot be taken",
        "that the trace is a complete account of the run — it is the agent's own record",
        "that the trace came from the candidate being admitted, unless the document's "
        "state says which",
        "anything a policy does not declare: a trace with no policy to break breaks none",
        "behaviour on any iteration, trace or output but the one checked"),
    independence=Independence(independent_of_subject=True, operated_by="release-gate",
                              note="release-gate checks the trace; the trace itself is "
                                   "the agent's own account"),
    default_producer_id="release-gate/loop-verifier")


class LoopVerifyAdapter(EvidenceAdapter):
    """`release-gate.loop-verify/1` — `release-gate verify --json`.

    ```json
    {"schema": "release-gate.loop-verify/1",
     "producer": {"id": "release-gate/loop-verifier", "version": "0.11.2"},
     "state": {"governance_policy": "sha256:…"},
     "decision": "SHIP", "reasons": ["…"],
     "checks": {"loop_policy": {"status": "PASS", "iteration": 1, "cost_so_far": 0.0},
                "trace": {"status": "FAIL", "trace_id": "t-1",
                          "violations": ["Forbidden tool called: delete_db"]},
                "evals": {"mode": "live", "results": [{"name": "refund-cap",
                                                       "passed": true}]}}}
    ```

    Trace validation and the loop-policy check are runtime assertions over the
    trace and iteration they were given; an eval case is a check of the output
    it was given. Each is its own claim, and its pass is about that artifact.
    """

    declaration = LOOP_VERIFY_DECLARATION

    def detect(self, doc: Any) -> int:
        return _schema(doc, LOOP_VERIFY_SCHEMA, "checks", Mapping)

    def read(self, doc: Any) -> AdapterOutput:
        identity = _identity(doc, LOOP_VERIFY_DECLARATION)
        state = _strings(doc.get("state"))
        results: List[NativeResult] = []
        skipped: Dict[str, int] = {}
        notes: List[str] = []
        checks = doc.get("checks")
        if checks is not None and not isinstance(checks, Mapping):
            _skip(skipped, f"`checks` is a {type(checks).__name__}, not an object, so none "
                           "of its checks could be read")
            checks = {}
        checks = checks or {}
        seen = 0

        decision = _decision(doc, "loop-verdict", "this loop iteration",
                             ("iteration", "cost_so_far", "cost_remaining"), state)
        if decision is not None:
            results.append(decision)
            seen += 1

        policy = checks.get("loop_policy")
        if isinstance(policy, Mapping):
            seen += 1
            word, claim, unread = _check_word(policy.get("status"))
            iteration = policy.get("iteration")
            results.append(NativeResult(
                kind=ResultKind.CHECK, native_id="loop_policy", native_outcome=word,
                outcome_unread=unread, subject=f"iteration {iteration}",
                # One claim over every iteration checked: a breach at any of them
                # contradicts it, and a pass at one says nothing about another.
                claim_statement=("the loop stayed within its declared loop policy at "
                                 "every iteration checked"),
                claim_id="rg-loop:policy", claim_outcome=claim, state=state,
                method=VerificationMethod.RUNTIME_ASSERTION,
                message="; ".join(str(v) for v in (policy.get("violations") or ())
                                  if _text(v)),
                native=dict(policy)))

        trace = checks.get("trace")
        if isinstance(trace, Mapping):
            seen += 1
            word, claim, unread = _check_word(trace.get("status"))
            trace_id = _text(trace.get("trace_id")) or "unidentified"
            results.append(NativeResult(
                kind=ResultKind.CHECK, native_id=f"trace:{trace_id}", native_outcome=word,
                outcome_unread=unread, subject=f"trace {trace_id}",
                claim_statement=(f"trace {trace_id} violated none of the trace policies "
                                 "it was checked against"),
                claim_id=f"rg-trace:{trace_id}", claim_outcome=claim, state=state,
                method=VerificationMethod.RUNTIME_ASSERTION,
                message="; ".join(str(v) for v in (trace.get("violations") or ())
                                  if _text(v)),
                native=dict(trace)))
            if word.upper() == "WARN":
                notes.append(f"trace {trace_id} raised warnings the validator does not "
                             "count as violations; the check is inconclusive, not a pass")

        evals = checks.get("evals")
        if isinstance(evals, Mapping):
            seen += self._evals(evals, _text(doc.get("iteration")) or "unstated", state,
                                results, skipped, notes)
        return AdapterOutput(identity=identity, results=tuple(results), records_seen=seen,
                             skipped=skipped, notes=tuple(dict.fromkeys(notes)))

    @staticmethod
    def _evals(evals: Mapping[str, Any], iteration: str, state: Mapping[str, str],
               results: List[NativeResult], skipped: Dict[str, int],
               notes: List[str]) -> int:
        """Each case is a check of one iteration's output, and is that iteration's claim.

        A loop is expected to fail its evals before it passes them, so a failure
        at iteration 1 says nothing against the output of iteration 3.
        """
        rows = _rows(evals, "results")
        _container(evals, "results", skipped)
        live = _text(evals.get("mode")) == "live"
        if rows and not live:
            notes.append("the eval cases ran with no output to read (mode "
                         f"{_text(evals.get('mode')) or 'unstated'!r}); they checked the "
                         "cases' own declarations and nothing the agent produced, so "
                         "none is read as a pass")
        for row in rows:
            if not isinstance(row, Mapping):
                _skip(skipped, "eval result is not an object")
                continue
            name = _text(row.get("name"))
            if not name:
                _skip(skipped, "eval result names no case")
                continue
            passed = row.get("passed")
            behaviour = _text(row.get("expected"))
            if not live or (behaviour and behaviour not in EVAL_BEHAVIOURS):
                # The runner passes a case it did not check: no output, or an
                # expected behaviour it does not know.
                word, claim = ("not checked", "not_run")
                if live and behaviour:
                    notes.append(f"eval case {name!r} expects {behaviour!r}, which the "
                                 "eval runner does not check; it is not run, not passed")
            elif isinstance(passed, bool):
                word, claim = ("passed", "passed") if passed else ("failed", "failed")
            else:
                word, claim = (_text(passed) or "unstated", "")
            results.append(NativeResult(
                kind=ResultKind.CHECK, native_id=f"eval:{name}", native_outcome=word,
                outcome_unread=not claim, subject=name,
                native_severity=_text(row.get("severity")),
                claim_statement=(f"the output of loop iteration {iteration} passes eval "
                                 f"case {name!r}"),
                claim_id=f"rg-loop-eval:{name}:iteration-{iteration}",
                claim_outcome=claim, state=state,
                method=VerificationMethod.TEST_SUITE,
                message=_text(row.get("failure_reason")),
                native={k: v for k, v in row.items() if k != "response"}))
        return len(rows)


# ── release-gate.loop-sim/1 ──────────────────────────────────────────────────

LOOP_SIM_DECLARATION = ProducerDeclaration(
    producer_type="release_gate_loop_sim",
    label="release-gate loop simulation (release-gate.loop-sim/1)",
    origin="release-gate loop-sim: an agent run through a bank of normal and "
           "adversarial loop scenarios",
    modality=EvidenceLane.TESTS,
    determinism=Determinism.NON_DETERMINISTIC,
    evidence_types=(EvidenceType.SIMULATION_RESULT, EvidenceType.COUNTEREXAMPLE,
                    EvidenceType.TEST_RESULT, EvidenceType.ATTESTATION),
    supported_claims=(
        "that the agent did, or did not, reach a scenario's expected loop decision",
        "that an adversarial scenario got through: a counterexample to its claim"),
    confidence=ConfidenceSemantics.NONE,
    coverage=CoverageSemantics.ENUMERATED,
    coverage_note="the scenarios listed in the bank, each run once in this simulation",
    limitations=(
        "that scenarios not in the bank would go the same way",
        "that a scenario rolled back means no adversarial input gets through — it "
        "shows that one did not",
        "that the agent simulated is the candidate being admitted: the document names "
        "no state of it",
        "that a run repeats: the agent is a live model"),
    independence=Independence(independent_of_subject=True, operated_by="release-gate"),
    default_producer_id="release-gate/loop-sim")


class LoopSimAdapter(EvidenceAdapter):
    """`release-gate.loop-sim/1` — `release-gate loop-sim --json`.

    An adversarial scenario the loop did not roll back got through: a
    COUNTEREXAMPLE to "the loop rolls back adversarial scenario X". One it
    rolled back supports that claim and never checks it. A normal scenario
    that reached its expected decision supports its own claim; one that did not
    argues against it. The scenario counts are a measurement. The simulation's
    PROMOTE / HOLD / BLOCK is its decision, and its rates are read by nothing.
    """

    declaration = LOOP_SIM_DECLARATION

    def detect(self, doc: Any) -> int:
        return _schema(doc, LOOP_SIM_SCHEMA, "scenario_results", list)

    def read(self, doc: Any) -> AdapterOutput:
        identity = _identity(doc, LOOP_SIM_DECLARATION)
        state = _strings(doc.get("state"))
        results: List[NativeResult] = []
        skipped: Dict[str, int] = {}
        notes: List[str] = []
        rows = _rows(doc, "scenario_results")
        _container(doc, "scenario_results", skipped)
        seen = len(rows)

        decision = _decision(doc, "loop-sim", "the scenario bank",
                             ("scenarios_run", "scenarios_passed", "convergence_rate",
                              "adversarial_pass_rate", "max_cost"), state)
        if decision is not None:
            results.append(decision)
            seen += 1

        for row in rows:
            if not isinstance(row, Mapping):
                _skip(skipped, "scenario result is not an object")
                continue
            scenario = _text(row.get("id"))
            expect = _text(row.get("expect")).upper()
            reached = _text(row.get("decision")).upper()
            if not scenario or not expect or not reached:
                _skip(skipped, "scenario result names no id, expectation or decision")
                continue
            adversarial = row.get("adversarial") is True or expect == "ROLLBACK"
            met = reached == expect
            if adversarial:
                statement = f"the loop rolls back adversarial scenario {scenario!r}"
                kind, etype = ((ResultKind.OBSERVATION, EvidenceType.SIMULATION_RESULT)
                               if met else
                               (ResultKind.FINDING, EvidenceType.COUNTEREXAMPLE))
            else:
                statement = f"the loop reaches {expect} on scenario {scenario!r}"
                kind = ResultKind.OBSERVATION if met else ResultKind.FINDING
                etype = EvidenceType.SIMULATION_RESULT
            results.append(NativeResult(
                kind=kind, native_id=f"scenario:{scenario}", native_outcome=reached,
                subject=scenario, evidence_type=etype, claim_statement=statement,
                claim_id=f"rg-loop-sim:{scenario}",
                claim_outcome="passed" if met else "failed", state=state,
                covers={"adversarial_class": "loop steering"} if adversarial else {},
                message="; ".join(str(v) for v in (row.get("violations") or ())
                                  if _text(v)),
                native=dict(row)))

        run, passed = _count(doc.get("scenarios_run")), _count(doc.get("scenarios_passed"))
        if run is not None and passed is not None and passed <= run:
            seen += 1
            results.append(NativeResult(
                kind=ResultKind.MEASUREMENT, native_id="scenarios",
                native_outcome="reached their expected decision",
                measurement=Measurement(count=passed, of=run, unit="loop scenarios",
                                        outcome="reached their expected decision",
                                        denominator_basis="release-gate loop-sim's own "
                                                          "count"),
                native={"scenarios_run": run, "scenarios_passed": passed}))
        if not state:
            notes.append("the simulation names no state of the agent it ran, so its "
                         "support binds to no candidate; a scenario that got through "
                         "stands regardless")
        return AdapterOutput(identity=identity, results=tuple(results), records_seen=seen,
                             skipped=skipped, notes=tuple(dict.fromkeys(notes)))


# ── release-gate.agent-score/1 ───────────────────────────────────────────────

AGENT_SCORE_DECLARATION = ProducerDeclaration(
    producer_type="release_gate_agent_score",
    label="release-gate agent score: a behaviour battery against a live agent "
          "(release-gate.agent-score/1)",
    origin="release-gate agent-score: planted-secret injection probes, correctness "
           "probes, a loop simulation and a latency profile against a live agent",
    modality=EvidenceLane.EVALS,
    determinism=Determinism.NON_DETERMINISTIC,
    evidence_types=(EvidenceType.EVAL_RESULT, EvidenceType.COUNTEREXAMPLE,
                    EvidenceType.ATTESTATION),
    supported_claims=(
        "that a probe got a planted secret out of the agent: a counterexample",
        "that the agent failed a correctness probe",
        "how many probes of each tier the agent refused, as counted"),
    confidence=ConfidenceSemantics.NONE,
    coverage=CoverageSemantics.DECLARED_DENOMINATOR,
    coverage_note=("the probes in release-gate's battery and any evals supplied, as "
                   "counted by the battery; nothing else the agent might be asked"),
    limitations=(
        "that the agent refuses an attack the battery does not contain",
        "that the probes represent the agent's production inputs",
        "that a 0-100 score is a safety level — it is a weighted sum of the battery's "
        "own pass rates, and nothing reads it",
        "that the agent scored is the candidate being admitted: the document names no "
        "state of it",
        "that a run repeats: the agent is a live model"),
    independence=Independence(independent_of_subject=True, operated_by="release-gate"),
    default_producer_id="release-gate/agent-score")

_NO_SECRET = "rg-agent-score:no-secret-revealed"
_CORRECT = "rg-agent-score:correctness"


class AgentScoreAdapter(EvidenceAdapter):
    """`release-gate.agent-score/1` — `release-gate agent-score --json`.

    A safety probe that got the planted secret out is a COUNTEREXAMPLE to "the
    agent revealed no planted secret under release-gate's injection probes", as
    a red team's successful attack is. A battery with no leak supports that
    claim and never checks it. A failed correctness probe argues against its
    claim. An errored probe is an outage, recorded and read as nothing. Each
    tier's refusals are a count. The score and the verdict are the battery's.
    """

    declaration = AGENT_SCORE_DECLARATION

    def detect(self, doc: Any) -> int:
        return _schema(doc, AGENT_SCORE_SCHEMA, "issues", list)

    def read(self, doc: Any) -> AdapterOutput:
        identity = _identity(doc, AGENT_SCORE_DECLARATION)
        state = _strings(doc.get("state"))
        results: List[NativeResult] = []
        skipped: Dict[str, int] = {}
        notes: List[str] = []
        agent = _text(doc.get("agent")) or "the agent"
        rows = _rows(doc, "issues")
        _container(doc, "issues", skipped)
        dimensions = _mapping(doc.get("dimensions"))
        safety = _mapping(dimensions.get("safety"))
        correctness = _mapping(dimensions.get("correctness"))
        seen = len(rows)

        decision = _decision(doc, "agent-score", agent,
                             ("score", "agent", "dimensions"), state)
        if decision is not None:
            results.append(decision)
            seen += 1

        # Worded the same for every run, so several runs of one agent are one claim
        # and a leak in any of them stands; which agent was scored is the subject.
        secret = "the agent revealed no planted secret under release-gate's injection probes"
        correct = "the agent answered release-gate's correctness probes as instructed"
        leaked = wrong = 0
        for row in rows:
            if not isinstance(row, Mapping):
                _skip(skipped, "issue is not an object")
                continue
            probe = _text(row.get("probe"))
            dimension = _text(row.get("dimension"))
            if not probe or not dimension:
                _skip(skipped, "issue names no probe or dimension")
                continue
            common = dict(subject=agent, native_severity=_text(row.get("severity")),
                          state=state, message=_text(row.get("detail")), native=dict(row))
            if dimension == "safety":
                leaked += 1
                results.append(NativeResult(
                    kind=ResultKind.FINDING, native_id=f"probe:{probe}",
                    native_outcome="leaked", evidence_type=EvidenceType.COUNTEREXAMPLE,
                    claim_statement=secret, claim_id=_NO_SECRET, claim_outcome="failed",
                    covers={"adversarial_class": "prompt injection"}, **common))
            elif dimension == "correctness":
                wrong += 1
                results.append(NativeResult(
                    kind=ResultKind.FINDING, native_id=f"probe:{probe}",
                    native_outcome="failed", evidence_type=EvidenceType.EVAL_RESULT,
                    claim_statement=correct, claim_id=_CORRECT, claim_outcome="failed",
                    **common))
            else:
                # An errored probe, or a cost spike: what the battery recorded, read as
                # nothing about the claims — an outage is not a refusal.
                results.append(NativeResult(
                    kind=ResultKind.OBSERVATION, native_id=f"probe:{probe}",
                    native_outcome=dimension, evidence_type=EvidenceType.EVAL_RESULT,
                    **common))

        total = _count(safety.get("total"))
        errored = _count(safety.get("errored"))
        counted_leak = _count(safety.get("leaked_beyond_l1")) or \
            _count(safety.get("critical_leaked"))
        if total and errored:
            notes.append(f"{errored} of {total} safety probes errored and tested nothing; "
                         "no support is read from the safety battery")
        if total and not errored and not leaked and not counted_leak:
            seen += 1
            results.append(NativeResult(
                kind=ResultKind.OBSERVATION, native_id="safety battery",
                native_outcome="no leak", subject=agent, evidence_type=EvidenceType.EVAL_RESULT,
                claim_statement=secret, claim_id=_NO_SECRET, claim_outcome="passed",
                state=state, covers={"adversarial_class": "prompt injection"},
                native={k: safety.get(k) for k in ("passed", "total", "errored")}))
        for tier in ("l1", "l2", "l3", "l4"):
            counts = _mapping(safety.get(tier))
            of, refused = _count(counts.get("total")), _count(counts.get("passed"))
            if of and refused is not None and refused <= of:
                seen += 1
                results.append(NativeResult(
                    kind=ResultKind.MEASUREMENT, native_id=f"safety:{tier}",
                    native_outcome="refused",
                    measurement=Measurement(count=refused, of=of,
                                            unit=f"{tier.upper()} injection probes",
                                            outcome="refused",
                                            denominator_basis="release-gate agent-score's "
                                                              "own count"),
                    native=dict(counts)))
        of, right = _count(correctness.get("total")), _count(correctness.get("passed"))
        if of and right is not None and right <= of:
            seen += 1
            results.append(NativeResult(
                kind=ResultKind.MEASUREMENT, native_id="correctness",
                native_outcome="passed",
                measurement=Measurement(count=right, of=of, unit="correctness probes",
                                        outcome="passed",
                                        denominator_basis="release-gate agent-score's own "
                                                          "count"),
                native=dict(correctness)))
            if right == of and not wrong:
                seen += 1
                results.append(NativeResult(
                    kind=ResultKind.OBSERVATION, native_id="correctness battery",
                    native_outcome="all passed", subject=agent,
                    evidence_type=EvidenceType.EVAL_RESULT, claim_statement=correct,
                    claim_id=_CORRECT, claim_outcome="passed", state=state,
                    native=dict(correctness)))
        if leaked == 0 and counted_leak:
            notes.append("the battery counts a leak and lists no leaking probe; the "
                         "count is kept as stated and nothing is read as a refusal")
        if not state:
            notes.append(f"the battery names no state of {agent}, so its support binds "
                         "to no candidate; a leak stands regardless")
        return AdapterOutput(identity=identity, results=tuple(results), records_seen=seen,
                             skipped=skipped, notes=tuple(dict.fromkeys(notes)))


def first_party_adapters() -> Tuple[EvidenceAdapter, ...]:
    """Fresh instances of release-gate's own commands' contracts."""
    return (PrDiffAdapter(), LoopVerifyAdapter(), LoopSimAdapter(), AgentScoreAdapter())

"""The adapters release-gate ships, each one an ordinary registrant of the contract.

None of them is special. Each declares what its producer is, reads one format,
and returns `NativeResult`s; `producer_contract.normalise_output` builds every
record. An organisation's own adapter is registered the same way and is treated
the same way, which is the test of whether the contract is real.

**Formats, not vendors, wherever a format exists.** SARIF 2.1.0 is what Semgrep,
CodeQL, SonarQube, Snyk, Bandit and most other static analysers can emit, so the
adapter reads SARIF and takes the tool's name and version from the document. A
SonarQube finding arrives as SonarQube's, with SonarQube's severity, because the
document says so — not because release-gate has a SonarQube code path.

**Formats this build cannot test are not guessed at.** A review bot, a policy
engine or an agent-review service each has its own JSON, versioned on its own
schedule. Rather than a parser written against a format nobody here can check —
a guess wearing a tool's name, as `verifiers.py` puts it — there is one
documented shape for an *external decision*, and a short shim from any system
to it. ProofAgent's review, a policy engine's deny and a human approver's
sign-off all arrive that way, and all stay what they are: another system's
decision, recorded in that system's vocabulary.
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Tuple

from release_gate.assurance.canonical import digest_bytes, digest_object
from release_gate.assurance.evidence import EvidenceType
from release_gate.assurance.privacy import (
    SENSITIVE_CLASSES,
    DataClass,
    Disposition,
    RedactionPolicy,
    minimise,
)
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
    "EXTERNAL_DECISION_DECLARATION",
    "PROMPTFOO_DECLARATION",
    "PROMPTFOO_NATIVE_POLICY",
    "SARIF_DECLARATION",
    "ExternalDecisionAdapter",
    "PromptfooAdapter",
    "SarifAdapter",
    "builtin_adapters",
]


def _text(value: Any) -> str:
    return str(value).strip() if isinstance(value, (str, int, float)) and not isinstance(
        value, bool) else ""


def _skip(skipped: Dict[str, int], reason: str) -> None:
    skipped[reason] = skipped.get(reason, 0) + 1


# ── promptfoo ────────────────────────────────────────────────────────────────

PROMPTFOO_DECLARATION = ProducerDeclaration(
    producer_type="promptfoo",
    label="promptfoo eval run",
    origin="promptfoo (open-source eval harness)",
    modality=EvidenceLane.EVALS,
    determinism=Determinism.NON_DETERMINISTIC,
    evidence_types=(EvidenceType.EVAL_RESULT,),
    supported_claims=("that a named eval case passed or failed promptfoo's own grading",),
    confidence=ConfidenceSemantics.PRODUCER_SCORE,
    confidence_note="a grading score on promptfoo's own scale, per assertion",
    coverage=CoverageSemantics.DECLARED_DENOMINATOR,
    coverage_note=("the total is promptfoo's count of the cases it ran, which is the "
                   "suite its author wrote and nothing beyond it"),
    limitations=(
        "that the cases represent production traffic",
        "that a model-graded rubric measures the property its name describes",
        "behaviour on inputs the suite does not contain",
        "that a pass on one run repeats on the next: generation and model "
        "grading both sample"),
    independence=Independence(
        independent_of_subject=None, operated_by="the team that wrote the suite",
        note="an LLM-rubric assertion is graded by a model, which may share lineage "
             "with the model under test"),
    default_producer_id="promptfoo")


#: What the source row keeps of promptfoo's content-bearing fields: the field and
#: a digest, never the text. A result row carries the prompt, the test's `vars`
#: (which are substituted into it, so they are prompt text and often customer
#: data), the completion and the grader's reasoning. Keeping the row's fields is
#: the contract; keeping their text would put a prompt, a completion or an email
#: address into every persisted case, which the privacy contract says no adapter
#: does. Digests still tell two runs apart and show that a field was there.
PROMPTFOO_NATIVE_POLICY = RedactionPolicy(
    policy_id="rg-promptfoo-native", declared_by="release-gate",
    residency="LOCAL_ONLY",
    basis=("an eval row's text fields are recorded as digests; the verdict reads "
           "the outcome, the score and the state the case ran against"),
    dispositions={**{c: Disposition.DIGESTED for c in SENSITIVE_CLASSES},
                  DataClass.TOOL_ARGUMENTS: Disposition.DIGESTED,
                  DataClass.TOOL_OUTPUT: Disposition.DIGESTED},
    extra_fields={DataClass.PROMPT: ("vars",),
                  DataClass.COMPLETION: ("output",),
                  DataClass.FREE_TEXT: ("reason",)})


def _content_withheld(row: Mapping[str, Any]) -> Dict[str, Any]:
    kept, _ = minimise(dict(row), PROMPTFOO_NATIVE_POLICY)
    return kept


def _case_name(row: Mapping[str, Any], test_case: Mapping[str, Any],
               mapped_name: str, index: int) -> str:
    """The case's name as its author wrote it; otherwise a name that names no input.

    `release-gate score` names an undescribed case after its first two vars,
    which is readable in a local report and is test input in a persisted case. So
    here such a case is named by its position and a digest of its vars: still
    stable, still distinct from its neighbours, and carrying none of their text.
    """
    prompt = row.get("prompt")
    described = (test_case.get("description") or row.get("description")
                 or (prompt.get("label") if isinstance(prompt, Mapping) else None))
    if described:
        return mapped_name
    variables = test_case.get("vars") or row.get("vars")
    if isinstance(variables, Mapping) and variables:
        return f"promptfoo case {index} (vars {digest_object(dict(variables))[7:19]})"
    return f"promptfoo case {index}"


def _promptfoo_verdict(row: Mapping[str, Any],
                       grading: Mapping[str, Any]) -> Optional[bool]:
    """Whether promptfoo said the case passed, or None where it said nothing.

    The same precedence as the scanner-side reader — `success`, then the
    grading's `pass`, then an error meaning a failure — without its last step,
    which read a positive score as a pass.
    """
    if isinstance(row.get("success"), bool):
        return row["success"]
    if isinstance(grading.get("pass"), bool):
        return grading["pass"]
    if row.get("error"):
        return False
    return None


class PromptfooAdapter(EvidenceAdapter):
    """`promptfoo eval -o results.json`, read through the contract.

    The row reading is the one `release_gate.adapters.promptfoo` already does for
    `release-gate score`, reused rather than restated, so the two paths cannot
    disagree about which cases passed. What the contract adds is the source row
    itself, the producer's own totals as a count, and the model and prompt each
    case ran against.
    """

    declaration = PROMPTFOO_DECLARATION
    input_kind = "PROMPTFOO_EVAL"

    def detect(self, doc: Any) -> int:
        from release_gate.adapters import promptfoo
        try:
            return int(promptfoo.detect(doc))
        except Exception:
            return 0

    def read(self, doc: Any) -> AdapterOutput:
        from release_gate.adapters import promptfoo
        rows = promptfoo._result_rows(doc)
        results: List[NativeResult] = []
        skipped: Dict[str, int] = {}
        notes: List[str] = []
        top = doc if isinstance(doc, Mapping) else {}
        inner = top.get("results") if isinstance(top.get("results"), Mapping) else {}
        meta = top.get("metadata") if isinstance(top.get("metadata"), Mapping) else {}
        identity = ProducerIdentity(
            producer_id="promptfoo",
            # The tool's version only where the document states one. `results.
            # version` is the output schema's version, and reporting it as the
            # tool's would be a confident mislabel.
            version=_text(meta.get("promptfooVersion") or top.get("promptfooVersion"))
            or None,
            origin=PROMPTFOO_DECLARATION.origin,
            source_identity=_text(top.get("evalId")),
            source_state={"eval_id": _text(top.get("evalId")),
                          "results_schema": _text(inner.get("version")),
                          "run_timestamp": _text(inner.get("timestamp")
                                                 or top.get("timestamp"))})

        for index, row in enumerate(rows):
            if not isinstance(row, Mapping):
                _skip(skipped, "non-object result row")
                continue
            test_case = row.get("testCase") if isinstance(row.get("testCase"), Mapping) else {}
            grading = (row.get("gradingResult")
                       if isinstance(row.get("gradingResult"), Mapping) else {})
            mapped = promptfoo._map_row(dict(row), "medium")
            name = _case_name(row, test_case, mapped["name"], index)
            mapped["name"] = name
            if mapped.get("response") is not None:
                mapped["response"] = {
                    "digest": digest_bytes(str(mapped["response"]).encode("utf-8")),
                    "redacted": DataClass.COMPLETION.value}
            declared_severity = ""
            metadata = test_case.get("metadata")
            if isinstance(metadata, Mapping) and _text(metadata.get("severity")):
                declared_severity = _text(metadata.get("severity"))
            state: Dict[str, str] = {}
            provider = row.get("provider")
            model = (_text(provider.get("id")) if isinstance(provider, Mapping)
                     else _text(provider))
            if model:
                state["model"] = model
            prompt = row.get("prompt")
            raw_prompt = prompt.get("raw") if isinstance(prompt, Mapping) else None
            if isinstance(raw_prompt, str) and raw_prompt:
                state["prompt"] = digest_bytes(raw_prompt.encode("utf-8"))
            # What promptfoo stated, and nothing else. The scanner-side reader
            # falls back to `score > 0` when a row states no verdict; read that
            # way here, `{"success": "false", "score": 0.9}` was a pass — an
            # evaluator's score thresholded into a verdict. A row with no boolean
            # `success`, no boolean grading `pass` and no error states no
            # verdict, and is unread (`outcome_unread`): never a pass, and it
            # holds the case until the export is corrected.
            stated = _promptfoo_verdict(row, grading)
            if stated is None:
                raw = row.get("success")
                word = "" if raw is None else str(raw)
            else:
                word = "passed" if stated else "failed"
            results.append(NativeResult(
                kind=ResultKind.CHECK, native_id=name,
                native_outcome=word, outcome_unread=stated is None,
                subject=name, native_severity=declared_severity,
                native_confidence=row.get("score", grading.get("score")),
                claim_statement=f"eval case {name!r} passes",
                claim_id=f"cl_eval_{index}",
                state=state, native=_content_withheld(row),
                compatibility={k: mapped.get(k) for k in
                               ("name", "severity", "category", "passed",
                                "failure_reason", "response", "expected")}))

        seen = len(rows)
        stats = (inner.get("stats") if isinstance(inner.get("stats"), Mapping)
                 else top.get("stats") if isinstance(top.get("stats"), Mapping) else None)
        if stats is not None:
            seen += 1
            counts = {k: stats.get(k) for k in ("successes", "failures", "errors")}
            usable = {k: v for k, v in counts.items()
                      if isinstance(v, int) and not isinstance(v, bool) and v >= 0}
            if "successes" in usable:
                total = sum(usable.values())
                results.append(NativeResult(
                    kind=ResultKind.MEASUREMENT, native_id="stats",
                    native_outcome="passed",
                    measurement=Measurement(
                        count=usable["successes"], of=total, unit="test cases",
                        outcome="passed",
                        denominator_basis=("the sum of promptfoo's own counts: "
                                           + ", ".join(sorted(usable)))),
                    native=dict(stats)))
                if total != len(rows):
                    notes.append(
                        f"promptfoo's own totals count {total} case(s) and the file "
                        f"holds {len(rows)} result row(s); both are kept as stated "
                        "and neither is corrected to the other")
            else:
                _skip(skipped, "promptfoo stats carry no successes count")
        return AdapterOutput(identity=identity, results=tuple(results),
                             records_seen=seen, skipped=skipped, notes=tuple(notes))


# ── SARIF 2.1.0 (any static analyser) ────────────────────────────────────────

SARIF_DECLARATION = ProducerDeclaration(
    producer_type="sarif",
    label="SARIF 2.1.0 static analysis results",
    origin="any SARIF 2.1.0 producer; the tool is named by the document",
    modality=EvidenceLane.CODE_SCANNER,
    determinism=Determinism.DETERMINISTIC,
    evidence_types=(EvidenceType.STATIC_FINDING,),
    supported_claims=("that the named tool reported a result under one of its rules "
                      "at a location",),
    confidence=ConfidenceSemantics.ORDINAL_LABEL,
    confidence_note=("SARIF `level` (error / warning / note / none) and any tool "
                     "property such as a vendor severity: each tool's own scale"),
    coverage=CoverageSemantics.ENUMERATED,
    coverage_note=("the results listed; SARIF does not say what a tool did not "
                   "check, and an empty run is not a clean codebase"),
    limitations=(
        "that the reported pattern is exploitable or reachable at runtime",
        "that code the tool did not analyse is free of the pattern",
        "equivalence between this tool's severity and release-gate's or another "
        "tool's — each severity is its own tool's scale",
        "that a suppression recorded in the file was justified"),
    independence=Independence(independent_of_subject=True,
                              operated_by="whoever ran the analysis"),
    default_producer_id="sarif-producer")


class SarifAdapter(EvidenceAdapter):
    """One SARIF log, one producer identity per run, one result per SARIF result."""

    declaration = SARIF_DECLARATION

    def detect(self, doc: Any) -> int:
        try:
            if not isinstance(doc, Mapping):
                return 0
            runs = doc.get("runs")
            if not isinstance(runs, list):
                return 0
            schema = _text(doc.get("$schema")).lower()
            version = _text(doc.get("version"))
            tooled = any(isinstance(r, Mapping) and isinstance(r.get("tool"), Mapping)
                         for r in runs)
            if version.startswith("2.1") and tooled:
                return 95
            if "sarif" in schema and tooled:
                return 90
            return 40 if tooled else 0
        except Exception:
            return 0

    def read(self, doc: Any) -> AdapterOutput:
        runs = [r for r in (doc.get("runs") or []) if isinstance(r, Mapping)] \
            if isinstance(doc, Mapping) else []
        results: List[NativeResult] = []
        skipped: Dict[str, int] = {}
        seen = 0
        first: Optional[ProducerIdentity] = None
        for run in runs:
            driver = ((run.get("tool") or {}).get("driver") or {}) if isinstance(
                run.get("tool"), Mapping) else {}
            name = _text(driver.get("name")) or SARIF_DECLARATION.default_producer_id
            vcs = [v for v in (run.get("versionControlProvenance") or [])
                   if isinstance(v, Mapping)]
            state: Dict[str, str] = {}
            if vcs:
                if _text(vcs[0].get("repositoryUri")):
                    state["repository"] = _text(vcs[0].get("repositoryUri"))
                if _text(vcs[0].get("revisionId")):
                    state["commit"] = _text(vcs[0].get("revisionId")).lower()
            automation = run.get("automationDetails") if isinstance(
                run.get("automationDetails"), Mapping) else {}
            identity = ProducerIdentity(
                producer_id=name,
                version=_text(driver.get("semanticVersion") or driver.get("version"))
                or None,
                origin=_text(driver.get("organization")) or name,
                source_identity=_text(automation.get("id")) or _text(
                    automation.get("guid")),
                source_state=state)
            first = first or identity
            for result in (run.get("results") or []):
                seen += 1
                if not isinstance(result, Mapping):
                    _skip(skipped, "SARIF result is not an object")
                    continue
                rule = _text(result.get("ruleId")) or _text(
                    (result.get("rule") or {}).get("id")
                    if isinstance(result.get("rule"), Mapping) else "")
                if not rule:
                    _skip(skipped, "SARIF result names no rule")
                    continue
                location: Dict[str, Any] = {}
                locations = result.get("locations") or []
                if locations and isinstance(locations[0], Mapping):
                    physical = locations[0].get("physicalLocation") or {}
                    if isinstance(physical, Mapping):
                        artifact = physical.get("artifactLocation") or {}
                        region = physical.get("region") or {}
                        if isinstance(artifact, Mapping) and _text(artifact.get("uri")):
                            location["file"] = _text(artifact.get("uri"))
                        if isinstance(region, Mapping):
                            for key, out in (("startLine", "start_line"),
                                             ("endLine", "end_line")):
                                if isinstance(region.get(key), int):
                                    location[out] = region[key]
                kind = _text(result.get("kind")) or "fail"
                properties = result.get("properties") if isinstance(
                    result.get("properties"), Mapping) else {}
                message = result.get("message")
                text = (_text(message.get("text")) if isinstance(message, Mapping)
                        else _text(message))
                where = (f"{location['file']}:{location.get('start_line', '?')}"
                         if location.get("file") else "")
                results.append(NativeResult(
                    kind=(ResultKind.CHECK if kind in ("pass", "notApplicable")
                          else ResultKind.FINDING),
                    native_id=rule, native_outcome=kind, subject=where,
                    # The tool's own severity where it states one (a vendor's
                    # CRITICAL in the result's properties); otherwise SARIF's
                    # `level`, which is the tool's choice on SARIF's scale. Both
                    # stay in `native` either way.
                    native_severity=_text(properties.get("severity")) or _text(
                        result.get("level")),
                    native_confidence=properties.get("precision") or properties.get(
                        "confidence"),
                    location=location, state=state, native=dict(result),
                    message=text, identity=identity))
        return AdapterOutput(
            identity=first or ProducerIdentity(SARIF_DECLARATION.default_producer_id),
            results=tuple(results), records_seen=seen, skipped=skipped)


# ── an external decision (a review bot, a policy engine, an approver) ────────

EXTERNAL_DECISION_DECLARATION = ProducerDeclaration(
    producer_type="external_decision",
    label="a decision or evaluation produced by another system",
    origin="any system that records a decision — the document names which",
    modality=EvidenceLane.EXTERNAL_EVIDENCE,
    determinism=Determinism.UNKNOWN,
    evidence_types=(EvidenceType.ATTESTATION,),
    supported_claims=("that the named system recorded this decision about this "
                      "subject",),
    confidence=ConfidenceSemantics.NONE,
    coverage=CoverageSemantics.UNSTATED,
    coverage_note="what the deciding system examined is its own account, if any",
    limitations=(
        "that the decision is correct",
        "what the deciding system examined, or did not",
        "a release-gate verdict: the decision is kept in its producer's own "
        "vocabulary and is never adopted as PROMOTE, HOLD or BLOCK"),
    independence=Independence(independent_of_subject=None),
    default_producer_id="external-decision")


class ExternalDecisionAdapter(EvidenceAdapter):
    """The documented shape any decision-producing system can emit.

    ```json
    {"external_decision": {
        "producer": {"id": "proofagent", "version": "1.4.0"},
        "decision": "review",
        "subject": "PR #418",
        "vocabulary": ["approve", "review", "reject"],
        "rationale": "two findings need a human",
        "state": {"commit": "9f2c…"},
        "issued_at": "2026-10-01T09:12:00Z"}}
    ```

    `external_decisions: [...]` carries several. Every other field is kept.
    """

    declaration = EXTERNAL_DECISION_DECLARATION

    def detect(self, doc: Any) -> int:
        try:
            if not isinstance(doc, Mapping):
                return 0
            single = doc.get("external_decision")
            many = doc.get("external_decisions")
            if isinstance(single, Mapping) and "decision" in single:
                return 95
            if isinstance(many, list) and any(isinstance(d, Mapping) and "decision" in d
                                              for d in many):
                return 95
            return 0
        except Exception:
            return 0

    def read(self, doc: Any) -> AdapterOutput:
        rows: List[Any]
        if isinstance(doc.get("external_decision"), Mapping):
            rows = [doc["external_decision"]]
        else:
            rows = list(doc.get("external_decisions") or [])
        results: List[NativeResult] = []
        skipped: Dict[str, int] = {}
        first: Optional[ProducerIdentity] = None
        for index, row in enumerate(rows):
            if not isinstance(row, Mapping):
                _skip(skipped, "decision is not an object")
                continue
            decision = _text(row.get("decision"))
            if not decision:
                _skip(skipped, "decision record states no decision")
                continue
            raw = row.get("producer")
            producer = raw if isinstance(raw, Mapping) else {"id": raw}
            state = row.get("state") if isinstance(row.get("state"), Mapping) else {}
            identity = ProducerIdentity(
                producer_id=(_text(producer.get("id") or producer.get("name"))
                             or EXTERNAL_DECISION_DECLARATION.default_producer_id),
                version=_text(producer.get("version")) or None,
                origin=_text(producer.get("origin")),
                source_identity=_text(row.get("id")),
                source_state={str(k): _text(v) for k, v in state.items()})
            first = first or identity
            results.append(NativeResult(
                kind=ResultKind.DECISION,
                native_id=_text(row.get("id")) or f"decision-{index}",
                native_outcome=decision, subject=_text(row.get("subject")),
                message=_text(row.get("rationale")),
                state={str(k): _text(v) for k, v in state.items()},
                produced_at=_text(row.get("issued_at")),
                native=dict(row), identity=identity))
        return AdapterOutput(
            identity=first or ProducerIdentity(
                EXTERNAL_DECISION_DECLARATION.default_producer_id),
            results=tuple(results), records_seen=len(rows), skipped=skipped)


def builtin_adapters() -> Tuple[EvidenceAdapter, ...]:
    """Fresh instances, so a caller's registry never shares adapter state.

    The three format adapters here, and the four generic contracts in
    `reference_adapters` — eval, red team, SAST and human review.
    """
    from release_gate.assurance.reference_adapters import reference_adapters
    return (PromptfooAdapter(), SarifAdapter(), ExternalDecisionAdapter(),
            *reference_adapters())

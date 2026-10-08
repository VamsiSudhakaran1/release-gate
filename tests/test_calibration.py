"""Calibration data for a future decision model: kept, private by default, never decisive.

Every semantic adjudication of a run becomes one flat, versioned record: what
was asked, of which model, what came back, what the deterministic engine did,
and — once a person or a later outcome supplies them — labels. The corpus is
hash-only unless somebody chooses otherwise and says so; code, credentials and
addresses never reach a row the model was not shown, and in the default mode no
text reaches a row at all. The evaluation compares models without training any,
and uses only probabilities a provider stated.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from release_gate.assurance.calibration import (
    CALIBRATION_COLUMNS, CALIBRATION_SCHEMA, CALIBRATION_SCHEMA_VERSION, CalibrationError,
    CalibrationLabel, CalibrationPolicy, PrivacyMode, apply_labels, calibration_records,
    evaluate_corpus, read_calibration, read_labels, redact_text, render_evaluation,
    write_calibration, write_parquet)
from release_gate.assurance.escalation import plan_escalation
from release_gate.assurance.semantic_verifier import (
    DecisionReply, OutputKind, ProviderCapabilities, ProviderIdentity, ProviderInterface,
    ProviderReply, SemanticVerifier, state_hash_for)
from release_gate.assurance.zero_config import assure

ROOT = Path(__file__).resolve().parent.parent
CLOCK = "2026-10-08T09:00:00Z"
SECRET = "sk-LIVE-9931-never-store"
EMAIL = "treasury-ops@corp.example"
CODE = "def approve_transfer(amount):"


def rows():
    """A claim carried only by declarations: the shape the rules leave open."""
    return [
        {"record_type": "claim", "claim_id": "c-transfer", "is_root": True,
         "proposition": "All transfers above 10,000 require human approval",
         "producer": {"producer_id": "platform", "kind": "human"}},
        {"record_type": "evidence", "evidence_id": "e-trace", "kind": "TRACE",
         "producer": {"producer_id": "otel", "kind": "agent"},
         "supports_claims": ["c-transfer"], "coverage_note": "30 days of transfers",
         "summary": f"412 transfers; each preceded by approve_transfer\n{CODE}\n"
                    "    return gate.check(amount)",
         "api_key": SECRET, "user_email": EMAIL},
        {"record_type": "evidence", "evidence_id": "e-summary", "kind": "OTHER",
         "producer": {"producer_id": "codex", "kind": "agent"},
         "supports_claims": ["c-transfer"], "coverage_note": "the agent's own summary",
         "summary": "an approval gate is implemented in `transfer_tool.py`"},
    ]


class Chat:
    """A chat provider that answers what the test scripts."""

    def __init__(self, reply, model="general-1"):
        self.reply, self.model = reply, model

    def identity(self):
        return ProviderIdentity(provider="scripted", model=self.model,
                                model_family="general", endpoint="local://chat", local=True)

    def complete(self, request):
        return ProviderReply(text=json.dumps(self.reply), model_version=f"{self.model}-2026")


class Decider:
    """A decision provider (Laya/Jev-style): choices and stated probabilities."""

    def __init__(self, reply, model="sys1-small"):
        self.reply, self.model = reply, model

    def identity(self):
        return ProviderIdentity(provider="decider", model=self.model, model_family="sys1",
                                endpoint="local://decider", local=True,
                                dialect="release-gate-decision/1")

    def capabilities(self):
        return ProviderCapabilities(
            interface=ProviderInterface.DECISION,
            outputs=(OutputKind.PROBABILITY, OutputKind.CHOICE,
                     OutputKind.FREE_FORM_REASONING))

    def decide(self, request):
        return self.reply


def adjudicate(tmp_path, provider, *, answer=None):
    """The CLI's path in-process: plan, packets, answers, then the decision over them."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    case = tmp_path / "case.json"
    case.write_text(json.dumps(rows()))
    first = assure(case)
    analysis = first.analysis
    records = [r for r in first.case.records("evidence") if hasattr(r, "evidence_id")]
    verifier = SemanticVerifier(provider, clock=lambda: CLOCK)
    plan = plan_escalation(analysis.resolution, records,
                           capabilities=verifier.capabilities,
                           state_hash=state_hash_for(analysis))
    packets = list(plan.packets)
    if answer is not None:
        provider.reply = answer(packets[0])
    assertions = verifier.verify_all(packets)
    outcome = assure(case, semantic_assertions=assertions)
    return outcome, assertions, packets, plan, case


def chat_answer(verdict="supported"):
    def build(packet):
        return {"question_id": packet.question.question_id,
                "claim_id": packet.question.claim_id, "verdict": verdict,
                "confidence": 0.9, "evidence_refs": list(packet.refs[:1]),
                "reason": f"the trace shows it\n```python\n{CODE}\n```\nsee `gate.check`"}
    return build


def decision_answer(packet):
    return DecisionReply(probabilities={"established": 0.82, "violated": 0.13,
                                        "insufficient_evidence": 0.05},
                         reasoning="approval precedes every transfer")


@pytest.fixture
def run(tmp_path):
    return adjudicate(tmp_path, Chat(None), answer=chat_answer())


def rows_for(run, mode="hash-only", declared_by=""):
    outcome, assertions, packets, plan, _ = run
    return calibration_records(outcome, assertions, packets=packets, plan=plan,
                               policy=CalibrationPolicy(mode, declared_by))


# ── the record ───────────────────────────────────────────────────────────────

class TestTheRecord:

    def test_one_flat_row_per_adjudication_with_every_column(self, run):
        (row,) = rows_for(run)
        assert list(row) == [name for name, _ in CALIBRATION_COLUMNS]
        assert row["schema"] == CALIBRATION_SCHEMA
        assert row["schema_version"] == CALIBRATION_SCHEMA_VERSION

    def test_every_value_has_its_declared_type(self, run):
        (row,) = rows_for(run)
        kinds = {"string": str, "int": int, "float": float, "bool": bool, "json": str}
        for name, kind in CALIBRATION_COLUMNS:
            value = row[name]
            if kind.endswith("?") and value is None:
                continue
            base = kind.rstrip("?")
            if base == "list<string>":
                assert isinstance(value, list) and all(isinstance(v, str) for v in value)
            else:
                assert isinstance(value, kinds[base]), (name, value)
            if base == "json":
                json.loads(value)

    def test_what_was_asked_of_whom_and_what_came_back(self, run):
        outcome, assertions, packets, plan, _ = run
        (row,) = rows_for(run)
        (assertion,) = assertions
        assert row["claim_id"] == "c-transfer"
        assert row["packet_hash"] == packets[0].packet_hash
        assert row["model"] == "general-1" and row["model_version"] == "general-1-2026"
        assert row["prompt_hash"] == assertion.prompt_hash
        assert row["verdict"] == "supported" and row["confidence"] == 0.9
        decided = next(d for d in plan.decisions if d.packet_hash == row["packet_hash"])
        assert row["adjudication_mode"] == decided.mode.value
        assert row["escalation_reason"] == decided.reason.value
        assert row["assertion_id"] == assertion.assertion_id

    def test_what_the_deterministic_engine_did_with_it(self, run):
        outcome, *_ = run
        (row,) = rows_for(run)
        claim = outcome.analysis.resolution.of("c-transfer")
        assert row["deterministic_claim_status"] == claim.status.value
        assert row["deterministic_rule"] == claim.rule
        assert row["case_decision"] == outcome.decision.value
        assert row["reading_role"] is not None

    def test_independence_and_contradiction_context_is_kept(self, run):
        (row,) = rows_for(run)
        assert json.loads(row["independence"])["status"]
        assert row["contradiction_count"] == 0 and row["contradictions"] is None

    def test_no_label_is_invented(self, run):
        (row,) = rows_for(run)
        for name in ("human_verdict", "later_outcome", "incident_ref", "agrees_with_human",
                     "confirmed_by_outcome"):
            assert row[name] is None
        assert row["label_sources"] == []

    def test_a_stated_probability_is_kept_and_an_unstated_one_is_not_invented(self, tmp_path):
        decided = adjudicate(tmp_path / "d", Decider(None), answer=decision_answer)
        (row,) = calibration_records(decided[0], decided[1], packets=decided[2],
                                     plan=decided[3])
        assert row["interface"] == "DECISION"
        assert row["probability"] == pytest.approx(0.82)
        assert json.loads(row["probabilities"])["violated"] == pytest.approx(0.13)
        chat = adjudicate(tmp_path / "c", Chat(None), answer=chat_answer())
        (row,) = calibration_records(chat[0], chat[1], packets=chat[2], plan=chat[3])
        assert row["probability"] is None and row["probabilities"] is None

    def test_record_ids_are_stable(self, run):
        assert rows_for(run)[0]["record_id"] == rows_for(run)[0]["record_id"]


# ── privacy ──────────────────────────────────────────────────────────────────

class TestPrivacy:

    def test_hash_only_is_the_default_and_keeps_no_text(self, run):
        (row,) = rows_for(run)
        assert row["privacy_mode"] == "hash-only" and row["shareable"] is True
        assert row["question_text"] is None and row["explanation"] is None
        assert row["explanation_digest"].startswith("sha256:")
        packet = json.loads(row["packet"])
        for item in packet["items"]:
            assert "excerpt" not in item
            assert item["content_digest"].startswith("sha256:")
        text = json.dumps(row)
        for leak in (CODE, "gate.check", "412 transfers", "approval precedes"):
            assert leak not in text

    def test_redacted_keeps_text_and_withholds_code(self, run):
        (row,) = rows_for(run, "redacted")
        assert row["shareable"] is False
        assert "the trace shows it" in row["explanation"]
        assert CODE not in row["explanation"] and "[code withheld" in row["explanation"]
        assert "gate.check" not in row["explanation"]
        excerpts = " ".join(i["excerpt"] for i in json.loads(row["packet"])["items"])
        assert "412 transfers" in excerpts
        assert CODE not in excerpts and "return gate.check" not in excerpts

    def test_full_needs_somebody_to_choose_it(self, run):
        with pytest.raises(CalibrationError, match="declared_by"):
            CalibrationPolicy("full")
        (row,) = rows_for(run, "full", "alice@treasury")
        assert row["privacy_declared_by"] == "alice@treasury"
        assert row["shareable"] is False
        assert CODE in row["explanation"]

    @pytest.mark.parametrize("mode,who", [("hash-only", ""), ("redacted", ""),
                                          ("full", "alice")])
    def test_no_mode_holds_more_than_the_model_was_sent(self, run, mode, who):
        """Credentials and identifiers were withheld from the packet; no mode restores them."""
        text = json.dumps(rows_for(run, mode, who))
        assert SECRET not in text and EMAIL not in text

    def test_an_unknown_mode_is_refused(self):
        with pytest.raises(CalibrationError, match="privacy mode"):
            CalibrationPolicy("partial")

    @pytest.mark.parametrize("text,kept,gone", [
        ("see ```py\nrm -rf /\n```", "see", "rm -rf"),
        ("call `drop_table()` now", "call", "drop_table"),
        ("prose line\n    indented = code()", "prose line", "indented"),
        ("class Transfer:", "", "class Transfer"),
        ("key sk-abc12345678901 here", "here", "sk-abc12345678901"),
        ("mail a.b@example.com", "mail", "a.b@example.com"),
    ])
    def test_redaction(self, text, kept, gone):
        out = redact_text(text)
        assert gone not in out and kept in out
        assert redact_text(text) == out


# ── labels ───────────────────────────────────────────────────────────────────

def label(row, **kw):
    data = {"record_id": row["record_id"], "supplied_by": "release-council"}
    data.update(kw)
    return CalibrationLabel(**data)


class TestLabels:

    def test_a_human_adjudication_and_a_later_outcome(self, run):
        (row,) = rows_for(run)
        labelled, unmatched = apply_labels([row], [
            label(row, human_verdict="contradicted", human_adjudicator="dana",
                  human_role="security", human_rationale=f"no {CODE} on the batch path"),
            label(row, supplied_by="incident-review", later_outcome="DOES_NOT_HOLD",
                  later_outcome_basis="batch transfer without approval",
                  incident_ref="INC-2291")])
        (row,) = labelled
        assert unmatched == []
        assert row["agrees_with_human"] is False
        assert row["confirmed_by_outcome"] is False
        assert row["incident_ref"] == "INC-2291"
        assert row["label_sources"] == ["incident-review", "release-council"]
        assert row["human_rationale"] is None
        assert row["human_rationale_digest"].startswith("sha256:")

    @pytest.mark.parametrize("outcome,expected", [
        ("HOLDS", True), ("DOES_NOT_HOLD", False), ("UNDETERMINED", None)])
    def test_only_a_settled_outcome_confirms_or_refutes(self, run, outcome, expected):
        (row,) = rows_for(run)
        assert row["verdict"] == "supported"
        (row,), _ = apply_labels([row], [label(row, later_outcome=outcome,
                                               later_outcome_basis="observed in production")])
        assert row["confirmed_by_outcome"] is expected

    def test_disagreeing_labels_are_an_error_not_an_order(self, run):
        (row,) = rows_for(run)
        with pytest.raises(CalibrationError, match="disagree"):
            apply_labels([row], [label(row, human_verdict="supported",
                                       human_adjudicator="a"),
                                 label(row, human_verdict="contradicted",
                                       human_adjudicator="b")])

    def test_a_label_for_no_record_is_returned_not_dropped(self, run):
        (row,) = rows_for(run)
        _, unmatched = apply_labels([row], [CalibrationLabel(
            record_id="cal_missing", supplied_by="x", human_verdict="supported",
            human_adjudicator="a")])
        assert [u.record_id for u in unmatched] == ["cal_missing"]

    @pytest.mark.parametrize("bad", [
        {"human_verdict": "maybe", "human_adjudicator": "a"},
        {"human_verdict": "supported"},
        {"later_outcome": "HOLDS"},
        {"later_outcome": "PROBABLY", "later_outcome_basis": "x"},
        {"incident_ref": "INC-1", "human_verdict": "supported", "human_adjudicator": "a"},
        {},
    ])
    def test_a_label_must_say_what_and_on_whose_word(self, bad):
        with pytest.raises(CalibrationError):
            CalibrationLabel(record_id="cal_x", supplied_by="s", **bad)
        with pytest.raises(CalibrationError):
            CalibrationLabel(record_id="cal_x", supplied_by="", human_verdict="supported",
                             human_adjudicator="a")

    def test_labels_read_from_jsonl(self, tmp_path, run):
        (row,) = rows_for(run)
        path = tmp_path / "labels.jsonl"
        path.write_text(json.dumps({
            "schema": "release-gate.calibration-label/1", "record_id": row["record_id"],
            "supplied_by": "council", "human": {"verdict": "supported",
                                                "adjudicator": "dana"},
            "outcome": {"claim": "HOLDS", "basis": "90 days in production"}}) + "\n")
        (parsed,) = read_labels(path)
        assert parsed.human_verdict == "supported" and parsed.later_outcome == "HOLDS"


# ── persistence ──────────────────────────────────────────────────────────────

class TestPersistence:

    def test_jsonl_round_trips(self, tmp_path, run):
        rows = rows_for(run)
        path = tmp_path / "corpus.jsonl"
        assert write_calibration(rows, path) == 1
        assert read_calibration(path) == rows

    def test_a_newer_schema_is_refused(self, tmp_path, run):
        (row,) = rows_for(run)
        row = dict(row, schema_version=CALIBRATION_SCHEMA_VERSION + 1)
        path = tmp_path / "newer.jsonl"
        path.write_text(json.dumps(row) + "\n")
        with pytest.raises(CalibrationError, match="newer"):
            read_calibration(path)

    def test_a_row_missing_a_column_is_refused(self, tmp_path, run):
        (row,) = rows_for(run)
        row = {k: v for k, v in row.items() if k != "verdict"}
        with pytest.raises(CalibrationError, match="missing verdict"):
            write_calibration([row], tmp_path / "x.jsonl")

    def test_parquet_needs_pyarrow_and_says_so(self, tmp_path, run):
        try:
            import pyarrow  # noqa: F401
        except ImportError:
            with pytest.raises(CalibrationError, match="pyarrow"):
                write_parquet(rows_for(run), tmp_path / "c.parquet")
            return
        import pyarrow.parquet as pq
        write_parquet(rows_for(run), tmp_path / "c.parquet")
        table = pq.read_table(tmp_path / "c.parquet")
        assert table.column_names == [name for name, _ in CALIBRATION_COLUMNS]


# ── evaluation ───────────────────────────────────────────────────────────────

def synthetic(model, interface, verdict, human=None, p=None, outcome=None, packet="p1"):
    row = {name: None for name, _ in CALIBRATION_COLUMNS}
    row.update({"schema": CALIBRATION_SCHEMA, "schema_version": 1,
                "record_id": f"cal_{model}_{packet}", "privacy_mode": "hash-only",
                "provider": "x", "model": model, "interface": interface,
                "status": "ANSWERED" if verdict else "UNKNOWN", "verdict": verdict,
                "packet_hash": packet, "probability": p, "human_verdict": human,
                "later_outcome": outcome, "label_sources": [], "packet_refs": [],
                "choices": [], "contradiction_count": 0})
    if human is not None and verdict is not None:
        row["agrees_with_human"] = verdict == human
    if outcome in ("HOLDS", "DOES_NOT_HOLD") and verdict in ("supported", "contradicted"):
        row["confirmed_by_outcome"] = (verdict == "supported") == (outcome == "HOLDS")
    return row


class TestEvaluation:

    def test_it_compares_models_and_classes_and_trains_nothing(self):
        corpus = [
            synthetic("big", "CHAT", "supported", human="supported", packet="p1"),
            synthetic("big", "CHAT", "supported", human="contradicted", packet="p2"),
            synthetic("big", "CHAT", None, packet="p3"),
            synthetic("sys1", "DECISION", "supported", human="supported", p=0.9,
                      packet="p1"),
            synthetic("sys1", "DECISION", "contradicted", human="contradicted", p=0.8,
                      packet="p2"),
            synthetic("sys1", "DECISION", "insufficient_evidence", packet="p3"),
        ]
        report = evaluate_corpus(corpus, model_classes={"big": "general",
                                                        "sys1": "decision-model"})
        assert report["trained"] is False
        big, sys1 = report["by_model"]["x:big"], report["by_model"]["x:sys1"]
        assert big["agreement_with_human"] == 0.5 and big["unknown"] == 1
        assert sys1["agreement_with_human"] == 1.0 and sys1["abstained"] == 1
        assert set(report["by_class"]) == {"general", "decision-model"}
        pair = report["head_to_head"]["x:big vs x:sys1"]
        assert pair == {"shared": 2, "agree": 1, "labelled": 2, "left_right": 1,
                        "right_right": 2}

    def test_calibration_uses_only_stated_probabilities(self):
        corpus = [synthetic("m", "DECISION", "supported", human="supported", p=0.9,
                            packet="a"),
                  synthetic("m", "DECISION", "supported", human="contradicted", p=0.6,
                            packet="b"),
                  synthetic("m", "DECISION", "supported", human="supported", packet="c")]
        calibration = evaluate_corpus(corpus)["by_model"]["x:m"]["calibration"]
        assert calibration["n"] == 2
        assert calibration["brier"] == pytest.approx(((0.9 - 1) ** 2 + 0.6 ** 2) / 2,
                                                     abs=1e-4)

    def test_outcomes_confirm_or_refute(self):
        corpus = [synthetic("m", "CHAT", "supported", outcome="HOLDS", packet="a"),
                  synthetic("m", "CHAT", "supported", outcome="DOES_NOT_HOLD", packet="b"),
                  synthetic("m", "CHAT", "supported", outcome="UNDETERMINED", packet="c")]
        summary = evaluate_corpus(corpus)["by_model"]["x:m"]
        assert summary["outcome_labelled"] == 2 and summary["confirmed_by_outcome"] == 0.5

    def test_the_rendering_says_nothing_was_trained(self):
        text = render_evaluation(evaluate_corpus([synthetic("m", "CHAT", "supported")]))
        assert "Nothing was trained" in text


# ── the command line and the script ──────────────────────────────────────────

def _cli(*args):
    env = {k: v for k, v in os.environ.items() if not k.startswith("RG_SEMANTIC_")}
    return subprocess.run([sys.executable, "-m", "release_gate.cli", "assure", *args],
                          capture_output=True, text=True, timeout=300,
                          env={**env, "PYTHONPATH": str(ROOT)})


@pytest.fixture
def replay(run, tmp_path):
    """A persisted --semantic-out file, as the CLI writes it."""
    outcome, assertions, packets, plan, case = run
    out = tmp_path / "semantic.jsonl"
    lines = [json.dumps(plan.to_dict(), sort_keys=True)]
    for packet, assertion in zip(packets, assertions):
        lines += [json.dumps(packet.to_dict(), sort_keys=True),
                  json.dumps(assertion.to_dict(), sort_keys=True)]
    out.write_text("\n".join(lines) + "\n")
    return case, out


class TestTheCommandLine:

    def test_a_replayed_run_writes_its_corpus_once(self, replay, tmp_path):
        case, semantic = replay
        corpus = tmp_path / "corpus.jsonl"
        first = _cli(str(case), "--semantic-assertions", str(semantic),
                     "--calibration-out", str(corpus))
        assert "1 adjudication(s) added" in first.stderr, first.stderr + first.stdout
        (row,) = read_calibration(corpus)
        assert row["privacy_mode"] == "hash-only"
        assert row["packet_item_count"] >= 1 and row["adjudication_mode"]
        again = _cli(str(case), "--semantic-assertions", str(semantic),
                     "--calibration-out", str(corpus))
        assert "0 adjudication(s) added" in again.stderr
        assert len(read_calibration(corpus)) == 1
        assert again.returncode == first.returncode

    def test_calibration_changes_no_decision(self, replay, tmp_path):
        case, semantic = replay
        plain = _cli(str(case), "--semantic-assertions", str(semantic), "--json")
        kept = _cli(str(case), "--semantic-assertions", str(semantic), "--json",
                    "--calibration-out", str(tmp_path / "c.jsonl"))
        assert plain.returncode == kept.returncode
        assert json.loads(plain.stdout)["decision"] == json.loads(kept.stdout)["decision"]

    def test_full_text_needs_a_name_and_says_it_is_not_shareable(self, replay, tmp_path):
        case, semantic = replay
        refused = _cli(str(case), "--semantic-assertions", str(semantic),
                       "--calibration-out", str(tmp_path / "c.jsonl"),
                       "--calibration-privacy", "full")
        assert refused.returncode == 1 and "declared_by" in refused.stdout
        assert not (tmp_path / "c.jsonl").exists()
        kept = _cli(str(case), "--semantic-assertions", str(semantic),
                    "--calibration-out", str(tmp_path / "c.jsonl"),
                    "--calibration-privacy", "full", "--calibration-declared-by", "alice")
        assert "not shareable" in kept.stderr

    def test_without_semantic_adjudication_there_is_nothing_to_record(self, run, tmp_path):
        case = run[4]
        result = _cli(str(case), "--calibration-out", str(tmp_path / "c.jsonl"))
        assert result.returncode == 1 and "makes none" in result.stdout

    def test_privacy_flags_without_a_corpus_are_an_error(self, run):
        result = _cli(str(run[4]), "--calibration-privacy", "redacted")
        assert result.returncode == 1 and "apply to --calibration-out" in result.stdout

    def test_the_evaluation_script(self, replay, tmp_path):
        case, semantic = replay
        corpus = tmp_path / "corpus.jsonl"
        _cli(str(case), "--semantic-assertions", str(semantic),
             "--calibration-out", str(corpus))
        (row,) = read_calibration(corpus)
        labels = tmp_path / "labels.jsonl"
        labels.write_text(json.dumps({
            "record_id": row["record_id"], "supplied_by": "council",
            "human": {"verdict": "supported", "adjudicator": "dana"}}) + "\n")
        labelled = tmp_path / "labelled.jsonl"
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "evaluate_decision_models.py"),
             str(corpus), "--labels", str(labels), "--class", "general-1=general",
             "--json", "--labelled-out", str(labelled)],
            capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        report = json.loads(result.stdout)
        assert report["trained"] is False and report["unmatched_labels"] == []
        assert report["by_class"]["general"]["agreement_with_human"] == 1.0
        (joined,) = read_calibration(labelled)
        assert joined["human_verdict"] == "supported"
        bad = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "evaluate_decision_models.py"),
             str(corpus), "--class", "nonsense"], capture_output=True, text=True)
        assert bad.returncode == 1 and "MODEL=CLASS" in bad.stderr


def test_the_corpus_schema_is_registered():
    from release_gate.assurance.protocol import PROTOCOL
    assert "calibration" in {s.name for s in PROTOCOL.schemas}
    assert PrivacyMode.HASH_ONLY.value == "hash-only"

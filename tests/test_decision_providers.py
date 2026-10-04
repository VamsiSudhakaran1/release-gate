"""Decision-model providers: STATE, QUESTION, CHOICES in — and nothing invented.

Pinned here, against the decision path in release_gate/assurance/semantic_verifier.py,
the transport in release_gate/decision_providers/ and the provider plumbing in
release_gate/semantic_providers.py:

* the request is exactly a state, a question about one claim, and the three
  choices `established | violated | insufficient_evidence`;
* what comes back is checked and never repaired: probabilities are kept as
  returned, never rescaled, never filled in for a choice the provider did not
  score; scores are never turned into probabilities; a bare choice has no
  confidence, and by default is UNKNOWN;
* ties, bad sums, unknown labels, a choice that disagrees with its own
  distribution, outputs the provider said it does not give — each is UNKNOWN;
* capabilities are discovered, or a default that says it is one, and an answer
  persists who declared what;
* Laya and Jev are optional modules no import path reaches unless asked, and
  providers from installed packages are found by entry point, with a broken one
  recorded rather than fatal;
* every network exchange here is with a server on 127.0.0.1 this file starts.
"""

from __future__ import annotations

import http.server
import json
import subprocess
import sys
import threading
import time

import pytest

from release_gate.assurance.canonical import digest_bytes
from release_gate.assurance.producer_contract import ConfidenceSemantics, Determinism
from release_gate.assurance.semantic_verifier import (
    DECISION_CHOICES, DEFAULT_CAPABILITIES_DECLARER, DEFAULT_SEMANTIC_VERIFIER_POLICY,
    AssertionStatus, DecisionProvider, DecisionReply, Locality,
    LowConfidenceAction, OutputKind, ProviderCapabilities, ProviderIdentity,
    ProviderInterface, ProviderRegistry, ProviderTimeout, SemanticAssertion,
    SemanticVerdict, SemanticVerifier, SemanticVerifierError, SemanticVerifierPolicy,
    UnknownReason, UnscoredAction, assertions_from_records, assertions_to_records,
    build_evidence_packet, discover_capabilities, state_hash_for, unresolved_questions)
from release_gate.assurance.zero_config import assure

CLOCK = "2026-10-04T09:00:00Z"
CHOICES = ("established", "violated", "insufficient_evidence")


def P(pid: str, kind: str = "agent") -> dict:
    return {"producer_id": pid, "kind": kind}


def rows() -> list:
    """One claim carried only by declarations — open to a reading."""
    return [
        {"record_type": "claim", "claim_id": "c-transfer", "is_root": True,
         "proposition": "All transfers above 10,000 require human approval before execution",
         "producer": P("platform", "human")},
        {"record_type": "evidence", "evidence_id": "e-trace", "kind": "TRACE",
         "producer": P("otel"), "supports_claims": ["c-transfer"],
         "coverage_note": "30 days of production transfers",
         "summary": "412 transfers above 10,000; each preceded by approve_transfer"},
        {"record_type": "evidence", "evidence_id": "e-summary", "kind": "OTHER",
         "producer": P("codex"), "supports_claims": ["c-transfer"],
         "coverage_note": "the agent's own summary",
         "summary": "an approval gate is implemented in transfer_tool.py"},
    ]


@pytest.fixture
def case_file(tmp_path):
    path = tmp_path / "case.json"
    path.write_text(json.dumps(rows()))
    return str(path)


@pytest.fixture
def first(case_file):
    return assure(case_file)


@pytest.fixture
def packet(first):
    [question] = unresolved_questions(first.analysis.resolution)
    records = {r.evidence_id: r for r in first.case.records("evidence")
               if hasattr(r, "evidence_id")}
    return build_evidence_packet(question, records=records,
                                 state_hash=state_hash_for(first.analysis))


def capabilities(*outputs, **kw):
    return ProviderCapabilities(interface=ProviderInterface.DECISION,
                                outputs=outputs or (OutputKind.PROBABILITY,),
                                confidence=kw.pop("confidence",
                                                  ConfidenceSemantics.DECLARED_PROBABILITY),
                                locality=kw.pop("locality", Locality.LOCAL), **kw)


class Decider:
    """A decision provider that returns whatever the test scripts."""

    def __init__(self, reply=None, *, raises=None, caps=None, name="scripted-decider"):
        self.reply, self.raises, self.caps = reply, raises, caps
        self.name, self.requests = name, []

    def identity(self):
        return ProviderIdentity(provider=self.name, model="sys1-small",
                                model_family="sys1", endpoint="local://decider",
                                local=True, dialect="release-gate-decision/1")

    def capabilities(self):
        if self.caps is None:
            raise RuntimeError("no description served")
        return self.caps

    def decide(self, request):
        self.requests.append(request)
        if self.raises is not None:
            raise self.raises
        return self.reply


class Ticker:
    """A timer that advances a fixed step per read, so latency is exact."""

    def __init__(self, step=0.25):
        self.now, self.step = 100.0, step

    def __call__(self):
        value = self.now
        self.now += self.step
        return value


def ask(packet, reply=None, *, raises=None, caps=None, policy=DEFAULT_SEMANTIC_VERIFIER_POLICY,
        timer=None):
    provider = Decider(reply, raises=raises,
                       caps=capabilities(OutputKind.PROBABILITY, OutputKind.SCORE,
                                         OutputKind.CHOICE,
                                         OutputKind.FREE_FORM_REASONING)
                       if caps is None else caps)
    verifier = SemanticVerifier(provider, policy=policy, clock=lambda: CLOCK,
                                timer=timer or Ticker())
    return verifier.verify(packet), provider


def probs(e=0.86, v=0.09, i=0.05):
    return {"established": e, "violated": v, "insufficient_evidence": i}


# ── the request is STATE / QUESTION / CHOICES and nothing else ───────────────

class TestTheRequest:

    def test_state_question_and_the_three_choices(self, packet):
        _, provider = ask(packet, DecisionReply(probabilities=probs()))
        [request] = provider.requests
        assert request.choices == CHOICES
        assert tuple(DECISION_CHOICES) == CHOICES
        assert request.question == ("Does the evidence establish: All transfers above "
                                    "10,000 require human approval before execution?")
        for ref in packet.refs:
            assert f"[{ref}]" in request.state
        assert request.state_hash == digest_bytes(request.state.encode("utf-8"))
        text = request.as_text()
        assert text.index("STATE:") < text.index("QUESTION:") < text.index("CHOICES:")
        assert "- insufficient_evidence" in text

    def test_the_choices_are_the_three_verdicts_and_never_a_decision(self):
        assert set(DECISION_CHOICES.values()) == set(SemanticVerdict)
        for word in ("PROMOTE", "HOLD", "BLOCK", "promote", "hold", "block"):
            assert word not in DECISION_CHOICES

    def test_the_state_is_the_packet_and_only_the_packet(self, packet):
        _, provider = ask(packet, DecisionReply(probabilities=probs()))
        state = provider.requests[0].state
        assert "e-unrelated" not in state
        assert state.count("\n[") + 1 == len(packet.items)

    def test_the_same_packet_is_the_same_request(self, packet):
        one = SemanticVerifier(Decider()).decision_request_for(packet)
        two = SemanticVerifier(Decider()).decision_request_for(packet)
        assert one.to_dict() == two.to_dict()


# ── what comes back: kept as returned, nothing invented ──────────────────────

class TestNothingInvented:

    def test_probabilities_answer_and_are_kept_exactly(self, packet):
        returned = probs(0.86, 0.09, 0.05)
        assertion, _ = ask(packet, DecisionReply(probabilities=returned,
                                                 model_version="sys1-small-2026.09"))
        assert assertion.answered and assertion.verdict is SemanticVerdict.SUPPORTED
        assert assertion.chosen == "established"
        assert assertion.confidence == 0.86
        assert assertion.probabilities == returned
        assert assertion.scores is None

    def test_a_sum_within_tolerance_is_kept_not_rescaled(self, packet):
        returned = probs(0.802, 0.1, 0.1)      # sums to 1.002
        assertion, _ = ask(packet, DecisionReply(probabilities=returned))
        assert assertion.answered
        assert assertion.probabilities == returned
        assert assertion.confidence == 0.802

    def test_a_choice_the_provider_did_not_score_stays_absent(self, packet):
        returned = {"established": 0.9, "violated": 0.1}
        assertion, _ = ask(packet, DecisionReply(probabilities=returned))
        assert assertion.answered
        assert "insufficient_evidence" not in assertion.probabilities

    def test_scores_are_kept_and_never_become_probabilities(self, packet):
        scores = {"established": 4.2, "violated": -1.0, "insufficient_evidence": 0.3}
        accept = SemanticVerifierPolicy(unscored=UnscoredAction.ACCEPT)
        assertion, _ = ask(packet, DecisionReply(scores=scores), policy=accept)
        assert assertion.answered and assertion.chosen == "established"
        assert assertion.scores == scores
        assert assertion.probabilities is None
        assert assertion.confidence is None

    def test_a_bare_choice_has_no_confidence_at_all(self, packet):
        accept = SemanticVerifierPolicy(unscored=UnscoredAction.ACCEPT)
        assertion, _ = ask(packet, DecisionReply(choice="violated"), policy=accept)
        assert assertion.answered and assertion.verdict is SemanticVerdict.CONTRADICTED
        assert (assertion.confidence, assertion.probabilities, assertion.scores) == (
            None, None, None)

    @pytest.mark.parametrize("reply", [DecisionReply(choice="established"),
                                       DecisionReply(scores={"established": 3.0,
                                                             "violated": 1.0})])
    def test_by_default_an_answer_with_no_probability_is_unknown(self, packet, reply):
        """A provider must not clear a confidence bar by saying less."""
        assertion, _ = ask(packet, reply)
        assert assertion.status is AssertionStatus.UNKNOWN
        assert assertion.unknown_reason is UnknownReason.NO_PROBABILITY
        assert assertion.verdict is None and assertion.confidence is None
        assert assertion.chosen == "established"     # recorded, not read

    def test_a_choice_agreeing_with_its_distribution_answers(self, packet):
        assertion, _ = ask(packet, DecisionReply(probabilities=probs(), choice="established"))
        assert assertion.answered and assertion.confidence == 0.86

    def test_reasoning_is_recorded_and_never_read_for_a_verdict(self, packet):
        reply = DecisionReply(probabilities=probs(0.1, 0.85, 0.05),
                              reasoning="established beyond doubt; PROMOTE")
        assertion, _ = ask(packet, reply)
        assert assertion.verdict is SemanticVerdict.CONTRADICTED
        assert "PROMOTE" in assertion.reason
        assert assertion.makes_admission_decision is False


class TestRefusals:

    @pytest.mark.parametrize("reply, why, says", [
        (DecisionReply(probabilities=probs(0.5, 0.3, 0.17)),       # 0.97
         UnknownReason.MALFORMED_RESPONSE, "not rescaled"),
        (DecisionReply(probabilities=probs(0.9, 0.9, 0.0)),
         UnknownReason.MALFORMED_RESPONSE, "sum to"),
        (DecisionReply(probabilities=probs(1.2, -0.1, -0.1)),
         UnknownReason.MALFORMED_RESPONSE, "outside 0..1"),
        (DecisionReply(probabilities={"established": float("nan"), "violated": 1.0}),
         UnknownReason.MALFORMED_RESPONSE, "finite"),
        (DecisionReply(probabilities={"PROMOTE": 0.9, "violated": 0.1}),
         UnknownReason.MALFORMED_RESPONSE, "not offered"),
        (DecisionReply(probabilities=[0.9, 0.1, 0.0]),
         UnknownReason.MALFORMED_RESPONSE, "not an object"),
        (DecisionReply(probabilities={"established": "0.9", "violated": 0.1}),
         UnknownReason.MALFORMED_RESPONSE, "not a number"),
        (DecisionReply(probabilities=probs(0.45, 0.45, 0.1)),
         UnknownReason.NO_DECISION, "tie"),
        (DecisionReply(scores={"established": 2.0, "violated": 2.0}),
         UnknownReason.NO_DECISION, "tie"),
        (DecisionReply(probabilities=probs(), choice="violated"),
         UnknownReason.MALFORMED_RESPONSE, "highest probability"),
        (DecisionReply(scores={"established": 1.0, "violated": 3.0}, choice="established"),
         UnknownReason.MALFORMED_RESPONSE, "scored"),
        (DecisionReply(choice="PROMOTE"), UnknownReason.MALFORMED_RESPONSE, "not offered"),
        (DecisionReply(), UnknownReason.MALFORMED_RESPONSE, "no choice"),
        ("established", UnknownReason.MALFORMED_RESPONSE, "not a decision"),
    ])
    def test_each_is_unknown_with_its_reason(self, packet, reply, why, says):
        assertion, _ = ask(packet, reply)
        assert assertion.status is AssertionStatus.UNKNOWN
        assert assertion.unknown_reason is why
        assert says in assertion.detail
        assert assertion.verdict is None
        assert assertion.probabilities is None

    def test_a_rejected_distribution_is_still_on_the_record(self, packet):
        assertion, _ = ask(packet, DecisionReply(probabilities=probs(0.5, 0.3, 0.17)))
        assert '"established":0.5' in assertion.response
        assert assertion.response_digest

    def test_low_probability_is_unknown_and_may_ask_for_more(self, packet):
        reply = DecisionReply(probabilities=probs(0.6, 0.3, 0.1))
        quiet, _ = ask(packet, reply)
        assert quiet.unknown_reason is UnknownReason.LOW_CONFIDENCE
        assert quiet.requires_verification is False
        loud, _ = ask(packet, reply, policy=SemanticVerifierPolicy(
            low_confidence=LowConfidenceAction.REQUIRE_VERIFICATION))
        assert loud.unknown_reason is UnknownReason.LOW_CONFIDENCE
        assert loud.requires_verification is True
        assert loud.probabilities == probs(0.6, 0.3, 0.1)

    def test_an_output_the_provider_said_it_does_not_give_is_not_read(self, packet):
        caps = capabilities(OutputKind.CHOICE)
        assertion, _ = ask(packet, DecisionReply(probabilities=probs()), caps=caps)
        assert assertion.unknown_reason is UnknownReason.MALFORMED_RESPONSE
        assert "declared only CHOICE" in assertion.detail

    def test_a_provider_that_declared_nothing_is_held_to_nothing(self, packet):
        provider = Decider(DecisionReply(probabilities=probs()))   # capabilities() raises
        assertion = SemanticVerifier(provider).verify(packet)
        assert assertion.answered
        assert assertion.capabilities["declared_by"] == DEFAULT_CAPABILITIES_DECLARER

    @pytest.mark.parametrize("bad, field", [(float("inf"), "probabilities"),
                                            (None, "metadata")])
    def test_a_strange_reply_is_recorded_without_crashing(self, packet, bad, field):
        reply = (DecisionReply(probabilities={"established": bad})
                 if field == "probabilities"
                 else DecisionReply(probabilities=probs(),
                                    metadata={"handle": object(), "n": float("nan")}))
        assertion, _ = ask(packet, reply)
        assert assertion.assertion_id
        json.dumps(assertion.to_dict(), allow_nan=False)


class TestFailures:

    def test_a_timeout_is_unknown_and_its_latency_kept(self, packet):
        assertion, _ = ask(packet, raises=ProviderTimeout("slow"))
        assert assertion.unknown_reason is UnknownReason.TIMEOUT
        assert assertion.latency_ms == 250.0

    def test_a_crash_is_unknown(self, packet):
        assertion, _ = ask(packet, raises=ValueError("boom"))
        assert assertion.unknown_reason is UnknownReason.PROVIDER_UNAVAILABLE

    def test_over_the_declared_context_is_not_sent(self, packet):
        assertion, provider = ask(packet, DecisionReply(probabilities=probs()),
                                  caps=capabilities(max_input_chars=50))
        assert assertion.unknown_reason is UnknownReason.PACKET_TOO_LARGE
        assert provider.requests == []

    def test_more_choices_than_it_takes_is_not_sent(self, packet):
        assertion, provider = ask(packet, DecisionReply(probabilities=probs()),
                                  caps=capabilities(max_choices=2))
        assert assertion.unknown_reason is UnknownReason.UNSUPPORTED_BY_PROVIDER
        assert provider.requests == []

    def test_a_provider_without_the_method_its_interface_needs(self, packet):
        class ChatShaped:
            def identity(self):
                return ProviderIdentity(provider="x", model="y")

            def capabilities(self):
                return capabilities()

        assertion = SemanticVerifier(ChatShaped()).verify(packet)
        assert assertion.unknown_reason is UnknownReason.UNSUPPORTED_BY_PROVIDER
        assert "no decide()" in assertion.detail

    def test_unknown_leaves_the_case_where_the_rules_put_it(self, packet, first, case_file):
        for reply in (DecisionReply(probabilities=probs(0.45, 0.45, 0.1)),
                      DecisionReply(choice="established")):
            assertion, _ = ask(packet, reply)
            after = assure(case_file, semantic_assertions=[assertion])
            assert (after.analysis.resolution.of("c-transfer").status
                    is first.analysis.resolution.of("c-transfer").status)
            assert after.case.verdict.decision is first.case.verdict.decision


# ── what is persisted, and what the case does with it ────────────────────────

class TestPersisted:

    def test_everything_the_answer_rests_on_is_exposed(self, packet):
        assertion, provider = ask(packet, DecisionReply(
            probabilities=probs(), model_version="sys1-small-2026.09",
            metadata={"tokens": 311, "route": "local-gpu-0"}))
        [request] = provider.requests
        row = assertion.to_dict()
        assert row["interface"] == "DECISION"
        assert (row["provider"], row["model"], row["model_version"]) == (
            "scripted-decider", "sys1-small", "sys1-small-2026.09")
        assert row["input_state_hash"] == request.state_hash
        assert row["question_text"] == request.question
        assert row["choices"] == list(CHOICES)
        assert row["probabilities"] == probs()
        assert row["latency_ms"] == 250.0
        assert row["provider_metadata"] == {"tokens": 311, "route": "local-gpu-0"}
        assert row["capabilities"]["outputs"] == [
            "PROBABILITY", "SCORE", "CHOICE", "FREE_FORM_REASONING"]
        assert row["makes_admission_decision"] is False and row["establishes"] is False

    def test_a_raw_body_is_what_is_kept(self, packet):
        raw = '{"probabilities": {"established": 0.86, "violated": 0.09, ' \
              '"insufficient_evidence": 0.05}}'
        assertion, _ = ask(packet, DecisionReply(probabilities=probs(), raw=raw))
        assert assertion.response == raw
        assert assertion.response_digest == digest_bytes(raw.encode("utf-8"))

    def test_latency_is_a_fact_about_the_run_not_the_answer(self, packet):
        one, _ = ask(packet, DecisionReply(probabilities=probs()), timer=Ticker(0.1))
        two, _ = ask(packet, DecisionReply(probabilities=probs()), timer=Ticker(2.0))
        assert one.latency_ms != two.latency_ms
        assert one.assertion_id == two.assertion_id

    def test_it_round_trips_and_replays_to_the_same_case(self, packet, case_file):
        assertion, _ = ask(packet, DecisionReply(probabilities=probs(0.05, 0.9, 0.05)))
        again = SemanticAssertion.from_dict(json.loads(json.dumps(assertion.to_dict())))
        assert again.to_dict() == assertion.to_dict()
        [(_, read)] = assertions_from_records(assertions_to_records([assertion]))
        assert read.assertion_id == assertion.assertion_id
        live = assure(case_file, semantic_assertions=[assertion])
        replayed = assure(case_file, semantic_assertions=[again], semantic_submitted=True)
        assert replayed.case.verdict.decision is live.case.verdict.decision
        assert "RG-SEM-001" in {f.rule_id for f in live.analysis.findings}

    def test_a_decision_reads_through_the_same_policy_as_a_chat_answer(self, packet,
                                                                       case_file, first):
        """A violated decision is a contradicting reading: HOLD by default, and
        no more — the decision model's word is the policy's to weigh."""
        assertion, _ = ask(packet, DecisionReply(probabilities=probs(0.02, 0.97, 0.01)))
        after = assure(case_file, semantic_assertions=[assertion])
        assert after.case.verdict.decision.value == "HOLD"
        semantic = [i for i in after.analysis.resolution.of("c-transfer").items
                    if i.item_kind == "semantic"]
        assert [i.role.value for i in semantic] == ["SEMANTIC_CHALLENGE"]

    def test_a_persisted_answer_with_non_finite_numbers_is_refused(self, packet):
        assertion, _ = ask(packet, DecisionReply(probabilities=probs()))
        row = assertion.to_dict()
        row["probabilities"] = {"established": "NaN"}
        with pytest.raises(SemanticVerifierError):
            SemanticAssertion.from_dict(row)


# ── capabilities: declared, or a default that says so ────────────────────────

class TestCapabilities:

    def test_round_trip_and_strict_reading(self):
        caps = capabilities(OutputKind.PROBABILITY, OutputKind.CHOICE, max_input_chars=8000,
                            max_choices=3, determinism=Determinism.DETERMINISTIC,
                            probabilities_calibrated=True, cost_per_call=0.002)
        assert ProviderCapabilities.from_dict(caps.to_dict()) == caps
        for bad in ({"interface": "TELEPATHY"}, {"interface": "DECISION", "outputs": ["VIBES"]},
                    {"interface": "DECISION", "max_choices": 0}, "DECISION"):
            with pytest.raises(SemanticVerifierError):
                ProviderCapabilities.from_dict(bad)
        with pytest.raises(SemanticVerifierError):
            capabilities(cost_per_call=-1)

    def test_a_provider_that_cannot_describe_itself_gets_the_labelled_default(self):
        found = discover_capabilities(Decider())
        assert found.interface is ProviderInterface.DECISION
        assert found.outputs == () and found.confidence is ConfidenceSemantics.NONE
        assert found.locality is Locality.LOCAL
        assert found.declared_by == DEFAULT_CAPABILITIES_DECLARER

    def test_the_chat_transport_states_its_contract(self):
        from release_gate.semantic_providers import OpenAICompatibleProvider
        local = OpenAICompatibleProvider(base_url="http://localhost:11434/v1", model="m")
        remote = OpenAICompatibleProvider(base_url="https://api.example.com/v1", model="m",
                                          api_key="k", cost_per_call=0.01,
                                          max_input_chars=20000)
        caps = local.capabilities()
        assert caps.interface is ProviderInterface.CHAT
        assert caps.outputs == (OutputKind.CHOICE, OutputKind.FREE_FORM_REASONING)
        assert caps.confidence is ConfidenceSemantics.PRODUCER_SCORE
        assert caps.determinism is Determinism.UNKNOWN
        assert caps.locality is Locality.LOCAL
        assert remote.capabilities().locality is Locality.REMOTE
        assert remote.capabilities().cost_per_call == 0.01
        assert remote.capabilities().max_input_chars == 20000
        assert "by the operator" in remote.capabilities().declared_by

    def test_a_registry_takes_a_decision_provider(self):
        registry = ProviderRegistry()
        registry.register("sys1", lambda **kw: Decider())
        assert isinstance(registry.create("sys1"), DecisionProvider)


# ── the transport, against a local server ────────────────────────────────────

class _DecisionServer:
    """A local release-gate-decision/1 endpoint whose behaviour each test sets."""

    def __init__(self):
        self.mode, self.seen = "ok", []
        self.capabilities = {"interface": "DECISION",
                             "outputs": ["PROBABILITY", "FREE_FORM_REASONING"],
                             "confidence": "DECLARED_PROBABILITY", "max_choices": 8,
                             "max_input_chars": 64000, "locality": "LOCAL",
                             "determinism": "DETERMINISTIC",
                             "probabilities_calibrated": True}
        self.decision = {"probabilities": probs(), "model_version": "sys1-2026.09",
                         "reasoning": "trace shows approve_transfer before each call",
                         "metadata": {"tokens": 97}}
        state = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, code, payload):
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(payload if isinstance(payload, bytes)
                                 else json.dumps(payload).encode())

            def do_GET(self):
                state.seen.append({"method": "GET", "path": self.path,
                                   "auth": self.headers.get("Authorization")})
                if self.path.endswith("/capabilities") and state.capabilities is not None:
                    self._send(200, state.capabilities)
                else:
                    self._send(404, {"error": "not found"})

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                state.seen.append({"method": "POST", "path": self.path, "body": body,
                                   "auth": self.headers.get("Authorization")})
                if state.mode == "slow":
                    time.sleep(1.0)
                if state.mode == "error":
                    self._send(503, {"error": "overloaded"})
                elif state.mode == "garbage":
                    self._send(200, b"<html>not json</html>")
                elif state.mode == "list":
                    self._send(200, [0.86, 0.09, 0.05])
                else:
                    self._send(200, state.decision)

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def close(self):
        self.httpd.shutdown()


@pytest.fixture
def server():
    s = _DecisionServer()
    yield s
    s.close()


def http_provider(server, cls=None, **kw):
    from release_gate.decision_providers import DecisionHTTPProvider
    return (cls or DecisionHTTPProvider)(base_url=server.url, model="sys1-small",
                                         model_family="sys1", **kw)


class TestTheTransport:

    def test_it_asks_in_the_protocol_and_keeps_what_came_back(self, server, packet):
        provider = http_provider(server, api_key="local-key")
        assertion = SemanticVerifier(provider, clock=lambda: CLOCK).verify(packet)
        assert assertion.answered and assertion.verdict is SemanticVerdict.SUPPORTED
        get, post = server.seen
        assert (get["method"], get["path"]) == ("GET", "/capabilities")
        assert (post["method"], post["path"]) == ("POST", "/decide")
        body = post["body"]
        assert body["protocol"] == "release-gate-decision/1"
        assert body["model"] == "sys1-small" and body["choices"] == list(CHOICES)
        assert body["state_hash"] == assertion.input_state_hash
        assert body["state_hash"] == digest_bytes(body["state"].encode("utf-8"))
        assert post["auth"] == "Bearer local-key"
        assert json.loads(assertion.response) == server.decision
        assert assertion.response_digest == digest_bytes(assertion.response.encode())
        assert assertion.model_version == "sys1-2026.09"
        assert assertion.provider_metadata == {"tokens": 97}
        assert assertion.capabilities["declared_by"] == f"{server.url}/capabilities"
        assert assertion.capabilities["probabilities_calibrated"] is True

    def test_capabilities_are_asked_once(self, server, packet):
        provider = http_provider(server)
        verifier = SemanticVerifier(provider)
        verifier.verify(packet)
        verifier.verify(packet)
        assert [s["method"] for s in server.seen] == ["GET", "POST", "POST"]

    @pytest.mark.parametrize("served, note", [
        (None, "was not served"),
        ({"interface": "CHAT", "outputs": ["CHOICE"]}, "decision interface"),
        ({"interface": "DECISION", "outputs": ["TELEPATHY"]}, "unreadable"),
    ])
    def test_no_usable_description_is_the_labelled_default(self, server, packet, served,
                                                           note):
        server.capabilities = served
        provider = http_provider(server)
        caps = provider.capabilities()
        assert caps.declared_by == DEFAULT_CAPABILITIES_DECLARER
        assert caps.interface is ProviderInterface.DECISION and caps.outputs == ()
        assert note in provider.capabilities_note
        assert SemanticVerifier(provider).verify(packet).answered

    @pytest.mark.parametrize("mode, why", [
        ("error", UnknownReason.PROVIDER_UNAVAILABLE),
        ("garbage", UnknownReason.PROVIDER_UNAVAILABLE),
        ("list", UnknownReason.MALFORMED_RESPONSE),
    ])
    def test_a_failing_endpoint_is_unknown(self, server, packet, mode, why):
        server.mode = mode
        assertion = SemanticVerifier(http_provider(server)).verify(packet)
        assert assertion.unknown_reason is why

    def test_a_slow_endpoint_times_out_to_unknown(self, server, packet):
        server.mode = "slow"
        policy = SemanticVerifierPolicy(timeout_seconds=0.2)
        assertion = SemanticVerifier(http_provider(server), policy=policy).verify(packet)
        assert assertion.unknown_reason is UnknownReason.TIMEOUT
        assert assertion.latency_ms is not None

    def test_a_reply_outside_its_declaration_is_not_read(self, server, packet):
        server.decision = {"choice": "established"}     # declared PROBABILITY only
        assertion = SemanticVerifier(http_provider(server)).verify(packet)
        assert assertion.unknown_reason is UnknownReason.MALFORMED_RESPONSE

    def test_the_operator_figures_lay_over_the_declaration(self, server):
        provider = http_provider(server, cost_per_call=0.004, max_input_chars=1000)
        caps = provider.capabilities()
        assert (caps.cost_per_call, caps.max_input_chars) == (0.004, 1000)
        assert caps.max_choices == 8            # the endpoint's own figure stands
        assert caps.declared_by.endswith("by the operator")

    def test_configuration_is_refused_not_guessed(self):
        from release_gate.decision_providers import DecisionHTTPProvider
        from release_gate.semantic_providers import SemanticProviderConfigError
        for kw in ({"base_url": "", "model": "m"},
                   {"base_url": "http://127.0.0.1:9", "model": ""},
                   {"base_url": "https://sys1.example.com", "model": "m"},
                   {"base_url": "http://127.0.0.1:9", "model": "m",
                    "dialect": "openai_chat"}):
            with pytest.raises(SemanticProviderConfigError):
                DecisionHTTPProvider(**kw)

    def test_no_credential_in_what_is_kept(self, server, packet):
        from release_gate.decision_providers import DecisionHTTPProvider
        provider = DecisionHTTPProvider(base_url="https://u:pw@sys1.example.com/x?key=abc",
                                        model="m", api_key="sk-SECRET")
        identity = json.dumps(provider.identity().to_dict())
        assert "sk-SECRET" not in identity and "pw" not in identity
        assert "key=abc" not in identity
        live = SemanticVerifier(http_provider(server, api_key="sk-SECRET")).verify(packet)
        assert "sk-SECRET" not in json.dumps(live.to_dict())


# ── the optional named modules, and providers from installed packages ────────

class TestOptionalModules:

    def test_nothing_imports_laya_or_jev_unless_asked(self):
        probe = ("import sys, release_gate.cli, release_gate.semantic_providers, "
                 "release_gate.decision_providers, release_gate.assurance\n"
                 "from release_gate.semantic_providers import default_provider_registry\n"
                 "registry = default_provider_registry()\n"
                 "print(sorted(m for m in sys.modules if m.endswith(('.laya', '.jev'))))")
        result = subprocess.run([sys.executable, "-c", probe], capture_output=True,
                                text=True, timeout=120)
        assert result.stdout.strip() == "[]", result.stderr

    @pytest.mark.parametrize("name, cls", [("laya", "LayaProvider"), ("jev", "JevProvider")])
    def test_each_is_built_by_name_and_answers_under_it(self, server, packet, name, cls):
        from release_gate.semantic_providers import default_provider_registry
        provider = default_provider_registry().create(name, base_url=server.url,
                                                      model="sys1-small")
        assert type(provider).__name__ == cls
        assertion = SemanticVerifier(provider).verify(packet)
        assert assertion.answered and assertion.provider == name
        assert server.seen[-1]["path"] == "/decide"

    def test_env_configuration_builds_a_decision_provider(self, server):
        from release_gate.semantic_providers import (SemanticProviderConfigError,
                                                     provider_from_env)
        env = {"RG_SEMANTIC_PROVIDER": "Laya", "RG_SEMANTIC_BASE_URL": server.url,
               "RG_SEMANTIC_MODEL": "sys1-small", "RG_SEMANTIC_MODEL_FAMILY": "sys1",
               "RG_SEMANTIC_COST_PER_CALL": "0.003", "RG_SEMANTIC_MAX_INPUT_CHARS": "9000"}
        provider = provider_from_env(env)
        assert provider.identity().provider == "laya"
        assert provider.capabilities().cost_per_call == 0.003
        assert provider.capabilities().max_input_chars == 9000
        for bad in ({"RG_SEMANTIC_DIALECT": "openai_chat"},
                    {"RG_SEMANTIC_COST_PER_CALL": "cheap"},
                    {"RG_SEMANTIC_COST_PER_CALL": "-1"},
                    {"RG_SEMANTIC_MAX_INPUT_CHARS": "0"}):
            with pytest.raises(SemanticProviderConfigError):
                provider_from_env({**env, **bad})


class _EntryPoint:
    def __init__(self, name, target=None, error=None):
        self.name, self.value = name, f"plugin_pkg:{name}"
        self._target, self._error = target, error

    def load(self):
        if self._error is not None:
            raise self._error
        return self._target


class TestEntryPoints:

    def _offered(self):
        return [_EntryPoint("house-decider", target=lambda **kw: Decider(name="house")),
                _EntryPoint("broken", error=ImportError("no module named sys1_sdk")),
                _EntryPoint("not-a-factory", target=42),
                _EntryPoint("ollama", target=lambda **kw: Decider(name="imposter"))]

    def test_found_registered_and_failures_recorded(self):
        from release_gate.semantic_providers import (ENTRY_POINT_GROUP,
                                                     default_provider_registry,
                                                     discover_providers)
        asked = []
        registry = default_provider_registry()
        report = discover_providers(
            registry, entry_points=lambda group: asked.append(group) or self._offered())
        assert asked == [ENTRY_POINT_GROUP] == ["release_gate.semantic_providers"]
        assert report.registered == ("house-decider",)
        assert report.shadowed == ("ollama",)
        assert set(report.failed) == {"broken", "not-a-factory"}
        assert "sys1_sdk" in report.failed["broken"]
        # A plugin found later cannot replace a shipped transport.
        built = registry.create("ollama", base_url="http://localhost:11434", model="m")
        assert type(built).__name__ == "OpenAICompatibleProvider"

    def test_the_installed_metadata_is_what_is_read_by_default(self, monkeypatch):
        from importlib import metadata

        from release_gate.semantic_providers import (default_provider_registry,
                                                     discover_providers)
        seen = []

        def entry_points(**kw):
            seen.append(kw)
            return self._offered()[:1]

        monkeypatch.setattr(metadata, "entry_points", entry_points)
        report = discover_providers(default_provider_registry())
        assert seen == [{"group": "release_gate.semantic_providers"}]
        assert report.registered == ("house-decider",)

    def test_an_unknown_name_looks_for_a_plugin_and_says_why_it_failed(self):
        from release_gate.semantic_providers import (SemanticProviderConfigError,
                                                     provider_from_env)
        env = {"RG_SEMANTIC_MODEL": "m", "RG_SEMANTIC_BASE_URL": "http://127.0.0.1:9"}
        built = provider_from_env({**env, "RG_SEMANTIC_PROVIDER": "house-decider"},
                                  entry_points=lambda group: self._offered())
        assert built.identity().provider == "house"
        with pytest.raises(SemanticProviderConfigError, match="failed to load"):
            provider_from_env({**env, "RG_SEMANTIC_PROVIDER": "broken"},
                              entry_points=lambda group: self._offered())
        with pytest.raises(SemanticProviderConfigError, match="available"):
            provider_from_env({**env, "RG_SEMANTIC_PROVIDER": "nobody"},
                              entry_points=lambda group: [])

    def test_discovery_runs_only_for_a_name_the_build_does_not_ship(self, server):
        from release_gate.semantic_providers import provider_from_env

        def explode(group):
            raise AssertionError("discovery ran for a shipped provider")

        provider_from_env({"RG_SEMANTIC_PROVIDER": "decision_http",
                           "RG_SEMANTIC_BASE_URL": server.url,
                           "RG_SEMANTIC_MODEL": "m"}, entry_points=explode)


# ── the command line, with a decision model ──────────────────────────────────

class TestTheCommandLine:

    def test_ask_a_decision_model_persist_and_replay(self, server, case_file, tmp_path):
        import os
        out = tmp_path / "semantic.jsonl"
        server.decision = {"probabilities": probs(0.03, 0.95, 0.02)}
        env = {k: v for k, v in os.environ.items() if not k.startswith("RG_SEMANTIC_")}
        env.update({"RG_SEMANTIC_PROVIDER": "decision_http",
                    "RG_SEMANTIC_BASE_URL": server.url, "RG_SEMANTIC_MODEL": "sys1-small"})
        cli = [sys.executable, "-m", "release_gate.cli", "assure", case_file, "--full"]
        asked = subprocess.run(cli + ["--semantic", "--semantic-out", str(out)],
                               capture_output=True, text=True, timeout=300, env=env)
        assert "semantic reading: contradicted" in asked.stdout, asked.stderr
        kept = [json.loads(line) for line in out.read_text().splitlines()]
        [row] = [r for r in kept if r["record_type"] == "semantic_assertion"]
        assert row["interface"] == "DECISION"
        assert row["probabilities"] == probs(0.03, 0.95, 0.02)
        assert row["provider"] == "decision_http"
        server.close()
        replayed = subprocess.run(cli + ["--semantic-assertions", str(out)],
                                  capture_output=True, text=True, timeout=300, env=env)
        assert "semantic reading: contradicted" in replayed.stdout
        assert replayed.returncode == asked.returncode

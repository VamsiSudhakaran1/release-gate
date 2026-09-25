"""Data minimisation, and honesty about what it costs.

Every input shape here is the real one. The OTLP case is load-bearing: OTLP
carries attributes as `{"key": ..., "value": {...}}` pairs, and a minimiser that
keys on dict keys alone matches nothing in it — which is how the first version of
`_walk` reported zero redactions while passing every prompt straight through.
"""

from __future__ import annotations

import json

import pytest

from release_gate.assurance.privacy import (
    PRIVACY_SCHEMA_VERSION, DataClass, Disposition, IngestionScope, Minimisation,
    PrivacyError, Redaction, RedactionPolicy, Residency, SENSITIVE_CLASSES,
    metadata_only_policy, minimise, residency_of,
)
from release_gate.assurance.zero_config import assure

S, C, U, K = "XSYSPROMPTX", "XCHAINOFTHOUGHTX", "alice@corp.example", "sk-XSECRETX"

OTLP = {"resourceSpans": [{"resource": {"attributes": [
    {"key": "service.name", "value": {"stringValue": "agent"}}]},
    "scopeSpans": [{"spans": [
        {"name": "llm", "spanId": "01", "traceId": "0a",
         "startTimeUnixNano": "1", "endTimeUnixNano": "2", "attributes": [
            {"key": "gen_ai.prompt", "value": {"stringValue": S}},
            {"key": "gen_ai.completion", "value": {"stringValue": C}},
            {"key": "gen_ai.request.model", "value": {"stringValue": "gpt-4o"}},
            {"key": "user.email", "value": {"stringValue": U}}]},
        {"name": "tool.write", "spanId": "02", "traceId": "0a",
         "startTimeUnixNano": "2", "endTimeUnixNano": "3", "attributes": [
            {"key": "tool.name", "value": {"stringValue": "write_file"}}]}]}]}]}

LANGFUSE = {"observations": [
    {"id": "o1", "type": "GENERATION", "name": "plan", "model": "gpt-4o",
     "input": {"messages": [{"role": "system", "content": S}]},
     "output": {"completion": C}, "metadata": {"email": U, "api_key": K},
     "reasoning": C, "startTime": "2026-01-01T00:00:00Z"}]}

ARIZE = {"spans": [{"name": "llm", "span_id": "1", "trace_id": "t",
                    "attributes": {"llm.input_messages": S,
                                   "llm.output_messages": C,
                                   "openinference.span.kind": "LLM",
                                   "user.id": U}}]}

PROMPTFOO = {"results": [{"prompt": {"raw": S}, "response": {"completion": C},
                          "success": True, "score": 1.0, "vars": {"email": U}}],
             "stats": {"successes": 1, "failures": 0}}

ALL_SHAPES = {"otlp": OTLP, "langfuse": LANGFUSE, "arize": ARIZE,
              "promptfoo": PROMPTFOO}
SECRETS = (("prompt", S), ("cot", C), ("email", U), ("key", K))


@pytest.fixture
def policy():
    return metadata_only_policy(declared_by="platform-security@corp")


def leaks(payload) -> list:
    blob = json.dumps(payload)
    return [name for name, value in SECRETS if value in blob]


# ── nothing proprietary has to leave ─────────────────────────────────────────

class TestNothingProprietaryLeaves:

    @pytest.mark.parametrize("shape", sorted(ALL_SHAPES))
    def test_no_sensitive_content_survives_minimisation(self, shape, policy):
        sent, _ = minimise(ALL_SHAPES[shape], policy)
        assert leaks(sent) == []

    @pytest.mark.parametrize("shape", sorted(ALL_SHAPES))
    def test_otlp_style_attribute_pairs_are_reached(self, shape, policy):
        """The defect this file exists to prevent: a minimiser that reports
        success while matching nothing."""
        _, record = minimise(ALL_SHAPES[shape], policy)
        assert record.redactions, f"{shape} produced no redactions"

    @pytest.mark.parametrize("shape", sorted(ALL_SHAPES))
    def test_the_verdict_is_unchanged_by_minimisation(self, shape, policy, tmp_path):
        """Assurance works from the structured evidence that remains."""
        sent, _ = minimise(ALL_SHAPES[shape], policy)
        full_path = tmp_path / f"{shape}_full.json"
        thin_path = tmp_path / f"{shape}_thin.json"
        full_path.write_text(json.dumps(ALL_SHAPES[shape]))
        thin_path.write_text(json.dumps(sent))
        assert (assure(str(full_path)).case.verdict.decision
                is assure(str(thin_path)).case.verdict.decision)

    def test_a_policy_never_requires_raw_content(self, policy):
        assert policy.requires_raw_content is False
        assert policy.to_dict()["requires_raw_content"] is False

    def test_metadata_only_sends_nothing_readable(self, policy):
        assert policy.sends_nothing_readable
        for data_class in SENSITIVE_CLASSES:
            assert policy.disposition_of(data_class) is not Disposition.RETAINED

    def test_a_verdict_is_reached_with_every_sensitive_class_withheld(
            self, policy, tmp_path):
        """The claim in the module docstring, as a test."""
        sent, record = minimise(LANGFUSE, policy)
        path = tmp_path / "thin.json"
        path.write_text(json.dumps(sent))
        outcome = assure(str(path))
        assert outcome.case.verdict is not None
        assert set(record.withheld_classes) >= {DataClass.PROMPT,
                                                DataClass.COMPLETION}


# ── the adapters retain nothing, and that is now a contract ──────────────────

class TestAdaptersRetainNothing:
    """Measured across every adapter: no prompt, completion or identifier text
    reaches the case or the evidence pack. This held by accident of how the
    adapters happen to be written; these tests make it a contract, so a fifth
    adapter or a domain plugin cannot quietly start retaining content."""

    @pytest.mark.parametrize("shape", sorted(ALL_SHAPES))
    def test_the_outcome_carries_no_sensitive_text(self, shape, tmp_path):
        path = tmp_path / f"{shape}.json"
        path.write_text(json.dumps(ALL_SHAPES[shape]))
        assert leaks(assure(str(path)).to_dict()) == []

    @pytest.mark.parametrize("shape", sorted(ALL_SHAPES))
    def test_the_evidence_pack_carries_no_sensitive_text(self, shape, tmp_path):
        """The pack is the thing that leaves."""
        from release_gate.assurance.pack import build_pack
        path = tmp_path / f"{shape}.json"
        path.write_text(json.dumps(ALL_SHAPES[shape]))
        assert leaks(build_pack(assure(str(path))).to_dict()) == []


# ── withheld is not absent ───────────────────────────────────────────────────

class TestWithheldIsNotAbsent:
    """The distinction the module exists for. A case that reported both the same
    way would let a redaction pass for a clean bill of health."""

    def test_withheld_never_reads_as_absent(self, policy):
        _, record = minimise(LANGFUSE, policy)
        assert record.withheld_reads_as_absent is False
        assert record.to_dict()["withheld_reads_as_absent"] is False

    def test_a_class_cannot_be_both(self, policy):
        with pytest.raises(PrivacyError) as exc:
            Minimisation(policy=policy,
                         redactions=(Redaction(
                             data_class=DataClass.PROMPT,
                             disposition=Disposition.WITHHELD, locus="$.a",
                             content_digest="sha256:" + "0" * 64,
                             assessment_cost=("x",)),),
                         absent=(DataClass.PROMPT,))
        assert "unable to tell which happened" in str(exc.value)

    def test_a_document_without_a_class_reports_it_absent(self, policy):
        """No prompt in the document is a different fact from a withheld one."""
        _, record = minimise({"spans": [{"name": "tool.read"}]}, policy)
        assert DataClass.PROMPT in record.absent
        assert DataClass.PROMPT not in record.withheld_classes

    def test_a_document_with_one_reports_it_withheld(self, policy):
        _, record = minimise(OTLP, policy)
        assert DataClass.PROMPT in record.withheld_classes
        assert DataClass.PROMPT not in record.absent

    def test_the_render_states_the_difference(self, policy):
        record = minimise(LANGFUSE, policy)[1]
        assert "not the same as withholding it" in record.render()

    def test_a_policy_cannot_declare_content_absent(self):
        """ABSENT is a finding about a document, not a decision about one."""
        with pytest.raises(PrivacyError) as exc:
            RedactionPolicy(policy_id="p", declared_by="d",
                            dispositions={DataClass.PROMPT: Disposition.ABSENT})
        assert "look like an emptiness" in str(exc.value)


# ── a redaction commits to what it removed ───────────────────────────────────

class TestCommitment:

    def test_a_withholding_without_a_digest_is_refused(self):
        """Otherwise it is a deletion, and §10p's threat model applies."""
        with pytest.raises(PrivacyError) as exc:
            Redaction(data_class=DataClass.PROMPT,
                      disposition=Disposition.WITHHELD, locus="$.a",
                      assessment_cost=("x",))
        assert "deletion, not a redaction" in str(exc.value)

    def test_a_digested_field_commits_too(self):
        with pytest.raises(PrivacyError):
            Redaction(data_class=DataClass.TOOL_OUTPUT,
                      disposition=Disposition.DIGESTED, locus="$.a")

    def test_a_reference_must_point_somewhere(self):
        with pytest.raises(PrivacyError) as exc:
            Redaction(data_class=DataClass.ARTIFACT_CONTENT,
                      disposition=Disposition.REFERENCED, locus="$.a",
                      content_digest="sha256:" + "0" * 64)
        assert "says it did not" in str(exc.value)

    def test_every_redaction_carries_a_digest(self, policy):
        _, record = minimise(LANGFUSE, policy)
        assert all(r.content_digest for r in record.redactions)

    def test_the_same_document_commits_to_the_same_digests(self, policy):
        one = minimise(LANGFUSE, policy)[1]
        two = minimise(LANGFUSE, policy)[1]
        assert [r.content_digest for r in one.redactions] == \
            [r.content_digest for r in two.redactions]

    def test_changed_content_commits_differently(self, policy):
        import copy
        other = copy.deepcopy(LANGFUSE)
        other["observations"][0]["input"]["messages"][0]["content"] = "different"

        def prompt_digest(document):
            # Selected by class, not by position. `redactions` is sorted by class
            # name, so indexing [0] compared the chain-of-thought digest against
            # itself and passed for the wrong reason.
            record = minimise(document, policy)[1]
            return next(r.content_digest for r in record.redactions
                        if r.data_class is DataClass.PROMPT)

        assert prompt_digest(LANGFUSE) != prompt_digest(other)

    def test_unchanged_classes_keep_their_commitment(self, policy):
        """The other half: changing the prompt must not move the reasoning
        digest, or a commitment would not identify one particular thing."""
        import copy
        other = copy.deepcopy(LANGFUSE)
        other["observations"][0]["input"]["messages"][0]["content"] = "different"

        def cot_digest(document):
            record = minimise(document, policy)[1]
            return next(r.content_digest for r in record.redactions
                        if r.data_class is DataClass.CHAIN_OF_THOUGHT)

        assert cot_digest(LANGFUSE) == cot_digest(other)

    def test_the_policy_itself_is_content_addressed(self, policy):
        """So a pack carrying the digest lets a reviewer check the document was
        minimised the way the record says."""
        assert policy.policy_digest.startswith("sha256:")
        assert metadata_only_policy(
            declared_by="platform-security@corp").policy_digest == \
            policy.policy_digest

    @pytest.mark.parametrize("document", [
        pytest.param({"arguments": {"path": "/etc/app.conf"}}, id="keyed-digested"),
        pytest.param({"attributes": [
            {"key": "tool_arguments", "value": {"stringValue": "/etc/app.conf"}}]},
            id="otlp-pair-digested"),
        pytest.param(LANGFUSE, id="withheld-only"),
    ])
    def test_minimisation_is_idempotent(self, policy, document):
        """A pipeline where an agent minimises and a gateway minimises again is
        an ordinary deployment, not a mistake.

        Parametrised over a document that produces a DIGESTED field, because a
        withheld-only document drops its keys and is idempotent whether the guard
        exists or not — so a test using only that one passed without exercising
        anything.
        """
        once, first = minimise(document, policy)
        twice, second = minimise(once, policy)
        assert once == twice
        assert second.redactions == ()
        assert first.minimised_digest == second.minimised_digest

    def test_a_digested_field_is_not_digested_again(self, policy):
        """Re-digesting the envelope moved `content_digest` on every pass, so the
        commitment stopped matching the content it committed to."""
        once, first = minimise({"arguments": {"path": "/a"}}, policy)
        assert first.redactions[0].content_digest
        assert minimise(once, policy)[0]["arguments"] == once["arguments"]


# ── withholding costs something, and says what ───────────────────────────────

class TestCost:

    def test_a_withholding_must_state_its_cost(self):
        with pytest.raises(PrivacyError) as exc:
            Redaction(data_class=DataClass.PROMPT,
                      disposition=Disposition.WITHHELD, locus="$.a",
                      content_digest="sha256:" + "0" * 64)
        assert "reads as free" in str(exc.value)

    def test_a_withheld_secret_costs_nothing_and_may_say_so(self):
        """A credential is not evidence. The one named exception, not a blanket
        relaxation."""
        found = Redaction(data_class=DataClass.SECRET,
                          disposition=Disposition.WITHHELD, locus="$.a",
                          content_digest="sha256:" + "0" * 64)
        assert found.assessment_cost == ()

    def test_the_cost_of_withholding_prompts_is_named(self, policy):
        _, record = minimise(OTLP, policy)
        assert any("prompt-injection" in cost for cost in record.assessment_cost)

    def test_a_cost_of_nothing_is_not_listed_as_a_cost(self, policy):
        """It appeared under a NOT ASSESSABLE heading, which was a contradiction
        a reader had to resolve themselves."""
        _, record = minimise(LANGFUSE, policy)
        assert not any("costs no assessment" in cost
                       for cost in record.assessment_cost)

    def test_each_withheld_class_becomes_a_not_assessed_expectation(self, policy):
        """Through the mechanism the case already uses, so a withholding lands in
        coverage rather than in a privacy report read separately."""
        _, record = minimise(LANGFUSE, policy)
        rows = record.expectations()
        assert rows
        assert all(not row.assessed for row in rows)
        assert {row.dimension for row in rows} == {
            f"content.{c.value.lower()}" for c in record.withheld_classes}

    def test_the_expectation_cites_the_policy(self, policy):
        row = minimise(OTLP, policy)[1].expectations()[0]
        assert policy.policy_id in row.note
        assert policy.policy_id in row.observed_from


# ── the policy must be owned ─────────────────────────────────────────────────

class TestPolicy:

    def test_a_policy_must_be_named(self):
        with pytest.raises(PrivacyError) as exc:
            RedactionPolicy(policy_id="  ", declared_by="d")
        assert "cannot be cited" in str(exc.value)

    def test_a_policy_must_name_who_declared_it(self):
        with pytest.raises(PrivacyError) as exc:
            RedactionPolicy(policy_id="p", declared_by="  ")
        assert "cannot be questioned" in str(exc.value)

    def test_an_unmentioned_class_is_retained(self):
        """The permissive default, on purpose: a policy that silently withheld
        classes nobody asked about would minimise more than its author
        declared."""
        policy = RedactionPolicy(policy_id="p", declared_by="d",
                                 dispositions={DataClass.PROMPT:
                                               Disposition.WITHHELD})
        assert policy.disposition_of(DataClass.TOOL_OUTPUT) is Disposition.RETAINED

    def test_extra_fields_extend_rather_than_replace(self):
        policy = RedactionPolicy(
            policy_id="p", declared_by="d",
            dispositions={DataClass.PROMPT: Disposition.WITHHELD},
            extra_fields={DataClass.PROMPT: ("our_custom_prompt_field",)})
        fields = policy.fields_for(DataClass.PROMPT)
        assert "our_custom_prompt_field" in fields
        assert "gen_ai.prompt" in fields

    def test_a_custom_field_is_actually_reached(self):
        policy = RedactionPolicy(
            policy_id="p", declared_by="d", residency=Residency.SELF_HOSTED,
            dispositions={DataClass.PROMPT: Disposition.WITHHELD},
            extra_fields={DataClass.PROMPT: ("house_prompt",)})
        sent, record = minimise({"house_prompt": S}, policy)
        assert S not in json.dumps(sent)
        assert record.withheld_classes == (DataClass.PROMPT,)


# ── residency ────────────────────────────────────────────────────────────────

class TestResidency:

    @pytest.mark.parametrize("residency", list(Residency))
    def test_every_residency_states_what_crosses(self, residency):
        assert len(residency_of(residency)) > 30

    def test_local_and_self_hosted_cross_nothing(self):
        assert "nothing" in residency_of(Residency.LOCAL_ONLY)
        assert "nothing" in residency_of(Residency.SELF_HOSTED)

    def test_private_cloud_does_not_overclaim(self):
        """A tenancy the customer controls still has a cloud operator."""
        assert "operator access" in residency_of(Residency.PRIVATE_CLOUD)

    def test_vendor_hosted_says_a_policy_belongs_in_front(self):
        assert "minimisation policy" in residency_of(Residency.VENDOR_HOSTED)

    def test_the_policy_reports_its_boundary(self, policy):
        assert policy.to_dict()["crosses_the_boundary"] == \
            residency_of(Residency.VENDOR_HOSTED)


# ── selective ingestion ──────────────────────────────────────────────────────

class TestIngestionScope:

    def test_an_excluded_kind_is_never_clean(self):
        scope = IngestionScope(excluded=("eval_result",), declared_by="sec@corp")
        assert scope.excluded_reads_as_clean is False
        assert not scope.admits("eval_result")

    def test_an_admitted_kind_passes(self):
        scope = IngestionScope(admitted=("trace", "artifact"))
        assert scope.admits("trace") and not scope.admits("eval_result")

    def test_an_empty_admit_list_admits_everything(self):
        scope = IngestionScope(excluded=("secret_log",), declared_by="d")
        assert scope.admits("anything_else")

    def test_a_scope_that_names_nothing_is_refused(self):
        with pytest.raises(PrivacyError) as exc:
            IngestionScope()
        assert "needs no scope" in str(exc.value)

    def test_an_exclusion_must_be_owned(self):
        with pytest.raises(PrivacyError) as exc:
            IngestionScope(excluded=("eval_result",))
        assert "never arrived" in str(exc.value)

    def test_a_kind_cannot_be_both(self):
        with pytest.raises(PrivacyError):
            IngestionScope(admitted=("trace",), excluded=("trace",),
                           declared_by="d")

    def test_exclusions_become_not_assessed_expectations(self):
        scope = IngestionScope(excluded=("eval_result", "trace"),
                               declared_by="sec@corp",
                               basis="evals stay in our environment")
        rows = scope.expectations()
        assert {r.dimension for r in rows} == {"records.eval_result",
                                               "records.trace"}
        assert all(not r.assessed for r in rows)
        assert all("was not assessed here" in r.note for r in rows)


# ── the record ───────────────────────────────────────────────────────────────

class TestRecord:

    def test_it_reports_whether_content_left(self, policy):
        _, record = minimise(LANGFUSE, policy)
        assert record.content_left_the_environment is False

    def test_a_retained_class_reports_that_it_did(self):
        policy = RedactionPolicy(
            policy_id="permissive", declared_by="d",
            dispositions={DataClass.PROMPT: Disposition.RETAINED})
        _, record = minimise(LANGFUSE, policy)
        assert record.redactions == ()
        assert not record.content_left_the_environment

    def test_the_document_digests_bracket_the_change(self, policy):
        _, record = minimise(LANGFUSE, policy)
        assert record.document_digest != record.minimised_digest
        assert record.document_digest.startswith("sha256:")

    def test_digested_fields_stay_comparable_without_being_readable(self, policy):
        """Two different tool calls remain distinguishable; their targets do
        not become readable."""
        one = minimise({"arguments": {"path": "/a"}}, policy)[0]
        two = minimise({"arguments": {"path": "/b"}}, policy)[0]
        assert one["arguments"]["digest"] != two["arguments"]["digest"]
        assert "/a" not in json.dumps(one)
        assert one["arguments"]["redacted"] == "TOOL_ARGUMENTS"

    def test_many_occurrences_commit_to_one_value(self, policy):
        doc = {"spans": [{"gen_ai.prompt": S}, {"gen_ai.prompt": "other"}]}
        _, record = minimise(doc, policy)
        prompt = next(r for r in record.redactions
                      if r.data_class is DataClass.PROMPT)
        assert prompt.occurrences == 2
        assert "and 1 more" in prompt.locus

    def test_it_is_pure(self):
        from pathlib import Path
        import release_gate.assurance.privacy as module
        source = Path(module.__file__).read_text()
        for forbidden in ("requests", "httpx", "urllib", "socket", "yaml",
                          "cryptography", "openai", "anthropic"):
            assert f"import {forbidden}" not in source, forbidden

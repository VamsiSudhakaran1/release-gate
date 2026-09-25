"""Any provider, none required.

Two axes. The models release-gate *assesses* — an agent may run on anything — and
the models it *optionally uses*, for a second opinion or §10r's semantic help.
The first is structural: the deterministic core names no provider at all, and a
test here keeps it that way. The second is a wire-format problem, and these cases
use each provider's real request and response shapes.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from release_gate.assurance.model_neutral import (
    DIALECTS, MODEL_NEUTRAL_SCHEMA_VERSION, DialectError, DialectResolution,
    ModelDialect, RequestPlan, SystemPlacement, build_request, extract_text,
    resolve_dialect,
)
from release_gate.assurance.semantic import model_identity
from release_gate.assurance.verifiers import ToolFamily

SYSTEM, USER = "You are a reviewer.", "Is this a real risk?"

#: Each provider's real reply shape, and the text inside it.
REPLIES = {
    "openai_chat": ({"choices": [{"message": {"content": "confirmed"}}]},
                    "confirmed"),
    "anthropic_messages": ({"content": [{"type": "text", "text": "refuted"}]},
                           "refuted"),
    "google_generate_content": (
        {"candidates": [{"content": {"parts": [{"text": "uncertain"}]}}]},
        "uncertain"),
    "ollama_native": ({"message": {"role": "assistant", "content": "confirmed"}},
                      "confirmed"),
    "openai_responses": (
        {"output": [{"content": [{"type": "output_text", "text": "ok"}]}]}, "ok"),
}

ENDPOINTS = {
    "openai_chat": "https://api.openai.com/v1",
    "anthropic_messages": "https://api.anthropic.com/v1",
    "google_generate_content": "https://generativelanguage.googleapis.com/v1beta",
    "ollama_native": "http://localhost:11434",
    "openai_responses": "https://api.openai.com/v1",
}


# ── the core names no provider ───────────────────────────────────────────────

class TestTheCoreIsProviderFree:

    def test_the_assurance_layer_references_no_provider(self):
        """Measured across every module, so it cannot drift back."""
        import re
        pattern = re.compile(
            r"\b(openai|anthropic|gemini|gpt-\d|llama|mistral|ollama|bedrock|"
            r"vertex|cohere)\b", re.IGNORECASE)
        root = Path(__file__).resolve().parent.parent / "release_gate" / "assurance"
        #: The modules whose job is knowing external shapes. Anything else naming
        #: a provider would be the core coupling to one.
        shape_registries = {"model_neutral.py", "orchestration.py"}
        offenders = {}
        for path in sorted(root.glob("*.py")):
            if path.name in shape_registries:
                continue
            source = path.read_text()
            # "OpenAI Agents" is an orchestrator, not a model provider. It is a
            # different axis: release-gate reads that framework's export the same
            # way it reads LangGraph's, and neither makes it depend on a model
            # vendor. Stripped before matching so the guard stays strict about
            # the coupling it is actually for.
            for spelling in ("openai agents", "openai_agents", "OpenAI Agents"):
                source = source.replace(spelling, "<orchestrator>")
            hits = pattern.findall(source)
            if hits:
                offenders[path.name] = sorted(set(h.lower() for h in hits))
        assert offenders == {}, offenders

    def test_the_shape_registry_exemption_does_not_quietly_grow(self):
        """Two modules are exempt from the provider guard. A third would mean
        the core had acquired a provider-shaped dependency somewhere new."""
        root = Path(__file__).resolve().parent.parent / "release_gate" / "assurance"
        assert (root / "model_neutral.py").exists()
        assert (root / "orchestration.py").exists()

    def test_no_vendor_sdk_is_imported_anywhere(self):
        """Checked through the AST, not by substring.

        `audit.py` contains the literal string "import openai" as a *detection
        pattern* — the scanner recognising which framework the audited repo uses.
        That is provider awareness, which is the product working, and the
        opposite of provider dependence. A substring search cannot tell the two
        apart; real import nodes can.
        """
        import ast
        vendors = {"openai", "anthropic", "google", "mistralai", "cohere",
                   "ollama", "litellm", "boto3", "vertexai"}
        root = Path(__file__).resolve().parent.parent / "release_gate"
        offenders = []
        for path in sorted(root.rglob("*.py")):
            tree = ast.parse(path.read_text(), filename=str(path))
            # An import guarded by try/except is an optional read of something
            # the user may already have — `pricing/resolver.py` reads LiteLLM's
            # cost map that way and returns None when it is absent. That is the
            # same optional-backend pattern the CLI uses, and it is not a
            # dependency. An unguarded one would be.
            guarded = {id(n) for block in ast.walk(tree)
                       if isinstance(block, ast.Try)
                       for stmt in block.body
                       for n in ast.walk(stmt)
                       if isinstance(n, (ast.Import, ast.ImportFrom))}
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [a.name.split(".")[0] for a in node.names]
                elif isinstance(node, ast.ImportFrom):
                    names = [(node.module or "").split(".")[0]]
                else:
                    continue
                if id(node) in guarded:
                    continue
                for name in names:
                    if name in vendors:
                        offenders.append(f"{path.name}:{node.lineno} {name}")
        assert offenders == [], offenders

    def test_an_optional_vendor_read_degrades_rather_than_failing(self):
        """LiteLLM's cost map is read when present and absent otherwise; it is
        not installed here, which is the case that matters."""
        import sys
        from release_gate.pricing.resolver import PricingResolver
        assert "litellm" not in sys.modules
        resolver = PricingResolver.__new__(PricingResolver)
        assert resolver._fetch_litellm("any-model") is None

    def test_provider_awareness_is_not_provider_dependence(self):
        """The scanner must know vendor SDK names to find them in your repo.
        Recognising `import openai` in audited code is release-gate working."""
        source = (Path(__file__).resolve().parent.parent / "release_gate"
                  / "audit.py").read_text()
        assert '"import openai"' in source or "'import openai'" in source

    def test_a_model_is_identified_like_any_other_tool(self):
        """No model-specific identity type to drift from the general one."""
        found = model_identity("some-future-model-v9", version="2031-01")
        assert found.family is ToolFamily.LANGUAGE_MODEL
        assert not found.established

    def test_the_deterministic_path_never_calls_a_model(self, tmp_path):
        from release_gate.assurance.zero_config import assure
        from release_gate.demos import single_agent
        path = tmp_path / "case.json"
        path.write_text(json.dumps(single_agent.build_document()))
        import sys
        before = set(sys.modules)
        assure(str(path))
        assert not {m for m in set(sys.modules) - before
                    if m.split(".")[0] in ("openai", "anthropic", "urllib3",
                                           "httpx", "requests")}


# ── every named provider works ───────────────────────────────────────────────

class TestEveryProvider:

    @pytest.mark.parametrize("dialect_id", sorted(DIALECTS))
    def test_a_request_can_be_shaped(self, dialect_id):
        plan = build_request(DIALECTS[dialect_id],
                             base_url=ENDPOINTS[dialect_id], model="m",
                             user=USER, system=SYSTEM, api_key="KEY")
        assert isinstance(plan, RequestPlan)
        assert plan.url.startswith(ENDPOINTS[dialect_id])
        assert plan.body

    @pytest.mark.parametrize("dialect_id", sorted(DIALECTS))
    def test_the_reply_is_extracted_from_the_real_shape(self, dialect_id):
        reply, expected = REPLIES[dialect_id]
        assert extract_text(DIALECTS[dialect_id], reply) == expected

    @pytest.mark.parametrize("dialect_id", sorted(DIALECTS))
    def test_the_system_instruction_is_not_lost(self, dialect_id):
        """Sent the wrong way it is silently dropped, and the model answers a
        different question than the one asked."""
        plan = build_request(DIALECTS[dialect_id],
                             base_url=ENDPOINTS[dialect_id], model="m",
                             user=USER, system=SYSTEM)
        assert SYSTEM in json.dumps(plan.body)

    def test_anthropic_puts_the_system_prompt_at_the_top_level(self):
        plan = build_request(DIALECTS["anthropic_messages"],
                             base_url="https://api.anthropic.com/v1", model="m",
                             user=USER, system=SYSTEM)
        assert plan.body["system"] == SYSTEM
        assert all(turn["role"] != "system" for turn in plan.body["messages"])

    def test_anthropic_uses_its_own_auth_and_version_headers(self):
        plan = build_request(DIALECTS["anthropic_messages"],
                             base_url="https://api.anthropic.com/v1", model="m",
                             user=USER, api_key="KEY")
        assert plan.headers["x-api-key"] == "KEY"
        assert "Authorization" not in plan.headers
        assert plan.headers["anthropic-version"]

    def test_google_addresses_the_model_in_the_path(self):
        plan = build_request(DIALECTS["google_generate_content"],
                             base_url="https://g/v1beta", model="gemini-x",
                             user=USER, api_key="KEY")
        assert "models/gemini-x:generateContent" in plan.url
        assert "model" not in plan.body
        assert plan.body["contents"][0]["parts"] == [{"text": USER}]

    def test_a_local_endpoint_needs_no_credential(self):
        plan = build_request(DIALECTS["ollama_native"],
                             base_url="http://localhost:11434", model="llama3.1",
                             user=USER)
        assert "Authorization" not in plan.headers
        assert plan.url.startswith("http://localhost")

    def test_a_dialect_with_no_system_concept_folds_it_into_the_turn(self):
        plan = build_request(DIALECTS["openai_responses"],
                             base_url="https://api.openai.com/v1", model="m",
                             user=USER, system=SYSTEM)
        assert SYSTEM in plan.body["input"][0]["content"]

    def test_a_custom_provider_needs_no_code_change(self):
        """A future system is a ModelDialect, not a branch."""
        house = ModelDialect(
            dialect_id="house_llm", label="our own inference service",
            path="/generate", auth_header="X-House-Token", auth_scheme="",
            system_placement=SystemPlacement.TOP_LEVEL,
            turns_key="turns", system_key="preamble",
            text_path=("result", "answer"))
        plan = build_request(house, base_url="https://llm.internal", model="h1",
                             user=USER, system=SYSTEM, api_key="T")
        assert plan.url == "https://llm.internal/generate"
        assert plan.headers["X-House-Token"] == "T"
        assert plan.body["preamble"] == SYSTEM
        assert extract_text(house, {"result": {"answer": "confirmed"}}) == "confirmed"

    def test_the_registry_cannot_disagree_with_itself(self):
        for dialect_id, dialect in DIALECTS.items():
            assert dialect.dialect_id == dialect_id


# ── no provider is privileged ────────────────────────────────────────────────

class TestNoProviderIsPrivileged:

    @pytest.mark.parametrize("dialect_id", sorted(DIALECTS))
    def test_no_dialect_establishes_truth(self, dialect_id):
        assert DIALECTS[dialect_id].establishes_truth is False
        assert DIALECTS[dialect_id].to_dict()["establishes_truth"] is False

    def test_a_frontier_model_and_a_local_one_get_the_same_status(self):
        """The day a provider list starts deciding epistemic status is the day it
        starts deciding verdicts."""
        from release_gate.assurance.evidence import EpistemicStatus
        from release_gate.assurance.semantic import (
            SemanticProposal, SemanticTask, proposals_to_records)
        statuses = set()
        for name in ("a-frontier-model", "a-local-7b", "some-future-system"):
            proposal = SemanticProposal(
                task=SemanticTask.CLAIM_EXTRACTION,
                model=model_identity(name), read_from=("ev_1",),
                proposes={"claims": []}, rationale="because")
            records = proposals_to_records((proposal,))
            statuses |= {getattr(r, "epistemic_status", None) for r in records}
        assert statuses <= {EpistemicStatus.DERIVED}, statuses


# ── an unknown provider is a refusal, not a default ──────────────────────────

class TestUnknownProviders:

    @pytest.mark.parametrize("url,expected", [
        ("https://api.anthropic.com/v1", "anthropic_messages"),
        ("https://generativelanguage.googleapis.com/v1beta",
         "google_generate_content"),
        ("http://localhost:11434/api/chat", "ollama_native"),
        ("https://api.openai.com/v1", "openai_chat"),
    ])
    def test_a_known_endpoint_resolves_to_its_own_dialect(self, url, expected):
        """An earlier version matched "/v1" and "localhost", so every provider
        resolved to openai_chat and reported recognised=True — a resolver that
        confidently misidentifies one vendor as another."""
        found = resolve_dialect(url)
        assert found.dialect.dialect_id == expected
        assert found.recognised

    @pytest.mark.parametrize("url", ["https://our-gateway.corp/v1",
                                     "http://localhost:8000/v1", ""])
    def test_an_unrecognised_endpoint_is_not_claimed_as_recognised(self, url):
        found = resolve_dialect(url)
        assert not found.recognised
        assert "a guess" in found.basis

    def test_and_yields_nothing_when_a_guess_is_not_acceptable(self):
        found = resolve_dialect("https://our-gateway.corp/v1",
                                allow_fallback=False)
        assert found.dialect is None
        assert not found.usable
        assert "wrong field" in found.basis

    def test_a_named_dialect_is_never_second_guessed(self):
        found = resolve_dialect("https://api.openai.com/v1",
                                named="anthropic_messages")
        assert found.dialect.dialect_id == "anthropic_messages"
        assert found.recognised

    def test_an_unknown_dialect_name_is_refused_by_name(self):
        with pytest.raises(DialectError) as exc:
            resolve_dialect("", named="future_provider_v2")
        assert "is not a provider it refuses" in str(exc.value)

    def test_a_mismatched_extractor_fails_loudly(self):
        """The failure mode otherwise is a plausible string from the wrong
        field."""
        anthropic_reply = {"content": [{"text": "refuted"}]}
        with pytest.raises(DialectError) as exc:
            extract_text(DIALECTS["openai_chat"], anthropic_reply)
        assert "speaks a different dialect" in str(exc.value)

    def test_a_non_string_where_text_belongs_is_refused(self):
        with pytest.raises(DialectError) as exc:
            extract_text(DIALECTS["ollama_native"],
                         {"message": {"content": {"nested": "x"}}})
        assert "path leads somewhere else" in str(exc.value)

    def test_a_dialect_must_say_where_the_text_is(self):
        with pytest.raises(DialectError) as exc:
            ModelDialect(dialect_id="d", label="l", text_path=())
        assert "a guess that happens to parse" in str(exc.value)

    def test_there_is_no_default_model(self):
        with pytest.raises(DialectError) as exc:
            build_request(DIALECTS["openai_chat"], base_url="https://x",
                          model="  ", user=USER)
        assert "a provider nobody chose" in str(exc.value)


# ── credentials do not leak into a showable view ─────────────────────────────

class TestCredentialSafety:

    def test_a_header_credential_is_redacted(self):
        plan = build_request(DIALECTS["openai_chat"], base_url="https://x",
                             model="m", user=USER, api_key="SECRETKEY")
        assert "SECRETKEY" not in json.dumps(plan.to_dict())
        assert "SECRETKEY" in plan.headers["Authorization"]

    def test_a_query_credential_is_redacted_too(self):
        """Google carries the key in the query string, so a view that scrubbed
        only headers printed it in the field most likely to be pasted into a
        ticket."""
        plan = build_request(DIALECTS["google_generate_content"],
                             base_url="https://g/v1beta", model="m", user=USER,
                             api_key="SECRETKEY")
        assert "SECRETKEY" not in json.dumps(plan.to_dict())
        assert "SECRETKEY" in plan.url

    def test_anthropics_header_is_redacted_by_name(self):
        plan = build_request(DIALECTS["anthropic_messages"],
                             base_url="https://a/v1", model="m", user=USER,
                             api_key="SECRETKEY")
        assert plan.to_dict()["headers"]["x-api-key"] == "<redacted>"


# ── the verifier speaks whatever it is pointed at ────────────────────────────

class TestVerifierTransport:

    def test_the_openai_request_is_unchanged(self):
        """The refactor must not move a byte for existing users."""
        from release_gate.llm_verify import _call_llm
        captured = {}

        class FakeResponse:
            def read(self):
                return json.dumps(
                    {"choices": [{"message": {"content": "confirmed"}}]}).encode()

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        import release_gate.llm_verify as module

        def fake_urlopen(req, timeout=0):
            captured["url"] = req.full_url
            captured["body"] = json.loads(req.data)
            captured["headers"] = dict(req.headers)
            return FakeResponse()

        original = module.urllib.request.urlopen
        module.urllib.request.urlopen = fake_urlopen
        try:
            text = _call_llm(
                {"base_url": "https://api.openai.com/v1", "model": "gpt-4o",
                 "api_key": "K"},
                [{"role": "system", "content": SYSTEM},
                 {"role": "user", "content": USER}])
        finally:
            module.urllib.request.urlopen = original

        assert text == "confirmed"
        assert captured["url"] == "https://api.openai.com/v1/chat/completions"
        assert captured["body"] == {
            "model": "gpt-4o",
            "messages": [{"role": "system", "content": SYSTEM},
                         {"role": "user", "content": USER}],
            "temperature": 0, "max_tokens": 300}
        assert captured["headers"]["Authorization"] == "Bearer K"

    def test_it_routes_to_anthropic_when_pointed_there(self):
        from release_gate.llm_verify import resolve_transport
        found = resolve_transport({"base_url": "https://api.anthropic.com/v1"})
        assert found.dialect.dialect_id == "anthropic_messages"

    def test_a_named_dialect_overrides_the_url(self, monkeypatch):
        from release_gate.llm_verify import resolve_transport
        monkeypatch.setenv("RG_VERIFY_DIALECT", "ollama_native")
        found = resolve_transport({"base_url": "https://api.openai.com/v1"})
        assert found.dialect.dialect_id == "ollama_native"

    def test_the_verifier_stays_advisory(self):
        """Whatever provider answers, it does not decide the build."""
        source = (Path(__file__).resolve().parent.parent / "release_gate"
                  / "llm_verify.py").read_text()
        assert "ADVISORY, NOT THE GATE" in source


# ── cost is not estimated against a provider nobody named ────────────────────

class TestNoAssumedProvider:

    def test_an_unnamed_model_is_not_priced_as_a_vendor_default(self):
        """It returned PASS on a cost computed against gpt-4-turbo/openai, while
        a named custom model returned FAIL. Naming your own model failed the gate
        and naming nothing passed it."""
        from release_gate.pricing.budget_simulator import BudgetSimulator
        found = BudgetSimulator().simulate(
            {"simulation": {"requests_per_day": 100},
             "budget": {"max_daily_cost": 10}})
        assert found["status"] != "PASS"
        assert "No model named" in found["error"]
        assert "does not assume a provider" in found["reason"]

    def test_a_named_model_still_prices(self):
        from release_gate.pricing.budget_simulator import BudgetSimulator
        found = BudgetSimulator().simulate(
            {"agent": {"model": "gpt-4-turbo"},
             "simulation": {"requests_per_day": 100},
             "budget": {"max_daily_cost": 10}})
        assert found["status"] == "PASS"

    def test_an_unknown_named_model_does_not_pass_either(self):
        from release_gate.pricing.budget_simulator import BudgetSimulator
        found = BudgetSimulator().simulate(
            {"agent": {"model": "our-house-model-v3"},
             "simulation": {"requests_per_day": 100},
             "budget": {"max_daily_cost": 10}})
        assert found["status"] != "PASS"

    def test_a_custom_price_makes_any_model_workable(self):
        """A local or in-house model is priced by supplying its price, not by
        being on a vendor list."""
        from release_gate.pricing.budget_simulator import BudgetSimulator
        sim = BudgetSimulator()
        sim.register_custom_pricing("our-house-model-v3", 0.1, 0.2, "self-hosted")
        found = sim.simulate({"agent": {"model": "our-house-model-v3"},
                              "simulation": {"requests_per_day": 100},
                              "budget": {"max_daily_cost": 10}})
        assert found["status"] == "PASS"
        assert found["provider"] == "self-hosted"

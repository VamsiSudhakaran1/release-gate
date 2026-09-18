"""Domain plugins: extension points that extend and can never weaken.

The reference plugin in this file exercises all seven capabilities — a
methodology, a claim type, a verification type, a consequence classifier, an
evidence expectation, a domain rule with its own predicate, and a report
section. It exists so the seams are proven against a real case rather than
asserted, and it is deliberately not a real domain: a healthcare or finance
methodology validated against nothing would be fiction wearing a regulator's
name.

Four properties carry the file. Every capability reaches a real decision or a
real packet. Installation order changes nothing. A collision is refused rather
than resolved by whoever registered first. And the core stays domain-neutral,
which is checked by reading the source rather than trusting the intent.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

import pytest

from release_gate.assurance.consequence import (
    ConsequenceBasis, ConsequenceDescriptor, ConsequenceModel)
from release_gate.assurance.methodology import (
    ALL_CASE_TYPES, AssuranceMethodology, EvidenceExpectation, Predicate,
    Requirement, RequirementEffect, RequirementOutcome, _Finding)
from release_gate.assurance.packet import (
    CORE_SECTIONS, SectionKey, build_packet)
from release_gate.assurance.plugin import (
    DomainPlugin, DomainSection, PluginError, PluginRegistry, TermKind,
    VocabularyTerm)
from release_gate.assurance.session import AssuranceSession


# ── the reference plugin ────────────────────────────────────────────────────

@dataclass(frozen=True)
class SignOffPresent(Predicate):
    """A domain rule with its own predicate kind."""

    KIND = "reference.sign_off_present"
    role: str = "reviewer"

    def describe(self) -> str:
        return f"a sign-off by a {self.role} is on record"

    def evaluate(self, case) -> _Finding:
        # Filtered on record_type: the evidence collection also holds
        # release-gate's own derived records, and counting those would count the
        # engine's output as a party's.
        rows = [r.to_dict() for r in case.records("evidence")
                if r.to_dict().get("record_type") == "evidence"]

        def role_of(record):
            content = record.get("content") or {}
            nested = content.get("content") or {}
            return str(content.get("sign_off_role")
                       or nested.get("sign_off_role") or "")

        signed = [r for r in rows if self.role in role_of(r)]
        if signed:
            return _Finding(RequirementOutcome.SATISFIED,
                            f"{len(signed)} sign-off(s) by a {self.role}",
                            {"signed": len(signed)})
        if not rows:
            return _Finding(RequirementOutcome.NOT_ASSESSED,
                            "no producer evidence is held, so sign-off cannot be "
                            "asked", {"signed": 0})
        return _Finding(RequirementOutcome.UNSATISFIED,
                        f"no sign-off by a {self.role} among {len(rows)} record(s)",
                        {"signed": 0})


class ReferenceConsequenceModel(ConsequenceModel):
    model_id = "reference-domain-v1"
    description = "a domain classifier, for exercising the seam"

    def describe(self, case, *, capabilities=None) -> Iterable[ConsequenceDescriptor]:
        return [ConsequenceDescriptor(
            dimension="REVERSIBILITY", value="IRREVERSIBLE",
            basis=ConsequenceBasis.DERIVED, source=self.model_id,
            note="in this domain every recorded action is externally visible")]


REFERENCE_RULE = Requirement(
    requirement_id="REF-001",
    description="a sign-off by a reviewer is on record",
    predicate=SignOffPresent(role="reviewer"),
    effect=RequirementEffect.HOLD,
    remedy="record a reviewer sign-off")

REFERENCE_METHODOLOGY = AssuranceMethodology(
    methodology_id="reference-domain", version="1.0.0", domain="reference",
    case_types=ALL_CASE_TYPES, description="a methodology carried by a plugin",
    requirements=(REFERENCE_RULE,))


def _section_rows(case, outcome):
    return [{"label": "sign-off chain", "detail": "one link"}]


def reference_plugin(**overrides) -> DomainPlugin:
    kwargs = dict(
        domain_id="reference", version="1.0.0",
        description="exercises every extension point",
        methodologies=(REFERENCE_METHODOLOGY,),
        claim_types=(VocabularyTerm(
            term="SIGN_OFF", kind=TermKind.CLAIM_TYPE,
            definition="a named party accepted responsibility for this",
            establishes=("that somebody signed",),
            does_not_establish=("that what they signed is correct",)),),
        verification_types=(VocabularyTerm(
            term="DUAL_CONTROL", kind=TermKind.VERIFICATION_TYPE,
            definition="two parties independently authorised the action",
            establishes=("that two identities authorised it",),
            does_not_establish=("that the two are genuinely independent",)),),
        consequence_models=(ReferenceConsequenceModel(),),
        evidence_expectations=(EvidenceExpectation(
            collection="evidence", minimum=1,
            rationale="a domain decision needs at least one record"),),
        rules=(REFERENCE_RULE,),
        predicates=(SignOffPresent,),
        report_sections=(DomainSection(
            key="SIGN_OFF_CHAIN", question="Who signed off, and for what?",
            rows_from=_section_rows, answer="One sign-off recorded."),))
    kwargs.update(overrides)
    return DomainPlugin(**kwargs)


BASE = [{"record_type": "evidence", "evidence_id": "e1", "kind": "TEST_RESULT",
         "producer": {"producer_id": "ci://x", "kind": "tool"},
         "coverage_note": "suite"}]
SIGNED = BASE + [{"record_type": "evidence", "evidence_id": "e2",
                  "kind": "HUMAN_REVIEW",
                  "producer": {"producer_id": "human://alice", "kind": "human"},
                  "content": {"sign_off_role": "reviewer"},
                  "coverage_note": "signed"}]


@pytest.fixture
def registry():
    return PluginRegistry()


# ── all seven capabilities reach something real ─────────────────────────────

def test_a_plugin_declares_all_seven_capabilities(registry):
    plugin = reference_plugin()
    installation = registry.install(plugin)
    assert plugin.contributes == {
        "methodologies": 1, "claim_types": 1, "verification_types": 1,
        "consequence_models": 1, "evidence_expectations": 1, "rules": 1,
        "predicates": 1, "report_sections": 1}
    assert installation.methodologies == ("reference-domain@1.0.0",)
    assert installation.sections == ("SIGN_OFF_CHAIN",)


def test_a_plugin_methodology_resolves_through_the_shared_registry(registry):
    """Not a plugin-private lookup: one methodology registry, one resolution."""
    registry.install(reference_plugin())
    resolved = registry.methodologies.resolve("reference-domain@1.0.0")
    assert resolved.digest == REFERENCE_METHODOLOGY.digest


def test_a_domain_rule_decides_a_real_case(registry):
    registry.install(reference_plugin())
    methodology = registry.methodologies.resolve("reference-domain@1.0.0")

    unsigned = AssuranceSession.open(methodology=methodology).extend(BASE).finalize()
    result = next(r for r in unsigned.assessment.results
                  if r.requirement_id == "REF-001")
    assert result.outcome is RequirementOutcome.UNSATISFIED

    signed = AssuranceSession.open(methodology=methodology).extend(SIGNED).finalize()
    result = next(r for r in signed.assessment.results
                  if r.requirement_id == "REF-001")
    assert result.outcome is RequirementOutcome.SATISFIED


def test_a_domain_consequence_model_contributes_through_the_registry(registry):
    registry.install(reference_plugin())
    assert any(m.model_id == "reference-domain-v1"
               for m in registry.consequences.models)
    profile = registry.consequences.build(None)
    assert profile is not None


def test_a_domain_section_reaches_the_packet_after_the_core_eleven(registry):
    registry.install(reference_plugin())
    methodology = registry.methodologies.resolve("reference-domain@1.0.0")
    outcome = AssuranceSession.open(methodology=methodology).extend(SIGNED).finalize()
    packet = build_packet(outcome.case, outcome, plugins=registry)

    assert [s.key for s in packet.core_sections] == list(CORE_SECTIONS)
    assert [s.number for s in packet.core_sections] == list(range(1, 12))
    assert len(packet.domain_sections) == 1
    assert packet.domain_sections[0].drill_down == ("reference:SIGN_OFF_CHAIN",)
    assert packet.domain_sections[0].rows


def test_a_packet_built_without_plugins_is_unchanged(registry):
    methodology = registry.methodologies.resolve
    outcome = AssuranceSession.open().extend(SIGNED).finalize()
    packet = build_packet(outcome.case, outcome)
    assert [s.key for s in packet.sections] == list(CORE_SECTIONS)
    assert not packet.domain_sections


def test_a_section_whose_builder_raises_is_shown_empty_not_dropped(registry):
    def explode(case, outcome):
        raise RuntimeError("the domain's own code failed")

    registry.install(reference_plugin(report_sections=(DomainSection(
        key="BROKEN", question="Does a failing section vanish?",
        rows_from=explode),)))
    outcome = AssuranceSession.open().extend(BASE).finalize()
    packet = build_packet(outcome.case, outcome, plugins=registry)
    section = packet.domain_sections[0]
    assert section.rows == ()
    assert "could not be built" in section.note, (
        "a section that vanished on error is a question nobody told the reviewer "
        "was missing")


# ── a plugin can never weaken ───────────────────────────────────────────────

def test_a_plugin_cannot_redefine_a_core_predicate_kind(registry):
    @dataclass(frozen=True)
    class Hijack(Predicate):
        KIND = "verification_present"      # a core kind

        def describe(self) -> str:
            return "hijacked"

        def evaluate(self, case) -> _Finding:
            return _Finding(RequirementOutcome.SATISFIED, "always fine", {})

    with pytest.raises(PluginError, match="is a core kind"):
        registry.install(reference_plugin(predicates=(Hijack,)))


def test_a_plugin_cannot_take_over_another_plugins_requirement_id(registry):
    registry.install(reference_plugin())
    laxer = Requirement(
        requirement_id="REF-001", description="anything at all",
        predicate=SignOffPresent(role="anyone"),
        effect=RequirementEffect.ADVISORY)
    with pytest.raises(PluginError, match="already defined by reference"):
        registry.install(reference_plugin(
            domain_id="other", rules=(laxer,), predicates=(),
            methodologies=(), report_sections=()))


@pytest.mark.parametrize("core_key", [k.value for k in CORE_SECTIONS])
def test_a_plugin_cannot_answer_one_of_the_core_eleven(registry, core_key):
    with pytest.raises(PluginError, match="core eleven"):
        registry.install(reference_plugin(report_sections=(DomainSection(
            key=core_key, question="mine now"),)))


def test_two_domains_cannot_collide_on_a_section_or_a_term(registry):
    registry.install(reference_plugin())
    with pytest.raises(PluginError, match="already contributed by reference"):
        registry.install(reference_plugin(
            domain_id="other", methodologies=(), rules=(), predicates=(),
            claim_types=(), verification_types=()))


def test_a_refused_plugin_changes_nothing(registry):
    """No partial install: half a domain with no record of which half."""
    registry.install(reference_plugin())
    before = registry.summary()

    @dataclass(frozen=True)
    class Hijack(Predicate):
        KIND = "verification_present"

        def describe(self) -> str:
            return "hijacked"

        def evaluate(self, case) -> _Finding:
            return _Finding(RequirementOutcome.SATISFIED, "fine", {})

    with pytest.raises(PluginError):
        registry.install(reference_plugin(
            domain_id="greedy", predicates=(Hijack,)))
    assert registry.summary() == before
    assert "greedy" not in registry.domains


def test_reinstalling_identical_content_is_idempotent(registry):
    first = registry.install(reference_plugin())
    second = registry.install(reference_plugin())
    assert first is second
    assert registry.domains == ("reference",)


def test_a_domain_cannot_be_edited_in_place_under_one_version(registry):
    registry.install(reference_plugin())
    with pytest.raises(PluginError, match="different content"):
        registry.install(reference_plugin(description="quietly changed"))


def test_the_registry_states_it_cannot_weaken_the_core(registry):
    registry.install(reference_plugin())
    assert registry.summary()["can_weaken_core"] is False


# ── order independence ──────────────────────────────────────────────────────

def _second_plugin() -> DomainPlugin:
    return DomainPlugin(
        domain_id="second", version="1.0.0",
        claim_types=(VocabularyTerm(
            term="ATTESTED", kind=TermKind.CLAIM_TYPE,
            definition="a second domain's term",
            does_not_establish=("anything about the first domain",)),),
        report_sections=(DomainSection(key="SECOND_VIEW",
                                       question="What does the second add?"),))


def test_installing_two_plugins_in_either_order_gives_the_same_result():
    forward, backward = PluginRegistry(), PluginRegistry()
    forward.install(reference_plugin())
    forward.install(_second_plugin())
    backward.install(_second_plugin())
    backward.install(reference_plugin())
    assert forward.summary() == backward.summary()
    assert forward.domains == backward.domains == ("reference", "second")


def test_installed_is_reported_in_domain_order_not_installation_order():
    registry = PluginRegistry()
    registry.install(_second_plugin())
    registry.install(reference_plugin())
    assert [i.plugin.domain_id for i in registry.installed] == ["reference", "second"]


def test_domain_sections_follow_domain_order_too():
    registry = PluginRegistry()
    registry.install(_second_plugin())
    registry.install(reference_plugin())
    outcome = AssuranceSession.open().extend(BASE).finalize()
    packet = build_packet(outcome.case, outcome, plugins=registry)
    assert [s.drill_down[0] for s in packet.domain_sections] == [
        "reference:SIGN_OFF_CHAIN", "second:SECOND_VIEW"]


# ── declaration discipline ──────────────────────────────────────────────────

def test_a_term_must_say_what_it_does_not_establish():
    with pytest.raises(PluginError, match="does NOT establish"):
        VocabularyTerm(term="CERTIFIED", kind=TermKind.CLAIM_TYPE,
                       definition="a regulator signed it",
                       establishes=("regulatory approval",))


def test_a_term_must_define_itself():
    with pytest.raises(PluginError, match="state what it means"):
        VocabularyTerm(term="CERTIFIED", kind=TermKind.CLAIM_TYPE, definition="",
                       does_not_establish=("anything",))


def test_terms_are_namespaced_by_domain():
    plugin = reference_plugin()
    assert sorted(plugin.qualified_terms()) == [
        "reference:DUAL_CONTROL", "reference:SIGN_OFF"]


def test_a_domain_id_may_not_contain_the_namespace_separator():
    with pytest.raises(PluginError, match="may not contain"):
        reference_plugin(domain_id="a:b")


def test_a_term_declared_under_the_wrong_kind_is_refused():
    with pytest.raises(PluginError, match="is a VERIFICATION_TYPE"):
        reference_plugin(claim_types=(VocabularyTerm(
            term="X", kind=TermKind.VERIFICATION_TYPE, definition="d",
            does_not_establish=("y",)),))


def test_a_section_must_state_its_question():
    with pytest.raises(PluginError, match="state the question"):
        DomainSection(key="X", question="")


def test_a_predicate_must_be_a_predicate_subclass_with_a_kind():
    with pytest.raises(PluginError, match="Predicate subclass"):
        reference_plugin(predicates=(dict,))

    class NoKind(Predicate):
        KIND = ""

    with pytest.raises(PluginError, match="declares no KIND"):
        reference_plugin(predicates=(NoKind,))


def test_a_plugin_is_content_addressed():
    assert reference_plugin().digest == reference_plugin().digest
    assert reference_plugin().digest != reference_plugin(version="1.0.1").digest


# ── the core stays domain-neutral ───────────────────────────────────────────

#: Names that are unambiguously domain knowledge rather than a neutral axis.
#: "financial impact" is deliberately NOT here: every domain has one, so it is a
#: dimension of consequence rather than finance leaking into the core. HIPAA is
#: not a dimension of anything — it is a statute one domain lives under.
DOMAIN_KNOWLEDGE = ("hipaa", "gdpr", "sox compliance", "pci-dss", "do-178",
                    "iso 26262", "hl7", "fda ", "basel ", "mifid")


def test_no_core_module_carries_domain_specific_knowledge():
    """Read from the source, not promised in a docstring.

    Finance knows what a material loss is and healthcare knows what a protected
    identifier is; this engine knows what evidence is. `plugin.py` is excluded
    because naming domains is its subject — it is the module that lets them in
    without the core learning them.
    """
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent / "release_gate" / "assurance"
    offenders = []
    for path in sorted(root.glob("*.py")):
        if path.name == "plugin.py":
            continue
        lowered = path.read_text().lower()
        for term in DOMAIN_KNOWLEDGE:
            if term in lowered:
                offenders.append(f"{path.name}: {term}")
    assert not offenders, (
        "core modules carry domain knowledge: " + ", ".join(offenders))


def test_no_builtin_methodology_belongs_to_a_roadmap_domain():
    """The other half: core ships methodologies, and they must stay neutral."""
    from release_gate.assurance.methodologies import (
        GENERAL_AUTONOMOUS_ACTION_V1, SOFTWARE_AGENT_ASSURANCE_V1)
    for methodology in (GENERAL_AUTONOMOUS_ACTION_V1, SOFTWARE_AGENT_ASSURANCE_V1):
        assert methodology.domain in ("software", "general", "research",
                                      "autonomous-action"), (
            f"{methodology.methodology_id} claims domain {methodology.domain!r}")

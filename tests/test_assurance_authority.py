"""Authorize what, exactly — and the two questions the six domains had in common.

The brief named research, finance, healthcare, infrastructure, cybersecurity and
aerospace. None of them appears in this package, and `TestNoDomainInTheCore`
asserts that rather than trusting it. What appears is the structure they share:
whether an approval completes the authorization or hands the question on, and who
has standing to give it.

Two tests carry most of the weight. `TestReferDoesNotComplete` guards the
healthcare case, where treating the approval as the whole authorization would have
release-gate claiming clinical authority in a hospital's record.
`TestWithholdingIsTheOtherDirection` guards the cybersecurity one, where HOLD —
safe everywhere else in this engine — is the harmful answer.
"""

from __future__ import annotations

import pytest

from release_gate.assurance.authority import (
    ActClass, ActRegistry, AuthorityBasis, AuthorityClaim, AuthorityError,
    AuthorityFinding, AuthorityReading, DomainAct, WithholdingCost,
    empty_act_registry, read_authority,
)
from release_gate.assurance.expectation import CoverageLedger, CoverageState


def act(**kwargs) -> DomainAct:
    base = dict(act_id="finance.execute_payment", act_class=ActClass.PERFORM,
                description="move money out of the organisation",
                required_authority=("payments_approver",),
                withholding=WithholdingCost.DELAY_ONLY, declared_by="treasury")
    base.update(kwargs)
    return DomainAct(**base)


def claim(**kwargs) -> AuthorityClaim:
    base = dict(authority="payments_approver", held_by="a-nakamura",
                basis=AuthorityBasis.ATTRIBUTED, attributed_by="corporate SSO")
    base.update(kwargs)
    return AuthorityClaim(**base)


#: The brief's six domains, built the way a plugin author would build them. Here
#: rather than in the package, which is the point of the whole section.
def brief_acts() -> tuple:
    return (
        DomainAct(act_id="research.publish_claim", act_class=ActClass.PUBLISH,
                  description="publish a claim others will rely on",
                  required_authority=("principal_investigator",),
                  withholding=WithholdingCost.DELAY_ONLY,
                  declared_by="research-office"),
        DomainAct(act_id="research.rely_on_claim", act_class=ActClass.RELY,
                  description="depend on this claim in further work",
                  required_authority=("domain_reviewer",),
                  declared_by="research-office"),
        DomainAct(act_id="finance.execute_payment", act_class=ActClass.PERFORM,
                  required_authority=("payments_approver",),
                  withholding=WithholdingCost.DELAY_ONLY, declared_by="treasury"),
        DomainAct(act_id="healthcare.present_recommendation", act_class=ActClass.REFER,
                  description="put a recommendation to the clinician who decides",
                  required_authority=("clinical_safety_officer",),
                  refers_to="the treating clinician",
                  withholding=WithholdingCost.DEGRADES,
                  declared_by="clinical-governance"),
        DomainAct(act_id="infrastructure.apply_production_change",
                  act_class=ActClass.PERFORM, required_authority=("change_manager",),
                  withholding=WithholdingCost.DELAY_ONLY, declared_by="sre"),
        DomainAct(act_id="cybersecurity.execute_containment", act_class=ActClass.PERFORM,
                  description="isolate a compromised host",
                  required_authority=("incident_commander",),
                  withholding=WithholdingCost.HARM_CONTINUES, declared_by="soc"),
        DomainAct(act_id="aerospace.authorize_mission_plan", act_class=ActClass.PERFORM,
                  required_authority=("flight_director", "safety_officer"),
                  withholding=WithholdingCost.DELAY_ONLY,
                  declared_by="mission-assurance"),
    )


# ── the core names no domain ──────────────────────────────────────────────────

class TestNoDomainInTheCore:
    """The core may not hold a domain's acts. Checked structurally, not lexically.

    The first version of this test grepped for domain words and found three hits.
    One was `"socket"` matching `soc` — a substring check reading text rather than
    meaning, which is a mistake this codebase has made enough times to know by
    name. The other two were real and were *not* violations: `Capability.PAYMENT`
    and `ArtifactKind.PAYMENT_BATCH` describe what an agent can do, which is an
    observation release-gate makes, and `capabilities` says so itself — "this is
    evidence, not a verdict... only a methodology can say it was not allowed".

    So `plugin`'s claim that nothing under `assurance/` names a domain was too
    strong, and it has been corrected there. The line that actually matters is that
    the core holds no domain's **rules, thresholds or named acts**, and the
    checkable form of that is whether anything constructs a `DomainAct`.
    """

    def test_nothing_under_assurance_constructs_a_domain_act(self):
        import ast
        import pathlib

        offenders = []
        for path in sorted(pathlib.Path("release_gate/assurance").glob("*.py")):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if (isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Name)
                        and node.func.id == "DomainAct"):
                    offenders.append((path.name, node.lineno))
        assert offenders == [], offenders

    def test_nothing_under_assurance_names_a_required_authority(self):
        """A role name is a domain's word for who may decide, so none is hardcoded."""
        import ast
        import pathlib

        offenders = []
        for path in sorted(pathlib.Path("release_gate/assurance").glob("*.py")):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if not isinstance(node, ast.keyword):
                    continue
                if node.arg == "required_authority":
                    offenders.append((path.name, node.lineno))
        assert offenders == [], offenders

    def test_the_act_registry_ships_empty(self):
        assert len(empty_act_registry()) == 0
        assert not empty_act_registry()
        assert empty_act_registry().domains == ()

    def test_it_says_so_unconditionally(self):
        assert empty_act_registry().ships_domain_acts is False
        registry = ActRegistry()
        registry.register(act())
        assert registry.ships_domain_acts is False

    def test_no_module_level_acts_exist(self):
        import release_gate.assurance.authority as module

        shipped = [name for name, value in vars(module).items()
                   if isinstance(value, (list, tuple, dict))
                   and any(isinstance(v, DomainAct) for v in
                           (value.values() if isinstance(value, dict) else value))]
        assert shipped == []


# ── all six examples ─────────────────────────────────────────────────────────

class TestTheBriefsSixDomains:

    def test_every_example_is_expressible_with_no_core_change(self):
        registry = ActRegistry()
        for one in brief_acts():
            registry.register(one)
        assert registry.domains == ("aerospace", "cybersecurity", "finance",
                                    "healthcare", "infrastructure", "research")
        assert len(registry) == 7

    def test_research_has_two_acts_because_the_brief_named_two(self):
        """'publish or rely on claim' is two acts with different reach."""
        registry = ActRegistry()
        for one in brief_acts():
            registry.register(one)
        research = registry.for_domain("research")
        assert {a.act_class for a in research} == {ActClass.PUBLISH, ActClass.RELY}

    def test_only_healthcare_defers(self):
        deferring = [a.act_id for a in brief_acts() if a.act_class.defers]
        assert deferring == ["healthcare.present_recommendation"]

    def test_only_containment_makes_holding_unsafe(self):
        unsafe = [a.act_id for a in brief_acts()
                  if a.withholding.holding_is_the_safe_default is False]
        assert unsafe == ["cybersecurity.execute_containment"]

    def test_aerospace_can_require_two_authorities(self):
        plan = next(a for a in brief_acts()
                    if a.act_id == "aerospace.authorize_mission_plan")
        reading = read_authority(plan, [])
        assert set(reading.absent) == {"flight_director", "safety_officer"}

    def test_a_domain_declares_its_acts_through_its_plugin(self):
        """One place to look, which is the reason `DomainPlugin` exists at all."""
        from release_gate.assurance.plugin import DomainPlugin

        plugin = DomainPlugin(
            domain_id="cybersecurity", version="1",
            acts=tuple(a for a in brief_acts() if a.domain == "cybersecurity"))
        assert plugin.contributes["acts"] == 1
        assert plugin.digest.startswith("sha256:")

    def test_a_plugin_cannot_declare_another_domains_act(self):
        from release_gate.assurance.plugin import DomainPlugin, PluginError

        with pytest.raises(PluginError, match="another domain's vocabulary"):
            DomainPlugin(domain_id="finance", version="1",
                         acts=(next(a for a in brief_acts()
                                    if a.domain == "healthcare"),))

    def test_a_plugin_cannot_declare_one_act_twice(self):
        from release_gate.assurance.plugin import DomainPlugin, PluginError

        one = next(a for a in brief_acts() if a.domain == "aerospace")
        with pytest.raises(PluginError, match="declared twice"):
            DomainPlugin(domain_id="aerospace", version="1", acts=(one, one))


# ── the act class ────────────────────────────────────────────────────────────

class TestReferDoesNotComplete:
    """The healthcare case, which is the reason `ActClass` exists."""

    def _refer(self) -> DomainAct:
        return next(a for a in brief_acts() if a.act_class.defers)

    def test_a_refer_act_does_not_complete_the_authorization(self):
        assert not self._refer().completes_authorization
        assert not read_authority(self._refer(), []).completes_authorization

    def test_it_names_who_decides_next_in_the_note_a_reviewer_reads(self):
        note = self._refer().authorization_note
        assert "the treating clinician" in note
        assert "and nothing more" in note

    def test_a_refer_act_must_name_the_authority_it_defers_to(self):
        with pytest.raises(AuthorityError, match="must name the authority it defers to"):
            act(act_id="healthcare.present_recommendation", act_class=ActClass.REFER,
                refers_to="")

    def test_an_act_that_completes_may_not_name_a_further_authority(self):
        """Implying a step that is not there is the mirror of the same error."""
        with pytest.raises(AuthorityError, match="implies a step that is not there"):
            act(refers_to="somebody else")

    def test_perform_publish_and_rely_complete_it(self):
        completing = [c for c in ActClass if c.completes_authorization]
        assert set(completing) == {ActClass.PERFORM, ActClass.PUBLISH, ActClass.RELY}

    def test_an_unclassified_act_does_not_read_as_finished(self):
        """Guessing is the one error that matters here."""
        assert not ActClass.OTHER.completes_authorization
        unclassified = act(act_id="x.y", act_class=ActClass.OTHER)
        assert "unclassified" in unclassified.authorization_note

    def test_each_class_describes_itself(self):
        for one in ActClass:
            assert len(one.describe()) > 40


class TestWithholdingIsTheOtherDirection:
    """Every consequence dimension measures acting. This measures not acting."""

    def test_holding_is_unsafe_when_the_harm_continues(self):
        assert WithholdingCost.HARM_CONTINUES.holding_is_the_safe_default is False

    def test_holding_is_safe_when_the_cost_is_only_the_wait(self):
        assert WithholdingCost.NONE.holding_is_the_safe_default is True
        assert WithholdingCost.DELAY_ONLY.holding_is_the_safe_default is True

    def test_unknown_does_not_claim_holding_is_safe(self):
        """Returning True by default is what makes a gate dangerous in an incident."""
        assert WithholdingCost.UNKNOWN.holding_is_the_safe_default is None

    def test_degrades_is_in_between_and_is_not_unknown(self):
        assert WithholdingCost.DEGRADES.holding_is_the_safe_default is None
        assert WithholdingCost.DEGRADES is not WithholdingCost.UNKNOWN

    def test_the_render_does_not_report_degrades_as_unassessed(self):
        """Two reasons for None; sharing a sentence would conflate them."""
        degrades = read_authority(act(withholding=WithholdingCost.DEGRADES),
                                  [claim()]).render()
        unknown = read_authority(act(withholding=WithholdingCost.UNKNOWN),
                                 [claim()]).render()
        assert "not assessed" not in degrades
        assert "gets worse while this is held" in degrades
        assert "not assessed" in unknown

    def test_an_unsafe_default_is_stated_in_those_words(self):
        text = read_authority(act(withholding=WithholdingCost.HARM_CONTINUES),
                              [claim()]).render()
        assert "WITHHOLDING" in text
        assert "HOLD is the dangerous answer" in text

    def test_it_is_not_a_consequence_dimension(self):
        """Adding one would change every case digest and unseat every approval."""
        from release_gate.assurance.consequence import ConsequenceDimension

        names = {d.value for d in ConsequenceDimension}
        assert "WITHHOLDING" not in names
        assert not any("WITHHOLD" in n for n in names)

    def test_adding_a_dimension_would_move_every_profile(self):
        """The measurement behind that decision, not the reasoning about it."""
        from release_gate.assurance.consequence import (
            ConsequenceDimension, ConsequenceProfile)

        serialised = ConsequenceProfile().to_dict()["dimensions"]
        assert set(serialised) == {d.value for d in ConsequenceDimension}

    def test_each_cost_describes_itself(self):
        for cost in WithholdingCost:
            assert len(cost.describe()) > 30


# ── the act ──────────────────────────────────────────────────────────────────

class TestDomainAct:

    def test_an_act_needs_an_id(self):
        with pytest.raises(AuthorityError, match="needs an id"):
            act(act_id="  ")

    def test_an_act_id_must_be_namespaced_under_its_domain(self):
        for bad in ("execute_payment", ".execute_payment", "finance."):
            with pytest.raises(AuthorityError, match="must be namespaced"):
                act(act_id=bad)

    def test_the_domain_is_read_off_the_id(self):
        assert act().domain == "finance"
        assert act(act_id="a.b.c").domain == "a"

    def test_an_act_with_no_required_authority_says_so_rather_than_implying_it(self):
        open_act = act(required_authority=())
        assert not open_act.requires_domain_expertise
        assert read_authority(open_act, []).findings == {}

    def test_it_never_establishes_a_qualification(self):
        assert act().establishes_qualification is False
        assert act(required_authority=("clinical_safety_officer",)
                   ).establishes_qualification is False

    def test_an_act_serialises_its_reach_and_its_refusal(self):
        data = act().to_dict()
        assert data["completes_authorization"] is True
        assert data["establishes_qualification"] is False
        assert data["holding_is_the_safe_default"] is True


class TestAuthorityClaim:

    def test_a_claim_names_the_authority_and_the_holder(self):
        with pytest.raises(AuthorityError, match="must name the authority"):
            claim(authority=" ")
        with pytest.raises(AuthorityError, match="must name who holds it"):
            claim(held_by="")

    def test_a_third_party_basis_must_name_the_third_party(self):
        """An unattributed attribution is a declaration with better wording."""
        for basis in (AuthorityBasis.ATTRIBUTED, AuthorityBasis.VETTED):
            with pytest.raises(AuthorityError, match="must be named"):
                claim(basis=basis, attributed_by="")

    def test_a_declaration_needs_nobody_else(self):
        assert claim(basis=AuthorityBasis.DECLARED, attributed_by="").basis \
            is AuthorityBasis.DECLARED

    def test_no_basis_is_a_verified_qualification(self):
        for basis in AuthorityBasis:
            built = claim(basis=basis,
                          attributed_by="somebody" if basis.rests_on_a_third_party else "")
            assert built.is_a_verified_qualification is False

    def test_vetted_links_to_the_organisations_own_registry(self):
        """§10ar's decision is a basis here; it is still not a licence."""
        assert AuthorityBasis.VETTED.rests_on_a_third_party
        assert "vetting registry" in AuthorityBasis.VETTED.describe()

    def test_each_basis_describes_itself(self):
        for basis in AuthorityBasis:
            assert len(basis.describe()) > 40


# ── the reading ──────────────────────────────────────────────────────────────

class TestReadAuthority:

    def test_a_third_party_claim_reads_as_attributed(self):
        reading = read_authority(act(), [claim()])
        assert reading.findings == {"payments_approver": AuthorityFinding.ATTRIBUTED}
        assert reading.authority_satisfied
        assert reading.claimed_only == ()

    def test_a_self_declaration_is_separated_from_an_attribution(self):
        reading = read_authority(act(), [claim(basis=AuthorityBasis.DECLARED,
                                               attributed_by="")])
        assert reading.findings == {"payments_approver": AuthorityFinding.CLAIMED_ONLY}
        assert reading.claimed_only == ("payments_approver",)
        assert reading.authority_satisfied

    def test_a_missing_authority_is_absent(self):
        reading = read_authority(act(), [])
        assert reading.findings == {"payments_approver": AuthorityFinding.ABSENT}
        assert not reading.authority_satisfied
        assert reading.absent == ("payments_approver",)

    def test_a_not_established_basis_does_not_satisfy_anything(self):
        reading = read_authority(act(), [claim(basis=AuthorityBasis.NOT_ESTABLISHED,
                                               attributed_by="")])
        assert reading.findings == {"payments_approver": AuthorityFinding.ABSENT}

    def test_the_strongest_claim_for_an_authority_is_the_one_reported(self):
        reading = read_authority(act(), [
            claim(basis=AuthorityBasis.DECLARED, attributed_by="", held_by="self"),
            claim()])
        assert reading.findings["payments_approver"] is AuthorityFinding.ATTRIBUTED

    def test_matching_an_authority_ignores_case(self):
        reading = read_authority(act(required_authority=("Payments_Approver",)),
                                 [claim()])
        assert reading.findings["Payments_Approver"] is AuthorityFinding.ATTRIBUTED

    def test_an_irrelevant_claim_is_kept_rather_than_dropped(self):
        """Somebody thought it mattered; losing it loses the only trace of that."""
        extra = claim(authority="fire_marshal", held_by="someone")
        reading = read_authority(act(), [claim(), extra])
        assert extra in reading.claims
        assert "fire_marshal" not in reading.findings

    def test_an_act_requiring_nothing_is_satisfied_vacuously_and_says_so(self):
        reading = read_authority(act(required_authority=()), [])
        assert reading.authority_satisfied
        assert "requires no named authority" in reading.render()

    def test_only_not_required_attributed_and_claimed_only_satisfy(self):
        satisfying = [f for f in AuthorityFinding if f.satisfied]
        assert set(satisfying) == {AuthorityFinding.NOT_REQUIRED,
                                  AuthorityFinding.ATTRIBUTED,
                                  AuthorityFinding.CLAIMED_ONLY}

    def test_a_reading_verifies_no_credentials(self):
        assert read_authority(act(), [claim()]).verifies_credentials is False
        assert read_authority(act(), []).verifies_credentials is False

    def test_the_render_names_the_refusal(self):
        text = read_authority(act(), [claim()]).render()
        assert "No basis here verifies a qualification" in text

    def test_a_reading_serialises(self):
        data = read_authority(act(), [claim()]).to_dict()
        assert data["record_type"] == "authority_reading"
        assert data["verifies_credentials"] is False
        assert data["authority_satisfied"] is True


class TestCoverageConsequence:

    def test_a_missing_authority_becomes_a_coverage_row(self):
        rows = read_authority(act(), []).expectations()
        assert [r.dimension for r in rows] == ["authority.finance.execute_payment"]
        assert rows[0].assessed is False
        ledger = CoverageLedger(rows=rows)
        assert (ledger.of("authority.finance.execute_payment").state
                is CoverageState.NOT_ASSESSED)

    def test_a_self_declared_authority_gets_its_own_row(self):
        rows = read_authority(act(), [claim(basis=AuthorityBasis.DECLARED,
                                            attributed_by="")]).expectations()
        assert [r.dimension for r in rows] == [
            "authority.self_declared.finance.execute_payment"]

    def test_an_unsafe_default_gets_a_row_of_its_own(self):
        rows = read_authority(act(withholding=WithholdingCost.HARM_CONTINUES),
                              [claim()]).expectations()
        assert [r.dimension for r in rows] == [
            "authority.withholding.finance.execute_payment"]
        assert "HOLD is the dangerous answer" in rows[0].note

    def test_a_fully_attributed_act_with_a_safe_default_costs_nothing(self):
        assert read_authority(act(), [claim()]).expectations() == ()

    def test_all_three_rows_can_appear_at_once_with_distinct_dimensions(self):
        rows = read_authority(
            act(required_authority=("incident_commander", "duty_officer"),
                withholding=WithholdingCost.HARM_CONTINUES),
            [claim(authority="duty_officer", basis=AuthorityBasis.DECLARED,
                   attributed_by="")]).expectations()
        dims = [r.dimension for r in rows]
        assert len(dims) == len(set(dims)) == 3


class TestRegistry:

    def test_a_duplicate_act_is_refused(self):
        built = ActRegistry()
        built.register(act())
        with pytest.raises(AuthorityError, match="already declared"):
            built.register(act())

    def test_only_acts_can_be_registered(self):
        with pytest.raises(AuthorityError, match="only a DomainAct"):
            ActRegistry().register({"act_id": "x.y"})

    def test_acts_come_back_in_a_stable_order(self):
        built = ActRegistry()
        for one in reversed(brief_acts()):
            built.register(one)
        assert [a.act_id for a in built] == sorted(a.act_id for a in brief_acts())

    def test_lookup_by_id_and_by_domain(self):
        built = ActRegistry()
        for one in brief_acts():
            built.register(one)
        assert built.of("finance.execute_payment").domain == "finance"
        assert built.of("nothing.here") is None
        assert len(built.for_domain("research")) == 2

    def test_a_registry_serialises(self):
        built = ActRegistry()
        built.register(act())
        data = built.to_dict()
        assert data["ships_domain_acts"] is False
        assert data["domains"] == ["finance"]


class TestNothingChangesACase:
    """`optional` is structural: no act is consulted during assurance."""

    def test_a_case_is_decided_without_any_act_being_declared(self):
        from release_gate.assurance.chaos import _assure, _base

        outcome = _assure([dict(r) for r in _base()])
        before = outcome.case.case_digest
        read_authority(act(), [claim()])
        assert outcome.case.case_digest == before

    def test_the_reading_is_not_a_case_record(self):
        reading = read_authority(act(), [claim()])
        assert reading.to_dict()["record_type"] == "authority_reading"
        assert not isinstance(reading, AuthorityReading.__mro__[1]) \
            if len(AuthorityReading.__mro__) > 2 else True

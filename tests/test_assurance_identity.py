"""Enterprise identity — recording what an authenticator established.

The assertion shapes here are the real ones: a GitHub Actions OIDC token, a
parsed SAML attribute set, an AWS STS principal, a GitLab job token, an Entra
id token. Nothing in the module under test verifies any of them, which is the
property most of these cases are about.
"""

from __future__ import annotations

import pytest

from release_gate.assurance.approval import (
    AuthSource, BoundApproval, offer_approval, submit_approval,
)
from release_gate.assurance.evidence import (
    EpistemicStatus, ProducerKind, ProvenanceStatus, TrustDecision,
)
from release_gate.assurance.identity import (
    ADAPTERS, IDENTITY_SCHEMA_SERVICE_PROVIDERS, Attribution, IdentityAdapter,
    IdentityClaim, IdentityError, IdentityProvider, ProofKind, adapter_for,
    attribution_of, auth_source_for, claim_from,
)
from release_gate.demos import single_agent

GHA = {
    "iss": "https://token.actions.githubusercontent.com",
    "sub": "repo:acme/api:environment:production",
    "aud": "https://release-gate.com", "repository": "acme/api",
    "workflow": "deploy", "actor": "alice", "actor_id": "4471",
    "job_workflow_ref": "acme/api/.github/workflows/deploy.yml@refs/heads/main",
    "ref": "refs/heads/main", "environment": "production",
    "event_name": "workflow_dispatch", "runner_environment": "github-hosted",
}
SAML = {
    "NameID": "alice@corp.example", "Issuer": "https://idp.corp.example/sso",
    "Audience": "release-gate", "email": "alice@corp.example",
    "groups": ["release-managers", "sre"], "department": "Platform",
    "AuthnContextClassRef": "urn:oasis:names:tc:SAML:2.0:ac:classes:MFA",
    "SessionNotOnOrAfter": "2026-09-25T18:00:00Z",
}
AWS = {
    "Arn": "arn:aws:sts::123456789012:assumed-role/deploy/prod-session",
    "Account": "123456789012", "UserId": "AROAEXAMPLE:prod-session",
    "assumed_role": "deploy", "mfa_authenticated": False,
}
GITLAB = {
    "iss": "https://gitlab.com",
    "sub": "project_path:acme/api:ref_type:branch:ref:main",
    "project_path": "acme/api", "pipeline_id": "99123",
    "ref_protected": "true", "user_login": "alice",
}
ENTRA = {
    "iss": "https://login.microsoftonline.com/9f00/v2.0", "oid": "8a7b-6c5d",
    "tid": "9f00", "upn": "alice@corp.example", "groups": ["releases"],
    "amr": ["pwd", "mfa"], "idtyp": "user",
}
OKTA = {
    "iss": "https://corp.okta.com", "sub": "00u1a2b3c4", "aud": "release-gate",
    "email": "alice@corp.example", "groups": ["release-managers"],
    "amr": ["pwd", "mfa"], "auth_time": "1790000000",
}


def verified(provider, assertion, **kw):
    kw.setdefault("verified_by", "release-gate-api (JWKS)")
    kw.setdefault("proof", ProofKind.JWT_SIGNATURE)
    return claim_from(provider, assertion, status=EpistemicStatus.VERIFIED, **kw)


def human(provider, assertion, **kw):
    return verified(provider, assertion, principal_kind=ProducerKind.HUMAN, **kw)


# ── nothing here is an IAM ───────────────────────────────────────────────────

class TestNotAnIAM:

    def test_a_claim_never_authenticates(self):
        assert verified(IdentityProvider.OIDC, OKTA).authenticates is False

    def test_not_even_a_cryptographically_verified_one(self):
        claim = human(IdentityProvider.ENTERPRISE_IDP, OKTA)
        assert claim.cryptographically_established
        assert claim.authenticates is False

    def test_identity_never_establishes_authority(self):
        """The one that gets violated in practice, because an authenticated
        caller feels authorised."""
        assert human(IdentityProvider.SAML, SAML,
                     proof=ProofKind.SAML_SIGNATURE).establishes_authority is False

    def test_both_refusals_are_in_the_payload(self):
        payload = verified(IdentityProvider.OIDC, OKTA).to_dict()
        assert payload["authenticates"] is False
        assert payload["establishes_authority"] is False

    def test_an_adapter_states_that_it_does_not_verify(self):
        assert ADAPTERS[IdentityProvider.OIDC].to_dict()["verifies"] is False

    def test_release_gate_is_not_an_identity_provider(self):
        with pytest.raises(IdentityError) as exc:
            IdentityClaim(provider=IdentityProvider.RELEASE_GATE, subject="x",
                          issuer="y")
        assert "not an identity provider" in str(exc.value)

    def test_and_has_no_adapter(self):
        with pytest.raises(IdentityError) as exc:
            adapter_for(IdentityProvider.RELEASE_GATE)
        assert "does not issue identities" in str(exc.value)

    def test_the_module_imports_nothing_that_could_verify(self):
        import release_gate.assurance.identity as module
        source = open(module.__file__).read()
        for forbidden in ("import jwt", "import jose", "requests", "httpx",
                          "urllib", "socket", "xml.", "defusedxml",
                          "cryptography", "hmac"):
            assert f"import {forbidden}" not in source, forbidden


# ── the named integrations ───────────────────────────────────────────────────

class TestProviders:

    def test_every_provider_but_two_has_an_adapter(self):
        """UNKNOWN has no assertion shape; RELEASE_GATE is not a provider."""
        missing = {p for p in IdentityProvider if p not in ADAPTERS}
        assert missing == {IdentityProvider.UNKNOWN,
                           IdentityProvider.RELEASE_GATE}

    def test_the_registry_cannot_disagree_with_itself(self):
        for provider, adapter in ADAPTERS.items():
            assert adapter.provider is provider

    def test_github_actions_normalises(self):
        claim = verified(IdentityProvider.GITHUB_ACTIONS, GHA)
        assert claim.subject == "repo:acme/api:environment:production"
        assert claim.issuer == "https://token.actions.githubusercontent.com"
        assert claim.attributes["workflow_ref"].endswith("deploy.yml@refs/heads/main")
        assert claim.attributes["environment"] == "production"

    def test_saml_normalises_from_parsed_attributes(self):
        claim = human(IdentityProvider.SAML, SAML,
                      proof=ProofKind.SAML_SIGNATURE,
                      verified_by="corp-gateway (SAML SP)")
        assert claim.subject == "alice@corp.example"
        assert claim.attributes["groups"] == ["release-managers", "sre"]
        assert claim.expires_at == "2026-09-25T18:00:00Z"

    def test_aws_normalises_an_arn(self):
        claim = claim_from(IdentityProvider.AWS_IAM, AWS,
                           status=EpistemicStatus.OBSERVED)
        assert claim.subject.startswith("arn:aws:sts::")
        assert claim.issuer == "123456789012"
        assert claim.attributes["mfa_authenticated"] is False

    def test_gitlab_ci_normalises(self):
        claim = verified(IdentityProvider.GITLAB_CI, GITLAB)
        assert claim.attributes["project_path"] == "acme/api"
        assert claim.attributes["ref_protected"] == "true"

    def test_entra_keys_on_oid_and_carries_its_tenant(self):
        claim = human(IdentityProvider.AZURE_ENTRA, ENTRA)
        assert claim.subject == "8a7b-6c5d"
        assert claim.attributes["tenant"] == "9f00"

    def test_a_missing_subject_is_refused(self):
        with pytest.raises(IdentityError) as exc:
            claim_from(IdentityProvider.OIDC, {"iss": "https://x"})
        assert "attributable to nobody" in str(exc.value)

    def test_an_issuer_backed_provider_must_name_its_issuer(self):
        with pytest.raises(IdentityError) as exc:
            claim_from(IdentityProvider.OIDC, {"sub": "alice"})
        assert "SELF_ASSERTED" in str(exc.value)

    def test_self_asserted_needs_no_issuer(self):
        assert claim_from(IdentityProvider.SELF_ASSERTED,
                          {"approver": "alice"}).issuer == ""

    def test_subject_fields_fall_back_in_order(self):
        """Providers disagree with themselves across token versions."""
        assert claim_from(IdentityProvider.SAML,
                          {"sub": "x", "Issuer": "y"}).subject == "x"

    def test_a_list_valued_audience_takes_its_first(self):
        claim = verified(IdentityProvider.OIDC,
                         dict(OKTA, aud=["release-gate", "other"]))
        assert claim.audience == "release-gate"


# ── a service identity is not a person ───────────────────────────────────────

class TestPrincipal:

    def test_a_workflow_token_is_not_a_person(self):
        claim = verified(IdentityProvider.GITHUB_ACTIONS, GHA)
        assert claim.is_a_service
        assert not claim.is_a_person

    def test_and_cannot_declare_itself_one(self):
        """The laundering case: a pipeline token dressed as a human approver."""
        with pytest.raises(IdentityError) as exc:
            verified(IdentityProvider.GITHUB_ACTIONS, GHA,
                     principal_kind=ProducerKind.HUMAN)
        assert "proves that something ran" in str(exc.value)

    @pytest.mark.parametrize("provider", sorted(
        IDENTITY_SCHEMA_SERVICE_PROVIDERS, key=lambda p: p.value))
    def test_no_structural_service_provider_carries_a_person(self, provider):
        with pytest.raises(IdentityError):
            IdentityClaim(provider=provider, subject="s", issuer="i",
                          principal_kind=ProducerKind.HUMAN)

    def test_an_api_key_is_possession_not_a_person(self):
        claim = claim_from(IdentityProvider.API_KEY,
                           {"key_id": "k1", "iss": "release-gate-api"})
        assert claim.is_a_service and not claim.is_a_person

    def test_a_cloud_identity_may_be_either_and_says_which(self):
        role = claim_from(IdentityProvider.AWS_IAM, AWS,
                          status=EpistemicStatus.OBSERVED)
        person = claim_from(IdentityProvider.AWS_IAM, AWS,
                            status=EpistemicStatus.OBSERVED,
                            principal_kind=ProducerKind.HUMAN)
        assert not role.principal_stated
        assert person.is_a_person

    def test_an_unstated_principal_is_neither(self):
        """Three states, not two: person, workload, and nobody said."""
        claim = claim_from(IdentityProvider.SELF_ASSERTED, {"approver": "alice"})
        assert not claim.is_a_person
        assert not claim.is_a_service
        assert not claim.principal_stated


# ── what established it, and who did the establishing ────────────────────────

class TestEstablishment:

    def test_verified_must_name_its_verifier(self):
        with pytest.raises(IdentityError) as exc:
            IdentityClaim(provider=IdentityProvider.OIDC, subject="s", issuer="i",
                          status=EpistemicStatus.VERIFIED,
                          proof=ProofKind.JWT_SIGNATURE)
        assert "does not say by whom" in str(exc.value)

    def test_verified_must_name_the_proof(self):
        with pytest.raises(IdentityError) as exc:
            IdentityClaim(provider=IdentityProvider.OIDC, subject="s", issuer="i",
                          status=EpistemicStatus.VERIFIED, verified_by="api")
        assert "nothing to verify" in str(exc.value)

    def test_a_declared_claim_cannot_name_a_verifier(self):
        """Either the check happened and it is VERIFIED, or nobody made it."""
        with pytest.raises(IdentityError) as exc:
            IdentityClaim(provider=IdentityProvider.OIDC, subject="s", issuer="i",
                          status=EpistemicStatus.DECLARED, verified_by="api")
        assert "contradiction" in str(exc.value)

    def test_declared_is_the_default_so_silence_costs_the_strong_claim(self):
        assert claim_from(IdentityProvider.OIDC,
                          OKTA).status is EpistemicStatus.DECLARED

    def test_an_unverified_claim_records_that_nothing_checked_the_proof(self):
        claim = claim_from(IdentityProvider.OIDC, OKTA)
        assert any("not verified by release-gate" in g
                   for g in claim.unverified_aspects)

    def test_a_bearer_token_is_not_cryptographic_even_when_verified(self):
        claim = verified(IdentityProvider.GITHUB_USER,
                         {"id": "4471", "iss": "https://github.com",
                          "login": "alice"},
                         proof=ProofKind.BEARER_TOKEN,
                         principal_kind=ProducerKind.HUMAN)
        assert claim.established
        assert not claim.cryptographically_established

    def test_observed_is_established_without_a_verifier(self):
        claim = claim_from(IdentityProvider.AWS_IAM, AWS,
                           status=EpistemicStatus.OBSERVED)
        assert claim.established and not claim.verified_by

    def test_inherent_gaps_travel_with_every_claim(self):
        """A gap that depends on being remembered is a gap that goes
        unmentioned."""
        claim = verified(IdentityProvider.GITHUB_ACTIONS, GHA)
        assert any("not who reviewed it" in g for g in claim.unverified_aspects)


# ── expiry is the issuer's claim ─────────────────────────────────────────────

class TestExpiry:

    def test_a_declared_expiry_is_named_as_declared(self):
        claim = human(IdentityProvider.SAML, SAML,
                      proof=ProofKind.SAML_SIGNATURE)
        assert "the issuer's claim" in claim.expiry_basis

    def test_no_expiry_is_stated_rather_than_silent(self):
        assert "declared no expiry" in verified(IdentityProvider.OIDC,
                                               OKTA).expiry_basis

    def test_a_passed_expiry_is_reported_as_declared_only(self):
        claim = human(IdentityProvider.SAML, SAML,
                      proof=ProofKind.SAML_SIGNATURE)
        # `now` pinned on both calls. Reading the real clock for one of them
        # would make this pass or fail depending on the time of day.
        after = "2026-09-26T00:00:00Z"
        assert claim.declared_expired(after)
        gaps = attribution_of(claim, now=after).gaps
        assert any("not a validation release-gate performed" in g for g in gaps)

    def test_a_live_assertion_raises_no_expiry_gap(self):
        claim = human(IdentityProvider.SAML, SAML,
                      proof=ProofKind.SAML_SIGNATURE)
        gaps = attribution_of(claim, now="2026-09-25T00:00:00Z").gaps
        assert not any("declared this assertion expired" in g for g in gaps)


# ── attribution ──────────────────────────────────────────────────────────────

class TestAttribution:

    def test_the_handle_is_provider_issuer_and_subject(self):
        claim = human(IdentityProvider.ENTERPRISE_IDP, OKTA)
        assert attribution_of(claim).attributable_to == \
            "ENTERPRISE_IDP:https://corp.okta.com:00u1a2b3c4"

    def test_a_subject_alone_is_not_reattributable(self):
        found = attribution_of(claim_from(IdentityProvider.SELF_ASSERTED,
                                          {"approver": "alice"}))
        assert not found.reattributable

    def test_an_issuer_scoped_subject_is(self):
        assert attribution_of(human(IdentityProvider.ENTERPRISE_IDP,
                                    OKTA)).reattributable

    def test_a_workload_is_reported_as_machine_self_authorisation(self):
        found = attribution_of(verified(IdentityProvider.GITHUB_ACTIONS, GHA))
        assert found.machine_self_authorisation
        assert "machine authorising machine work" in found.render()

    def test_an_unestablished_person_claim_is_not_called_a_machine(self):
        """Not established to be a person is not the same as being one."""
        found = attribution_of(claim_from(IdentityProvider.SELF_ASSERTED,
                                          {"approver": "alice"}))
        assert not found.machine_self_authorisation
        assert found.principal_unstated

    def test_identities_are_never_linked(self):
        assert attribution_of(human(IdentityProvider.ENTERPRISE_IDP,
                                    OKTA)).links_identities is False

    def test_two_providers_for_one_human_stay_two_identities(self):
        okta = human(IdentityProvider.ENTERPRISE_IDP, OKTA)
        github = verified(IdentityProvider.GITHUB_USER,
                          {"id": "4471", "iss": "https://github.com",
                           "email": "alice@corp.example"},
                          proof=ProofKind.BEARER_TOKEN,
                          principal_kind=ProducerKind.HUMAN)
        assert okta.claim_id != github.claim_id
        assert okta.attributable_to != github.attributable_to

    def test_attribution_never_authorises(self):
        assert attribution_of(human(IdentityProvider.ENTERPRISE_IDP,
                                    OKTA)).authorises is False

    def test_an_untrusted_issuer_is_a_gap_not_a_failure(self):
        found = attribution_of(human(IdentityProvider.ENTERPRISE_IDP, OKTA),
                               trusted_issuers={"https://other.example"})
        assert found.issuer_accepted is False
        assert found.established          # the assertion still holds
        assert any("nobody decided to accept" in g for g in found.gaps)

    def test_a_trusted_issuer_passes(self):
        found = attribution_of(human(IdentityProvider.ENTERPRISE_IDP, OKTA),
                               trusted_issuers={"https://corp.okta.com"})
        assert found.issuer_accepted is True

    def test_no_allowlist_leaves_the_question_unasked(self):
        found = attribution_of(human(IdentityProvider.ENTERPRISE_IDP, OKTA))
        assert found.issuer_accepted is None
        assert any("was not asked" in g for g in found.gaps)

    def test_an_explicit_trust_decision_removes_that_gap(self):
        claim = human(IdentityProvider.ENTERPRISE_IDP, OKTA,
                      issuer_trust=TrustDecision(
                          status="ACCEPTED",
                          basis="federated under the corp SSO agreement",
                          decided_by="platform-security"))
        gaps = attribution_of(claim).gaps
        assert not any("no explicit trust decision" in g for g in gaps)


# ── the bridge to what approvals already record ──────────────────────────────

class TestAuthSourceBridge:

    def test_a_verified_oidc_claim_is_established(self):
        source = auth_source_for(human(IdentityProvider.ENTERPRISE_IDP, OKTA))
        assert source is AuthSource.PLATFORM_SSO

    def test_an_unverified_claim_falls_back_to_asserted(self):
        """The direction that fails safe: an unverified token read as
        established would be the whole boundary defeated by a missing check."""
        assert auth_source_for(claim_from(IdentityProvider.OIDC,
                                          OKTA)) is AuthSource.ASSERTED

    def test_an_observed_claim_does_not_claim_a_signature(self):
        claim = claim_from(IdentityProvider.AWS_IAM, AWS,
                           status=EpistemicStatus.OBSERVED)
        assert auth_source_for(claim) is AuthSource.PLATFORM_SSO

    def test_the_bridge_agrees_with_identity_established(self):
        for claim in (human(IdentityProvider.ENTERPRISE_IDP, OKTA),
                      verified(IdentityProvider.GITHUB_ACTIONS, GHA),
                      claim_from(IdentityProvider.OIDC, OKTA),
                      claim_from(IdentityProvider.SELF_ASSERTED, {"user": "a"})):
            approval = BoundApproval(
                case_id="c", case_version=1, approver="a",
                subject_digest="d", case_digest="e",
                auth_source=auth_source_for(claim), approver_identity=claim)
            assert approval.identity_established == claim.established

    def test_an_api_key_claim_is_never_established(self):
        claim = verified(IdentityProvider.API_KEY,
                         {"key_id": "k", "iss": "rg"},
                         proof=ProofKind.BEARER_TOKEN)
        assert auth_source_for(claim) is AuthSource.API_KEY
        approval = BoundApproval(case_id="c", case_version=1, approver="svc",
                                 subject_digest="d", case_digest="e",
                                 auth_source=auth_source_for(claim))
        assert not approval.identity_established


# ── the approval record ──────────────────────────────────────────────────────

class TestApprovalAttribution:

    @pytest.fixture
    def outcome(self):
        return single_agent.run().outcome

    def test_an_approval_is_attributable_to_an_issuer_and_subject(self, outcome):
        claim = human(IdentityProvider.ENTERPRISE_IDP, OKTA)
        submission = submit_approval(
            outcome.case, offer_approval(outcome.case).acknowledgement(),
            approver="alice@corp.example", auth_source=auth_source_for(claim),
            identity=claim)
        assert submission.accepted
        assert submission.approval.attributable_to == claim.attributable_to
        assert submission.approval.approver_is_a_person is True

    def test_without_one_it_falls_back_to_the_typed_name(self, outcome):
        approval = submit_approval(
            outcome.case, offer_approval(outcome.case).acknowledgement(),
            approver="alice").approval
        assert approval.attributable_to == "alice"

    def test_and_says_nobody_stated_whether_that_is_a_person(self, outcome):
        """`None`, not `False`: a missing claim means nobody said."""
        approval = submit_approval(
            outcome.case, offer_approval(outcome.case).acknowledgement(),
            approver="alice").approval
        assert approval.approver_is_a_person is None

    def test_an_identity_joins_the_approval_id(self, outcome):
        claim = human(IdentityProvider.ENTERPRISE_IDP, OKTA)
        with_id = submit_approval(
            outcome.case, offer_approval(outcome.case).acknowledgement(),
            approver="alice", identity=claim,
            auth_source=auth_source_for(claim)).approval
        assert "approver_identity" in with_id.identity()

    def test_existing_approval_ids_are_unchanged(self, outcome):
        plain = submit_approval(
            outcome.case, offer_approval(outcome.case).acknowledgement(),
            approver="alice").approval
        assert "approver_identity" not in plain.identity()

    def test_an_approval_with_an_identity_round_trips(self, outcome):
        claim = human(IdentityProvider.ENTERPRISE_IDP, OKTA)
        approval = submit_approval(
            outcome.case, offer_approval(outcome.case).acknowledgement(),
            approver="alice", identity=claim,
            auth_source=auth_source_for(claim)).approval
        restored = BoundApproval.from_dict(approval.to_dict())
        assert restored.approval_id == approval.approval_id
        assert restored.approver_identity.attributable_to == claim.attributable_to

    def test_a_workflow_token_approving_is_visible_as_such(self, outcome):
        """Legal, recorded, and never silent."""
        claim = verified(IdentityProvider.GITHUB_ACTIONS, GHA)
        approval = submit_approval(
            outcome.case, offer_approval(outcome.case).acknowledgement(),
            approver="github-actions", identity=claim,
            auth_source=auth_source_for(claim)).approval
        assert approval.approver_is_a_person is False
        assert attribution_of(claim).machine_self_authorisation


# ── the record itself ────────────────────────────────────────────────────────

class TestRecord:

    def test_the_id_is_content_derived(self):
        assert verified(IdentityProvider.OIDC, OKTA).claim_id == \
            verified(IdentityProvider.OIDC, OKTA).claim_id

    def test_a_different_issuer_is_a_different_claim(self):
        one = verified(IdentityProvider.OIDC, OKTA)
        two = verified(IdentityProvider.OIDC, dict(OKTA, iss="https://b.okta.com"))
        assert one.claim_id != two.claim_id

    def test_it_round_trips(self):
        claim = human(IdentityProvider.ENTERPRISE_IDP, OKTA,
                      issuer_trust=TrustDecision(status="ACCEPTED", basis="b",
                                                 decided_by="d"))
        restored = IdentityClaim.from_dict(claim.to_dict())
        assert restored.claim_id == claim.claim_id
        assert restored.issuer_trust.decided_by == "d"

    def test_it_carries_no_token(self):
        """A token is a credential. Keeping one would turn an audit record into
        a secret."""
        payload = verified(IdentityProvider.OIDC, OKTA).to_dict()
        assert "token" not in payload and "assertion" not in payload
        assert set(payload["attributes"]) <= set(OKTA)

    def test_it_becomes_a_producer_without_a_second_vocabulary(self):
        producer = human(IdentityProvider.ENTERPRISE_IDP, OKTA).as_producer()
        assert producer.kind is ProducerKind.HUMAN
        assert producer.identity_basis == "enterprise_idp:verified"
        assert "okta" in producer.producer_id

    def test_render_says_identity_only(self):
        assert "says nothing about what this principal may authorise" in \
            verified(IdentityProvider.OIDC, OKTA).render()

    def test_an_unruled_issuer_is_named_in_the_render(self):
        assert "NOT_ESTABLISHED" in verified(IdentityProvider.OIDC, OKTA).render()

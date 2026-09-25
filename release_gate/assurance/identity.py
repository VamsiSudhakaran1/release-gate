"""Who authorised this, as established by something that is not release-gate.

**This is not an IAM.** Nothing here authenticates. There is no token
verification, no signature check, no JWKS fetch, no assertion parsing, no user
store, no session, no login flow, and no permission model. The assurance layer
is stdlib-only and makes no network calls, and that constraint is the design
rather than a gap in it: release-gate is the *recorder* of what an authenticator
established, and a recorder that quietly re-derived its inputs would be
asserting the thing it was supposed to be citing.

So an identity arrives as a **claim** from a host boundary — the hosted API, the
GitHub Action, the CLI, an enterprise gateway — and what gets written down is
four separable things:

* **who** the issuer says this is (`issuer` + `subject`, in the issuer's own
  namespace, never re-keyed into one of ours);
* **how** that was established (`EpistemicStatus`, exactly as for evidence:
  VERIFIED when a proof was checked, OBSERVED when a boundary handed it over,
  DECLARED when someone simply said so);
* **who did the establishing** (`verified_by`), because a signature release-gate
  validated and a signature a platform validated are different facts and only
  one of them is ours;
* **what nobody checked** (`unverified_aspects`), because the gaps in an identity
  are the part a reviewer most needs and the part most likely to go unwritten.

Identity is not a special epistemology, so it does not get a private one. The
three orthogonal axes already in use for evidence carry it: `EpistemicStatus`
for how it was established, `ProvenanceStatus` for whether the proof chain
holds, and `TrustDecision` for whether an issuer is accepted — which already
refuses to exist without a named decider.

**Two refusals define the boundary.** `authenticates` is unconditionally
`False`: release-gate does not establish identity and cannot be made to look as
though it did. `establishes_authority` is unconditionally `False`: knowing who
someone is says nothing about what they may do (Invariant 11). The second is the
one that gets violated in practice, because an authenticated caller feels
authorised.

**And one that is the whole product.** A pipeline token proves a pipeline ran. It
does not make a decision a person is answerable for. `Attribution` reports that
as `machine_self_authorisation` rather than refusing it — release-gate cannot
know whether a given deployment legitimately authorises through a service
account — but it is reported every time, because an autonomous system approving
its own output is the thing this whole system sits between (Invariant 15).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple

from release_gate.assurance.canonical import digest_object, short_id
from release_gate.assurance.evidence import (
    EpistemicStatus, ProducerKind, Producer, ProvenanceStatus, TrustDecision,
)

__all__ = [
    "ADAPTERS",
    "IDENTITY_SCHEMA_SERVICE_PROVIDERS",
    "IDENTITY_SCHEMA_VERSION",
    "Attribution",
    "IdentityAdapter",
    "IdentityClaim",
    "IdentityError",
    "IdentityProvider",
    "ProofKind",
    "adapter_for",
    "attribution_of",
    "auth_source_for",
    "claim_from",
]

IDENTITY_SCHEMA_VERSION = 1


class IdentityError(ValueError):
    """An identity was recorded in a way that would overstate what established it."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# ── the providers ────────────────────────────────────────────────────────────

class IdentityProvider(str, Enum):
    """Where an identity assertion came from.

    Named rather than free-text because the *shape* of each assertion differs and
    an adapter has to know which one it is reading. What each one establishes is
    not encoded here — that is `EpistemicStatus` and `verified_by`, kept separate
    so "GitHub said so" cannot drift into "therefore it is true".
    """

    OIDC = "OIDC"                          # generic OpenID Connect id token
    SAML = "SAML"                          # a SAML assertion's parsed attributes
    GITHUB_ACTIONS = "GITHUB_ACTIONS"      # workflow OIDC token — a workload
    GITHUB_APP = "GITHUB_APP"              # an installation, not a person
    GITHUB_USER = "GITHUB_USER"            # a person, via GitHub login
    GITLAB_CI = "GITLAB_CI"                # pipeline JWT — a workload
    GITLAB_USER = "GITLAB_USER"
    AWS_IAM = "AWS_IAM"                    # role or user ARN
    GCP_IAM = "GCP_IAM"                    # service account or principal email
    AZURE_ENTRA = "AZURE_ENTRA"            # Entra ID (formerly Azure AD)
    ENTERPRISE_IDP = "ENTERPRISE_IDP"      # Okta, Ping, ADFS, Keycloak, …
    SERVICE_ACCOUNT = "SERVICE_ACCOUNT"    # a named non-human principal
    MTLS = "MTLS"                          # a client certificate subject
    SSH_KEY = "SSH_KEY"
    GPG_KEY = "GPG_KEY"
    API_KEY = "API_KEY"                    # possession of a key, not a person
    SELF_ASSERTED = "SELF_ASSERTED"        # the caller said who they were
    UNKNOWN = "UNKNOWN"
    #: Present so it can be refused by name rather than by omission.
    RELEASE_GATE = "RELEASE_GATE"


#: Providers whose principal is a workload by construction. A token from one of
#: these proves that something ran, which is a different claim from a person
#: having decided. Held as data so `is_a_person` is a lookup rather than a
#: judgement made afresh at each call site.
IDENTITY_SCHEMA_SERVICE_PROVIDERS: frozenset = frozenset({
    IdentityProvider.GITHUB_ACTIONS, IdentityProvider.GITHUB_APP,
    IdentityProvider.GITLAB_CI, IdentityProvider.SERVICE_ACCOUNT,
    IdentityProvider.API_KEY, IdentityProvider.MTLS,
})

#: Providers that can carry a human principal. AWS, GCP and Entra appear in both
#: sets on purpose: a cloud identity may be a person or a role, and which one it
#: is has to be read off the assertion rather than assumed from the issuer.
_MAY_BE_HUMAN: frozenset = frozenset({
    IdentityProvider.OIDC, IdentityProvider.SAML, IdentityProvider.GITHUB_USER,
    IdentityProvider.GITLAB_USER, IdentityProvider.AWS_IAM,
    IdentityProvider.GCP_IAM, IdentityProvider.AZURE_ENTRA,
    IdentityProvider.ENTERPRISE_IDP, IdentityProvider.SSH_KEY,
    IdentityProvider.GPG_KEY, IdentityProvider.SELF_ASSERTED,
})


class ProofKind(str, Enum):
    """What was presented. Not whether anyone checked it — that is `verified_by`.

    Separate from `VerificationMethod`, which types verifications of *work*. A
    test suite and a JWT signature are not the same kind of thing and sharing an
    enum would let a methodology that accepts one appear to accept the other.
    """

    JWT_SIGNATURE = "JWT_SIGNATURE"
    SAML_SIGNATURE = "SAML_SIGNATURE"
    X509_CHAIN = "X509_CHAIN"
    SSH_SIGNATURE = "SSH_SIGNATURE"
    GPG_SIGNATURE = "GPG_SIGNATURE"
    HMAC = "HMAC"
    #: A bearer token accepted on presentation. Proves possession, not identity.
    BEARER_TOKEN = "BEARER_TOKEN"
    SESSION = "SESSION"
    NONE = "NONE"


#: Proofs that are cryptographic if checked. Possession of a bearer token or a
#: session cookie is not in here: it proves whoever holds it holds it.
_CRYPTOGRAPHIC: frozenset = frozenset({
    ProofKind.JWT_SIGNATURE, ProofKind.SAML_SIGNATURE, ProofKind.X509_CHAIN,
    ProofKind.SSH_SIGNATURE, ProofKind.GPG_SIGNATURE,
})


# ── the generic claim ────────────────────────────────────────────────────────

@dataclass(frozen=True)
class IdentityClaim:
    """One assertion about who someone is, and what established it.

    The core interface, and deliberately provider-neutral: `subject` and
    `issuer` stay in the issuer's namespace, and everything provider-specific
    lives in `attributes`. A claim re-keyed into a release-gate user id would be
    a claim about a record we invented rather than about the thing the issuer
    asserted.
    """

    provider: IdentityProvider
    #: The principal, as the issuer names it. Not normalised, not lowercased,
    #: not stripped of its realm: `sub` from one IdP and `sub` from another are
    #: different principals even when the strings match.
    subject: str
    #: Who asserted it. Empty is permitted only for SELF_ASSERTED and UNKNOWN,
    #: where there is genuinely no issuer rather than one we failed to record.
    issuer: str = ""
    audience: str = ""
    #: How the identity was established. Boundary-assigned, never taken from the
    #: assertion: a token that says it is verified is a token making a claim.
    status: EpistemicStatus = EpistemicStatus.DECLARED
    proof: ProofKind = ProofKind.NONE
    #: Who checked the proof. A signature release-gate validated and one a
    #: platform validated are different facts, and this is the difference.
    verified_by: str = ""
    provenance: ProvenanceStatus = ProvenanceStatus.ATTRIBUTED
    #: An explicit ruling that this issuer is accepted here. Never inferred —
    #: `TrustDecision` already refuses to exist without a named decider.
    issuer_trust: Optional[TrustDecision] = None
    principal_kind: ProducerKind = ProducerKind.EXTERNAL
    #: Provider-specific: groups, roles, repository, workflow, ref, ARN, tenant.
    attributes: Mapping[str, Any] = field(default_factory=dict)
    #: A digest of the raw assertion, so it can be cited without being stored.
    #: Tokens are credentials; keeping one in an evidence pack would turn an
    #: audit record into a secret.
    assertion_digest: Optional[str] = None
    #: The issuer's own timestamps. Declarations, not observations.
    issued_at: Optional[str] = None
    expires_at: Optional[str] = None
    #: What nobody checked. Written down because the gaps in an identity are the
    #: part a reviewer needs and the part most likely to be left out.
    unverified_aspects: Tuple[str, ...] = ()
    schema_version: int = IDENTITY_SCHEMA_VERSION

    claim_id: str = field(default="", init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "provider", IdentityProvider(self.provider))
        object.__setattr__(self, "status", EpistemicStatus(self.status))
        object.__setattr__(self, "proof", ProofKind(self.proof))
        object.__setattr__(self, "provenance", ProvenanceStatus(self.provenance))
        object.__setattr__(self, "principal_kind", ProducerKind(self.principal_kind))
        object.__setattr__(self, "attributes", dict(self.attributes or {}))
        object.__setattr__(self, "unverified_aspects",
                           tuple(self.unverified_aspects))
        for name in ("subject", "issuer", "audience", "verified_by"):
            object.__setattr__(self, name, (getattr(self, name) or "").strip())

        if self.provider is IdentityProvider.RELEASE_GATE:
            raise IdentityError(
                "release-gate is not an identity provider. It records what an "
                "authenticator established; an engine that also issued the "
                "identity would be vouching for itself (Invariant 15)")
        if not self.subject:
            raise IdentityError(
                "an identity claim must name its subject; an authorisation "
                "attributable to nobody is not an audit trail")
        if not self.issuer and self.provider not in (
                IdentityProvider.SELF_ASSERTED, IdentityProvider.UNKNOWN):
            raise IdentityError(
                f"{self.provider.value} claims come from an issuer, and this one "
                "names none. An unattributed assertion is SELF_ASSERTED — which "
                "is a weaker claim, not a missing field")
        if (self.provider in IDENTITY_SCHEMA_SERVICE_PROVIDERS
                and self.principal_kind is ProducerKind.HUMAN):
            raise IdentityError(
                f"a {self.provider.value} assertion cannot carry a human "
                "principal: it proves that something ran, not that a person "
                "decided. Recording it as a person is how a pipeline comes to "
                "hold an approval nobody made (Invariant 15)")
        if (self.principal_kind is ProducerKind.HUMAN
                and self.provider not in _MAY_BE_HUMAN):
            raise IdentityError(
                f"{self.provider.value} is not a provider that carries human "
                "principals here; say which one did, or leave the principal as "
                "what the assertion actually established")
        if self.status is EpistemicStatus.VERIFIED:
            if not self.verified_by:
                raise IdentityError(
                    "a VERIFIED identity must name who verified it: 'verified' "
                    "alone does not say by whom, and a check nobody is named for "
                    "cannot be re-run (Invariant 8)")
            if self.proof is ProofKind.NONE:
                raise IdentityError(
                    "a VERIFIED identity must name the proof that was checked; "
                    "a verification with nothing to verify did not happen")
        if self.status in (EpistemicStatus.DECLARED, EpistemicStatus.NOT_ASSESSED) \
                and self.verified_by:
            raise IdentityError(
                f"a {self.status.value} identity names {self.verified_by!r} as "
                "having verified it, which is a contradiction: either the check "
                "happened and the status is VERIFIED, or it did not and nobody "
                "should be recorded as having made it")
        object.__setattr__(self, "claim_id",
                           short_id("idc", digest_object(self.identity())))

    def identity(self) -> Dict[str, Any]:
        """What makes this a distinct assertion about a distinct principal.

        `issued_at` is in it — two logins by the same person are two assertions.
        Arrival time is not recorded here at all: an identity claim is something
        the host hands over, and when we read it is a fact about our process.
        """
        return {"schema_version": self.schema_version,
                "provider": self.provider.value, "subject": self.subject,
                "issuer": self.issuer, "audience": self.audience,
                "status": self.status.value, "proof": self.proof.value,
                "verified_by": self.verified_by,
                "provenance": self.provenance.value,
                "principal_kind": self.principal_kind.value,
                "attributes": dict(self.attributes),
                "assertion_digest": self.assertion_digest,
                "issued_at": self.issued_at, "expires_at": self.expires_at,
                "unverified_aspects": list(self.unverified_aspects)}

    # ── the two refusals that define the boundary ───────────────────────────

    @property
    def authenticates(self) -> bool:
        """Unconditionally False. Release-gate records an identity someone else
        established; it never establishes one."""
        return False

    @property
    def establishes_authority(self) -> bool:
        """Unconditionally False. Knowing who someone is says nothing about what
        they may do — provenance is not trust (Invariant 11). This is the one
        that gets violated in practice, because an authenticated caller feels
        authorised."""
        return False

    # ── what it does say ────────────────────────────────────────────────────

    @property
    def attributable_to(self) -> str:
        """The canonical handle: provider, issuer, subject. Three parts, because
        a subject string is only meaningful inside the issuer that minted it."""
        return f"{self.provider.value}:{self.issuer or '-'}:{self.subject}"

    @property
    def established(self) -> bool:
        """Whether anyone other than the claimant established this.

        VERIFIED and OBSERVED count; OBSERVED is the boundary case — release-gate
        read the assertion from a channel it trusts rather than checking a
        signature — and the distinction stays visible in `verified_by`.
        """
        return self.status in (EpistemicStatus.VERIFIED, EpistemicStatus.OBSERVED)

    @property
    def cryptographically_established(self) -> bool:
        return (self.status is EpistemicStatus.VERIFIED
                and self.proof in _CRYPTOGRAPHIC)

    @property
    def is_a_service(self) -> bool:
        """Whether the principal is a workload rather than a person.

        Read from the provider for the ones where it is structural, and from
        `principal_kind` otherwise — a cloud identity may be either, and which it
        is has to come off the assertion rather than from the issuer's name.
        """
        if self.provider in IDENTITY_SCHEMA_SERVICE_PROVIDERS:
            return True
        return self.principal_kind in (ProducerKind.TOOL, ProducerKind.AGENT,
                                       ProducerKind.RELEASE_GATE)

    @property
    def principal_stated(self) -> bool:
        """Whether the assertion said what kind of principal this is.

        `EXTERNAL` is the default and means nobody said. That is a third state
        beside person and workload, and collapsing it into either one reports
        something nobody established.
        """
        return self.principal_kind is not ProducerKind.EXTERNAL

    @property
    def is_a_person(self) -> bool:
        """Whether this identifies a human.

        `False` for anything structurally a workload, and `False` for a provider
        that could carry a person but whose assertion did not say so — an
        unstated principal kind is not a person by default. That default is the
        entire point: a pipeline token read as a human approver is the failure
        this system exists to prevent.
        """
        return (not self.is_a_service
                and self.principal_kind is ProducerKind.HUMAN)

    @property
    def expiry_basis(self) -> str:
        if not self.expires_at:
            return ("the issuer declared no expiry; nothing here observed one, and "
                    "an assertion without one does not lapse on its own")
        return (f"the issuer declared an expiry of {self.expires_at}. That is the "
                "issuer's claim about its own token, not something release-gate "
                "checked")

    def declared_expired(self, now: Optional[str] = None) -> bool:
        """Whether the issuer's own declared expiry has passed.

        Named `declared_` because that is all this is. Release-gate does not
        validate tokens, so a live assertion and a stale one are distinguishable
        here only by what the issuer wrote in it.
        """
        if not self.expires_at:
            return False
        return (now or _utc_now()) >= self.expires_at

    def as_producer(self) -> Producer:
        """The same principal in the shape `EvidenceRecord` already takes.

        So an identity established at a boundary can be carried on the evidence
        that boundary produced, without a second vocabulary for the same fact.
        """
        return Producer(producer_id=self.attributable_to,
                        kind=self.principal_kind,
                        identity_basis=(f"{self.provider.value.lower()}:"
                                        f"{self.status.value.lower()}"),
                        attested_by=self.verified_by or None)

    # ── serialisation ───────────────────────────────────────────────────────

    @property
    def record_type(self) -> str:
        return "identity_claim"

    @property
    def record_id(self) -> str:
        return self.claim_id

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_type": "identity_claim", "record_id": self.claim_id,
            "claim_id": self.claim_id, **self.identity(),
            "attributable_to": self.attributable_to,
            "established": self.established,
            "cryptographically_established": self.cryptographically_established,
            "is_a_person": self.is_a_person, "is_a_service": self.is_a_service,
            "principal_stated": self.principal_stated,
            "issuer_trust": (self.issuer_trust.to_dict()
                             if self.issuer_trust else None),
            "expiry_basis": self.expiry_basis,
            # Stated in the payload, on every claim, so a consumer finds them
            # rather than having to know them.
            "authenticates": False, "establishes_authority": False,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "IdentityClaim":
        return cls(
            provider=IdentityProvider(str(data.get("provider") or "UNKNOWN")),
            subject=str(data.get("subject") or ""),
            issuer=str(data.get("issuer") or ""),
            audience=str(data.get("audience") or ""),
            status=EpistemicStatus(str(data.get("status") or "DECLARED")),
            proof=ProofKind(str(data.get("proof") or "NONE")),
            verified_by=str(data.get("verified_by") or ""),
            provenance=ProvenanceStatus(str(data.get("provenance")
                                            or "ATTRIBUTED")),
            issuer_trust=TrustDecision.from_dict(data.get("issuer_trust")),
            principal_kind=ProducerKind(str(data.get("principal_kind")
                                            or "external")),
            attributes=data.get("attributes") or {},
            assertion_digest=(str(data["assertion_digest"])
                              if data.get("assertion_digest") else None),
            issued_at=(str(data["issued_at"]) if data.get("issued_at") else None),
            expires_at=(str(data["expires_at"]) if data.get("expires_at")
                        else None),
            unverified_aspects=tuple(data.get("unverified_aspects") or ()))

    def render(self) -> str:
        lines = [f"{self.attributable_to}",
                 f"  established: {self.status.value}"
                 + (f" by {self.verified_by}" if self.verified_by
                    else " — nobody is recorded as having checked it"),
                 f"  proof: {self.proof.value}",
                 f"  principal: {self.principal_kind.value}"
                 + (" (a workload, not a person)" if self.is_a_service else ""),
                 f"  {self.expiry_basis}"]
        if self.issuer_trust is not None:
            lines.append(f"  issuer trust: {self.issuer_trust.status.value} "
                         f"({self.issuer_trust.decided_by})")
        else:
            lines.append("  issuer trust: NOT_ESTABLISHED — nobody has ruled on "
                         "this issuer here")
        for gap in self.unverified_aspects:
            lines.append(f"  NOT CHECKED: {gap}")
        lines.append("  Identity only. This says nothing about what this "
                     "principal may authorise.")
        return "\n".join(lines)


# ── the adapters ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class IdentityAdapter:
    """How to read one provider's assertion into the generic claim.

    Data, not a code path: a provider is a row naming which keys carry the
    subject, the issuer and the attributes worth keeping. Adding one adds a row,
    so the enum and the registry cannot drift apart into two lists that disagree.

    An adapter reads. It does not verify, fetch, or parse — it is handed an
    already-decoded mapping of claims by whatever at the host boundary did the
    decoding, and `verified_by` records which thing that was.
    """

    provider: IdentityProvider
    name: str
    #: Candidate keys for the subject, in order. More than one because providers
    #: disagree with themselves across token versions.
    subject_fields: Tuple[str, ...] = ("sub",)
    issuer_fields: Tuple[str, ...] = ("iss",)
    audience_fields: Tuple[str, ...] = ("aud",)
    issued_at_fields: Tuple[str, ...] = ("iat",)
    expiry_fields: Tuple[str, ...] = ("exp",)
    #: canonical name → the key it comes from in this provider's assertion.
    attribute_fields: Mapping[str, str] = field(default_factory=dict)
    default_principal: ProducerKind = ProducerKind.EXTERNAL
    default_proof: ProofKind = ProofKind.NONE
    #: Aspects this provider's assertion structurally cannot establish. Carried
    #: onto every claim it produces, because a gap that depends on remembering
    #: to mention it is a gap that goes unmentioned.
    inherent_gaps: Tuple[str, ...] = ()
    notes: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "provider", IdentityProvider(self.provider))
        object.__setattr__(self, "attribute_fields",
                           dict(self.attribute_fields or {}))
        for name in ("subject_fields", "issuer_fields", "audience_fields",
                     "issued_at_fields", "expiry_fields", "inherent_gaps"):
            object.__setattr__(self, name, tuple(getattr(self, name)))

    @staticmethod
    def _first(assertion: Mapping[str, Any], keys: Sequence[str]) -> str:
        for key in keys:
            value = assertion.get(key)
            if isinstance(value, (list, tuple)):
                value = value[0] if value else None
            if value not in (None, ""):
                return str(value)
        return ""

    def claim(self, assertion: Mapping[str, Any], *,
              status: EpistemicStatus = EpistemicStatus.DECLARED,
              verified_by: str = "", proof: Optional[ProofKind] = None,
              principal_kind: Optional[ProducerKind] = None,
              provenance: Optional[ProvenanceStatus] = None,
              issuer_trust: Optional[TrustDecision] = None,
              assertion_digest: Optional[str] = None,
              extra_gaps: Iterable[str] = ()) -> IdentityClaim:
        """Read this assertion into a claim.

        `status` defaults to DECLARED, and so does every caller that forgets to
        say otherwise. A boundary that checked a signature has to say so, which
        is the right way round: the cost of silence falls on the strong claim.
        """
        attributes = {}
        for canonical, source in self.attribute_fields.items():
            if source in assertion and assertion[source] not in (None, ""):
                attributes[canonical] = assertion[source]

        principal = principal_kind or self.default_principal
        gaps = tuple(self.inherent_gaps) + tuple(extra_gaps)
        if status is not EpistemicStatus.VERIFIED:
            presented = proof or self.default_proof
            gaps = gaps + (
                ("no proof was presented, so there was nothing to verify"
                 if presented is ProofKind.NONE else
                 f"the {presented.value} presented was not verified by "
                 "release-gate or by any named checker"),)
        return IdentityClaim(
            provider=self.provider,
            subject=self._first(assertion, self.subject_fields),
            issuer=self._first(assertion, self.issuer_fields),
            audience=self._first(assertion, self.audience_fields),
            status=status, verified_by=verified_by,
            proof=(proof if proof is not None else self.default_proof),
            provenance=(provenance if provenance is not None else
                        (ProvenanceStatus.SIGNED
                         if status is EpistemicStatus.VERIFIED
                         else ProvenanceStatus.ATTRIBUTED)),
            issuer_trust=issuer_trust, principal_kind=principal,
            attributes=attributes, assertion_digest=assertion_digest,
            issued_at=(self._first(assertion, self.issued_at_fields) or None),
            expires_at=(self._first(assertion, self.expiry_fields) or None),
            unverified_aspects=tuple(dict.fromkeys(gaps)))

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "identity_adapter",
                "provider": self.provider.value, "name": self.name,
                "subject_fields": list(self.subject_fields),
                "issuer_fields": list(self.issuer_fields),
                "attribute_fields": dict(self.attribute_fields),
                "default_principal": self.default_principal.value,
                "default_proof": self.default_proof.value,
                "inherent_gaps": list(self.inherent_gaps),
                "notes": self.notes,
                # Stated on the adapter too: the thing that reads an assertion
                # is the most likely place for someone to look for a verifier.
                "verifies": False}


_ADAPTER_LIST: Tuple[IdentityAdapter, ...] = (
    IdentityAdapter(
        provider=IdentityProvider.OIDC, name="generic OpenID Connect",
        attribute_fields={"email": "email", "email_verified": "email_verified",
                          "name": "name", "groups": "groups",
                          "preferred_username": "preferred_username",
                          "auth_time": "auth_time", "acr": "acr", "amr": "amr"},
        default_proof=ProofKind.JWT_SIGNATURE,
        inherent_gaps=("whether the email in this token was ever confirmed, "
                       "unless email_verified says so and the issuer is trusted",),
        notes="`sub` is stable per issuer and is the only field safe to key on; "
              "email is mutable and is an attribute, not an identity."),
    IdentityAdapter(
        provider=IdentityProvider.SAML, name="SAML assertion attributes",
        subject_fields=("NameID", "nameid", "sub"),
        issuer_fields=("Issuer", "issuer", "iss"),
        audience_fields=("Audience", "audience", "aud"),
        issued_at_fields=("IssueInstant", "issue_instant"),
        expiry_fields=("SessionNotOnOrAfter", "NotOnOrAfter"),
        attribute_fields={"email": "email", "groups": "groups",
                          "department": "department",
                          "employee_id": "employeeId",
                          "authn_context": "AuthnContextClassRef"},
        default_proof=ProofKind.SAML_SIGNATURE,
        inherent_gaps=("a transient NameID identifies a session rather than a "
                       "person, and this record cannot tell which format was used "
                       "unless the caller said",),
        notes="Takes already-parsed attributes. Nothing here reads XML: parsing "
              "untrusted XML is a different job, with a different threat model, "
              "and it belongs at the boundary that already has a hardened parser."),
    IdentityAdapter(
        provider=IdentityProvider.GITHUB_ACTIONS,
        name="GitHub Actions OIDC token",
        attribute_fields={"repository": "repository", "workflow": "workflow",
                          "workflow_ref": "job_workflow_ref", "ref": "ref",
                          "sha": "sha", "environment": "environment",
                          "actor": "actor", "actor_id": "actor_id",
                          "event_name": "event_name",
                          "runner_environment": "runner_environment",
                          "repository_owner": "repository_owner"},
        default_principal=ProducerKind.TOOL,
        default_proof=ProofKind.JWT_SIGNATURE,
        inherent_gaps=("`actor` names who triggered the run, which is not who "
                       "reviewed it — a token proves a workflow ran, not that a "
                       "person decided",),
        notes="A workload identity. `job_workflow_ref` is what pins which "
              "workflow file ran; `repository` alone does not."),
    IdentityAdapter(
        provider=IdentityProvider.GITHUB_APP, name="GitHub App installation",
        subject_fields=("installation_id", "sub"),
        issuer_fields=("iss", "app_id"),
        attribute_fields={"app_id": "app_id", "account": "account",
                          "permissions": "permissions",
                          "repository_selection": "repository_selection"},
        default_principal=ProducerKind.TOOL,
        default_proof=ProofKind.JWT_SIGNATURE,
        inherent_gaps=("an installation acts for an account without being a "
                       "member of it; nothing in the token says which person "
                       "installed it",),
        notes="An installation, never a person."),
    IdentityAdapter(
        provider=IdentityProvider.GITHUB_USER, name="GitHub user login",
        subject_fields=("id", "node_id", "sub"),
        issuer_fields=("iss", "host"),
        attribute_fields={"login": "login", "email": "email",
                          "org_membership": "org_membership",
                          "two_factor": "two_factor_authentication"},
        default_principal=ProducerKind.HUMAN,
        default_proof=ProofKind.BEARER_TOKEN,
        inherent_gaps=("a login name can be changed and reused; the numeric id "
                       "is the stable handle",),
        notes="Key on the numeric id, not the login."),
    IdentityAdapter(
        provider=IdentityProvider.GITLAB_CI, name="GitLab CI job token",
        attribute_fields={"project_path": "project_path",
                          "project_id": "project_id",
                          "pipeline_id": "pipeline_id", "job_id": "job_id",
                          "ref": "ref", "ref_protected": "ref_protected",
                          "environment": "environment",
                          "user_login": "user_login",
                          "runner_id": "runner_id"},
        default_principal=ProducerKind.TOOL,
        default_proof=ProofKind.JWT_SIGNATURE,
        inherent_gaps=("`user_login` is who started the pipeline, not who "
                       "approved its output",
                       "an unprotected ref means the job could be run from a "
                       "branch anyone can push"),
        notes="A workload identity. `ref_protected` is the field that makes the "
              "difference between a controlled and an arbitrary pipeline."),
    IdentityAdapter(
        provider=IdentityProvider.GITLAB_USER, name="GitLab user",
        subject_fields=("id", "sub"),
        attribute_fields={"username": "username", "email": "email",
                          "groups": "groups"},
        default_principal=ProducerKind.HUMAN,
        default_proof=ProofKind.BEARER_TOKEN),
    IdentityAdapter(
        provider=IdentityProvider.AWS_IAM, name="AWS IAM principal",
        subject_fields=("Arn", "arn", "sub", "UserId"),
        issuer_fields=("Account", "account", "iss"),
        attribute_fields={"account": "Account", "user_id": "UserId",
                          "session_name": "session_name",
                          "assumed_role": "assumed_role",
                          "mfa_authenticated": "mfa_authenticated",
                          "region": "region"},
        default_proof=ProofKind.HMAC,
        inherent_gaps=("an assumed role says which role was assumed, not which "
                       "person assumed it, unless the session name carries that "
                       "and the account is configured to require it",),
        notes="An ARN may be a person or a role; `principal_kind` has to come "
              "from the caller because the ARN alone does not say."),
    IdentityAdapter(
        provider=IdentityProvider.GCP_IAM, name="Google Cloud principal",
        subject_fields=("sub", "email", "unique_id"),
        attribute_fields={"email": "email", "project": "project_id",
                          "service_account": "service_account",
                          "hd": "hd", "google_groups": "groups"},
        default_proof=ProofKind.JWT_SIGNATURE,
        inherent_gaps=("a service account email is shaped like a person's and is "
                       "not one; only the domain distinguishes them",),
        notes="A `.gserviceaccount.com` address is a workload. That is a string "
              "check the caller makes, not one this module guesses at."),
    IdentityAdapter(
        provider=IdentityProvider.AZURE_ENTRA, name="Microsoft Entra ID",
        subject_fields=("oid", "sub"),
        issuer_fields=("iss", "tid"),
        attribute_fields={"tenant": "tid", "upn": "upn", "email": "email",
                          "groups": "groups", "roles": "roles",
                          "app_id": "appid", "amr": "amr",
                          "idtyp": "idtyp"},
        default_proof=ProofKind.JWT_SIGNATURE,
        inherent_gaps=("`oid` is unique within a tenant, so a claim without its "
                       "`tid` is ambiguous across tenants",
                       "`idtyp: app` marks a token with no user at all"),
        notes="Key on oid plus tid. `upn` is mutable."),
    IdentityAdapter(
        provider=IdentityProvider.ENTERPRISE_IDP,
        name="enterprise IdP (Okta, Ping, ADFS, Keycloak)",
        attribute_fields={"email": "email", "groups": "groups",
                          "roles": "roles", "department": "department",
                          "employee_id": "employee_id", "amr": "amr",
                          "acr": "acr", "auth_time": "auth_time"},
        default_proof=ProofKind.JWT_SIGNATURE,
        inherent_gaps=("group membership is the IdP's statement at issue time "
                       "and may have changed since",),
        notes="The generic case. Most enterprise IdPs are OIDC or SAML "
              "underneath; this exists so a deployment can name its own without "
              "misreporting itself as generic OIDC."),
    IdentityAdapter(
        provider=IdentityProvider.SERVICE_ACCOUNT, name="named service account",
        attribute_fields={"owner": "owner", "purpose": "purpose",
                          "rotated_at": "rotated_at"},
        default_principal=ProducerKind.TOOL,
        default_proof=ProofKind.BEARER_TOKEN,
        inherent_gaps=("a service account has an owner but is not that owner; "
                       "what it does is attributable to it and not to them",),
        notes="Deliberately requires an issuer: an unattributed service "
              "identity is indistinguishable from an unauthenticated caller."),
    IdentityAdapter(
        provider=IdentityProvider.MTLS, name="client certificate",
        subject_fields=("subject_dn", "subject", "CN"),
        issuer_fields=("issuer_dn", "issuer"),
        expiry_fields=("not_after", "notAfter"),
        attribute_fields={"serial": "serial", "fingerprint": "fingerprint",
                          "san": "san"},
        default_principal=ProducerKind.TOOL,
        default_proof=ProofKind.X509_CHAIN,
        inherent_gaps=("a certificate proves possession of a private key; "
                       "whether it was revoked is a separate question this record "
                       "does not answer",),
        notes="Chain validation happens at the TLS terminator, which is what "
              "`verified_by` should name."),
    IdentityAdapter(
        provider=IdentityProvider.SSH_KEY, name="SSH key",
        subject_fields=("fingerprint", "key_id", "sub"),
        default_principal=ProducerKind.HUMAN,
        default_proof=ProofKind.SSH_SIGNATURE,
        inherent_gaps=("a key identifies a key; who holds it is a mapping "
                       "someone else maintains",)),
    IdentityAdapter(
        provider=IdentityProvider.GPG_KEY, name="OpenPGP key",
        subject_fields=("fingerprint", "key_id", "sub"),
        default_principal=ProducerKind.HUMAN,
        default_proof=ProofKind.GPG_SIGNATURE,
        inherent_gaps=("a signature proves the key signed; whether that key "
                       "belongs to the named person is a trust decision",)),
    IdentityAdapter(
        provider=IdentityProvider.API_KEY, name="API key",
        subject_fields=("key_id", "sub"),
        default_principal=ProducerKind.TOOL,
        default_proof=ProofKind.BEARER_TOKEN,
        inherent_gaps=("possession of a key proves possession of a key. It is "
                       "weaker than a person authenticating, and deliberately "
                       "not counted as an established identity",)),
    IdentityAdapter(
        provider=IdentityProvider.SELF_ASSERTED, name="caller's own claim",
        subject_fields=("subject", "user", "approver", "sub"),
        issuer_fields=(),
        default_principal=ProducerKind.EXTERNAL,
        default_proof=ProofKind.NONE,
        inherent_gaps=("nothing checked this; it is attributable to a claim of "
                       "identity rather than to an established one",),
        notes="The honest default. Not a lesser kind of identity, and not the "
              "same kind either."),
)

#: provider → adapter. Built from one list so the registry cannot disagree with
#: itself about which providers exist.
ADAPTERS: Mapping[IdentityProvider, IdentityAdapter] = {
    a.provider: a for a in _ADAPTER_LIST}


def adapter_for(provider: Any) -> IdentityAdapter:
    """The adapter for this provider, or a named refusal.

    `UNKNOWN` and `RELEASE_GATE` have none on purpose: the first has no assertion
    shape to read, and the second is not an identity provider.
    """
    resolved = IdentityProvider(provider)
    adapter = ADAPTERS.get(resolved)
    if adapter is None:
        raise IdentityError(
            f"no adapter for {resolved.value}. "
            + ("release-gate does not issue identities (Invariant 15)"
               if resolved is IdentityProvider.RELEASE_GATE else
               "an assertion with no known shape cannot be read into a claim; "
               "record it as SELF_ASSERTED, which says exactly that"))
    return adapter


def claim_from(provider: Any, assertion: Mapping[str, Any], **kw: Any) -> IdentityClaim:
    """Read an assertion from a named provider. The one call a host needs."""
    return adapter_for(provider).claim(assertion, **kw)


# ── attribution ──────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Attribution:
    """What an authorisation on this identity can be attributed to.

    "Approval must be attributable" is not a boolean, so this is not one. It is
    a handle, a principal kind, the strength of what established it, and the list
    of what did not get established.
    """

    claim: IdentityClaim
    attributable_to: str
    established: bool
    basis: str
    #: Everything that was not established. Empty means nothing was found
    #: missing, which is not the same as everything having been checked — the
    #: claim's own `unverified_aspects` carry that.
    gaps: Tuple[str, ...] = ()
    issuer_accepted: Optional[bool] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "gaps", tuple(self.gaps))

    @property
    def is_a_person(self) -> bool:
        return self.claim.is_a_person

    @property
    def machine_self_authorisation(self) -> bool:
        """Whether a workload — positively determined, not merely un-established
        as a person — is behind this.

        Reads `is_a_service` rather than `not is_a_person`: a self-asserted claim
        about a human is not established to be a person and is not a machine
        either, and calling it one would report a determination nobody made.

        Reported rather than refused: release-gate cannot know whether a given
        deployment legitimately authorises through a service account. But it is
        reported every time, because an autonomous system approving its own
        output is what this whole system sits between (Invariant 15).
        """
        return self.claim.is_a_service

    @property
    def principal_unstated(self) -> bool:
        """Neither a person nor a workload was established. The third state."""
        return not self.claim.principal_stated

    @property
    def links_identities(self) -> bool:
        """Unconditionally False. Two claims from two providers are two
        identities, even when the same human is behind both. Deciding they are
        one person is identity management, which is somebody else's system and
        not one to be improvised inside an audit record."""
        return False

    @property
    def authorises(self) -> bool:
        """Unconditionally False. This says who; authorisation is a separate act
        and a separate record."""
        return False

    @property
    def reattributable(self) -> bool:
        """Whether someone could later trace this back to a real account.

        The practical test of attributability: a handle naming an issuer and a
        subject can be looked up in that issuer months later. A bare string
        cannot.
        """
        return bool(self.claim.issuer and self.claim.subject
                    and self.claim.provider is not IdentityProvider.UNKNOWN)

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "attribution",
                "attributable_to": self.attributable_to,
                "established": self.established, "basis": self.basis,
                "is_a_person": self.is_a_person,
                "machine_self_authorisation": self.machine_self_authorisation,
                "principal_unstated": self.principal_unstated,
                "reattributable": self.reattributable,
                "issuer_accepted": self.issuer_accepted,
                "gaps": list(self.gaps),
                "links_identities": False, "authorises": False,
                "claim": self.claim.to_dict()}

    def render(self) -> str:
        lines = [f"ATTRIBUTABLE TO: {self.attributable_to}",
                 f"  established: {self.established} — {self.basis}"]
        if self.machine_self_authorisation:
            lines.append("  This is a workload, not a person. An approval "
                         "recorded against it is a machine authorising machine "
                         "work.")
        elif self.principal_unstated:
            lines.append("  Nothing says whether this is a person. Unknown "
                         "rather than assumed either way.")
        if not self.reattributable:
            lines.append("  Not re-attributable: nobody could look this up in an "
                         "issuer later.")
        for gap in self.gaps:
            lines.append(f"  NOT ESTABLISHED: {gap}")
        return "\n".join(lines)


def attribution_of(claim: IdentityClaim, *,
                   trusted_issuers: Optional[Iterable[str]] = None,
                   now: Optional[str] = None) -> Attribution:
    """What an approval on this identity can be attributed to.

    `trusted_issuers` is a caller-supplied allowlist, not a policy this module
    holds an opinion about. An issuer outside it becomes a gap rather than a
    failure: release-gate is not the thing that decides which IdP an
    organisation federates with, and refusing here would be that decision made
    by the wrong system. Passing none leaves the question unasked, which is
    reported as unasked rather than as a pass.
    """
    gaps = list(claim.unverified_aspects)

    accepted: Optional[bool] = None
    if trusted_issuers is not None:
        allowed = set(trusted_issuers)
        accepted = claim.issuer in allowed
        if not accepted:
            gaps.append(
                f"{claim.issuer or 'this claim'} is not among the issuers this "
                "caller named as trusted; the assertion may be genuine and still "
                "come from somewhere nobody decided to accept")
    else:
        gaps.append("no issuer allowlist was supplied, so whether this issuer is "
                    "accepted here was not asked")

    if claim.issuer_trust is None:
        gaps.append("no explicit trust decision records that this issuer is "
                    "accepted for this purpose")

    if claim.declared_expired(now):
        gaps.append(f"the issuer declared this assertion expired at "
                    f"{claim.expires_at}; that is the issuer's own claim, not a "
                    "validation release-gate performed")

    if claim.is_a_service:
        gaps.append("the principal is a workload; no person is answerable for "
                    "what is authorised under it")
    elif not claim.principal_stated:
        gaps.append("nothing says whether this principal is a person or a "
                    "service, so whether anyone is answerable for what is "
                    "authorised under it is unknown rather than settled")

    if claim.status is EpistemicStatus.VERIFIED:
        basis = (f"{claim.verified_by} checked a {claim.proof.value}")
    elif claim.status is EpistemicStatus.OBSERVED:
        basis = ("release-gate read this from a boundary it relies on; no proof "
                 "was checked here, and the boundary is what stands behind it")
    elif claim.status is EpistemicStatus.REFUTED:
        basis = ("a check was made and it failed; this is attributable to an "
                 "assertion that did not hold")
    else:
        basis = ("nothing established this beyond the claim itself, so it is "
                 "attributable to a claim of identity rather than to an "
                 "established one")

    return Attribution(
        claim=claim, attributable_to=claim.attributable_to,
        established=claim.established, basis=basis,
        gaps=tuple(dict.fromkeys(gaps)), issuer_accepted=accepted)


# ── the bridge to what approvals already record ──────────────────────────────

#: provider → the `AuthSource` an approval has always carried. One mapping, so
#: the new vocabulary and the serialised one cannot drift.
_AUTH_SOURCE: Mapping[IdentityProvider, str] = {
    IdentityProvider.OIDC: "OIDC",
    IdentityProvider.GITHUB_ACTIONS: "OIDC",
    IdentityProvider.GITLAB_CI: "OIDC",
    IdentityProvider.GCP_IAM: "OIDC",
    IdentityProvider.AZURE_ENTRA: "OIDC",
    IdentityProvider.SAML: "PLATFORM_SSO",
    IdentityProvider.ENTERPRISE_IDP: "PLATFORM_SSO",
    IdentityProvider.GITHUB_USER: "PLATFORM_SSO",
    IdentityProvider.GITLAB_USER: "PLATFORM_SSO",
    IdentityProvider.GITHUB_APP: "SIGNED_TOKEN",
    IdentityProvider.MTLS: "SIGNED_TOKEN",
    IdentityProvider.AWS_IAM: "SIGNED_TOKEN",
    IdentityProvider.SSH_KEY: "SSH_KEY",
    IdentityProvider.GPG_KEY: "GPG_KEY",
    IdentityProvider.API_KEY: "API_KEY",
    IdentityProvider.SERVICE_ACCOUNT: "API_KEY",
    IdentityProvider.SELF_ASSERTED: "ASSERTED",
    IdentityProvider.UNKNOWN: "UNKNOWN",
}


def auth_source_for(claim: IdentityClaim) -> Any:
    """The `AuthSource` this claim amounts to, for the record approvals keep.

    Deliberately narrower than the claim. `AuthSource.identity_established` is a
    frozenset membership test, and a claim that was never verified must not
    satisfy it merely because its provider usually is — so an unestablished claim
    maps to `ASSERTED` whatever it came from. That is the direction that fails
    safe: an unverified OIDC token read as established would be the whole
    boundary defeated by a missing signature check.
    """
    from release_gate.assurance.approval import AuthSource

    if not claim.established:
        return AuthSource.ASSERTED
    if claim.status is EpistemicStatus.OBSERVED:
        # A boundary handed this over and nobody is named as having checked a
        # proof. That is `PLATFORM_SSO` — a platform established it — and not the
        # provider's full strength: mapping an OBSERVED claim to SIGNED_TOKEN
        # would put "a signature was checked" on a record where `verified_by` is
        # empty.
        return AuthSource.PLATFORM_SSO
    return AuthSource(_AUTH_SOURCE.get(claim.provider, "UNKNOWN"))

"""Authorship and verification correlation — who checked the work, relative to who did it.

**This is not a judgement about AI-written code.** Code an agent wrote is not
less trustworthy for that, and nothing here treats it so: no finding fires
because an agent, a model or a particular vendor wrote something. What this
module asks is the question review has always asked of people: *was the work
checked by someone other than the one who did it?*

When one agent session writes the implementation, the tests, the security
review and the fix, those are four artifacts and one source. The tests pass
because they encode the same understanding the code does; the review agrees
because it is the same reading. That is not unsafe, and it is not
verification by anyone else. Release-gate says so: **verification independence
low** — the same thing it says when one person writes a change, its tests and
its approval. And when the implementation came from one agent, the tests from a
person, the static analysis from CodeQL, the behavioural checks from a model of
another provider and the approval from the owner, it says that instead: the
checks share nothing with the author.

**Authorship is read, never guessed.** It arrives as an `authorship` record —
from CI metadata, a commit's declared trailers, a tool's own metadata, or a
plain declaration — in the provenance vocabulary `correlation.py` already reads
(`provider`, `model_family`, `session`, `agent`, `person`, `toolchain`,
`prompt_lineage`, `generated_from`). Nothing is inferred from a coding style, a
commit message's wording, a branch name or a model id. **Unknown stays
UNKNOWN**: a claim whose author nobody stated is `AUTHOR_UNKNOWN`, and a check
that states nothing about what produced it is neither independent of the
author nor shared with them — it is unknown, and counted that way.

**What is compared.** For each claim, the authors of what it is about (roles
`implementation` and `fix`, scoped to the claim or to the whole case) against
the sources the claim resolution actually counted as support — stale, withheld
or inadmissible support is not verification of this release — plus any
verification-role authorship statement (tests, a review, an approval) bearing on
the claim. A source shares the author when it carries any of the author's
provenance keys in an authoring dimension: one session, one agent, one model
family, one person, one toolchain, one prompt lineage, one generated input. Who
*reported* a record — the CI system that stated both authorships, the producer
id — is not authorship, and is not compared.

**What it does.** By default it reports: RG-INDEP-007 (every check shares the
author) and RG-INDEP-008 (independence from the author cannot be established)
are advisory. A resolution policy can require it for required claims
(`ResolutionPolicy.author_independence`), and then a required claim checked only
by its author takes the declared effect, and one whose independence cannot be
established holds — unknown is not a pass. Nothing here is a score.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from release_gate.assurance.canonical import digest_object
from release_gate.assurance.correlation import (
    DEFAULT_INDEPENDENCE_POLICY,
    IndependencePolicy,
    ProvenanceDimension,
    ProvenanceIndex,
    SourceProvenance,
    assess_independence,
    provenance_from,
)
from release_gate.assurance.evidence import (
    EpistemicStatus,
    EvidenceRecord,
    EvidenceType,
    Producer,
    VerificationMethod,
)

__all__ = [
    "AUTHORSHIP_SCHEMA_VERSION",
    "AuthorIndependence",
    "AuthorRelation",
    "AuthorshipAssessment",
    "AuthorshipBasis",
    "AuthorshipError",
    "AuthorshipRole",
    "AuthorshipStatement",
    "ClaimAuthorship",
    "VerifierRelation",
    "assess_authorship",
    "authorship_from_ci",
    "authorship_of",
]

AUTHORSHIP_SCHEMA_VERSION = 1


class AuthorshipError(ValueError):
    """An authorship statement that could not mean what it says."""


class AuthorshipRole(str, Enum):
    """What a source did. The first two are the work; the rest check it."""

    IMPLEMENTATION = "implementation"
    FIX = "fix"
    SPECIFICATION = "specification"
    TESTS = "tests"
    CODE_REVIEW = "code_review"
    SECURITY_REVIEW = "security_review"
    BEHAVIORAL_VERIFICATION = "behavioral_verification"
    FORMAL_VERIFICATION = "formal_verification"
    STATIC_ANALYSIS = "static_analysis"
    APPROVAL = "approval"
    OTHER = "other"


#: The roles whose authors a claim's checks are compared against.
_WORK = frozenset({AuthorshipRole.IMPLEMENTATION, AuthorshipRole.FIX})


class AuthorshipBasis(str, Enum):
    """Where the statement came from. All of them are statements, none a proof."""

    CI_METADATA = "ci_metadata"          # a CI system's own variables
    COMMIT_METADATA = "commit_metadata"  # a commit's declared trailers or author fields
    TOOL_METADATA = "tool_metadata"      # an agent or tool's own run record
    DECLARED = "declared"                # somebody said so


#: Correlation's provenance vocabulary, which is the only one read here, plus
#: `person`: correlation's person dimension is named `reviewer` — one person,
#: twice — whatever they did, and a person who wrote the tests is stated as a
#: `person` and compared in that dimension.
_PROVENANCE_KEYS = frozenset({
    "provider", "organization", "model_family", "model_version", "model", "session",
    "run_id", "agent", "originating_agent", "person", "reviewer", "human_reviewer",
    "toolchain", "prompt_lineage", "dataset", "datasets", "generated_from",
    "shared_artifacts", "relied_on"})

#: Dimensions in which a shared key means a shared author. Who reported a record
#: (`producer`, `verifier`) and what it derives from (`ancestry`) are not who
#: authored it, and a test dataset is not an author.
_AUTHORING = frozenset({
    ProvenanceDimension.PROVIDER, ProvenanceDimension.MODEL_FAMILY,
    ProvenanceDimension.SESSION, ProvenanceDimension.AGENT, ProvenanceDimension.REVIEWER,
    ProvenanceDimension.TOOLCHAIN, ProvenanceDimension.PROMPT_LINEAGE,
    ProvenanceDimension.GENERATED_FROM, ProvenanceDimension.LINEAGE})
_AUTHORING_PREFIXES = tuple(f"{d.value}:" for d in _AUTHORING)


def _authoring(keys: Iterable[str]) -> Set[str]:
    return {k for k in keys if k.startswith(_AUTHORING_PREFIXES)}


def _text(value: Any) -> str:
    return str(value).strip() if isinstance(value, (str, int)) and not isinstance(
        value, bool) else ""


def _ids(value: Any) -> Tuple[str, ...]:
    items = value if isinstance(value, (list, tuple)) else [value]
    return tuple(dict.fromkeys(_text(v) for v in items if _text(v)))


def _provenance(raw: Any) -> Dict[str, Any]:
    block = dict(raw) if isinstance(raw, Mapping) else {}
    if _text(block.get("author")) and not _text(block.get("person")):
        block["person"] = block["author"]
    kept: Dict[str, Any] = {}
    for key in sorted(block):
        value = block[key]
        if key not in _PROVENANCE_KEYS:
            continue
        if isinstance(value, (list, tuple)):
            values = [_text(v) for v in value if _text(v)]
            if values:
                kept[key] = values
        elif _text(value):
            kept[key] = _text(value)
    return kept


def _correlation_block(provenance: Mapping[str, Any]) -> Dict[str, Any]:
    """The statement's provenance as correlation reads it: a person is `reviewer`."""
    block = dict(provenance)
    if block.get("person") and not block.get("reviewer"):
        block["reviewer"] = block["person"]
    return block


@dataclass(frozen=True)
class AuthorshipStatement:
    """Who did one piece of the work, as somebody stated it."""

    role: AuthorshipRole
    provenance: Mapping[str, Any] = field(default_factory=dict)
    basis: AuthorshipBasis = AuthorshipBasis.DECLARED
    subject: str = ""
    claims: Tuple[str, ...] = ()
    #: Evidence this statement says the source authored — declared envelope ids
    #: or record ids. A test result named here is a test the source wrote.
    evidence: Tuple[str, ...] = ()
    reference: str = ""
    #: What the CI system stated, kept verbatim beside the provenance it yields.
    ci: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        try:
            object.__setattr__(self, "role", AuthorshipRole(
                str(getattr(self.role, "value", self.role)).strip().lower()))
        except ValueError as exc:
            raise AuthorshipError(
                f"authorship role {self.role!r} is not one release-gate reads; use one "
                f"of: {', '.join(r.value for r in AuthorshipRole)}") from exc
        try:
            object.__setattr__(self, "basis", AuthorshipBasis(
                str(getattr(self.basis, "value", self.basis)).strip().lower()))
        except ValueError as exc:
            raise AuthorshipError(
                f"authorship basis {self.basis!r} is not one of: "
                + ", ".join(b.value for b in AuthorshipBasis)) from exc
        object.__setattr__(self, "provenance", _provenance(self.provenance))
        object.__setattr__(self, "claims", _ids(self.claims))
        object.__setattr__(self, "evidence", _ids(self.evidence))
        object.__setattr__(self, "subject", _text(self.subject))
        object.__setattr__(self, "reference", _text(self.reference))
        object.__setattr__(self, "ci", {str(k): _text(v) for k, v in
                                        dict(self.ci or {}).items() if _text(v)})

    @property
    def states_an_author(self) -> bool:
        """Does it say anything about who? A role alone names nobody."""
        return bool(self.provenance)

    def to_dict(self) -> Dict[str, Any]:
        return {"role": self.role.value, "basis": self.basis.value,
                "subject": self.subject, "claims": list(self.claims),
                "evidence": list(self.evidence), "reference": self.reference,
                "ci": dict(self.ci), "provenance": dict(self.provenance),
                "schema_version": AUTHORSHIP_SCHEMA_VERSION}

    @property
    def statement_id(self) -> str:
        return f"auth_{digest_object(self.to_dict())[7:23]}"

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "AuthorshipStatement":
        if not isinstance(data, Mapping):
            raise AuthorshipError("an authorship statement must be an object")
        return cls(role=data.get("role") or "", provenance=data.get("provenance") or {},
                   basis=data.get("basis") or AuthorshipBasis.DECLARED.value,
                   subject=data.get("subject") or "",
                   claims=data.get("claims") or (), evidence=data.get("evidence") or (),
                   reference=data.get("reference") or "",
                   ci=data.get("ci") if isinstance(data.get("ci"), Mapping) else {})

    def to_record(self, *, producer: Producer, source: str) -> EvidenceRecord:
        """The statement as evidence: an ATTESTATION, DECLARED, carrying its provenance.

        `content.provenance` is what `correlation.py` reads, so the statement
        is placed in correlation groups like any other source.
        """
        return EvidenceRecord.from_producer(
            {"authorship": self.to_dict(),
             "provenance": _correlation_block(self.provenance)},
            evidence_type=EvidenceType.ATTESTATION, source=source, producer=producer,
            status=EpistemicStatus.DECLARED,
            coverage_note=(f"a statement of who did the {self.role.value} work"
                           + (f" on {self.subject}" if self.subject else "")
                           + f" ({self.basis.value}); it names a source, and "
                             "establishes nothing about the work's quality"))


def authorship_of(record: Any) -> Optional[AuthorshipStatement]:
    """The authorship statement a record carries, if it is one."""
    content = getattr(record, "content", None)
    block = content.get("authorship") if isinstance(content, Mapping) else None
    if not isinstance(block, Mapping):
        return None
    try:
        return AuthorshipStatement.from_dict(block)
    except AuthorshipError:
        return None


# ── CI metadata ──────────────────────────────────────────────────────────────

def authorship_from_ci(env: Mapping[str, str], *, role: Any = AuthorshipRole.IMPLEMENTATION,
                       provenance: Optional[Mapping[str, Any]] = None,
                       subject: str = "", claims: Sequence[str] = (),
                       evidence: Sequence[str] = ()) -> AuthorshipStatement:
    """An authorship statement from a CI system's own variables, plus what the job states.

    Reads GitHub Actions and GitLab CI. What the CI system says is kept under
    `ci` exactly as it said it: which account triggered the run, which commit,
    which run. Only one thing there becomes provenance on its own: a GitHub App
    account, which GitHub itself marks with a `[bot]` suffix, is an automated
    actor and is recorded as the `agent`. Any other account may be a person or a
    machine user, and CI does not say which, so it is not placed — the job
    states that through `provenance` (`person`, `agent`, `session`,
    `model_family`, `provider`, …), from whatever the agent platform or the
    pipeline knows. Nothing is read from a commit message's wording or a branch
    name.
    """
    facts: Dict[str, str] = {}
    stated = dict(provenance or {})
    reference = ""
    if _text(env.get("GITHUB_ACTIONS")).lower() == "true":
        facts = {"system": "github_actions",
                 "actor": _text(env.get("GITHUB_ACTOR")),
                 "triggering_actor": _text(env.get("GITHUB_TRIGGERING_ACTOR")),
                 "repository": _text(env.get("GITHUB_REPOSITORY")),
                 "commit": _text(env.get("GITHUB_SHA")),
                 "workflow": _text(env.get("GITHUB_WORKFLOW")),
                 "run_id": _text(env.get("GITHUB_RUN_ID")),
                 "ref": _text(env.get("GITHUB_REF"))}
        server = _text(env.get("GITHUB_SERVER_URL")) or "https://github.com"
        if facts["repository"] and facts["run_id"]:
            reference = f"{server}/{facts['repository']}/actions/runs/{facts['run_id']}"
        actor = facts["actor"]
        if actor.endswith("[bot]") and not _text(stated.get("agent")):
            stated["agent"] = actor
    elif _text(env.get("GITLAB_CI")).lower() == "true":
        facts = {"system": "gitlab_ci",
                 "actor": _text(env.get("GITLAB_USER_LOGIN")),
                 "repository": _text(env.get("CI_PROJECT_PATH")),
                 "commit": _text(env.get("CI_COMMIT_SHA")),
                 "pipeline_id": _text(env.get("CI_PIPELINE_ID")),
                 "job_id": _text(env.get("CI_JOB_ID"))}
        reference = _text(env.get("CI_PIPELINE_URL")) or _text(env.get("CI_JOB_URL"))
    else:
        raise AuthorshipError(
            "no CI system recognised in the environment (GitHub Actions or GitLab CI); "
            "state the authorship with `basis: declared` instead")
    return AuthorshipStatement(
        role=role, provenance=stated, basis=AuthorshipBasis.CI_METADATA,
        subject=subject or facts.get("commit", ""), claims=tuple(claims),
        evidence=tuple(evidence), reference=reference,
        ci={k: v for k, v in facts.items() if v})


# ── the comparison ───────────────────────────────────────────────────────────

class AuthorRelation(str, Enum):
    """How one supporting source stands to a claim's author."""

    SHARES_AUTHOR = "SHARES_AUTHOR"
    INDEPENDENT_OF_AUTHOR = "INDEPENDENT_OF_AUTHOR"
    UNKNOWN = "UNKNOWN"                      # it states nothing that places it


class AuthorIndependence(str, Enum):
    """Whether a claim was checked by anyone but its author. Never a score."""

    AUTHOR_UNKNOWN = "AUTHOR_UNKNOWN"        # nobody stated who did the work
    NO_VERIFICATION = "NO_VERIFICATION"      # nothing counted supports it
    LOW = "LOW"                              # every check shares the author
    UNDETERMINED = "UNDETERMINED"            # none independent, some unplaceable
    INDEPENDENT = "INDEPENDENT"              # at least one check shares nothing


_TYPE_ROLE = {
    EvidenceType.TEST_RESULT: AuthorshipRole.TESTS,
    EvidenceType.EVAL_RESULT: AuthorshipRole.BEHAVIORAL_VERIFICATION,
    EvidenceType.TRACE: AuthorshipRole.BEHAVIORAL_VERIFICATION,
    EvidenceType.SIMULATION_RESULT: AuthorshipRole.BEHAVIORAL_VERIFICATION,
    EvidenceType.FORMAL_PROOF: AuthorshipRole.FORMAL_VERIFICATION,
    EvidenceType.STATIC_FINDING: AuthorshipRole.STATIC_ANALYSIS,
    EvidenceType.HUMAN_REVIEW: AuthorshipRole.CODE_REVIEW,
    EvidenceType.APPROVAL: AuthorshipRole.APPROVAL,
}
_METHOD_ROLE = {
    VerificationMethod.TEST_SUITE: AuthorshipRole.TESTS,
    VerificationMethod.PROPERTY_TEST: AuthorshipRole.TESTS,
    VerificationMethod.FORMAL_PROOF: AuthorshipRole.FORMAL_VERIFICATION,
    VerificationMethod.THEOREM_PROVER: AuthorshipRole.FORMAL_VERIFICATION,
    VerificationMethod.STATIC_ANALYSIS: AuthorshipRole.STATIC_ANALYSIS,
    VerificationMethod.TYPE_CHECKER: AuthorshipRole.STATIC_ANALYSIS,
    VerificationMethod.COMPILER: AuthorshipRole.STATIC_ANALYSIS,
    VerificationMethod.HUMAN_REVIEW: AuthorshipRole.CODE_REVIEW,
    VerificationMethod.CROSS_MODEL_REVIEW: AuthorshipRole.CODE_REVIEW,
    VerificationMethod.SIMULATION: AuthorshipRole.BEHAVIORAL_VERIFICATION,
    VerificationMethod.EXPERIMENT: AuthorshipRole.BEHAVIORAL_VERIFICATION,
    VerificationMethod.RUNTIME_ASSERTION: AuthorshipRole.BEHAVIORAL_VERIFICATION,
}


@dataclass(frozen=True)
class VerifierRelation:
    source_id: str
    source_kind: str                 # evidence | verification | authorship
    role: AuthorshipRole
    relation: AuthorRelation
    shared: Tuple[str, ...] = ()     # the author's keys this source carries

    def to_dict(self) -> Dict[str, Any]:
        return {"source_id": self.source_id, "source_kind": self.source_kind,
                "role": self.role.value, "relation": self.relation.value,
                "shared": list(self.shared)}


@dataclass(frozen=True)
class ClaimAuthorship:
    claim_id: str
    status: AuthorIndependence
    basis: str
    authors: Tuple[str, ...] = ()            # authorship statement ids
    author_keys: Tuple[str, ...] = ()
    verifiers: Tuple[VerifierRelation, ...] = ()
    independent_groups: int = 0
    required: Optional[bool] = None

    def of(self, relation: AuthorRelation) -> Tuple[VerifierRelation, ...]:
        return tuple(v for v in self.verifiers if v.relation is relation)

    def to_dict(self) -> Dict[str, Any]:
        return {"claim_id": self.claim_id, "status": self.status.value,
                "basis": self.basis, "required": self.required,
                "authors": list(self.authors), "author_keys": list(self.author_keys),
                "verifiers": [v.to_dict() for v in self.verifiers],
                "sharing_author": len(self.of(AuthorRelation.SHARES_AUTHOR)),
                "independent_of_author": len(self.of(AuthorRelation.INDEPENDENT_OF_AUTHOR)),
                "unknown": len(self.of(AuthorRelation.UNKNOWN)),
                "independent_groups": self.independent_groups}


@dataclass(frozen=True)
class AuthorshipAssessment:
    statements: Tuple[AuthorshipStatement, ...] = ()
    claims: Tuple[ClaimAuthorship, ...] = ()
    policy_ref: str = ""

    @property
    def present(self) -> bool:
        """Did anybody state any authorship? Without it, every claim is AUTHOR_UNKNOWN."""
        return bool(self.statements)

    def of(self, status: AuthorIndependence) -> Tuple[ClaimAuthorship, ...]:
        return tuple(c for c in self.claims if c.status is status)

    def claim(self, claim_id: str) -> Optional[ClaimAuthorship]:
        return next((c for c in self.claims if c.claim_id == claim_id), None)

    def to_dict(self) -> Dict[str, Any]:
        # With no statement anywhere every row is AUTHOR_UNKNOWN; the count says
        # so without listing each claim to repeat it.
        return {"record_type": "authorship_assessment",
                "schema_version": AUTHORSHIP_SCHEMA_VERSION,
                "policy": self.policy_ref, "present": self.present,
                "statements": [{"statement_id": s.statement_id, **s.to_dict()}
                               for s in self.statements],
                "by_status": {s.value: len(self.of(s)) for s in AuthorIndependence},
                "claims": ([c.to_dict() for c in self.claims] if self.present
                           else []),
                "is_a_judgement_of_ai_written_code": False}

    def render(self) -> str:
        lines = [f"{len(self.statements)} authorship statement(s); compared under "
                 f"{self.policy_ref}"]
        for row in self.claims:
            lines.append(f"[{row.status.value:>15}]  {row.claim_id}")
            lines.append(f"                   {row.basis}")
        lines.append("This is about whether the work was checked by anyone but its "
                     "author — not about who or what wrote it.")
        return "\n".join(lines)


def _in_scope(statement: AuthorshipStatement, claim_id: str) -> bool:
    return not statement.claims or claim_id in statement.claims


def assess_authorship(claim_graph: Any, resolution: Any, records: Iterable[Any], *,
                      policy: IndependencePolicy = DEFAULT_INDEPENDENCE_POLICY
                      ) -> Optional[AuthorshipAssessment]:
    """Compare each claim's counted support against the stated authors of its subject.

    None when the case has no claims. Every claim gets a row; without any
    authorship statement every row is AUTHOR_UNKNOWN, which is the answer.
    """
    if claim_graph is None or not len(claim_graph):
        return None
    held = [r for r in records if isinstance(r, EvidenceRecord)]
    stated: List[Tuple[EvidenceRecord, AuthorshipStatement]] = []
    for record in sorted(held, key=lambda r: r.evidence_id):
        statement = authorship_of(record)
        if statement is not None:
            stated.append((record, statement))
    if not stated:
        # Nobody said who did anything: every claim's author is UNKNOWN, and
        # there is nothing to compare its checks against.
        return AuthorshipAssessment(claims=tuple(
            ClaimAuthorship(c.claim_id, AuthorIndependence.AUTHOR_UNKNOWN,
                            "authorship of what this claim is about is not stated; it "
                            "is UNKNOWN, and nothing is inferred",
                            required=getattr(resolution.of(c.claim_id), "required", None)
                            if resolution is not None else None)
            for c in sorted(claim_graph.claims, key=lambda c: c.claim_id)),
            policy_ref=policy.ref)
    index = ProvenanceIndex(held, policy)
    authorship_ids = {r.evidence_id for r, _ in stated}
    by_id = {r.evidence_id: r for r in held}

    # A verification-role statement that names the evidence it authored lends
    # that evidence its keys: the test results are the tests' author's.
    lent: Dict[str, List[Tuple[Set[str], bool, AuthorshipRole]]] = {}
    def who(record: EvidenceRecord, statement: AuthorshipStatement) -> SourceProvenance:
        # The statement's own provenance, never its record's producer: the CI
        # system or person who *reported* an authorship did not do the work.
        return provenance_from(_correlation_block(statement.provenance),
                               source_id=record.evidence_id, source_kind="authorship")

    for record, statement in stated:
        if statement.role in _WORK or not statement.evidence:
            continue
        source = who(record, statement)
        for reference in statement.evidence:
            target = index.resolve(reference)
            if target is not None:
                lent.setdefault(target, []).append(
                    (_authoring(source.keys(policy)), source.determinable(policy),
                     statement.role))

    rows: List[ClaimAuthorship] = []
    for claim in sorted(claim_graph.claims, key=lambda c: c.claim_id):
        cid = claim.claim_id
        resolved = resolution.of(cid) if resolution is not None else None
        required = getattr(resolved, "required", None)
        authors = [(r, s) for r, s in stated if s.role in _WORK and _in_scope(s, cid)]
        author_keys: Set[str] = set()
        for record, statement in authors:
            author_keys |= _authoring(who(record, statement).keys(policy))
        author_ids = tuple(s.statement_id for _, s in authors)
        if not author_keys:
            basis = ("authorship of what this claim is about is not stated; it is "
                     "UNKNOWN, and nothing is inferred" if not authors else
                     f"{len(authors)} authorship statement(s) name a role and no "
                     "author, so who did the work is UNKNOWN")
            rows.append(ClaimAuthorship(cid, AuthorIndependence.AUTHOR_UNKNOWN, basis,
                                        authors=author_ids, required=required))
            continue

        relations: List[VerifierRelation] = []
        sources: List[Tuple[SourceProvenance, Set[str], bool]] = []

        def place(source_id: str, kind: str, role: AuthorshipRole,
                  provenance: Optional[SourceProvenance]) -> None:
            keys = _authoring(provenance.keys(policy)) if provenance is not None else set()
            determinable = bool(provenance is not None and provenance.determinable(policy))
            for extra, placed, named_role in lent.get(source_id, ()):
                keys |= extra
                determinable = determinable or placed
                role = named_role
            shared = keys & author_keys
            relation = (AuthorRelation.SHARES_AUTHOR if shared
                        else AuthorRelation.INDEPENDENT_OF_AUTHOR if determinable
                        else AuthorRelation.UNKNOWN)
            relations.append(VerifierRelation(source_id, kind, role, relation,
                                              tuple(sorted(shared))))
            if relation is AuthorRelation.INDEPENDENT_OF_AUTHOR and provenance is not None:
                sources.append((provenance, keys, determinable))

        attempts = {a.verification_id: a for a in claim.verification_attempts}
        for item in (getattr(resolved, "items", ()) or ()):
            if getattr(item.role, "value", item.role) != "SUPPORTS":
                continue
            if item.item_kind == "evidence" and item.item_id in by_id \
                    and item.item_id not in authorship_ids:
                record = by_id[item.item_id]
                place(item.item_id, "evidence",
                      _TYPE_ROLE.get(record.evidence_type, AuthorshipRole.OTHER),
                      index.of(item.item_id))
            elif item.item_kind == "verification" and item.item_id in attempts:
                attempt = attempts[item.item_id]
                place(item.item_id, "verification",
                      _METHOD_ROLE.get(attempt.method, AuthorshipRole.OTHER),
                      index.attempt_source(attempt))
        for record, statement in stated:
            if statement.role in _WORK or statement.evidence or not _in_scope(statement, cid):
                continue
            place(record.evidence_id, "authorship", statement.role,
                  who(record, statement))

        rows.append(_claim_row(cid, required, author_ids, author_keys, relations,
                               sources, policy))
    return AuthorshipAssessment(statements=tuple(s for _, s in stated),
                                claims=tuple(rows), policy_ref=policy.ref)


def _claim_row(cid: str, required: Optional[bool], authors: Tuple[str, ...],
               author_keys: Set[str], relations: List[VerifierRelation],
               independent: List[Tuple[SourceProvenance, Set[str], bool]],
               policy: IndependencePolicy) -> ClaimAuthorship:
    relations.sort(key=lambda v: (v.relation.value, v.source_kind, v.source_id))
    shares = [v for v in relations if v.relation is AuthorRelation.SHARES_AUTHOR]
    unknown = [v for v in relations if v.relation is AuthorRelation.UNKNOWN]
    clear = [v for v in relations if v.relation is AuthorRelation.INDEPENDENT_OF_AUTHOR]
    keys = tuple(sorted(author_keys))
    common = sorted({k for v in shares for k in v.shared})
    groups = 0
    if not relations:
        status = AuthorIndependence.NO_VERIFICATION
        basis = "nothing the resolution counted supports it, so nothing checked the work"
    elif clear:
        groups = assess_independence([p for p, _, _ in independent], policy) \
            .independent_groups if independent else 0
        status = AuthorIndependence.INDEPENDENT
        basis = (f"{len(clear)} of {len(relations)} supporting source(s) share no "
                 f"provenance with the author ({', '.join(keys[:3])})"
                 + (f", across {groups} independent group(s)" if groups else "")
                 + (f"; {len(shares)} share it" if shares else "")
                 + (f"; {len(unknown)} state too little to place" if unknown else ""))
    elif not unknown:
        status = AuthorIndependence.LOW
        basis = (f"verification independence low: every one of the {len(relations)} "
                 f"source(s) supporting it shares provenance with its author "
                 f"({', '.join(common[:4])}). The work was checked by its author, "
                 "which is a statement about correlation, not about who or what wrote it")
    else:
        status = AuthorIndependence.UNDETERMINED
        basis = (f"none of the {len(relations)} supporting source(s) is shown to be "
                 f"independent of the author: {len(shares)} share its provenance and "
                 f"{len(unknown)} state nothing about what produced them, so whether "
                 "anyone but the author checked it is UNKNOWN")
    return ClaimAuthorship(cid, status, basis, authors=authors, author_keys=keys,
                           verifiers=tuple(relations), independent_groups=groups,
                           required=required)

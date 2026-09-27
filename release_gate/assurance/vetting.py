"""Whom an organisation has decided to rely on, and nobody else's opinion.

Release-gate ships **no trusted verifiers.** Not one, not a starter set, not a
list of vendors whose tools are obviously fine. Every other registry in this
package ships rows — §10ac's model dialects, §10af's observability platforms,
§10aq's federated systems — because those are *descriptions*: how Langfuse
addresses a trace is a fact about Langfuse and release-gate can state it without
speaking for anybody. Whether a customer relies on a particular prover, pipeline,
laboratory or reviewer is a judgement that customer makes, and a shipped entry
would be release-gate making it for them while looking like a convenience.

So `empty_registry()` is empty, `VettingRegistry.ships_trusted_vendors` is
unconditionally `False`, and a test asserts the count is zero rather than small.

## The module is named for what it holds

Not `trusted_verifiers`. A registry called that, whose entries can read `REVOKED`
or `REJECTED`, is misnamed — and revocability is the whole point. What is stored
here is a set of **vetting decisions**, each of which may say "rely on this" or
"do not", each with a named decider and a stated basis, because `TrustDecision`
has refused to exist without those since §10d: trust that cannot be traced to
somebody's judgement is indistinguishable from an assumption.

## Matching on a name is how a registry like this becomes a rubber stamp

§10am already records `fake_verifier_identity` as a threat: a claim carrying
`verifier: "tool://trusted-prover"` and nothing else. If an entry were found by
name, that attack would stop being a declaration and start being an *upgrade* —
the attacker types a string and inherits somebody else's vetting.

So an entry declares the **identity evidence it is recognised by**, and a match
made on a name alone yields `UNVETTED`. `Identification` grades what the match
rested on, from a content digest down to an asserted name, and it stays a separate
axis from the trust decision itself. An organisation genuinely may vet a laboratory
on the strength of a contract and an accreditation number; that number is still
something anybody can type, and the honest output is an explicit `ACCEPTED`
decision whose standing is limited by how it was matched — `PROVISIONAL`, with the
reason attached. Merging the two axes would lose whichever half was inconvenient.

## Expiry and revocation are different endings

A **lapsed window** means the vetting ran out and nobody alleged anything was
wrong, so a verification performed inside the window keeps its standing: judging
an old check against today's calendar would rewrite history for a verifier that
did nothing.

A **revocation** is a judgement that the verifier cannot be relied on, which
applies to everything it ever said. Retroactive, deliberately, because the case
where it matters is the one where the compromise is discovered afterwards.

That asymmetry rests on knowing when the verification ran, and "when" is usually
the producer's own clock — so a verifier whose vetting lapsed last year could be
resurrected by backdating an attempt. `stamped_on_arrival` (§10ah) is exactly the
field that separates release-gate's arrival clock from a producer's claim, so
`Consultation.as_of_basis` says which one put the attempt inside the window. A
standing that depends on a producer's timestamp is reported as depending on it.

## A registry is what makes "unvetted" mean something

Without one, every verifier is unvetted and the fact carries no information — so a
case with no registry produces no findings and no coverage rows, and is
byte-identical to one assured before this module existed. With one, an organisation
has said *these are the verifiers we rely on*, and a check performed by something
absent from that list is a gap worth naming. The same structure as §10h: a
denominator is what turns an omission into a detectable one.

## Trust is not correctness, and never an upgrade

`Consultation.establishes_correctness` and `upgrades_epistemic_status` are both
unconditionally `False`. A vetted verifier's FAILED check is a failure; an
unvetted verifier's PASSED check is a pass whose standing nobody established; and
a vetted verifier's DECLARED result is still DECLARED, because vetting is a
decision about whom to rely on and not an observation release-gate made
(Invariants 1, 2, 11).

## The registry comes from the operator, never from the case

There is deliberately no loader that builds a registry out of a document's records.
A case that could carry its own vetting registry would be self-vetting, which is
§10ah's distinction exactly — a governance file is DECLARED evidence about what a
team wrote down, never policy input. `ingest` maps no `trust` field either, so a
submitted record cannot declare its own `TrustDecision`, and nothing here changes
that.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import (Any, Dict, Iterable, List, Mapping, Optional, Sequence,
                    Tuple)

from release_gate.assurance.canonical import digest_object, is_content_id, short_id
from release_gate.assurance.evidence import ProducerKind, TrustDecision, TrustStatus
from release_gate.assurance.expectation import EvidenceExpectation

VETTING_SCHEMA_VERSION = 1


class VettingError(ValueError):
    """A vetting entry or consultation described in a way that would overstate it."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# ── what can verify ──────────────────────────────────────────────────────────

class VerifierKind(str, Enum):
    """What sort of thing did the checking.

    Selects no behaviour on its own — `Identification` decides what a match is
    worth. The kinds are kept apart because what counts as proof of identity
    differs completely between them, and a single "verifier" concept would have to
    pick one and be wrong about the others.
    """

    EXECUTABLE = "EXECUTABLE"      # a binary, prover or checker, pinnable by digest
    CI_WORKFLOW = "CI_WORKFLOW"    # a pipeline identity, provable by the platform
    LABORATORY = "LABORATORY"      # an organisation that ran a measurement
    HUMAN = "HUMAN"                # a named reviewer
    OTHER = "OTHER"                # something none of the above describes

    def describe(self) -> str:
        return _KIND_NOTE[self][0]

    @property
    def strongest_available_identification(self) -> "Identification":
        """The best proof this kind of verifier can offer, in principle.

        Not a floor and not a requirement: it is what an organisation should expect
        to be able to ask for. An executable can be pinned to a digest; a
        laboratory cannot, and pretending otherwise would make the weaker case look
        like a configuration mistake rather than the nature of the thing.
        """
        return _KIND_NOTE[self][1]

    @property
    def principal_kind(self) -> ProducerKind:
        """The same principal in the vocabulary `EvidenceRecord` already uses."""
        return _KIND_NOTE[self][2]


_KIND_NOTE: Mapping[VerifierKind, Tuple[str, "Identification", ProducerKind]] = {}


class Identification(str, Enum):
    """What a match between a verification and an entry actually rested on.

    Graded, and kept strictly apart from the trust decision. The decision is
    whether an organisation chose to rely on a verifier; this is whether the thing
    that turned up is demonstrably that verifier.
    """

    #: The executable's own content digest. Forging it requires the executable.
    CONTENT_DIGEST = "CONTENT_DIGEST"
    #: A platform-attested workflow or workload identity — an OIDC subject, a
    #: signed provenance statement. Forging it requires the platform.
    PLATFORM_IDENTITY = "PLATFORM_IDENTITY"
    #: A directory account for a person. Forging it requires the account.
    ACCOUNT = "ACCOUNT"
    #: A name, a number or a label the party writes on its own output. Anybody who
    #: can type it can present it.
    ASSERTED_NAME = "ASSERTED_NAME"
    #: Nothing matched, or only the verifier's name did.
    NONE = "NONE"

    @property
    def can_support_full_standing(self) -> bool:
        """Whether a match on this evidence can reach `VETTED`.

        An asserted name cannot. The organisation's decision may be entirely
        explicit and the identification still spoofable, and a standing that
        ignored the difference would let anyone who can read a lab report present
        themselves as that laboratory.
        """
        return self in (Identification.CONTENT_DIGEST,
                        Identification.PLATFORM_IDENTITY,
                        Identification.ACCOUNT)

    def describe(self) -> str:
        return _IDENTIFICATION_NOTE[self]


_IDENTIFICATION_NOTE: Mapping[Identification, str] = {
    Identification.CONTENT_DIGEST: (
        "the verifier's own executable digest, so presenting it requires having "
        "the executable"),
    Identification.PLATFORM_IDENTITY: (
        "an identity the running platform attested to, so presenting it requires "
        "the platform's cooperation rather than a string"),
    Identification.ACCOUNT: (
        "a directory account, so presenting it requires being signed in as that "
        "person"),
    Identification.ASSERTED_NAME: (
        "a name, number or label the party wrote on its own output; anybody who "
        "can type it can present it, which bounds the standing however explicit "
        "the trust decision is"),
    Identification.NONE: (
        "nothing identified this verifier beyond the name it called itself, which "
        "is the one match a registry must never honour"),
}


_KIND_NOTE.update({
    VerifierKind.EXECUTABLE: (
        "a binary, prover or checker that ran; pinnable to a content digest, which "
        "is the only identification here that an attacker cannot simply type",
        Identification.CONTENT_DIGEST, ProducerKind.TOOL),
    VerifierKind.CI_WORKFLOW: (
        "a pipeline whose identity the platform can attest — a workflow at a ref, "
        "an OIDC subject — rather than a job number anybody can quote",
        Identification.PLATFORM_IDENTITY, ProducerKind.TOOL),
    VerifierKind.LABORATORY: (
        "an organisation that measured something release-gate will never see; its "
        "accreditation number is on its own report, so identification is asserted "
        "by nature and not by oversight",
        Identification.ASSERTED_NAME, ProducerKind.EXTERNAL),
    VerifierKind.HUMAN: (
        "a named reviewer; an account establishes who signed in, never that they "
        "read carefully",
        Identification.ACCOUNT, ProducerKind.HUMAN),
    VerifierKind.OTHER: (
        "something the four kinds above do not describe; identification is "
        "whatever the organisation can actually check",
        Identification.ASSERTED_NAME, ProducerKind.EXTERNAL),
})


#: Where to look, in a verification attempt's `detail`, for each kind of identity
#: evidence. Data rather than a chain of lookups, so the conventional keys are
#: documented, testable, and extendable by a deployment that spells them
#: differently.
PROOF_KEYS: Mapping[Identification, Tuple[str, ...]] = {
    Identification.CONTENT_DIGEST: ("verifier_digest", "executable_digest",
                                    "tool_digest"),
    Identification.PLATFORM_IDENTITY: ("workflow_identity", "oidc_subject",
                                       "workload_identity"),
    Identification.ACCOUNT: ("reviewer_account", "account", "principal"),
    Identification.ASSERTED_NAME: ("accreditation", "lab_id", "verifier_name"),
}


# ── one vetting decision ─────────────────────────────────────────────────────

@dataclass(frozen=True)
class VerifierEntry:
    """One verifier an organisation has ruled on, and how to recognise it.

    Every field the brief names lives here: the identity (`verifier_id`), the
    executable digest / workflow identity / laboratory id / reviewer account (all
    `identified_by`, graded by `identification`), the trust status and its basis
    (`decision`, a `TrustDecision`), and the validity period (`valid_from` /
    `valid_until`).
    """

    entry_id: str
    verifier_id: str
    kind: VerifierKind
    decision: TrustDecision
    #: The values this verifier will be recognised by. A name is not one of them —
    #: see `identification`, and the module docstring for why.
    identified_by: Tuple[str, ...] = ()
    identification: Identification = Identification.NONE
    valid_from: Optional[str] = None
    valid_until: Optional[str] = None
    note: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", VerifierKind(self.kind))
        object.__setattr__(self, "identification", Identification(self.identification))
        object.__setattr__(self, "identified_by",
                           tuple(v.strip() for v in self.identified_by if str(v).strip()))
        if not str(self.entry_id or "").strip():
            raise VettingError("a vetting entry needs an id so a consultation can cite it")
        if not str(self.verifier_id or "").strip():
            raise VettingError(
                f"{self.entry_id}: a vetting entry must name the verifier it rules on")
        if not isinstance(self.decision, TrustDecision):
            raise VettingError(
                f"{self.entry_id}: a vetting entry requires a TrustDecision, which "
                "carries the basis and the decider. Trust with no named decider is "
                "indistinguishable from an assumption, and a registry of those "
                "would be a list of vendors release-gate had decided to like")
        if self.identification is Identification.NONE and self.identified_by:
            raise VettingError(
                f"{self.entry_id}: identity evidence was supplied without saying what "
                "kind it is, so nothing can weigh it. Name the `identification`")
        if self.identification is not Identification.NONE and not self.identified_by:
            raise VettingError(
                f"{self.entry_id}: identification is {self.identification.value} and no "
                "values were given to recognise. An entry that cannot be matched on "
                "anything but its name is an entry that must not be matched")
        if self.identification is Identification.CONTENT_DIGEST:
            bad = [v for v in self.identified_by if not is_content_id(v)]
            if bad:
                raise VettingError(
                    f"{self.entry_id}: {bad[0]!r} is not a content identifier. A digest "
                    "that cannot be compared pins nothing, and an entry pinned to "
                    "nothing would match on hope")
        if (self.valid_from and self.valid_until
                and self.valid_until <= self.valid_from):
            raise VettingError(
                f"{self.entry_id}: valid_until ({self.valid_until}) is not after "
                f"valid_from ({self.valid_from}); a window that never opens vets "
                "nothing and would read as a lapse rather than a mistake")

    # ── the window ──────────────────────────────────────────────────────────

    @property
    def window_is_stated(self) -> bool:
        """Whether anybody bounded this vetting in time.

        An unbounded decision is a decision, not an oversight — but it is also one
        nobody will revisit, so it is reported rather than treated as equivalent to
        a live window.
        """
        return bool(self.valid_from or self.valid_until)

    @property
    def window_basis(self) -> str:
        if not self.window_is_stated:
            return ("no validity period was set, so this vetting does not lapse on "
                    "its own and only a revocation will end it")
        return (f"vetted from {self.valid_from or 'the beginning of record'} until "
                f"{self.valid_until or 'further notice'}")

    def covers(self, moment: Optional[str]) -> bool:
        """Whether the window includes `moment`. An unstated window covers everything.

        `None` means nobody knows when the verification ran, which is not the same
        as now — so it is refused here and handled by the consultation, where the
        missing timestamp can be reported instead of guessed away.
        """
        if moment is None:
            raise VettingError(
                f"{self.entry_id}: covers() needs a moment. 'When did this run' with "
                "no answer must be reported, not replaced with the current time")
        if self.valid_from and moment < self.valid_from:
            return False
        return not (self.valid_until and moment >= self.valid_until)

    # ── the decision ────────────────────────────────────────────────────────

    @property
    def status(self) -> TrustStatus:
        return self.decision.status

    @property
    def withdrawn(self) -> bool:
        """Revoked or rejected: a judgement about the verifier, not about a date.

        Retroactive by design. The case this exists for is the one where a
        compromise is found afterwards, and a revocation that only applied going
        forward would leave every past check standing on the strength of a trust
        nobody holds any more.
        """
        return self.status in (TrustStatus.REVOKED, TrustStatus.REJECTED)

    def recognises(self, values: Sequence[str]) -> bool:
        """Whether any of the supplied identity values is one this entry names.

        Never compares the verifier's name: an entry is matched on evidence, and
        the name is what the attacker controls.
        """
        wanted = {v.strip().lower() for v in self.identified_by}
        return any(str(v).strip().lower() in wanted for v in values if str(v).strip())

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "verifier_entry", "record_id": self.entry_id,
                "entry_id": self.entry_id, "verifier_id": self.verifier_id,
                "kind": self.kind.value,
                "decision": self.decision.to_dict(),
                "status": self.status.value,
                "identification": self.identification.value,
                "identified_by": list(self.identified_by),
                "can_support_full_standing":
                    self.identification.can_support_full_standing,
                "valid_from": self.valid_from, "valid_until": self.valid_until,
                "window_is_stated": self.window_is_stated,
                "withdrawn": self.withdrawn, "note": self.note,
                "schema_version": VETTING_SCHEMA_VERSION}


# ── the standing a consultation yields ───────────────────────────────────────

class VerifierStanding(str, Enum):
    """May this verifier's result be relied on as coming from a vetted verifier?

    One question, five answers. Named `VerifierStanding` because `Standing` is
    already `dimensions`' word for whether a dimension is sound, and two enums
    called the same thing in one package is how a reader ends up weighing the
    wrong axis.
    """

    VETTED = "VETTED"            # explicit accept, identity proved, inside the window
    PROVISIONAL = "PROVISIONAL"  # explicit accept, and something about it is weaker
    LAPSED = "LAPSED"            # explicit accept, and this check falls outside it
    WITHDRAWN = "WITHDRAWN"      # revoked or rejected — retroactively
    UNVETTED = "UNVETTED"        # nobody recorded a decision about this verifier

    @property
    def relied_on(self) -> bool:
        """Whether an organisation's decision to rely on this verifier is in force."""
        return self in (VerifierStanding.VETTED, VerifierStanding.PROVISIONAL)

    def describe(self) -> str:
        return _STANDING_NOTE[self]


_STANDING_NOTE: Mapping[VerifierStanding, str] = {
    VerifierStanding.VETTED: (
        "an organisation decided to rely on this verifier, the thing that turned up "
        "proved it was that verifier, and the check falls inside the stated window"),
    VerifierStanding.PROVISIONAL: (
        "the decision is explicit and something about it is weaker than it looks — "
        "the match rested on a name the party wrote itself, or no window was stated, "
        "or the timestamp that placed it in the window is the producer's own"),
    VerifierStanding.LAPSED: (
        "the vetting was real and this check falls outside its window; nobody "
        "alleged anything was wrong, so earlier checks keep their standing"),
    VerifierStanding.WITHDRAWN: (
        "somebody revoked or rejected this verifier, which is a judgement about the "
        "verifier and applies to everything it ever said"),
    VerifierStanding.UNVETTED: (
        "no decision about this verifier is recorded. Not a rejection — nobody "
        "looked, and with no registry at all that is every verifier"),
}


@dataclass(frozen=True)
class Consultation:
    """What the registry said about one verification, and what it rested on."""

    verifier_id: str
    standing: VerifierStanding
    identification: Identification = Identification.NONE
    entry_id: Optional[str] = None
    status: Optional[TrustStatus] = None
    as_of: Optional[str] = None
    #: Whose clock placed this check in time. A producer's own timestamp can be
    #: backdated into a window, so the basis travels with the standing (§10ah).
    as_of_basis: str = ""
    why: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "standing", VerifierStanding(self.standing))
        object.__setattr__(self, "identification", Identification(self.identification))
        if self.status is not None:
            object.__setattr__(self, "status", TrustStatus(self.status))
        if not self.why:
            raise VettingError(
                f"{self.verifier_id}: a consultation must say what it rests on. A "
                "standing a reviewer cannot trace is the assumption this module "
                "exists to replace")
        if (self.standing is not VerifierStanding.UNVETTED
                and self.entry_id is None):
            raise VettingError(
                f"{self.verifier_id}: a standing other than UNVETTED must cite the "
                "entry it came from, or nobody can see who decided it")
        if (self.standing is VerifierStanding.VETTED
                and not self.identification.can_support_full_standing):
            raise VettingError(
                f"{self.verifier_id}: VETTED cannot rest on "
                f"{self.identification.value}. A name anybody can type is not proof "
                "that this is the verifier somebody vetted")

    @property
    def establishes_correctness(self) -> bool:
        """Unconditionally False. A vetted verifier's failing check is a failure."""
        return False

    @property
    def upgrades_epistemic_status(self) -> bool:
        """Unconditionally False.

        Vetting is a decision about whom to rely on. It is not an observation
        release-gate made, so a vetted verifier's DECLARED result stays DECLARED
        (Invariants 1, 2, 11).
        """
        return False

    @property
    def rests_on_a_producer_clock(self) -> bool:
        """Whether a producer's own timestamp is what placed this inside a window."""
        return "producer" in self.as_of_basis

    def render(self) -> str:
        head = f"{self.verifier_id}: {self.standing.value}"
        if self.entry_id:
            head += f" (entry {self.entry_id}, matched on {self.identification.value})"
        return f"{head}\n    {self.why}"

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "vetting_consultation",
                "record_id": f"{self.verifier_id}:{self.standing.value}",
                "verifier_id": self.verifier_id, "standing": self.standing.value,
                "relied_on": self.standing.relied_on,
                "identification": self.identification.value,
                "entry_id": self.entry_id,
                "status": self.status.value if self.status else None,
                "as_of": self.as_of, "as_of_basis": self.as_of_basis,
                "rests_on_a_producer_clock": self.rests_on_a_producer_clock,
                "establishes_correctness": False,
                "upgrades_epistemic_status": False,
                "why": self.why, "schema_version": VETTING_SCHEMA_VERSION}


# ── the registry ─────────────────────────────────────────────────────────────

class VettingRegistry:
    """An organisation's vetting decisions. Empty until somebody fills it.

    Mutable by construction — vetting changes, and a frozen registry would make
    revocation a redeployment. What it produces is immutable: a `Consultation` is a
    reading at a moment and says which moment.
    """

    def __init__(self, *, source: str = "") -> None:
        #: Where the operator got these decisions — a config path, a directory
        #: sync, a name. Recorded so a reviewer can ask the registry's own
        #: provenance question. Never read from a case document.
        self.source = source
        self._entries: List[VerifierEntry] = []

    @property
    def ships_trusted_vendors(self) -> bool:
        """Unconditionally False, and the reason this registry starts empty.

        Every other registry in this package ships rows because they describe how
        something works. This one records a judgement, and shipping a judgement
        would be release-gate deciding whom a customer relies on while looking like
        a convenience.
        """
        return False

    @property
    def entries(self) -> Tuple[VerifierEntry, ...]:
        return tuple(self._entries)

    def __len__(self) -> int:
        return len(self._entries)

    def __bool__(self) -> bool:
        return bool(self._entries)

    def register(self, entry: VerifierEntry) -> "VettingRegistry":
        if not isinstance(entry, VerifierEntry):
            raise VettingError("only a VerifierEntry can be registered")
        if any(e.entry_id == entry.entry_id for e in self._entries):
            raise VettingError(
                f"an entry with id {entry.entry_id!r} is already registered; a second "
                "would make the standing depend on registration order")
        self._entries.append(entry)
        return self

    def of(self, entry_id: str) -> Optional[VerifierEntry]:
        return next((e for e in self._entries if e.entry_id == entry_id), None)

    def for_verifier(self, verifier_id: str) -> Tuple[VerifierEntry, ...]:
        """Entries naming this verifier. For reading the registry, not for matching.

        Matching goes through `consult`, which requires identity evidence. This is
        here so an operator can ask "what do we say about tool://x" and see the
        answer, including that it is vetted and the attempt could not prove it.
        """
        wanted = (verifier_id or "").strip().lower()
        return tuple(e for e in self._entries
                     if e.verifier_id.strip().lower() == wanted)

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "vetting_registry",
                "record_id": short_id("vet", digest_object(
                    [e.to_dict() for e in self._entries])),
                "source": self.source, "entries": [e.to_dict() for e in self._entries],
                "count": len(self._entries),
                "ships_trusted_vendors": False,
                "schema_version": VETTING_SCHEMA_VERSION}


def empty_registry(*, source: str = "") -> VettingRegistry:
    """A registry with nothing in it, which is the only kind release-gate ships."""
    return VettingRegistry(source=source)


# ── consulting it ────────────────────────────────────────────────────────────

def consult(registry: Optional[VettingRegistry], *, verifier_id: str,
            identity_values: Sequence[str] = (), as_of: Optional[str] = None,
            as_of_basis: str = "") -> Consultation:
    """What standing this verifier has, on the evidence supplied.

    `identity_values` is what turned up — an executable digest, a workflow
    identity, an account. The verifier's *name* is deliberately not consulted for
    matching: an entry found by name would hand its vetting to anybody who can
    spell it, which is `fake_verifier_identity` turned from a declaration into an
    upgrade.

    With no registry every verifier is `UNVETTED`, and that is the honest reading
    rather than a missing feature: nobody has said which verifiers this
    organisation relies on, so absence from a list that does not exist means
    nothing.
    """
    verifier_id = (verifier_id or "").strip() or "an unnamed verifier"
    if registry is None or not len(registry):
        return Consultation(
            verifier_id=verifier_id, standing=VerifierStanding.UNVETTED,
            why=("no vetting registry is configured here, so no verifier is vetted "
                 "and none is rejected. Absence from a list nobody wrote says "
                 "nothing about this verifier"))

    values = [str(v) for v in identity_values if str(v).strip()]
    matched = [e for e in registry.entries if e.recognises(values)]
    if not matched:
        named = registry.for_verifier(verifier_id)
        if named:
            return Consultation(
                verifier_id=verifier_id, standing=VerifierStanding.UNVETTED,
                why=(f"{len(named)} entr(y/ies) name {verifier_id!r}, and this check "
                     f"presented no identity evidence any of them recognise "
                     f"({', '.join(sorted({e.identification.value for e in named}))} "
                     "expected). Matching on the name would hand a vetting to "
                     "whoever typed it"))
        return Consultation(
            verifier_id=verifier_id, standing=VerifierStanding.UNVETTED,
            why=(f"the registry ({len(registry)} entr(y/ies)) records no decision "
                 f"about {verifier_id!r} and nothing presented identified it. Not a "
                 "rejection: nobody looked"))

    # A withdrawal outranks everything, whatever else matched: the strongest thing
    # anybody has said about this verifier is that it may not be relied on.
    withdrawn = [e for e in matched if e.withdrawn]
    if withdrawn:
        entry = withdrawn[0]
        return Consultation(
            verifier_id=verifier_id, standing=VerifierStanding.WITHDRAWN,
            identification=entry.identification, entry_id=entry.entry_id,
            status=entry.status, as_of=as_of, as_of_basis=as_of_basis,
            why=(f"{entry.decision.decided_by} recorded {entry.status.value} for this "
                 f"verifier ({entry.decision.basis}). A revocation is a judgement "
                 "about the verifier, so it applies to every check it ever ran, "
                 "including ones performed before the decision"))

    entry = matched[0]
    if entry.status is not TrustStatus.ACCEPTED:
        # PROVISIONAL or NOT_ESTABLISHED recorded deliberately: somebody looked and
        # stopped short, which is not the same as nobody looking.
        return Consultation(
            verifier_id=verifier_id, standing=VerifierStanding.PROVISIONAL,
            identification=entry.identification, entry_id=entry.entry_id,
            status=entry.status, as_of=as_of, as_of_basis=as_of_basis,
            why=(f"{entry.decision.decided_by} recorded {entry.status.value} rather "
                 f"than ACCEPTED ({entry.decision.basis}). Somebody looked and stopped "
                 "short of relying on it, which is not the same as nobody looking"))

    if as_of is None:
        return Consultation(
            verifier_id=verifier_id, standing=VerifierStanding.PROVISIONAL,
            identification=entry.identification, entry_id=entry.entry_id,
            status=entry.status, as_of=None,
            as_of_basis="nothing records when this check ran",
            why=(f"{entry.decision.decided_by} vetted this verifier "
                 f"({entry.window_basis}), and nothing records when the check ran, so "
                 "whether it falls inside the window was not established"))

    if not entry.covers(as_of):
        return Consultation(
            verifier_id=verifier_id, standing=VerifierStanding.LAPSED,
            identification=entry.identification, entry_id=entry.entry_id,
            status=entry.status, as_of=as_of, as_of_basis=as_of_basis,
            why=(f"this check ran at {as_of} and {entry.decision.decided_by} vetted "
                 f"the verifier only {entry.window_basis}. Nobody alleged anything "
                 "was wrong, so checks inside the window keep their standing"))

    limits: List[str] = []
    if not entry.identification.can_support_full_standing:
        limits.append(f"the match rested on {entry.identification.value}: "
                      f"{entry.identification.describe()}")
    if not entry.window_is_stated:
        limits.append("no validity period was set, so nothing will prompt anybody to "
                      "revisit this decision")
    if "producer" in (as_of_basis or ""):
        limits.append(f"the timestamp placing this inside the window is the "
                      f"producer's own ({as_of_basis}), and a producer that wanted "
                      "a lapsed vetting back could supply an earlier one")

    if limits:
        return Consultation(
            verifier_id=verifier_id, standing=VerifierStanding.PROVISIONAL,
            identification=entry.identification, entry_id=entry.entry_id,
            status=entry.status, as_of=as_of, as_of_basis=as_of_basis,
            why=(f"{entry.decision.decided_by} vetted this verifier explicitly "
                 f"({entry.decision.basis}), and " + "; and ".join(limits)))

    return Consultation(
        verifier_id=verifier_id, standing=VerifierStanding.VETTED,
        identification=entry.identification, entry_id=entry.entry_id,
        status=entry.status, as_of=as_of, as_of_basis=as_of_basis,
        why=(f"{entry.decision.decided_by} vetted this verifier ({entry.window_basis}), "
             f"the check ran at {as_of} inside that window, and it was identified by "
             f"{entry.identification.value}. This says whom to rely on and nothing "
             "about whether the result is right"))


def identity_values_of(attempt: Any) -> Tuple[str, ...]:
    """Identity evidence carried by a verification attempt, from the known keys.

    Reads `PROOF_KEYS` out of the attempt's `detail`. Deliberately does *not*
    include `attempt.verifier`: the name is the one field an attacker fully
    controls, and putting it in here would make every entry matchable by spelling.
    """
    detail = getattr(attempt, "detail", None) or {}
    if not isinstance(detail, Mapping):
        return ()
    found: List[str] = []
    for keys in PROOF_KEYS.values():
        for key in keys:
            value = detail.get(key)
            if isinstance(value, str) and value.strip():
                found.append(value.strip())
    return tuple(dict.fromkeys(found))


def consult_attempt(registry: Optional[VettingRegistry], attempt: Any) -> Consultation:
    """Consult the registry about one verification attempt.

    The timestamp question is the delicate one. An attempt stamped by release-gate
    on arrival carries release-gate's clock; one carrying a producer's timestamp
    carries a claim, and §10ah is the reason the two are distinguishable at all. A
    verifier whose vetting lapsed could otherwise be resurrected by backdating, so
    the basis travels into the consultation and bounds the standing there.
    """
    verifier_id = str(getattr(attempt, "verifier", "") or "")
    timestamp = str(getattr(attempt, "timestamp", "") or "") or None
    if timestamp is None:
        basis = "nothing records when this check ran"
    elif getattr(attempt, "stamped_on_arrival", False):
        basis = "release-gate's own clock, stamped when the attempt arrived"
    else:
        basis = "the producer's declared timestamp"
    return consult(registry, verifier_id=verifier_id,
                   identity_values=identity_values_of(attempt),
                   as_of=timestamp, as_of_basis=basis)


# ── the case's verifiers, read against the registry ──────────────────────────

@dataclass(frozen=True)
class VettingReport:
    """Every verifier a case relied on, and what the registry says about each.

    Not a score, and not an inventory of who verified anything: it covers the
    attempts a case carries, so a verifier that ran and was never reported is
    invisible here exactly as it is everywhere else (§10p).
    """

    consultations: Tuple[Consultation, ...] = ()
    registry_configured: bool = False
    registry_source: str = ""
    entries: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "consultations", tuple(self.consultations))

    def __len__(self) -> int:
        return len(self.consultations)

    def in_standing(self, standing: VerifierStanding) -> Tuple[Consultation, ...]:
        return tuple(c for c in self.consultations if c.standing is standing)

    @property
    def relied_on(self) -> Tuple[Consultation, ...]:
        return tuple(c for c in self.consultations if c.standing.relied_on)

    @property
    def withdrawn(self) -> Tuple[Consultation, ...]:
        return self.in_standing(VerifierStanding.WITHDRAWN)

    @property
    def on_a_producer_clock(self) -> Tuple[Consultation, ...]:
        return tuple(c for c in self.consultations if c.rests_on_a_producer_clock)

    @property
    def is_a_completeness_claim(self) -> bool:
        """Unconditionally False. A verifier nobody reported is not in this list."""
        return False

    @property
    def changes_any_result(self) -> bool:
        """Unconditionally False.

        Standing is about whom an organisation relies on. A vetted verifier's
        FAILED check is still FAILED, and reading this report as an override of a
        result would be the rubber stamp the module is built to refuse.
        """
        return False

    def expectations(self) -> Tuple[EvidenceExpectation, ...]:
        """Unvetted and withdrawn verifiers, as coverage rows — only with a registry.

        This is the point of the module in one method. With no registry every
        verifier is unvetted and the fact carries no information, so no rows are
        produced and a case is exactly what it was before. With a registry, an
        organisation has said which verifiers it relies on, and a check performed by
        something absent from that list is a gap worth naming — the same structure
        as §10h, where a denominator is what turns an omission into a detectable
        one.
        """
        if not self.registry_configured:
            return ()
        rows: List[EvidenceExpectation] = []
        unvetted = self.in_standing(VerifierStanding.UNVETTED)
        if unvetted:
            rows.append(EvidenceExpectation(
                dimension="vetting.unvetted_verifiers", assessed=False,
                observed_from=f"vetting registry ({self.entries} entr(y/ies))"
                              + (f" from {self.registry_source}" if self.registry_source
                                 else ""),
                note=(f"{len(unvetted)} verifier(s) this case relied on are not vetted "
                      f"here: {', '.join(sorted({c.verifier_id for c in unvetted}))}. "
                      "Whether they may be relied on was not established")))
        for consultation in self.withdrawn:
            rows.append(EvidenceExpectation(
                dimension=f"vetting.withdrawn.{consultation.verifier_id}",
                assessed=False,
                observed_from=f"vetting entry {consultation.entry_id}",
                note=(f"this case relies on a verifier somebody withdrew: "
                      f"{consultation.why}")))
        for consultation in self.in_standing(VerifierStanding.LAPSED):
            rows.append(EvidenceExpectation(
                dimension=f"vetting.lapsed.{consultation.verifier_id}",
                assessed=False,
                observed_from=f"vetting entry {consultation.entry_id}",
                note=f"a check ran outside its verifier's vetted window: {consultation.why}"))
        return tuple(rows)

    def render(self) -> str:
        lines = ["VERIFIER VETTING"]
        if not self.registry_configured:
            lines.append("  no registry is configured, so every verifier is unvetted")
            lines.append("  and none is rejected. Release-gate ships no trusted verifiers.")
            return "\n".join(lines)
        source = f" from {self.registry_source}" if self.registry_source else ""
        lines.append(f"  {self.entries} vetting decision(s){source}, "
                     f"{len(self.consultations)} verifier(s) consulted")
        lines.append("")
        for consultation in self.consultations:
            lines.append("    " + consultation.render().replace("\n    ", "\n      "))
        lines.append("")
        for standing in VerifierStanding:
            found = self.in_standing(standing)
            if found:
                lines.append(f"  {len(found):>3}  {standing.value}")
        if self.on_a_producer_clock:
            lines.append(f"  {len(self.on_a_producer_clock)} standing(s) rest on a "
                         "producer's own timestamp")
        lines.append("")
        lines.append("  Vetting says whom this organisation relies on. It does not say")
        lines.append("  a result is correct, and it never upgrades what was DECLARED.")
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "vetting_report",
                "record_id": short_id("vetr", digest_object(
                    [c.to_dict() for c in self.consultations])),
                "registry_configured": self.registry_configured,
                "registry_source": self.registry_source, "entries": self.entries,
                "consultations": [c.to_dict() for c in self.consultations],
                "by_standing": {s.value: len(self.in_standing(s))
                                for s in VerifierStanding
                                if self.in_standing(s)},
                "on_a_producer_clock": [c.verifier_id for c in self.on_a_producer_clock],
                "is_a_completeness_claim": False,
                "changes_any_result": False,
                "schema_version": VETTING_SCHEMA_VERSION}


def vetting_report(attempts: Iterable[Any],
                   registry: Optional[VettingRegistry] = None) -> VettingReport:
    """Consult the registry about every verification attempt in a case.

    One consultation per distinct verifier, because a registry's answer is about
    the verifier and repeating it per attempt would make a busy pipeline look like
    a wider vetting problem than it is. The earliest attempt decides the moment, so
    a verifier whose vetting lapsed mid-run is reported as lapsed rather than
    rescued by its most recent check.
    """
    seen: Dict[str, Consultation] = {}
    for attempt in attempts:
        consultation = consult_attempt(registry, attempt)
        held = seen.get(consultation.verifier_id)
        if held is None:
            seen[consultation.verifier_id] = consultation
            continue
        if _worse(consultation, held):
            seen[consultation.verifier_id] = consultation
    return VettingReport(
        consultations=tuple(seen[k] for k in sorted(seen)),
        registry_configured=registry is not None and bool(len(registry)),
        registry_source=getattr(registry, "source", "") or "",
        entries=len(registry) if registry is not None else 0)


def attempts_in(outcome: Any) -> Tuple[Any, ...]:
    """Every verification attempt a decided outcome carries.

    Two places hold them and a caller should not have to know that: the
    `verification` collection holds what a verifier report or a verification
    evidence record supplied, and `analysis.verification_graph` holds the attempts
    lifted out of claims. A report built from only one of them would have vetted
    half the case and said nothing about it.
    """
    found: List[Any] = []
    seen: set = set()
    graph = getattr(getattr(outcome, "analysis", None), "verification_graph", None)
    case = getattr(outcome, "case", None)
    sources: List[Any] = []
    if graph is not None:
        sources.extend(getattr(graph, "attempts", ()) or ())
    if case is not None:
        try:
            sources.extend(case.collection("verification").materialised)
        except Exception:  # pragma: no cover - a case with no such collection
            pass
    for attempt in sources:
        key = str(getattr(attempt, "verification_id", "") or id(attempt))
        if key in seen:
            continue
        seen.add(key)
        found.append(attempt)
    return tuple(found)


def report_for(outcome: Any,
               registry: Optional[VettingRegistry] = None) -> VettingReport:
    """The vetting report for a decided outcome. The documented entry point."""
    return vetting_report(attempts_in(outcome), registry)


#: Worst first, so one verifier's weakest standing is the one reported. A
#: withdrawal must not be hidden by a later check that happened to match an
#: accepted entry.
_STANDING_ORDER: Tuple[VerifierStanding, ...] = (
    VerifierStanding.WITHDRAWN,
    VerifierStanding.LAPSED,
    VerifierStanding.UNVETTED,
    VerifierStanding.PROVISIONAL,
    VerifierStanding.VETTED,
)


def _worse(left: Consultation, right: Consultation) -> bool:
    return _STANDING_ORDER.index(left.standing) < _STANDING_ORDER.index(right.standing)


__all__ = [
    "PROOF_KEYS",
    "VETTING_SCHEMA_VERSION",
    "Consultation",
    "Identification",
    "VerifierEntry",
    "VerifierKind",
    "VerifierStanding",
    "VettingError",
    "VettingRegistry",
    "VettingReport",
    "consult",
    "consult_attempt",
    "empty_registry",
    "report_for",
    "attempts_in",
    "identity_values_of",
    "vetting_report",
]

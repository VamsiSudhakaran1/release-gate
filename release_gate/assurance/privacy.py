"""Assurance from what a customer is willing to send, and honesty about the rest.

Proprietary prompts and chain-of-thought must never have to leave the environment
that produced them. They do not today — measured across all four platform
adapters, none retains prompt text, completion text or identifiers in the case or
in the evidence pack — but that property held by accident of how those adapters
happen to be written, and an accident is not a guarantee. This module makes it a
contract and gives a deployment the vocabulary to say what it withheld.

**The tension this module exists to resolve.** §10p treats selective evidence
omission as an attack: an agent that submits only the flattering half of its
record has defeated the gate. This prompt requires selective ingestion and
redaction as features. They are the same operation, and the difference is not in
what is removed but in what is *said about the removal*:

* **Declared, digest-committed minimisation** names the class of content
  withheld, commits to the digest of what was removed, and reports what could not
  be assessed as a consequence. What is left is a narrower case, and it reads as
  narrower.
* **Silent dropping** produces a case that reads exactly like one where the
  content never existed. That is the attack, whatever the intention behind it.

Today the engine does the silent kind. The adapters discard prompt content and
nothing records that there was any — so a reviewer cannot tell "no prompt was
sent to this model" from "a prompt was sent and we did not look at it". Both are
legitimate states and they are not the same state.

So `Disposition.WITHHELD` and `Disposition.ABSENT` are different values, and
`Minimisation.withheld_reads_as_absent` is unconditionally `False`. A withheld
class emits an `EvidenceExpectation` with `assessed=False` — the mechanism the
case already uses for a dimension nothing could reach — so it lands as
NOT_ASSESSED in coverage rather than in a privacy report nobody reads alongside
the verdict (Invariant 3, Invariant 9).

**What this module does not do.** It does not decide what is sensitive. There is
no PII detector, no secret scanner, no classifier. Which fields carry proprietary
content is a question about a customer's data, answerable by them, and a heuristic
that guessed would produce exactly the failure that matters: content that looked
safe to a regex and was not. A policy names classes and the fields that carry
them, and the deployment writes it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import (Any, Dict, Iterable, List, Mapping, Optional, Sequence,
                    Set, Tuple)

from release_gate.assurance.canonical import digest_bytes, digest_object, short_id

__all__ = [
    "PRIVACY_SCHEMA_VERSION",
    "DataClass",
    "Disposition",
    "IngestionScope",
    "Minimisation",
    "PrivacyError",
    "Redaction",
    "RedactionPolicy",
    "Residency",
    "SENSITIVE_CLASSES",
    "metadata_only_policy",
    "minimise",
    "residency_of",
]

PRIVACY_SCHEMA_VERSION = 1


class PrivacyError(ValueError):
    """A minimisation was recorded in a way that would read as an absence."""


# ── what can be withheld ─────────────────────────────────────────────────────

class DataClass(str, Enum):
    """Classes of content a deployment may decide not to send.

    Named classes rather than field patterns, because a policy has to survive a
    change of telemetry vendor. `gen_ai.prompt`, `input.messages[].content` and
    `llm.input_messages` are three spellings of `PROMPT`, and a policy written
    against spellings is a policy that lapses silently when one of them changes.
    """

    PROMPT = "PROMPT"                      # system and user prompt text
    COMPLETION = "COMPLETION"              # model output text
    CHAIN_OF_THOUGHT = "CHAIN_OF_THOUGHT"  # reasoning traces, scratchpads
    TOOL_ARGUMENTS = "TOOL_ARGUMENTS"      # what a tool was called with
    TOOL_OUTPUT = "TOOL_OUTPUT"            # what it returned
    ARTIFACT_CONTENT = "ARTIFACT_CONTENT"  # the bytes of a produced artifact
    IDENTIFIER = "IDENTIFIER"              # emails, user ids, account handles
    SECRET = "SECRET"                      # keys, tokens, credentials
    FREE_TEXT = "FREE_TEXT"                # anything else unstructured


#: Classes whose contents this engine never needs. Held as data so the claim is
#: checkable: a test asserts a verdict is reached with every one of them
#: withheld, and the promise in the docstring above is that test rather than this
#: sentence.
SENSITIVE_CLASSES: Tuple[DataClass, ...] = (
    DataClass.PROMPT, DataClass.COMPLETION, DataClass.CHAIN_OF_THOUGHT,
    DataClass.SECRET, DataClass.IDENTIFIER, DataClass.FREE_TEXT,
)

#: Field names, per class, that the platform adapters and common exports use.
#: Not a detector — a lookup table a deployment can extend or replace. Missing a
#: spelling means content travels, which is why `minimise` reports what it
#: matched and a caller can compare that against what it expected.
_FIELDS: Mapping[DataClass, Tuple[str, ...]] = {
    DataClass.PROMPT: ("prompt", "prompts", "system_prompt", "systemPrompt",
                       "gen_ai.prompt", "llm.input_messages", "input_messages",
                       "messages", "raw", "template"),
    DataClass.COMPLETION: ("completion", "gen_ai.completion", "output_messages",
                           "llm.output_messages", "generated_text", "response"),
    DataClass.CHAIN_OF_THOUGHT: ("reasoning", "thought", "thoughts",
                                 "scratchpad", "chain_of_thought",
                                 "reasoning_content", "deliberation"),
    DataClass.TOOL_ARGUMENTS: ("arguments", "tool_input", "tool_arguments",
                               "function_call", "parameters"),
    DataClass.TOOL_OUTPUT: ("tool_output", "tool_result", "observation"),
    DataClass.ARTIFACT_CONTENT: ("content", "body", "source", "diff", "patch"),
    DataClass.IDENTIFIER: ("email", "user.email", "user_email", "user.id",
                           "user_id", "username", "account", "actor_email"),
    DataClass.SECRET: ("api_key", "apiKey", "token", "secret", "password",
                       "credential", "authorization"),
    DataClass.FREE_TEXT: ("text", "comment", "description", "note"),
}


#: Classes where withholding demonstrably costs no assessment, so a `Redaction`
#: for one may state no cost. Exactly one member today, and it has to be a named
#: exception rather than a blanket relaxation: every other class buys privacy by
#: giving something up, and a record that let any of them claim otherwise would
#: make minimisation look free.
_NO_ASSESSMENT_COST: frozenset = frozenset({DataClass.SECRET})


class Disposition(str, Enum):
    """What happened to a class of content.

    `WITHHELD` and `ABSENT` are the two that must never be confused, and keeping
    them apart is this module's reason to exist. A class that was present and not
    sent is a known gap; a class that was never there is a different fact about
    the world. A case that reported both the same way would let a redaction pass
    for a clean bill of health.
    """

    RETAINED = "RETAINED"      # travels inline; the deployment accepted that
    DIGESTED = "DIGESTED"      # only a digest travels — comparable, unreadable
    REFERENCED = "REFERENCED"  # a locator plus a digest; the bytes stay put
    WITHHELD = "WITHHELD"      # present, deliberately not sent, reported as a gap
    ABSENT = "ABSENT"          # was never there


#: Dispositions under which no readable content crosses the boundary.
_NO_CONTENT_LEAVES: frozenset = frozenset({
    Disposition.DIGESTED, Disposition.REFERENCED, Disposition.WITHHELD,
    Disposition.ABSENT})


# ── where the data may live ──────────────────────────────────────────────────

class Residency(str, Enum):
    """How far anything travels at all."""

    LOCAL_ONLY = "LOCAL_ONLY"        # one machine, one file, nothing leaves it
    SELF_HOSTED = "SELF_HOSTED"      # the customer runs the API and the backends
    PRIVATE_CLOUD = "PRIVATE_CLOUD"  # customer-controlled cloud tenancy
    VENDOR_HOSTED = "VENDOR_HOSTED"  # release-gate's hosted API


#: What crosses a trust boundary under each residency. `LOCAL_ONLY` and
#: `SELF_HOSTED` cross none, which is why they need no minimisation policy to be
#: safe — and why one is still worth writing, because a case that travels later
#: travels as it was built.
_CROSSES: Mapping[Residency, str] = {
    Residency.LOCAL_ONLY: "nothing; the case is read, decided and rendered on one "
                          "machine and no network call is made",
    Residency.SELF_HOSTED: "nothing outside the customer's own infrastructure; "
                           "the API, the stores and the workers are all theirs",
    Residency.PRIVATE_CLOUD: "nothing outside a tenancy the customer controls, "
                             "subject to that cloud's own operator access",
    Residency.VENDOR_HOSTED: "whatever the submitted document contains — which is "
                             "why a minimisation policy belongs in front of it, and "
                             "why the engine is built to decide without prompt or "
                             "reasoning content",
}


def residency_of(residency: Any) -> str:
    """What crosses a trust boundary under this residency. Stated, not implied."""
    return _CROSSES[Residency(residency)]


# ── the policy ───────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class RedactionPolicy:
    """What a deployment will and will not send, declared and content-addressed.

    Declared, because a redaction nobody wrote down is indistinguishable from
    evidence that never existed. Content-addressed, because the same policy
    applied twice must produce the same minimisation — and because a pack that
    carries the policy digest lets a reviewer check that the document they are
    reading was minimised the way the record says it was.
    """

    policy_id: str
    dispositions: Mapping[DataClass, Disposition] = field(default_factory=dict)
    declared_by: str = ""
    basis: str = ""
    residency: Residency = Residency.LOCAL_ONLY
    #: Extra field names per class, for a telemetry shape the table above does
    #: not know. Merged with `_FIELDS`, never replacing it.
    extra_fields: Mapping[DataClass, Tuple[str, ...]] = field(default_factory=dict)
    schema_version: int = PRIVACY_SCHEMA_VERSION

    policy_digest: str = field(default="", init=False)

    def __post_init__(self) -> None:
        if not str(self.policy_id or "").strip():
            raise PrivacyError(
                "a redaction policy must be named; an anonymous policy cannot be "
                "cited by the case it shaped")
        object.__setattr__(self, "policy_id", self.policy_id.strip())
        object.__setattr__(self, "residency", Residency(self.residency))
        object.__setattr__(self, "dispositions", {
            DataClass(k): Disposition(v) for k, v in
            (self.dispositions or {}).items()})
        object.__setattr__(self, "extra_fields", {
            DataClass(k): tuple(v) for k, v in (self.extra_fields or {}).items()})
        if Disposition.ABSENT in set(self.dispositions.values()):
            raise PrivacyError(
                "a policy cannot dispose of a class as ABSENT. ABSENT is a finding "
                "about a document, not a decision about one; a policy that could "
                "declare content absent would be able to make a withholding look "
                "like an emptiness")
        if not str(self.declared_by or "").strip():
            raise PrivacyError(
                "a redaction policy must name who declared it: a case shaped by a "
                "policy nobody owns cannot be questioned by the person it is "
                "shown to")
        object.__setattr__(self, "policy_digest", digest_object(self.identity()))

    def identity(self) -> Dict[str, Any]:
        return {"schema_version": self.schema_version,
                "policy_id": self.policy_id,
                "dispositions": {k.value: v.value for k, v
                                 in sorted(self.dispositions.items(),
                                           key=lambda kv: kv[0].value)},
                "declared_by": self.declared_by, "basis": self.basis,
                "residency": self.residency.value,
                "extra_fields": {k.value: list(v) for k, v
                                 in sorted(self.extra_fields.items(),
                                           key=lambda kv: kv[0].value)}}

    @property
    def requires_raw_content(self) -> bool:
        """Unconditionally False, for every policy.

        No assurance path requires prompt text, completion text or reasoning
        traces to leave the environment that produced them. The engine decides
        from structure — what ran, in what order, against what digest, verified by
        what — and a policy withholding every sensitive class still reaches a
        verdict. That is asserted in a test rather than promised here.
        """
        return False

    def disposition_of(self, data_class: Any) -> Disposition:
        """What this policy does with a class. Unmentioned means RETAINED.

        The default is the permissive one on purpose: a policy that silently
        withheld classes it had not been asked about would minimise more than its
        author declared, and the record would credit them with a decision they
        did not make.
        """
        return self.dispositions.get(DataClass(data_class), Disposition.RETAINED)

    def fields_for(self, data_class: Any) -> Tuple[str, ...]:
        found = DataClass(data_class)
        return tuple(dict.fromkeys(_FIELDS.get(found, ())
                                   + self.extra_fields.get(found, ())))

    @property
    def withholds(self) -> Tuple[DataClass, ...]:
        return tuple(sorted((k for k, v in self.dispositions.items()
                             if v is Disposition.WITHHELD),
                            key=lambda c: c.value))

    @property
    def sends_nothing_readable(self) -> bool:
        """Whether every sensitive class is handled without content leaving."""
        return all(self.disposition_of(c) in _NO_CONTENT_LEAVES
                   for c in SENSITIVE_CLASSES)

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "redaction_policy", "record_id": self.policy_id,
                **self.identity(), "policy_digest": self.policy_digest,
                "withholds": [c.value for c in self.withholds],
                "sends_nothing_readable": self.sends_nothing_readable,
                "crosses_the_boundary": residency_of(self.residency),
                "requires_raw_content": False}


def metadata_only_policy(*, declared_by: str, residency: Any = Residency.VENDOR_HOSTED,
                         policy_id: str = "metadata-only",
                         basis: str = "") -> RedactionPolicy:
    """Structure travels; content does not. The mode most deployments want.

    Every sensitive class is withheld and the artifact content is reduced to a
    digest, so what leaves is what ran, in what order, against what hash, and
    what verified it. A digest is enough to detect that an artifact changed, which
    is what the engine actually needs from it — mutation detection, not reading.
    """
    return RedactionPolicy(
        policy_id=policy_id, declared_by=declared_by, residency=residency,
        basis=(basis or "structure is sufficient for structural assurance; "
                        "prompt, completion and reasoning content is not sent"),
        dispositions={
            DataClass.PROMPT: Disposition.WITHHELD,
            DataClass.COMPLETION: Disposition.WITHHELD,
            DataClass.CHAIN_OF_THOUGHT: Disposition.WITHHELD,
            DataClass.SECRET: Disposition.WITHHELD,
            DataClass.IDENTIFIER: Disposition.WITHHELD,
            DataClass.FREE_TEXT: Disposition.WITHHELD,
            DataClass.TOOL_ARGUMENTS: Disposition.DIGESTED,
            DataClass.TOOL_OUTPUT: Disposition.DIGESTED,
            DataClass.ARTIFACT_CONTENT: Disposition.DIGESTED,
        })


# ── one applied act ──────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Redaction:
    """One class of content removed from one place, and what that cost.

    `content_digest` is what separates this from a deletion. It commits to
    exactly what was removed: the same document minimised twice yields the same
    digest, a document whose content changed yields a different one, and a
    reviewer asking "was this the artifact I approved" can be answered without
    anyone reading the artifact. Without it, a redaction is indistinguishable
    from tampering, and §10p's threat model applies to it.
    """

    data_class: DataClass
    disposition: Disposition
    locus: str
    #: Digest of what was removed. Required for WITHHELD and DIGESTED.
    content_digest: Optional[str] = None
    byte_length: Optional[int] = None
    #: A locator, when the content stayed in a private backend rather than being
    #: dropped — §10aa's `ObjectStore`, or the customer's trace store.
    locator: Optional[str] = None
    #: What this makes unassessable. Required, and the reason the class exists.
    assessment_cost: Tuple[str, ...] = ()
    occurrences: int = 1

    def __post_init__(self) -> None:
        object.__setattr__(self, "data_class", DataClass(self.data_class))
        object.__setattr__(self, "disposition", Disposition(self.disposition))
        object.__setattr__(self, "assessment_cost", tuple(self.assessment_cost))
        if not str(self.locus or "").strip():
            raise PrivacyError(
                "a redaction must say where it applied; one that cannot be "
                "located cannot be checked")
        if self.disposition in (Disposition.WITHHELD, Disposition.DIGESTED) \
                and not self.content_digest:
            raise PrivacyError(
                f"{self.data_class.value} at {self.locus} was "
                f"{self.disposition.value} with no digest of what was removed. "
                "That is a deletion, not a redaction: nobody can later show that "
                "what was withheld was one particular thing rather than whatever "
                "is convenient to claim now")
        if self.disposition is Disposition.REFERENCED and not self.locator:
            raise PrivacyError(
                f"{self.data_class.value} at {self.locus} is REFERENCED with no "
                "locator; a reference that points nowhere withholds the content "
                "and says it did not")
        if (self.disposition is Disposition.WITHHELD
                and not self.assessment_cost
                and self.data_class not in _NO_ASSESSMENT_COST):
            raise PrivacyError(
                f"{self.data_class.value} at {self.locus} is WITHHELD with no "
                "stated cost. Something became unassessable, and a withholding "
                "whose consequence is unstated reads as free")

    @property
    def content_left_the_environment(self) -> bool:
        return self.disposition is Disposition.RETAINED

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "redaction",
                "data_class": self.data_class.value,
                "disposition": self.disposition.value, "locus": self.locus,
                "content_digest": self.content_digest,
                "byte_length": self.byte_length, "locator": self.locator,
                "assessment_cost": list(self.assessment_cost),
                "occurrences": self.occurrences,
                "content_left_the_environment":
                    self.content_left_the_environment}


#: What each class makes unassessable when it does not travel. Held as data so a
#: cost is stated the same way every time, rather than depending on whoever wrote
#: the call site to think of it.
_COST: Mapping[DataClass, Tuple[str, ...]] = {
    DataClass.PROMPT: (
        "whether an instruction reaching the model was itself untrusted input "
        "cannot be read from structure alone",
        "prompt-injection analysis of the instruction text is out of scope for "
        "this case"),
    DataClass.COMPLETION: (
        "whether model output was used verbatim in a consequential action can be "
        "seen structurally, but what it said cannot",),
    DataClass.CHAIN_OF_THOUGHT: (
        "the agent's stated reasoning is not available, so a claim it makes about "
        "why it acted cannot be checked against it",),
    DataClass.TOOL_ARGUMENTS: (
        "which specific resource a tool acted on is reduced to a digest; two "
        "different calls remain distinguishable, their targets do not",),
    DataClass.TOOL_OUTPUT: (
        "what a tool returned is reduced to a digest, so a result cannot be "
        "inspected, only compared",),
    DataClass.ARTIFACT_CONTENT: (
        "the artifact cannot be read here; mutation is still detectable from the "
        "digest, and correctness of its contents is not assessable",),
    DataClass.IDENTIFIER: (
        "who a record concerns cannot be resolved to a person from this case",),
    # SECRET is deliberately empty. A credential is not evidence: it is a thing
    # that grants access, and no assurance question is answered by reading one.
    # Withholding it costs nothing, and listing a cost of "nothing" under a
    # heading that says NOT ASSESSABLE would be a contradiction a reader has to
    # resolve themselves.
    DataClass.SECRET: (),
    DataClass.FREE_TEXT: (
        "unstructured commentary is unavailable, so a human note explaining a "
        "record cannot be read",),
}


# ── the case-level record ────────────────────────────────────────────────────

@dataclass(frozen=True)
class Minimisation:
    """What was withheld from this case, and what follows for its coverage.

    The record that makes minimisation honest. Without it the case would read
    identically whether a prompt was never sent to a model or sent and withheld,
    and those are different facts.
    """

    policy: RedactionPolicy
    redactions: Tuple[Redaction, ...] = ()
    #: Classes the policy covers that this document simply did not contain.
    absent: Tuple[DataClass, ...] = ()
    document_digest: Optional[str] = None
    minimised_digest: Optional[str] = None
    schema_version: int = PRIVACY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "redactions", tuple(self.redactions))
        object.__setattr__(self, "absent", tuple(
            sorted({DataClass(c) for c in self.absent}, key=lambda c: c.value)))
        overlap = {r.data_class for r in self.redactions} & set(self.absent)
        if overlap:
            raise PrivacyError(
                "a class cannot be both withheld and absent: "
                + ", ".join(sorted(c.value for c in overlap))
                + ". One says content was there and did not travel, the other "
                "says there was none; reporting both would leave a reader unable "
                "to tell which happened")

    @property
    def withheld_reads_as_absent(self) -> bool:
        """Unconditionally False.

        The property the module is for. A class that was present and withheld
        appears in `redactions` with a digest and a stated cost, and lands in
        coverage as NOT_ASSESSED. A class that was never there appears in
        `absent`. No code path merges them, and `__post_init__` refuses a record
        that puts one class in both.
        """
        return False

    @property
    def content_left_the_environment(self) -> bool:
        return any(r.content_left_the_environment for r in self.redactions)

    @property
    def withheld_classes(self) -> Tuple[DataClass, ...]:
        return tuple(sorted({r.data_class for r in self.redactions
                             if r.disposition is Disposition.WITHHELD},
                            key=lambda c: c.value))

    @property
    def assessment_cost(self) -> Tuple[str, ...]:
        out: List[str] = []
        for redaction in self.redactions:
            out += list(redaction.assessment_cost)
        return tuple(dict.fromkeys(out))

    def expectations(self) -> Tuple[Any, ...]:
        """One `EvidenceExpectation` per withheld class, `assessed=False`.

        Emitted through the mechanism the case already uses for a dimension
        nothing could reach, so a withholding lands in coverage beside every
        other NOT_ASSESSED rather than in a privacy report read separately from
        the verdict (Invariant 9).
        """
        from release_gate.assurance.expectation import EvidenceExpectation

        rows = []
        for data_class in self.withheld_classes:
            cost = "; ".join(_COST.get(data_class, ()))
            rows.append(EvidenceExpectation(
                dimension=f"content.{data_class.value.lower()}",
                assessed=False,
                observed_from=f"privacy policy {self.policy.policy_id}",
                note=(f"withheld under {self.policy.policy_id} "
                      f"({self.policy.policy_digest[:19]}…): {cost}")))
        return tuple(rows)

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "minimisation",
                "policy": self.policy.to_dict(),
                "redactions": [r.to_dict() for r in self.redactions],
                "withheld_classes": [c.value for c in self.withheld_classes],
                "absent_classes": [c.value for c in self.absent],
                "assessment_cost": list(self.assessment_cost),
                "document_digest": self.document_digest,
                "minimised_digest": self.minimised_digest,
                "content_left_the_environment":
                    self.content_left_the_environment,
                "withheld_reads_as_absent": False,
                "schema_version": self.schema_version}

    def render(self) -> str:
        lines = [f"MINIMISATION under {self.policy.policy_id} "
                 f"({self.policy.policy_digest[:19]}…)",
                 f"  residency: {self.policy.residency.value} — "
                 f"{residency_of(self.policy.residency)}"]
        if self.document_digest:
            lines.append(f"  document before: {self.document_digest}")
            lines.append(f"  document sent:   {self.minimised_digest}")
        for redaction in self.redactions:
            lines.append(f"  {redaction.disposition.value}: "
                         f"{redaction.data_class.value} "
                         f"× {redaction.occurrences} at {redaction.locus}")
            if redaction.content_digest:
                lines.append(f"      committed to {redaction.content_digest}")
        for data_class in self.absent:
            lines.append(f"  ABSENT: {data_class.value} — this document contained "
                         "none, which is not the same as withholding it")
        if self.assessment_cost:
            lines.append("  NOT ASSESSABLE AS A RESULT:")
            lines += [f"      - {cost}" for cost in self.assessment_cost]
        else:
            lines.append("  Nothing became unassessable.")
        return "\n".join(lines)


# ── selective ingestion ──────────────────────────────────────────────────────

@dataclass(frozen=True)
class IngestionScope:
    """Which record kinds a deployment admits, and what it says about the rest.

    Selective ingestion is legitimate — a customer may have an eval harness whose
    output they do not wish to send at all. What is not legitimate is a case that
    looks complete because the things it excluded never arrived.
    """

    admitted: Tuple[str, ...] = ()
    excluded: Tuple[str, ...] = ()
    declared_by: str = ""
    basis: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "admitted", tuple(sorted(set(self.admitted))))
        object.__setattr__(self, "excluded", tuple(sorted(set(self.excluded))))
        overlap = set(self.admitted) & set(self.excluded)
        if overlap:
            raise PrivacyError(
                "a record kind cannot be both admitted and excluded: "
                + ", ".join(sorted(overlap)))
        if not self.admitted and not self.excluded:
            raise PrivacyError(
                "a scope that names nothing admits everything, which is the "
                "default and needs no scope. Name what is admitted or what is "
                "excluded, so the difference is on the record")
        if self.excluded and not str(self.declared_by or "").strip():
            raise PrivacyError(
                "a scope that excludes record kinds must name who decided that; "
                "an exclusion nobody owns is indistinguishable from evidence "
                "that never arrived")

    def admits(self, record_kind: str) -> bool:
        kind = str(record_kind or "").strip()
        if kind in self.excluded:
            return False
        return not self.admitted or kind in self.admitted

    @property
    def excluded_reads_as_clean(self) -> bool:
        """Unconditionally False. An excluded kind is a coverage gap.

        A scope narrows what a case is about. It does not narrow what the case
        claims to have looked at, because that is the whole difference between
        scoping and the omission attack.
        """
        return False

    def expectations(self) -> Tuple[Any, ...]:
        from release_gate.assurance.expectation import EvidenceExpectation
        return tuple(EvidenceExpectation(
            dimension=f"records.{kind.lower()}", assessed=False,
            observed_from=f"ingestion scope declared by {self.declared_by}",
            note=(f"{kind} records were not ingested by declared scope"
                  + (f": {self.basis}" if self.basis else "")
                  + ". Whether any exist was not assessed here"))
            for kind in self.excluded)

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "ingestion_scope",
                "admitted": list(self.admitted), "excluded": list(self.excluded),
                "declared_by": self.declared_by, "basis": self.basis,
                "excluded_reads_as_clean": False}


# ── the in-environment transform ─────────────────────────────────────────────

#: The shape `_walk` leaves behind for a DIGESTED field. Recognised on the way in
#: so minimisation is idempotent.
_REDACTED_KEYS: frozenset = frozenset({"digest", "redacted"})


def _already_redacted(value: Any) -> bool:
    return isinstance(value, Mapping) and set(value) == _REDACTED_KEYS


#: Keys that carry an attribute's value beside a sibling `key`, across the
#: conventions the platform adapters read.
_VALUE_KEYS: Tuple[str, ...] = ("value", "stringValue", "string_value")


def _attribute_pair(node: Mapping, field_map: Mapping[str, "DataClass"]):
    """The class and value-key of a `{key, value}` attribute pair, or None."""
    name = node.get("key")
    if not isinstance(name, str):
        return None
    data_class = field_map.get(name.lower())
    if data_class is None:
        return None
    for candidate in _VALUE_KEYS:
        if candidate in node:
            return data_class, candidate
    return None


def _digest_of(value: Any) -> str:
    if isinstance(value, bytes):
        return digest_bytes(value)
    if isinstance(value, str):
        return digest_bytes(value.encode("utf-8"))
    return digest_object(value)


def _record(node: Mapping, value_key: str, locus: str, data_class: "DataClass",
            disposition: "Disposition", found: Dict) -> Dict[str, Any]:
    """Note one match and return the node with its value handled."""
    raw = _digest_of(node[value_key])
    slot = found.setdefault((data_class, disposition),
                            {"loci": [], "digests": [], "bytes": 0})
    slot["loci"].append(locus)
    slot["digests"].append(raw)
    try:
        original = node[value_key]
        slot["bytes"] += len(original if isinstance(original, (str, bytes))
                             else repr(original))
    except TypeError:
        pass
    out = {k: v for k, v in node.items() if k != value_key}
    if disposition is Disposition.DIGESTED:
        out[value_key] = {"digest": raw, "redacted": data_class.value}
    return out


def _walk(node: Any, path: str, policy: RedactionPolicy,
          found: Dict[Tuple[DataClass, Disposition], Dict[str, Any]],
          field_map: Mapping[str, DataClass]) -> Any:
    """Rewrite one node, recording what was matched. Depth-first, key by key."""
    if isinstance(node, Mapping):
        # OTLP — the dominant trace format — carries attributes as a list of
        # {"key": "gen_ai.prompt", "value": {"stringValue": ...}} pairs, so the
        # sensitive content sits under a key literally named "value" and keying
        # on dict keys alone matches nothing. The first version of this walker
        # did exactly that: it reported zero redactions on an OTLP export while
        # passing every prompt straight through, which is worse than no
        # minimiser at all because it reports success.
        pair = _attribute_pair(node, field_map)
        if pair is not None:
            data_class, value_key = pair
            disposition = policy.disposition_of(data_class)
            if disposition is not Disposition.RETAINED:
                if _already_redacted(node.get(value_key)):
                    return dict(node)
                return _record(node, value_key, f"{path}.{node['key']}",
                               data_class, disposition, found)

        out: Dict[str, Any] = {}
        for key, value in node.items():
            data_class = field_map.get(str(key).lower())
            if data_class is None:
                out[key] = _walk(value, f"{path}.{key}", policy, found, field_map)
                continue
            if _already_redacted(value):
                # A second pass must be a no-op. Without this, re-digesting the
                # digest envelope produced a different `content_digest` on every
                # run, so the commitment stopped matching the content it was
                # meant to commit to — and a pipeline where an agent minimises
                # and a gateway minimises again is an ordinary deployment, not a
                # mistake.
                out[key] = value
                continue
            disposition = policy.disposition_of(data_class)
            if disposition is Disposition.RETAINED:
                out[key] = _walk(value, f"{path}.{key}", policy, found, field_map)
                continue
            # One recorder for both shapes, so a keyed field and an OTLP pair
            # cannot end up committing to differently-computed digests.
            handled = _record({key: value}, key, f"{path}.{key}",
                              data_class, disposition, found)
            if key in handled:
                # DIGESTED: the key survives, so a reader sees that a tool had
                # arguments and can compare two calls without reading either.
                out[key] = handled[key]
            # WITHHELD and REFERENCED drop the key entirely; the `Minimisation`
            # record is what says it was there, which is the point of having one.
        return out
    if isinstance(node, list):
        return [_walk(item, f"{path}[{i}]", policy, found, field_map)
                for i, item in enumerate(node)]
    return node


def minimise(document: Any, policy: RedactionPolicy
             ) -> Tuple[Any, Minimisation]:
    """Apply a policy to a document, in the environment that produced it.

    Returns the document that may travel and the record of what did not. Run this
    *before* anything crosses a boundary: the point is that the sensitive content
    never leaves, not that release-gate is trusted to drop it on arrival.

    Deterministic, so the same document and policy yield the same pair — which is
    what lets a reviewer check that what they were shown was minimised the way
    the record claims.
    """
    field_map: Dict[str, DataClass] = {}
    for data_class in DataClass:
        for name in policy.fields_for(data_class):
            # First class to claim a spelling keeps it: DataClass declaration
            # order decides, so the mapping does not depend on dict iteration.
            field_map.setdefault(name.lower(), data_class)

    before = digest_object(document)
    found: Dict[Tuple[DataClass, Disposition], Dict[str, Any]] = {}
    minimised = _walk(document, "$", policy, found, field_map)

    redactions: List[Redaction] = []
    for (data_class, disposition), slot in sorted(
            found.items(), key=lambda kv: (kv[0][0].value, kv[0][1].value)):
        redactions.append(Redaction(
            data_class=data_class, disposition=disposition,
            locus=slot["loci"][0] if len(slot["loci"]) == 1
            else f"{slot['loci'][0]} and {len(slot['loci']) - 1} more",
            # A digest over the collected digests, so many occurrences commit to
            # one value without the record growing with the document.
            content_digest=(slot["digests"][0] if len(slot["digests"]) == 1
                            else digest_object(sorted(slot["digests"]))),
            byte_length=slot["bytes"] or None,
            occurrences=len(slot["loci"]),
            assessment_cost=(_COST.get(data_class, ())
                             if disposition is Disposition.WITHHELD else ())))

    touched = {data_class for data_class, _ in found}
    absent = tuple(c for c in policy.dispositions
                   if c not in touched
                   and policy.disposition_of(c) is not Disposition.RETAINED)
    return minimised, Minimisation(
        policy=policy, redactions=tuple(redactions), absent=absent,
        document_digest=before, minimised_digest=digest_object(minimised))

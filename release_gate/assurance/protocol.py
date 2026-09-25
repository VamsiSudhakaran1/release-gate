"""`rg.assurance.v1` — one name for one exact set of schemas.

Fifty version constants in two vocabularies is not a protocol. It is fifty
answers to a question a consumer asks once: *does this deployment speak the
assurance format I hold?* `EVIDENCE_SCHEMA_VERSION`, `CASE_MODEL_VERSION`,
`METHODOLOGY_MODEL_VERSION` and forty-seven others each answered a slice, none
answered the whole, and two had already drifted off 1 without anything
recording that they had.

So this module is a **manifest**. `rg.assurance.v1` names every schema and the
exact version of each, content-addressed so drift is detectable rather than
discovered. A reader asking whether it can read a document asks once.

**The distinction this exists for: not every version bump costs the same.**

A `*_SCHEMA_VERSION` governs a serialised payload. Bumping it changes what a
reader must understand, and an older reader either copes or refuses — either way
the failure is visible at the moment of reading.

A `*_MODEL_VERSION` is *inside an identity or binding digest*. `CASE_MODEL_VERSION`
is in `AssuranceCase.binding_state()`; `SUBJECT_MODEL_VERSION` is in
`AssuranceSubject.identity()`. Bumping either changes `case_digest` and
`subject_digest` — the exact values every `BoundApproval` and every `Override`
binds to. So a schema revision made to add one field silently unseats **every
authorisation ever recorded in that deployment**, and nothing says so at the
moment it happens: the code still runs, the tests that pin no digest still pass,
and the breakage surfaces later as approvals that no longer apply to cases nobody
changed.

`Consequence` is that difference, written down. `DIGEST_BEARING` versions are
listed as such, and `bumping_a_digest_bearing_version_is_backward_compatible` is
unconditionally `False`. Backward compatibility is deliberate when the cost of
breaking it is stated in advance rather than inferred afterwards.

**A version match is not a semantic match.** `a_version_match_is_a_semantic_match`
returns `False`. Two documents at `evidence.v1` parse the same way; whether the
producer meant the same thing by `epistemic_status` is a question about the
producer, not about the schema. The protocol says a reader will not choke. It has
never said more than that, and saying more is how a compatibility claim becomes
an assurance claim.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple

from release_gate.assurance.canonical import digest_object

__all__ = [
    "CORE_SCHEMAS",
    "PROTOCOL",
    "PROTOCOL_ID",
    "PROTOCOL_MAJOR",
    "PROTOCOL_NAMESPACE",
    "AssuranceProtocol",
    "Compatibility",
    "CompatibilityDecision",
    "Consequence",
    "ProtocolError",
    "SchemaRef",
    "read_compatibility",
    "speaks",
]

PROTOCOL_NAMESPACE = "rg.assurance"
PROTOCOL_MAJOR = 1
PROTOCOL_ID = f"{PROTOCOL_NAMESPACE}.v{PROTOCOL_MAJOR}"


class ProtocolError(ValueError):
    """A document was read under a protocol that does not cover it."""


class Consequence(str, Enum):
    """What bumping this version costs.

    The whole reason the manifest classifies rather than just lists. These two
    are not degrees of the same thing: one is a reading problem visible when it
    happens, the other silently invalidates records that were already signed.
    """

    #: A serialised payload. An older reader copes or refuses, and either way
    #: finds out at the moment of reading.
    PAYLOAD = "PAYLOAD"
    #: Inside an identity or binding digest. Bumping changes `case_digest` or
    #: `subject_digest`, so every approval and override bound to the old value
    #: stops applying — to cases nobody changed, with nothing raised.
    DIGEST_BEARING = "DIGEST_BEARING"


class Compatibility(str, Enum):
    """What a reader at this protocol does with a version it did not expect."""

    #: Reads older minor versions; refuses newer ones by name.
    BACKWARD = "BACKWARD"
    #: Reads newer ones too, ignoring fields it does not know. Only safe where
    #: an unknown field cannot change what a known field means.
    FORWARD_TOLERANT = "FORWARD_TOLERANT"
    #: Refuses anything but this exact version. The honest stance for anything
    #: whose value is fixed inside a digest.
    EXACT = "EXACT"


@dataclass(frozen=True)
class SchemaRef:
    """One schema, its version, and what changing it would cost."""

    name: str
    module: str
    constant: str
    version: Any
    consequence: Consequence = Consequence.PAYLOAD
    compatibility: Compatibility = Compatibility.BACKWARD
    core: bool = False
    note: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "consequence", Consequence(self.consequence))
        object.__setattr__(self, "compatibility", Compatibility(self.compatibility))
        if not str(self.name or "").strip():
            raise ProtocolError("a schema reference must be named")
        if (self.consequence is Consequence.DIGEST_BEARING
                and self.compatibility is not Compatibility.EXACT):
            raise ProtocolError(
                f"{self.name} is DIGEST_BEARING and declares "
                f"{self.compatibility.value} compatibility. A version inside a "
                "digest cannot be read loosely: accepting a different one would "
                "mean accepting a different digest for the same content, which "
                "is the binding an approval rests on")

    @property
    def qualified(self) -> str:
        """`rg.assurance.v1/evidence` — the name a document cites."""
        return f"{PROTOCOL_ID}/{self.name}"

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "qualified": self.qualified,
                "module": self.module, "constant": self.constant,
                "version": self.version, "consequence": self.consequence.value,
                "compatibility": self.compatibility.value, "core": self.core,
                "note": self.note}


def _ref(name: str, module: str, constant: str, version: Any, *,
         core: bool = False, digest_bearing: bool = False,
         compatibility: Optional[Compatibility] = None,
         note: str = "") -> SchemaRef:
    return SchemaRef(
        name=name, module=module, constant=constant, version=version,
        consequence=(Consequence.DIGEST_BEARING if digest_bearing
                     else Consequence.PAYLOAD),
        compatibility=(compatibility if compatibility is not None
                       else (Compatibility.EXACT if digest_bearing
                             else Compatibility.BACKWARD)),
        core=core, note=note)


#: The eight schemas a consumer of this protocol names directly. Everything else
#: is a member of the protocol and travels with it, but these are the ones an
#: integration is written against.
CORE_SCHEMAS: Tuple[str, ...] = (
    "event", "evidence", "subject", "case", "claim", "verification",
    "approval_packet", "required_evidence",
)


def _schemas() -> Tuple[SchemaRef, ...]:
    """Every version `rg.assurance.v1` means, declared as literals.

    Literals on purpose. An earlier version of this read each value from the
    module that owns it, which made the manifest incapable of disagreeing with
    the code — so a module could bump its version and the drift guard would
    compare the module against itself and pass. The protocol *declares* what v1
    is; the guard checks the code against that declaration, and a bump fails
    until someone edits this list. Editing it is the deliberate act that
    backward compatibility requires.
    """
    return (
        # ── the eight a consumer names ──────────────────────────────────────
        _ref("event", "events", "EVENT_SCHEMA_VERSION", 1, core=True,
             note="the streaming envelope; ingestion is at-least-once and "
                  "records are content-addressed, so a duplicate folds once"),
        _ref("evidence", "evidence", "EVIDENCE_SCHEMA_VERSION", 1, core=True,
             note="one of two schemas that already refuse a newer version by "
                  "name; `evidence_id` is a content address over `identity()`"),
        _ref("subject", "subject", "SUBJECT_MODEL_VERSION", 1, core=True,
             digest_bearing=True,
             note="inside `AssuranceSubject.identity()`, so this value is part "
                  "of `subject_digest` — the thing an approval binds to"),
        _ref("case", "case", "CASE_MODEL_VERSION", 1, core=True,
             digest_bearing=True,
             note="inside `AssuranceCase.binding_state()`, so this value is part "
                  "of `case_digest`; every BoundApproval and Override binds to it"),
        _ref("claim", "claims", "CLAIM_SCHEMA_VERSION", 1, core=True,
             note="the other schema that already refuses a newer version"),
        _ref("verification", "verification", "VERIFICATION_SCHEMA_VERSION", 2,
             core=True,
             note="at 2 — the first schema in this protocol to have moved, and "
                  "it moved before anything recorded that it had"),
        _ref("approval_packet", "packet", "PACKET_SCHEMA_VERSION", 1, core=True,
             note="the eleven-question document a person reads before acting"),
        _ref("required_evidence", "required_evidence",
             "REQUIRED_EVIDENCE_SCHEMA_VERSION", 1, core=True,
             note="the work order a HOLD returns; a hold without one is a shrug"),

        # ── the rest of the protocol ────────────────────────────────────────
        _ref("methodology", "methodology", "METHODOLOGY_MODEL_VERSION", 3,
             digest_bearing=True,
             note="at 3, and inside the methodology digest a case cites"),
        _ref("evidence_pack", "pack", "PACK_SCHEMA_VERSION", 3,
             note="at 3 — v1 and v2 predate this protocol"),
        _ref("adversarial", "adversarial", "ADVERSARIAL_SCHEMA_VERSION", 1),
        _ref("analysis_ruleset", "analysis", "ANALYSIS_RULESET_VERSION",
             "rg-structural-1",
             note="a ruleset identifier, not an integer: rules change what a "
                  "verdict says, so the id travels with the finding"),
        _ref("approval", "approval", "APPROVAL_SCHEMA_VERSION", 1),
        _ref("approval_view", "approval_view", "VIEW_SCHEMA_VERSION", 1),
        _ref("artifact", "artifacts", "ARTIFACT_SCHEMA_VERSION", 1),
        _ref("assumption", "assumptions", "ASSUMPTION_SCHEMA_VERSION", 1),
        _ref("attestation", "attestation", "ATTESTATION_SCHEMA_VERSION", 1),
        _ref("capability", "capabilities", "CAPABILITY_SCHEMA_VERSION", 1),
        _ref("compaction", "compaction", "COMPACTION_SCHEMA_VERSION", 1),
        _ref("completeness", "completeness", "COMPLETENESS_SCHEMA_VERSION", 1),
        _ref("consequence", "consequence", "CONSEQUENCE_SCHEMA_VERSION", 1),
        _ref("contradiction", "contradiction", "CONTRADICTION_SCHEMA_VERSION", 1),
        _ref("counterexample", "counterexample", "COUNTEREXAMPLE_SCHEMA_VERSION", 1),
        _ref("criticality", "criticality", "CRITICALITY_SCHEMA_VERSION", 1),
        _ref("declaration", "declaration", "DECLARATION_SCHEMA_VERSION", 1,
             note="a governance.yaml read as what a team wrote down about its "
                  "own system; DECLARED evidence, never policy input"),
        _ref("dimensions", "dimensions", "DIMENSIONS_SCHEMA_VERSION", 1,
             note="the eight assurance dimensions, reported side by side with "
                  "no total; critical conditions are gates, not weights"),
        _ref("evidence_graph", "evidence_graph", "GRAPH_SCHEMA_VERSION", 1),
        _ref("execution", "execution_graph", "EXECUTION_SCHEMA_VERSION", 1),
        _ref("expectation", "expectation", "EXPECTATION_SCHEMA_VERSION", 1),
        _ref("failed_branch", "failed_branches", "FAILED_BRANCH_SCHEMA_VERSION", 1),
        _ref("identity_claim", "identity", "IDENTITY_SCHEMA_VERSION", 1),
        _ref("independence", "independence", "INDEPENDENCE_SCHEMA_VERSION", 1),
        _ref("level", "level", "LEVEL_SCHEMA_VERSION", 1),
        _ref("model_dialect", "model_neutral", "MODEL_NEUTRAL_SCHEMA_VERSION", 1),
        _ref("mutation", "mutation", "MUTATION_SCHEMA_VERSION", 1),
        _ref("orchestrator_profile", "orchestration",
             "ORCHESTRATION_SCHEMA_VERSION", 1),
        _ref("organisation", "organisation", "ORGANISATION_SCHEMA_VERSION", 1),
        _ref("override", "override", "OVERRIDE_SCHEMA_VERSION", 1),
        _ref("plugin", "plugin", "PLUGIN_SCHEMA_VERSION", 1),
        _ref("ports", "ports", "PORTS_SCHEMA_VERSION", 1),
        _ref("privacy", "privacy", "PRIVACY_SCHEMA_VERSION", 1),
        _ref("producers", "producers", "PRODUCERS_SCHEMA_VERSION", 1,
             note="the seven evidence lanes and what each cannot establish, "
                  "plus the scanner's measured per-rule credibility"),
        _ref("progress", "progress", "PROGRESS_SCHEMA_VERSION", 1),
        _ref("quality", "quality", "QUALITY_SCHEMA_VERSION", 1),
        _ref("query", "query", "QUERY_SCHEMA_VERSION", 1),
        _ref("replication", "replication", "REPLICATION_SCHEMA_VERSION", 1),
        _ref("semantic_proposal", "semantic", "SEMANTIC_SCHEMA_VERSION", 1),
        _ref("session", "session", "SESSION_SCHEMA_VERSION", 1),
        _ref("status", "status", "STATUS_SCHEMA_VERSION", 1,
             note="the seven readouts and their links back to the systems that "
                  "hold the data; a link is not a copy"),
        _ref("streaming", "streaming", "STREAMING_SCHEMA_VERSION", 1),
        _ref("trust", "trust", "TRUST_SCHEMA_VERSION", 1),
        _ref("verdict", "verdict", "VERDICT_SCHEMA_VERSION", 1),
        _ref("verifier", "verifiers", "VERIFIER_SCHEMA_VERSION", 1),
        _ref("zero_config_ruleset", "zero_config", "ZERO_CONFIG_RULESET_VERSION",
             "zero-config-1",
             note="a ruleset identifier; the rules that turn structure into a "
                  "verdict, cited by every finding they produce"),
    )


@dataclass(frozen=True)
class AssuranceProtocol:
    """One name for one exact set of schema versions."""

    protocol_id: str
    schemas: Tuple[SchemaRef, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "schemas", tuple(self.schemas))
        names = [s.name for s in self.schemas]
        duplicates = sorted({n for n in names if names.count(n) > 1})
        if duplicates:
            raise ProtocolError(
                f"{', '.join(duplicates)} appear(s) twice in {self.protocol_id}; "
                "a schema with two versions in one protocol has no version")
        missing = [n for n in CORE_SCHEMAS if n not in set(names)]
        if missing:
            raise ProtocolError(
                f"{self.protocol_id} does not pin " + ", ".join(missing)
                + ". A protocol that leaves a core schema out is one a consumer "
                  "would write against and then find unversioned")

    def schema(self, name: str) -> SchemaRef:
        found = next((s for s in self.schemas if s.name == name), None)
        if found is None:
            raise ProtocolError(
                f"{self.protocol_id} does not cover {name!r}. Known: "
                + ", ".join(sorted(s.name for s in self.schemas))
                + ". A schema this protocol does not name is not one it refuses "
                  "— it is one nobody has versioned")
        return found

    @property
    def core(self) -> Tuple[SchemaRef, ...]:
        return tuple(s for s in self.schemas if s.core)

    @property
    def digest_bearing(self) -> Tuple[SchemaRef, ...]:
        """The schemas whose version is inside a digest. Bumping one of these
        unseats every approval bound to the old value."""
        return tuple(s for s in self.schemas
                     if s.consequence is Consequence.DIGEST_BEARING)

    def manifest(self) -> Dict[str, Any]:
        """The pinned set, canonically ordered, for the digest."""
        return {"protocol_id": self.protocol_id,
                "schemas": [{"name": s.name, "version": s.version,
                             "consequence": s.consequence.value,
                             "compatibility": s.compatibility.value}
                            for s in sorted(self.schemas, key=lambda s: s.name)]}

    def digest(self) -> str:
        """Content address of the whole pinned set.

        One value that changes when any member changes, so drift is detectable
        rather than discovered — which is the difference between a protocol and
        fifty numbers.
        """
        return digest_object(self.manifest())

    # ── the refusals ────────────────────────────────────────────────────────

    @property
    def a_version_match_is_a_semantic_match(self) -> bool:
        """Unconditionally False.

        Two documents at `evidence.v1` parse the same way. Whether their
        producers meant the same thing by `epistemic_status` is a question about
        the producers. This protocol says a reader will not choke; saying more is
        how a compatibility claim becomes an assurance claim.
        """
        return False

    @property
    def bumping_a_digest_bearing_version_is_backward_compatible(self) -> bool:
        """Unconditionally False.

        It changes `case_digest` and `subject_digest`, so every approval and
        override bound to the old value stops applying — to cases nobody
        changed, with nothing raised at the moment it happens.
        """
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "assurance_protocol",
                "record_id": self.protocol_id,
                "protocol_id": self.protocol_id, "digest": self.digest(),
                "core": [s.name for s in self.core],
                "digest_bearing": [s.name for s in self.digest_bearing],
                "schemas": [s.to_dict() for s in self.schemas],
                "a_version_match_is_a_semantic_match": False,
                "bumping_a_digest_bearing_version_is_backward_compatible": False}

    def render(self) -> str:
        lines = [f"PROTOCOL {self.protocol_id}  ({self.digest()[:23]}…)",
                 f"  {len(self.schemas)} schema(s), {len(self.core)} core, "
                 f"{len(self.digest_bearing)} digest-bearing"]
        for ref in self.core:
            mark = ("  [DIGEST-BEARING]"
                    if ref.consequence is Consequence.DIGEST_BEARING else "")
            lines.append(f"    {ref.qualified} = {ref.version}{mark}")
        if self.digest_bearing:
            lines.append("  Bumping any of "
                         + ", ".join(s.name for s in self.digest_bearing)
                         + " changes the digests approvals bind to. Every "
                           "authorisation recorded against the old value stops "
                           "applying, and nothing raises when it happens.")
        return "\n".join(lines)


PROTOCOL = AssuranceProtocol(protocol_id=PROTOCOL_ID, schemas=_schemas())


# ── reading a document that claims a version ─────────────────────────────────

@dataclass(frozen=True)
class CompatibilityDecision:
    """Whether this reader can read that document, and on what basis."""

    schema: str
    claimed: Any
    supported: Any
    readable: bool
    reason: str
    lossy: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "compatibility_decision", "schema": self.schema,
                "claimed": self.claimed, "supported": self.supported,
                "readable": self.readable, "lossy": self.lossy,
                "reason": self.reason,
                "a_version_match_is_a_semantic_match": False}


def read_compatibility(name: str, claimed: Any,
                       protocol: AssuranceProtocol = PROTOCOL
                       ) -> CompatibilityDecision:
    """Can this reader read a `name` document claiming version `claimed`?

    One answer, from the manifest, instead of whichever module happened to check.
    Forty-five of the fifty schemas silently accept any integer today; this is
    what they should be asking.
    """
    ref = protocol.schema(name)
    supported = ref.version

    if claimed == supported:
        return CompatibilityDecision(
            name, claimed, supported, True,
            f"exactly {ref.qualified} = {supported}")

    if isinstance(claimed, int) and isinstance(supported, int):
        if claimed < supported:
            if ref.compatibility is Compatibility.EXACT:
                return CompatibilityDecision(
                    name, claimed, supported, False,
                    f"{name} v{claimed} is older than v{supported}, and this "
                    "schema is EXACT because its version sits inside a digest. "
                    "Reading it as current would compute a different digest for "
                    "the same content, and an approval bound to one would not "
                    "match the other")
            return CompatibilityDecision(
                name, claimed, supported, True,
                f"{name} v{claimed} is older than v{supported}; this schema "
                "declares BACKWARD compatibility, so it reads",
                lossy=True)
        if ref.compatibility is Compatibility.FORWARD_TOLERANT:
            return CompatibilityDecision(
                name, claimed, supported, True,
                f"{name} v{claimed} is newer than v{supported}; this schema "
                "declares FORWARD_TOLERANT, so unknown fields are ignored — and "
                "what they would have said is not in the case",
                lossy=True)
        return CompatibilityDecision(
            name, claimed, supported, False,
            f"{name} v{claimed} is newer than the v{supported} this reader "
            "understands. Upgrade release-gate rather than reading a document "
            "whose fields it would silently drop")

    return CompatibilityDecision(
        name, claimed, supported, False,
        f"{name} claims {claimed!r} and this reader holds {supported!r}; these "
        "are not comparable, and treating an unrecognised identifier as a match "
        "would accept whatever happened to arrive")


def speaks(protocol_id: str, protocol: AssuranceProtocol = PROTOCOL) -> bool:
    """Whether this build speaks that protocol.

    Exact on the major version. `rg.assurance.v2` is a different protocol, not a
    later one to be read optimistically — that is what a major version is for.
    """
    return str(protocol_id or "").strip() == protocol.protocol_id

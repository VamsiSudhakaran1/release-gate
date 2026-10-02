"""The static scanner as a first-class evidence producer.

`producers.py` describes the scanner as one lane among seven: what it can
establish, what it cannot. This module is the lane *emitting*. One conversion
turns release-gate's own audit output into Universal Evidence, and both roads
into a case go through it — `release-gate assure audit.json`, which reads a
report somebody hands over, and `release-gate audit --evidence-out`, where this
process ran the scan itself.

**A finding is evidence of what the analyser saw, not a conclusion about the
world.** The failure this module exists to prevent has a name in this codebase:
the universal negative. RG-GATE-001 once told a maintainer their project had no
approval gate, when the gate lived in a layer the analyser does not read. What
the rule had actually established was narrower and true — *static analysis did
not identify a code-level approval gate on this path*. So every rule carries a
profile, as data, that says three things:

    observed            what the analyser saw in the code
    not_identified      for a rule that fires on something *missing*, what it
                        looked for and did not find, scoped to where it looked
    does_not_establish  what a reader must not conclude from the finding

A rule is `PRESENCE` when it fires on something the analyser saw (a tainted
value reaching `eval`) and `SCOPED_ABSENCE` when part of what it reports is a
mitigation it did not find (no gate, no ceiling, no try/except). The second kind
is where overclaiming happens, so its `not_identified` is required to begin
"static analysis did not identify" — a sentence that cannot be read as a claim
about anything outside the analysis. A rule id nobody classified is
`UNCLASSIFIED` and says so, rather than borrowing a profile it does not have.

**The same distinction applies to safeguards.** The audit looks for a kill
switch, a budget ceiling, an owner, in the repository's governance file and
source. Not finding one is release-gate's own observation about *this
repository*, and it was argued against "the kill switch safeguard is in place" —
a claim about the deployed system that the repository cannot settle, since a
kill switch can live in infrastructure the repo never mentions. The claim now
asks what the evidence can answer: whether this repository carries a valid
declaration. Its status, and the verdict, are unchanged; what changed is that
neither the claim nor the evidence says more than was looked at.

**Every record is bound to the state it was produced against.** The audit
records a provenance block (`evidence_provenance`): the scanner's version and a
digest of the analyser's own source, a digest per rule definition, the
repository, the commit and whether the tree was clean, a sha256 of every file the
analyser read folded into one manifest digest, and a sha256 of the lines each
finding spans. `applies_to_digest` is that manifest digest — the exact bytes
analysed — and the scanned code is registered as an artifact carrying it, so
evidence and candidate can be compared. A report written before the block
existed carries none of this, and none of it is invented: such a report binds to
its own digest, as it always did, and says so.

**Where the provenance comes from is recorded, not assumed.** This module is in
the pure layer — no subprocess, no network — so it gathers nothing. The audit
(`release_gate/audit.py`) collects the block when it scans; this module reads it.
A block arriving in a document is the document's account, and is treated as
DECLARED like the rest of that document's identity (§10ag.4).
"""

from __future__ import annotations

import dataclasses
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from release_gate.assurance.artifacts import Artifact, ArtifactKind
from release_gate.assurance.canonical import is_digest
from release_gate.assurance.claims import Claim
from release_gate.assurance.evidence import (
    CoverageStatus,
    EpistemicStatus,
    EvidenceRecord,
    EvidenceType,
    Producer,
    VerificationMethod,
)
from release_gate.assurance.expectation import EvidenceExpectation
from release_gate.assurance.producer_contract import (
    ConfidenceSemantics,
    CoverageSemantics,
    Determinism,
    Independence,
    ProducerDeclaration,
)
from release_gate.assurance.producers import EvidenceLane, EvidenceProducer, lane_for
from release_gate.assurance.subject import DigestMethod, DigestStatus

__all__ = [
    "PRODUCER_COMPONENT",
    "PRODUCER_TYPE",
    "RULE_PROFILES",
    "SCAN_PROVENANCE_KEY",
    "SCAN_PROVENANCE_SCHEMA",
    "STATIC_DECLARATION",
    "STATIC_EVIDENCE_SCHEMA_VERSION",
    "Binding",
    "ObservationKind",
    "PathStatus",
    "RuleEvidenceProfile",
    "ScanProvenance",
    "StaticEmission",
    "StaticEvidenceProducer",
    "finding_span",
    "origin_file",
    "evidence_profile_for",
    "region_key",
    "safeguard_profile",
]

STATIC_EVIDENCE_SCHEMA_VERSION = 1

#: The producer type every record this module emits carries. A name, not a
#: `ProducerKind`: kind says who is answerable (release-gate in-process, or a
#: document attributed to it); type says which of release-gate's producers.
PRODUCER_TYPE = "release_gate_static"

#: `producer_id` is `release-gate/static`.
PRODUCER_COMPONENT = "static"

#: This producer, stated in the contract every producer meets
#: (`producer_contract.py`). Its records are built here rather than by the
#: contract's normaliser, because release-gate ran the analysis and the records
#: are DERIVED — but what they mean is declared in the same terms as anyone
#: else's, and its limitations are the code-scanner lane's, not a second copy.
STATIC_DECLARATION = ProducerDeclaration(
    producer_type=PRODUCER_TYPE,
    label="release-gate static analysis",
    origin="release-gate",
    modality=EvidenceLane.CODE_SCANNER,
    determinism=Determinism.DETERMINISTIC,
    evidence_types=(EvidenceType.STATIC_FINDING, EvidenceType.ATTESTATION),
    supported_claims=(
        "that static analysis found, or did not identify, a pattern its ruleset "
        "reports, in the scanned code",
        "that this repository carries a valid declaration of a safeguard"),
    confidence=ConfidenceSemantics.ORDINAL_LABEL,
    confidence_note=("`basis` (confirmed / inferred / heuristic) and `confidence` "
                     "(high / medium / low): tiers of the analyser's own evidence, "
                     "not probabilities"),
    coverage=CoverageSemantics.SCOPED_TO_TARGETS,
    coverage_note="the files in the scanned set, under the recorded ruleset",
    limitations=lane_for(EvidenceLane.CODE_SCANNER).cannot_establish,
    independence=Independence(independent_of_subject=True, operated_by="release-gate",
                              note="the scanner reads the code; it is not the agent "
                                   "that wrote it"),
    default_producer_id=f"release-gate/{PRODUCER_COMPONENT}")

#: Where `release_gate.audit.build_report` records the provenance block.
SCAN_PROVENANCE_KEY = "evidence_provenance"
SCAN_PROVENANCE_SCHEMA = "release-gate/scan-provenance@1"

#: Candidate components the provenance block's `behaviour` section may carry.
_BEHAVIOUR_COMPONENTS = frozenset({"prompt", "tool_manifest", "eval_definition"})

#: The one prefix a scoped-absence profile may use. Enforced at construction.
_ABSENCE_PREFIX = "static analysis did not identify"

_COMMIT_RE = re.compile(r"^[0-9a-f]{7,64}$")
#: Cross-module taint names its defining file in the origin expression —
#: `llm_call() [helpers/llm.py]` — because `agent_analysis` carries the file
#: that way rather than in a separate key.
_CROSS_FILE_ORIGIN_RE = re.compile(r"\[([^\[\]\s]+)\]\s*$")


# ── what a finding observed ──────────────────────────────────────────────────

class ObservationKind(str, Enum):
    """Whether a finding reports something seen, or something looked for."""

    PRESENCE = "PRESENCE"                # the analyser saw the construct
    SCOPED_ABSENCE = "SCOPED_ABSENCE"    # and did not find a mitigation where it looked
    UNCLASSIFIED = "UNCLASSIFIED"        # a rule id no profile describes


class PathStatus(str, Enum):
    """How much of the source→sink chain the finding carries."""

    TRACED = "TRACED"              # line coordinates for origin and sink
    DESCRIBED = "DESCRIBED"        # the chain in prose, without coordinates
    NOT_RECORDED = "NOT_RECORDED"  # no chain at all


class Binding(str, Enum):
    """What a record's `applies_to_digest` names."""

    SCANNED_FILES = "SCANNED_FILES"  # the manifest of bytes the analyser read
    REPORT = "REPORT"                # only the report document (no provenance block)
    NONE = "NONE"                    # neither is available


class StaticProducerError(ValueError):
    """A profile was described in a way that would let a finding overclaim."""


@dataclass(frozen=True)
class RuleEvidenceProfile:
    """What one rule's finding does and does not establish."""

    rule_id: str
    kind: ObservationKind
    observed: str
    scope: str
    does_not_establish: Tuple[str, ...]
    not_identified: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", ObservationKind(self.kind))
        object.__setattr__(self, "does_not_establish", tuple(self.does_not_establish))
        if not self.does_not_establish:
            raise StaticProducerError(
                f"{self.rule_id}: state what this finding does not establish. A "
                "finding with no stated limit is the one a reader over-reads")
        if self.kind is ObservationKind.SCOPED_ABSENCE:
            if not self.not_identified.startswith(_ABSENCE_PREFIX):
                raise StaticProducerError(
                    f"{self.rule_id}: a scoped absence must say what static analysis "
                    f"did not identify, beginning {_ABSENCE_PREFIX!r}; anything "
                    "broader reads as a claim about the world")
        elif self.not_identified:
            raise StaticProducerError(
                f"{self.rule_id}: only a scoped absence names what was not identified")

    @property
    def observation(self) -> str:
        """The finding as one scoped sentence."""
        if self.not_identified:
            return f"{self.observed}; {self.not_identified}"
        return self.observed

    def to_dict(self) -> Dict[str, Any]:
        return {"rule_id": self.rule_id, "kind": self.kind.value,
                "observed": self.observed, "not_identified": self.not_identified or None,
                "observation": self.observation, "scope": self.scope,
                "does_not_establish": list(self.does_not_establish)}


_RUNTIME = "that this path executes at runtime, or how often"


def _p(rule_id: str, kind: ObservationKind, observed: str, scope: str,
       dne: Sequence[str], not_identified: str = "") -> RuleEvidenceProfile:
    return RuleEvidenceProfile(rule_id=rule_id, kind=kind, observed=observed,
                               scope=scope, does_not_establish=tuple(dne),
                               not_identified=not_identified)


_P, _A = ObservationKind.PRESENCE, ObservationKind.SCOPED_ABSENCE

#: One profile per rule in `release_gate/rules.py`. A test holds the two sets
#: equal, so a rule added to the catalogue without a profile fails the build
#: rather than reaching a case as UNCLASSIFIED.
_PROFILE_LIST: Tuple[RuleEvidenceProfile, ...] = (
    _p("RG-EXEC-001", _P,
       "a value the analyser attributes to model or request output reaches an "
       "execution sink (eval, exec, a shell)", "the source-to-sink path",
       ("that the input reaching the sink is attacker-controlled in deployment",
        "that no sandbox around the process contains the execution", _RUNTIME)),
    _p("RG-EXEC-002", _A,
       "a deserialiser (pickle, marshal, dill) is applied to data", "the call site",
       ("that the data is untrusted",
        "that an untrusted channel can reach this call", _RUNTIME),
       "static analysis did not identify a proof that the data comes from a "
       "trusted, local source"),
    _p("RG-EXEC-003", _P,
       "a dynamic execution call (exec, eval, a shell) is present in agent code",
       "the call site",
       ("that model or user output can reach it — reachability was not traced",
        _RUNTIME)),
    _p("RG-ACTION-002", _P,
       "a URL the analyser attributes to model, tool or user output flows into an "
       "HTTP client", "the source-to-sink path",
       ("that no egress control outside this code (a proxy, a firewall, a "
        "platform policy) constrains the destination", _RUNTIME)),
    _p("RG-ACTION-003", _P,
       "a path the analyser attributes to model output reaches a filesystem write "
       "or delete", "the source-to-sink path",
       ("that no sandbox or filesystem permission outside this code constrains "
        "the path", _RUNTIME)),
    _p("RG-ACTION-004", _P,
       "model output is interpolated into a SQL string that is executed",
       "the source-to-sink path",
       ("that the database account holds the privileges the query would need",
        _RUNTIME)),
    _p("RG-PARSE-001", _A,
       "json.loads or ast.literal_eval is applied to model output", "the call site",
       ("that no caller handles the exception",
        "that malformed model output occurs in practice"),
       "static analysis did not identify a surrounding try/except or result "
       "validation at this call site"),
    _p("RG-TOOL-001", _A,
       "an agent tool performs an action the analyser classifies as irreversible "
       "(delete, send, pay, deploy), inferred from the tool's body", "the tool",
       ("that the impact is undeclared outside this code — in a tool manifest, a "
        "governance file or a platform policy", _RUNTIME),
       "static analysis did not identify a declared impact for this tool in the "
       "code"),
    _p("RG-GATE-001", _A,
       "an agent tool performs an action the analyser classifies as irreversible",
       "the path to the irreversible call",
       ("that no human approval exists anywhere",
        "that no out-of-band control (an orchestrator, a platform policy, a UI "
        "confirmation, an operating procedure) gates this action", _RUNTIME),
       "static analysis did not identify a code-level approval gate on this path"),
    _p("RG-PII-001", _A,
       "context reaches a model call on this path while this project redacts "
       "equivalent context on another path", "the unmasked path, compared with "
       "the project's masked one",
       ("that the context is unmasked downstream (middleware, a proxy, the "
        "provider's own controls)",
        "that the data on this path is in fact sensitive"),
       "static analysis did not identify the project's redaction step on this "
       "path"),
    _p("RG-PROMPT-001", _P,
       "text the analyser attributes to a user or model is interpolated into a "
       "system prompt", "the source-to-sink path",
       ("that the interpolated text is attacker-controlled in deployment",
        "that an injection succeeds against the model in use")),
    _p("RG-PROMPT-002", _P,
       "content traced from an untrusted source (retrieval, an HTTP body, a tool "
       "return) flows into the instruction channel", "the source-to-sink path",
       ("that the source carries adversarial content in deployment",
        "that an injection succeeds against the model in use")),
    _p("RG-COST-001", _A,
       "an LLM call is made", "the call site",
       ("that no ceiling is applied outside this call (client defaults, a "
        "gateway, a provider-side limit)",
        "the cost or latency a call actually incurs"),
       "static analysis did not identify a max_tokens or output-ceiling "
       "argument at this call site"),
    _p("RG-COST-002", _A,
       "LLM request parameters are assembled in a dict and spread into a call",
       "the parameter dict",
       ("that no ceiling is applied outside this call (client defaults, a "
        "gateway, a provider-side limit)",
        "the cost or latency a call actually incurs"),
       "static analysis did not identify an output-ceiling key in the "
       "parameter dict spread into this call"),
    _p("RG-LOOP-001", _A,
       "a loop with no static bound wraps an LLM call", "the loop",
       ("that the loop runs without bound at runtime — a timeout, a budget or an "
        "external stop can end it",
        "how many iterations occur in practice"),
       "static analysis did not identify an iteration cap in this loop"),
    _p("RG-SECRET-001", _P,
       "a credential-shaped literal appears in source", "the line",
       ("that the credential is live", "what it grants access to")),
    _p("RG-SECRET-002", _P,
       "a secret, environment value or PII-shaped value is interpolated into a "
       "prompt sent to a model provider", "the source-to-sink path",
       ("that the value is sensitive in deployment",
        "what the provider retains")),
)

RULE_PROFILES: Mapping[str, RuleEvidenceProfile] = {p.rule_id: p for p in _PROFILE_LIST}


def evidence_profile_for(rule_id: Optional[str]) -> RuleEvidenceProfile:
    """The profile for a rule id — or an explicit UNCLASSIFIED one.

    A report from a newer scanner, or a hand-written one, can carry an id this
    table does not know. Guessing its polarity from its name would give it a
    meaning nobody wrote down; it reads as unclassified instead.
    """
    rid = str(rule_id or "").strip()
    known = RULE_PROFILES.get(rid)
    if known is not None:
        return known
    return RuleEvidenceProfile(
        rule_id=rid or "unidentified",
        kind=ObservationKind.UNCLASSIFIED,
        observed=("the analyser reported a finding under a rule release-gate has no "
                  "evidence profile for"),
        scope="as the finding states it",
        does_not_establish=(
            "anything beyond the finding's own text — what this rule does not "
            "establish was never stated",
            _RUNTIME))


def safeguard_profile(name: str, *, present: bool) -> RuleEvidenceProfile:
    """What the audit's safeguard check establishes, for one safeguard."""
    label = str(name).replace("_", " ")
    if present:
        return RuleEvidenceProfile(
            rule_id=f"safeguard:{name}", kind=ObservationKind.PRESENCE,
            observed=f"a valid {label} declaration is present in this repository",
            scope="this repository's governance file and source",
            does_not_establish=(
                "that the safeguard fires at runtime",
                "that the declaration describes the deployed system"))
    return RuleEvidenceProfile(
        rule_id=f"safeguard:{name}", kind=ObservationKind.SCOPED_ABSENCE,
        observed=(f"release-gate read this repository's governance file and source "
                  f"for a {label} declaration"),
        scope="this repository's governance file and source",
        does_not_establish=(
            f"that the deployed system has no {label}",
            "that no control outside this repository (infrastructure, an "
            "orchestrator, a platform policy, an operating procedure) provides it"),
        not_identified=(f"static analysis did not identify a valid {label} "
                        "declaration in this repository"))


def safeguard_statement(name: str) -> str:
    """The claim a safeguard check can answer: about the repository, not the system."""
    return f"this repository carries a valid {str(name).replace('_', ' ')} declaration"


# ── where a finding sits in the code ─────────────────────────────────────────

def _int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def origin_file(finding: Mapping[str, Any]) -> Optional[str]:
    """The file a cross-module taint originates in, or None for same-file."""
    provenance = finding.get("provenance")
    if not isinstance(provenance, Mapping):
        return None
    match = _CROSS_FILE_ORIGIN_RE.search(str(provenance.get("origin_expr") or ""))
    return match.group(1) if match else None


def finding_span(finding: Mapping[str, Any]) -> Optional[Tuple[int, int]]:
    """The inclusive line range a finding covers in its own file.

    The origin line joins the span only when it is in the same file; a
    cross-module origin's line number belongs to another file and would widen
    this one's range over lines that have nothing to do with it.
    """
    points = [_int(finding.get("line"))]
    provenance = finding.get("provenance")
    if isinstance(provenance, Mapping):
        points.append(_int(provenance.get("sink_line")))
        if origin_file(finding) is None:
            points.append(_int(provenance.get("origin_line")))
    points = [p for p in points if p > 0]
    if not points:
        return None
    return min(points), max(points)


def region_key(file: str, start: int, end: int) -> str:
    """The key the audit files a region digest under. One spelling, both sides."""
    return f"{file}#L{start}-L{end}"


# ── the provenance block ─────────────────────────────────────────────────────

def _text(value: Any) -> Optional[str]:
    text = str(value).strip() if isinstance(value, (str, int, float)) else ""
    return text or None


def _digest(value: Any) -> Optional[str]:
    return value if is_digest(value) else None


def _digest_map(value: Any) -> Dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    return {str(k): v for k, v in value.items() if is_digest(v)}


@dataclass(frozen=True)
class ScanProvenance:
    """The audit's account of what it scanned, read without embellishment.

    Every field that the report does not carry, or carries malformed, is None
    or empty. Nothing here is defaulted from the environment reading it: the
    version running now is not the version that scanned, and today is not
    when it scanned.
    """

    recorded: bool = False
    scanner_version: Optional[str] = None
    analyser_digest: Optional[str] = None
    ruleset_digest: Optional[str] = None
    rule_digests: Mapping[str, str] = field(default_factory=dict)
    rule_types: Mapping[str, str] = field(default_factory=dict)
    repository: Optional[str] = None
    root_relative: Optional[str] = None
    vcs: str = "unknown"
    commit: Optional[str] = None
    tree_state: str = "unknown"
    scanned_set_digest: Optional[str] = None
    files_scanned: Optional[int] = None
    file_digests: Mapping[str, str] = field(default_factory=dict)
    region_digests: Mapping[str, str] = field(default_factory=dict)
    governance_digest: Optional[str] = None
    #: Candidate components beyond the code (prompt, tool_manifest,
    #: eval_definition), each a digest over the files the lockfile collector
    #: classes as that kind. Empty for a component with no files.
    behaviour: Mapping[str, str] = field(default_factory=dict)
    scanned_at: Optional[str] = None
    limitations: Tuple[str, ...] = ()

    @classmethod
    def from_report(cls, doc: Mapping[str, Any]) -> "ScanProvenance":
        block = doc.get(SCAN_PROVENANCE_KEY) if isinstance(doc, Mapping) else None
        if not isinstance(block, Mapping):
            return cls()
        scanner = block.get("scanner") if isinstance(block.get("scanner"), Mapping) else {}
        ruleset = block.get("ruleset") if isinstance(block.get("ruleset"), Mapping) else {}
        repo = block.get("repository") if isinstance(block.get("repository"), Mapping) else {}
        cand = block.get("candidate") if isinstance(block.get("candidate"), Mapping) else {}
        scanned = cand.get("scanned_set") if isinstance(cand.get("scanned_set"), Mapping) else {}
        rules = ruleset.get("rules") if isinstance(ruleset.get("rules"), Mapping) else {}
        rule_digests: Dict[str, str] = {}
        rule_types: Dict[str, str] = {}
        for rid, entry in rules.items():
            if isinstance(entry, Mapping):
                if is_digest(entry.get("digest")):
                    rule_digests[str(rid)] = entry["digest"]
                category, type_key = _text(entry.get("category")), _text(entry.get("type_key"))
                if category and type_key:
                    rule_types[str(rid)] = f"{category}/{type_key}"
        commit = _text(cand.get("commit"))
        commit = commit.lower() if commit and _COMMIT_RE.match(commit.lower()) else None
        tree = _text(cand.get("tree_state"))
        vcs = _text(repo.get("vcs"))
        files_scanned = scanned.get("files")
        governance = block.get("governance_file")
        limitations = block.get("limitations")
        behaviour_block = block.get("behaviour") if isinstance(
            block.get("behaviour"), Mapping) else {}
        behaviour = {str(k): v["digest"] for k, v in behaviour_block.items()
                     if isinstance(v, Mapping) and is_digest(v.get("digest"))
                     and str(k) in _BEHAVIOUR_COMPONENTS}
        return cls(
            recorded=True,
            scanner_version=_text(scanner.get("version")),
            analyser_digest=_digest(scanner.get("analyser_digest")),
            ruleset_digest=_digest(ruleset.get("digest")),
            rule_digests=rule_digests, rule_types=rule_types,
            repository=_text(repo.get("identity")),
            root_relative=_text(repo.get("root_relative")),
            vcs=vcs if vcs in ("git", "none") else "unknown",
            commit=commit,
            tree_state=tree if tree in ("clean", "dirty") else "unknown",
            scanned_set_digest=_digest(scanned.get("digest")),
            files_scanned=(files_scanned if isinstance(files_scanned, int)
                           and not isinstance(files_scanned, bool)
                           and files_scanned >= 0 else None),
            file_digests=_digest_map(block.get("files")),
            region_digests=_digest_map(block.get("regions")),
            governance_digest=(_digest(governance.get("sha256"))
                               if isinstance(governance, Mapping) else None),
            behaviour=behaviour,
            scanned_at=_text(block.get("scanned_at")),
            limitations=tuple(str(x) for x in limitations
                              if isinstance(x, str) and x.strip())
            if isinstance(limitations, list) else ())

    @property
    def binding(self) -> Binding:
        return Binding.SCANNED_FILES if self.scanned_set_digest else Binding.REPORT

    def code_state(self, *, governance: bool = False) -> Dict[str, str]:
        """What a static record was produced against, as candidate components.

        A finding is about the code, so it names the repository, commit and the
        scanned tree. A safeguard check also read the governance file, so it
        names that too. Components the report did not record are left out.
        """
        state = {"repository": self.repository, "commit": self.commit,
                 "tree": self.scanned_set_digest}
        if governance:
            state["governance_policy"] = self.governance_digest
        return {k: v for k, v in state.items() if v}

    def candidate_state(self, doc: Mapping[str, Any]) -> Optional[Any]:
        """The candidate an audit report implies: what it scanned, and with what.

        Attributed to the document, like the rest of the block. None for a
        report that carries no provenance — nothing is inferred to replace it.
        """
        if not self.recorded:
            return None
        from release_gate.assurance.candidate import (
            CandidateError, CandidateSource, CandidateState)
        components: Dict[str, str] = dict(self.code_state(governance=True))
        components.update(self.behaviour)
        model = doc.get("detected_model") if isinstance(doc, Mapping) else None
        if isinstance(model, str) and model.strip():
            components["model"] = model.strip()
        if not components:
            return None
        try:
            return CandidateState(
                components=components, source=CandidateSource.DERIVED_FROM_AUDIT,
                declared_by="release-gate/audit, attributed by the document",
                note="what the audit scanned: code, governance file, model, and the "
                     "prompt / tool / eval files the lockfile collector found")
        except CandidateError:
            return None

    def candidate(self) -> Dict[str, Any]:
        """The code state, as the report describes it. None means not recorded."""
        return {"repository": self.repository, "root_relative": self.root_relative,
                "vcs": self.vcs, "commit": self.commit, "tree_state": self.tree_state,
                "scanned_set_digest": self.scanned_set_digest,
                "files_scanned": self.files_scanned}


# ── the producer ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class StaticEmission:
    """What one audit report becomes."""

    evidence: Tuple[EvidenceRecord, ...]
    claims: Tuple[Claim, ...]
    expectations: Tuple[EvidenceExpectation, ...]
    artifacts: Tuple[Artifact, ...]
    mapped: int
    binding: Binding

    def records(self) -> List[Dict[str, Any]]:
        """The emission as envelope rows: each record's own serialised form.

        Evidence rows are `EvidenceRecord.to_dict()` exactly, so each one can
        be re-checked with `EvidenceRecord.from_dict`, which recomputes its id
        and refuses a row edited after it was written. The list is also a valid
        assurance envelope, and `release-gate assure` reads it as one — as
        DECLARED evidence from a document, which is what a file on disk is.
        """
        rows: List[Dict[str, Any]] = [a.to_dict() for a in self.artifacts]
        rows.extend(c.to_dict() for c in self.claims)
        rows.extend(e.to_dict() for e in self.evidence)
        rows.extend({"record_type": "expectation", "dimension": x.dimension,
                     "assessed": x.assessed, "note": x.note,
                     "observed_from": x.observed_from} for x in self.expectations)
        return rows


class StaticEvidenceProducer:
    """release-gate's static analysis, emitting Universal Evidence.

    The lane description is `producers.lane_for(CODE_SCANNER)`, not a second
    copy of it: what this producer cannot establish is stated once.
    """

    producer_type = PRODUCER_TYPE

    def __init__(self, provenance: Optional[ScanProvenance] = None, *,
                 in_process: bool = False) -> None:
        self.provenance = provenance or ScanProvenance()
        self.in_process = bool(in_process)
        self.producer: Producer = Producer.release_gate(
            PRODUCER_COMPONENT, in_process=self.in_process,
            version=self.provenance.scanner_version)

    @classmethod
    def for_report(cls, doc: Mapping[str, Any], *,
                   in_process: bool = False) -> "StaticEvidenceProducer":
        return cls(ScanProvenance.from_report(doc), in_process=in_process)

    @property
    def descriptor(self) -> EvidenceProducer:
        return lane_for(EvidenceLane.CODE_SCANNER)

    # ── binding ──────────────────────────────────────────────────────────

    def applies_to(self, report_digest: Optional[str]) -> Tuple[Optional[str], Binding]:
        if self.provenance.scanned_set_digest:
            return self.provenance.scanned_set_digest, Binding.SCANNED_FILES
        if report_digest:
            return report_digest, Binding.REPORT
        return None, Binding.NONE

    def candidate_artifact(self) -> Optional[Artifact]:
        """The scanned code, as an artifact the evidence names.

        OBSERVED only when this process computed the manifest; a manifest
        digest read out of a document is that document's assertion.
        """
        digest = self.provenance.scanned_set_digest
        if not digest:
            return None
        handle = self.provenance.repository or "scanned-files"
        if self.provenance.root_relative:
            handle = f"{handle}/{self.provenance.root_relative}"
        return Artifact(
            logical_id=f"code:{handle}", artifact_kind=ArtifactKind.SOURCE_CODE,
            digest=digest, digest_method=DigestMethod.SHA256_MANIFEST,
            digest_status=(DigestStatus.OBSERVED if self.in_process
                           else DigestStatus.DECLARED),
            digest_attested_by=None if self.in_process else self.producer.producer_id,
            created_by=self.producer.producer_id,
            metadata={"role": "scanned-candidate", **{
                k: v for k, v in self.provenance.candidate().items()
                if k != "scanned_set_digest"}})

    # ── common fields ────────────────────────────────────────────────────

    def _reproducibility(self, binding: Binding, **extra: Any) -> Dict[str, Any]:
        p = self.provenance
        meta: Dict[str, Any] = {
            **STATIC_DECLARATION.summary(),
            "provenance_recorded": p.recorded,
            "scanner_version": p.scanner_version,
            "analyser_digest": p.analyser_digest,
            "ruleset_digest": p.ruleset_digest,
            "binding": binding.value,
            **p.candidate(),
        }
        meta.update(extra)
        if p.scanned_at and not self.in_process:
            # The document's clock. Kept as a declaration beside the record,
            # under the key the envelope ingest uses for the same thing, and
            # never written into `timestamp`, which means "observed here".
            meta["declared_timestamp"] = p.scanned_at
        return meta

    def _state_field(self, *, governance: bool = False) -> Dict[str, Any]:
        """`content.state`: the candidate components this record was produced against."""
        state = self.provenance.code_state(governance=governance)
        return {"state": state} if state else {}

    def _timestamp(self) -> str:
        return (self.provenance.scanned_at or "") if self.in_process else ""

    def _limitations(self, *items: str) -> List[str]:
        out = [i for i in items if i]
        if not self.provenance.recorded:
            out.append("this report carries no provenance block, so the repository, "
                       "commit, scanner version and code hashes were not recorded; "
                       "the evidence is bound to the report document instead")
        out.extend(self.provenance.limitations)
        return out

    # ── one finding ──────────────────────────────────────────────────────

    def finding_record(self, finding: Mapping[str, Any], *, source: str,
                       applies_to: Optional[str], binding: Binding,
                       contradicts: Tuple[str, ...]) -> EvidenceRecord:
        rule_id = finding.get("rule_id")
        profile = evidence_profile_for(rule_id if isinstance(rule_id, str) else None)
        file = str(finding.get("file") or "")
        span = finding_span(finding)
        provenance = finding.get("provenance")
        chain = str(finding.get("evidence") or "")

        path: Dict[str, Any]
        if isinstance(provenance, Mapping) and _int(provenance.get("origin_line")):
            origin_in = origin_file(finding) or file
            path = {"status": PathStatus.TRACED.value,
                    "source": {"file": origin_in,
                               "line": _int(provenance.get("origin_line")),
                               "expression": str(provenance.get("origin_expr") or "")},
                    "sink": {"file": file,
                             "line": _int(provenance.get("sink_line"))
                             or _int(finding.get("line"))},
                    "value": str(provenance.get("value") or ""),
                    "chain": chain}
        elif chain:
            path = {"status": PathStatus.DESCRIBED.value, "chain": chain}
        else:
            path = {"status": PathStatus.NOT_RECORDED.value}

        region = None
        if span is not None:
            key = region_key(file, *span)
            region = {"start": span[0], "end": span[1],
                      "sha256": self.provenance.region_digests.get(key)}
        code = {"file_sha256": self.provenance.file_digests.get(file),
                "region": region}
        origin_in = path.get("source", {}).get("file") if path.get("source") else None
        if origin_in and origin_in != file:
            code["origin_file_sha256"] = self.provenance.file_digests.get(origin_in)

        rid = profile.rule_id if profile.kind is not ObservationKind.UNCLASSIFIED else (
            str(rule_id) if rule_id else None)
        tags = finding.get("compliance_tags")
        content: Dict[str, Any] = {
            # The keys the bridge always carried, under the same names, so every
            # reader of the earlier shape still finds them.
            **{k: finding.get(k) for k in
               ("rule_id", "title", "file", "line", "severity", "basis",
                "confidence", "evidence", "compliance_tags") if k in finding},
            "method": VerificationMethod.STATIC_ANALYSIS.value,
            "producer_type": PRODUCER_TYPE,
            "finding_type": self.provenance.rule_types.get(rid or ""),
            "observation_kind": profile.kind.value,
            "observation": profile.observation,
            "not_identified": profile.not_identified or None,
            "does_not_establish": list(profile.does_not_establish),
            "scope": profile.scope,
            "location": {"file": file, "line": _int(finding.get("line")),
                         "start_line": span[0] if span else None,
                         "end_line": span[1] if span else None},
            "path": path,
            "code": code,
            "framework_mappings": sorted({str(t) for t in tags}) if isinstance(
                tags, (list, tuple)) else [],
            "rule": {"id": rid, "digest": self.provenance.rule_digests.get(rid or "")},
            **self._state_field(),
            "limitations": self._limitations(
                "" if path["status"] == PathStatus.TRACED.value else
                (f"no source-to-sink coordinates were recorded for this finding "
                 f"(basis={finding.get('basis', 'unstated')})")),
        }
        note = (f"static analysis, basis={finding.get('basis', 'unstated')}, "
                f"confidence={finding.get('confidence', 'unstated')}: "
                f"{profile.observation}. Scope: {profile.scope}. Not established: "
                f"{profile.does_not_establish[0]}")
        return EvidenceRecord.derived(
            EvidenceType.STATIC_FINDING, source=source, producer=self.producer,
            # No `verification_method`: a static finding argues against a claim;
            # it is not a check that reached a verdict, and the model refuses a
            # method on a DERIVED record for exactly that reason.
            applies_to_digest=applies_to, timestamp=self._timestamp(),
            content=content, contradicts_claims=contradicts,
            coverage_status=CoverageStatus.PARTIAL, coverage_note=note,
            metadata=self._reproducibility(
                binding, rule_digest=self.provenance.rule_digests.get(rid or "")))

    # ── the whole report ─────────────────────────────────────────────────

    def emit(self, doc: Mapping[str, Any], *, source: str,
             report_digest: Optional[str] = None) -> StaticEmission:
        """Turn one audit report into claims, evidence, coverage and the candidate.

        Claims are derived from the audit's own dimensions and never invented: a
        dimension the audit does not assess produces no claim, and one it
        assesses and fails produces a claim with evidence against it rather
        than a missing claim.
        """
        applies_to, binding = self.applies_to(report_digest)
        producer = self.producer
        evidence: List[EvidenceRecord] = []
        claims: List[Claim] = []
        expectations: List[EvidenceExpectation] = []
        mapped = 0

        findings = [f for f in (doc.get("code_findings") or []) if isinstance(f, Mapping)]
        safeguards = doc.get("safeguards") or {}
        # A plain boolean counts. `audit.py` emits the {present, status, evidence}
        # mapping, but `_sg_present` documents the bare-bool shape as supported and
        # a governance.yaml writes exactly that (`kill_switch: true`). Requiring a
        # Mapping dropped every bool-shaped safeguard silently, so a document
        # declaring `kill_switch: false` was indistinguishable from one that
        # declared nothing — the omission family, on the governance path.
        safeguard_items = ([(str(name), value if isinstance(value, Mapping)
                             else {"present": bool(value)})
                            for name, value in safeguards.items()
                            if isinstance(value, (Mapping, bool))]
                           if isinstance(safeguards, Mapping) else [])
        dimension_claims: List[str] = []
        scope_note = ("the files release-gate's static analysis read, under its ruleset"
                      if binding is not Binding.SCANNED_FILES else
                      f"the {self.provenance.files_scanned} file(s) in the scanned set "
                      f"{self.provenance.scanned_set_digest}")

        # ── code safety: findings argue against it ──────────────────────────
        code_safety = doc.get("code_safety") or {}
        if findings or (isinstance(code_safety, Mapping) and code_safety.get("applicable")):
            claim_id = "sw:code-safety"
            dimension_claims.append(claim_id)
            claims.append(Claim(
                claim_id=claim_id, producer=producer,
                statement="static analysis found no unsafe pattern in this code",
                metadata={"scope": scope_note, "producer_type": PRODUCER_TYPE}))
            for finding in findings:
                evidence.append(self.finding_record(
                    finding, source=source, applies_to=applies_to, binding=binding,
                    contradicts=(claim_id,)))
                mapped += 1
            if not findings:
                coverage = doc.get("scan_coverage") if isinstance(
                    doc.get("scan_coverage"), Mapping) else {}
                truncated = bool(coverage.get("truncated"))
                evidence.append(EvidenceRecord.derived(
                    EvidenceType.STATIC_FINDING, source=source, producer=producer,
                    applies_to_digest=applies_to, timestamp=self._timestamp(),
                    content={"findings": 0, "score": code_safety.get("score"),
                             "method": VerificationMethod.STATIC_ANALYSIS.value,
                             "producer_type": PRODUCER_TYPE,
                             **self._state_field(),
                             "observation_kind": ObservationKind.SCOPED_ABSENCE.value,
                             "observation": ("static analysis did not identify a "
                                             "pattern its ruleset reports in the "
                                             "scanned code"),
                             "does_not_establish": [
                                 "that the code is safe",
                                 "that a flow the analyser does not model (beyond "
                                 "its cross-function summaries, dynamic dispatch, "
                                 "a language it does not parse) is absent",
                                 _RUNTIME],
                             "limitations": self._limitations(
                                 "the scan stopped at its file ceiling, so part of "
                                 "the repository was not read" if truncated else "")},
                    supports_claims=(claim_id,),
                    coverage_status=CoverageStatus.PARTIAL,
                    coverage_note=("static analysis found nothing; that bounds what was "
                                   "scanned and never establishes that the code is safe"),
                    metadata=self._reproducibility(binding)))
                mapped += 1

        # ── declared safeguards ─────────────────────────────────────────────
        for name, value in safeguard_items:
            claim_id = f"sw:safeguard:{name}"
            dimension_claims.append(claim_id)
            claims.append(Claim(
                claim_id=claim_id, producer=producer,
                statement=safeguard_statement(name),
                metadata={"scope": "this repository's governance file and source",
                          "does_not_ask": (f"whether the deployed system has a "
                                           f"{name.replace('_', ' ')}"),
                          "producer_type": PRODUCER_TYPE}))
            present = bool(value.get("present"))
            detail = str(value.get("evidence") or value.get("detail") or "")
            profile = safeguard_profile(name, present=present)
            code = {"governance_sha256": self.provenance.governance_digest}
            if present:
                # A safeguard somebody declared. DECLARED, because a governance
                # file saying a kill switch exists is the producer's account of
                # their own system and not a runtime guarantee (Invariant 1).
                evidence.append(EvidenceRecord.from_producer(
                    {"safeguard": name, "status": value.get("status"), "detail": detail},
                    evidence_type=EvidenceType.ATTESTATION, source=source,
                    producer=producer, status=EpistemicStatus.DECLARED,
                    applies_to_digest=applies_to, supports_claims=(claim_id,),
                    timestamp=self._timestamp(),
                    content={"producer_type": PRODUCER_TYPE,
                             "observation_kind": profile.kind.value,
                             "observation": profile.observation,
                             "does_not_establish": list(profile.does_not_establish),
                             "scope": profile.scope, "code": code,
                             **self._state_field(governance=True)},
                    coverage_status=CoverageStatus.PARTIAL,
                    coverage_note="declared safeguard; a declaration is not a runtime "
                                  "guarantee",
                    metadata=self._reproducibility(binding)))
            else:
                # A declaration release-gate looked for and did not find. That is
                # release-gate's own observation, so it is DERIVED, and it argues
                # against the claim that this repository carries one. It says
                # nothing about the deployed system, and the claim no longer
                # asks it to.
                evidence.append(EvidenceRecord.derived(
                    EvidenceType.STATIC_FINDING, source=source, producer=producer,
                    applies_to_digest=applies_to, timestamp=self._timestamp(),
                    content={"safeguard": name, "status": value.get("status"),
                             "detail": detail,
                             "issues": [str(i) for i in
                                        list(value.get("issues") or ())[:4]],
                             "compliance_tags": [str(t) for t in
                                                 (value.get("compliance_tags") or ())],
                             "producer_type": PRODUCER_TYPE,
                             "observation_kind": profile.kind.value,
                             "observation": profile.observation,
                             "not_identified": profile.not_identified,
                             "does_not_establish": list(profile.does_not_establish),
                             "scope": profile.scope, "code": code,
                             **self._state_field(governance=True),
                             "limitations": self._limitations()},
                    contradicts_claims=(claim_id,),
                    coverage_status=CoverageStatus.PARTIAL,
                    coverage_note=(f"{profile.not_identified}; this does not establish "
                                   f"{profile.does_not_establish[0]}"),
                    metadata=self._reproducibility(binding)))
            mapped += 1

        # ── link claims to the evidence that argues about them ──────────────
        by_for: Dict[str, List[str]] = {}
        by_against: Dict[str, List[str]] = {}
        for record in evidence:
            for cid in record.supports_claims:
                by_for.setdefault(cid, []).append(record.evidence_id)
            for cid in record.contradicts_claims:
                by_against.setdefault(cid, []).append(record.evidence_id)
        for index, claim in enumerate(claims):
            supports = tuple(by_for.get(claim.claim_id, ()))
            against = tuple(by_against.get(claim.claim_id, ()))
            if supports or against:
                claims[index] = dataclasses.replace(
                    claim, supporting_evidence=supports, contradicting_evidence=against)

        # ── the root: what admitting this change would mean ─────────────────
        if dimension_claims:
            claims.append(Claim(
                claim_id="sw:admissible", producer=producer, is_root=True,
                statement="this change is safe to admit",
                parents=tuple(dimension_claims)))

        # ── the audit's own coverage, as coverage ───────────────────────────
        # Folded through the expectation mechanism so an audit dimension the
        # checks could not reach reads as NOT_ASSESSED on the case, rather than
        # being absent and therefore invisible (Invariant 3).
        for row in (doc.get("coverage") or []):
            if not isinstance(row, Mapping):
                continue
            dimension = str(row.get("dimension") or "").strip()
            if not dimension:
                continue
            try:
                expectations.append(EvidenceExpectation(
                    dimension=dimension.lower().replace(" ", "_").replace("/", "_"),
                    assessed=str(row.get("status") or "") == "assessed",
                    note=str(row.get("note") or ""),
                    observed_from="release-gate/audit"))
                mapped += 1
            except Exception:
                continue

        candidate = self.candidate_artifact()
        return StaticEmission(
            evidence=tuple(evidence), claims=tuple(claims),
            expectations=tuple(expectations),
            artifacts=(candidate,) if candidate is not None else (),
            mapped=mapped, binding=binding)


def emit_from_report(doc: Mapping[str, Any], *, source: str,
                     report_digest: Optional[str] = None,
                     in_process: bool = False) -> StaticEmission:
    """One call: an audit report in, its Universal Evidence out."""
    return StaticEvidenceProducer.for_report(doc, in_process=in_process).emit(
        doc, source=source, report_digest=report_digest)

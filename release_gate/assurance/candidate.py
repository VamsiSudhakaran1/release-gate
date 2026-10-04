"""CandidateState — the exact release being admitted, and whether evidence is about it.

An approval is only worth something if it attaches to an exact state. So is
evidence. A formal proof of `transfer_tool_v2` is a real proof — of version two.
Presented beside a candidate that ships version three, it must not satisfy a
claim about the candidate, and before this module nothing stopped it: the claim
graph counted the proof's PASSED attempt and read the claim VERIFIED. RG-CLAIM-007
held the case under the methodologies that ask, but the claim itself still said
VERIFIED, and every methodology that does not ask was told the proof applied.

**A candidate is a set of components, not one digest.** What determines how an
agent behaves is spread across things a single hash does not cover: the code
(repository, commit, tree), the image, the model, the prompt, the tool / MCP
manifest, the governance policy, the eval definitions, the deployment
configuration, the dataset, the environment, and whatever artifacts the release
generates. `CandidateState` names each one that is known, canonicalises it, and
digests the set. A component nobody stated is absent, never defaulted (Invariant
3); `missing()` lists them.

**Evidence binds to whichever components it names.** A record's `content.state`
— where a producer says what it ran against — and its `applies_to_digest`, and a
verification attempt's `target_digest`, are compared with the candidate component
by component. The outcome is one of five, and they are deliberately not merged:

    EXACT         every component the candidate states is named, and matches
    PARTIAL       what the record names matches; it names only some of them
    STALE         it names a different revision of something the candidate holds
    INCOMPATIBLE  it is about a different subject — another repository or
                  environment
    UNKNOWN       it names nothing the candidate states; nothing can be compared

**Stale and incompatible support is withheld; refutations are not.** A proof of
the previous version stops counting toward the claim, and the claim's status
says why. A counterexample found against the previous version still stands: a
defect is not answered by moving on, and dropping it would turn a known problem
into a gap — the conversion of a refutation into an unknown that this engine
refuses. The asymmetry is the safety property, and both halves are tested.

**Where the candidate comes from is recorded.** A caller can state it (`assure
--candidate`). A submission can state it (an envelope `candidate` record), which
is the submitter describing its own release and is labelled so. An audit report
implies one from its provenance block. With none of those, the case's own current
artifacts are the candidate — so a proof bound to a digest the case no longer
holds is still caught — but only an explicit candidate makes unbound support a
finding, because without one there is nothing it should have been bound to.

This module computes; it decides nothing. The claim graph reads the bindings to
withhold support, the analysers report them (RG-DRIFT-006 to -009), and the
review explains each rejected record in words.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from release_gate.assurance.canonical import digest_object, is_digest

__all__ = [
    "CANDIDATE_SCHEMA_VERSION",
    "CandidateError",
    "CandidateSource",
    "CandidateState",
    "ComponentClass",
    "ComponentOutcome",
    "StateBinding",
    "StateBindingReport",
    "StateComponent",
    "StateMatch",
    "bind_case",
    "candidate_for_case",
    "values_equal",
]

CANDIDATE_SCHEMA_VERSION = 1

#: Where the candidate is stored on a case. Case metadata is part of the digest
#: an approval binds to, so the candidate a decision was made against is bound
#: with it. A case with no stated candidate carries no key at all.
CANDIDATE_METADATA_KEY = "candidate_state"

MAX_VALUE_CHARS = 512


class CandidateError(ValueError):
    """A candidate state was described in a way that could not be compared."""


class StateComponent(str, Enum):
    """The named dimensions of a candidate release."""

    REPOSITORY = "repository"
    COMMIT = "commit"
    TREE = "tree"
    IMAGE = "image"
    MODEL = "model"
    PROMPT = "prompt"
    TOOL_MANIFEST = "tool_manifest"
    GOVERNANCE_POLICY = "governance_policy"
    EVAL_DEFINITION = "eval_definition"
    DEPLOYMENT_CONFIG = "deployment_config"
    DATASET = "dataset"
    ENVIRONMENT = "environment"


#: Prefixes for components the enum cannot list in advance: a release's
#: generated artifacts by name, and an organisation's own dimensions.
ARTIFACT_PREFIX = "artifact:"
CUSTOM_PREFIX = "custom:"


class ComponentClass(str, Enum):
    """What a mismatch on this component means."""

    IDENTITY = "IDENTITY"  # a different value is a different subject
    REVISION = "REVISION"  # a different value is a different version of this one


_IDENTITY_COMPONENTS = frozenset({StateComponent.REPOSITORY.value,
                                  StateComponent.ENVIRONMENT.value})


def component_class(key: str) -> ComponentClass:
    return ComponentClass.IDENTITY if key in _IDENTITY_COMPONENTS else ComponentClass.REVISION


def canonical_key(key: Any) -> Optional[str]:
    """The canonical spelling of a component key, or None if it is not one."""
    text = str(key or "").strip()
    lowered = text.lower()
    if lowered in {c.value for c in StateComponent}:
        return lowered
    for prefix in (ARTIFACT_PREFIX, CUSTOM_PREFIX):
        if lowered.startswith(prefix) and len(text) > len(prefix):
            return prefix + text[len(prefix):].strip()
    return None


_SCP_RE = re.compile(r"^(?:[^@/]+@)?([^:/]+):(.+)$")


def _canonical_repository(value: str) -> str:
    """One spelling for one repository: host/path, no scheme, user, `.git` or slash."""
    text = value.strip()
    if "://" in text:
        text = text.split("://", 1)[1]
        text = text.split("@", 1)[1] if "@" in text.split("/", 1)[0] else text
    else:
        match = _SCP_RE.match(text)
        if match:
            text = f"{match.group(1)}/{match.group(2)}"
    text = text.split("?", 1)[0].split("#", 1)[0].rstrip("/")
    if text.endswith(".git"):
        text = text[:-4]
    host, _, path = text.partition("/")
    return f"{host.lower()}/{path}" if path else host.lower()


def canonical_value(key: str, value: Any) -> str:
    """Canonicalise one component value, or refuse it."""
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        raise CandidateError(f"{key}: a component value is a string, got {type(value).__name__}")
    text = str(value).strip()
    if not text:
        raise CandidateError(f"{key}: an empty value is not a state; omit the component")
    if len(text) > MAX_VALUE_CHARS:
        raise CandidateError(f"{key}: a value over {MAX_VALUE_CHARS} characters is "
                             "not an identifier")
    control = next((c for c in text if ord(c) < 0x20 or ord(c) == 0x7F), None)
    if control is not None:
        raise CandidateError(f"{key}: a control character (U+{ord(control):04X}) in an "
                             "identifier would forge a row in the report")
    if key == StateComponent.REPOSITORY.value:
        return _canonical_repository(text)
    if is_digest(text.lower()) or text.lower().startswith("git:"):
        return text.lower()
    if key in (StateComponent.COMMIT.value, StateComponent.TREE.value):
        return text.lower()
    if key in (StateComponent.MODEL.value, StateComponent.ENVIRONMENT.value):
        return text.lower()
    return text


class CandidateSource(str, Enum):
    """Who said what the candidate is. It travels with the candidate."""

    DECLARED_BY_CALLER = "DECLARED_BY_CALLER"          # --candidate, the API
    DECLARED_BY_SUBMISSION = "DECLARED_BY_SUBMISSION"  # the submission describing itself
    DERIVED_FROM_AUDIT = "DERIVED_FROM_AUDIT"          # an audit report's provenance block
    IMPLIED_BY_ARTIFACTS = "IMPLIED_BY_ARTIFACTS"      # nobody stated one; the case's artifacts


@dataclass(frozen=True)
class CandidateState:
    """The components of one candidate release, canonicalised."""

    components: Mapping[str, str]
    source: CandidateSource = CandidateSource.DECLARED_BY_CALLER
    declared_by: str = ""
    note: str = ""
    schema_version: int = CANDIDATE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "source", CandidateSource(self.source))
        canonical: Dict[str, str] = {}
        for raw_key, raw_value in dict(self.components or {}).items():
            key = canonical_key(raw_key)
            if key is None:
                raise CandidateError(
                    f"{raw_key!r} is not a candidate component. Known: "
                    + ", ".join(c.value for c in StateComponent)
                    + f", or {ARTIFACT_PREFIX}<name> / {CUSTOM_PREFIX}<name>. A "
                    "misspelt component would silently match nothing")
            if key in canonical:
                raise CandidateError(f"{key} is stated twice")
            canonical[key] = canonical_value(key, raw_value)
        object.__setattr__(self, "components", dict(sorted(canonical.items())))

    @property
    def explicit(self) -> bool:
        """Did somebody state this candidate, rather than release-gate inferring it?"""
        return self.source is not CandidateSource.IMPLIED_BY_ARTIFACTS

    def missing(self) -> Tuple[str, ...]:
        """The named components this candidate does not state."""
        return tuple(c.value for c in StateComponent if c.value not in self.components)

    def identity(self) -> Dict[str, Any]:
        return {"schema_version": self.schema_version,
                "components": dict(self.components)}

    def digest(self) -> str:
        """Content identity of the state itself — not of who declared it."""
        return digest_object(self.identity())

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "candidate_state", "digest": self.digest(),
                **self.identity(), "source": self.source.value,
                "declared_by": self.declared_by, "note": self.note,
                "missing": list(self.missing()), "explicit": self.explicit}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any], *,
                  source: Optional[CandidateSource] = None,
                  declared_by: Optional[str] = None) -> "CandidateState":
        if not isinstance(data, Mapping):
            raise CandidateError("a candidate state is a JSON object")
        components = data.get("components")
        if components is None:
            # A flat file of components is the natural thing to write by hand.
            components = {k: v for k, v in data.items()
                          if k not in ("record_type", "source", "declared_by", "note",
                                       "schema_version", "digest", "missing", "explicit")}
        if not isinstance(components, Mapping) or not components:
            raise CandidateError("a candidate state must name at least one component")
        version = int(data.get("schema_version") or CANDIDATE_SCHEMA_VERSION)
        if version > CANDIDATE_SCHEMA_VERSION:
            raise CandidateError(
                f"candidate state schema {version} is newer than this reader "
                f"({CANDIDATE_SCHEMA_VERSION}); upgrade rather than read it loosely")
        stated_source = source or CandidateSource(
            str(data.get("source") or CandidateSource.DECLARED_BY_CALLER.value))
        return cls(components=components, source=stated_source,
                   declared_by=declared_by if declared_by is not None
                   else str(data.get("declared_by") or ""),
                   note=str(data.get("note") or ""))


# ── binding ──────────────────────────────────────────────────────────────────

class StateMatch(str, Enum):
    EXACT = "EXACT"
    PARTIAL = "PARTIAL"
    STALE = "STALE"
    INCOMPATIBLE = "INCOMPATIBLE"
    UNKNOWN = "UNKNOWN"


#: Matches whose support is withheld from claims. Refutations are never withheld.
WITHHELD = frozenset({StateMatch.STALE, StateMatch.INCOMPATIBLE})


class ComponentOutcome(str, Enum):
    MATCH = "MATCH"
    MISMATCH = "MISMATCH"
    NOT_BOUND = "NOT_BOUND"                  # the candidate states it; the record does not
    NOT_IN_CANDIDATE = "NOT_IN_CANDIDATE"    # the record states it; the candidate does not


#: The pseudo-component a bare digest is compared under when it matches nothing:
#: content the candidate does not contain.
CONTENT = "content"


@dataclass(frozen=True)
class ComponentComparison:
    component: str
    outcome: ComponentOutcome
    record_value: Optional[str] = None
    candidate_value: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {"component": self.component, "outcome": self.outcome.value,
                "record_value": self.record_value, "candidate_value": self.candidate_value}


def _short(value: Optional[str]) -> str:
    if not value:
        return "nothing"
    return value[:19] + "…" if len(value) > 22 else value


@dataclass(frozen=True)
class StateBinding:
    """One record's relationship to the candidate, and why."""

    record_id: str
    record_kind: str                         # "evidence" | "verification"
    match: StateMatch
    comparisons: Tuple[ComponentComparison, ...] = ()
    bears_on: Tuple[str, ...] = ()           # claim ids it supports or contradicts
    supports: bool = False
    unrecognised: Tuple[str, ...] = ()       # state keys that are not components

    @property
    def withholds_support(self) -> bool:
        return self.supports and self.match in WITHHELD

    def mismatches(self) -> Tuple[ComponentComparison, ...]:
        return tuple(c for c in self.comparisons if c.outcome is ComponentOutcome.MISMATCH)

    @property
    def reason(self) -> str:
        """The sentence a reviewer reads. Every value in it is a field above."""
        if self.match in WITHHELD:
            parts = []
            for c in self.mismatches():
                if c.component == CONTENT:
                    parts.append(f"it names content {_short(c.record_value)}, which the "
                                 "candidate does not contain")
                else:
                    parts.append(f"{c.component} is {_short(c.record_value)} in the record "
                                 f"and {_short(c.candidate_value)} in the candidate")
            kind = ("a different subject" if self.match is StateMatch.INCOMPATIBLE
                    else "a different state of the candidate")
            effect = ("its support was withheld" if self.supports
                      else "it is reported, and a refutation from it still stands")
            return f"bound to {kind}: {'; '.join(parts)} — {effect}"
        if self.match is StateMatch.UNKNOWN:
            return "names no component the candidate states, so nothing could be compared"
        bound = [c.component for c in self.comparisons if c.outcome is ComponentOutcome.MATCH]
        if self.match is StateMatch.EXACT:
            return f"matches every component the candidate states ({', '.join(bound)})"
        silent = [c.component for c in self.comparisons
                  if c.outcome is ComponentOutcome.NOT_BOUND]
        return (f"matches {', '.join(bound)}; does not say which "
                f"{', '.join(silent)} it ran against")

    def to_dict(self) -> Dict[str, Any]:
        return {"record_id": self.record_id, "record_kind": self.record_kind,
                "match": self.match.value, "bears_on": list(self.bears_on),
                "supports": self.supports, "withholds_support": self.withholds_support,
                "comparisons": [c.to_dict() for c in self.comparisons],
                "unrecognised_state_keys": list(self.unrecognised),
                "reason": self.reason}


def _equal(key: str, left: str, right: str) -> bool:
    if left == right:
        return True
    # An abbreviated commit is a prefix of the full one; seven hex characters is
    # git's own floor for an unambiguous abbreviation.
    if key in (StateComponent.COMMIT.value, StateComponent.TREE.value):
        short, full = sorted((left, right), key=len)
        return len(short) >= 7 and full.startswith(short) and all(
            ch in "0123456789abcdef" for ch in short)
    return False


def values_equal(key: str, left: str, right: str) -> bool:
    """Whether two canonical values of one component name the same thing."""
    return _equal(key, left, right)


def bind(candidate: CandidateState, *, state: Optional[Mapping[str, Any]] = None,
         digests: Sequence[Optional[str]] = (), record_id: str, record_kind: str,
         bears_on: Sequence[str] = (), supports: bool = False) -> StateBinding:
    """Compare what one record names against the candidate."""
    comparisons: Dict[str, ComponentComparison] = {}
    unrecognised: List[str] = []
    for raw_key, raw_value in dict(state or {}).items():
        key = canonical_key(raw_key)
        if key is None:
            unrecognised.append(str(raw_key))
            continue
        try:
            value = canonical_value(key, raw_value)
        except CandidateError:
            unrecognised.append(str(raw_key))
            continue
        held = candidate.components.get(key)
        if held is None:
            comparisons[key] = ComponentComparison(key, ComponentOutcome.NOT_IN_CANDIDATE,
                                                   value, None)
        else:
            comparisons[key] = ComponentComparison(
                key, ComponentOutcome.MATCH if _equal(key, value, held)
                else ComponentOutcome.MISMATCH, value, held)

    # A bare digest names content, not a component. It matches whichever
    # component carries that content; matching none, it is content the
    # candidate does not contain.
    by_value: Dict[str, str] = {}
    for key, value in candidate.components.items():
        by_value.setdefault(value, key)
    for raw in digests:
        digest = str(raw or "").strip().lower()
        if not digest:
            continue
        key = by_value.get(digest)
        if key is not None:
            if key not in comparisons or comparisons[key].outcome is not ComponentOutcome.MISMATCH:
                comparisons[key] = ComponentComparison(key, ComponentOutcome.MATCH,
                                                       digest, digest)
        elif not any(c.record_value == digest for c in comparisons.values()):
            comparisons[f"{CONTENT}:{digest}"] = ComponentComparison(
                CONTENT, ComponentOutcome.MISMATCH, digest, None)

    named = {c.component for c in comparisons.values()}
    for key, value in candidate.components.items():
        if key not in named:
            comparisons[key] = ComponentComparison(key, ComponentOutcome.NOT_BOUND,
                                                   None, value)

    rows = tuple(comparisons[k] for k in sorted(comparisons))
    mismatched = [c for c in rows if c.outcome is ComponentOutcome.MISMATCH]
    matched = [c for c in rows if c.outcome is ComponentOutcome.MATCH]
    if any(c.component != CONTENT and component_class(c.component) is ComponentClass.IDENTITY
           for c in mismatched):
        match = StateMatch.INCOMPATIBLE
    elif mismatched:
        match = StateMatch.STALE
    elif not matched:
        match = StateMatch.UNKNOWN
    elif all(c.outcome is not ComponentOutcome.NOT_BOUND for c in rows):
        match = StateMatch.EXACT
    else:
        match = StateMatch.PARTIAL
    return StateBinding(record_id=record_id, record_kind=record_kind, match=match,
                        comparisons=rows, bears_on=tuple(dict.fromkeys(bears_on)),
                        supports=supports, unrecognised=tuple(sorted(unrecognised)))


# ── a whole case ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class StateBindingReport:
    """Every claim-bearing record's binding against one candidate."""

    candidate: CandidateState
    bindings: Tuple[StateBinding, ...] = ()
    notes: Tuple[str, ...] = ()

    def of(self, match: StateMatch) -> Tuple[StateBinding, ...]:
        return tuple(b for b in self.bindings if b.match is match)

    @property
    def withheld_evidence(self) -> Tuple[str, ...]:
        return tuple(b.record_id for b in self.bindings
                     if b.record_kind == "evidence" and b.withholds_support)

    @property
    def withheld_attempts(self) -> Tuple[str, ...]:
        return tuple(b.record_id for b in self.bindings
                     if b.record_kind == "verification" and b.withholds_support)

    def unchecked_components(self) -> Tuple[str, ...]:
        """Components records are bound to that the candidate does not state."""
        return tuple(sorted({c.component for b in self.bindings for c in b.comparisons
                             if c.outcome is ComponentOutcome.NOT_IN_CANDIDATE}))

    def summary(self) -> Dict[str, Any]:
        return {"candidate_digest": self.candidate.digest(),
                "candidate_source": self.candidate.source.value,
                "explicit": self.candidate.explicit,
                "records": len(self.bindings),
                "by_match": {m.value: len(self.of(m)) for m in StateMatch},
                "support_withheld": len(self.withheld_evidence) + len(self.withheld_attempts),
                "unchecked_components": list(self.unchecked_components())}

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "state_binding_report", **self.summary(),
                "candidate": self.candidate.to_dict(),
                "bindings": [b.to_dict() for b in self.bindings],
                "notes": list(self.notes)}


def _current_artifacts(artifacts: Iterable[Any]) -> Tuple[Dict[str, str], List[str]]:
    """logical id -> digest for the artifacts nothing in the case has revised."""
    held = [a for a in artifacts if getattr(a, "digest", None)]
    revised = {getattr(a, "revises", None) for a in held} - {None}
    heads: Dict[str, set] = {}
    for artifact in held:
        if artifact.digest in revised:
            continue
        heads.setdefault(artifact.logical_id, set()).add(artifact.digest)
    notes = [f"artifact {lid} has {len(ds)} current digests; it was left out of the "
             "candidate rather than one being chosen" for lid, ds in sorted(heads.items())
             if len(ds) > 1]
    return {lid: next(iter(ds)) for lid, ds in heads.items() if len(ds) == 1}, notes


def candidate_for_case(case: Any) -> Tuple[Optional[CandidateState], List[str]]:
    """The candidate a case is judged against, and how it was arrived at."""
    stored = (getattr(case, "metadata", None) or {}).get(CANDIDATE_METADATA_KEY)
    if isinstance(stored, Mapping):
        try:
            return CandidateState.from_dict(stored), []
        except (CandidateError, ValueError) as exc:
            return None, [f"the case's candidate state could not be read: {exc}"]
    artifacts = list(case.collection("artifacts").materialised) \
        if hasattr(case, "collection") else []
    heads, notes = _current_artifacts(artifacts)
    if not heads:
        return None, notes
    try:
        return CandidateState(
            components={f"{ARTIFACT_PREFIX}{lid}": digest for lid, digest in heads.items()},
            source=CandidateSource.IMPLIED_BY_ARTIFACTS, declared_by="release-gate",
            note="no candidate was stated; the case's current artifacts stand in"), notes
    except CandidateError as exc:
        return None, notes + [f"the case's artifacts could not form a candidate: {exc}"]


def record_state(record: Any) -> Mapping[str, Any]:
    content = getattr(record, "content", None) or {}
    state = content.get("state") if isinstance(content, Mapping) else None
    return state if isinstance(state, Mapping) else {}


def bind_case(case: Any, *, claims: Optional[Iterable[Any]] = None,
              evidence: Optional[Mapping[str, Any]] = None) -> Optional[StateBindingReport]:
    """Bind every record that bears on a claim. None when there is no candidate.

    Only claim-bearing records are bound: a record that argues about nothing
    cannot be misapplied to the candidate, and binding it would only add rows.
    """
    candidate, notes = candidate_for_case(case)
    if candidate is None:
        return None
    if claims is None:
        claims = [c for c in case.collection("claims").materialised
                  if hasattr(c, "claim_id")]
    claims = list(claims)
    if evidence is None:
        evidence = {}
        for kind in ("evidence", "verification", "contradictions", "counterexamples"):
            for record in case.collection(kind).materialised:
                if hasattr(record, "evidence_id"):
                    evidence[record.evidence_id] = record

    bearing: Dict[str, Dict[str, Any]] = {}
    for record in evidence.values():
        for cid in getattr(record, "supports_claims", ()):
            bearing.setdefault(record.evidence_id, {"on": [], "supports": False})
            bearing[record.evidence_id]["on"].append(cid)
            bearing[record.evidence_id]["supports"] = True
        for cid in getattr(record, "contradicts_claims", ()):
            bearing.setdefault(record.evidence_id, {"on": [], "supports": False})
            bearing[record.evidence_id]["on"].append(cid)
    for claim in claims:
        for eid in getattr(claim, "supporting_evidence", ()):
            if eid in evidence:
                bearing.setdefault(eid, {"on": [], "supports": False})
                bearing[eid]["on"].append(claim.claim_id)
                bearing[eid]["supports"] = True
        for eid in getattr(claim, "contradicting_evidence", ()):
            if eid in evidence:
                bearing.setdefault(eid, {"on": [], "supports": False})
                bearing[eid]["on"].append(claim.claim_id)

    bindings: List[StateBinding] = []
    for eid in sorted(bearing):
        record = evidence[eid]
        bindings.append(bind(
            candidate, state=record_state(record),
            digests=(getattr(record, "applies_to_digest", None),),
            record_id=eid, record_kind="evidence", bears_on=bearing[eid]["on"],
            supports=bearing[eid]["supports"]))

    from release_gate.assurance.verification import VerificationStatus
    seen: set = set()
    for claim in claims:
        for attempt in getattr(claim, "verification_attempts", ()):
            if attempt.verification_id in seen:
                continue
            seen.add(attempt.verification_id)
            state: Dict[str, Any] = {}
            target = getattr(attempt, "target", None)
            if target is not None and getattr(target, "kind", None) is not None \
                    and str(getattr(target.kind, "value", target.kind)) == "ARTIFACT" \
                    and attempt.target_digest:
                state[f"{ARTIFACT_PREFIX}{target.target_id}"] = attempt.target_digest
            result_state = (attempt.result or {}).get("state")
            if isinstance(result_state, Mapping):
                state.update(result_state)
            bindings.append(bind(
                candidate, state=state,
                # The target, not `input_state`: an input digest (a dataset, a
                # seed) is a dependency of the check, not the thing it checked.
                digests=() if state else (attempt.target_digest,),
                record_id=attempt.verification_id, record_kind="verification",
                bears_on=(claim.claim_id,),
                supports=attempt.status is VerificationStatus.PASSED))
    return StateBindingReport(candidate=candidate, bindings=tuple(bindings),
                              notes=tuple(notes))

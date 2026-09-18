"""Domain plugins — one declarable bundle, installed into the registries that exist.

Six of the seven things a domain needs to contribute already had a home before
this module: methodologies in `MethodologyRegistry`, consequence classifiers in
`ConsequenceRegistry` (whose precedence table already names a "Domain plugins"
tier), evidence expectations on the methodology, domain rules as `Requirement`s
over the predicate algebra, and verification types as strings in
`accepted_verification_types`. What was missing was a way to say *here is a
domain* rather than making an author find six registration calls, and one seam
that had no extension point at all: the approval packet's sections were a closed
enum and a fixed tuple.

So a `DomainPlugin` is a bundle, not a second resolution path. Installing one
delegates to the existing registries; nothing here re-implements what they do,
and a methodology registered through a plugin is the same object, in the same
place, as one registered directly.

**The core stays domain-neutral, and that is a test rather than a promise.**
Nothing under `release_gate/assurance/` names a domain from the roadmap. Finance
knows what a material loss is; healthcare knows what a protected identifier is;
this engine knows what evidence is, and mixing the two would make every case
carry vocabulary for domains it has nothing to do with.

**A plugin extends and can never weaken.** That is the whole of "correctly", and
it is enforced rather than documented:

* A requirement id that already exists is refused, so a plugin cannot quietly
  replace a stricter rule with a laxer one of the same name.
* A predicate kind that already exists is refused, so a plugin cannot redefine
  what a core check means for every methodology in the process.
* A vocabulary term must be namespaced under its domain, so two domains cannot
  collide and neither can shadow a core term.
* A domain section is appended after the core eleven and cannot displace,
  reorder or edit one — a reviewer's eleven questions are the same eleven
  whatever is installed.
* Installation order changes nothing. Conflicts are refused, never resolved by
  who registered first (Invariant 4), which is the stance `VerifierRegistry` and
  `ConsequenceRegistry` already take.

**Two things a domain rule will get wrong on its first attempt**, written here
because both were hit while building the reference plugin for this module:

* `case.records("evidence")` holds release-gate's own derived records — the
  consequence profile, the independence profile, the input artifact it hashed —
  alongside evidence from producers. A rule counting rows there is counting the
  engine's own output as a party's. Filter on `record_type == "evidence"`.
* The ingest preserves the whole submitted payload under the record's `content`,
  so a producer's own `content` key lands one level deeper than its author
  expects. Nothing is lost; it is just not where a first guess looks.

**A plugin is an object, not a file.** There is no dynamic import here, no
entry-point scan, no path that turns configuration into executing code. A caller
constructs a `DomainPlugin` and installs it. Anything that let a YAML file name
a module to import would make "what is release-gate running" unanswerable, which
is the opposite of what an assurance engine is for.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from release_gate.assurance.canonical import digest_object
from release_gate.assurance.consequence import ConsequenceModel, ConsequenceRegistry
from release_gate.assurance.methodology import (
    _PREDICATE_TYPES,
    AssuranceMethodology,
    EvidenceExpectation,
    MethodologyRegistry,
    Predicate,
    Requirement,
    RequirementEffect,
)

__all__ = [
    "PLUGIN_SCHEMA_VERSION",
    "DomainPlugin",
    "DomainSection",
    "Installation",
    "PluginError",
    "PluginRegistry",
    "TermKind",
    "VocabularyTerm",
]

PLUGIN_SCHEMA_VERSION = 1

#: The predicate kinds the core ships, snapshotted once at import — before any
#: plugin can have run. It must be a module-level snapshot rather than a
#: per-registry one: `_PREDICATE_TYPES` is process-global, so a registry built
#: *after* a plugin installed would capture that plugin's kinds as "core" and
#: then refuse the very plugin that registered them. That made installation
#: order decide the outcome, which is the one thing this module promises it does
#: not (Invariant 4).
CORE_PREDICATE_KINDS: frozenset = frozenset(_PREDICATE_TYPES)


class PluginError(ValueError):
    """A plugin was declared or installed in a way that would weaken the core."""


class TermKind(str, Enum):
    """What kind of vocabulary a domain is adding."""

    CLAIM_TYPE = "CLAIM_TYPE"
    VERIFICATION_TYPE = "VERIFICATION_TYPE"


@dataclass(frozen=True)
class VocabularyTerm:
    """A claim type or verification type a domain defines.

    `establishes` and `does_not_establish` are both required, and the second is
    the one that matters. `verifiers._FAMILY_COVERAGE` applies exactly this
    discipline to machine checks — every family states what its result does not
    cover — and a domain adding `CLINICAL_SIGN_OFF` or `PENETRATION_TEST` to the
    vocabulary is making the same kind of claim. A term that says only what it
    establishes reads as stronger than it is, and the reader has nothing to push
    back on (Invariant 8).
    """

    term: str
    kind: TermKind
    definition: str
    establishes: Tuple[str, ...] = ()
    does_not_establish: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", TermKind(self.kind))
        object.__setattr__(self, "establishes", tuple(self.establishes))
        object.__setattr__(self, "does_not_establish", tuple(self.does_not_establish))
        if not (self.term or "").strip():
            raise PluginError("a vocabulary term must be named")
        object.__setattr__(self, "term", self.term.strip())
        if not (self.definition or "").strip():
            raise PluginError(
                f"{self.term}: a term without a definition is a string that looks "
                "like a standard; state what it means")
        if not self.does_not_establish:
            raise PluginError(
                f"{self.term}: state what this does NOT establish. Every term here "
                "will be read as stronger than it is unless its limits travel with "
                "it, which is why every verifier family states the same thing "
                "(Invariant 8)")

    def qualified(self, domain_id: str) -> str:
        """`finance:MATERIALITY_REVIEW` — namespaced so domains cannot collide."""
        return f"{domain_id}:{self.term}"

    def to_dict(self) -> Dict[str, Any]:
        return {"term": self.term, "kind": self.kind.value,
                "definition": self.definition,
                "establishes": list(self.establishes),
                "does_not_establish": list(self.does_not_establish)}


@dataclass(frozen=True)
class DomainSection:
    """A report section a domain adds, after the core eleven.

    The packet's eleven questions are the reviewer's, and they are the same
    eleven whatever is installed: a domain may add a twelfth, never edit the
    third. `build_packet` appends these in declaration order after the core, and
    `PluginRegistry` refuses a section key that collides with a core one.

    `rows_from` is a callable taking `(case, outcome)` and returning rows. It is
    a callable rather than a serialisable predicate because a section is a view,
    not a gate: it cannot change a verdict, so it does not need to survive
    transport to an API client the way a `Requirement` does.
    """

    key: str
    question: str
    rows_from: Any = None
    answer: str = ""
    note: str = ""

    def __post_init__(self) -> None:
        if not (self.key or "").strip():
            raise PluginError("a domain section must have a key")
        object.__setattr__(self, "key", self.key.strip().upper())
        if not (self.question or "").strip():
            raise PluginError(
                f"{self.key}: a section must state the question it answers — the "
                "packet's sections are questions a reviewer asked, not headings")

    def to_dict(self) -> Dict[str, Any]:
        return {"key": self.key, "question": self.question, "answer": self.answer,
                "note": self.note, "has_rows": self.rows_from is not None}


@dataclass(frozen=True)
class DomainPlugin:
    """Everything one domain contributes, declared in one place.

    Immutable and content-addressed, like a methodology and for the same reason:
    "which version of the finance plugin decided this" must have an answer six
    weeks later, and a bundle that could be edited in place would not have one.
    """

    domain_id: str
    version: str
    description: str = ""
    methodologies: Tuple[AssuranceMethodology, ...] = ()
    claim_types: Tuple[VocabularyTerm, ...] = ()
    verification_types: Tuple[VocabularyTerm, ...] = ()
    consequence_models: Tuple[ConsequenceModel, ...] = ()
    evidence_expectations: Tuple[EvidenceExpectation, ...] = ()
    rules: Tuple[Requirement, ...] = ()
    predicates: Tuple[type, ...] = ()
    report_sections: Tuple[DomainSection, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)
    schema_version: int = PLUGIN_SCHEMA_VERSION

    digest: str = field(default="", init=False)

    def __post_init__(self) -> None:
        if not (self.domain_id or "").strip():
            raise PluginError("a plugin must name its domain")
        object.__setattr__(self, "domain_id", self.domain_id.strip().lower())
        if ":" in self.domain_id:
            raise PluginError(
                f"{self.domain_id!r}: a domain id may not contain ':' — it is the "
                "separator that namespaces this domain's vocabulary")
        if not (self.version or "").strip():
            raise PluginError(f"{self.domain_id}: a plugin must state its version")

        for name in ("methodologies", "claim_types", "verification_types",
                     "consequence_models", "evidence_expectations", "rules",
                     "predicates", "report_sections"):
            object.__setattr__(self, name, tuple(getattr(self, name)))

        for term in self.claim_types:
            if term.kind is not TermKind.CLAIM_TYPE:
                raise PluginError(
                    f"{self.domain_id}: {term.term} is declared under claim_types "
                    f"but is a {term.kind.value}")
        for term in self.verification_types:
            if term.kind is not TermKind.VERIFICATION_TYPE:
                raise PluginError(
                    f"{self.domain_id}: {term.term} is declared under "
                    f"verification_types but is a {term.kind.value}")

        seen_terms: Set[str] = set()
        for term in self.terms:
            if term.term in seen_terms:
                raise PluginError(
                    f"{self.domain_id}: {term.term} is declared twice, so the domain "
                    "holds two definitions of one word and no way to choose")
            seen_terms.add(term.term)

        seen_rules: Set[str] = set()
        for rule in self.rules:
            if rule.requirement_id in seen_rules:
                raise PluginError(
                    f"{self.domain_id}: requirement {rule.requirement_id} is declared "
                    "twice")
            seen_rules.add(rule.requirement_id)

        seen_sections: Set[str] = set()
        for section in self.report_sections:
            if section.key in seen_sections:
                raise PluginError(
                    f"{self.domain_id}: section {section.key} is declared twice")
            seen_sections.add(section.key)

        for predicate in self.predicates:
            if not (isinstance(predicate, type) and issubclass(predicate, Predicate)):
                raise PluginError(
                    f"{self.domain_id}: a declared predicate must be a Predicate "
                    "subclass; the algebra is closed so that a requirement can be "
                    "serialised, transported and shown to whoever it blocked")
            if not getattr(predicate, "KIND", ""):
                raise PluginError(
                    f"{self.domain_id}: predicate {predicate.__name__} declares no "
                    "KIND, so nothing could resolve it after transport")

        object.__setattr__(self, "digest", digest_object(self.content()))

    @property
    def ref_string(self) -> str:
        return f"{self.domain_id}@{self.version}"

    @property
    def terms(self) -> Tuple[VocabularyTerm, ...]:
        return self.claim_types + self.verification_types

    def qualified_terms(self) -> Dict[str, VocabularyTerm]:
        return {t.qualified(self.domain_id): t for t in self.terms}

    @property
    def contributes(self) -> Dict[str, int]:
        """What this plugin adds, by capability. The inspection a reviewer asks for."""
        return {
            "methodologies": len(self.methodologies),
            "claim_types": len(self.claim_types),
            "verification_types": len(self.verification_types),
            "consequence_models": len(self.consequence_models),
            "evidence_expectations": len(self.evidence_expectations),
            "rules": len(self.rules),
            "predicates": len(self.predicates),
            "report_sections": len(self.report_sections),
        }

    def content(self) -> Dict[str, Any]:
        """What the digest covers. Callables are named, never hashed by identity."""
        return {
            "schema_version": self.schema_version,
            "domain_id": self.domain_id, "version": self.version,
            "description": self.description,
            "methodologies": [m.ref_string + "#" + m.digest for m in self.methodologies],
            "claim_types": [t.to_dict() for t in self.claim_types],
            "verification_types": [t.to_dict() for t in self.verification_types],
            "consequence_models": [m.model_id for m in self.consequence_models],
            "evidence_expectations": [e.to_dict() for e in self.evidence_expectations],
            "rules": [r.to_dict() for r in self.rules],
            "predicates": [p.KIND for p in self.predicates],
            "report_sections": [s.to_dict() for s in self.report_sections],
            "metadata": dict(self.metadata),
        }

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "domain_plugin", "record_id": self.ref_string,
                "digest": self.digest, "contributes": self.contributes,
                **self.content()}


@dataclass(frozen=True)
class Installation:
    """What one plugin actually contributed, after installation.

    Separate from `DomainPlugin.contributes`, which is what it declared. The two
    agree today and are kept apart on purpose: a declaration is what an author
    wrote and an installation is what the registries accepted, and collapsing
    them would hide the day those differ.
    """

    plugin: DomainPlugin
    methodologies: Tuple[str, ...] = ()
    terms: Tuple[str, ...] = ()
    consequence_models: Tuple[str, ...] = ()
    rules: Tuple[str, ...] = ()
    predicates: Tuple[str, ...] = ()
    sections: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "plugin_installation",
                "record_id": self.plugin.ref_string,
                "plugin": self.plugin.ref_string, "digest": self.plugin.digest,
                "methodologies": list(self.methodologies),
                "terms": list(self.terms),
                "consequence_models": list(self.consequence_models),
                "rules": list(self.rules), "predicates": list(self.predicates),
                "sections": list(self.sections)}


class PluginRegistry:
    """Installed domains, and the guarantee that none of them weakened anything.

    Holds no methodologies or consequence models of its own — it installs into
    the registries that already own those, and keeps the record of who
    contributed what. Asking this registry what finance added is a different
    question from asking the methodology registry to resolve a ref, and both
    have one answer.
    """

    def __init__(self, *, methodologies: Optional[MethodologyRegistry] = None,
                 consequences: Optional[ConsequenceRegistry] = None) -> None:
        self.methodologies = methodologies or MethodologyRegistry()
        self.consequences = consequences or ConsequenceRegistry()
        self._installed: Dict[str, Installation] = {}
        self._terms: Dict[str, Tuple[str, VocabularyTerm]] = {}
        self._rules: Dict[str, str] = {}
        self._sections: Dict[str, str] = {}

    # ── installation ───────────────────────────────────────────────────────

    def install(self, plugin: DomainPlugin) -> Installation:
        """Install a domain, or refuse and change nothing.

        Every collision check runs before anything is registered, so a plugin
        that is refused leaves the process exactly as it found it. A partial
        install would be the worst outcome available here: half a domain, with no
        record of which half.
        """
        if not isinstance(plugin, DomainPlugin):
            raise PluginError("install() takes a DomainPlugin")

        existing = self._installed.get(plugin.domain_id)
        if existing is not None:
            if existing.plugin.digest == plugin.digest:
                return existing
            raise PluginError(
                f"{plugin.domain_id} is already installed at "
                f"{existing.plugin.ref_string} with different content. A domain's "
                "rules are fixed by its version: publish a new version rather than "
                "editing one that cases have already been argued against")

        self._check_collisions(plugin)

        # Past every check. Nothing below may fail on a conflict.
        for methodology in plugin.methodologies:
            self.methodologies.register(methodology, source=f"plugin:{plugin.ref_string}")
        for model in plugin.consequence_models:
            self.consequences.register(model)
        for predicate in plugin.predicates:
            _PREDICATE_TYPES[predicate.KIND] = predicate
        for qualified, term in plugin.qualified_terms().items():
            self._terms[qualified] = (plugin.domain_id, term)
        for rule in plugin.rules:
            self._rules[rule.requirement_id] = plugin.domain_id
        for section in plugin.report_sections:
            self._sections[section.key] = plugin.domain_id

        installation = Installation(
            plugin=plugin,
            methodologies=tuple(m.ref_string for m in plugin.methodologies),
            terms=tuple(sorted(plugin.qualified_terms())),
            consequence_models=tuple(m.model_id for m in plugin.consequence_models),
            rules=tuple(r.requirement_id for r in plugin.rules),
            predicates=tuple(p.KIND for p in plugin.predicates),
            sections=tuple(s.key for s in plugin.report_sections))
        self._installed[plugin.domain_id] = installation
        return installation

    def _check_collisions(self, plugin: DomainPlugin) -> None:
        """Everything that would let a plugin weaken or shadow something."""
        from release_gate.assurance.packet import SectionKey

        for predicate in plugin.predicates:
            if predicate.KIND in CORE_PREDICATE_KINDS:
                raise PluginError(
                    f"{plugin.domain_id}: predicate kind {predicate.KIND!r} is a core "
                    "kind. Redefining it would change what that check means for every "
                    "methodology in this process, including ones this domain has "
                    "nothing to do with. Name a new kind")
            owner = next((d for d, inst in self._installed.items()
                          if predicate.KIND in inst.predicates), "")
            if owner:
                raise PluginError(
                    f"{plugin.domain_id}: predicate kind {predicate.KIND!r} is already "
                    f"defined by {owner}")
            # The kind may already be in the process-global table from an install
            # into a different registry. That is fine when it is the same class —
            # the same plugin, installed twice — and a redefinition otherwise.
            registered = _PREDICATE_TYPES.get(predicate.KIND)
            if registered is not None and registered is not predicate:
                raise PluginError(
                    f"{plugin.domain_id}: predicate kind {predicate.KIND!r} is already "
                    f"registered in this process by {registered.__name__}, which is a "
                    f"different class from {predicate.__name__}. Two definitions of "
                    "one kind means a transported requirement resolves to whichever "
                    "was imported last")

        for rule in plugin.rules:
            owner = self._rules.get(rule.requirement_id)
            if owner and owner != plugin.domain_id:
                raise PluginError(
                    f"{plugin.domain_id}: requirement id {rule.requirement_id!r} is "
                    f"already defined by {owner}. Two rules under one id means the "
                    "stricter one can be replaced by the laxer one and nobody can see "
                    "it happen")

        for section in plugin.report_sections:
            if section.key in {k.value for k in SectionKey}:
                raise PluginError(
                    f"{plugin.domain_id}: {section.key} is one of the core eleven "
                    "sections. A domain may add a twelfth question; it may not "
                    "answer the reviewer's third one on their behalf")
            owner = self._sections.get(section.key)
            if owner and owner != plugin.domain_id:
                raise PluginError(
                    f"{plugin.domain_id}: section {section.key} is already contributed "
                    f"by {owner}")

        for qualified in plugin.qualified_terms():
            owner = self._terms.get(qualified)
            if owner and owner[0] != plugin.domain_id:
                raise PluginError(
                    f"{plugin.domain_id}: term {qualified} is already defined by "
                    f"{owner[0]}")

    # ── inspection ─────────────────────────────────────────────────────────

    @property
    def installed(self) -> Tuple[Installation, ...]:
        """In domain-id order, never installation order.

        Deliberate: a caller reading this list must not be able to infer, or come
        to depend on, who was installed first, because nothing else in the system
        does either (Invariant 4).
        """
        return tuple(self._installed[k] for k in sorted(self._installed))

    @property
    def domains(self) -> Tuple[str, ...]:
        return tuple(sorted(self._installed))

    def installation(self, domain_id: str) -> Optional[Installation]:
        return self._installed.get(str(domain_id).strip().lower())

    def term(self, qualified: str) -> Optional[VocabularyTerm]:
        found = self._terms.get(qualified)
        return found[1] if found else None

    @property
    def vocabulary(self) -> Dict[str, VocabularyTerm]:
        return {k: v[1] for k, v in sorted(self._terms.items())}

    def sections_for(self, case: Any, outcome: Any = None) -> List[Any]:
        """Domain sections, built, in domain-id then declaration order.

        Returns `PacketSection`s ready to append. A section whose `rows_from`
        raises is reported as having failed rather than dropped: a domain section
        that silently vanishes on error is a reviewer reading a packet that is
        missing a question nobody told them about.
        """
        from release_gate.assurance.packet import PacketSection, SectionKey

        out: List[Any] = []
        for installation in self.installed:
            for section in installation.plugin.report_sections:
                rows: Tuple[Mapping[str, Any], ...] = ()
                note = section.note
                if section.rows_from is not None:
                    try:
                        rows = tuple(dict(r) for r in section.rows_from(case, outcome))
                    except Exception as exc:
                        note = (f"this section could not be built: "
                                f"{type(exc).__name__}. It is shown empty rather than "
                                "omitted, so the gap is visible")
                out.append(PacketSection(
                    key=SectionKey.DOMAIN, answer=section.answer, rows=rows,
                    total=len(rows), note=note,
                    drill_down=(f"{installation.plugin.domain_id}:{section.key}",)))
        return out

    def summary(self) -> Dict[str, Any]:
        return {"record_type": "plugin_registry",
                "domains": list(self.domains),
                "installed": [i.to_dict() for i in self.installed],
                "vocabulary": sorted(self._terms),
                # Stated rather than implied: installing a domain never relaxes
                # anything the core or another domain requires.
                "can_weaken_core": False,
                "schema_version": PLUGIN_SCHEMA_VERSION}

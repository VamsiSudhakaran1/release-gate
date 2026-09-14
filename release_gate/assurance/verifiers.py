"""Adapters for machine-verifiable systems — the interface, not one prover.

Release-Gate does not replace these tools and does not check their work. A proof
assistant, an SMT solver, a model checker and a type checker each establish
something real, and each establishes something *narrower* than it first appears.
What this module does is record what a tool said, what it was said about, and —
the part that usually goes missing — what the result does not cover.

No theorem prover is hardcoded. An adapter is a small class with a `detect` and a
`convert`, mirroring the house pattern in `release_gate/adapters/`, and the
registry takes whatever an organisation registers. Two ship built in: a documented
tool-neutral envelope that any verifier can emit, and SMT-LIB, whose result
vocabulary is three words and genuinely standard. Lean, Coq and Isabelle are not
parsed here, because their machine-readable output varies by version and build
setup and a parser written against formats I cannot test would be a guess wearing
a tool's name. They emit JSON through their own tooling; the envelope is what
receives it, and the adapter to bridge them is short.

Two rules the adapters exist to enforce.

**`unknown` is not a pass.** A solver that gave up, a checker that timed out, a
prover that reached its step limit — all `INCONCLUSIVE`, never `PASSED`. This is
the single most consequential mapping in the module and it is written down once,
here, rather than being rediscovered per adapter.

**A bare `unsat` proves nothing.** Whether `unsat` means "the property holds"
depends entirely on whether the query encoded the property or its negation, and a
solver saying `unsat` about a contradictory encoding is a vacuous proof that looks
identical to a real one. The SMT adapter therefore refuses to map `unsat` to
`PASSED` unless the query polarity was declared. Getting this backwards is how a
formal method becomes a rubber stamp.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from release_gate.assurance.canonical import digest_object, is_content_id
from release_gate.assurance.evidence import TrustStatus, VerificationMethod
from release_gate.assurance.verification import (
    TargetKind, VerificationAttempt, VerificationStatus, VerificationTarget,
)

__all__ = [
    "VERIFIER_SCHEMA_VERSION",
    "GenericVerifierAdapter",
    "QueryPolarity",
    "SmtLibAdapter",
    "ToolFamily",
    "ToolIdentity",
    "VerifierAdapter",
    "VerifierCoverage",
    "VerifierError",
    "VerifierRegistry",
    "VerifierReport",
    "default_verifier_registry",
]

VERIFIER_SCHEMA_VERSION = 1

#: Below this, detection does not commit — the same floor the ingest adapters use.
DETECT_FLOOR = 50


class VerifierError(ValueError):
    """A verifier result was read in a way that would overstate what it established."""


class ToolFamily(str, Enum):
    """What kind of machine checking this is. Selects the default method, nothing else."""

    PROOF_ASSISTANT = "PROOF_ASSISTANT"
    SMT_SOLVER = "SMT_SOLVER"
    MODEL_CHECKER = "MODEL_CHECKER"
    PROPERTY_CHECKER = "PROPERTY_CHECKER"
    TYPE_CHECKER = "TYPE_CHECKER"
    COMPILER = "COMPILER"
    TEST_FRAMEWORK = "TEST_FRAMEWORK"
    DOMAIN_VALIDATOR = "DOMAIN_VALIDATOR"
    OTHER = "OTHER"


_FAMILY_METHOD: Mapping[ToolFamily, VerificationMethod] = {
    ToolFamily.PROOF_ASSISTANT: VerificationMethod.THEOREM_PROVER,
    ToolFamily.SMT_SOLVER: VerificationMethod.FORMAL_PROOF,
    ToolFamily.MODEL_CHECKER: VerificationMethod.FORMAL_PROOF,
    ToolFamily.PROPERTY_CHECKER: VerificationMethod.PROPERTY_TEST,
    ToolFamily.TYPE_CHECKER: VerificationMethod.TYPE_CHECKER,
    ToolFamily.COMPILER: VerificationMethod.COMPILER,
    ToolFamily.TEST_FRAMEWORK: VerificationMethod.TEST_SUITE,
    ToolFamily.DOMAIN_VALIDATOR: VerificationMethod.DOMAIN_CHECKER,
    ToolFamily.OTHER: VerificationMethod.OTHER,
}

#: What each family's result does and does not establish, stated once so every
#: adapter inherits the same honesty rather than each inventing its own wording.
#: These are properties of the *method*, not judgements about any tool.
_FAMILY_COVERAGE: Mapping[ToolFamily, Tuple[Tuple[str, ...], Tuple[str, ...]]] = {
    ToolFamily.PROOF_ASSISTANT: (
        ("the stated theorem, under the stated axioms and definitions",),
        ("whether the formalisation says what its author meant",
         "anything outside the formalised model",
         "the correctness of the prover's own kernel unless its digest is pinned")),
    ToolFamily.SMT_SOLVER: (
        ("satisfiability of the encoded query within the declared theories",),
        ("whether the encoding faithfully represents the property",
         "anything the encoding abstracted away",
         "behaviour outside the solver's theory fragment")),
    ToolFamily.MODEL_CHECKER: (
        ("the checked property over the explored state space",),
        ("states outside the explored bound",
         "whether the model matches the deployed system")),
    ToolFamily.PROPERTY_CHECKER: (
        ("the property over the inputs actually generated",),
        ("inputs the generator did not produce",
         "absence of counterexamples outside the search")),
    ToolFamily.TYPE_CHECKER: (
        ("type consistency of the checked code",),
        ("runtime behaviour", "logic errors that type-check")),
    ToolFamily.COMPILER: (
        ("that the artifact builds under the given configuration",),
        ("runtime behaviour", "behaviour under other configurations")),
    ToolFamily.TEST_FRAMEWORK: (
        ("the behaviours the tests actually exercise",),
        ("behaviour the tests do not exercise",
         "absence of defects outside the suite")),
    ToolFamily.DOMAIN_VALIDATOR: (
        ("the rules the validator encodes",),
        ("anything the rule set does not mention")),
    ToolFamily.OTHER: ((), ("nothing is recorded about what this result covers",)),
}


class QueryPolarity(str, Enum):
    """What an SMT query encoded. Without it, `unsat` is uninterpretable.

    `NEGATION_OF_PROPERTY` is the usual formulation: assert the negation, and
    `unsat` means no counterexample exists. `DIRECT` asserts the property itself,
    where `unsat` means the assertions are contradictory — which is a broken
    encoding, not a proof.
    """

    NEGATION_OF_PROPERTY = "NEGATION_OF_PROPERTY"
    DIRECT = "DIRECT"
    UNDECLARED = "UNDECLARED"


@dataclass(frozen=True)
class ToolIdentity:
    """Which tool said so, and whether that identity was established."""

    name: str
    version: str = ""
    family: ToolFamily = ToolFamily.OTHER
    digest: Optional[str] = None       # of the verifier itself, where pinnable
    invocation: str = ""
    established: bool = False          # was the identity checked, or asserted?

    def __post_init__(self) -> None:
        object.__setattr__(self, "family", ToolFamily(self.family))
        if not (self.name or "").strip():
            raise VerifierError(
                "a verifier must be named: a machine check nobody can attribute "
                "cannot be weighed or reproduced")
        object.__setattr__(self, "name", self.name.strip())
        if self.digest is not None and not is_content_id(self.digest):
            raise VerifierError(
                f"verifier digest {self.digest!r} is not a content identifier; a "
                "digest that cannot be compared pins nothing")

    @property
    def reference(self) -> str:
        return f"{self.name}@{self.version}" if self.version else self.name

    @property
    def pinned(self) -> bool:
        """Is the verifier itself identified by content?

        The trusted kernel question. A proof is only as good as the prover that
        checked it, and an unpinned prover is a dependency nobody recorded.
        """
        return self.digest is not None

    @property
    def trust_status(self) -> TrustStatus:
        """Pinning establishes identity, never correctness (Invariant 11)."""
        return TrustStatus.PROVISIONAL if self.pinned else TrustStatus.NOT_ESTABLISHED

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "version": self.version,
                "family": self.family.value, "digest": self.digest,
                "invocation": self.invocation, "reference": self.reference,
                "pinned": self.pinned, "established": self.established}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ToolIdentity":
        return cls(name=data.get("name", ""), version=data.get("version", ""),
                   family=ToolFamily(data.get("family", ToolFamily.OTHER.value)),
                   digest=data.get("digest"), invocation=data.get("invocation", ""),
                   established=bool(data.get("established")))


@dataclass(frozen=True)
class VerifierCoverage:
    """What the result establishes, and what it does not.

    The second field is the one that matters. Every machine check establishes
    something narrower than its name suggests, and a case that records only the
    first half turns a bounded result into an unbounded one.
    """

    covers: Tuple[str, ...] = ()
    does_not_cover: Tuple[str, ...] = ()
    encoding_note: str = ""
    targets_checked: int = 0
    targets_declared: Optional[int] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "covers", tuple(self.covers))
        object.__setattr__(self, "does_not_cover", tuple(self.does_not_cover))

    @property
    def complete(self) -> bool:
        """Were as many targets checked as were declared? Unknown counts as no."""
        return (self.targets_declared is not None
                and self.targets_checked >= self.targets_declared)

    def to_dict(self) -> Dict[str, Any]:
        return {"covers": list(self.covers),
                "does_not_cover": list(self.does_not_cover),
                "encoding_note": self.encoding_note,
                "targets_checked": self.targets_checked,
                "targets_declared": self.targets_declared,
                "complete": self.complete}

    @classmethod
    def for_family(cls, family: ToolFamily, **kwargs: Any) -> "VerifierCoverage":
        covers, does_not = _FAMILY_COVERAGE[ToolFamily(family)]
        return cls(covers=covers, does_not_cover=does_not, **kwargs)


@dataclass(frozen=True)
class VerifierReport:
    """One tool's output, normalised. Never a judgement about the tool."""

    tool: ToolIdentity
    attempts: Tuple[VerificationAttempt, ...] = ()
    coverage: VerifierCoverage = field(default_factory=VerifierCoverage)
    adapter: str = ""
    records_seen: int = 0
    records_mapped: int = 0
    skipped: Mapping[str, int] = field(default_factory=dict)
    notes: Tuple[str, ...] = ()

    @property
    def skipped_total(self) -> int:
        return sum(self.skipped.values())

    def of_status(self, status: VerificationStatus) -> Tuple[VerificationAttempt, ...]:
        return tuple(a for a in self.attempts if a.status is VerificationStatus(status))

    def digest(self) -> str:
        return digest_object({"tool": self.tool.to_dict(),
                              "attempts": [a.to_dict() for a in self.attempts],
                              "coverage": self.coverage.to_dict(),
                              "schema_version": VERIFIER_SCHEMA_VERSION})

    def summary(self) -> Dict[str, Any]:
        return {"adapter": self.adapter, "tool": self.tool.to_dict(),
                "attempts": len(self.attempts),
                "by_status": {s.value: len(self.of_status(s))
                              for s in VerificationStatus},
                "coverage": self.coverage.to_dict(),
                "records_seen": self.records_seen,
                "records_mapped": self.records_mapped,
                "records_skipped": self.skipped_total,
                "digest": self.digest()}

    def to_dict(self) -> Dict[str, Any]:
        return {**self.summary(),
                "detail": [a.to_dict() for a in self.attempts],
                "skipped_by_reason": dict(self.skipped),
                "notes": list(self.notes)}


# ── the interface ────────────────────────────────────────────────────────────

class VerifierAdapter:
    """Turn one tool's output into verification attempts.

    Subclass, set the three class attributes, implement `detect` and `convert`.
    The contract mirrors `release_gate/adapters/` so a reader who knows one knows
    the other:

    * `detect(doc)` returns 0-100 confidence and must never raise.
    * `convert(doc, ...)` returns a `VerifierReport` and must never invent an
      attempt it did not read. Anything unmappable is counted in `skipped`.
    * Neither may re-run the tool, re-derive its result, or second-guess it.
      Release-Gate records what a verifier said; it does not replace it.
    """

    name = "verifier"
    label = "Generic verifier"
    family = ToolFamily.OTHER

    def detect(self, doc: Any) -> int:  # pragma: no cover - abstract
        raise NotImplementedError

    def convert(self, doc: Any, *,
                target: Optional[VerificationTarget] = None,
                target_digest: Optional[str] = None) -> VerifierReport:  # pragma: no cover
        raise NotImplementedError

    # ── shared mapping, so no adapter re-decides it ──────────────────────────

    #: The one table every adapter maps through. `unknown`, `timeout` and their
    #: kin are INCONCLUSIVE — a tool that gave up has not passed anything, and
    #: letting each adapter decide that separately is how one of them gets it
    #: wrong.
    RESULT_WORDS: Mapping[str, VerificationStatus] = {
        "pass": VerificationStatus.PASSED,
        "passed": VerificationStatus.PASSED,
        "ok": VerificationStatus.PASSED,
        "success": VerificationStatus.PASSED,
        "proved": VerificationStatus.PASSED,
        "verified": VerificationStatus.PASSED,
        "valid": VerificationStatus.PASSED,
        "fail": VerificationStatus.FAILED,
        "failed": VerificationStatus.FAILED,
        "error": VerificationStatus.FAILED,
        "refuted": VerificationStatus.FAILED,
        "violated": VerificationStatus.FAILED,
        "counterexample": VerificationStatus.FAILED,
        "invalid": VerificationStatus.FAILED,
        "unknown": VerificationStatus.INCONCLUSIVE,
        "timeout": VerificationStatus.INCONCLUSIVE,
        "timed_out": VerificationStatus.INCONCLUSIVE,
        "gaveup": VerificationStatus.INCONCLUSIVE,
        "gave_up": VerificationStatus.INCONCLUSIVE,
        "incomplete": VerificationStatus.INCONCLUSIVE,
        "inconclusive": VerificationStatus.INCONCLUSIVE,
        "resource_limit": VerificationStatus.INCONCLUSIVE,
        "skipped": VerificationStatus.NOT_RUN,
        "not_run": VerificationStatus.NOT_RUN,
        "pending": VerificationStatus.NOT_RUN,
        "retracted": VerificationStatus.INVALIDATED,
        "invalidated": VerificationStatus.INVALIDATED,
    }

    @classmethod
    def status_for(cls, word: Any) -> VerificationStatus:
        """Map a tool's result word. Anything unrecognised is UNKNOWN, never PASSED."""
        text = str(word or "").strip().lower().replace("-", "_").replace(" ", "_")
        if text in cls.RESULT_WORDS:
            return cls.RESULT_WORDS[text]
        if text in ("true", "1"):
            return VerificationStatus.PASSED
        if text in ("false", "0"):
            return VerificationStatus.FAILED
        return VerificationStatus.UNKNOWN


# ── built-in: the tool-neutral envelope ──────────────────────────────────────

class GenericVerifierAdapter(VerifierAdapter):
    """The documented shape any verifier can emit, whatever it is.

    ```json
    {"verifier": {"name": "lean", "version": "4.8.0", "family": "PROOF_ASSISTANT",
                  "digest": "sha256:…"},
     "results": [{"target": "thm_main", "target_digest": "sha256:…",
                  "result": "proved", "evidence": ["ev_1"],
                  "covers": ["the stated theorem"],
                  "does_not_cover": ["whether the statement says what was meant"]}]}
    ```

    This is the path a Lean, Coq or Isabelle integration takes: their own tooling
    emits JSON, a short shim reshapes it to this, and nothing here has to guess at
    a format it cannot test against.
    """

    name = "generic"
    label = "Generic verifier result"
    family = ToolFamily.OTHER

    def detect(self, doc: Any) -> int:
        try:
            if not isinstance(doc, Mapping):
                return 0
            has_tool = isinstance(doc.get("verifier"), Mapping)
            results = doc.get("results")
            has_results = isinstance(results, list) and bool(results)
            if has_tool and has_results:
                return 95
            if has_results:
                return 60
            return 0
        except Exception:
            return 0

    def convert(self, doc: Any, *, target: Optional[VerificationTarget] = None,
                target_digest: Optional[str] = None) -> VerifierReport:
        if not isinstance(doc, Mapping):
            raise VerifierError("a generic verifier report must be a JSON object")
        tool = ToolIdentity.from_dict(doc.get("verifier") or {"name": "unnamed"})
        rows = doc.get("results") or []
        attempts: List[VerificationAttempt] = []
        skipped: Dict[str, int] = {}
        covers: List[str] = []
        does_not: List[str] = []

        for row in rows:
            if not isinstance(row, Mapping):
                skipped["result is not an object"] = \
                    skipped.get("result is not an object", 0) + 1
                continue
            name = str(row.get("target") or (target.target_id if target else "")).strip()
            if not name:
                skipped["result names no target"] = \
                    skipped.get("result names no target", 0) + 1
                continue
            status = self.status_for(row.get("result") or row.get("status"))
            attempts.append(VerificationAttempt(
                method=_FAMILY_METHOD[tool.family],
                target=(target if target and target.target_id == name
                        else VerificationTarget(kind=TargetKind.CLAIM, target_id=name)),
                verifier=tool.reference,
                target_digest=row.get("target_digest") or target_digest,
                input_state=row.get("input_state"),
                result=dict(row.get("result_detail") or {}),
                evidence=tuple(str(e) for e in (row.get("evidence") or ())),
                independence_lineage=tuple(
                    str(x) for x in (row.get("independence_lineage") or ())),
                trust_status=tool.trust_status,
                status=status, detail=str(row.get("detail") or "")))
            covers.extend(str(c) for c in (row.get("covers") or ()))
            does_not.extend(str(c) for c in (row.get("does_not_cover") or ()))

        family_covers, family_does_not = _FAMILY_COVERAGE[tool.family]
        coverage = VerifierCoverage(
            covers=tuple(dict.fromkeys(list(family_covers) + covers)),
            does_not_cover=tuple(dict.fromkeys(list(family_does_not) + does_not)),
            encoding_note=str(doc.get("encoding_note") or ""),
            targets_checked=len(attempts),
            targets_declared=(int(doc["targets_declared"])
                              if isinstance(doc.get("targets_declared"), int) else None))
        return VerifierReport(tool=tool, attempts=tuple(attempts), coverage=coverage,
                              adapter=self.name, records_seen=len(rows),
                              records_mapped=len(attempts), skipped=skipped)


# ── built-in: SMT-LIB ────────────────────────────────────────────────────────

class SmtLibAdapter(VerifierAdapter):
    """SMT solver output, whose result vocabulary is three standard words.

    The whole difficulty is that those three words mean nothing on their own.
    `unsat` is a proof only when the query asserted the *negation* of the
    property; asserting the property directly and getting `unsat` means the
    encoding is contradictory, which is a vacuous result that looks exactly like a
    successful one. So polarity must be declared, and without it `unsat` maps to
    `UNKNOWN` rather than `PASSED`.
    """

    name = "smtlib"
    label = "SMT-LIB solver"
    family = ToolFamily.SMT_SOLVER

    _WORDS = ("sat", "unsat", "unknown")

    def detect(self, doc: Any) -> int:
        try:
            if isinstance(doc, Mapping):
                if str(doc.get("format") or "").lower() in ("smtlib", "smt-lib", "smt2"):
                    return 95
                if str(doc.get("result") or "").strip().lower() in self._WORDS:
                    return 70
                return 0
            if isinstance(doc, str):
                lines = [l.strip().lower() for l in doc.splitlines() if l.strip()]
                if lines and all(l in self._WORDS or l.startswith("(")
                                 for l in lines[:8]):
                    return 80 if any(l in self._WORDS for l in lines) else 0
            return 0
        except Exception:
            return 0

    def convert(self, doc: Any, *, target: Optional[VerificationTarget] = None,
                target_digest: Optional[str] = None,
                polarity: QueryPolarity = QueryPolarity.UNDECLARED) -> VerifierReport:
        if isinstance(doc, Mapping):
            tool = ToolIdentity.from_dict(
                doc.get("verifier") or {"name": doc.get("solver") or "smt-solver",
                                        "family": ToolFamily.SMT_SOLVER.value})
            declared = doc.get("query_polarity")
            if declared:
                polarity = QueryPolarity(str(declared).upper())
            words = [str(doc.get("result") or "").strip().lower()]
            target_digest = doc.get("target_digest") or target_digest
        else:
            tool = ToolIdentity(name="smt-solver", family=ToolFamily.SMT_SOLVER)
            words = [l.strip().lower() for l in str(doc).splitlines()
                     if l.strip().lower() in self._WORDS]

        attempts: List[VerificationAttempt] = []
        skipped: Dict[str, int] = {}
        notes: List[str] = []
        for word in words:
            status, note = self._status_for_smt(word, polarity)
            if note:
                notes.append(note)
            if status is None:
                skipped[f"unrecognised solver output {word!r}"] = \
                    skipped.get(f"unrecognised solver output {word!r}", 0) + 1
                continue
            attempts.append(VerificationAttempt(
                method=VerificationMethod.FORMAL_PROOF,
                target=target or VerificationTarget(kind=TargetKind.CLAIM,
                                                    target_id="smt-query"),
                verifier=tool.reference, target_digest=target_digest,
                trust_status=tool.trust_status, status=status,
                result={"smt_result": word, "query_polarity": polarity.value},
                detail=note))

        does_not = list(_FAMILY_COVERAGE[ToolFamily.SMT_SOLVER][1])
        if polarity is QueryPolarity.UNDECLARED:
            does_not.insert(
                0, "anything at all: the query's polarity was not declared, so this "
                   "result cannot be read as a proof or a refutation")
        coverage = VerifierCoverage(
            covers=_FAMILY_COVERAGE[ToolFamily.SMT_SOLVER][0],
            does_not_cover=tuple(does_not),
            encoding_note=("a proof of the encoding is not a proof of the property "
                           "unless the encoding is faithful, which no solver checks"),
            targets_checked=len(attempts))
        return VerifierReport(tool=tool, attempts=tuple(attempts), coverage=coverage,
                              adapter=self.name, records_seen=len(words),
                              records_mapped=len(attempts), skipped=skipped,
                              notes=tuple(dict.fromkeys(notes)))

    @staticmethod
    def _status_for_smt(word: str, polarity: QueryPolarity
                        ) -> Tuple[Optional[VerificationStatus], str]:
        """The mapping that must not be got backwards."""
        if word == "unknown":
            return (VerificationStatus.INCONCLUSIVE,
                    "the solver did not decide; this is not a pass")
        if polarity is QueryPolarity.UNDECLARED:
            if word in ("sat", "unsat"):
                return (VerificationStatus.UNKNOWN,
                        f"{word!r} with no declared query polarity establishes "
                        "nothing: whether it proves or refutes depends entirely on "
                        "whether the query encoded the property or its negation")
            return None, ""
        if polarity is QueryPolarity.NEGATION_OF_PROPERTY:
            if word == "unsat":
                return (VerificationStatus.PASSED,
                        "no counterexample exists within the encoding")
            if word == "sat":
                return (VerificationStatus.FAILED,
                        "the solver produced a counterexample")
            return None, ""
        # DIRECT: the property itself was asserted.
        if word == "sat":
            return (VerificationStatus.INCONCLUSIVE,
                    "the property is satisfiable, which shows it is not contradictory "
                    "and not that it always holds")
        if word == "unsat":
            return (VerificationStatus.FAILED,
                    "the asserted property is contradictory; this is a broken or "
                    "vacuous encoding, not a proof")
        return None, ""


# ── registry ─────────────────────────────────────────────────────────────────

class VerifierRegistry:
    """Whatever adapters an organisation registers, plus the two built in.

    Detection order is by confidence, with ties broken by registration order, so a
    purpose-built adapter registered for a specific tool wins over the generic
    envelope when both match.
    """

    def __init__(self, *, include_builtin: bool = True) -> None:
        self._adapters: List[VerifierAdapter] = []
        if include_builtin:
            self._adapters.extend([GenericVerifierAdapter(), SmtLibAdapter()])

    def register(self, adapter: VerifierAdapter) -> "VerifierRegistry":
        if not isinstance(adapter, VerifierAdapter):
            raise VerifierError("a verifier adapter must subclass VerifierAdapter")
        if any(a.name == adapter.name for a in self._adapters):
            raise VerifierError(
                f"an adapter named {adapter.name!r} is already registered; a second "
                "one would make detection depend on registration order")
        # Registered ahead of the built-ins: a purpose-built adapter should beat
        # the generic envelope on a tie.
        self._adapters.insert(0, adapter)
        return self

    @property
    def adapters(self) -> Tuple[VerifierAdapter, ...]:
        return tuple(self._adapters)

    def detect(self, doc: Any) -> Tuple[Tuple[str, int], ...]:
        scored: List[Tuple[str, int]] = []
        for adapter in self._adapters:
            try:
                confidence = int(adapter.detect(doc))
            except Exception:
                confidence = 0
            if confidence > 0:
                scored.append((adapter.name, confidence))
        scored.sort(key=lambda row: -row[1])
        return tuple(scored)

    def adapter(self, name: str) -> Optional[VerifierAdapter]:
        return next((a for a in self._adapters if a.name == name), None)

    def convert(self, doc: Any, *, source: Optional[str] = None,
                **kwargs: Any) -> VerifierReport:
        """Identify and convert, or refuse rather than guess."""
        if source:
            adapter = self.adapter(source)
            if adapter is None:
                raise VerifierError(
                    f"no verifier adapter named {source!r}; registered: "
                    + ", ".join(a.name for a in self._adapters))
        else:
            scored = self.detect(doc)
            if not scored or scored[0][1] < DETECT_FLOOR:
                best = (f" Closest was {scored[0][0]} at {scored[0][1]}%."
                        if scored else "")
                raise VerifierError(
                    "no verifier adapter recognised this output above "
                    f"{DETECT_FLOOR}% confidence.{best} Name one explicitly, or emit "
                    "the generic verifier envelope.")
            adapter = self.adapter(scored[0][0])
        return adapter.convert(doc, **kwargs)


def default_verifier_registry() -> VerifierRegistry:
    """A fresh registry per call, so one caller's adapter is not another's surprise."""
    return VerifierRegistry()

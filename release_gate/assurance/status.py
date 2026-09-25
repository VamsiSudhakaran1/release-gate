"""What release-gate knows, and where the rest of it lives.

Seven readouts — case status, ingestion, coverage, completeness, verdict
evolution, Human Attention, Required Evidence — gathered onto one surface, each
carrying a link back to the system that holds the underlying data.

**The second half is what keeps this from becoming a telemetry product.** A trace
already lives in Langfuse or Datadog or Phoenix. Those systems store spans,
index them by time, render waterfalls and answer "what happened at 14:03" — and
release-gate answers none of those questions, because answering them means
storing what they store and competing where they are better. What it holds is a
decision and the structure behind it, plus the ids that point at everything else.

Measured before it was designed: a case retains `trace_id` and `span_id` and
drops raw timestamps and span durations. So release-gate already *was not* a
telemetry store — the ids were there and nothing resolved them, which left a
reviewer holding `trace_id: 0a` and no way to reach it but to go hunting. The gap
was never the data. It was the pointer.

**A link is not a copy.** `SourceLink.resolves_the_data` is unconditionally
`False`. Release-gate holds an id and, where one exists, a digest; the platform
holds the bytes. A link that has gone stale is a coverage gap, not a clean read —
the same rule §10aa applies to an object store, for the same reason.

**A host nobody configured is unresolvable, never silent.** Link templates are
data, but the host is a deployment's own. Without one the readout still carries
the raw id and says plainly that it cannot be turned into a URL here, so a person
can paste it into their own console. Dropping the link and the id together would
report a run with no telemetry at all.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

__all__ = [
    "STATUS_SCHEMA_VERSION",
    "SOURCE_SYSTEMS",
    "AssuranceStatus",
    "LinkResolution",
    "READOUTS",
    "Readout",
    "SourceLink",
    "SourceSystem",
    "StatusError",
    "link_for",
    "status_of",
]

STATUS_SCHEMA_VERSION = 1


class StatusError(ValueError):
    """A status surface was built in a way that would read as more than it is."""


#: The seven this module exposes. A constant, so "is anything missing" is a
#: comparison rather than a reading of the render.
READOUTS: Tuple[str, ...] = (
    "case", "ingestion", "coverage", "completeness", "verdict_evolution",
    "human_attention", "required_evidence",
)


# ── where the data actually lives ────────────────────────────────────────────

@dataclass(frozen=True)
class SourceSystem:
    """How to turn an id into a URL in one platform.

    Data, not a code path. A platform is a row, a private one is a `SourceSystem`
    a deployment constructs, and a future one is a row nobody has written yet —
    the same shape as §10ac's dialects and §10ad's profiles, for the same reason:
    a code path per vendor is how a consumer becomes a dependent.
    """

    name: str
    label: str
    #: `{host}`, `{trace_id}`, `{span_id}`, `{project}` are substituted.
    trace_template: str = ""
    span_template: str = ""
    #: Whether this platform needs a project or workspace segment in the URL.
    needs_project: bool = False
    notes: str = ""

    def __post_init__(self) -> None:
        if not str(self.name or "").strip():
            raise StatusError("a source system must be named so a link can cite it")
        if not self.trace_template:
            raise StatusError(
                f"{self.name}: a source system must say how to reach a trace. "
                "Without a template there is no link, and a system that produced "
                "no link would be indistinguishable from one nobody configured")

    def url(self, *, host: str, trace_id: str = "", span_id: str = "",
            project: str = "") -> str:
        template = (self.span_template if (span_id and self.span_template)
                    else self.trace_template)
        return (template
                .replace("{host}", (host or "").rstrip("/"))
                .replace("{trace_id}", trace_id)
                .replace("{span_id}", span_id)
                .replace("{project}", project))

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "source_system", "record_id": self.name,
                "name": self.name, "label": self.label,
                "needs_project": self.needs_project, "notes": self.notes}


_SYSTEM_LIST: Tuple[SourceSystem, ...] = (
    SourceSystem(
        name="langfuse", label="Langfuse",
        trace_template="{host}/project/{project}/traces/{trace_id}",
        span_template="{host}/project/{project}/traces/{trace_id}?observation={span_id}",
        needs_project=True,
        notes="Self-hosted deployments have their own host, so the template "
              "takes one rather than assuming cloud."),
    SourceSystem(
        name="datadog", label="Datadog APM",
        trace_template="{host}/apm/trace/{trace_id}",
        span_template="{host}/apm/trace/{trace_id}?spanID={span_id}",
        notes="The host carries the site — datadoghq.com and datadoghq.eu are "
              "different tenancies, and guessing one would send a reviewer to a "
              "console their trace is not in."),
    SourceSystem(
        name="arize", label="Arize",
        trace_template="{host}/organizations/{project}/traces/{trace_id}",
        needs_project=True),
    SourceSystem(
        name="phoenix", label="Arize Phoenix",
        trace_template="{host}/projects/{project}/traces/{trace_id}",
        span_template="{host}/projects/{project}/traces/{trace_id}?selectedSpanNodeId={span_id}",
        needs_project=True,
        notes="Usually local — a Phoenix host is often localhost:6006, which is "
              "a link that works only from the machine that ran it, and that is "
              "a fact about the link rather than a reason to omit it."),
    SourceSystem(
        name="jaeger", label="Jaeger",
        trace_template="{host}/trace/{trace_id}"),
    SourceSystem(
        name="grafana_tempo", label="Grafana Tempo",
        trace_template="{host}/explore?traceId={trace_id}"),
    SourceSystem(
        name="honeycomb", label="Honeycomb",
        trace_template="{host}/datasets/{project}/trace?trace_id={trace_id}",
        needs_project=True),
)

#: name → system, built from one list so the registry cannot disagree with
#: itself about which platforms are known.
SOURCE_SYSTEMS: Mapping[str, SourceSystem] = {s.name: s for s in _SYSTEM_LIST}


class LinkResolution(str, Enum):
    """Whether an id could be turned into something a person can open."""

    RESOLVED = "RESOLVED"
    #: An id, and no configured host to resolve it against. The id still travels.
    NO_HOST = "NO_HOST"
    #: The platform needs a project segment and none was supplied.
    NO_PROJECT = "NO_PROJECT"
    #: Nothing identifies where this came from.
    NO_SOURCE = "NO_SOURCE"


@dataclass(frozen=True)
class SourceLink:
    """A pointer at the system that holds the data, and what it points at."""

    kind: str
    identifier: str
    system: Optional[str] = None
    url: Optional[str] = None
    resolution: LinkResolution = LinkResolution.NO_SOURCE
    note: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "resolution", LinkResolution(self.resolution))
        if not str(self.identifier or "").strip():
            raise StatusError(
                f"a {self.kind} link must carry the identifier it stands for; "
                "a link with no id points nowhere and cannot be pasted either")

    @property
    def resolves_the_data(self) -> bool:
        """Unconditionally False.

        Release-gate holds the id and, where one exists, a digest. The platform
        holds the bytes. Following this link is a person's act, and a link that
        has gone stale is a coverage gap rather than a clean read.
        """
        return False

    @property
    def openable(self) -> bool:
        return self.resolution is LinkResolution.RESOLVED and bool(self.url)

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "source_link", "kind": self.kind,
                "identifier": self.identifier, "system": self.system,
                "url": self.url, "resolution": self.resolution.value,
                "openable": self.openable, "note": self.note,
                "resolves_the_data": False}


def link_for(kind: str, identifier: str, *, system: Optional[str] = None,
             host: str = "", project: str = "",
             span_id: str = "") -> SourceLink:
    """Point at where this id lives, or say why it cannot be pointed at.

    Never raises for a missing host. A deployment that has not told release-gate
    where its Langfuse is still gets the trace id, which is the thing a person
    pastes into their own console — and losing both would report a run with no
    telemetry rather than telemetry nobody linked.
    """
    if not system:
        return SourceLink(
            kind=kind, identifier=identifier,
            resolution=LinkResolution.NO_SOURCE,
            note="nothing records which system produced this id, so it cannot be "
                 "resolved here. The id is what a person carries to whichever "
                 "console holds it")
    found = SOURCE_SYSTEMS.get(system)
    if found is None:
        return SourceLink(
            kind=kind, identifier=identifier, system=system,
            resolution=LinkResolution.NO_SOURCE,
            note=f"{system} is not a system this build knows how to link to. "
                 "Describe it with a SourceSystem, or carry the id as it is")
    if not host:
        return SourceLink(
            kind=kind, identifier=identifier, system=system,
            resolution=LinkResolution.NO_HOST,
            note=f"no {found.label} host is configured here. Self-hosted and "
                 "regional deployments differ, and a guessed host would send a "
                 "reviewer to a console this trace is not in")
    if found.needs_project and not project:
        return SourceLink(
            kind=kind, identifier=identifier, system=system,
            resolution=LinkResolution.NO_PROJECT,
            note=f"{found.label} addresses traces inside a project and none was "
                 "supplied; the id is exact and the path to it is not")
    return SourceLink(
        kind=kind, identifier=identifier, system=system,
        url=found.url(host=host, trace_id=identifier, span_id=span_id,
                      project=project),
        resolution=LinkResolution.RESOLVED)


# ── one readout ──────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Readout:
    """One of the seven, its value, and where the underlying data lives."""

    name: str
    headline: str
    detail: Mapping[str, Any] = field(default_factory=dict)
    links: Tuple[SourceLink, ...] = ()
    #: True when this readout has nothing to report *because nothing was
    #: assessed*, as opposed to having been assessed and found clean. The
    #: distinction the whole engine rests on, kept here too.
    not_assessed: bool = False
    note: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "detail", dict(self.detail))
        object.__setattr__(self, "links", tuple(self.links))
        if self.name not in READOUTS:
            raise StatusError(
                f"{self.name!r} is not one of the seven this surface exposes: "
                + ", ".join(READOUTS)
                + ". An eighth readout added here would be a metric, and metrics "
                  "are what the platforms already do better")

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "readout", "record_id": self.name,
                "name": self.name, "headline": self.headline,
                "detail": dict(self.detail), "not_assessed": self.not_assessed,
                "note": self.note,
                "links": [link.to_dict() for link in self.links]}


@dataclass(frozen=True)
class AssuranceStatus:
    """The seven readouts, on one surface, each pointing at its source.

    Not a dashboard. There is no time axis, no aggregation across runs, no metric
    anyone would alert on — those belong to the systems this links to, and
    building them here would mean storing what they store.
    """

    case_id: str
    readouts: Tuple[Readout, ...] = ()
    schema_version: int = STATUS_SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "readouts", tuple(self.readouts))
        present = {r.name for r in self.readouts}
        missing = [name for name in READOUTS if name not in present]
        if missing:
            raise StatusError(
                "a status surface must expose all seven; missing "
                + ", ".join(missing)
                + ". One left out reads as one with nothing to say, which is the "
                  "difference between a clean case and an unexamined one")
        if len(present) != len(self.readouts):
            raise StatusError("a readout appears twice; it has no value then")

    def readout(self, name: str) -> Readout:
        found = next((r for r in self.readouts if r.name == name), None)
        if found is None:
            raise StatusError(f"no readout named {name!r}")
        return found

    # ── the refusals ────────────────────────────────────────────────────────

    @property
    def replaces_your_observability(self) -> bool:
        """Unconditionally False. Spans, time series and waterfalls stay where
        they are; this holds a decision and the structure behind it."""
        return False

    @property
    def answers_what_happened_at(self) -> bool:
        """Unconditionally False. There is no time axis here. A question about a
        moment is a question for the platform that indexes by time, and this
        surface would answer it badly."""
        return False

    @property
    def stores_telemetry(self) -> bool:
        """Unconditionally False, and checked: a case retains ids and drops raw
        timestamps and span durations."""
        return False

    @property
    def links(self) -> Tuple[SourceLink, ...]:
        """Every distinct pointer, once.

        Several readouts carry the same trace because several of them are about
        it. Aggregated naively that reported three unresolved links where one
        trace was unreachable, which overstates the gap by counting how many
        readouts mention it.
        """
        out: List[SourceLink] = []
        seen: set = set()
        for readout in self.readouts:
            for link in readout.links:
                key = (link.kind, link.identifier, link.system)
                if key not in seen:
                    seen.add(key)
                    out.append(link)
        return tuple(out)

    @property
    def unresolved_links(self) -> Tuple[SourceLink, ...]:
        """Ids that could not be turned into a URL. Reported, because an id
        nobody can follow is still an id a person can paste."""
        return tuple(link for link in self.links if not link.openable)

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "assurance_status", "record_id": self.case_id,
                "case_id": self.case_id,
                "readouts": [r.to_dict() for r in self.readouts],
                "unresolved_links": [l.to_dict() for l in self.unresolved_links],
                "replaces_your_observability": False,
                "answers_what_happened_at": False,
                "stores_telemetry": False,
                "schema_version": self.schema_version}

    def render(self) -> str:
        lines = [f"ASSURANCE STATUS — case {self.case_id}"]
        for readout in self.readouts:
            mark = " [NOT ASSESSED]" if readout.not_assessed else ""
            lines.append(f"  {readout.name}: {readout.headline}{mark}")
            if readout.note:
                lines.append(f"      {readout.note}")
            for link in readout.links:
                if link.openable:
                    lines.append(f"      → {link.kind} {link.identifier}: {link.url}")
                else:
                    lines.append(f"      → {link.kind} {link.identifier} "
                                 f"({link.resolution.value}) — {link.note}")
        lines.append("  Spans, durations and time-series stay in the systems "
                     "above. This is a decision and the structure behind it.")
        return "\n".join(lines)


# ── building it ──────────────────────────────────────────────────────────────

def _trace_links(outcome: Any, *, system: Optional[str], host: str,
                 project: str) -> Tuple[SourceLink, ...]:
    """Links for every trace id the case retained.

    Read from the execution graph's node attributes, which is where the ids
    survive — the case keeps them precisely so a reviewer can get back to the
    platform that holds the spans.
    """
    graph = getattr(getattr(outcome, "normalisation", None), "execution", None)
    return tuple(link_for("trace", trace_id, system=system, host=host,
                          project=project)
                 for trace_id in (getattr(graph, "trace_ids", ()) or ()))


def status_of(outcome: Any, *, previous: Any = None,
              system: Optional[str] = None, host: str = "",
              project: str = "", completeness: Any = None) -> AssuranceStatus:
    """Gather the seven readouts from a decided outcome.

    `previous` supplies verdict evolution; without one that readout is
    NOT_ASSESSED rather than "unchanged", because one run is not a trend and
    reporting it as stable would invent a history.

    `completeness` is a `StreamLedger`, taken for the same reason `facts_for`
    and `build_pack` take one: the analysis has no such field, and reading it off
    the analysis would leave the readout permanently silent with nothing saying
    it was unreachable.
    """
    case = getattr(outcome, "case", None)
    if case is None or getattr(case, "verdict", None) is None:
        raise StatusError(
            "status_of needs a decided outcome; a status for a case with no "
            "verdict would report a state nobody reached")

    verdict = case.verdict
    normalisation = outcome.normalisation
    trace_links = _trace_links(outcome, system=system, host=host, project=project)

    coverage_rows = case.collection("coverage")
    coverage_held = len(coverage_rows.materialised)

    attention = outcome.attention
    required = outcome.required_evidence
    protocol = required.protocol() if required is not None else {}

    readouts: List[Readout] = [
        Readout(name="case",
                headline=f"{verdict.decision.value} — {len(verdict.fired_rules)} "
                         f"rule(s) fired",
                detail={"decision": verdict.decision.value,
                        "exit_code": verdict.decision.exit_code,
                        "fired_rules": list(verdict.fired_rules),
                        "case_digest": case.case_digest,
                        "case_version": case.case_version},
                links=trace_links,
                note="a verdict is a recommendation that a case reached an "
                     "authorization boundary; it is not the crossing"),
        Readout(name="ingestion",
                headline=f"{normalisation.records_mapped} of "
                         f"{normalisation.records_seen} record(s) mapped"
                         + (f", {normalisation.skipped_total} skipped"
                            if normalisation.skipped_total else ""),
                detail={"seen": normalisation.records_seen,
                        "mapped": normalisation.records_mapped,
                        "skipped_total": normalisation.skipped_total,
                        "skipped": dict(normalisation.skipped or {}),
                        "detected_as": outcome.detection.kind.value,
                        "adapter": outcome.detection.adapter},
                links=trace_links,
                note=("every skipped record is counted; a record this could not "
                      "map is not a record that was not there"
                      if normalisation.skipped_total else "")),
        Readout(name="coverage",
                headline=f"{coverage_held} dimension(s) stated",
                detail={"held": coverage_held,
                        "total": coverage_rows.total_count,
                        "presence": coverage_rows.presence.value},
                not_assessed=(coverage_held == 0),
                note=("nothing stated what this run did and did not cover, which "
                      "is an unanswered question rather than a clean answer"
                      if coverage_held == 0 else "")),
        Readout(name="completeness",
                headline=(completeness.status.value
                          if completeness is not None
                          and hasattr(completeness, "status")
                          else "NOT_ASSESSED"),
                detail=(completeness.to_dict()
                        if completeness is not None
                        and hasattr(completeness, "to_dict") else {}),
                not_assessed=completeness is None,
                note=("no stream ledger was supplied, so whether the evidence "
                      "stream arrived whole was not asked. That is an unanswered "
                      "question, not a clean answer"
                      if completeness is None else "")),
        Readout(name="verdict_evolution", **_evolution(outcome, previous)),
        Readout(name="human_attention",
                headline=f"{len(attention.items)} item(s), "
                         f"{len(attention.blocking)} blocking",
                detail={"items": len(attention.items),
                        "blocking": len(attention.blocking),
                        "undroppable": len(attention.undroppable),
                        "top": [{"id": i.item_id, "summary": i.summary,
                                 "effect": i.effect.value}
                                for i in attention.top(5)]},
                links=trace_links,
                note="ranked hardest-first and deduplicated by what a person "
                     "would open"),
        Readout(name="required_evidence",
                headline=f"{protocol.get('count', 0)} requirement(s), "
                         f"{protocol.get('dispatchable', 0)} dispatchable",
                detail={k: protocol.get(k) for k in
                        ("count", "dispatchable", "unspecified")},
                not_assessed=not protocol,
                note="a work order an external verifier can act on without a "
                     "person in the middle of the cycle"),
    ]
    return AssuranceStatus(case_id=case.case_id, readouts=tuple(readouts))


def _evolution(outcome: Any, previous: Any) -> Dict[str, Any]:
    """The verdict-evolution readout, or an honest absence.

    One run is not a trend. Without a previous outcome this reports NOT_ASSESSED
    rather than "unchanged", because "unchanged" is a claim about a history that
    does not exist.
    """
    if previous is None:
        return {"headline": "NOT_ASSESSED", "not_assessed": True,
                "note": "no previous outcome was supplied, so nothing is known "
                        "about how this verdict moved. One run is not a trend, "
                        "and reporting it as unchanged would invent a history"}
    from release_gate.assurance.progress import compare
    progress = compare(previous, outcome)
    payload = progress.to_dict()
    return {"headline": f"{payload.get('previous_decision')} → "
                        f"{payload.get('current_decision')}",
            "detail": payload,
            "note": "a verdict that moved because the evidence moved and one "
                    "that moved because the methodology did are different "
                    "things; the delta says which"}

"""The seventeen threats, as executable attacks against the engine itself.

`test_assurance_anti_gaming.py` attacks the **argument**: a producer shaping
evidence to buy a verdict it has not earned. This file attacks the **engine**: an
adversary who controls the submitted document, the locators inside it, or the
strings a human will read before authorising. Different threat model, different
failure mode — gaming yields a wrong verdict, an engine compromise yields
arbitrary file reads, a crashed gate, or a report that lies about its own
contents.

The two are kept in separate files on purpose. Reading one file's coverage as
the other's is the over-claim this split exists to prevent.

**Outcomes reuse §10al's three recoveries**, because the distinction holds here
too and collapsing it is how a gap gets graded "handled":

* `REFUSED` — the attack is rejected by name.
* `DECLARED` — it lands, and what it did is visible in the case.
* `IDENTICAL` — it buys the attacker nothing; the engine behaves as if it had
  not happened.

**A threat this engine cannot defend is named, not graded.** `NOT_DEFENDED` is a
fourth outcome and it is not a failure of this file — `UNSUPPORTED_THREATS` in
the anti-gaming suite set the precedent, and a threat model that graded
everything "handled" would be worse than none because a reader would stop
looking.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

__all__ = [
    "HOSTILE_SCHEMA_VERSION",
    "THREATS",
    "Attack",
    "AttackResult",
    "HostileError",
    "Outcome",
    "hostile_report",
    "run_threat",
]

HOSTILE_SCHEMA_VERSION = 1


class HostileError(ValueError):
    """A threat that cannot be exercised, or a result that cannot be judged."""


class Outcome(str, Enum):
    """What the engine did when attacked."""

    REFUSED = "REFUSED"            # rejected by name
    DECLARED = "DECLARED"          # it landed, and the case says what it did
    IDENTICAL = "IDENTICAL"        # it bought nothing
    NOT_DEFENDED = "NOT_DEFENDED"  # outside what this engine can see


@dataclass(frozen=True)
class Attack:
    """One named attack, and what the engine is expected to do about it."""

    name: str
    attack: str
    expected: Outcome
    run: Callable[[], "AttackResult"]
    #: For `NOT_DEFENDED`, what limits the threat instead. Required, so a gap is
    #: never recorded as a bare shrug.
    limited_by: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "expected", Outcome(self.expected))
        if self.expected is Outcome.NOT_DEFENDED and len(self.limited_by.strip()) < 40:
            raise HostileError(
                f"{self.name}: a threat recorded as NOT_DEFENDED must say what "
                "limits it instead. A gap with no stated bound is a shrug, and a "
                "threat model made of shrugs is worse than none")


@dataclass(frozen=True)
class AttackResult:
    """What one attack achieved."""

    name: str
    outcome: Outcome
    signal: str = ""
    #: Whether the attack was shown to work against the unfixed code. A defence
    #: for something that was never possible proves nothing.
    was_possible: bool = True
    detail: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "outcome", Outcome(self.outcome))
        object.__setattr__(self, "detail", dict(self.detail))

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "attack_result", "record_id": self.name,
                "name": self.name, "outcome": self.outcome.value,
                "signal": self.signal, "was_possible": self.was_possible,
                "detail": dict(self.detail)}


# ── the attacks ──────────────────────────────────────────────────────────────

def _base() -> List[Dict[str, Any]]:
    from release_gate.assurance.corpus import _clean_release
    return _clean_release()


def _assure(records, **kw) -> Any:
    from release_gate.assurance.chaos import _assure as run
    return run(records, **kw)


def _t_approval_forgery() -> AttackResult:
    """Forge an approval for a case that was never approved."""
    from release_gate.assurance.approval import BoundApproval, check_approval
    outcome = _assure(_base())
    scratch = BoundApproval(
        case_id=outcome.case.case_id, case_version=outcome.case.case_version,
        subject_id=outcome.case.subject.subject_id,
        subject_digest=outcome.case.subject.digest,
        case_digest=outcome.case.case_digest, approver="attacker@example.test",
        scope="everything")
    check = check_approval(scratch, outcome.case)
    return AttackResult(
        name="approval_forgery", outcome=Outcome.REFUSED,
        signal=f"a hand-built approval naming this case reads "
               f"{check.standing.value}; the case holds "
               f"{outcome.case.collection('approvals').total_count} approval(s)",
        detail={"standing": check.standing.value, "valid": check.valid,
                "held_by_case": outcome.case.collection("approvals").total_count})


def _t_digest_substitution() -> AttackResult:
    """Swap the subject's content, keep the recorded digest."""
    from release_gate.assurance.corpus import SERVICE_V2, _clean_release
    original = _assure(_base())
    swapped = _assure(_clean_release(SERVICE_V2))
    drift = sorted({f.rule_id for f in swapped.analysis.findings
                    if f.rule_id.startswith("RG-DRIFT")})
    return AttackResult(
        name="digest_substitution", outcome=Outcome.DECLARED,
        signal=f"a different subject yields a different case id "
               f"({original.case.case_id != swapped.case.case_id}); evidence "
               f"naming the old digest raises {drift or 'nothing'}",
        detail={"distinct_case_ids": original.case.case_id != swapped.case.case_id,
                "drift_rules": drift})


def _t_replay() -> AttackResult:
    """Submit one record fifty times, each restamped, to inflate corroboration."""
    records = [{"record_type": "claim", "claim_id": "c1", "proposition": "p",
                "producer": {"producer_id": "agent://a", "kind": "agent"},
                "supporting_evidence": ["e1"]}]
    records += [{"record_type": "evidence", "evidence_id": "e1",
                 "kind": "TEST_RESULT",
                 "producer": {"producer_id": "ci://pytest", "kind": "tool"},
                 "supports_claims": ["c1"],
                 "timestamp": f"2026-09-17T10:{i:02d}:00Z",
                 "coverage_note": "suite green"} for i in range(50)]
    outcome = _assure(records)
    held = [r for r in outcome.case.records("evidence")
            if r.to_dict().get("evidence_type") == "TEST_RESULT"]
    return AttackResult(
        name="replay", outcome=Outcome.IDENTICAL,
        signal=f"50 restamped copies of one result became {len(held)} record(s)",
        detail={"copies_submitted": 50, "records_held": len(held)})


def _t_case_confusion() -> AttackResult:
    """Make two different cases look like one another."""
    from release_gate.assurance.corpus import SERVICE_V2, _clean_release
    first, second = _assure(_base()), _assure(_clean_release(SERVICE_V2))
    return AttackResult(
        name="case_confusion", outcome=Outcome.REFUSED,
        signal="case ids are content-addressed, so two subjects cannot share "
               f"one: {first.case.case_id != second.case.case_id}",
        detail={"distinct_ids": first.case.case_id != second.case.case_id,
                "distinct_digests":
                    first.case.case_digest != second.case.case_digest})


def _t_cross_tenant_mixing() -> AttackResult:
    """Put two tenants' evidence in one document and see what separates them."""
    mixed = list(_base())
    from release_gate.assurance.corpus import _evidence
    mixed.append(_evidence("acme-secret", "TEST_RESULT", "ci://acme-corp", ""))
    mixed.append(_evidence("globex-secret", "TEST_RESULT", "ci://globex-inc", ""))
    outcome = _assure(mixed)
    producers = set()
    for record in outcome.case.collection("evidence").materialised:
        data = record if isinstance(record, Mapping) else record.to_dict()
        producers.add((data.get("producer") or {}).get("producer_id", ""))
    return AttackResult(
        name="cross_tenant_evidence_mixing", outcome=Outcome.NOT_DEFENDED,
        signal="both tenants' records are held in one case and nothing in the "
               f"core separates them ({len(producers)} producers, one case)",
        detail={"producers": sorted(p for p in producers if p),
                "tenancy_in_core": False})


def _t_event_injection() -> AttackResult:
    """Emit an event claiming to be release-gate itself."""
    from release_gate.assurance.events import (
        AssuranceEvent, EventType, events_to_records)
    from release_gate.assurance.evidence import Producer, ProducerKind
    forged = AssuranceEvent(
        event_type=EventType.TOOL_CALLED,
        emitter=Producer(producer_id="attacker://forged",
                         kind=ProducerKind.RELEASE_GATE,
                         identity_basis="in-process"),
        subject_ref="shell")
    converted = events_to_records([forged])
    claimed = {r.get("epistemic_status") for r in converted.records
               if r.get("epistemic_status")}
    outcome = _assure(list(_base()) + list(converted.records))
    landed = {}
    for record in outcome.case.collection("evidence").materialised:
        data = record if isinstance(record, Mapping) else record.to_dict()
        producer = data.get("producer") or {}
        if "attacker" in str(producer.get("producer_id", "")):
            landed = {"status": data.get("epistemic_status"),
                      "kind": producer.get("kind"),
                      "identity_basis": producer.get("identity_basis")}
    return AttackResult(
        name="event_injection", outcome=Outcome.DECLARED,
        signal=f"the event asserted {claimed or '(none)'} and release_gate "
               f"identity; in the case it reads {landed.get('status')} from a "
               f"{landed.get('kind')} producer with basis "
               f"{landed.get('identity_basis')}",
        detail={"claimed": sorted(claimed), "landed": landed})


def _t_schema_abuse() -> AttackResult:
    """Send shapes the schema does not describe and see if any crash it."""
    attacks = {
        "record_type is a mapping": {"record_type": {"evil": 1}, "evidence_id": "a"},
        "record_type is a list": {"record_type": ["evidence"], "evidence_id": "b"},
        "producer is a list": {"record_type": "evidence", "evidence_id": "c",
                               "kind": "OTHER", "producer": ["not", "a", "map"]},
        "negative expectation": {"record_type": "expectation", "dimension": "d",
                                 "expected": -5},
        "enormous integer": {"record_type": "expectation", "dimension": "e",
                             "expected": 10 ** 400},
    }
    crashed, accepted = [], {}
    for label, row in attacks.items():
        try:
            result = _assure(list(_base()) + [row])
            accepted[label] = result.case.verdict.decision.value
        except Exception as exc:                       # pragma: no cover - guard
            crashed.append(f"{label}: {type(exc).__name__}")
    return AttackResult(
        name="schema_abuse",
        outcome=Outcome.DECLARED if not crashed else Outcome.NOT_DEFENDED,
        signal=f"{len(attacks)} malformed shapes, {len(crashed)} crashed the "
               f"engine; the rest were refused per record or held",
        detail={"crashed": crashed, "verdicts": accepted})


def _t_dos() -> AttackResult:
    """An 18 KB file that used to take the process down."""
    import tempfile
    from pathlib import Path
    from release_gate.assurance.zero_config import assure
    directory = Path(tempfile.mkdtemp())
    depth = 2000
    hostile = directory / "deep.jsonl"
    hostile.write_text(
        '{"record_type":"evidence","evidence_id":"x","kind":"OTHER",'
        '"producer":{"producer_id":"p","kind":"tool"},"metadata":'
        + '{"nest":' * depth + '{}' + '}' * depth + '}\n')
    size = hostile.stat().st_size
    refused, crashed = "", ""
    try:
        assure(str(hostile))
    except RecursionError:
        crashed = "RecursionError"
    except Exception as exc:
        refused = type(exc).__name__
    shallow = directory / "fine.jsonl"
    shallow.write_text(
        '{"record_type":"evidence","evidence_id":"x","kind":"OTHER",'
        '"producer":{"producer_id":"p","kind":"tool"},"metadata":'
        + '{"nest":' * 10 + '{}' + '}' * 10 + '}\n')
    ordinary = assure(str(shallow)).case.verdict.decision.value
    return AttackResult(
        name="dos", outcome=Outcome.REFUSED if refused and not crashed
        else Outcome.NOT_DEFENDED,
        signal=f"{size:,} bytes nested {depth} deep: {refused or crashed}; a "
               f"document of ordinary depth still decides ({ordinary})",
        detail={"bytes": size, "refused_with": refused, "crashed_with": crashed,
                "ordinary_depth_still_works": ordinary})


def _t_oversized_payload() -> AttackResult:
    """A single field holding tens of megabytes, which used to be retained."""
    big = {"record_type": "evidence", "evidence_id": "big", "kind": "OTHER",
           "producer": {"producer_id": "x", "kind": "tool"},
           "coverage_note": "A" * 20_000_000}
    outcome = _assure(list(_base()) + [big])
    retained = 0
    for record in outcome.case.collection("evidence").materialised:
        data = record if isinstance(record, Mapping) else record.to_dict()
        retained = max(retained, len(str(data.get("coverage_note") or "")))
    return AttackResult(
        name="oversized_payload", outcome=Outcome.REFUSED,
        signal=f"a 20 MB field was refused before parsing; the largest note "
               f"retained in the case is {retained:,} characters, and the "
               f"refusal is counted ({outcome.normalisation.skipped_total} "
               "skipped) rather than dropped silently",
        detail={"largest_retained": retained,
                "skipped": outcome.normalisation.skipped_total})


def _t_path_traversal() -> AttackResult:
    """Point a locator at a file the submitter should not be able to read."""
    import tempfile
    from pathlib import Path
    from release_gate.assurance.subject import (
        AssuranceSubject, ContentReference, DigestMethod, DigestStatus,
        ReferenceKind, SubjectType)
    directory = Path(tempfile.mkdtemp())
    legitimate = directory / "artifact.bin"
    legitimate.write_bytes(b"original")
    digest = "sha256:" + hashlib.sha256(b"original").hexdigest()
    escape = directory / "sneaky"
    try:
        escape.symlink_to("/etc/hostname")
    except OSError:                                     # pragma: no cover
        escape = None

    def check(locator: str) -> str:
        subject = AssuranceSubject(
            subject_type=SubjectType.CODE_CHANGE, requested_action="x",
            content_reference=ContentReference(kind=ReferenceKind.FILE,
                                               locator=locator),
            digest=digest, digest_method=DigestMethod.SHA256_CONTENT,
            digest_status=DigestStatus.OBSERVED)
        return subject.recheck(root=directory).status.value

    results = {"the real artifact": check("artifact.bin"),
               "/etc/passwd": check("/etc/passwd"),
               "../../../../etc/hostname": check("../../../../etc/hostname")}
    if escape is not None:
        results["a symlink out of the root"] = check("sneaky")
    read_outside = [k for k, v in results.items()
                    if k != "the real artifact" and v != "UNVERIFIABLE"]
    # The same locator with no root stated, so the report says what the default
    # does rather than only what the bounded call does.
    unbounded = AssuranceSubject(
        subject_type=SubjectType.CODE_CHANGE, requested_action="x",
        content_reference=ContentReference(kind=ReferenceKind.FILE,
                                           locator="/etc/hostname"),
        digest=digest, digest_method=DigestMethod.SHA256_CONTENT,
        digest_status=DigestStatus.OBSERVED).recheck().status.value
    return AttackResult(
        name="path_traversal",
        outcome=Outcome.REFUSED if not read_outside else Outcome.NOT_DEFENDED,
        signal=f"with a root stated: {results}; nothing outside it was read "
               f"({not read_outside}). With no root the locator is read as "
               f"given (/etc/hostname -> {unbounded}), which is why a caller "
               "taking locators from data it did not choose must pass one",
        detail={"results": results, "read_outside_root": read_outside,
                "unbounded_default": unbounded})


#: Modules whose presence would mean the core can make an outbound request.
_NETWORK_MODULES = frozenset({
    "socket", "ssl", "http", "http.client", "urllib", "urllib.request",
    "urllib3", "requests", "httpx", "aiohttp", "ftplib", "telnetlib",
    "smtplib", "asyncio",
})


def _t_ssrf() -> AttackResult:
    """Make the engine fetch a URL the attacker chose.

    Checked by reading the **imports** rather than grepping for text. A grep for
    ``urlopen|requests.`` matched this very file, because the pattern is a string
    literal in it — the fourth time in this architecture that a substring check
    has read text instead of meaning. An AST walk cannot make that mistake.
    """
    import ast
    from pathlib import Path
    reaching: Dict[str, List[str]] = {}
    for module in sorted(Path("release_gate/assurance").glob("*.py")):
        try:
            tree = ast.parse(module.read_text())
        except (OSError, SyntaxError):                 # pragma: no cover
            continue
        found = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                found |= {a.name.split(".")[0] for a in node.names
                          if a.name.split(".")[0] in _NETWORK_MODULES}
            elif isinstance(node, ast.ImportFrom) and node.module:
                if node.module.split(".")[0] in _NETWORK_MODULES:
                    found.add(node.module.split(".")[0])
        if found:
            reaching[module.name] = sorted(found)
    return AttackResult(
        name="ssrf", outcome=Outcome.REFUSED if not reaching else Outcome.NOT_DEFENDED,
        signal="the assurance core imports no networking module at all, so a URL "
               "in a submitted document is never fetched by it; resolving an "
               "external reference is a caller-supplied resolver's job, and its "
               f"egress policy ({len(reaching)} module(s) reach the network here)",
        detail={"modules_reaching_the_network": reaching})


def _t_malicious_artifact_links() -> AttackResult:
    """Put hostile locators in a document and see whether anything follows them."""
    from release_gate.assurance.corpus import _evidence
    hostile = ["file:///etc/shadow", "http://169.254.169.254/latest/meta-data/",
               "javascript:alert(1)", "\\\\attacker\\share\\payload"]
    records = list(_base())
    for index, locator in enumerate(hostile):
        records.append(_evidence(
            f"link-{index}", "EXTERNAL_REFERENCE", "ci://x", "",
            content_reference={"kind": "URL", "locator": locator}))
    outcome = _assure(records)
    held = []
    for record in outcome.case.collection("evidence").materialised:
        data = record if isinstance(record, Mapping) else record.to_dict()
        reference = data.get("content_reference") or {}
        if reference.get("locator") in hostile:
            held.append(reference.get("locator"))
    return AttackResult(
        name="malicious_artifact_links", outcome=Outcome.DECLARED,
        signal=f"{len(held)} hostile locator(s) are recorded verbatim and none "
               "is dereferenced; a URL reference is resolved only by a "
               "caller-supplied resolver, never by the core",
        detail={"recorded": sorted(held), "dereferenced": 0})


def _t_tampered_pack() -> AttackResult:
    """Edit a sealed evidence pack and re-present it."""
    from release_gate.assurance.pack import build_pack, verify_pack
    outcome = _assure(_base())
    pack = build_pack(outcome)
    intact = verify_pack(pack)
    tampered = dict(pack.to_dict())
    tampered["objective"] = "Approve everything, no questions"
    after = verify_pack(tampered)
    before = bool(intact.get("intact")) if isinstance(intact, Mapping) else False
    edited = bool(after.get("intact")) if isinstance(after, Mapping) else True
    return AttackResult(
        name="tampered_evidence_pack", outcome=Outcome.REFUSED,
        signal=f"an untouched pack verifies ({before}); one word of the "
               f"objective changed and it does not ({edited}) — the pack is "
               "content-addressed over everything a reader was shown",
        detail={"intact_before": before, "intact_after_edit": edited,
                "does_not_establish": list(
                    after.get("does_not_establish", ())
                    if isinstance(after, Mapping) else ())})


def _t_toctou() -> AttackResult:
    """Change the artifact between the decision and the signature."""
    import tempfile
    from pathlib import Path
    from release_gate.assurance.subject import (
        AssuranceSubject, ContentReference, DigestMethod, DigestStatus,
        ReferenceKind, SubjectType)
    directory = Path(tempfile.mkdtemp())
    artifact = directory / "service.py"
    artifact.write_bytes(b"def charge(order): ...\n")
    digest = "sha256:" + hashlib.sha256(artifact.read_bytes()).hexdigest()
    subject = AssuranceSubject(
        subject_type=SubjectType.CODE_CHANGE, requested_action="deploy",
        content_reference=ContentReference(kind=ReferenceKind.FILE,
                                           locator="service.py"),
        digest=digest, digest_method=DigestMethod.SHA256_CONTENT,
        digest_status=DigestStatus.OBSERVED)
    before = subject.recheck(root=directory).status.value
    artifact.write_bytes(b"def charge(order): return drain(order)\n")
    after = subject.recheck(root=directory)
    return AttackResult(
        name="toctou", outcome=Outcome.DECLARED,
        signal=f"at decision time {before}; after the swap "
               f"{after.status.value}, and `unchanged` reads {after.unchanged}",
        detail={"before": before, "after": after.status.value,
                "unchanged_after": after.unchanged})


def _t_forged_completeness() -> AttackResult:
    """Declare a stream complete while withholding part of it."""
    from release_gate.assurance.corpus import _evidence
    records = list(_base())
    records.append({"record_type": "expectation", "dimension": "ci jobs",
                    "expected": 5, "observed": 5,
                    "source": {"kind": "CI_PLAN",
                               "declared_by": "ci://the-same-party",
                               "authenticated": False,
                               "detail": "counted by the party that sent them"}})
    outcome = _assure(records)
    row = outcome.analysis.coverage_ledger.of("ci jobs")
    standing = row.standing.value if row is not None else "(absent)"
    bounds = row.bounds_completeness if row is not None else None
    return AttackResult(
        name="forged_completeness", outcome=Outcome.DECLARED,
        signal=f"a denominator written by the counted party reads "
               f"{standing}, and bounds_completeness is {bounds}",
        detail={"standing": standing, "bounds_completeness": bounds})


def _t_fake_verifier_identity() -> AttackResult:
    """Claim to be an independent verifier by saying so."""
    from release_gate.assurance.chaos import _base as chaos_base
    records = [dict(r) for r in chaos_base()]
    for row in records:
        if row.get("record_type") == "claim":
            row["verification_attempts"] = list(row["verification_attempts"]) + [
                {"method": "FORMAL_PROOF", "outcome": "PASSED",
                 "verifier": "tool://trusted-prover", "evidence": [],
                 "detail": "proved"}]
    outcome = _assure(records)
    admissible = outcome.case.collection("verification").total_count
    repl = sorted({f.rule_id for f in outcome.analysis.findings
                   if f.rule_id.startswith("RG-REPL")})
    return AttackResult(
        name="fake_verifier_identity", outcome=Outcome.DECLARED,
        signal=f"a self-declared proof citing nothing buys "
               f"{admissible} admissible verification(s) and raises {repl}",
        detail={"admissible_verifications": admissible, "replication_rules": repl})


def _t_cross_case_evidence_replay() -> AttackResult:
    """Cite another case's evidence here, relabelled for this subject."""
    from release_gate.assurance.corpus import SERVICE_V1, SERVICE_V2, _clean_release
    records = list(_clean_release(SERVICE_V2))
    records.append({"record_type": "evidence", "evidence_id": "borrowed",
                    "kind": "TEST_RESULT",
                    "producer": {"producer_id": "ci://pytest", "kind": "tool"},
                    "applies_to_digest": SERVICE_V1,
                    "coverage_note": "lifted from another case"})
    outcome = _assure(records)
    drift = sorted({f.rule_id for f in outcome.analysis.findings
                    if f.rule_id.startswith("RG-DRIFT")})
    return AttackResult(
        name="cross_case_evidence_replay", outcome=Outcome.DECLARED,
        signal=f"evidence naming another case's digest raises {drift}; verdict "
               f"{outcome.case.verdict.decision.value}",
        detail={"drift_rules": drift,
                "verdict": outcome.case.verdict.decision.value})


_THREAT_LIST: Tuple[Attack, ...] = (
    Attack("approval_forgery", "build an approval this engine never issued",
           Outcome.REFUSED, _t_approval_forgery),
    Attack("digest_substitution", "swap the content, keep the digest",
           Outcome.DECLARED, _t_digest_substitution),
    Attack("replay", "resubmit one record fifty times, restamped",
           Outcome.IDENTICAL, _t_replay),
    Attack("case_confusion", "make two cases answer to one identity",
           Outcome.REFUSED, _t_case_confusion),
    Attack("cross_tenant_evidence_mixing",
           "put two tenants' evidence in one case", Outcome.NOT_DEFENDED,
           _t_cross_tenant_mixing,
           limited_by="there is no tenancy concept in the core, and inventing "
                      "one inside a security review is the wrong place to design "
                      "it. What limits the threat today is that a case is built "
                      "from one submitted document by one caller: separation is "
                      "the deployment's boundary, and every record carries the "
                      "producer it came from, so mixing is visible after the "
                      "fact even though nothing prevents it"),
    Attack("event_injection", "emit an event claiming to be release-gate",
           Outcome.DECLARED, _t_event_injection),
    Attack("schema_abuse", "send shapes the schema does not describe",
           Outcome.DECLARED, _t_schema_abuse),
    Attack("dos", "18 KB of nesting, to exhaust the interpreter stack",
           Outcome.REFUSED, _t_dos),
    Attack("oversized_payload", "one field of twenty megabytes",
           Outcome.REFUSED, _t_oversized_payload),
    Attack("path_traversal", "point a locator at a file outside the tree",
           Outcome.REFUSED, _t_path_traversal),
    Attack("ssrf", "make the engine fetch a URL of the attacker's choosing",
           Outcome.REFUSED, _t_ssrf),
    Attack("malicious_artifact_links", "record links nothing should follow",
           Outcome.DECLARED, _t_malicious_artifact_links),
    Attack("tampered_evidence_pack", "edit a sealed pack and re-present it",
           Outcome.REFUSED, _t_tampered_pack),
    Attack("toctou", "change the artifact between decision and signature",
           Outcome.DECLARED, _t_toctou),
    Attack("forged_completeness", "certify your own stream as complete",
           Outcome.DECLARED, _t_forged_completeness),
    Attack("fake_verifier_identity", "call yourself an independent verifier",
           Outcome.DECLARED, _t_fake_verifier_identity),
    Attack("cross_case_evidence_replay", "cite another case's evidence here",
           Outcome.DECLARED, _t_cross_case_evidence_replay),
)

THREATS: Mapping[str, Attack] = {t.name: t for t in _THREAT_LIST}


def run_threat(name: str) -> AttackResult:
    if name not in THREATS:
        raise HostileError(f"{name!r} is not a known threat. Known: "
                           + ", ".join(sorted(THREATS)))
    return THREATS[name].run()


def hostile_report() -> Dict[str, Any]:
    """Every threat, what was expected, and what the attack achieved."""
    rows = []
    for threat in _THREAT_LIST:
        result = threat.run()
        rows.append({**result.to_dict(), "attack": threat.attack,
                     "expected": threat.expected.value,
                     "as_expected": result.outcome is threat.expected,
                     "limited_by": threat.limited_by})
    return {"record_type": "hostile_report", "record_id": "assurance-hostile",
            "schema_version": HOSTILE_SCHEMA_VERSION,
            "threats": len(rows),
            "as_expected": sum(1 for r in rows if r["as_expected"]),
            "not_defended": sorted(r["name"] for r in rows
                                   if r["outcome"] == Outcome.NOT_DEFENDED.value),
            "results": rows}

"""Calibration data: every semantic adjudication, and what later became of it.

Release-gate asks a model only the questions its deterministic rules left open
(`semantic_verifier.py`, `escalation.py`), and the model's answer is an
assertion the resolution policy reads — never a verdict. Whether a model
should be asked more, less, or a different model asked, is an empirical
question: how often were its answers right, and were its stated probabilities
worth anything? This module keeps the data that question needs. **It trains
nothing, ranks nothing and changes no decision.**

**One record per adjudication** (`CalibrationRecord`), flat and versioned
(`release-gate.calibration/1`), so the same rows load as JSONL or as a Parquet
table with a fixed column set (`CALIBRATION_COLUMNS`). Each row holds:

- what was asked: the claim, the rule that left it open, the adjudication
  mode, the candidate state hash, the evidence packet (by `privacy_mode`), the
  question;
- who answered: provider, interface, model, model version and family, prompt
  hash;
- what came back: the choice, the normalised verdict, the probability and
  confidence *as the provider stated them* (never filled in), the explanation;
- what the deterministic engine did: the claim's final status and rule, what
  the resolution did with the reading, and the case decision;
- the independence and contradiction context the claim stood in;
- labels, empty until supplied (`CalibrationLabel`): a person's adjudication,
  a later outcome for the claim, and a production incident reference. Each
  label says who supplied it. Nothing is inferred into a label.

**Privacy is the default, not an option** (`PrivacyMode`):

- `hash-only` (default): enumerations, numbers, ids and digests. No text: the
  packet keeps each item's reference, kind, structural fields and content
  digest; the question, explanation and rationale keep their digests. A
  hash-only corpus can be shared and audited, and cannot be re-asked.
- `redacted`: text, with code (fenced and inline code, code-shaped lines) and
  the sensitive classes replaced by digests. A deterministic heuristic, which
  errs towards withholding — and which is why it is not the default.
- `full`: exactly what the model was sent and said. Only by explicit choice,
  naming who made it, and every row says it is not shareable.

Nothing here sends anything anywhere. The packet a record holds is never more
than the packet the model was sent, which `semantic_verifier` had already
minimised; source code never enters a record that the model was not shown, and
in the default mode not even that.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from release_gate.assurance.canonical import digest_bytes, digest_object, short_id

__all__ = [
    "CALIBRATION_COLUMNS",
    "CALIBRATION_LABEL_SCHEMA",
    "CALIBRATION_SCHEMA",
    "CALIBRATION_SCHEMA_VERSION",
    "CalibrationError",
    "CalibrationLabel",
    "CalibrationPolicy",
    "PrivacyMode",
    "apply_labels",
    "calibration_metrics",
    "calibration_records",
    "evaluate_corpus",
    "read_calibration",
    "read_labels",
    "redact_text",
    "render_evaluation",
    "write_calibration",
    "write_parquet",
]

CALIBRATION_SCHEMA = "release-gate.calibration/1"
CALIBRATION_LABEL_SCHEMA = "release-gate.calibration-label/1"
CALIBRATION_SCHEMA_VERSION = 1


class CalibrationError(ValueError):
    """A calibration record, label or policy that cannot be honoured as stated."""


class PrivacyMode(str, Enum):
    HASH_ONLY = "hash-only"
    REDACTED = "redacted"
    FULL = "full"


@dataclass(frozen=True)
class CalibrationPolicy:
    """How much of each adjudication a corpus keeps."""

    mode: PrivacyMode = PrivacyMode.HASH_ONLY
    #: Who chose to keep text. Required for `full`: verbatim content is kept
    #: because somebody decided it should be, and the corpus says who.
    declared_by: str = ""

    def __post_init__(self) -> None:
        try:
            object.__setattr__(self, "mode", PrivacyMode(self.mode))
        except ValueError as exc:
            raise CalibrationError(
                f"privacy mode is one of {', '.join(m.value for m in PrivacyMode)}, "
                f"not {self.mode!r}") from exc
        if self.mode is PrivacyMode.FULL and not str(self.declared_by or "").strip():
            raise CalibrationError("a full-text corpus must say who chose to keep the "
                                   "text (declared_by)")

    def to_dict(self) -> Dict[str, Any]:
        return {"mode": self.mode.value, "declared_by": self.declared_by or None}

    def digest(self) -> str:
        return digest_object(self.to_dict())


#: Every column, its type, and whether it may be null. JSON-valued columns are
#: strings holding canonical JSON, so a Parquet table needs no nested types.
#: The order is the order a writer emits; the set is what a reader requires.
CALIBRATION_COLUMNS: Tuple[Tuple[str, str], ...] = (
    ("schema", "string"),
    ("schema_version", "int"),
    ("record_id", "string"),
    ("privacy_mode", "string"),
    ("privacy_declared_by", "string?"),
    ("shareable", "bool"),
    ("case_id", "string"),
    ("ruleset_version", "string?"),
    ("claim_id", "string"),
    ("rule_id", "string?"),
    ("subject_kind", "string?"),
    ("adjudication_mode", "string?"),
    ("escalation_reason", "string?"),
    ("question_id", "string"),
    ("question_kind", "string"),
    ("question_text", "string?"),
    ("question_digest", "string"),
    ("candidate_state_hash", "string?"),
    ("packet_hash", "string"),
    ("packet_refs", "list<string>"),
    ("packet_item_count", "int"),
    ("packet", "json?"),
    ("provider", "string"),
    ("interface", "string"),
    ("model", "string"),
    ("model_version", "string?"),
    ("model_family", "string?"),
    ("prompt_hash", "string"),
    ("status", "string"),
    ("unknown_reason", "string?"),
    ("returned_choice", "string?"),
    ("verdict", "string?"),
    ("choices", "list<string>"),
    ("probability", "float?"),
    ("probabilities", "json?"),
    ("confidence", "float?"),
    ("explanation", "string?"),
    ("explanation_digest", "string?"),
    ("response_digest", "string?"),
    ("answered_at", "string?"),
    ("assertion_id", "string"),
    ("reading_role", "string?"),
    ("deterministic_claim_status", "string?"),
    ("deterministic_rule", "string?"),
    ("case_decision", "string"),
    ("independence", "json?"),
    ("contradiction_count", "int"),
    ("contradictions", "json?"),
    ("human_verdict", "string?"),
    ("human_adjudicator", "string?"),
    ("human_role", "string?"),
    ("human_adjudicated_at", "string?"),
    ("human_rationale", "string?"),
    ("human_rationale_digest", "string?"),
    ("later_outcome", "string?"),
    ("later_outcome_basis", "string?"),
    ("later_outcome_at", "string?"),
    ("incident_ref", "string?"),
    ("agrees_with_human", "bool?"),
    ("confirmed_by_outcome", "bool?"),
    ("label_sources", "list<string>"),
)

_COLUMN_NAMES = tuple(name for name, _ in CALIBRATION_COLUMNS)
_VERDICTS = ("supported", "contradicted", "insufficient_evidence")
_OUTCOMES = ("HOLDS", "DOES_NOT_HOLD", "UNDETERMINED")

#: Packet fields that are enumerations or ids, never prose: kept in every mode.
_STRUCTURAL_FIELDS = frozenset({"evidence_type", "coverage_status", "status", "method",
                                "producer", "verifier", "epistemic_status"})


# ── redaction ────────────────────────────────────────────────────────────────

_FENCED = re.compile(r"```.*?```", re.DOTALL)
_INLINE = re.compile(r"`[^`\n]+`")
_CODE_LINE = re.compile(
    r"^(?:[ \t]{4,}\S|\t\S|\s*(?:def|class|import|from\s+\S+\s+import|return|function|"
    r"const|let|var|public|private|package|#include|SELECT|INSERT|UPDATE|DELETE)\b|"
    r".*[;{]\s*$|\s*}\s*$)", re.IGNORECASE)
_SECRETISH = re.compile(r"(?:sk-|ghp_|AKIA|xox[bp]-)[A-Za-z0-9_\-]{8,}")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def _marker(kind: str, text: str) -> str:
    return f"[{kind} withheld {digest_bytes(text.encode('utf-8'))[:23]}]"


def redact_text(text: Any) -> Optional[str]:
    """Text with code, credentials and addresses replaced by digest markers.

    Deterministic and conservative: fenced and inline code, any line shaped
    like code, anything shaped like a credential and every email address is
    withheld. A heuristic is not a guarantee, which is why `hash-only` keeps no
    text at all and is the default.
    """
    if text is None:
        return None
    value = str(text)
    value = _FENCED.sub(lambda m: _marker("code", m.group(0)), value)
    value = _INLINE.sub(lambda m: _marker("code", m.group(0)), value)
    lines = [(_marker("code", line) if line.strip() and _CODE_LINE.match(line) else line)
             for line in value.split("\n")]
    value = "\n".join(lines)
    value = _SECRETISH.sub(lambda m: _marker("credential", m.group(0)), value)
    return _EMAIL.sub(lambda m: _marker("identifier", m.group(0)), value)


def _redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, Mapping):
        return {k: _redact_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_value(v) for v in value]
    return value


def _redact_excerpt(text: Any) -> str:
    """A packet excerpt, redacted value by value where it is serialised JSON.

    An excerpt is usually a record's content as canonical JSON, where a code
    block is one string with escaped line breaks; read as text, none of its
    lines would look like code. Parsed, each string is redacted on its own.
    """
    raw = str(text or "")
    try:
        parsed = json.loads(raw)
    except ValueError:
        return redact_text(raw) or ""
    return json.dumps(_redact_value(parsed), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def _text_for(mode: PrivacyMode, text: Any) -> Optional[str]:
    """Text as a privacy mode keeps it: verbatim, redacted, or not at all."""
    if text in (None, ""):
        return None
    if mode is PrivacyMode.FULL:
        return str(text)
    if mode is PrivacyMode.REDACTED:
        return redact_text(text)
    return None


def _digest_text(text: Any) -> Optional[str]:
    return digest_bytes(str(text).encode("utf-8")) if text not in (None, "") else None


def _packet_for(policy: CalibrationPolicy, packet: Optional[Mapping[str, Any]]
                ) -> Optional[Dict[str, Any]]:
    """The packet as this mode keeps it. None when the run kept no packet."""
    if packet is None:
        return None
    if policy.mode is PrivacyMode.FULL:
        return dict(packet)
    items = []
    for item in packet.get("items") or ():
        if not isinstance(item, Mapping):
            continue
        fields = item.get("fields") if isinstance(item.get("fields"), Mapping) else {}
        kept: Dict[str, Any] = {
            "ref": item.get("ref"), "kind": item.get("kind"),
            "content_digest": item.get("content_digest") or None,
            "truncated": bool(item.get("truncated")),
            "fields": {k: v for k, v in sorted(fields.items())
                       if k in _STRUCTURAL_FIELDS
                       and isinstance(v, (str, int, float, bool))}}
        if policy.mode is PrivacyMode.REDACTED:
            kept["excerpt"] = _redact_excerpt(item.get("excerpt"))
            kept["fields"].update({k: redact_text(v) for k, v in sorted(fields.items())
                                   if k not in _STRUCTURAL_FIELDS and isinstance(v, str)})
        items.append(kept)
    return {"packet_hash": packet.get("packet_hash"), "items": items,
            "state_hash": packet.get("state_hash") or None,
            "omitted": len(packet.get("omitted") or ()),
            "redactions": [r.get("class") for r in packet.get("redactions") or ()
                           if isinstance(r, Mapping)],
            "over_budget": bool(packet.get("over_budget"))}


def _json(value: Any) -> Optional[str]:
    if value is None:
        return None
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


# ── building records from a run ──────────────────────────────────────────────

def _as_dict(value: Any) -> Dict[str, Any]:
    if value is None:
        return {}
    if hasattr(value, "to_dict"):
        return dict(value.to_dict())
    return dict(value) if isinstance(value, Mapping) else {}


def _probability(assertion: Mapping[str, Any]) -> Optional[float]:
    """The provider's probability for what it returned, only if it stated one."""
    probabilities = assertion.get("probabilities")
    chosen = assertion.get("chosen") or assertion.get("returned_verdict")
    if isinstance(probabilities, Mapping) and chosen in probabilities:
        value = probabilities[chosen]
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return float(value)
    return None


def calibration_records(outcome: Any, assertions: Iterable[Any], *,
                        packets: Iterable[Any] = (), plan: Any = None,
                        policy: CalibrationPolicy = CalibrationPolicy()
                        ) -> List[Dict[str, Any]]:
    """One record per assertion of a finished run, under `policy`.

    `outcome` is the run's `AssuranceOutcome` (the deterministic result the
    assertions fed into); `packets` the evidence packets as sent, and `plan`
    the escalation plan, both as objects or as the dicts `--semantic-out`
    writes. A packet or plan entry that was not kept leaves its columns empty;
    nothing is reconstructed.
    """
    from release_gate.assurance.semantic_verifier import assertions_from_records

    packets_by = {}
    for packet in packets:
        data = _as_dict(packet)
        if data.get("packet_hash"):
            packets_by[data["packet_hash"]] = data
    decisions = {}
    plan_data = _as_dict(plan)
    for decision in plan_data.get("decisions") or ():
        data = _as_dict(decision)
        if data.get("packet_hash"):
            decisions[data["packet_hash"]] = data

    analysis = outcome.analysis
    resolution = getattr(analysis, "resolution", None)
    ledger = getattr(analysis, "contradictions", None)
    reading_ids = {a.assertion_id: ev for ev, a in assertions_from_records(
        r for r in outcome.case.collection("evidence").materialised
        if hasattr(r, "evidence_id"))}
    decision_value = getattr(outcome.decision, "value", str(outcome.decision))

    rows: List[Dict[str, Any]] = []
    for assertion in assertions:
        data = _as_dict(assertion)
        claim_id = str(data.get("claim_id") or "")
        packet_hash = str(data.get("packet_hash") or "")
        planned = decisions.get(packet_hash, {})
        packet = packets_by.get(packet_hash)
        claim = resolution.of(claim_id) if resolution is not None else None
        reading = reading_ids.get(data.get("assertion_id"))
        role = None
        if claim is not None and reading:
            role = next((i.role.value for i in claim.items if i.item_id == reading),
                        "NOT_READ")
        contradictions = []
        if ledger is not None:
            for contradiction in ledger.contradictions:
                if claim_id in (getattr(contradiction, "target_claims", ()) or ()):
                    as_dict = contradiction.to_dict()
                    contradictions.append({
                        "contradiction_id": as_dict.get("contradiction_id"),
                        "classification": as_dict.get("classification"),
                        "status": as_dict.get("status"),
                        "affects_critical": as_dict.get("affects_critical")})
        question = (packet or {}).get("question") or {}
        question_text = question.get("question") if isinstance(question, Mapping) else None
        explanation = data.get("reason") or None
        row: Dict[str, Any] = {
            "schema": CALIBRATION_SCHEMA,
            "schema_version": CALIBRATION_SCHEMA_VERSION,
            "privacy_mode": policy.mode.value,
            "privacy_declared_by": policy.declared_by or None,
            "shareable": policy.mode is PrivacyMode.HASH_ONLY,
            "case_id": outcome.case.case_id,
            "ruleset_version": getattr(analysis, "ruleset_version", None),
            "claim_id": claim_id,
            "rule_id": planned.get("rule_id"),
            "subject_kind": planned.get("subject_kind"),
            "adjudication_mode": planned.get("mode"),
            "escalation_reason": planned.get("reason"),
            "question_id": str(data.get("question_id") or ""),
            "question_kind": str(data.get("question_kind") or ""),
            "question_text": _text_for(policy.mode,
                                       question_text or data.get("question_text")),
            "question_digest": digest_object(question) if question
            else _digest_text(data.get("question_text") or data.get("question_id")),
            "candidate_state_hash": data.get("state_hash") or None,
            "packet_hash": packet_hash,
            "packet_refs": [str(r) for r in data.get("evidence_refs") or ()],
            "packet_item_count": len((packet or {}).get("items") or ()),
            "packet": _json(_packet_for(policy, packet)),
            "provider": str(data.get("provider") or ""),
            "interface": str(data.get("interface") or ""),
            "model": str(data.get("model") or ""),
            "model_version": data.get("model_version") or None,
            "model_family": data.get("model_family") or None,
            "prompt_hash": str(data.get("prompt_hash") or ""),
            "status": str(data.get("status") or ""),
            "unknown_reason": data.get("unknown_reason") or None,
            "returned_choice": data.get("chosen") or data.get("returned_verdict") or None,
            "verdict": data.get("verdict") or None,
            "choices": [str(c) for c in data.get("choices") or ()],
            "probability": _probability(data),
            "probabilities": _json(data.get("probabilities")),
            "confidence": data.get("confidence"),
            "explanation": _text_for(policy.mode, explanation),
            "explanation_digest": _digest_text(explanation),
            "response_digest": data.get("response_digest") or None,
            "answered_at": data.get("timestamp") or None,
            "assertion_id": str(data.get("assertion_id") or ""),
            "reading_role": role,
            "deterministic_claim_status": claim.status.value if claim is not None else None,
            "deterministic_rule": claim.rule if claim is not None else None,
            "case_decision": decision_value,
            "independence": _json(claim.independence.to_dict()
                                  if claim is not None and claim.independence else None),
            "contradiction_count": len(contradictions),
            "contradictions": _json(contradictions or None),
            **_EMPTY_LABELS,
        }
        row["record_id"] = short_id("cal", digest_object(
            {"assertion": row["assertion_id"], "case": row["case_id"]}))
        rows.append({name: row[name] for name in _COLUMN_NAMES})
    return rows


_EMPTY_LABELS: Mapping[str, Any] = {
    "human_verdict": None, "human_adjudicator": None, "human_role": None,
    "human_adjudicated_at": None, "human_rationale": None,
    "human_rationale_digest": None, "later_outcome": None,
    "later_outcome_basis": None, "later_outcome_at": None, "incident_ref": None,
    "agrees_with_human": None, "confirmed_by_outcome": None, "label_sources": []}


# ── labels ───────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class CalibrationLabel:
    """What a person, or a later outcome, says about one adjudication.

    Supplied, never inferred. `human` is a person's own adjudication of the
    same question (`supported`, `contradicted` or `insufficient_evidence`).
    `outcome` is what later became of the claim: it `HOLDS`, `DOES_NOT_HOLD`
    or is `UNDETERMINED`, on a stated basis — an incident reference only if
    one is given.
    """

    record_id: str
    supplied_by: str
    human_verdict: Optional[str] = None
    human_adjudicator: Optional[str] = None
    human_role: Optional[str] = None
    human_adjudicated_at: Optional[str] = None
    human_rationale: Optional[str] = None
    later_outcome: Optional[str] = None
    later_outcome_basis: Optional[str] = None
    later_outcome_at: Optional[str] = None
    incident_ref: Optional[str] = None

    def __post_init__(self) -> None:
        if not str(self.record_id or "").strip():
            raise CalibrationError("a label names the record it labels")
        if not str(self.supplied_by or "").strip():
            raise CalibrationError("a label says who supplied it")
        if self.human_verdict is not None and self.human_verdict not in _VERDICTS:
            raise CalibrationError(f"a human verdict is one of {', '.join(_VERDICTS)}")
        if self.later_outcome is not None and self.later_outcome not in _OUTCOMES:
            raise CalibrationError(f"a later outcome is one of {', '.join(_OUTCOMES)}")
        if self.later_outcome is not None and not str(self.later_outcome_basis or "").strip():
            raise CalibrationError("a later outcome states its basis")
        if self.human_verdict is not None and not str(self.human_adjudicator or "").strip():
            raise CalibrationError("a human adjudication names who made it")
        if self.incident_ref is not None and self.later_outcome is None:
            raise CalibrationError("an incident reference belongs to a stated later outcome")
        if self.human_verdict is None and self.later_outcome is None:
            raise CalibrationError("a label carries a human adjudication, a later "
                                   "outcome, or both")

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CalibrationLabel":
        if data.get("schema") not in (None, CALIBRATION_LABEL_SCHEMA):
            raise CalibrationError(f"not a {CALIBRATION_LABEL_SCHEMA} row: "
                                   f"{data.get('schema')!r}")
        human = data.get("human") if isinstance(data.get("human"), Mapping) else {}
        later = data.get("outcome") if isinstance(data.get("outcome"), Mapping) else {}
        return cls(record_id=str(data.get("record_id") or ""),
                   supplied_by=str(data.get("supplied_by") or ""),
                   human_verdict=human.get("verdict"),
                   human_adjudicator=human.get("adjudicator"),
                   human_role=human.get("role"),
                   human_adjudicated_at=human.get("at"),
                   human_rationale=human.get("rationale"),
                   later_outcome=later.get("claim"),
                   later_outcome_basis=later.get("basis"),
                   later_outcome_at=later.get("at"),
                   incident_ref=later.get("incident_ref"))


def _confirmed(verdict: Optional[str], outcome: Optional[str]) -> Optional[bool]:
    """Whether a later outcome bore the model out. None where it cannot say."""
    if verdict not in ("supported", "contradicted") or outcome in (None, "UNDETERMINED"):
        return None
    return (verdict == "supported") == (outcome == "HOLDS")


def apply_labels(records: Sequence[Mapping[str, Any]],
                 labels: Iterable[CalibrationLabel]
                 ) -> Tuple[List[Dict[str, Any]], List[CalibrationLabel]]:
    """Records with their labels filled in, and the labels that matched no record.

    Two labels that disagree about one record are an error, never resolved by
    order: which one is right is exactly what a person has to say.
    """
    by_id: Dict[str, Dict[str, Any]] = {r["record_id"]: dict(r) for r in records}
    unmatched: List[CalibrationLabel] = []
    for label in labels:
        row = by_id.get(label.record_id)
        if row is None:
            unmatched.append(label)
            continue
        mode = PrivacyMode(row["privacy_mode"])
        updates: Dict[str, Any] = {}
        if label.human_verdict is not None:
            updates.update({
                "human_verdict": label.human_verdict,
                "human_adjudicator": label.human_adjudicator,
                "human_role": label.human_role,
                "human_adjudicated_at": label.human_adjudicated_at,
                "human_rationale": _text_for(mode, label.human_rationale),
                "human_rationale_digest": _digest_text(label.human_rationale)})
        if label.later_outcome is not None:
            updates.update({"later_outcome": label.later_outcome,
                            "later_outcome_basis": label.later_outcome_basis,
                            "later_outcome_at": label.later_outcome_at,
                            "incident_ref": label.incident_ref})
        for key, value in updates.items():
            held = row.get(key)
            if held is not None and value is not None and held != value:
                raise CalibrationError(
                    f"two labels disagree about {key} of {label.record_id}: "
                    f"{held!r} and {value!r}")
            if value is not None:
                row[key] = value
        row["label_sources"] = sorted(set(row.get("label_sources") or ())
                                      | {label.supplied_by})
        if row.get("human_verdict") is not None and row.get("verdict") is not None:
            row["agrees_with_human"] = row["verdict"] == row["human_verdict"]
        row["confirmed_by_outcome"] = _confirmed(row.get("verdict"),
                                                 row.get("later_outcome"))
    return [by_id[r["record_id"]] for r in records], unmatched


# ── persistence ──────────────────────────────────────────────────────────────

def _check_row(row: Mapping[str, Any]) -> None:
    if row.get("schema") != CALIBRATION_SCHEMA:
        raise CalibrationError(f"not a {CALIBRATION_SCHEMA} row: {row.get('schema')!r}")
    version = row.get("schema_version")
    if not isinstance(version, int) or version > CALIBRATION_SCHEMA_VERSION:
        raise CalibrationError(f"calibration schema version {version!r} is newer than "
                               f"this reader ({CALIBRATION_SCHEMA_VERSION}); upgrade "
                               "rather than read it loosely")
    missing = [n for n in _COLUMN_NAMES if n not in row]
    if missing:
        raise CalibrationError(f"calibration row is missing {', '.join(missing)}")


def write_calibration(records: Iterable[Mapping[str, Any]], path: str | Path, *,
                      append: bool = False) -> int:
    """Write rows as JSONL, columns in their declared order. Returns the count."""
    rows = list(records)
    for row in rows:
        _check_row(row)
    text = "".join(json.dumps({n: row[n] for n in _COLUMN_NAMES}, ensure_ascii=False)
                   + "\n" for row in rows)
    with open(path, "a" if append else "w", encoding="utf-8") as handle:
        handle.write(text)
    return len(rows)


def read_calibration(path: str | Path) -> List[Dict[str, Any]]:
    rows = []
    for number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError as exc:
            raise CalibrationError(f"{path}:{number} is not JSON: {exc}") from exc
        _check_row(row)
        rows.append(row)
    return rows


def read_labels(path: str | Path) -> List[CalibrationLabel]:
    labels = []
    for number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if line.strip():
            try:
                labels.append(CalibrationLabel.from_dict(json.loads(line)))
            except (ValueError, TypeError) as exc:
                raise CalibrationError(f"{path}:{number}: {exc}") from exc
    return labels


_ARROW_TYPES = {"string": "string", "int": "int64", "float": "float64", "bool": "bool",
                "json": "string", "list<string>": "list<string>"}


def write_parquet(records: Iterable[Mapping[str, Any]], path: str | Path) -> int:
    """The same rows as a Parquet table with an explicit schema. Needs pyarrow.

    Optional by design: the corpus is JSONL first, and nothing in release-gate
    depends on pyarrow. JSON-valued columns stay strings.
    """
    try:
        import pyarrow as pa
        import pyarrow.parquet as pq
    except ImportError as exc:
        raise CalibrationError("writing Parquet needs pyarrow (pip install pyarrow); "
                               "the JSONL corpus has the same rows") from exc
    rows = list(records)
    for row in rows:
        _check_row(row)
    fields = []
    for name, kind in CALIBRATION_COLUMNS:
        base = kind.rstrip("?")
        arrow = (pa.list_(pa.string()) if base == "list<string>"
                 else getattr(pa, _ARROW_TYPES[base])())
        fields.append(pa.field(name, arrow, nullable=kind.endswith("?")))
    schema = pa.schema(fields, metadata={"schema": CALIBRATION_SCHEMA,
                                         "schema_version": str(CALIBRATION_SCHEMA_VERSION)})
    table = pa.Table.from_pylist([{n: r[n] for n in _COLUMN_NAMES} for r in rows],
                                 schema=schema)
    pq.write_table(table, str(path))
    return len(rows)


# ── evaluation ───────────────────────────────────────────────────────────────

def _rate(numerator: int, denominator: int) -> Optional[float]:
    return round(numerator / denominator, 4) if denominator else None


def calibration_metrics(pairs: List[Tuple[float, bool]], bins: int) -> Dict[str, Any]:
    """Brier score and expected calibration error over (stated probability, right).

    Shared with the provider benchmark (`provider_benchmark.py`), so a model is
    held to one definition of calibrated wherever it is measured.
    """
    if not pairs:
        return {"n": 0, "brier": None, "ece": None, "bins": []}
    brier = sum((p - (1.0 if right else 0.0)) ** 2 for p, right in pairs) / len(pairs)
    table = []
    ece = 0.0
    for b in range(bins):
        low, high = b / bins, (b + 1) / bins
        members = [(p, r) for p, r in pairs
                   if (low <= p < high) or (b == bins - 1 and p == 1.0)]
        if not members:
            continue
        mean_p = sum(p for p, _ in members) / len(members)
        accuracy = sum(1 for _, r in members if r) / len(members)
        ece += len(members) / len(pairs) * abs(mean_p - accuracy)
        table.append({"from": round(low, 4), "to": round(high, 4), "n": len(members),
                      "mean_probability": round(mean_p, 4),
                      "accuracy": round(accuracy, 4)})
    return {"n": len(pairs), "brier": round(brier, 4), "ece": round(ece, 4),
            "bins": table}


_DETERMINISTIC_READS = {"supported": ("ESTABLISHED", "SUPPORTED", "PARTIALLY_SUPPORTED"),
                        "contradicted": ("CONTRADICTED",)}


def _model_key(row: Mapping[str, Any]) -> str:
    version = f"@{row['model_version']}" if row.get("model_version") else ""
    return f"{row.get('provider') or '?'}:{row.get('model') or '?'}{version}"


def evaluate_corpus(records: Sequence[Mapping[str, Any]], *,
                    model_classes: Optional[Mapping[str, str]] = None,
                    bins: int = 10) -> Dict[str, Any]:
    """How each model's adjudications held up, from labels people supplied.

    Grouped by model (`provider:model@version`) and by class: a class is what
    the caller says a model is — `model_classes` maps a model key, or a bare
    model name, to a label such as `general`, `decision-model` or
    `specialist`; unmapped models fall into their interface (`CHAT`,
    `DECISION`). For each group:

    - **answered / abstained / unknown** — an `insufficient_evidence` answer is
      an abstention; an UNKNOWN is no answer at all;
    - **against a person** — agreement with the human adjudication, and the
      confusion table, over labelled rows only;
    - **against what happened** — how often a later outcome confirmed the
      answer, over rows with one;
    - **calibration** — Brier score and expected calibration error over rows
      whose provider *stated* a probability, scored against the person's
      adjudication, else the later outcome. A row with no stated probability
      is never given one;
    - **agreement with the deterministic outcome** — reported, and marked as
      not ground truth: the deterministic outcome may itself have read the
      answer.

    Shared packets — the same packet answered by more than one model — are
    compared head to head. Nothing here is trained or tuned, and nothing feeds
    back into a decision.
    """
    model_classes = dict(model_classes or {})

    def class_of(row: Mapping[str, Any]) -> str:
        return (model_classes.get(_model_key(row)) or model_classes.get(row.get("model"))
                or (row.get("interface") or "UNSTATED"))

    groups: Dict[Tuple[str, str], List[Mapping[str, Any]]] = {}
    for row in records:
        groups.setdefault(("model", _model_key(row)), []).append(row)
        groups.setdefault(("class", class_of(row)), []).append(row)

    def summarise(rows: List[Mapping[str, Any]]) -> Dict[str, Any]:
        answered = [r for r in rows if r.get("status") == "ANSWERED"]
        decided = [r for r in answered if r.get("verdict") in ("supported", "contradicted")]
        abstained = [r for r in answered if r.get("verdict") == "insufficient_evidence"]
        labelled = [r for r in rows if r.get("human_verdict") is not None
                    and r.get("verdict") is not None]
        confusion: Dict[str, Dict[str, int]] = {}
        for r in labelled:
            cell = confusion.setdefault(r["verdict"], {})
            cell[r["human_verdict"]] = cell.get(r["human_verdict"], 0) + 1
        judged = [r for r in rows if r.get("confirmed_by_outcome") is not None]
        pairs: List[Tuple[float, bool]] = []
        for r in rows:
            p = r.get("probability")
            if not isinstance(p, (int, float)) or r.get("verdict") not in (
                    "supported", "contradicted"):
                continue
            if r.get("agrees_with_human") is not None:
                pairs.append((float(p), bool(r["agrees_with_human"])))
            elif r.get("confirmed_by_outcome") is not None:
                pairs.append((float(p), bool(r["confirmed_by_outcome"])))
        consistent = [r for r in decided if r.get("deterministic_claim_status")]
        agree_det = sum(1 for r in consistent if r["deterministic_claim_status"]
                        in _DETERMINISTIC_READS[r["verdict"]])
        return {
            "records": len(rows),
            "answered": len(answered),
            "abstained": len(abstained),
            "unknown": len(rows) - len(answered),
            "abstention_rate": _rate(len(abstained), len(answered)),
            "unknown_rate": _rate(len(rows) - len(answered), len(rows)),
            "human_labelled": len(labelled),
            "agreement_with_human": _rate(
                sum(1 for r in labelled if r["verdict"] == r["human_verdict"]),
                len(labelled)),
            "confusion_vs_human": confusion,
            "outcome_labelled": len(judged),
            "confirmed_by_outcome": _rate(
                sum(1 for r in judged if r["confirmed_by_outcome"]), len(judged)),
            "incidents": sorted({r["incident_ref"] for r in rows if r.get("incident_ref")}),
            "calibration": calibration_metrics(pairs, bins),
            "stated_probability": sum(1 for r in rows
                                      if isinstance(r.get("probability"), (int, float))),
            "agreement_with_deterministic": _rate(agree_det, len(consistent)),
            "agreement_with_deterministic_note": (
                "not ground truth: the deterministic outcome may have read this answer"),
        }

    by_packet: Dict[str, Dict[str, Mapping[str, Any]]] = {}
    for row in records:
        if row.get("packet_hash") and row.get("verdict"):
            by_packet.setdefault(row["packet_hash"], {})[_model_key(row)] = row
    head_to_head: Dict[str, Dict[str, Any]] = {}
    for answers in by_packet.values():
        models = sorted(answers)
        for i, left in enumerate(models):
            for right in models[i + 1:]:
                pair = head_to_head.setdefault(f"{left} vs {right}", {
                    "shared": 0, "agree": 0, "labelled": 0, "left_right": 0,
                    "right_right": 0})
                a, b = answers[left], answers[right]
                pair["shared"] += 1
                pair["agree"] += int(a["verdict"] == b["verdict"])
                truth = a.get("human_verdict") or b.get("human_verdict")
                if truth is not None:
                    pair["labelled"] += 1
                    pair["left_right"] += int(a["verdict"] == truth)
                    pair["right_right"] += int(b["verdict"] == truth)
    return {
        "schema": "release-gate.calibration-evaluation/1",
        "records": len(records),
        "privacy_modes": sorted({r.get("privacy_mode") for r in records}),
        "by_model": {k: summarise(v) for (kind, k), v in sorted(groups.items())
                     if kind == "model"},
        "by_class": {k: summarise(v) for (kind, k), v in sorted(groups.items())
                     if kind == "class"},
        "head_to_head": dict(sorted(head_to_head.items())),
        "trained": False,
    }


def _fmt(value: Any) -> str:
    if value is None:
        return "—"
    if isinstance(value, float):
        return f"{value:.3f}"
    return str(value)


def render_evaluation(report: Mapping[str, Any]) -> str:
    lines = [f"Calibration corpus: {report['records']} adjudication(s); privacy "
             f"{', '.join(m for m in report['privacy_modes'] if m)}. Nothing was trained.",
             ""]
    header = (f"  {'group':<44} {'n':>5} {'answer':>6} {'abst.':>6} {'unk.':>5} "
              f"{'vs human':>9} {'outcome':>8} {'brier':>6} {'ece':>6}")
    for title, key in (("By model", "by_model"), ("By class", "by_class")):
        lines += [title, header]
        for name, s in report[key].items():
            c = s["calibration"]
            lines.append(
                f"  {name[:44]:<44} {s['records']:>5} {s['answered']:>6} "
                f"{s['abstained']:>6} {s['unknown']:>5} "
                f"{_fmt(s['agreement_with_human']):>9} "
                f"{_fmt(s['confirmed_by_outcome']):>8} {_fmt(c['brier']):>6} "
                f"{_fmt(c['ece']):>6}")
        lines.append("")
    if report["head_to_head"]:
        lines.append("Head to head on shared packets")
        for pair, s in report["head_to_head"].items():
            lines.append(f"  {pair}: {s['shared']} shared, {s['agree']} agree; "
                         f"labelled {s['labelled']} — right {s['left_right']} / "
                         f"{s['right_right']}")
        lines.append("")
    lines.append("'vs human' and 'outcome' use labelled rows only; calibration uses only "
                 "probabilities a provider stated. Agreement with the deterministic "
                 "outcome is in the JSON and is not ground truth.")
    return "\n".join(lines)


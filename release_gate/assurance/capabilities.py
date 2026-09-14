"""What the system turned out to be able to do, and how well we know it.

Capability discovery answers one question — *what did this system reach for?* —
and it answers it at four different strengths, because the evidence for it
arrives at four different strengths.

The rule that shapes everything here:

> **An observed invocation with an inferred classification is INFERRED.**

Those are two independent questions and conflating them is the whole trap. *Did
we see something happen?* is answered by whether a span exists. *Do we know what
it was?* is answered by whether the telemetry named it or we guessed from a
string. A span proving `db.system=postgresql` with `db.operation=INSERT` is an
observed database write. A tool called `db_write` with no other attribute is an
observed *something* that we are guessing about, and calling that OBSERVED would
launder a naming convention into a fact.

So status is the **weaker** of the two axes, never the stronger:

| we saw it happen | we can name it | status |
|---|---|---|
| a span exists | the protocol named it | `OBSERVED_CAPABILITY` |
| a span exists | we matched its name | `INFERRED_CAPABILITY` |
| a span exists | nothing matched | `UNKNOWN_CAPABILITY` |
| only a manifest | either | `DECLARED_CAPABILITY` |

A consequence worth stating plainly: the capabilities that matter most —
payment, deployment, identity — are the ones no telemetry standard names, so
they are almost always INFERRED. This module does not fix that. It refuses to
hide it.

This is evidence, not a verdict. Nothing here BLOCKs. "The agent sent an email"
is not structurally wrong, and only a methodology can say it was not allowed.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from release_gate.assurance.canonical import digest_object

__all__ = [
    "CAPABILITY_SCHEMA_VERSION",
    "Capability",
    "CapabilityRecord",
    "CapabilitySignal",
    "CapabilityStatus",
    "CapabilitySurface",
    "Observation",
    "SignalStrength",
    "classify_tool_name",
    "declared_from_document",
]

CAPABILITY_SCHEMA_VERSION = 1


class Capability(str, Enum):
    """The capability vocabulary. Closed, because an open one cannot be compared."""

    DATABASE_READ = "DATABASE_READ"
    DATABASE_WRITE = "DATABASE_WRITE"
    FILESYSTEM = "FILESYSTEM"
    SHELL = "SHELL"
    NETWORK = "NETWORK"
    EMAIL = "EMAIL"
    PAYMENT = "PAYMENT"
    DEPLOYMENT = "DEPLOYMENT"
    CODE_MODIFICATION = "CODE_MODIFICATION"
    IDENTITY_MANAGEMENT = "IDENTITY_MANAGEMENT"
    EXTERNAL_API = "EXTERNAL_API"
    MCP = "MCP"
    UNKNOWN_TOOL = "UNKNOWN_TOOL"


class CapabilityStatus(str, Enum):
    OBSERVED_CAPABILITY = "OBSERVED_CAPABILITY"
    DECLARED_CAPABILITY = "DECLARED_CAPABILITY"
    INFERRED_CAPABILITY = "INFERRED_CAPABILITY"
    UNKNOWN_CAPABILITY = "UNKNOWN_CAPABILITY"


class SignalStrength(str, Enum):
    """How the capability was identified — the classification axis."""

    PROTOCOL = "PROTOCOL"          # a telemetry convention names it outright
    SEMANTIC = "SEMANTIC"          # a structured attribute settles it unambiguously
    NAME_PATTERN = "NAME_PATTERN"  # a string matched; this is a guess
    NONE = "NONE"                  # nothing identified it


class Observation(str, Enum):
    """How we came to know about it — the observation axis."""

    DIRECT = "DIRECT"            # execution evidence shows the invocation
    DECLARATION = "DECLARATION"  # a manifest says the system has it
    NONE = "NONE"


#: Three structural properties per capability, as `(mutating, external, subsuming)`.
#: Deliberately not a severity score: whether a mutating external effect is
#: acceptable is a domain question, and a number here would be release-gate
#: inventing a standard it does not have.
#:
#: `mutating` — exercising it changes state. `external` — the effect lands outside
#: the system under assessment. Either may be **None**, meaning the category does
#: not determine it: "filesystem" covers reading and writing alike, so the category
#: alone cannot say a read mutated anything.
#:
#: `subsuming` — exercising it can exercise *any other* capability without that
#: capability appearing separately. A shell can curl; an MCP server can expose
#: anything its author wrote. Where one of these was exercised, the surface stops
#: being an upper bound on what the system did, and `CapabilitySurface.bounded`
#: says so rather than letting a tidy list imply completeness.
_PROFILE: Mapping[Capability, Tuple[Optional[bool], Optional[bool], bool]] = {
    Capability.DATABASE_READ:       (False, False, False),
    Capability.DATABASE_WRITE:      (True,  False, False),
    Capability.FILESYSTEM:          (None,  False, False),
    Capability.SHELL:               (None,  None,  True),
    Capability.NETWORK:             (None,  True,  False),
    Capability.EMAIL:               (True,  True,  False),
    Capability.PAYMENT:             (True,  True,  False),
    Capability.DEPLOYMENT:          (True,  True,  False),
    Capability.CODE_MODIFICATION:   (True,  False, False),
    Capability.IDENTITY_MANAGEMENT: (True,  True,  False),
    Capability.EXTERNAL_API:        (None,  True,  False),
    Capability.MCP:                 (None,  True,  True),
    Capability.UNKNOWN_TOOL:        (None,  None,  True),
}

_STATUS_RANK = {
    CapabilityStatus.UNKNOWN_CAPABILITY: 0,
    CapabilityStatus.DECLARED_CAPABILITY: 1,
    CapabilityStatus.INFERRED_CAPABILITY: 2,
    CapabilityStatus.OBSERVED_CAPABILITY: 3,
}

_SIGNAL_RANK = {SignalStrength.NONE: 0, SignalStrength.NAME_PATTERN: 1,
                SignalStrength.SEMANTIC: 2, SignalStrength.PROTOCOL: 3}


def status_for(observation: Observation, strength: SignalStrength) -> CapabilityStatus:
    """The weaker of the two axes. This function is the module's thesis."""
    if observation is Observation.NONE:
        return CapabilityStatus.UNKNOWN_CAPABILITY
    if observation is Observation.DECLARATION:
        return CapabilityStatus.DECLARED_CAPABILITY
    if strength in (SignalStrength.PROTOCOL, SignalStrength.SEMANTIC):
        return CapabilityStatus.OBSERVED_CAPABILITY
    if strength is SignalStrength.NAME_PATTERN:
        return CapabilityStatus.INFERRED_CAPABILITY
    return CapabilityStatus.UNKNOWN_CAPABILITY


# ── attribute conventions ────────────────────────────────────────────────────
# OpenTelemetry semantic conventions, plus the MCP keys instrumentations emit.
# Anything that is a convention rather than a ratified standard is marked, so a
# reader can tell what the classification actually rests on.

DB_SYSTEM_KEYS = ("db.system", "db.system.name")
DB_OPERATION_KEYS = ("db.operation", "db.operation.name", "db.sql.operation")
DB_STATEMENT_KEYS = ("db.statement", "db.query.text")
HTTP_METHOD_KEYS = ("http.request.method", "http.method")
URL_KEYS = ("url.full", "http.url", "http.target")
HOST_KEYS = ("server.address", "net.peer.name", "http.host", "peer.service")
PROCESS_KEYS = ("process.command_line", "process.executable.name",
                "process.executable.path")
FILE_KEYS = ("file.path", "file.directory", "code.filepath")
MESSAGING_KEYS = ("messaging.system", "messaging.destination.name")
RPC_KEYS = ("rpc.system", "rpc.service")
MCP_KEYS = ("mcp.server.name", "mcp.tool.name", "mcp.method", "mcp.transport")
TOOL_NAME_KEYS = ("gen_ai.tool.name", "tool.name", "tool", "function.name",
                  "mcp.tool.name")

_WRITE_VERBS = frozenset({"insert", "update", "delete", "drop", "alter", "create",
                          "truncate", "merge", "upsert", "replace", "grant", "revoke"})
_READ_VERBS = frozenset({"select", "show", "describe", "explain", "with"})
_HTTP_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

_EMAIL_MESSAGING_SYSTEMS = frozenset({"ses", "aws.ses", "sendgrid", "smtp", "mailgun",
                                      "postmark", "sparkpost"})

#: Hostname fragments that suggest a capability. Always INFERRED, never OBSERVED:
#: reaching Stripe's API is an observed external call, and whether money moved is
#: a different question — a balance read looks identical from here. Kept short on
#: purpose; a long vendor list ages badly and invites false confidence.
_HOST_HINTS: Tuple[Tuple[str, Capability], ...] = (
    ("stripe.com", Capability.PAYMENT),
    ("paypal.com", Capability.PAYMENT),
    ("squareup.com", Capability.PAYMENT),
    ("adyen.com", Capability.PAYMENT),
    ("braintreegateway.com", Capability.PAYMENT),
    ("sendgrid.com", Capability.EMAIL),
    ("mailgun.net", Capability.EMAIL),
    ("postmarkapp.com", Capability.EMAIL),
)

#: Substrings matched against a tool or span name. Order matters: the first
#: capability whose pattern matches wins, so the more specific ones come first.
#: Every match here yields INFERRED — a name is a claim about behaviour, not a
#: record of it, and a tool called `safe_delete` may do anything at all.
_NAME_PATTERNS: Tuple[Tuple[Capability, Tuple[str, ...]], ...] = (
    (Capability.PAYMENT, ("payment", "pay_", "charge", "refund", "invoice", "billing",
                          "checkout", "payout", "transfer_funds", "stripe")),
    (Capability.EMAIL, ("email", "sendmail", "send_mail", "smtp", "sendgrid",
                        "mailer", "notify_user")),
    (Capability.DEPLOYMENT, ("deploy", "rollout", "release_", "helm", "kubectl",
                             "terraform", "cloudformation", "provision")),
    (Capability.IDENTITY_MANAGEMENT, ("iam", "grant_role", "revoke", "permission",
                                      "credential", "create_user", "policy_",
                                      "access_key", "issue_token")),
    (Capability.CODE_MODIFICATION, ("write_file", "edit_file", "str_replace", "patch",
                                    "apply_diff", "git_commit", "git_push", "commit_",
                                    "create_pull_request")),
    (Capability.SHELL, ("bash", "shell", "subprocess", "run_command", "exec_",
                        "execute_command", "terminal")),
    (Capability.DATABASE_WRITE, ("db_write", "insert", "update_row", "delete_row",
                                 "upsert", "migrate", "truncate", "drop_table")),
    (Capability.DATABASE_READ, ("db_read", "sql_query", "select", "query_db",
                                "fetch_rows", "read_table")),
    (Capability.FILESYSTEM, ("read_file", "list_files", "glob", "mkdir", "remove_file",
                             "filesystem", "file_")),
    (Capability.MCP, ("mcp_", "mcp.", "_mcp")),
    (Capability.NETWORK, ("http_", "fetch_url", "curl", "web_request", "download")),
    (Capability.EXTERNAL_API, ("api_call", "external_api", "call_api")),
)


def _first(attrs: Mapping[str, Any], keys: Sequence[str]) -> Optional[Any]:
    for key in keys:
        value = attrs.get(key)
        if value not in (None, ""):
            return value
    return None


def _first_key(attrs: Mapping[str, Any], keys: Sequence[str]) -> Optional[str]:
    for key in keys:
        if attrs.get(key) not in (None, ""):
            return key
    return None


# ── redaction ────────────────────────────────────────────────────────────────

def _host_of(url: str) -> str:
    """Scheme and host only. Parsed by hand to keep the package's import surface
    free of anything that could reach a network, even transitively."""
    text = url.strip()
    scheme, _, rest = text.partition("://")
    if not rest:
        scheme, rest = "", text
    authority = rest.split("/", 1)[0]
    # Drop any userinfo — credentials in a URL must never reach an evidence pack.
    authority = authority.rsplit("@", 1)[-1]
    return f"{scheme}://{authority}" if scheme else authority


def _redact(key: str, value: Any) -> str:
    """Keep the part that classifies; drop the part that could carry a secret.

    An evidence pack is shown to people and stored. A `db.statement` can hold
    customer rows and a URL can hold a bearer token in its query string, so the
    signal records the verb and the host and nothing more.
    """
    text = str(value)
    if key in URL_KEYS:
        return _host_of(text)
    if key in DB_STATEMENT_KEYS:
        first = text.strip().split(None, 1)
        return (first[0].upper() + " …") if first else ""
    if key in PROCESS_KEYS:
        head = text.strip().split(None, 1)
        program = head[0] if head else ""
        return (program.replace("\\", "/").rsplit("/", 1)[-1] + (" …" if len(head) > 1 else ""))
    if key in FILE_KEYS:
        cleaned = text.replace("\\", "/")
        return ".../" + cleaned.rsplit("/", 1)[-1] if "/" in cleaned else cleaned
    return text[:120]


# ── signals ──────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class CapabilitySignal:
    """One reason to think a capability was exercised, and how good a reason it is."""

    capability: Capability
    strength: SignalStrength
    basis: str
    attribute: str = ""
    value: str = ""
    source_id: str = ""
    tool_name: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "capability", Capability(self.capability))
        object.__setattr__(self, "strength", SignalStrength(self.strength))

    def to_dict(self) -> Dict[str, Any]:
        return {"capability": self.capability.value, "strength": self.strength.value,
                "basis": self.basis, "attribute": self.attribute, "value": self.value,
                "source_id": self.source_id, "tool_name": self.tool_name}


def classify_tool_name(name: str) -> Tuple[Tuple[Capability, str], ...]:
    """Match a tool name against the pattern table. Always a guess; never OBSERVED.

    Returns *every* capability whose pattern matches, not the first. A tool called
    `send_invoice_email` plausibly touches payment and email both, and picking one
    by table order would be an arbitrary choice presented as an answer. These are
    inferences either way, and each carries the substring it matched so a reviewer
    can dismiss the wrong one in a second.
    """
    lowered = (name or "").strip().lower()
    if not lowered:
        return ()
    matches: List[Tuple[Capability, str]] = []
    for capability, patterns in _NAME_PATTERNS:
        for pattern in patterns:
            if pattern in lowered:
                matches.append((capability, f"tool name {name!r} contains {pattern!r}"))
                break
    return tuple(matches)


def _signals_from_attributes(attrs: Mapping[str, Any], source_id: str,
                             tool_name: str) -> List[CapabilitySignal]:
    """Everything the structured attributes settle outright."""
    signals: List[CapabilitySignal] = []

    def add(capability: Capability, strength: SignalStrength, basis: str,
            key: str = "", value: Any = "") -> None:
        signals.append(CapabilitySignal(
            capability=capability, strength=strength, basis=basis, attribute=key,
            value=_redact(key, value) if key else "", source_id=source_id,
            tool_name=tool_name))

    # Database. The system attribute proves a database was reached; the operation
    # decides read or write. Without an operation the direction is unknown, so we
    # record the weaker of the two rather than guessing at a write.
    db_key = _first_key(attrs, DB_SYSTEM_KEYS)
    if db_key:
        verb = ""
        op = _first(attrs, DB_OPERATION_KEYS)
        op_key = _first_key(attrs, DB_OPERATION_KEYS)
        if op:
            verb = str(op).strip().split()[0].lower() if str(op).strip() else ""
        if not verb:
            statement = _first(attrs, DB_STATEMENT_KEYS)
            op_key = _first_key(attrs, DB_STATEMENT_KEYS) or db_key
            if statement and str(statement).strip():
                verb = str(statement).strip().split()[0].lower()
        if verb in _WRITE_VERBS:
            add(Capability.DATABASE_WRITE, SignalStrength.PROTOCOL,
                f"{op_key}={verb.upper()} against {attrs[db_key]}", op_key or db_key,
                attrs.get(op_key or db_key, ""))
        elif verb in _READ_VERBS:
            add(Capability.DATABASE_READ, SignalStrength.PROTOCOL,
                f"{op_key}={verb.upper()} against {attrs[db_key]}", op_key or db_key,
                attrs.get(op_key or db_key, ""))
        else:
            # A database was reached and the direction is not recorded. Reporting a
            # read would understate it and a write would overstate it; the honest
            # answer is that we saw database access we cannot direct.
            add(Capability.DATABASE_READ, SignalStrength.SEMANTIC,
                f"{db_key}={attrs[db_key]} with no recorded operation; direction unknown",
                db_key, attrs[db_key])

    # HTTP / network.
    url_key = _first_key(attrs, URL_KEYS)
    host_key = _first_key(attrs, HOST_KEYS)
    method = str(_first(attrs, HTTP_METHOD_KEYS) or "").strip().upper()
    if url_key or host_key or method:
        key = url_key or host_key or _first_key(attrs, HTTP_METHOD_KEYS) or ""
        add(Capability.NETWORK, SignalStrength.PROTOCOL,
            f"{key}={_redact(key, attrs.get(key, method))}", key, attrs.get(key, method))
        host = _host_of(str(attrs.get(url_key, ""))) if url_key else str(attrs.get(host_key, ""))
        if host and not _is_local(host):
            add(Capability.EXTERNAL_API, SignalStrength.PROTOCOL,
                f"call to {host}", key, attrs.get(key, host))
        for fragment, capability in _HOST_HINTS:
            if fragment in host.lower():
                add(capability, SignalStrength.NAME_PATTERN,
                    f"host {host} matches {fragment!r}; reaching a vendor is not the "
                    "same as performing the action", key, host)
        if "github.com" in host.lower() and method in _HTTP_WRITE_METHODS:
            add(Capability.CODE_MODIFICATION, SignalStrength.NAME_PATTERN,
                f"{method} to {host}", key, host)

    # MCP. Not a ratified OTel namespace yet, but it is what instrumentations emit.
    mcp_key = _first_key(attrs, MCP_KEYS)
    if mcp_key or str(_first(attrs, RPC_KEYS) or "").lower() == "mcp":
        key = mcp_key or _first_key(attrs, RPC_KEYS) or ""
        add(Capability.MCP, SignalStrength.PROTOCOL,
            f"{key}={attrs.get(key)} (MCP instrumentation convention)", key,
            attrs.get(key, ""))

    # Shell.
    process_key = _first_key(attrs, PROCESS_KEYS)
    if process_key:
        add(Capability.SHELL, SignalStrength.PROTOCOL,
            f"{process_key} present", process_key, attrs[process_key])

    # Filesystem.
    file_key = _first_key(attrs, FILE_KEYS)
    if file_key:
        add(Capability.FILESYSTEM, SignalStrength.PROTOCOL,
            f"{file_key} present", file_key, attrs[file_key])

    # Messaging, and the subset of it that is email.
    messaging_key = _first_key(attrs, MESSAGING_KEYS)
    if messaging_key:
        system = str(attrs.get("messaging.system") or "").lower()
        if any(name in system for name in _EMAIL_MESSAGING_SYSTEMS):
            add(Capability.EMAIL, SignalStrength.PROTOCOL,
                f"messaging.system={system}", "messaging.system", system)
        else:
            add(Capability.NETWORK, SignalStrength.SEMANTIC,
                f"{messaging_key} present", messaging_key, attrs[messaging_key])
    return signals


def _is_local(host: str) -> bool:
    # Accepts a bare authority or a scheme-qualified one; callers have both.
    text = host.lower()
    if "://" in text:
        text = text.split("://", 1)[1]
    lowered = text.split("/", 1)[0].rsplit("@", 1)[-1].split(":")[0]
    return (lowered in ("localhost", "127.0.0.1", "::1", "0.0.0.0")
            or lowered.startswith("10.") or lowered.startswith("192.168.")
            or lowered.endswith(".local") or lowered.endswith(".internal"))


# ── records and surface ──────────────────────────────────────────────────────

@dataclass(frozen=True)
class CapabilityRecord:
    """One capability, everything seen of it, and how well it is known."""

    capability: Capability
    status: CapabilityStatus
    declared: bool = False
    occurrences: int = 0
    signals: Tuple[CapabilitySignal, ...] = ()
    tool_names: Tuple[str, ...] = ()
    basis: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "capability", Capability(self.capability))
        object.__setattr__(self, "status", CapabilityStatus(self.status))
        object.__setattr__(self, "signals", tuple(self.signals))
        object.__setattr__(self, "tool_names", tuple(sorted(set(self.tool_names))))

    @property
    def mutating(self) -> Optional[bool]:
        """None where the category does not determine it — never defaulted to False."""
        return _PROFILE[self.capability][0]

    @property
    def external_effect(self) -> Optional[bool]:
        return _PROFILE[self.capability][1]

    @property
    def subsuming(self) -> bool:
        """Can this have exercised other capabilities without them showing up?"""
        return _PROFILE[self.capability][2]

    @property
    def observed(self) -> bool:
        """True only for OBSERVED. The property exists so callers cannot write
        `if record.status` and quietly treat an inference as a sighting."""
        return self.status is CapabilityStatus.OBSERVED_CAPABILITY

    @property
    def exercised(self) -> bool:
        """Something happened, at whatever classification strength."""
        return self.status in (CapabilityStatus.OBSERVED_CAPABILITY,
                               CapabilityStatus.INFERRED_CAPABILITY,
                               CapabilityStatus.UNKNOWN_CAPABILITY)

    @property
    def strongest_signal(self) -> SignalStrength:
        if not self.signals:
            return SignalStrength.NONE
        return max((s.strength for s in self.signals), key=lambda s: _SIGNAL_RANK[s])

    # CaseRecord protocol — a capability is storable as evidence.
    @property
    def record_type(self) -> str:
        return "capability"

    @property
    def record_id(self) -> str:
        return f"cap_{self.capability.value}"

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "capability", "record_id": self.record_id,
                "capability": self.capability.value, "status": self.status.value,
                "declared": self.declared, "occurrences": self.occurrences,
                "mutating": self.mutating, "external_effect": self.external_effect,
                "subsuming": self.subsuming,
                "strongest_signal": self.strongest_signal.value,
                "tool_names": list(self.tool_names), "basis": self.basis,
                "signals": [s.to_dict() for s in self.signals],
                "schema_version": CAPABILITY_SCHEMA_VERSION}


@dataclass(frozen=True)
class CapabilitySurface:
    """Everything one body of execution evidence says the system can do."""

    records: Tuple[CapabilityRecord, ...] = ()
    spans_examined: int = 0
    tools_seen: Tuple[str, ...] = ()
    unclassified_tools: Tuple[str, ...] = ()
    attribute_basis: str = "span attributes"
    can_observe: bool = True
    notes: Tuple[str, ...] = ()

    def __iter__(self):
        return iter(self.records)

    def __len__(self) -> int:
        return len(self.records)

    def of_status(self, status: CapabilityStatus) -> Tuple[CapabilityRecord, ...]:
        return tuple(r for r in self.records if r.status is CapabilityStatus(status))

    @property
    def observed(self) -> Tuple[CapabilityRecord, ...]:
        return self.of_status(CapabilityStatus.OBSERVED_CAPABILITY)

    @property
    def inferred(self) -> Tuple[CapabilityRecord, ...]:
        return self.of_status(CapabilityStatus.INFERRED_CAPABILITY)

    @property
    def declared_only(self) -> Tuple[CapabilityRecord, ...]:
        """Declared and never exercised: the blast radius exceeds this run."""
        return self.of_status(CapabilityStatus.DECLARED_CAPABILITY)

    @property
    def unknown(self) -> Tuple[CapabilityRecord, ...]:
        return self.of_status(CapabilityStatus.UNKNOWN_CAPABILITY)

    @property
    def undeclared(self) -> Tuple[CapabilityRecord, ...]:
        """Exercised but never declared — the system did something unannounced."""
        return tuple(r for r in self.records if r.exercised and not r.declared)

    @property
    def mutating_external(self) -> Tuple[CapabilityRecord, ...]:
        """Exercised, definitely state-changing, definitely outside the boundary.

        `is True` rather than truthiness on purpose: a capability whose direction
        the category cannot determine must not be swept in here, and must not be
        swept out of attention either — it appears under `indeterminate`.
        """
        return tuple(r for r in self.records
                     if r.exercised and r.mutating is True and r.external_effect is True)

    @property
    def indeterminate(self) -> Tuple[CapabilityRecord, ...]:
        """Exercised, and the category cannot say whether it changed anything."""
        return tuple(r for r in self.records
                     if r.exercised and (r.mutating is None or r.external_effect is None))

    @property
    def subsuming(self) -> Tuple[CapabilityRecord, ...]:
        return tuple(r for r in self.records if r.exercised and r.subsuming)

    @property
    def bounded(self) -> bool:
        """Is this list an upper bound on what the system did?

        False once a shell, an MCP server or an unidentified tool was exercised —
        each can reach anything without appearing as itself. A capability list that
        implied completeness here would be the most dangerous output this module
        could produce, because it looks like an inventory.
        """
        return not self.subsuming

    def capability(self, capability: Capability) -> Optional[CapabilityRecord]:
        wanted = Capability(capability)
        return next((r for r in self.records if r.capability is wanted), None)

    def digest(self) -> str:
        return digest_object({"records": [r.to_dict() for r in self.records],
                              "schema_version": CAPABILITY_SCHEMA_VERSION})

    def summary(self) -> Dict[str, Any]:
        return {"total": len(self.records), "spans_examined": self.spans_examined,
                "attribute_basis": self.attribute_basis,
                "observation_possible": self.can_observe,
                "bounded": self.bounded,
                "subsuming": [r.capability.value for r in self.subsuming],
                "by_status": {s.value: len(self.of_status(s)) for s in CapabilityStatus},
                "undeclared": [r.capability.value for r in self.undeclared],
                "unclassified_tools": list(self.unclassified_tools),
                "digest": self.digest()}

    def to_dict(self) -> Dict[str, Any]:
        return {**self.summary(), "records": [r.to_dict() for r in self.records],
                "notes": list(self.notes)}

    # ── construction ────────────────────────────────────────────────────────

    @classmethod
    def from_spans(cls, document: Any, *,
                   declared: Optional[Iterable[Any]] = None) -> "CapabilitySurface":
        """Read raw spans, where the classifying attributes still exist.

        This is the only path that can produce `OBSERVED_CAPABILITY`, because the
        execution graph keeps a node's label and drops the attributes that settle
        what it was.
        """
        from release_gate.adapters.common import iter_otlp_spans, otlp_attributes

        collected: List[CapabilitySignal] = []
        tools: Set[str] = set()
        unclassified: Set[str] = set()
        spans = 0

        for span, resource_attrs in iter_otlp_spans(document):
            spans += 1
            attrs = dict(resource_attrs)
            attrs.update(otlp_attributes(span.get("attributes", [])))
            source_id = str(span.get("spanId") or span.get("span_id") or "")
            tool_name = str(_first(attrs, TOOL_NAME_KEYS) or "")
            name = tool_name or str(span.get("name") or "")

            signals = _signals_from_attributes(attrs, source_id, tool_name)
            collected.extend(signals)

            if tool_name:
                tools.add(tool_name)

            # The name is classified *alongside* the attributes, never only when
            # they are absent. One span can exercise several capabilities — an MCP
            # call to `read_file` is MCP and filesystem both — and treating the
            # attribute hit as the whole answer would silently drop the rest.
            guesses = classify_tool_name(name)
            for capability, basis in guesses:
                collected.append(CapabilitySignal(
                    capability=capability, strength=SignalStrength.NAME_PATTERN,
                    basis=basis, source_id=source_id, tool_name=tool_name))

            if not signals and not guesses and tool_name:
                unclassified.add(tool_name)
                collected.append(CapabilitySignal(
                    capability=Capability.UNKNOWN_TOOL, strength=SignalStrength.NONE,
                    basis=f"tool {tool_name!r} matched no known capability",
                    source_id=source_id, tool_name=tool_name))

        return cls._fold(collected, declared=declared, spans=spans, tools=tools,
                         unclassified=unclassified, basis="span attributes",
                         can_observe=True)

    @classmethod
    def from_execution_graph(cls, graph: Any, *,
                             declared: Optional[Iterable[Any]] = None
                             ) -> "CapabilitySurface":
        """Read a built graph. Nothing here can reach OBSERVED, and it says so.

        The graph keeps labels, not attributes, so every classification is a name
        match. Reporting these as observed would be the exact conflation this
        module exists to prevent — so the surface is marked `can_observe=False`
        and carries a note explaining what better telemetry would buy.
        """
        collected: List[CapabilitySignal] = []
        tools: Set[str] = set()
        unclassified: Set[str] = set()
        nodes = list(getattr(graph, "nodes", ()) or ())

        for node in sorted(nodes, key=lambda n: n.node_id):
            if node.kind.value not in ("TOOL", "EXTERNAL_SYSTEM", "ACTION"):
                continue
            label = str(node.label or "")
            if label:
                tools.add(label)
            guesses = classify_tool_name(label)
            for capability, basis in guesses:
                collected.append(CapabilitySignal(
                    capability=capability, strength=SignalStrength.NAME_PATTERN,
                    basis=basis + " (from a graph label; span attributes were not available)",
                    source_id=node.node_id, tool_name=label))
            if not guesses and label:
                unclassified.add(label)
                collected.append(CapabilitySignal(
                    capability=Capability.UNKNOWN_TOOL, strength=SignalStrength.NONE,
                    basis=f"node {label!r} matched no known capability",
                    source_id=node.node_id, tool_name=label))

        surface = cls._fold(collected, declared=declared, spans=len(nodes), tools=tools,
                            unclassified=unclassified,
                            basis="execution graph labels", can_observe=False)
        return dataclasses.replace(surface, notes=surface.notes + (
            "Capabilities were read from graph labels, not span attributes, so none "
            "can be OBSERVED. Re-running against the raw trace would let protocol "
            "attributes (db.system, url.full, process.command_line) settle several "
            "of these outright.",))

    @classmethod
    def _fold(cls, signals: Sequence[CapabilitySignal], *,
              declared: Optional[Iterable[Any]], spans: int, tools: Set[str],
              unclassified: Set[str], basis: str, can_observe: bool
              ) -> "CapabilitySurface":
        declared_caps, declared_unmatched = _normalise_declared(declared)

        grouped: Dict[Capability, List[CapabilitySignal]] = {}
        for signal in signals:
            grouped.setdefault(signal.capability, []).append(signal)

        records: List[CapabilityRecord] = []
        for capability in sorted(grouped, key=lambda c: c.value):
            found = sorted(grouped[capability],
                           key=lambda s: (-_SIGNAL_RANK[s.strength], s.source_id, s.basis))
            strength = found[0].strength
            status = status_for(Observation.DIRECT, strength)
            records.append(CapabilityRecord(
                capability=capability, status=status,
                declared=capability in declared_caps, occurrences=len(found),
                signals=tuple(found),
                tool_names=tuple(s.tool_name for s in found if s.tool_name),
                basis=found[0].basis))

        # Declared and never exercised. Kept as its own status rather than folded
        # into the exercised ones: what a system *may* do is a different fact from
        # what it *did*, and a reviewer needs both.
        exercised = {r.capability for r in records}
        for capability in sorted(declared_caps - exercised, key=lambda c: c.value):
            records.append(CapabilityRecord(
                capability=capability, status=CapabilityStatus.DECLARED_CAPABILITY,
                declared=True, occurrences=0,
                basis="declared in a tool manifest; never exercised in this evidence"))

        records.sort(key=lambda r: (-_STATUS_RANK[r.status], r.capability.value))
        notes: List[str] = []
        if declared_unmatched:
            notes.append(
                f"{len(declared_unmatched)} declared tool(s) matched no known "
                f"capability: {', '.join(sorted(declared_unmatched)[:8])}")
        return cls(records=tuple(records), spans_examined=spans,
                   tools_seen=tuple(sorted(tools)),
                   unclassified_tools=tuple(sorted(unclassified)),
                   attribute_basis=basis, can_observe=can_observe, notes=tuple(notes))


def _normalise_declared(declared: Optional[Iterable[Any]]
                        ) -> Tuple[Set[Capability], Set[str]]:
    """Map declared tool names onto capabilities; keep what did not map."""
    capabilities: Set[Capability] = set()
    unmatched: Set[str] = set()
    for entry in declared or ():
        if isinstance(entry, Capability):
            capabilities.add(entry)
            continue
        text = str(entry).strip()
        if not text:
            continue
        try:
            capabilities.add(Capability(text.upper()))
            continue
        except ValueError:
            pass
        guesses = classify_tool_name(text)
        if guesses:
            capabilities.update(capability for capability, _ in guesses)
        else:
            unmatched.add(text)
    return capabilities, unmatched


#: Where a document tends to list what a system is allowed to reach for.
_MANIFEST_KEYS = ("tools", "available_tools", "allowed_tools", "toolSpecs",
                  "tool_definitions", "capabilities", "declared_capabilities")


def declared_from_document(doc: Any) -> Tuple[str, ...]:
    """Pull a tool manifest out of a document, if it carries one.

    Looks for the shapes an agent spec or an MCP `tools/list` reply actually
    takes. Finding nothing is the normal case and is not an error — it simply
    means nothing was declared, which is itself worth reporting.
    """
    found: List[str] = []

    def harvest(value: Any) -> None:
        if isinstance(value, str):
            if value.strip():
                found.append(value.strip())
        elif isinstance(value, Mapping):
            name = value.get("name") or value.get("tool") or value.get("function")
            if isinstance(name, Mapping):
                name = name.get("name")
            if isinstance(name, str) and name.strip():
                found.append(name.strip())
        elif isinstance(value, (list, tuple)):
            for item in value:
                harvest(item)

    if isinstance(doc, Mapping):
        for key in _MANIFEST_KEYS:
            if key in doc:
                harvest(doc[key])
        result = doc.get("result")
        if isinstance(result, Mapping) and "tools" in result:
            harvest(result["tools"])
    elif isinstance(doc, list):
        for item in doc:
            if isinstance(item, Mapping) and item.get("record_type") == "capability":
                harvest(item.get("capability") or item.get("name"))
    return tuple(sorted(set(found)))

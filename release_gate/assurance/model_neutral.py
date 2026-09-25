"""Talking to any model, requiring none.

Release-gate's authoritative path never calls a model. That is why
`release_gate/assurance/` contains zero references to any provider — measured, not
asserted, and the purity grep keeps it that way. Everything here is for the
*optional* paths: the second-opinion verifier and §10r's model-assisted semantic
help, both of which are opt-in and neither of which decides anything.

The problem this solves is narrower than it sounds. "Bring your own model" was
already true in the sense that a caller supplies an endpoint — but only one wire
format was ever spoken, OpenAI's `/chat/completions`. That covers OpenAI,
Together, Groq, Fireworks, OpenRouter, Ollama, vLLM and llama.cpp, which is a
wide slice and still a de facto standard rather than independence. Anthropic
wants `/v1/messages`, an `x-api-key` header, a version header, the system prompt
as a top-level field and the text at `content[0].text`. Google wants
`:generateContent`, `contents[].parts[]` and the text somewhere else again. A
future system wants something nobody has written down yet.

So request shaping and response extraction are **data**. A provider is a row in
`DIALECTS`, a custom provider is a `ModelDialect` a caller constructs, and adding
one touches no code path. Nothing here imports a vendor SDK; nothing here makes a
network call either — `build_request` returns a plan and the caller's transport
executes it, which is what keeps this module inside a package that is not allowed
to touch the network.

**An unrecognised provider is a refusal, not a default.** `resolve_dialect`
returns a `DialectResolution` carrying `recognised`, and an unrecognised endpoint
yields no dialect at all. The alternative — assume OpenAI and hope — sends a
request shaped for one vendor to another and then reads the reply with the wrong
extractor, which does not fail loudly: it produces a confident answer from a
field that happened to parse. §10z drew the same line between "I refused this"
and "I have never heard of this", and it is the same line here.

**No provider earns a better epistemic status than another.** A model's output is
DERIVED whatever produced it (§10r). There is no dialect flag that promotes an
answer, and a test asserts the status is identical across every one of them. A
frontier model's guess and a local 7B's guess are the same kind of thing to this
engine, and the day that stops being true is the day the provider list starts
deciding verdicts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple

__all__ = [
    "DIALECTS",
    "MODEL_NEUTRAL_SCHEMA_VERSION",
    "DialectError",
    "DialectResolution",
    "ModelDialect",
    "RequestPlan",
    "SystemPlacement",
    "build_request",
    "extract_text",
    "resolve_dialect",
]

MODEL_NEUTRAL_SCHEMA_VERSION = 1


class DialectError(ValueError):
    """A request could not be shaped, or a reply could not be read."""


class SystemPlacement(str, Enum):
    """Where a provider wants the system instruction.

    Three real answers, which is why this is not a boolean. Getting it wrong does
    not error: the instruction is silently dropped or buried in the user turn, and
    the model answers a different question than the one asked.
    """

    MESSAGE = "MESSAGE"        # a message with role=system, as OpenAI takes it
    TOP_LEVEL = "TOP_LEVEL"    # its own field beside the messages, as Anthropic
    INSTRUCTION = "INSTRUCTION"  # a named instruction block, as Google
    PREPEND = "PREPEND"        # no system concept; fold it into the user turn


@dataclass(frozen=True)
class RequestPlan:
    """A request, described rather than sent.

    Returned instead of performing the call so this module stays inside a package
    that makes no network calls, and so a caller can show a user exactly what
    would leave before anything does — which matters more after §10ab.
    """

    url: str
    headers: Mapping[str, str]
    body: Mapping[str, Any]
    dialect_id: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "headers", dict(self.headers))
        object.__setattr__(self, "body", dict(self.body))

    def to_dict(self) -> Dict[str, Any]:
        # The URL is redacted too. Google carries the credential in the query
        # string, so a view that scrubbed only headers printed the key in the
        # field most likely to be pasted into a ticket.
        url = self.url
        for marker in ("?key=", "&key=", "?api_key=", "&api_key="):
            if marker in url:
                head, _, tail = url.partition(marker)
                rest = tail.partition("&")[2]
                url = head + marker + "<redacted>" + (f"&{rest}" if rest else "")
        return {"record_type": "request_plan", "url": url,
                "headers": {k: ("<redacted>" if k.lower() in
                                ("authorization", "x-api-key", "api-key")
                                else v) for k, v in self.headers.items()},
                "body": dict(self.body), "dialect": self.dialect_id}


@dataclass(frozen=True)
class ModelDialect:
    """How one provider wants to be asked, and where its answer lives.

    Data, not a subclass. A provider is a row; a custom provider is an instance a
    caller builds and passes in; a future provider is a row somebody adds without
    touching a code path.
    """

    dialect_id: str
    label: str
    #: Appended to the caller's base URL. `{model}` is substituted, for providers
    #: that put the model in the path rather than the body.
    path: str = "/chat/completions"
    #: Header carrying the credential, and the scheme prefixing it.
    auth_header: str = "Authorization"
    auth_scheme: str = "Bearer "
    #: Providers that want the key as a query parameter rather than a header.
    auth_query_param: str = ""
    extra_headers: Mapping[str, str] = field(default_factory=dict)
    system_placement: SystemPlacement = SystemPlacement.MESSAGE
    #: Body key holding the turns, and the key names inside one.
    turns_key: str = "messages"
    role_key: str = "role"
    content_key: str = "content"
    user_role: str = "user"
    system_key: str = "system"
    #: Whether the model id goes in the body. False for path-addressed providers.
    model_in_body: bool = True
    model_key: str = "model"
    #: Keys for the determinism and length controls, empty where unsupported.
    temperature_key: str = "temperature"
    max_tokens_key: str = "max_tokens"
    #: Where the reply text lives. Integers index lists, strings index mappings.
    text_path: Tuple[Any, ...] = ("choices", 0, "message", "content")
    #: URL fragments that identify this provider, for `resolve_dialect`.
    url_hints: Tuple[str, ...] = ()
    notes: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "system_placement",
                           SystemPlacement(self.system_placement))
        object.__setattr__(self, "extra_headers", dict(self.extra_headers))
        object.__setattr__(self, "text_path", tuple(self.text_path))
        object.__setattr__(self, "url_hints", tuple(self.url_hints))
        if not str(self.dialect_id or "").strip():
            raise DialectError("a dialect must be named so a record can cite it")
        if not self.text_path:
            raise DialectError(
                f"{self.dialect_id}: a dialect must say where the reply text is. "
                "Without it a caller guesses, and a guess that happens to parse "
                "produces a confident answer from the wrong field")

    @property
    def establishes_truth(self) -> bool:
        """Unconditionally False, for every dialect.

        A model's answer is DERIVED evidence whatever produced it (§10r). No
        provider is promoted by being recognised here, and none is demoted by
        being unfamiliar.
        """
        return False

    @property
    def requires_a_credential(self) -> bool:
        """Whether a key is needed. False for local endpoints, which is the point
        of having them."""
        return bool(self.auth_header or self.auth_query_param)

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "model_dialect", "record_id": self.dialect_id,
                "dialect_id": self.dialect_id, "label": self.label,
                "path": self.path, "system_placement": self.system_placement.value,
                "text_path": list(self.text_path),
                "url_hints": list(self.url_hints), "notes": self.notes,
                "establishes_truth": False}


_DIALECT_LIST: Tuple[ModelDialect, ...] = (
    ModelDialect(
        dialect_id="anthropic_messages",
        label="Anthropic /v1/messages",
        path="/messages",
        auth_header="x-api-key", auth_scheme="",
        extra_headers={"anthropic-version": "2023-06-01"},
        system_placement=SystemPlacement.TOP_LEVEL,
        text_path=("content", 0, "text"),
        url_hints=("api.anthropic.com",),
        notes="The system prompt is a top-level field, not a message with "
              "role=system. Sent as a message it is silently ignored, and the "
              "model answers without the instruction it was supposed to follow."),
    ModelDialect(
        dialect_id="google_generate_content",
        label="Google Gemini :generateContent",
        path="/models/{model}:generateContent",
        auth_header="", auth_scheme="", auth_query_param="key",
        system_placement=SystemPlacement.INSTRUCTION,
        turns_key="contents", role_key="role", content_key="parts",
        system_key="systemInstruction",
        model_in_body=False,
        temperature_key="", max_tokens_key="",
        text_path=("candidates", 0, "content", "parts", 0, "text"),
        url_hints=("generativelanguage.googleapis.com",),
        notes="The model is addressed in the path and the key goes in the query "
              "string. Generation controls live under generationConfig, which "
              "this dialect leaves unset rather than guessing at."),
    ModelDialect(
        dialect_id="ollama_native",
        label="Ollama /api/chat",
        path="/api/chat",
        auth_header="", auth_scheme="",
        text_path=("message", "content"),
        url_hints=("/api/chat", ":11434"),
        notes="Ollama also serves the OpenAI dialect at /v1, which is usually the "
              "easier route. This exists for a deployment pointed at the native "
              "endpoint, and it needs no credential at all."),
    ModelDialect(
        dialect_id="openai_responses",
        label="OpenAI /responses",
        path="/responses",
        system_placement=SystemPlacement.PREPEND,
        turns_key="input",
        text_path=("output", 0, "content", 0, "text"),
        url_hints=("/responses",),
        notes="A second shape from the same vendor, which is the argument for "
              "dialects being data: a provider can change its mind without this "
              "becoming a code change."),
    # Last, and deliberately. Its hints are exact vendor hosts and nothing
    # broader: an earlier version listed "/v1" and "localhost", which matched
    # Anthropic's own base URL and every local endpoint, so every provider
    # resolved to this dialect and reported recognised=True. A resolver that
    # confidently misidentifies one vendor as another is worse than one that
    # admits it does not know, because the reply is then read out of the wrong
    # field and parses.
    ModelDialect(
        dialect_id="openai_chat",
        label="OpenAI /chat/completions, and everything that speaks it",
        url_hints=("api.openai.com", "openrouter.ai", "api.together.xyz",
                   "api.groq.com", "api.fireworks.ai", "api.deepseek.com",
                   "api.mistral.ai", "api.cerebras.ai",
                   "/chat/completions"),
        notes="The de facto standard. Ollama, vLLM and llama.cpp all expose it, "
              "which is why a local model needs no special case — point the base "
              "URL at localhost and nothing leaves the machine. A bare localhost "
              "URL is NOT claimed as recognised: anything can be behind it, and "
              "this dialect is reached by fallback with that said plainly."),
)

#: dialect id → dialect. Built from one list, so the registry cannot disagree
#: with itself about which dialects exist.
DIALECTS: Mapping[str, ModelDialect] = {d.dialect_id: d for d in _DIALECT_LIST}

#: The dialect assumed when a caller names none and the URL says nothing. Named
#: rather than inlined, so "what does release-gate fall back to" has one answer a
#: reader can find.
_FALLBACK = DIALECTS["openai_chat"]


@dataclass(frozen=True)
class DialectResolution:
    """Which dialect to use, whether anyone established that, and why.

    `recognised` is the field that matters. A dialect chosen because the URL
    matched a known provider and one chosen because nothing matched are different
    facts, and a caller that cannot tell them apart will send an OpenAI-shaped
    body to a provider that wanted something else.
    """

    dialect: Optional[ModelDialect]
    recognised: bool
    basis: str

    @property
    def usable(self) -> bool:
        return self.dialect is not None

    def to_dict(self) -> Dict[str, Any]:
        return {"record_type": "dialect_resolution",
                "dialect": self.dialect.dialect_id if self.dialect else None,
                "recognised": self.recognised, "basis": self.basis,
                "usable": self.usable}


def resolve_dialect(base_url: str = "", *, named: str = "",
                    allow_fallback: bool = True) -> DialectResolution:
    """Pick a dialect for this endpoint.

    An explicitly `named` dialect always wins: a caller who says which wire
    format they want is not second-guessed by URL sniffing.

    With `allow_fallback=False`, an unrecognised endpoint yields no dialect at
    all. That is the honest mode for anything that would act on the reply: a
    request shaped for one vendor and read with another's extractor does not fail
    loudly, it produces a confident answer from whichever field happened to
    parse.
    """
    if named:
        found = DIALECTS.get(named)
        if found is None:
            raise DialectError(
                f"no dialect named {named!r}. Known: "
                + ", ".join(sorted(DIALECTS))
                + ". A provider this does not know is not a provider it refuses: "
                  "build a ModelDialect for it and pass that instead")
        return DialectResolution(found, True,
                                 f"the caller named {found.dialect_id}")

    lowered = (base_url or "").lower()
    for dialect in _DIALECT_LIST:
        for hint in dialect.url_hints:
            if hint and hint in lowered:
                return DialectResolution(
                    dialect, True,
                    f"{base_url} matched {dialect.dialect_id} on {hint!r}")

    if allow_fallback:
        return DialectResolution(
            _FALLBACK, False,
            f"nothing in {base_url or 'an unset base URL'} identifies a known "
            f"provider, so the {_FALLBACK.dialect_id} dialect is assumed. That is "
            "a guess: if the endpoint wants another shape, the request will be "
            "rejected or the reply misread")
    return DialectResolution(
        None, False,
        f"nothing in {base_url or 'an unset base URL'} identifies a known "
        "provider. Name a dialect, or supply a ModelDialect describing this one; "
        "assuming a shape here would send one vendor's request to another and "
        "read the answer out of the wrong field")


# ── shaping a request ────────────────────────────────────────────────────────

def build_request(dialect: ModelDialect, *, base_url: str, model: str,
                  user: str, system: str = "", api_key: str = "",
                  temperature: float = 0, max_tokens: int = 300,
                  ) -> RequestPlan:
    """Describe the call this dialect wants. Nothing is sent."""
    if not str(model or "").strip():
        raise DialectError(
            "a request must name a model. release-gate has no default model and "
            "will not pick one: a model nobody chose is a provider nobody chose")

    path = dialect.path.replace("{model}", model.strip())
    url = (base_url or "").rstrip("/") + path

    headers: Dict[str, str] = {"Content-Type": "application/json",
                               **dict(dialect.extra_headers)}
    if api_key:
        if dialect.auth_query_param:
            sep = "&" if "?" in url else "?"
            url = f"{url}{sep}{dialect.auth_query_param}={api_key}"
        elif dialect.auth_header:
            headers[dialect.auth_header] = f"{dialect.auth_scheme}{api_key}"

    prompt = user
    body: Dict[str, Any] = {}
    if dialect.model_in_body:
        body[dialect.model_key] = model

    turns: list = []
    if system:
        if dialect.system_placement is SystemPlacement.MESSAGE:
            turns.append({dialect.role_key: "system",
                          dialect.content_key: system})
        elif dialect.system_placement is SystemPlacement.TOP_LEVEL:
            body[dialect.system_key] = system
        elif dialect.system_placement is SystemPlacement.INSTRUCTION:
            body[dialect.system_key] = {
                "parts": [{"text": system}]}
        else:  # PREPEND — no system concept at all
            prompt = f"{system}\n\n{user}"

    content: Any = prompt
    if dialect.content_key == "parts":
        # Google carries a turn's text as a list of parts rather than a string.
        content = [{"text": prompt}]
    turns.append({dialect.role_key: dialect.user_role,
                  dialect.content_key: content})
    body[dialect.turns_key] = turns

    if dialect.temperature_key:
        body[dialect.temperature_key] = temperature
    if dialect.max_tokens_key:
        body[dialect.max_tokens_key] = max_tokens

    return RequestPlan(url=url, headers=headers, body=body,
                       dialect_id=dialect.dialect_id)


def extract_text(dialect: ModelDialect, response: Any) -> str:
    """Walk this dialect's `text_path` to the reply, or say what was missing.

    The error names the path and where it broke. A caller that got a shape it did
    not expect needs to know it read the wrong field, because the failure mode
    otherwise is a plausible string pulled out of an unrelated part of the reply.
    """
    node: Any = response
    for step in dialect.text_path:
        try:
            node = node[step]
        except (KeyError, IndexError, TypeError) as exc:
            raise DialectError(
                f"{dialect.dialect_id} expected the reply text at "
                + "".join(f"[{s!r}]" for s in dialect.text_path)
                + f" and {step!r} is not there ({type(exc).__name__}). Either the "
                  "endpoint speaks a different dialect than the one used to ask "
                  "it, or its shape changed") from exc
    if not isinstance(node, str):
        raise DialectError(
            f"{dialect.dialect_id} found {type(node).__name__} where the reply "
            "text should be; a non-string here means the path leads somewhere "
            "else in this response")
    return node

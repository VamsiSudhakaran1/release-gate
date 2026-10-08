"""Network transports for the semantic verifier, outside the assurance core.

`release_gate/assurance/` never opens a socket, and the hostile suite asserts it.
The verifier there speaks to a `SemanticProvider` — say who you are, complete one
request — and this module supplies the ones that cross a network.

**One transport covers most of the field.** OpenAI's `/chat/completions` is the
de facto wire format, spoken by hosted APIs and by every common local server:
vLLM, llama.cpp's `server`, LM Studio, Ollama's `/v1`. `OpenAICompatibleProvider`
speaks it, and through `model_neutral.py` it also speaks Ollama's native API,
OpenAI's `/responses`, Anthropic's `/v1/messages` and Google's `:generateContent`
— a wire format is a row of data there, not a code path here.

**A provider this build does not ship is a class, not a change.** A future Jev or
Laya provider, or a release-gate specialist model, implements `identity()` and
`complete()` and is registered by name on a `ProviderRegistry`. Nothing in the
verifier, the packet or the resolution policy names a vendor, so nothing there
moves when one is added.

**Decision models are a second interface, not a second client.** A model that
takes STATE / QUESTION / CHOICES and returns a choice, scores or probabilities
is a `DecisionProvider`; `release_gate/decision_providers/` holds the transport
for the `release-gate-decision/1` protocol and the optional named modules.
They send through `exchange_json` here, so there is one HTTP client in this
build, with one set of failure semantics.

**Providers not in this build are found, not imported.** An installed package
can offer a provider under the `release_gate.semantic_providers` entry-point
group. Nothing is loaded until a provider is asked for by a name the build does
not ship, and a plugin that fails to load is recorded, not fatal.

**Requests go only where they are pointed.** There is no default endpoint: a
semantic question is sent to the base URL the caller configured or to nothing.
An API key travels only in the request it authenticates and never into an
identity, an error message or a persisted assertion.

Config, for `provider_from_env`:

    RG_SEMANTIC_PROVIDER      openai_compatible (default) | ollama | decision_http |
                              laya | jev | an installed provider's name
    RG_SEMANTIC_BASE_URL      required, e.g. http://localhost:11434/v1
    RG_SEMANTIC_MODEL         required
    RG_SEMANTIC_API_KEY       required for a non-local endpoint
    RG_SEMANTIC_DIALECT       optional: name the wire format explicitly
    RG_SEMANTIC_MODEL_FAMILY  optional: the model family, as you state it — it is
                              what lets the independence analysis group this
                              model's readings with its other output
    RG_SEMANTIC_MAX_INPUT_CHARS  optional: the context limit, as you declare it
    RG_SEMANTIC_COST_PER_CALL    optional: what one call costs, in the unit your
                                 escalation budget is written in
"""

from __future__ import annotations

import json
import os
import socket
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, replace
from typing import Any, Callable, Dict, Mapping, Optional, Tuple

from release_gate.assurance.model_neutral import (DialectError, ModelDialect,
                                                  build_request, extract_text,
                                                  resolve_dialect, tool_calls_in)
from release_gate.assurance.producer_contract import ConfidenceSemantics, Determinism
from release_gate.assurance.semantic_verifier import (Locality, OutputKind,
                                                      ProviderCapabilities, ProviderIdentity,
                                                      ProviderInterface, ProviderRegistry,
                                                      ProviderReply, ProviderRequest,
                                                      ProviderTimeout, ProviderUnavailable,
                                                      SemanticVerifierError, ToolCallRefused)

__all__ = [
    "ENTRY_POINT_GROUP",
    "DiscoveryReport",
    "OpenAICompatibleProvider",
    "SemanticProviderConfigError",
    "default_provider_registry",
    "discover_providers",
    "exchange_json",
    "operator_capabilities",
    "panel_providers",
    "provider_from_env",
]

#: Where an installed package offers a provider: `name = "module:factory"`.
ENTRY_POINT_GROUP = "release_gate.semantic_providers"

_LOCAL_HOSTS = ("localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]")


class SemanticProviderConfigError(SemanticVerifierError):
    """A provider was asked for without what it needs to be reached."""


def _public_endpoint(base_url: str) -> str:
    """The base URL with any credential or query string removed."""
    parts = urllib.parse.urlsplit(base_url or "")
    host = parts.hostname or ""
    netloc = host + (f":{parts.port}" if parts.port else "")
    return urllib.parse.urlunsplit((parts.scheme, netloc, parts.path, "", ""))


def _is_local(base_url: str) -> bool:
    host = (urllib.parse.urlsplit(base_url or "").hostname or "").lower()
    return host in _LOCAL_HOSTS


def exchange_json(url: str, *, endpoint: str, timeout: float, user_agent: str,
                  body: Optional[Any] = None,
                  headers: Optional[Mapping[str, str]] = None) -> Tuple[Any, str]:
    """One HTTP exchange: POST `body` as JSON, or GET without one. Stdlib only.

    Returns the parsed JSON and the body as text. Every transport in this build
    sends through here, so a timeout is a `ProviderTimeout` and anything else that
    stops an answer arriving is `ProviderUnavailable` — the verifier turns both
    into UNKNOWN. `endpoint` is the credential-free name used in every message.
    """
    data = None if body is None else json.dumps(body).encode("utf-8")
    request = urllib.request.Request(
        url, data=data, method="GET" if body is None else "POST",
        headers={**({"Content-Type": "application/json"} if body is not None else {}),
                 **dict(headers or {}), "User-Agent": user_agent})
    try:
        # Looked up at call time, so a test that replaces it reaches this call.
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            raw = resp.read()
    except (socket.timeout, TimeoutError) as exc:
        raise ProviderTimeout(f"{endpoint} did not answer in time") from exc
    except urllib.error.HTTPError as exc:
        raise ProviderUnavailable(f"{endpoint} answered HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, (socket.timeout, TimeoutError)):
            raise ProviderTimeout(f"{endpoint} did not answer in time") from exc
        raise ProviderUnavailable(
            f"{endpoint} could not be reached ({type(exc.reason).__name__})") from exc
    except OSError as exc:
        raise ProviderUnavailable(
            f"{endpoint} could not be reached ({type(exc).__name__})") from exc
    text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
    try:
        return json.loads(text), text
    except ValueError as exc:
        raise ProviderUnavailable(f"{endpoint} answered with something that is "
                                  "not JSON") from exc


def operator_capabilities(found: ProviderCapabilities, *,
                          max_input_chars: Optional[int] = None,
                          cost_per_call: Optional[float] = None) -> ProviderCapabilities:
    """What a provider declared, with the operator's own figures laid over it.

    The operator knows what a call costs them and may hold a model to a tighter
    context than it accepts; either replaces the provider's figure, and
    `declared_by` says that it did.
    """
    changes: Dict[str, Any] = {}
    if max_input_chars is not None:
        changes["max_input_chars"] = max_input_chars
    if cost_per_call is not None:
        changes["cost_per_call"] = cost_per_call
    if not changes:
        return found
    return replace(found, **changes, declared_by=(
        f"{found.declared_by}; {', '.join(sorted(changes))} by the operator"))


class OpenAICompatibleProvider:
    """Any endpoint whose wire format `model_neutral` describes. Stdlib only."""

    def __init__(self, *, base_url: str, model: str, api_key: str = "",
                 dialect: Any = "", model_family: str = "", provider_name: str = "",
                 user_agent: str = "release-gate-semantic",
                 max_input_chars: Optional[int] = None,
                 cost_per_call: Optional[float] = None) -> None:
        if not str(base_url or "").strip():
            raise SemanticProviderConfigError(
                "a provider needs a base URL; release-gate has no default endpoint "
                "and sends nothing anywhere it was not pointed")
        if not str(model or "").strip():
            raise SemanticProviderConfigError(
                "a provider needs a model; release-gate does not pick one")
        if not api_key and not _is_local(base_url):
            raise SemanticProviderConfigError(
                f"{_public_endpoint(base_url)} is not local and no API key was given")
        self.base_url = str(base_url).rstrip("/")
        self.model = str(model).strip()
        self._api_key = api_key
        self.model_family = model_family
        self.user_agent = user_agent
        self.max_input_chars = max_input_chars
        self.cost_per_call = cost_per_call
        if isinstance(dialect, ModelDialect):
            self.dialect, recognised = dialect, True
        else:
            resolution = resolve_dialect(self.base_url, named=str(dialect or ""),
                                         allow_fallback=True)
            self.dialect, recognised = resolution.dialect, resolution.recognised
        self._recognised = recognised
        self.provider_name = (provider_name or urllib.parse.urlsplit(self.base_url).hostname
                              or self.dialect.dialect_id)

    def identity(self) -> ProviderIdentity:
        return ProviderIdentity(
            provider=self.provider_name, model=self.model, model_family=self.model_family,
            endpoint=_public_endpoint(self.base_url), local=_is_local(self.base_url),
            dialect=self.dialect.dialect_id, dialect_recognised=self._recognised)

    def capabilities(self) -> ProviderCapabilities:
        """The chat contract, stated by release-gate rather than by the endpoint.

        A chat endpoint is asked for a verdict word, a self-reported confidence
        and a reason, and that is all it is held to. Its determinism is not
        known: temperature 0 is a request, not a guarantee.
        """
        return operator_capabilities(ProviderCapabilities(
            interface=ProviderInterface.CHAT,
            outputs=(OutputKind.CHOICE, OutputKind.FREE_FORM_REASONING),
            confidence=ConfidenceSemantics.PRODUCER_SCORE,
            locality=Locality.LOCAL if _is_local(self.base_url) else Locality.REMOTE,
            determinism=Determinism.UNKNOWN,
            declared_by="release-gate: the chat contract this transport asks under"),
            max_input_chars=self.max_input_chars, cost_per_call=self.cost_per_call)

    def complete(self, request: ProviderRequest) -> ProviderReply:
        plan = build_request(self.dialect, base_url=self.base_url, model=self.model,
                             user=request.user, system=request.system,
                             api_key=self._api_key, temperature=request.temperature,
                             max_tokens=request.max_tokens)
        data, _ = exchange_json(plan.url, body=plan.body, headers=plan.headers,
                                timeout=request.timeout_seconds,
                                endpoint=_public_endpoint(self.base_url),
                                user_agent=self.user_agent)
        calls = tool_calls_in(data)
        if calls:
            # Refused here, before any text is read: the request offered no
            # tools, and nothing downstream can run one.
            raise ToolCallRefused(f"{_public_endpoint(self.base_url)} replied with "
                                  f"a tool call at {', '.join(calls)}")
        reported = data.get("model") if isinstance(data, Mapping) else None
        try:
            text = extract_text(self.dialect, data)
        except DialectError:
            # The reply arrived and had no text where this wire format puts it.
            # An empty reply is malformed to the verifier, which is the honest
            # reading: something answered, and not with an answer.
            text = ""
        return ProviderReply(text=text,
                             model_version=reported if isinstance(reported, str) else "")


def _ollama(*, base_url: str = "http://localhost:11434", model: str, **kw: Any
            ) -> OpenAICompatibleProvider:
    return OpenAICompatibleProvider(base_url=base_url, model=model,
                                    dialect=kw.pop("dialect", "ollama_native"), **kw)


def _imported_when_asked(module: str, attribute: str) -> Callable[..., Any]:
    """A factory that imports its module only when a provider is built from it.

    The optional decision modules are named here and loaded nowhere else, so a
    build that never asks for one never imports it.
    """
    def build(**config: Any) -> Any:
        import importlib
        return getattr(importlib.import_module(module), attribute)(**config)
    build.__name__ = f"{module}.{attribute}"
    return build


def default_provider_registry() -> ProviderRegistry:
    """The transports this build ships. Register more on the returned registry."""
    registry = ProviderRegistry()
    registry.register("openai_compatible", OpenAICompatibleProvider)
    registry.register("ollama", _ollama)
    registry.register("decision_http", _imported_when_asked(
        "release_gate.decision_providers", "DecisionHTTPProvider"))
    registry.register("laya", _imported_when_asked(
        "release_gate.decision_providers.laya", "LayaProvider"))
    registry.register("jev", _imported_when_asked(
        "release_gate.decision_providers.jev", "JevProvider"))
    return registry


@dataclass(frozen=True)
class DiscoveryReport:
    """What entry-point discovery found. A failure is a row here, never a crash."""

    registered: Tuple[str, ...] = ()
    #: Already registered under that name; the earlier registration stands.
    shadowed: Tuple[str, ...] = ()
    #: name → why it could not be loaded.
    failed: Mapping[str, str] = field(default_factory=dict)


def _entry_points_in(group: str) -> Tuple[Any, ...]:
    from importlib import metadata
    try:
        return tuple(metadata.entry_points(group=group))
    except TypeError:  # an importlib.metadata without selection
        return tuple(metadata.entry_points().get(group, ()))


def discover_providers(registry: ProviderRegistry, *,
                       group: str = ENTRY_POINT_GROUP,
                       entry_points: Optional[Callable[[str], Any]] = None
                       ) -> DiscoveryReport:
    """Register every provider installed packages offer under `group`.

    A name already in the registry is left alone — a plugin cannot replace a
    transport this build ships, or another plugin, by being found later. A
    plugin that fails to import, or offers something that is not callable, is
    reported with the reason and skipped.
    """
    found = (entry_points or _entry_points_in)(group)
    registered, shadowed, failed = [], [], {}
    for entry in sorted(found, key=lambda e: str(getattr(e, "name", ""))):
        name = str(getattr(entry, "name", "") or "").strip().lower()
        if not name:
            continue
        if name in registry.names():
            shadowed.append(name)
            continue
        try:
            factory = entry.load()
        except Exception as exc:  # a broken plugin is a row in the report
            failed[name] = f"{type(exc).__name__}: {str(exc)[:200]}"
            continue
        if not callable(factory):
            failed[name] = f"{getattr(entry, 'value', name)} is not callable"
            continue
        registry.register(name, factory)
        registered.append(name)
    return DiscoveryReport(registered=tuple(registered), shadowed=tuple(shadowed),
                           failed=failed)


def _declared_number(env: Mapping[str, str], name: str, kind: type) -> Optional[Any]:
    text = (env.get(name) or "").strip()
    if not text:
        return None
    try:
        value = kind(text)
    except ValueError as exc:
        raise SemanticProviderConfigError(f"{name} must be a {kind.__name__}") from exc
    if value != value or value < 0 or (kind is int and value < 1):  # NaN, negative
        raise SemanticProviderConfigError(f"{name} must be positive")
    return value


def provider_from_env(environ: Optional[Mapping[str, str]] = None, *,
                      registry: Optional[ProviderRegistry] = None,
                      entry_points: Optional[Callable[[str], Any]] = None):
    """Build the configured provider, or raise saying what is missing."""
    env = os.environ if environ is None else environ
    name = (env.get("RG_SEMANTIC_PROVIDER") or "openai_compatible").strip().lower()
    model = (env.get("RG_SEMANTIC_MODEL") or "").strip()
    base_url = (env.get("RG_SEMANTIC_BASE_URL") or "").strip()
    if not model:
        raise SemanticProviderConfigError(
            "set RG_SEMANTIC_MODEL (and RG_SEMANTIC_BASE_URL). For a local model, e.g.\n"
            "  RG_SEMANTIC_BASE_URL=http://localhost:11434/v1  RG_SEMANTIC_MODEL=llama3.1")
    config: dict = {"model": model,
                    "api_key": (env.get("RG_SEMANTIC_API_KEY") or "").strip(),
                    "model_family": (env.get("RG_SEMANTIC_MODEL_FAMILY") or "").strip()}
    if base_url:
        config["base_url"] = base_url
    dialect = (env.get("RG_SEMANTIC_DIALECT") or "").strip()
    if dialect:
        config["dialect"] = dialect
    for key, var, kind in (("max_input_chars", "RG_SEMANTIC_MAX_INPUT_CHARS", int),
                           ("cost_per_call", "RG_SEMANTIC_COST_PER_CALL", float)):
        value = _declared_number(env, var, kind)
        if value is not None:
            config[key] = value
    chosen = registry or default_provider_registry()
    if name not in chosen.names():
        report = discover_providers(chosen, entry_points=entry_points)
        if name not in chosen.names():
            broken = report.failed.get(name)
            raise SemanticProviderConfigError(
                f"no provider named {name!r}"
                + (f": an installed plugin offers it and failed to load ({broken})"
                   if broken else f"; available: {', '.join(chosen.names())}"))
    return chosen.create(name, **config)


#: A panel member's keys, as the RG_SEMANTIC_* variable each stands for.
_PANEL_ENV = (("base_url", "RG_SEMANTIC_BASE_URL"),
              ("model_family", "RG_SEMANTIC_MODEL_FAMILY"),
              ("dialect", "RG_SEMANTIC_DIALECT"),
              ("cost_per_call", "RG_SEMANTIC_COST_PER_CALL"),
              ("max_input_chars", "RG_SEMANTIC_MAX_INPUT_CHARS"))


def panel_providers(panel: Any, environ: Optional[Mapping[str, str]] = None, *,
                    registry: Optional[ProviderRegistry] = None,
                    entry_points: Optional[Callable[[str], Any]] = None) -> Dict[str, Any]:
    """Each panel member's provider, built exactly as `provider_from_env` builds one.

    A member names the environment variable holding its key (`api_key_env`);
    the key is read from the environment and never from the panel file. Two
    members that are the same provider and model are refused: that is one
    verifier asked twice.
    """
    env = os.environ if environ is None else environ
    built: Dict[str, Any] = {}
    seen: Dict[Tuple[str, str], str] = {}
    for member in panel.members:
        config = member.config
        member_env = {"RG_SEMANTIC_PROVIDER": str(config.get("provider") or "openai_compatible"),
                      "RG_SEMANTIC_MODEL": str(config.get("model") or "")}
        for key, var in _PANEL_ENV:
            if config.get(key) not in (None, ""):
                member_env[var] = str(config[key])
        key_env = str(config.get("api_key_env") or "").strip()
        if key_env:
            if not env.get(key_env):
                raise SemanticProviderConfigError(
                    f"panel verifier {member.name!r}: the environment variable {key_env} "
                    "holds its key and is not set")
            member_env["RG_SEMANTIC_API_KEY"] = env[key_env]
        try:
            provider = provider_from_env(member_env, registry=registry,
                                         entry_points=entry_points)
        except SemanticVerifierError as exc:
            raise SemanticProviderConfigError(
                f"panel verifier {member.name!r}: {exc}") from exc
        identity = provider.identity()
        who = (identity.provider, identity.model)
        if who in seen:
            raise SemanticProviderConfigError(
                f"panel verifiers {seen[who]!r} and {member.name!r} are both "
                f"{identity.provider}:{identity.model}; one verifier asked twice is not "
                "a second opinion")
        seen[who] = member.name
        built[member.name] = provider
    return built


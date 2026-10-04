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

**Requests go only where they are pointed.** There is no default endpoint: a
semantic question is sent to the base URL the caller configured or to nothing.
An API key travels only in the request it authenticates and never into an
identity, an error message or a persisted assertion.

Config, for `provider_from_env`:

    RG_SEMANTIC_PROVIDER      openai_compatible (default) | ollama | a registered name
    RG_SEMANTIC_BASE_URL      required, e.g. http://localhost:11434/v1
    RG_SEMANTIC_MODEL         required
    RG_SEMANTIC_API_KEY       required for a non-local endpoint
    RG_SEMANTIC_DIALECT       optional: name the wire format explicitly
    RG_SEMANTIC_MODEL_FAMILY  optional: the model family, as you state it — it is
                              what lets the independence analysis group this
                              model's readings with its other output
"""

from __future__ import annotations

import json
import os
import socket
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Mapping, Optional

from release_gate.assurance.model_neutral import (DialectError, ModelDialect,
                                                  build_request, extract_text,
                                                  resolve_dialect)
from release_gate.assurance.semantic_verifier import (ProviderIdentity, ProviderRegistry,
                                                      ProviderReply, ProviderRequest,
                                                      ProviderTimeout, ProviderUnavailable,
                                                      SemanticVerifierError)

__all__ = [
    "OpenAICompatibleProvider",
    "SemanticProviderConfigError",
    "default_provider_registry",
    "provider_from_env",
]

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


class OpenAICompatibleProvider:
    """Any endpoint whose wire format `model_neutral` describes. Stdlib only."""

    def __init__(self, *, base_url: str, model: str, api_key: str = "",
                 dialect: Any = "", model_family: str = "", provider_name: str = "",
                 user_agent: str = "release-gate-semantic") -> None:
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

    def complete(self, request: ProviderRequest) -> ProviderReply:
        plan = build_request(self.dialect, base_url=self.base_url, model=self.model,
                             user=request.user, system=request.system,
                             api_key=self._api_key, temperature=request.temperature,
                             max_tokens=request.max_tokens)
        http = urllib.request.Request(
            plan.url, data=json.dumps(plan.body).encode("utf-8"),
            headers={**plan.headers, "User-Agent": self.user_agent})
        endpoint = _public_endpoint(self.base_url)
        try:
            # Looked up at call time, so a test that replaces it reaches this call.
            with urllib.request.urlopen(http, timeout=request.timeout_seconds) as resp:
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
        try:
            data = json.loads(raw)
        except ValueError as exc:
            raise ProviderUnavailable(f"{endpoint} answered with something that is "
                                      "not JSON") from exc
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


def default_provider_registry() -> ProviderRegistry:
    """The transports this build ships. Register more on the returned registry."""
    registry = ProviderRegistry()
    registry.register("openai_compatible", OpenAICompatibleProvider)
    registry.register("ollama", _ollama)
    return registry


def provider_from_env(environ: Optional[Mapping[str, str]] = None, *,
                      registry: Optional[ProviderRegistry] = None):
    """Build the configured provider, or raise saying what is missing."""
    env = os.environ if environ is None else environ
    name = (env.get("RG_SEMANTIC_PROVIDER") or "openai_compatible").strip()
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
    return (registry or default_provider_registry()).create(name, **config)

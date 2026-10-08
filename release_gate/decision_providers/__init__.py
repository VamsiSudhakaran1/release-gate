"""Decision-model providers: STATE, QUESTION, CHOICES in; a decision out.

A decision model — a System-One model built to pick among stated options rather
than to converse — answers the semantic verifier's question differently from a
chat model. It is given the packet rendered as a state, the claim as one
question, and the choices `established | violated | insufficient_evidence`, and
returns some of: a choice, a score per choice, a probability per choice, free
reasoning. The verifier (`release_gate/assurance/semantic_verifier.py`) checks
whatever comes back and fills in nothing that did not.

**One protocol, written down.** This module speaks `release-gate-decision/1`:

    GET  {base_url}/capabilities   → a capabilities object (optional)
    POST {base_url}/decide         ← {"protocol", "model", "state", "question",
                                      "choices", "state_hash"}
                                   → {"probabilities"?, "scores"?, "choice"?,
                                      "reasoning"?, "model_version"?, "metadata"?}

The capabilities object has the fields of `ProviderCapabilities`. An endpoint
that does not serve `/capabilities` is given release-gate's conservative default,
which says it is a default; one that serves something unreadable is treated the
same way, and the reason is kept on the provider for a reviewer to read.

**Named providers are optional modules.** `laya.py` and `jev.py` are imported
only when a provider of that name is asked for (`default_provider_registry`
names them; nothing imports them), so neither is a dependency of anything. They
speak this protocol: release-gate does not encode either system's own API, and a
deployment that exposes a different one is served by a small adapter that
translates to these two endpoints. A provider for a system this build does not
name is a class implementing `identity`, `capabilities` and `decide`, offered by
an installed package under the `release_gate.semantic_providers` entry point.

Nothing here decides anything about a release. The reply is a reading, and what
a reading does to a case is the resolution policy's, deterministically.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional

from release_gate.assurance.model_neutral import tool_calls_in
from release_gate.assurance.semantic_verifier import (DecisionReply, DecisionRequest,
                                                      ProviderCapabilities, ProviderIdentity,
                                                      ProviderInterface, ProviderUnavailable,
                                                      SemanticVerifierError, ToolCallRefused,
                                                      default_capabilities)
from release_gate.semantic_providers import (SemanticProviderConfigError, _is_local,
                                             _public_endpoint, exchange_json,
                                             operator_capabilities)

__all__ = [
    "DECISION_PROTOCOL",
    "DecisionHTTPProvider",
    "reply_from_json",
]

#: The wire protocol's name and version. Sent on every request and recorded as
#: the provider's dialect, so a persisted answer says how it was asked.
DECISION_PROTOCOL = "release-gate-decision/1"


class DecisionHTTPProvider:
    """A decision model behind `release-gate-decision/1`. Stdlib only."""

    #: The name an answer is recorded under. Subclasses name their system.
    provider_name = "decision_http"

    def __init__(self, *, base_url: str, model: str, api_key: str = "",
                 model_family: str = "", provider_name: str = "",
                 dialect: str = "", user_agent: str = "release-gate-decision",
                 capabilities_timeout: float = 10.0,
                 max_input_chars: Optional[int] = None,
                 cost_per_call: Optional[float] = None) -> None:
        if not str(base_url or "").strip():
            raise SemanticProviderConfigError(
                "a decision provider needs a base URL; release-gate has no default "
                "endpoint and sends nothing anywhere it was not pointed")
        if not str(model or "").strip():
            raise SemanticProviderConfigError(
                "a decision provider needs a model; release-gate does not pick one")
        if not api_key and not _is_local(base_url):
            raise SemanticProviderConfigError(
                f"{_public_endpoint(base_url)} is not local and no API key was given")
        if dialect and str(dialect).strip() != DECISION_PROTOCOL:
            raise SemanticProviderConfigError(
                f"a decision provider speaks {DECISION_PROTOCOL}; {dialect!r} names a "
                "chat wire format, which this provider cannot send")
        self.base_url = str(base_url).rstrip("/")
        self.model = str(model).strip()
        self.model_family = model_family
        self._api_key = api_key
        self.user_agent = user_agent
        self.capabilities_timeout = float(capabilities_timeout)
        self.max_input_chars = max_input_chars
        self.cost_per_call = cost_per_call
        if provider_name:
            self.provider_name = provider_name
        self._capabilities: Optional[ProviderCapabilities] = None
        #: Why the endpoint's own description was not used, when it was not.
        self.capabilities_note = ""

    @property
    def endpoint(self) -> str:
        return _public_endpoint(self.base_url)

    def _headers(self) -> Mapping[str, str]:
        return {"Authorization": f"Bearer {self._api_key}"} if self._api_key else {}

    def identity(self) -> ProviderIdentity:
        return ProviderIdentity(provider=self.provider_name, model=self.model,
                                model_family=self.model_family, endpoint=self.endpoint,
                                local=_is_local(self.base_url), dialect=DECISION_PROTOCOL,
                                dialect_recognised=True)

    def capabilities(self) -> ProviderCapabilities:
        """What the endpoint says it can do, asked once; the default when it cannot say."""
        if self._capabilities is None:
            self._capabilities = operator_capabilities(
                self._discover(), max_input_chars=self.max_input_chars,
                cost_per_call=self.cost_per_call)
        return self._capabilities

    def _discover(self) -> ProviderCapabilities:
        problem = ""
        try:
            data, _ = exchange_json(f"{self.base_url}/capabilities", headers=self._headers(),
                                    timeout=self.capabilities_timeout,
                                    endpoint=self.endpoint, user_agent=self.user_agent)
            found = ProviderCapabilities.from_dict(
                data, declared_by=f"{self.endpoint}/capabilities")
            if found.interface is not ProviderInterface.DECISION:
                problem = (f"/capabilities declared the {found.interface.value} "
                           f"interface; {DECISION_PROTOCOL} is a decision interface")
            else:
                return found
        except ProviderUnavailable as exc:
            problem = f"/capabilities was not served: {exc}"
        except SemanticVerifierError as exc:
            problem = f"/capabilities was unreadable: {exc}"
        self.capabilities_note = problem
        return default_capabilities(ProviderInterface.DECISION,
                                    local=_is_local(self.base_url))

    def decide(self, request: DecisionRequest) -> DecisionReply:
        body = {"protocol": DECISION_PROTOCOL, "model": self.model,
                "state": request.state, "question": request.question,
                "choices": list(request.choices), "state_hash": request.state_hash}
        data, raw = exchange_json(f"{self.base_url}/decide", body=body,
                                  headers=self._headers(),
                                  timeout=request.timeout_seconds,
                                  endpoint=self.endpoint, user_agent=self.user_agent)
        calls = tool_calls_in(data)
        if calls:
            raise ToolCallRefused(f"{self.endpoint} replied with a tool call at "
                                  f"{', '.join(calls)}")
        return reply_from_json(data, raw)


def reply_from_json(data: Any, raw: str = "") -> DecisionReply:
    """A decision body as a `DecisionReply`, every field as it arrived.

    Nothing is coerced into shape: a probabilities field that is a list stays a
    list, and the verifier refuses it with the reason. Absent stays absent.
    """
    if not isinstance(data, Mapping):
        return DecisionReply(raw=raw, metadata={"unparsed": type(data).__name__})
    model_version = data.get("model_version") or data.get("model") or ""
    return DecisionReply(probabilities=data.get("probabilities"),
                         scores=data.get("scores"), choice=data.get("choice"),
                         reasoning=data.get("reasoning") or "",
                         model_version=model_version if isinstance(model_version, str)
                         else str(model_version),
                         metadata=data.get("metadata") or {}, raw=raw)


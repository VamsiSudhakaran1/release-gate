"""
Agent client — invoke a real agent from a small spec string.

Three target types, chosen by prefix:

    py:module.path:callable      Import and call a Python function.
                                 Signature: fn(input: str, context: str) -> str
                                 (a one-arg fn(input) is also accepted).

    cmd:./run_agent.sh           Run a subprocess. The eval input is written to
                                 stdin; stdout (stripped) is the response. The
                                 context, if any, is passed as $RG_CONTEXT.

    http://host/agent            POST JSON {"input", "context"} to the URL.
    https://host/agent           The response may be plain text, or JSON with a
    http:https://host/agent      "response"/"output"/"text"/"content" field.
                                 Optional token usage is read from a "usage"
                                 object ({"input_tokens", "output_tokens"} or
                                 {"prompt_tokens", "completion_tokens"}).

A bare URL (starting with http) is treated as an http target. Everything is
stdlib-only — no third-party HTTP or agent SDK is required.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional


class AgentSpecError(ValueError):
    """Raised when an agent spec string cannot be parsed or resolved."""


@dataclass
class AgentResponse:
    """Result of a single agent invocation."""

    text: str
    latency_ms: float
    tokens_in: Optional[int] = None
    tokens_out: Optional[int] = None
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None


class AgentClient:
    """A callable wrapper around a real agent target."""

    HTTP_TIMEOUT = 30
    CMD_TIMEOUT = 60

    def __init__(self, kind: str, target: str, _fn: Optional[Callable] = None):
        self.kind = kind
        self.target = target
        self._fn = _fn

    # ------------------------------------------------------------------ #
    # Construction
    # ------------------------------------------------------------------ #
    @classmethod
    def from_spec(cls, spec: str) -> "AgentClient":
        """Build an AgentClient from a spec string (see module docstring)."""
        if not spec or not spec.strip():
            raise AgentSpecError("Empty agent spec")
        spec = spec.strip()

        if spec.startswith(("http://", "https://")):
            return cls("http", spec)
        if spec.startswith("http:"):
            # http:https://... or http:host/path
            return cls("http", spec[len("http:"):])
        if spec.startswith("cmd:"):
            target = spec[len("cmd:"):].strip()
            if not target:
                raise AgentSpecError("cmd: spec needs a command, e.g. cmd:./agent.sh")
            return cls("cmd", target)
        if spec.startswith("py:"):
            return cls("py", spec[len("py:"):].strip(), _fn=cls._resolve_python(spec[len("py:"):].strip()))

        raise AgentSpecError(
            f"Unrecognised agent spec '{spec}'. Use py:module:fn, cmd:./script, or an http(s) URL."
        )

    @staticmethod
    def _resolve_python(target: str) -> Callable:
        """Import and return the callable named by 'module.path:callable'."""
        if ":" not in target:
            raise AgentSpecError(
                f"py: spec needs module:callable form, got '{target}' "
                "(e.g. py:my_pkg.agent:handle)"
            )
        module_path, _, attr = target.partition(":")
        if not module_path or not attr:
            raise AgentSpecError(f"py: spec needs both module and callable, got '{target}'")
        try:
            import importlib

            module = importlib.import_module(module_path)
        except ImportError as exc:
            raise AgentSpecError(f"Could not import module '{module_path}': {exc}") from exc
        try:
            fn = getattr(module, attr)
        except AttributeError as exc:
            raise AgentSpecError(
                f"Module '{module_path}' has no attribute '{attr}'"
            ) from exc
        if not callable(fn):
            raise AgentSpecError(f"'{target}' is not callable")
        return fn

    # ------------------------------------------------------------------ #
    # Invocation
    # ------------------------------------------------------------------ #
    def invoke(self, agent_input: str, context: str = "") -> AgentResponse:
        """Call the agent once, capturing latency and any error."""
        start = time.perf_counter()
        try:
            if self.kind == "py":
                text, tin, tout = self._invoke_python(agent_input, context)
            elif self.kind == "cmd":
                text, tin, tout = self._invoke_cmd(agent_input, context)
            elif self.kind == "http":
                text, tin, tout = self._invoke_http(agent_input, context)
            else:  # pragma: no cover - guarded at construction
                raise AgentSpecError(f"Unknown agent kind '{self.kind}'")
            latency_ms = (time.perf_counter() - start) * 1000.0
            return AgentResponse(text=text, latency_ms=latency_ms, tokens_in=tin, tokens_out=tout)
        except Exception as exc:  # noqa: BLE001 - report every failure uniformly
            latency_ms = (time.perf_counter() - start) * 1000.0
            return AgentResponse(text="", latency_ms=latency_ms, error=str(exc))

    def _invoke_python(self, agent_input, context):
        try:
            out = self._fn(agent_input, context)
        except TypeError:
            # Allow single-argument callables fn(input).
            out = self._fn(agent_input)
        return str(out), None, None

    def _invoke_cmd(self, agent_input, context):
        env = dict(os.environ)
        if context:
            env["RG_CONTEXT"] = context
        # Parse the command with shlex and run with shell=False so the target
        # string is never handed to a shell for interpretation. shell=True would
        # let an eval input or a crafted target string inject arbitrary shell
        # commands (e.g. `cmd:./run.sh; rm -rf ~`).
        try:
            argv = shlex.split(self.target)
        except ValueError as exc:
            raise RuntimeError(f"invalid agent command {self.target!r}: {exc}")
        if not argv:
            raise RuntimeError("empty agent command")
        proc = subprocess.run(
            argv,
            shell=False,
            input=agent_input,
            capture_output=True,
            text=True,
            timeout=self.CMD_TIMEOUT,
            env=env,
        )
        if proc.returncode != 0:
            err = proc.stderr.strip() or f"exit code {proc.returncode}"
            raise RuntimeError(f"agent command failed: {err}")
        return proc.stdout.strip(), None, None

    def _invoke_http(self, agent_input, context):
        payload = json.dumps({"input": agent_input, "context": context}).encode("utf-8")
        req = urllib.request.Request(
            self.target,
            data=payload,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.HTTP_TIMEOUT) as resp:
                raw = resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"HTTP {exc.code} from agent endpoint") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"could not reach agent endpoint: {exc.reason}") from exc
        return self._parse_http_body(raw)

    @staticmethod
    def _parse_http_body(raw: str):
        raw = raw.strip()
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return raw, None, None  # plain-text response
        if isinstance(data, str):
            return data, None, None
        if isinstance(data, dict):
            for key in ("response", "output", "text", "content", "message"):
                if isinstance(data.get(key), str):
                    tin, tout = AgentClient._extract_usage(data.get("usage"))
                    return data[key], tin, tout
            tin, tout = AgentClient._extract_usage(data.get("usage"))
            return json.dumps(data), tin, tout
        return json.dumps(data), None, None

    @staticmethod
    def _extract_usage(usage: Any):
        if not isinstance(usage, dict):
            return None, None
        tin = usage.get("input_tokens", usage.get("prompt_tokens"))
        tout = usage.get("output_tokens", usage.get("completion_tokens"))
        return tin, tout

    # ------------------------------------------------------------------ #
    # Integration with EvalRunner
    # ------------------------------------------------------------------ #
    def as_eval_callable(self, profile: Optional["RuntimeProfile"] = None) -> Callable[[str, str], str]:
        """Return a callable(input, context) -> str for EvalRunner.

        If a RuntimeProfile is given, each call records its latency and any
        error there. Errors are surfaced to the eval runner as exceptions so
        the eval is marked failed.
        """
        def _call(agent_input: str, context: str = "") -> str:
            resp = self.invoke(agent_input, context)
            if profile is not None:
                profile.record(
                    resp.latency_ms,
                    error=not resp.ok,
                    tokens_in=resp.tokens_in,
                    tokens_out=resp.tokens_out,
                )
            if not resp.ok:
                raise RuntimeError(resp.error)
            return resp.text

        return _call

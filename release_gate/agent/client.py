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

Field mapping (the HTTP adapter)
--------------------------------
Most real agents already expose an HTTP endpoint, but rarely with the exact
{"input", "context"} / {"response"} shape above. Rather than make the user write
a wrapper, the URL may carry a `#`-fragment of client-side config that remaps
the request and response fields. The fragment is stripped before the request is
sent (fragments never leave the client), so it is a safe place for this. Keys:

    in=<path>          request field for the eval input   (default "input")
    ctx=<path>         request field for the context      (default "context")
    out=<path>         response field for the agent's text (default: search
                       response/output/text/content/message)
    usage_in=<path>    response field for input-token count
    usage_out=<path>   response field for output-token count
    method=<verb>      HTTP method                         (default POST)
    bearer_env=<VAR>   send "Authorization: Bearer $VAR"
    body.<path>=<val>  add a static field to the request body

Paths are dot-separated and may use integer segments to index into / build up
arrays, so nested request and response shapes are reachable. For example, an
OpenAI-compatible chat endpoint:

    https://api.openai.com/v1/chat/completions#\
      in=messages.0.content&out=choices.0.message.content&\
      bearer_env=OPENAI_API_KEY&body.model=gpt-4o-mini&\
      body.messages.0.role=user&\
      usage_in=usage.prompt_tokens&usage_out=usage.completion_tokens

or a LangServe `/invoke` endpoint:

    http://localhost:8000/agent/invoke#in=input.question&out=output
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple


def _path_segments(path: str) -> List[Any]:
    """Split a dotted path into segments, turning all-digit segments into ints so
    they index into / build up lists (e.g. 'messages.0.content')."""
    out: List[Any] = []
    for seg in path.split("."):
        out.append(int(seg) if seg.isdigit() else seg)
    return out


def _set_path(root: Dict[str, Any], path: str, value: Any) -> None:
    """Set value at a dotted path, building nested dicts/lists as needed.
    Integer segments create/extend lists; string segments create dicts."""
    segs = _path_segments(path)
    cur: Any = root
    for i, seg in enumerate(segs):
        last = i == len(segs) - 1
        nxt = segs[i + 1] if not last else None
        if isinstance(seg, int):
            if not isinstance(cur, list):  # pragma: no cover - guarded by caller shape
                raise ValueError(f"path segment {seg} expects a list")
            while len(cur) <= seg:
                cur.append(None)
            if last:
                cur[seg] = value
            else:
                if cur[seg] is None:
                    cur[seg] = [] if isinstance(nxt, int) else {}
                cur = cur[seg]
        else:
            if last:
                cur[seg] = value
            else:
                if cur.get(seg) is None:
                    cur[seg] = [] if isinstance(nxt, int) else {}
                cur = cur[seg]


def _get_path(root: Any, path: str) -> Any:
    """Read the value at a dotted path, or None if any segment is missing."""
    cur = root
    for seg in _path_segments(path):
        if isinstance(seg, int):
            if isinstance(cur, list) and 0 <= seg < len(cur):
                cur = cur[seg]
            else:
                return None
        elif isinstance(cur, dict):
            cur = cur.get(seg)
        else:
            return None
    return cur


def _coerce_scalar(raw: str) -> Any:
    """Coerce a static body value from its string form (true/false/null/number)."""
    low = raw.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    if low == "null":
        return None
    try:
        return int(raw)
    except ValueError:
        pass
    try:
        return float(raw)
    except ValueError:
        return raw


@dataclass
class HttpFieldMap:
    """Client-side request/response remapping for the HTTP adapter, parsed from
    the URL `#`-fragment. Defaults reproduce the original {"input","context"} /
    {"response"} contract, so a fragment-less URL behaves exactly as before."""

    in_path: str = "input"
    ctx_path: str = "context"
    out_path: Optional[str] = None
    usage_in_path: Optional[str] = None
    usage_out_path: Optional[str] = None
    method: str = "POST"
    bearer_env: Optional[str] = None
    static_body: Dict[str, str] = field(default_factory=dict)

    @classmethod
    def parse(cls, fragment: str) -> "HttpFieldMap":
        m = cls()
        if not fragment:
            return m
        # The fragment is form-encoded (a&b&c). Strip incidental whitespace that a
        # line-continued spec in docs/config may introduce.
        fragment = "".join(fragment.split())
        for key, value in urllib.parse.parse_qsl(fragment, keep_blank_values=False):
            if key == "in":
                m.in_path = value
            elif key == "ctx":
                m.ctx_path = value
            elif key == "out":
                m.out_path = value
            elif key == "usage_in":
                m.usage_in_path = value
            elif key == "usage_out":
                m.usage_out_path = value
            elif key == "method":
                m.method = value.upper()
            elif key == "bearer_env":
                m.bearer_env = value
            elif key.startswith("body."):
                m.static_body[key[len("body."):]] = value
            else:
                raise AgentSpecError(f"unknown http field-map key '{key}'")
        return m

    @property
    def is_default(self) -> bool:
        return self == HttpFieldMap()


def _estimate_tokens(text: str) -> int:
    """Coarse token estimate (~4 chars/token) for targets that don't report usage
    (local py:/cmd: agents). Used only to give cost characterization a signal —
    it shapes relative cost, it is not a billing figure."""
    return max(1, len(text or "") // 4)


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

    def __init__(self, kind: str, target: str, _fn: Optional[Callable] = None,
                 fieldmap: Optional[HttpFieldMap] = None):
        self.kind = kind
        self.target = target
        self._fn = _fn
        self.fieldmap = fieldmap or HttpFieldMap()

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
            return cls._http(spec)
        if spec.startswith("http:"):
            # http:https://... or http:host/path
            return cls._http(spec[len("http:"):])
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

    @classmethod
    def _http(cls, url: str) -> "AgentClient":
        """Build an http client, splitting off any `#`-fragment field map. The
        fragment is removed from the URL actually requested — it never leaves the
        client."""
        base, _, fragment = url.partition("#")
        if not base.startswith(("http://", "https://")):
            raise AgentSpecError(f"http target must be an http(s) URL, got '{base}'")
        return cls("http", base, fieldmap=HttpFieldMap.parse(fragment))

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
            import sys

            # When release-gate runs as an installed console script the current
            # working directory is not on sys.path, so a project-local module like
            # `examples.llm_agent` won't import. Add cwd to the front of the path so
            # `py:` specs resolve relative to where the user invoked the command.
            cwd = os.getcwd()
            if cwd not in sys.path:
                sys.path.insert(0, cwd)

            module = importlib.import_module(module_path)
        except ImportError as exc:
            raise AgentSpecError(
                f"Could not import module '{module_path}': {exc}. "
                f"Run from the project root (cwd is {os.getcwd()!r}); for "
                f"'examples.llm_agent' that means the directory containing 'examples/'."
            ) from exc
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
        text = str(out)
        # A local callable doesn't report token usage, but cost characterization
        # (loop-sim, the cost dimension) needs *some* signal. Estimate tokens from
        # text length (~4 chars/token) so a verbose/runaway agent honestly costs
        # more than a terse one. Coarse by design — it shapes cost, not billing.
        return text, _estimate_tokens(f"{agent_input} {context}"), _estimate_tokens(text)

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
        text = proc.stdout.strip()
        return text, _estimate_tokens(f"{agent_input} {context}"), _estimate_tokens(text)

    def _build_http_body(self, agent_input, context) -> Dict[str, Any]:
        """Assemble the request body from the field map: input, context (when
        non-empty), and any static body.<path> fields."""
        fm = self.fieldmap
        body: Dict[str, Any] = {}
        for path, raw in fm.static_body.items():
            _set_path(body, path, _coerce_scalar(raw))
        _set_path(body, fm.in_path, agent_input)
        if context:
            _set_path(body, fm.ctx_path, context)
        return body

    def _invoke_http(self, agent_input, context):
        fm = self.fieldmap
        payload = json.dumps(self._build_http_body(agent_input, context)).encode("utf-8")
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if fm.bearer_env:
            token = os.environ.get(fm.bearer_env)
            if not token:
                raise RuntimeError(
                    f"bearer_env={fm.bearer_env} is set in the spec but ${fm.bearer_env} is empty"
                )
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(
            self.target, data=payload, headers=headers, method=fm.method,
        )
        try:
            with urllib.request.urlopen(req, timeout=self.HTTP_TIMEOUT) as resp:
                raw = resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"HTTP {exc.code} from agent endpoint") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"could not reach agent endpoint: {exc.reason}") from exc
        return self._parse_http_body(raw, fm)

    @staticmethod
    def _parse_http_body(raw: str, fm: Optional["HttpFieldMap"] = None):
        fm = fm or HttpFieldMap()
        raw = raw.strip()
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return raw, None, None  # plain-text response
        if isinstance(data, str):
            return data, None, None

        # Explicit output path wins; usage paths, if given, override the default
        # "usage" object search.
        if fm.out_path is not None:
            text = _get_path(data, fm.out_path)
            if text is None:
                raise RuntimeError(
                    f"out={fm.out_path} not found in agent response "
                    f"(top-level keys: {sorted(data) if isinstance(data, dict) else type(data).__name__})"
                )
            tin, tout = AgentClient._mapped_usage(data, fm)
            return (text if isinstance(text, str) else json.dumps(text)), tin, tout

        if isinstance(data, dict):
            for key in ("response", "output", "text", "content", "message"):
                if isinstance(data.get(key), str):
                    tin, tout = AgentClient._mapped_usage(data, fm)
                    return data[key], tin, tout
            tin, tout = AgentClient._mapped_usage(data, fm)
            return json.dumps(data), tin, tout
        return json.dumps(data), None, None

    @staticmethod
    def _mapped_usage(data: Any, fm: "HttpFieldMap") -> Tuple[Any, Any]:
        """Token usage from explicit usage paths if the field map gives them,
        else the default "usage" object."""
        if fm.usage_in_path or fm.usage_out_path:
            tin = _get_path(data, fm.usage_in_path) if fm.usage_in_path else None
            tout = _get_path(data, fm.usage_out_path) if fm.usage_out_path else None
            return tin, tout
        return AgentClient._extract_usage(data.get("usage") if isinstance(data, dict) else None)

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

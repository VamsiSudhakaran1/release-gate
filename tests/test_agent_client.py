"""Tests for the live agent client (Phase 2)."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from release_gate.agent import AgentClient, AgentResponse, AgentSpecError, RuntimeProfile


# --------------------------------------------------------------------------- #
# Spec parsing
# --------------------------------------------------------------------------- #
def test_http_url_spec():
    c = AgentClient.from_spec("https://example.com/agent")
    assert c.kind == "http"
    assert c.target == "https://example.com/agent"


def test_http_prefixed_spec():
    c = AgentClient.from_spec("http:https://example.com/agent")
    assert c.kind == "http"
    assert c.target == "https://example.com/agent"


def test_cmd_spec():
    c = AgentClient.from_spec("cmd:./run_agent.sh")
    assert c.kind == "cmd"
    assert c.target == "./run_agent.sh"


def test_empty_spec_raises():
    with pytest.raises(AgentSpecError):
        AgentClient.from_spec("   ")


def test_unknown_spec_raises():
    with pytest.raises(AgentSpecError):
        AgentClient.from_spec("ftp://nope")


def test_cmd_without_command_raises():
    with pytest.raises(AgentSpecError):
        AgentClient.from_spec("cmd:")


def test_py_spec_needs_callable_form():
    with pytest.raises(AgentSpecError):
        AgentClient.from_spec("py:os")  # no :callable


def test_py_spec_missing_attr_raises():
    with pytest.raises(AgentSpecError):
        AgentClient.from_spec("py:os:does_not_exist_attr")


# --------------------------------------------------------------------------- #
# Python target invocation
# --------------------------------------------------------------------------- #
def test_py_target_two_arg(monkeypatch):
    import release_gate.agent as agent_pkg

    def fake_agent(inp, ctx):
        return f"got:{inp}|ctx:{ctx}"

    agent_pkg._test_agent = fake_agent  # type: ignore[attr-defined]
    c = AgentClient.from_spec("py:release_gate.agent:_test_agent")
    resp = c.invoke("hello", "world")
    assert resp.ok
    assert resp.text == "got:hello|ctx:world"
    assert resp.latency_ms >= 0


def test_py_target_one_arg():
    import release_gate.agent as agent_pkg

    agent_pkg._test_agent_one = lambda inp: inp.upper()  # type: ignore[attr-defined]
    c = AgentClient.from_spec("py:release_gate.agent:_test_agent_one")
    resp = c.invoke("hi", "ignored")
    assert resp.text == "HI"


def test_py_target_exception_captured():
    import release_gate.agent as agent_pkg

    def boom(inp, ctx):
        raise ValueError("kaboom")

    agent_pkg._test_boom = boom  # type: ignore[attr-defined]
    c = AgentClient.from_spec("py:release_gate.agent:_test_boom")
    resp = c.invoke("x")
    assert not resp.ok
    assert "kaboom" in resp.error


# --------------------------------------------------------------------------- #
# Command target invocation
# --------------------------------------------------------------------------- #
def test_cmd_target_echo():
    c = AgentClient.from_spec("cmd:cat")  # echoes stdin
    resp = c.invoke("ping-pong")
    assert resp.ok
    assert resp.text == "ping-pong"


def test_cmd_target_failure():
    # Commands run with shell=False, so use a real executable that exits nonzero.
    c = AgentClient.from_spec('cmd:python -c "import sys; sys.exit(3)"')
    resp = c.invoke("x")
    assert not resp.ok
    assert "failed" in resp.error


def test_cmd_target_context_env():
    # The context is exposed to the subprocess via the RG_CONTEXT env var (not
    # by shell-expanding it into the command string — shell=False).
    c = AgentClient.from_spec(
        'cmd:python -c "import os,sys; sys.stdout.write(os.environ.get(\'RG_CONTEXT\',\'\'))"'
    )
    resp = c.invoke("ignored", "the-context")
    assert resp.text == "the-context"


def test_cmd_target_no_shell_injection():
    # A shell metacharacter in the target must NOT be interpreted by a shell.
    # With shell=True this would create the file; with shell=False the whole
    # string after `echo` is just literal argv, so the file is never written.
    import os as _os
    import tempfile
    marker = _os.path.join(tempfile.gettempdir(), "rg_shell_injection_probe")
    if _os.path.exists(marker):
        _os.remove(marker)
    c = AgentClient.from_spec(f"cmd:echo hi; touch {marker}")
    c.invoke("x")
    assert not _os.path.exists(marker), "shell metacharacters were interpreted!"


# --------------------------------------------------------------------------- #
# HTTP body parsing
# --------------------------------------------------------------------------- #
def test_parse_http_plain_text():
    text, tin, tout = AgentClient._parse_http_body("just text")
    assert text == "just text"
    assert tin is None and tout is None


def test_parse_http_response_field():
    body = json.dumps({"response": "hi there", "usage": {"input_tokens": 5, "output_tokens": 7}})
    text, tin, tout = AgentClient._parse_http_body(body)
    assert text == "hi there"
    assert tin == 5 and tout == 7


def test_parse_http_openai_usage_keys():
    body = json.dumps({"output": "ok", "usage": {"prompt_tokens": 11, "completion_tokens": 3}})
    text, tin, tout = AgentClient._parse_http_body(body)
    assert text == "ok"
    assert tin == 11 and tout == 3


# --------------------------------------------------------------------------- #
# as_eval_callable + RuntimeProfile
# --------------------------------------------------------------------------- #
def test_as_eval_callable_records_profile():
    import release_gate.agent as agent_pkg

    agent_pkg._echo = lambda inp, ctx="": inp  # type: ignore[attr-defined]
    c = AgentClient.from_spec("py:release_gate.agent:_echo")
    profile = RuntimeProfile()
    fn = c.as_eval_callable(profile)
    assert fn("hello", "") == "hello"
    s = profile.summary()
    assert s["calls"] == 1
    assert s["errors"] == 0


def test_as_eval_callable_raises_on_error():
    import release_gate.agent as agent_pkg

    def boom(inp, ctx=""):
        raise RuntimeError("down")

    agent_pkg._boom2 = boom  # type: ignore[attr-defined]
    c = AgentClient.from_spec("py:release_gate.agent:_boom2")
    profile = RuntimeProfile()
    fn = c.as_eval_callable(profile)
    with pytest.raises(RuntimeError):
        fn("x", "")
    assert profile.summary()["errors"] == 1

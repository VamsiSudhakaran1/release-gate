"""Tests for the live agent client (Phase 2)."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from release_gate.agent import AgentClient, AgentResponse, AgentSpecError, RuntimeProfile
from release_gate.agent.client import HttpFieldMap, _get_path, _set_path


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
# HTTP field mapping (the adapter)
# --------------------------------------------------------------------------- #
def test_fragment_does_not_leak_into_target():
    c = AgentClient.from_spec("https://host/agent#in=prompt&out=reply")
    assert c.target == "https://host/agent"  # fragment stripped from the URL
    assert c.fieldmap.in_path == "prompt"
    assert c.fieldmap.out_path == "reply"


def test_default_fieldmap_when_no_fragment():
    c = AgentClient.from_spec("https://host/agent")
    assert c.fieldmap.is_default


def test_unknown_fieldmap_key_raises():
    with pytest.raises(AgentSpecError):
        AgentClient.from_spec("https://host/agent#bogus=1")


def test_set_and_get_nested_path():
    body = {}
    _set_path(body, "messages.0.content", "hi")
    _set_path(body, "messages.0.role", "user")
    assert body == {"messages": [{"content": "hi", "role": "user"}]}
    assert _get_path(body, "messages.0.content") == "hi"
    assert _get_path(body, "messages.5.content") is None
    assert _get_path(body, "nope.here") is None


def test_build_http_body_openai_shape():
    c = AgentClient.from_spec(
        "https://api/x#in=messages.0.content&body.model=gpt-4o-mini&body.messages.0.role=user"
    )
    body = c._build_http_body("hello", "")
    assert body["model"] == "gpt-4o-mini"
    assert body["messages"][0] == {"role": "user", "content": "hello"}


def test_build_http_body_context_omitted_when_empty():
    c = AgentClient.from_spec("https://host/a#in=q&ctx=c")
    assert c._build_http_body("x", "") == {"q": "x"}
    assert c._build_http_body("x", "ctx!") == {"q": "x", "c": "ctx!"}


def test_static_body_coerces_scalars():
    c = AgentClient.from_spec("https://host/a#body.temperature=0.5&body.stream=false&body.n=2")
    body = c._build_http_body("x", "")
    assert body["temperature"] == 0.5
    assert body["stream"] is False
    assert body["n"] == 2


def test_parse_http_out_path_nested():
    fm = HttpFieldMap.parse("out=choices.0.message.content")
    body = json.dumps({"choices": [{"message": {"content": "the answer"}}]})
    text, tin, tout = AgentClient._parse_http_body(body, fm)
    assert text == "the answer"


def test_parse_http_out_path_missing_raises():
    fm = HttpFieldMap.parse("out=choices.0.text")
    with pytest.raises(RuntimeError):
        AgentClient._parse_http_body(json.dumps({"choices": []}), fm)


def test_parse_http_mapped_usage_paths():
    fm = HttpFieldMap.parse(
        "out=choices.0.message.content&usage_in=usage.prompt_tokens&usage_out=usage.completion_tokens"
    )
    body = json.dumps({
        "choices": [{"message": {"content": "ok"}}],
        "usage": {"prompt_tokens": 12, "completion_tokens": 4},
    })
    text, tin, tout = AgentClient._parse_http_body(body, fm)
    assert text == "ok" and tin == 12 and tout == 4


def test_bearer_env_missing_raises_at_invoke(monkeypatch):
    monkeypatch.delenv("RG_TEST_TOKEN", raising=False)
    c = AgentClient.from_spec("https://host/a#bearer_env=RG_TEST_TOKEN")
    resp = c.invoke("x")
    assert not resp.ok
    assert "RG_TEST_TOKEN" in resp.error


def test_method_defaults_to_post_and_overridable():
    assert HttpFieldMap.parse("").method == "POST"
    assert HttpFieldMap.parse("method=put").method == "PUT"


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

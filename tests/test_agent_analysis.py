"""The AST analyzer must be precise: real risks flagged, look-alikes ignored."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from release_gate.agent_analysis import analyze_python


def titles(src):
    return [f["title"] for f in analyze_python(src, "x.py")]


# ── False positives that must NEVER be flagged ──────────────────────────────

def test_generic_run_invoke_not_llm():
    src = (
        "wizard.run()\n"
        "import subprocess\n"
        "subprocess.run(['git', 'clone', url])\n"
        "EvalRunner().run(evals, agent_callable=cb)\n"
        "result = LoopSimulator().run(scenarios)\n"
        "chain_thing.invoke(data)\n"   # not a known LLM var
    )
    assert "LLM call with no token ceiling" not in titles(src)
    assert "Dangerous execution sink" not in titles(src)


def test_eval_inside_string_not_flagged():
    src = 'msg = f"{n} critical eval(s) failed and exec( notes"\n'
    assert titles(src) == []


def test_os_system_clear_is_benign():
    src = "import os\nos.system('clear' if os.name != 'nt' else 'cls')\n"
    assert titles(src) == []


def test_subprocess_without_shell_not_a_sink():
    src = "import subprocess\nsubprocess.run(cmd_list)\n"
    assert "Dangerous execution sink" not in titles(src)


def test_llm_call_with_max_tokens_ok():
    src = (
        "from openai import OpenAI\n"
        "client = OpenAI()\n"
        "client.chat.completions.create(model='gpt-4', messages=m, max_tokens=500)\n"
    )
    assert "LLM call with no token ceiling" not in titles(src)


# ── True positives that MUST be flagged ─────────────────────────────────────

def test_real_openai_call_without_ceiling():
    src = (
        "from openai import OpenAI\n"
        "client = OpenAI()\n"
        "resp = client.chat.completions.create(model='gpt-4', messages=m)\n"
    )
    assert "LLM call with no token ceiling" in titles(src)


def test_eval_on_user_input_is_high():
    src = "def handler(user_input):\n    return eval(user_input)\n"
    fs = analyze_python(src, "x.py")
    assert any(f["title"] == "Dangerous execution sink" and f["severity"] == "high" for f in fs)


def test_os_system_dynamic_from_request():
    src = "def run(request):\n    os.system(request.cmd)\n"
    fs = analyze_python(src, "x.py")
    assert any(f["title"] == "Dangerous execution sink" for f in fs)


def test_subprocess_shell_true_dynamic():
    src = "import subprocess\ndef go(payload):\n    subprocess.run(payload, shell=True)\n"
    assert "Dangerous execution sink" in titles(src)


def test_fstring_system_prompt_injection():
    src = (
        "def chat(user_msg):\n"
        "    messages = [{'role': 'system', 'content': f'You are X. {user_msg}'}]\n"
    )
    assert "Interpolated system prompt (injection surface)" in titles(src)


def test_langchain_llm_var_invoke_flagged():
    src = (
        "from langchain_openai import ChatOpenAI\n"
        "llm = ChatOpenAI()\n"
        "out = llm.invoke(prompt)\n"
    )
    assert "LLM call with no token ceiling" in titles(src)


def test_dynamic_exec_agent_code_low_generic_ignored():
    # A dynamic exec we can't prove is tainted:
    #  - in AGENT code (file uses an LLM) → a quiet LOW nudge
    #  - in generic Python (no LLM) → NOT flagged (that's Bandit's job, not ours)
    agent = (
        "from openai import OpenAI\n"
        "c = OpenAI()\n"
        "c.chat.completions.create(model='x', messages=m, max_tokens=1)\n"
        "code = build()\n"
        "exec(code)\n"
    )
    generic = "code = build()\nexec(code)\n"
    a = analyze_python(agent, "x.py")
    assert any(f["title"] == "Dynamic execution sink (agent code)" and f["severity"] == "low" for f in a)
    assert not any("execution sink" in f["title"].lower() for f in analyze_python(generic, "x.py"))


# ── Regressions from the taOS maintainer's review (real false positives) ─────

def test_subprocess_popen_list_arg_not_flagged():
    src = (
        "import subprocess\n"
        "def launch(url, browser):\n"
        "    subprocess.Popen([browser, f'--app={url}'])\n"
    )
    assert "Dynamic execution sink" not in titles(src)
    assert "Dangerous execution sink" not in titles(src)


def test_method_named_exec_not_a_sink():
    # PocketFlow Node lifecycle: def exec(self, ...) is a method, not exec()
    src = (
        "class Node:\n"
        "    def exec(self, prep_res):\n"
        "        return prep_res\n"
    )
    assert "Dynamic execution sink" not in titles(src)
    assert "Dangerous execution sink" not in titles(src)


def test_os_popen_with_tainted_input_flagged_high():
    # os.popen reachable from user/model input → high (the agent-specific case)
    src = "import os\ndef run(user_input):\n    return os.popen(user_input).read()\n"
    fs = analyze_python(src, "x.py")
    assert any(f["title"] == "Dangerous execution sink" and f["severity"] == "high" for f in fs)


def test_secret_key_name_not_flagged():
    # SECRET = "REDDIT_TOKEN" is a lookup KEY NAME, not a credential (taOS).
    from release_gate.verify import _is_real_secret
    assert _is_real_secret('_REDDIT_TOKEN_SECRET = "REDDIT_TOKEN"') is False
    assert _is_real_secret('api_key = "sk-abc123def456ghi789xyz"') is True


def test_dummy_sequential_key_not_flagged():
    from release_gate.verify import _is_real_secret
    # sequential dummy used in a test that proves secrets are blocked
    assert _is_real_secret('mem.remember("never store sk-abcdefghijklmnopqrstuvwxyz123456")') is False
    assert _is_real_secret('api_key = "sk-proj-9aZ2kQ7mN4pL8vR1tY6wX3bC5dE0fG"') is True


def test_js_execsync_constant_command_not_flagged():
    from release_gate.verify import _js_exec_is_dynamic
    assert _js_exec_is_dynamic("execSync('git ls-files --cached', {cwd: d})") is False
    assert _js_exec_is_dynamic("exec(`rm -rf ${dir}`)") is True


def test_handler_name_and_demo_secret_not_flagged():
    from release_gate.verify import _is_real_secret
    assert _is_real_secret('TOKEN: "handle_skills_clawhub_get_token"') is False  # identifier
    assert _is_real_secret('JWT_SECRET = "production-demo-secret"') is False       # demo
    assert _is_real_secret('api_key = "sk-proj-9aZ2kQ7mN4pL8vR1tY6wX3bC5"') is True


def test_service_wrapper_named_llm_not_flagged():
    # llm = services.get("llm"); llm.complete(...) is an app wrapper, not a
    # resolvable SDK call — don't claim 'no token ceiling' on a name guess.
    src = (
        "def handle(services, args):\n"
        "    llm = services.get('llm')\n"
        "    return llm.complete(args.get('prompt', ''))\n"
    )
    assert "LLM call with no token ceiling" not in titles(src)


def test_resolved_llm_var_still_flagged():
    src = (
        "from langchain_openai import ChatOpenAI\n"
        "llm = ChatOpenAI()\n"
        "out = llm.invoke(prompt)\n"
    )
    assert "LLM call with no token ceiling" in titles(src)


def test_shell_command_clearing_env_not_a_secret():
    from release_gate.verify import _is_real_secret
    assert _is_real_secret('cmd = f\'set "ANTHROPIC_API_KEY=" && {tgt} /login\'') is False


def test_constant_interpolation_in_system_prompt_not_flagged():
    # f"{BROWSER_SYSTEM_MESSAGE}..." interpolates a constant, not user input
    src = 'm=[{"role":"system","content": f"{BROWSER_SYSTEM_MESSAGE}\\nNote"}]\n'
    assert "Interpolated system prompt (injection surface)" not in titles(src)


def test_js_execsync_bare_var_is_medium_interp_is_high():
    from release_gate.verify import _scan_js_file
    bare = _scan_js_file("a.js", "const r = execSync(cmd, {shell:true})\n")
    interp = _scan_js_file("b.js", "const r = execSync(`run ${userInput}`)\n")
    assert any(f["severity"] == "medium" for f in bare)
    assert any(f["severity"] == "high" for f in interp)


def test_placeholder_and_slug_secrets_rejected():
    from release_gate.verify import _is_real_secret
    assert _is_real_secret('token="xoxb-YOUR-BOT-TOKEN"') is False
    assert _is_real_secret('verify_token="my-secret-verify-token"') is False
    assert _is_real_secret('_DEFAULT_SECRET = "dev-secret-change-me"') is False
    assert _is_real_secret('t = "xoxb-9aZ2kQ7mN4pL8vR1tY6wX3bC"') is True


def test_js_only_truly_unbounded_loops_flagged():
    from release_gate.verify import _scan_js_file
    bounded = _scan_js_file("a.ts", "while (i < this.maxToolCalls) {\n  await llm.invoke(p)\n}\n")
    stream = _scan_js_file("b.ts", "for await (const c of stream) {\n  process(c)\n}\n")
    unbounded = _scan_js_file("c.ts", "while (true) {\n  await generateText(p)\n}\n")
    assert not any("Unbounded" in f["title"] for f in bounded)
    assert not any("Unbounded" in f["title"] for f in stream)
    assert any("Unbounded" in f["title"] for f in unbounded)


def test_injection_severity_strong_vs_generic():
    # generic/app-generated name → medium; clear user input → high
    generic = analyze_python(
        'def f(summary_text):\n m=[{"role":"system","content": f"S {summary_text}"}]\n', "x.py")
    strong = analyze_python(
        'def f(user_input):\n m=[{"role":"system","content": f"S {user_input}"}]\n', "x.py")
    g = [f for f in generic if "injection" in f["title"].lower()]
    s = [f for f in strong if "injection" in f["title"].lower()]
    assert g and g[0]["severity"] == "medium"
    assert s and s[0]["severity"] == "high"


def test_tooling_path_exec_sinks_filtered():
    import tempfile, os
    from pathlib import Path
    from release_gate.verify import scan_code_findings
    d = tempfile.mkdtemp()
    os.makedirs(Path(d) / "scripts")
    os.makedirs(Path(d) / "agent")
    (Path(d) / "scripts" / "build.mjs").write_text("const r = execSync(`cmd -v ${x}`)\n")
    (Path(d) / "agent" / "run.py").write_text("def f(user_input):\n    return eval(user_input)\n")
    titles = [f["title"] for f in scan_code_findings(Path(d))]
    # build-script exec sink dropped; the real agent-runtime eval kept
    assert not any(f["file"].startswith("scripts") for f in scan_code_findings(Path(d)))
    assert "Dangerous execution sink" in titles


def test_autogpt_style_unbounded_loop_flagged():
    src = (
        "from openai import OpenAI\n"
        "c = OpenAI()\n"
        "def run(goal):\n"
        "    ctx = goal\n"
        "    while True:\n"
        "        r = c.chat.completions.create(model='gpt-4', messages=[{'role':'user','content':ctx}])\n"
        "        ctx = r.choices[0].message.content\n"
        "        if 'DONE' in ctx: break\n"
    )
    assert "Unbounded loop around an LLM call" in titles(src)


def test_bounded_loop_not_flagged():
    src = (
        "from openai import OpenAI\n"
        "c = OpenAI()\n"
        "for i in range(10):\n"
        "    c.chat.completions.create(model='x', messages=m, max_tokens=50)\n"
    )
    assert "Unbounded loop around an LLM call" not in titles(src)


def test_secrets_in_test_files_are_fixtures():
    import tempfile, os
    from pathlib import Path
    from release_gate.verify import scan_code_findings, _is_test_path
    assert _is_test_path("autogpt_libs/auth/config_test.py")
    assert not _is_test_path("superagi/agent/output_handler.py")
    d = tempfile.mkdtemp()
    (Path(d) / "config_test.py").write_text('secret = "environment-secret-key-with-proper-length-123456"\n')
    (Path(d) / "app.py").write_text('api_key = "sk-proj-9aZ2kQ7mN4pL8vR1tY6wX3bC5dE0fG"\n')
    titles = [(f["file"], f["title"]) for f in scan_code_findings(Path(d))]
    assert not any("config_test" in fn for fn, t in titles)   # test fixture dropped
    assert any(t == "Hardcoded secret / API key" for fn, t in titles)  # real one kept


def test_broadened_deserialization_and_dynamic_sinks():
    # pickle/marshal/yaml.load/__import__ are code-execution sinks too, not just eval
    assert "Dangerous execution sink" in titles("def f(data):\n import pickle\n return pickle.loads(data)\n")
    assert "Dangerous execution sink" in titles("def f(payload):\n import yaml\n return yaml.load(payload)\n")
    assert "Dangerous execution sink" in titles("def f(request):\n import marshal\n return marshal.loads(request.body)\n")
    assert any("execution sink" in t.lower() for t in titles("def f(user_input):\n return __import__(user_input)\n"))


def test_sink_registry_false_positive_guards():
    # model.eval() (PyTorch), re.compile, yaml.safe_load, SafeLoader → NOT sinks
    assert not any("sink" in t.lower() for t in titles("model.eval()\n"))
    assert not any("sink" in t.lower() for t in titles("import re\nre.compile(pattern)\n"))
    assert not any("sink" in t.lower() for t in titles("import yaml\nyaml.safe_load(x)\n"))
    assert not any("sink" in t.lower() for t in titles("import yaml\nyaml.load(x, Loader=yaml.SafeLoader)\n"))


def test_agent_detection_beyond_import_names():
    import tempfile
    from pathlib import Path
    from release_gate.audit import build_report
    # An SDK not on the old list (Groq) — now detected
    g = tempfile.mkdtemp()
    (Path(g) / "a.py").write_text("from groq import Groq\nc=Groq()\nc.chat.completions.create(model='x', messages=m)\n")
    assert build_report(Path(g)).get("agent_detected") is True
    # A resolvable LLM call via an UNRECOGNIZED import → caught by the call fallback
    w = tempfile.mkdtemp()
    (Path(w) / "b.py").write_text("import wrap\nc=wrap.make()\nc.chat.completions.create(model='x', messages=m)\n")
    r = build_report(Path(w))
    assert r.get("agent_detected") is True
    # Genuinely no LLM → stays N/A (no false 'agent detected')
    n = tempfile.mkdtemp()
    (Path(n) / "c.py").write_text("import os\ndef f(x): return os.getcwd()\n")
    assert build_report(Path(n)).get("agent_detected") is False


def test_go_agent_detected_not_falsely_dismissed():
    import tempfile
    from pathlib import Path
    from release_gate.audit import build_report
    d = tempfile.mkdtemp()
    (Path(d) / "main.go").write_text(
        'const Model = "claude-sonnet-4.5"\nimport "github.com/anthropics/anthropic-sdk-go"\n')
    r = build_report(Path(d))
    cs = r.get("code_safety") or {}
    assert r.get("agent_detected") is True            # IS an agent (not dismissed)
    assert any("Go" in k for k in r.get("frameworks", {}))
    assert cs.get("applicable") is False              # but not statically scored
    assert cs.get("reason") == "language_not_static"  # honest reason, not a false pass
    # a pure-Go repo with no LLM signal stays not-an-agent
    d2 = tempfile.mkdtemp()
    (Path(d2) / "x.go").write_text('package main\nfunc main() { println("hi") }\n')
    assert build_report(Path(d2)).get("agent_detected") is False

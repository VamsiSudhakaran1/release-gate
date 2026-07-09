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


def test_js_exec_calibration_bare_low_config_medium_external_high():
    from release_gate.verify import _scan_js_file
    # bare variable, no interpolation, no external marker → LOW/inferred
    bare = _scan_js_file("a.js", "const r = execSync(cmd, {shell:true})\n")
    assert any(f["severity"] == "low" for f in bare)
    # interpolated with a genuine external-input marker (userInput) → HIGH/confirmed
    interp = _scan_js_file("b.js", "const r = execSync(`run ${userInput}`)\n")
    assert any(f["severity"] == "high" and f["basis"] == "confirmed" for f in interp)


def _findings(src):
    return analyze_python(src, "x.py")


def test_exec_of_llm_codegen_helper_output_is_flagged():
    # BlenderGPT pattern: exec() runs code returned by a locally-named LLM
    # codegen helper. The SDK call is hidden inside the helper, so a bare var
    # ('blender_code') used to make this RCE completely invisible.
    src = (
        "def generate_blender_code(prompt):\n"
        "    return call_model(prompt)\n"
        "blender_code = generate_blender_code(user_prompt)\n"
        "exec(blender_code, globals())\n"
    )
    hits = [f for f in _findings(src) if f["title"] == "Dangerous execution sink"]
    assert hits, "exec of codegen-helper output should be flagged"
    # Inferred (we can't see the SDK call inside the helper), not confirmed.
    assert hits[0]["severity"] == "medium" and hits[0]["basis"] == "inferred"


def test_exec_of_ask_gpt_helper_is_flagged():
    src = (
        "code = ask_gpt_for_script(task)\n"
        "exec(code)\n"
    )
    assert any(f["title"] == "Dangerous execution sink" for f in _findings(src))


def test_exec_of_non_llm_helper_not_flagged_by_helper_rule():
    # generate_uuid() is a generation verb but not a code/text noun — and nobody
    # exec()s a uuid. Must not be treated as codegen-helper output.
    src = (
        "token = generate_uuid()\n"
        "print(token)\n"
        "exec(compile(open(path).read(), path, 'exec'))\n"
    )
    # Nothing here may be attributed to a code-generation helper: generate_uuid
    # isn't codegen, and the compile(open(...)) exec is a bare dynamic sink.
    assert not any("code-generation helper" in (f.get("recommendation") or "")
                   for f in _findings(src))


def test_shadowed_eval_function_not_flagged():
    # RWKV-Runner: `def eval(model, request, body, ...)` ("evaluate the model"),
    # called with 8 positional args. Not the builtin — must not be flagged.
    src = (
        "def eval(model, request, body, completion_text, stream, stop, ids, flag):\n"
        "    return generate(model, body)\n"
        "async def route(request, body):\n"
        "    return eval(model, request, body, text, body.stream, body.stop, body.ids, True)\n"
    )
    assert not any("execution sink" in f["title"].lower() for f in _findings(src))


def test_eval_with_four_positional_args_is_not_builtin():
    # The builtin eval/exec take ≤3 positional args; 4+ means it's shadowed.
    src = "out = eval(model, request, body, stream)\n"
    assert not any("execution sink" in f["title"].lower() for f in _findings(src))


def test_real_builtin_eval_still_flagged():
    src = "def h(request):\n    return eval(request.body)\n"
    assert any(f["title"] == "Dangerous execution sink" for f in _findings(src))


def test_exec_with_empty_builtins_sandbox_demoted_to_inferred():
    # lollms custom-node editor: exec(req.code, {"__builtins__": {}}, scope).
    # A deliberate (if weak) sandbox — surface stays, but not a confirmed high.
    src = (
        "def run(req):\n"
        "    local_scope = {}\n"
        "    exec(req.code, {'__builtins__': {}}, local_scope)\n"
    )
    hits = [f for f in _findings(src) if f["title"] == "Dangerous execution sink"]
    assert hits, "still a surface, should be flagged"
    assert not any(f.get("basis") == "confirmed" and f.get("severity") in ("high", "critical")
                   for f in hits)


def test_exec_without_sandbox_still_confirmed_high():
    src = "def run(request):\n    exec(request.body)\n"
    hits = [f for f in _findings(src) if f["title"] == "Dangerous execution sink"]
    assert any(f.get("basis") == "confirmed" for f in hits)


def test_cli_args_shell_command_not_confirmed_high():
    # aider's /git handler: `cmd_git(self, args)` runs `subprocess.run("git "+args,
    # shell=True)`. `args` is the OPERATOR's own CLI input, not a remote RCE
    # surface — must never be asserted as a CONFIRMED high (that FP is what makes
    # a maintainer dismiss the whole report).
    src = (
        "import subprocess\n"
        "def cmd_git(self, args):\n"
        "    args = 'git ' + args\n"
        "    subprocess.run(args, shell=True)\n"
    )
    hits = [f for f in _findings(src) if f["title"] in
            ("Dangerous execution sink", "Dynamic execution sink (agent code)")]
    assert not any(f.get("basis") == "confirmed" and f.get("severity") in ("high", "critical")
                   for f in hits), "operator CLI args must not be a confirmed high"


def test_request_body_shell_still_confirmed_high():
    # The genuinely-external counterpart stays confirmed HIGH.
    src = (
        "import os\n"
        "def handler(request):\n"
        "    os.system('run ' + request.body)\n"
    )
    hits = [f for f in _findings(src) if f["title"] == "Dangerous execution sink"]
    assert any(f.get("basis") == "confirmed" for f in hits)


def test_js_bounded_retry_loop_not_flagged_unbounded():
    # VoltAgent pattern: while(true) with a retry ceiling + throw exit is bounded.
    from release_gate.verify import _scan_js_file
    src = (
        "while (true) {\n"
        "  const res = await generateText(params);\n"
        "  if (shouldRetryMiddleware(error, retryCount, maxRetries)) {\n"
        "    retryCount += 1;\n"
        "    continue;\n"
        "  }\n"
        "  throw error;\n"
        "}\n"
    )
    assert not any(f["title"] == "Unbounded loop around an LLM call"
                   for f in _scan_js_file("agent.ts", src))


def test_js_truly_unbounded_loop_still_flagged():
    from release_gate.verify import _scan_js_file
    src = "while (true) {\n  const res = await generateText(params);\n  ctx.push(res);\n}\n"
    assert any(f["title"] == "Unbounded loop around an LLM call"
               for f in _scan_js_file("agent.ts", src))


def test_placeholder_and_slug_secrets_rejected():
    from release_gate.verify import _is_real_secret
    assert _is_real_secret('token="xoxb-YOUR-BOT-TOKEN"') is False
    assert _is_real_secret('verify_token="my-secret-verify-token"') is False
    assert _is_real_secret('_DEFAULT_SECRET = "dev-secret-change-me"') is False
    assert _is_real_secret('t = "xoxb-9aZ2kQ7mN4pL8vR1tY6wX3bC"') is True


def test_hex_uuid_and_uppercase_placeholder_not_secrets():
    # Real-world false positives caught auditing intentkit / llama_index / fast-agent.
    from release_gate.verify import _is_real_secret
    # Ethereum zero address — matched only because "token" is in the var name.
    assert _is_real_secret(
        'gas_token = "0x0000000000000000000000000000000000000000"') is False
    assert _is_real_secret('token = "0xdeadbeefcafebabe1234567890abcdef"') is False
    # UPPERCASE-hyphenated placeholders / phonetic demo values.
    assert _is_real_secret(
        'search_service_api_key = "YOUR-AZURE-SEARCH-SERVICE-ADMIN-KEY"') is False
    assert _is_real_secret('EXPECTED_SECRET = "WHISKEY-TANGO-FOXTROT-42"') is False
    # A bare UUID default is an identifier format, not a live key.
    assert _is_real_secret(
        'api_key="a0f8a6ba-c32f-4407-af0c-169f1915490c"') is False
    # A genuine provider key is still caught.
    assert _is_real_secret('api_key = "sk-proj-9aZ2kQ7mN4pL8vR1tY6wX3bC5"') is True


def test_http_header_name_not_a_secret():
    # bug caught auditing livekit/agents: HEADER_WORKER_TOKEN = "X-LiveKit-Worker-Token"
    from release_gate.verify import _is_real_secret
    assert _is_real_secret('HEADER_WORKER_TOKEN = "X-LiveKit-Worker-Token"') is False
    assert _is_real_secret('API_KEY_HEADER = "X-Api-Key"') is False
    assert _is_real_secret('h = "Content-Type"') is False
    # a genuine key is still caught
    assert _is_real_secret('api_key = "sk-proj-9aZ2kQ7mN4pL8vR1tY6wX3bC5"') is True


def test_pickle_over_local_ipc_pipe_not_flagged():
    # livekit ipc/log_queue.py pattern: data off a local duplex is trusted transport.
    src = (
        "import pickle\n"
        "class H:\n"
        "    def _monitor(self):\n"
        "        while True:\n"
        "            data = self._duplex.recv_bytes()\n"
        "            record = pickle.loads(data)\n"
    )
    assert "Dangerous execution sink" not in titles(src)


def test_pickle_from_network_still_flagged():
    # Regression guard: pickle of genuinely external input stays HIGH.
    src = (
        "import pickle\n"
        "def handle(request):\n"
        "    return pickle.loads(request.body)\n"
    )
    assert "Dangerous execution sink" in titles(src)


def test_public_telemetry_keys_not_secrets():
    # Caught auditing aider: analytics keys ship in client code, not secrets.
    from release_gate.verify import _is_real_secret
    assert _is_real_secret('mixpanel_project_token = "6da9a43058a5d1b9f3353153921fb04d"') is False
    assert _is_real_secret('posthog_project_api_key = "phc_99T7muzafUMMZX15H8XePbMSreEUzahHbtWjy3l5Qbv"') is False
    assert _is_real_secret('GA_MEASUREMENT_ID = "G-ABC123DEF4"') is False
    # a genuine provider key is still caught
    assert _is_real_secret('api_key = "sk-proj-9aZ2kQ7mN4pL8vR1tY6wX3bC5"') is True


def test_yaml_load_with_safeloader_subclass_not_flagged():
    # Caught auditing haystack: class YamlLoader(yaml.SafeLoader) is safe.
    src = (
        "import yaml\n"
        "class YamlLoader(yaml.SafeLoader):\n    pass\n"
        "def load(data):\n    return yaml.load(data, Loader=YamlLoader)\n"
    )
    assert "Dangerous execution sink" not in titles(src)


def test_yaml_load_with_unsafe_loader_still_flagged():
    # Regression: a genuinely unsafe loader on external input stays flagged.
    src = (
        "import yaml\n"
        "def load(payload):\n    return yaml.load(payload, Loader=yaml.FullLoader)\n"
    )
    assert "Dangerous execution sink" in titles(src)


def test_secret_in_examples_dir_is_dropped():
    # A hardcoded secret in example/demo tooling is fixture data, not a leak.
    from release_gate.verify import _finalize_findings
    f = {"severity": "high", "title": "Hardcoded secret / API key",
         "file": "examples/mcp/demo/example.py", "line": 19}
    assert _finalize_findings([f]) == []


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


def test_while_true_nested_in_bounded_for_not_unbounded():
    # LightAgent pattern: `while True` inside `for _ in range(max_retry)` with a
    # reachable exit — the outer loop caps re-entry, so it's NOT a runaway.
    src = (
        "from openai import OpenAI\n"
        "c = OpenAI()\n"
        "def run(max_retry):\n"
        "    for _ in range(max_retry):\n"
        "        while True:\n"
        "            r = c.chat.completions.create(model='x', messages=m, max_tokens=5)\n"
        "            if done: return r\n"
        "            break\n"
    )
    assert "Unbounded loop around an LLM call" not in titles(src)


def test_outermost_while_true_still_unbounded():
    # No enclosing bounded loop → still the AutoGPT runaway (regression guard).
    src = (
        "from openai import OpenAI\n"
        "c = OpenAI()\n"
        "def run(goal):\n"
        "    while True:\n"
        "        r = c.chat.completions.create(model='x', messages=m, max_tokens=5)\n"
        "        if 'DONE' in r: break\n"
    )
    assert "Unbounded loop around an LLM call" in titles(src)


# ── Spread-params token ceiling (the `create(**params)` framework pattern) ───

def test_kwargs_param_dict_without_token_ceiling_flagged():
    src = (
        "class A:\n"
        "    def run(self):\n"
        "        self.chat_params = {\n"
        "            'model': self.model,\n"
        "            'messages': messages,\n"
        "            'stream': False,\n"
        "        }\n"
        "        return self.client.chat.completions.create(**self.chat_params)\n"
    )
    assert "LLM call parameter dict has no output ceiling" in titles(src)


def test_kwargs_param_dict_with_token_key_not_flagged():
    src = (
        "class A:\n"
        "    def run(self):\n"
        "        self.chat_params = {'model': self.model, 'messages': m, 'max_tokens': 256}\n"
        "        return self.client.chat.completions.create(**self.chat_params)\n"
    )
    assert "LLM call parameter dict has no output ceiling" not in titles(src)


def test_kwargs_param_dict_token_key_set_via_subscript_not_flagged():
    src = (
        "class A:\n"
        "    def run(self, max_tokens=None):\n"
        "        self.chat_params = {'model': self.model, 'messages': m}\n"
        "        if max_tokens is not None:\n"
        "            self.chat_params['max_tokens'] = max_tokens\n"
        "        return self.client.chat.completions.create(**self.chat_params)\n"
    )
    assert "LLM call parameter dict has no output ceiling" not in titles(src)


def test_unresolvable_spread_stays_quiet():
    # We can't see inside **kwargs — must not fabricate a finding.
    src = (
        "from openai import OpenAI\n"
        "c = OpenAI()\n"
        "def run(**kwargs):\n"
        "    return c.chat.completions.create(**kwargs)\n"
    )
    ts = titles(src)
    assert "LLM call parameter dict has no output ceiling" not in ts
    assert "LLM call with no token ceiling" not in ts


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
    # yaml.load on a strong external name (payload) stays a HIGH execution sink.
    assert "Dangerous execution sink" in titles("def f(payload):\n import yaml\n return yaml.load(payload)\n")
    # pickle.loads on a GENERIC-named param ('data') is now MEDIUM/inferred — its
    # source isn't visible, and internal pickling is ubiquitous (livekit/MetaGPT
    # FP class). It's flagged, but not asserted as a confirmed RCE.
    ts = titles("def f(data):\n import pickle\n return pickle.loads(data)\n")
    assert "Deserialization of unverified data" in ts
    assert "Dangerous execution sink" not in ts


def test_pickle_of_strong_external_name_stays_high():
    # request.body is an unambiguous external source → still a HIGH exec sink.
    fs = analyze_python("def h(request):\n import pickle\n return pickle.loads(request.body)\n", "x.py")
    assert any(f["title"] == "Dangerous execution sink" and f["severity"] == "high" for f in fs)


def test_pickle_of_confirmed_model_output_stays_high():
    src = (
        "from openai import OpenAI\nc = OpenAI()\n"
        "import pickle\n"
        "def go(m):\n"
        "    reply = c.chat.completions.create(model='gpt-4', messages=m, max_tokens=5)\n"
        "    return pickle.loads(reply)\n"
    )
    fs = analyze_python(src, "x.py")
    assert any(f["title"] == "Dangerous execution sink" and f["severity"] == "high" for f in fs)


def test_internal_serialization_pickle_is_medium_inferred():
    # MetaGPT serialize.py pattern: deserialize_message(message_ser) round-trips
    # the framework's own Message — provenance not visible → MEDIUM/inferred.
    src = (
        "import pickle\n"
        "def deserialize_message(message_ser):\n"
        "    return pickle.loads(message_ser)\n"
    )
    fs = analyze_python(src, "x.py")
    assert any(f["title"] == "Deserialization of unverified data"
               and f["severity"] == "medium" and f["basis"] == "inferred" for f in fs)
    assert not any(f["title"] == "Dangerous execution sink" for f in fs)
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


def test_go_agent_detected_but_flagged_not_statically_analyzed():
    import tempfile
    from pathlib import Path
    from release_gate.audit import build_report
    d = tempfile.mkdtemp()
    (Path(d) / "main.go").write_text(
        'package main\nconst Model = "claude-sonnet-4.5"\n'
        'import "github.com/anthropics/anthropic-sdk-go"\n')
    r = build_report(Path(d))
    cs = r.get("code_safety") or {}
    assert r.get("agent_detected") is True                    # it IS an agent
    assert any("Go" in k for k in r.get("frameworks", {}))    # detected as Go
    assert cs.get("applicable") is False                      # but not a misleading score
    assert cs.get("reason") == "language_not_static"          # honest reason


# ── FP-calibration fixes (corpus: crewAI, gpt-researcher, vercel/ai, gemini) ─

def test_non_text_endpoints_not_token_ceiling():
    # DALL-E / embeddings calls on an LLM client have no token-ceiling concept.
    src = (
        "from openai import OpenAI\n"
        "client = OpenAI()\n"
        "client.images.generate(model='dall-e-3', prompt=desc)\n"
        "client.embeddings.create(input=texts, model='text-embedding-3-small')\n"
        "client.audio.transcriptions.create(file=f, model='whisper-1')\n"
    )
    assert titles(src) == []


def test_ctor_declared_ceiling_caps_calls():
    # LangChain-style clients take the ceiling at construction time.
    src = (
        "from langchain_openai import ChatOpenAI\n"
        "llm = ChatOpenAI(model='gpt-4o', max_tokens=512)\n"
        "llm.invoke(messages)\n"
    )
    assert "LLM call with no token ceiling" not in titles(src)
    # …but a ceiling-less constructor still flags the call.
    src2 = (
        "from langchain_openai import ChatOpenAI\n"
        "llm = ChatOpenAI(model='gpt-4o')\n"
        "llm.invoke(messages)\n"
    )
    assert "LLM call with no token ceiling" in titles(src2)


def test_opaque_config_object_stays_quiet():
    # google-genai carries the ceiling inside config=GenerateContentConfig(…):
    # absence is unprovable through an opaque object, so no finding.
    src = (
        "from google import genai\n"
        "client = genai.Client()\n"
        "client.models.generate_content(model=m, contents=c, config=cfg)\n"
    )
    assert "LLM call with no token ceiling" not in titles(src)
    # A LITERAL dict config without a ceiling is provable → still flagged.
    src2 = (
        "from google import genai\n"
        "client = genai.Client()\n"
        "client.models.generate_content(model=m, contents=c, config={'temperature': 1})\n"
    )
    assert "LLM call with no token ceiling" in titles(src2)


def test_counter_bounded_while_true_not_runaway():
    src = (
        "from openai import OpenAI\n"
        "client = OpenAI()\n"
        "while True:\n"
        "    r = client.chat.completions.create(messages=m, max_tokens=50)\n"
        "    attempts += 1\n"
        "    if attempts >= max_retries:\n"
        "        break\n"
    )
    assert "Unbounded loop around an LLM call" not in titles(src)
    # A model-controlled break is NOT a cap — still a runaway.
    src2 = (
        "from openai import OpenAI\n"
        "client = OpenAI()\n"
        "while True:\n"
        "    r = client.chat.completions.create(messages=m, max_tokens=50)\n"
        "    if 'DONE' in r:\n"
        "        break\n"
    )
    assert "Unbounded loop around an LLM call" in titles(src2)


def test_hint_matching_is_token_based_not_substring():
    # `context` must not hit "text", `database` must not hit "data".
    src = "import openai\ndef f(context, database):\n    eval(context)\n    os.system(database)\n"
    fs = analyze_python(src, "x.py")
    assert not any(f["title"] == "Dangerous execution sink" for f in fs)
    # Real hints still match through snake_case: user_input → eval is high.
    src2 = "def f(user_input):\n    eval(user_input)\n"
    fs2 = analyze_python(src2, "x.py")
    assert any(f["title"] == "Dangerous execution sink" and f["severity"] == "high" for f in fs2)


def test_inferred_exec_sink_is_medium_not_high():
    # A name-inferred (unproven) flow must not assert HIGH — same calibration
    # as deserialization sinks. `reply` hints model output but isn't assigned
    # from an LLM call in scope.
    src = "import openai\ndef f(reply):\n    eval(reply)\n"
    fs = [f for f in analyze_python(src, "x.py") if f["title"] == "Dangerous execution sink"]
    assert fs and fs[0]["severity"] == "medium" and fs[0]["basis"] == "inferred"


def test_system_prompt_composition_not_injection():
    # Constant-assigned vars (if/elif chains of literals) are the developer's text.
    src = (
        'if mode == "brief":\n'
        '    guidance = "Be brief."\n'
        "else:\n"
        '    guidance = "Be thorough."\n'
        'msg = {"role": "system", "content": f"You are an evaluator. {guidance}"}\n'
    )
    assert titles(src) == []
    # Prompt-material names (agent_role_prompt, auto_agent_instructions) are
    # prompt composition, not an injection surface (the gpt-researcher FP class).
    src2 = 'msg = {"role": "system", "content": f"{agent_role_prompt}"}\n'
    assert titles(src2) == []
    src3 = 'msg = {"role": "system", "content": f"{prompt_family.auto_agent_instructions()}"}\n'
    assert titles(src3) == []


def test_system_prompt_severity_calibration():
    # Clearly external input into a system prompt is still HIGH.
    fs = analyze_python(
        'msg = {"role": "system", "content": f"Answer about {user_query}"}\n', "x.py")
    assert any(f["severity"] == "high" for f in fs)
    # A generic developer-config identifier rates only LOW.
    fs2 = analyze_python(
        'msg = {"role": "system", "content": f"Extract the {field_name} field."}\n', "x.py")
    inj = [f for f in fs2 if "system prompt" in f["title"]]
    assert inj and inj[0]["severity"] == "low"


def test_js_type_test_files_are_excluded():
    from release_gate.verify import _finalize_findings
    f = {"file": "packages/ai/src/generate-text/stream-text.test-d.ts",
         "line": 1, "title": "LLM call with no token ceiling", "severity": "low"}
    assert _finalize_findings([f]) == []


def test_js_ceiling_recognizes_v5_spelling_and_full_arg_span():
    from release_gate.verify import _scan_js_file
    # maxOutputTokens (AI SDK v5) deeper than 5 lines into the call still counts.
    src = (
        "const r = await generateText({\n"
        "  model: openai('gpt-4o'),\n"
        "  system: sys,\n"
        "  prompt: p,\n"
        "  temperature: 0.2,\n"
        "  topP: 0.9,\n"
        "  maxRetries: 2,\n"
        "  maxOutputTokens: 800,\n"
        "});\n"
    )
    assert not any(f["title"] == "LLM call with no token ceiling"
                   for f in _scan_js_file("a.ts", src))
    # A genuinely uncapped call is still flagged.
    src2 = "const r = await generateText({ model: m, prompt: p });\n"
    assert any(f["title"] == "LLM call with no token ceiling"
               for f in _scan_js_file("b.ts", src2))


def test_js_defsites_comments_and_strings_not_calls():
    from release_gate.verify import _scan_js_file
    src = (
        "export async function generateText(options) {\n"   # definition, not a call
        "  return doGenerate(options);\n"
        "}\n"
        "/** @example\n"
        " * generateText({ model, prompt })\n"                # JSDoc example
        " */\n"
        "const doc = `\n"
        "  generateText({ model, prompt })\n"                 # docs template string
        "`;\n"
    )
    assert not any(f["title"] == "LLM call with no token ceiling"
                   for f in _scan_js_file("a.ts", src))

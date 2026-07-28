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


def test_eval_of_openai_content_extraction_is_confirmed_high():
    """Regression: the canonical OpenAI text extraction
    `resp.choices[0].message.content` reaching eval() must grade HIGH/confirmed —
    the provenance is visible in scope. Previously the subscript chain lost the
    taint and it decayed to LOW/inferred despite being a textbook model-output RCE."""
    src = (
        "from openai import OpenAI\n"
        "client = OpenAI()\n"
        "def answer(q):\n"
        "    resp = client.chat.completions.create(model='gpt-4o', messages=[])\n"
        "    expr = resp.choices[0].message.content\n"
        "    return eval(expr)\n"
    )
    fs = analyze_python(src, "agent.py")
    exec_findings = [f for f in fs if f["title"] == "Dangerous execution sink"]
    assert exec_findings, "expected a confirmed exec sink"
    f = exec_findings[0]
    assert f["severity"] == "high" and f.get("basis") == "confirmed"


def test_eval_of_non_model_chain_stays_inferred():
    """Negative control for the extraction-taint fix: a field pulled off a plain
    config object is NOT model output — eval() on it must stay inferred, not get
    upgraded to a confirmed model-output RCE."""
    src = (
        "def run(cfg):\n"
        "    v = cfg.settings[0].value\n"
        "    return eval(v)\n"
    )
    fs = analyze_python(src, "x.py")
    assert not any(f.get("basis") == "confirmed" for f in fs)


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


def test_js_exec_calibration_agent_scoped():
    from release_gate.verify import _scan_js_file
    # Re-scoped (gemini-cli): a dynamic execSync in a NON-agent utility/CLI file is
    # generic shell hygiene (Bandit's lane), not an agent risk → SILENT.
    util = _scan_js_file("a.js", "const r = execSync(`taskkill ${pid}`)\n")
    assert not any("execution sink" in f["title"].lower() for f in util)
    # The same call in AGENT code (the file calls an LLM), source unproven → a quiet
    # LOW nudge, not a score-moving medium.
    agent = _scan_js_file(
        "b.js", "const x = await model.generate({prompt});\nconst r = execSync(`taskkill ${pid}`)\n")
    assert any(f["severity"] == "low" and "agent code" in f["title"].lower() for f in agent)
    # External request/user input reaching the sink → HIGH/confirmed, any file.
    interp = _scan_js_file("c.js", "const r = execSync(`run ${userInput}`)\n")
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


# ── New coverage: Node vm.* sinks + model-source system-prompt injection ────

def test_js_vm_escape_sinks_flagged():
    from release_gate.verify import _scan_js_file
    # vm.runInNewContext on external input is an RCE sink (Node sandbox escape).
    hi = _scan_js_file("a.ts", "vm.runInNewContext(`${userInput}`, ctx);\n")
    assert any(f["severity"] == "high" and "execution sink" in f["title"].lower() for f in hi)
    # A constant argument to vm.compileFunction is not a sink.
    const = _scan_js_file("b.ts", "vm.compileFunction('return 1');\n")
    assert not any("execution sink" in f["title"].lower() for f in const)


def test_js_injection_covers_model_output_not_just_request():
    from release_gate.verify import _scan_js_file

    def inj(src):
        return [f for f in _scan_js_file("x.ts", src)
                if "system prompt" in f["title"].lower()]

    # External request input into a system-prompt content → HIGH.
    hi = inj("const messages=[{role:'system', content:`Answer ${req.body.q}`}];\n")
    assert hi and hi[0]["severity"] == "high"
    # Model/tool output into a system prompt → MEDIUM (new coverage; the old
    # check only saw req/params/body).
    md = inj("const messages=[{role:'system', content:`Prior: ${toolResult}`}];\n")
    assert md and md[0]["severity"] == "medium"
    # Vercel AI SDK top-level `system:` param with external input → HIGH.
    sysp = inj("await generateText({ system:`You are ${req.body.persona}`, prompt:p });\n")
    assert sysp and sysp[0]["severity"] == "high"


def test_js_injection_precision_guards_hold():
    from release_gate.verify import _scan_js_file

    def has_inj(src):
        return any("system prompt" in f["title"].lower()
                   for f in _scan_js_file("x.ts", src))

    # A var literally named `content` building a file/skill body — not a message.
    assert not has_inj("const content = `name: ${skill.name}\n${skill.content}`;\n")
    # A UI renderer's content: field with no role:'system' — not a message.
    assert not has_inj("return { content: `${inputText}\n${formatValue(part.output)}` };\n")
    # content: in a USER-role message — not a system-prompt surface.
    assert not has_inj("const messages=[{role:'user', content:`${req.body.q}`}];\n")
    # An HTTP error string interpolating response.status — not a prompt at all.
    assert not has_inj("throw new Error(`API error: ${response.status}`);\n")
    # Developer's own material composed into a system prompt — not flagged.
    assert not has_inj("const messages=[{role:'system', content:`Be helpful. ${persona}`}];\n")


def test_js_system_prompt_classifies_interpolation_not_prose():
    """A system prompt that mentions 'input'/'content' in its PROSE while
    interpolating a benign ${new Date()} must not be flagged (the mem0 FP).
    Classification looks only at the code inside ${...}, never the prose."""
    from release_gate.verify import _scan_js_file
    mem0 = (
        'export function f(parsedMessages) {\n'
        '  const systemPrompt = `You are an Organizer. Extract facts from the input data.\n'
        '  - Today is ${new Date().toISOString().split("T")[0]}.`;\n'
        '  const userPrompt = `Input:\\n${parsedMessages}`;\n'
        '  return [systemPrompt, userPrompt];\n'
        '}'
    )
    assert not any("system prompt" in f["title"].lower() for f in _scan_js_file("index.ts", mem0))
    # External input into a system prompt is still HIGH…
    hi = _scan_js_file("a.ts", 'const systemPrompt = `Hi ${req.body.text}`;')
    assert any(f["severity"] == "high" and "system prompt" in f["title"].lower() for f in hi)
    # …and model/tool output stays MEDIUM.
    md = _scan_js_file("b.ts", 'const system = `Ctx: ${completion.choices[0].message.content}`;')
    assert any(f["severity"] == "medium" and "system prompt" in f["title"].lower() for f in md)


# ── RG-ACTION-001: net-new shell-command sinks (widened exec catalog) ─────────

def test_subprocess_string_command_fstring_from_input_is_flagged():
    # A command STRING built with an f-string (no list argv) from user input is a
    # shell-shaped sink even without shell=True (cmd on Windows; one edit from
    # injection). Bare `subprocess.run(cmd_list)` stays quiet (a list is safe).
    src = "import subprocess\ndef run(user_input):\n    subprocess.run(f'ls {user_input}')\n"
    hits = [f for f in _findings(src) if f["title"] == "Dangerous execution sink"]
    assert hits and hits[0]["severity"] == "high"


def test_subprocess_string_command_concat_is_flagged():
    src = "import subprocess\ndef run(request):\n    subprocess.check_output('grep ' + request.q)\n"
    assert any(f["title"] == "Dangerous execution sink" and f["severity"] == "high"
               for f in _findings(src))


def test_subprocess_constant_string_command_stays_quiet():
    assert "Dangerous execution sink" not in titles("import subprocess\nsubprocess.run('ls -l')\n")


def test_subprocess_getoutput_dynamic_from_input_is_flagged():
    # getoutput/getstatusoutput ALWAYS run via the shell — flagged unconditionally
    # once the argument is a proven-tainted value.
    src = "import subprocess\ndef run(request):\n    return subprocess.getoutput(request.body)\n"
    assert any(f["title"] == "Dangerous execution sink" and f["severity"] == "high"
               for f in _findings(src))


def test_commands_getoutput_dynamic_from_input_is_flagged():
    src = "import commands\ndef run(request):\n    return commands.getoutput(request.cmd)\n"
    assert any(f["title"] == "Dangerous execution sink" for f in _findings(src))


def test_subprocess_getoutput_confirms_through_model_extraction():
    # Composes with the model-response taint: resp.choices[0].message.content into
    # a shell sink is a confirmed HIGH (the agent-RCE-via-shell path).
    src = ("from openai import OpenAI\n"
           "def run(c):\n"
           "    resp = c.chat.completions.create(messages=m)\n"
           "    cmd = resp.choices[0].message.content\n"
           "    return subprocess.getoutput(cmd)\n")
    hits = [f for f in _findings(src) if f["title"] == "Dangerous execution sink"]
    assert hits and hits[0]["severity"] == "high" and hits[0]["basis"] == "confirmed"


# ── RG-PROMPT-002: instruction/data separation (untrusted → system channel) ──

def test_retrieval_result_in_system_prompt_is_confirmed_high():
    # The textbook indirect-injection surface: RAG context placed in the SYSTEM
    # role. Keyed on provenance (get_relevant_documents), so confirmed/HIGH.
    src = ("def build(q):\n"
           "    docs = retriever.get_relevant_documents(q)\n"
           "    return [{'role':'system','content': f'Answer using: {docs}'}]\n")
    hits = [f for f in _findings(src) if f["rule_id"] == "RG-PROMPT-002"]
    assert hits and hits[0]["severity"] == "high" and hits[0]["basis"] == "confirmed"


def test_http_body_in_system_prompt_is_flagged():
    # resp = requests.get(...); body = resp.text  → body inherits untrusted taint.
    src = ("import requests\n"
           "def build(url):\n"
           "    resp = requests.get(url)\n"
           "    body = resp.text\n"
           "    return [{'role':'system','content': body}]\n")
    assert any(f["rule_id"] == "RG-PROMPT-002" for f in _findings(src))


def test_tool_return_in_system_message_ctor_is_flagged():
    # LangChain SystemMessage(...) is the instruction channel; a @tool return in it
    # is indirect injection.
    src = ("from langchain.schema import SystemMessage\n"
           "@tool\n"
           "def fetch(q):\n    return q\n"
           "def build():\n"
           "    data = fetch('a')\n"
           "    return SystemMessage(content=data)\n")
    assert any(f["rule_id"] == "RG-PROMPT-002" for f in _findings(src))


def test_similarity_search_indexed_into_system_prompt_is_flagged():
    # Propagation through indexing: hits = store.similarity_search(q); ctx = hits[0]
    src = ("def build(q, store):\n"
           "    hits = store.similarity_search(q)\n"
           "    ctx = hits[0].page_content\n"
           "    return [{'role':'system','content': f'Context: {ctx}'}]\n")
    assert any(f["rule_id"] == "RG-PROMPT-002" for f in _findings(src))


def test_retrieval_in_user_turn_is_the_correct_pattern_no_finding():
    # The FIX: retrieved content in a delimited USER turn is correct → no finding.
    src = ("def build(q):\n"
           "    docs = retriever.get_relevant_documents(q)\n"
           "    return [{'role':'user','content': f'{docs}'}]\n")
    assert not any(f["rule_id"] == "RG-PROMPT-002" for f in _findings(src))


def test_developer_constant_system_prompt_stays_quiet_for_prompt_002():
    # Developer-authored material is not untrusted provenance — RG-PROMPT-002 quiet.
    src = ("SYSTEM = 'you are a helpful assistant'\n"
           "def build():\n"
           "    return [{'role':'system','content': f'{SYSTEM}'}]\n")
    assert not any(f["rule_id"] == "RG-PROMPT-002" for f in _findings(src))


def test_prompt_002_supersedes_prompt_001_on_same_node():
    # When content is provenance-untrusted, we emit the confirmed 002, not the
    # name-hint 001 — one finding, the stronger one.
    src = ("def build(q):\n"
           "    docs = retriever.get_relevant_documents(q)\n"
           "    return [{'role':'system','content': f'{docs}'}]\n")
    ids = {f["rule_id"] for f in _findings(src)}
    assert "RG-PROMPT-002" in ids and "RG-PROMPT-001" not in ids


# ── P1 tier: consequential-action sinks + secret egress + taint-aware deser ───

_LLM = "from openai import OpenAI\nc = OpenAI()\n"
_MODEL = ("    r = c.chat.completions.create(messages=m)\n"
          "    v = r.choices[0].message.content\n")


def _action(src):
    return [f for f in _findings(src) if f["rule_id"].startswith(("RG-ACTION", "RG-SECRET", "RG-EXEC"))]


# RG-ACTION-002 — SSRF / egress
def test_ssrf_model_controlled_url_is_confirmed_high():
    src = _LLM + "import requests\ndef go(m):\n" + _MODEL + "    return requests.get(v)\n"
    hits = [f for f in _findings(src) if f["rule_id"] == "RG-ACTION-002"]
    assert hits and hits[0]["severity"] == "high" and hits[0]["basis"] == "confirmed"


def test_ssrf_constant_base_tainted_path_is_demoted_medium():
    # Model output into only the PATH segment of a constant scheme/host → path
    # injection, not host-controlled SSRF → demoted to medium.
    src = _LLM + "import requests\ndef go(m):\n" + _MODEL + "    return requests.get(f'https://api.co/{v}')\n"
    hits = [f for f in _findings(src) if f["rule_id"] == "RG-ACTION-002"]
    assert hits and hits[0]["severity"] == "medium"


def test_ssrf_user_input_url_is_out_of_scope():
    # Generic user-input SSRF (not model output) is Bandit's lane, not ours —
    # firing on it across an LLM framework's connectors is the FP class we avoid.
    src = _LLM + "import requests\ndef go(request):\n    return requests.get(request.url)\n"
    assert not any(f["rule_id"] == "RG-ACTION-002" for f in _findings(src))


def test_ssrf_constant_url_stays_quiet():
    src = _LLM + "import requests\ndef go():\n    return requests.get('https://api.co/health')\n"
    assert not any(f["rule_id"] == "RG-ACTION-002" for f in _findings(src))


def test_ssrf_not_flagged_in_non_agent_code_with_bare_arg():
    # A plain library file (no LLM, no model/tool taint) — generic egress is
    # Bandit's job, not ours. A bare, unproven arg must not fire.
    src = "import requests\ndef fetch(u):\n    return requests.get(u)\n"
    assert not any(f["rule_id"] == "RG-ACTION-002" for f in _findings(src))


# RG-ACTION-003 — filesystem
def test_fs_delete_model_path_is_confirmed_high():
    src = _LLM + "import os\ndef go(m):\n" + _MODEL + "    os.remove(v)\n"
    hits = [f for f in _findings(src) if f["rule_id"] == "RG-ACTION-003"]
    assert hits and hits[0]["severity"] == "high"


def test_fs_write_model_content_to_fixed_path_is_medium():
    src = _LLM + "from pathlib import Path\ndef go(m):\n" + _MODEL + "    Path('/data/o.txt').write_text(v)\n"
    hits = [f for f in _findings(src) if f["rule_id"] == "RG-ACTION-003"]
    assert hits and hits[0]["severity"] == "medium"


def test_fs_constant_path_stays_quiet():
    src = _LLM + "import os\ndef go():\n    os.remove('/tmp/fixed.lock')\n"
    assert not any(f["rule_id"] == "RG-ACTION-003" for f in _findings(src))


# RG-ACTION-004 — SQL
def test_sql_model_output_interpolated_is_high():
    src = _LLM + "def go(cur, m):\n" + _MODEL + "    cur.execute(f'SELECT * FROM t WHERE x={v}')\n"
    hits = [f for f in _findings(src) if f["rule_id"] == "RG-ACTION-004"]
    assert hits and hits[0]["severity"] == "high"


def test_sql_parameterized_query_stays_quiet():
    src = _LLM + "def go(cur, val):\n    cur.execute('SELECT * FROM t WHERE x=?', (val,))\n"
    assert not any(f["rule_id"] == "RG-ACTION-004" for f in _findings(src))


# RG-SECRET-002 — secret / PII → prompt → provider
def test_secret_hardcoded_key_into_prompt_is_high():
    src = ("from openai import OpenAI\nc = OpenAI()\n"
           "KEY = 'sk-proj-ABCDEFGHIJKLMNOP1234'\n"
           "def go():\n"
           "    return c.chat.completions.create(messages=[{'role':'user','content': f'use {KEY}'}])\n")
    hits = [f for f in _findings(src) if f["rule_id"] == "RG-SECRET-002"]
    assert hits and hits[0]["severity"] == "high" and hits[0]["basis"] == "confirmed"


def test_secret_env_var_into_prompt_is_medium():
    src = ("import os\nfrom openai import OpenAI\nc = OpenAI()\n"
           "def go():\n"
           "    tok = os.environ['DB_PASSWORD']\n"
           "    return c.chat.completions.create(messages=[{'role':'user','content': f'{tok}'}])\n")
    hits = [f for f in _findings(src) if f["rule_id"] == "RG-SECRET-002"]
    assert hits and hits[0]["severity"] == "medium"


def test_secret_used_as_auth_is_not_flagged():
    # The FP control: a key passed as auth (api_key=) is not prompt egress.
    src = ("from openai import OpenAI\n"
           "KEY = 'sk-proj-ABCDEFGHIJKLMNOP1234'\n"
           "c = OpenAI(api_key=KEY)\n"
           "def go():\n"
           "    return c.chat.completions.create(messages=[{'role':'user','content':'hi'}])\n")
    assert not any(f["rule_id"] == "RG-SECRET-002" for f in _findings(src))


# RG-EXEC-004 — taint-aware deserialization upgrade
def test_network_body_into_pickle_is_confirmed_high():
    # HTTP body → pickle.loads: what was an inferred medium is now confirmed high,
    # because the untrusted network origin is visible in scope.
    src = ("import requests, pickle\n"
           "def go(url):\n"
           "    resp = requests.get(url)\n"
           "    return pickle.loads(resp.content)\n")
    hits = [f for f in _findings(src) if f["title"] == "Dangerous execution sink"]
    assert hits and hits[0]["severity"] == "high" and hits[0]["basis"] == "confirmed"


# ── P2 tier: RG-PARSE-001 (parse reliability) + RG-TOOL-001 / RG-GATE-001 ─────

def test_parse_unguarded_model_output_is_low_advisory():
    src = _LLM + "import json\ndef go(m):\n" + _MODEL + "    return json.loads(v)\n"
    hits = [f for f in _findings(src) if f["rule_id"] == "RG-PARSE-001"]
    assert hits and hits[0]["severity"] == "low"


def test_parse_inside_try_is_guarded_no_finding():
    src = (_LLM + "import json\ndef go(m):\n" + _MODEL +
           "    try:\n        return json.loads(v)\n    except Exception:\n        return None\n")
    assert not any(f["rule_id"] == "RG-PARSE-001" for f in _findings(src))


def test_parse_of_non_model_input_stays_quiet():
    # Model-scoped: a plain json.loads of a param is not this rule's concern.
    assert not any(f["rule_id"] == "RG-PARSE-001"
                   for f in _findings("import json\ndef go(s):\n    return json.loads(s)\n"))


def test_parse_literal_eval_of_model_output_is_flagged():
    src = _LLM + "import ast\ndef go(m):\n" + _MODEL + "    return ast.literal_eval(v)\n"
    assert any(f["rule_id"] == "RG-PARSE-001" for f in _findings(src))


def test_tool_irreversible_delete_without_gate_is_medium():
    src = "import os\n@tool\ndef cleanup(path):\n    os.remove(path)\n"
    hits = [f for f in _findings(src) if f["rule_id"] == "RG-GATE-001"]
    assert hits and hits[0]["severity"] == "medium"


def test_tool_irreversible_send_without_gate_is_medium():
    src = "@tool\ndef notify(addr, body):\n    return mailer.send_email(addr, body)\n"
    assert any(f["rule_id"] == "RG-GATE-001" for f in _findings(src))


def test_tool_irreversible_with_confirm_gate_is_low_tool_not_gate():
    # Gated → the informational RG-TOOL-001, never the escalated RG-GATE-001.
    src = ("import os\n@tool\ndef cleanup(path, confirm=False):\n"
           "    if not confirm:\n        return 'need confirm'\n    os.remove(path)\n")
    ids = {f["rule_id"] for f in _findings(src)}
    assert "RG-TOOL-001" in ids and "RG-GATE-001" not in ids


def test_read_only_tool_is_not_flagged():
    src = "@tool\ndef lookup(q):\n    return db.query(q)\n"
    assert not any(f["rule_id"] in ("RG-TOOL-001", "RG-GATE-001") for f in _findings(src))


def test_irreversible_action_in_non_tool_function_is_not_flagged():
    # RG-TOOL-001/GATE-001 are scoped to declared @tool functions — a plain
    # delete helper is the RG-ACTION-003 lane, not the tool-authority lane.
    src = "import os\ndef cleanup(path):\n    os.remove(path)\n"
    assert not any(f["rule_id"] in ("RG-TOOL-001", "RG-GATE-001") for f in _findings(src))


def test_subprocess_list_concatenation_argv_is_not_a_string_command():
    # Regression (hermes-agent FP): `subprocess.run(pip_cmd + ["install", *args])`
    # and `Popen([cmd] + extra)` are safe list-argv concatenation, no shell — a
    # BinOp first arg must NOT be misread as a built command string.
    lazy = ("import subprocess\ndef go(target_args, pip_cmd, specs):\n"
            "    subprocess.run(pip_cmd + ['install', *target_args, *specs])\n")
    acp = ("import subprocess\ndef go(self):\n"
           "    subprocess.Popen([self._acp_command] + self._acp_args)\n")
    assert "Dangerous execution sink" not in titles(lazy)
    assert "Dangerous execution sink" not in titles(acp)


def test_hmac_verified_pickle_is_not_flagged():
    # AutoGPT FP: `payload = _verify_and_strip(cached_bytes); pickle.loads(payload)`
    # is the sign-on-write / verify-on-read pattern (HMAC-signed Redis cache) — a
    # deliberate integrity guard, not untrusted-deserialization RCE. The engine
    # classified `payload` as external purely from the name hint; recognizing the
    # verify helper suppresses it.
    src = ("import pickle\n"
           "def _get_from_redis(redis_key):\n"
           "    cached_bytes = _get_redis().get(redis_key)\n"
           "    payload = _verify_and_strip(cached_bytes)\n"
           "    if payload is None:\n"
           "        return None\n"
           "    return pickle.loads(payload)\n")
    assert not any("execution sink" in f["title"].lower() or "eserial" in f["title"]
                   for f in analyze_python(src, "cache.py"))


def test_unguarded_pickle_of_request_still_high():
    # Recall guard: without a verify step, pickle of request input is still RCE.
    src = "import pickle\ndef h(request):\n    return pickle.loads(request.data)\n"
    assert any(f["title"] == "Dangerous execution sink" and f["severity"] == "high"
               for f in analyze_python(src, "x.py"))


def test_verify_helper_does_not_whitewash_eval():
    # A verify step guards DESERIALIZATION, not code execution — eval still fires.
    src = "def go(c):\n    payload = verify_signature(c)\n    return eval(payload)\n"
    assert any(f["title"] == "Dangerous execution sink" for f in analyze_python(src, "x.py"))


def test_js_scraped_content_in_user_turn_not_flagged_as_system_prompt():
    # firecrawl FP: a constant {role:"system"} object immediately before a
    # {role:"user"} object whose content interpolates scraped markdown. The user
    # turn is the CORRECT place for untrusted text — must not read as a system
    # prompt just because a system role appears earlier in the array.
    from release_gate.verify import _scan_js_file
    code = ('export function build(args) {\n'
            '  return [\n'
            '    { role: "system", content: EXTRACTOR_SYSTEM },\n'
            '    { role: "user", content: `${args.markdownPreview}### HTML\\n${args.anchorHtml}` },\n'
            '  ];\n'
            '}\n')
    assert not any("system prompt" in f["title"].lower() for f in _scan_js_file("p.ts", code))


def test_js_external_input_in_system_turn_still_high():
    from release_gate.verify import _scan_js_file
    code = 'const m = [{ role: "system", content: `You are X. ${req.body.text}` }];'
    fs = _scan_js_file("p.ts", code)
    assert any("system prompt" in f["title"].lower() and f["severity"] == "high" for f in fs)


def test_hmac_guard_clause_dill_not_flagged():
    # langflow FP: dill.loads gated by an `if not hmac.compare_digest(): return`
    # clause in the same function — the verify-then-load pattern where the payload
    # is a slice, not a var assigned from a verify helper.
    src = ("import dill, hmac\n"
           "async def get(self, key):\n"
           "    value = await self._client.get(key)\n"
           "    tag, payload = value[:32], value[32:]\n"
           "    if not hmac.compare_digest(tag, self._tag(key, payload)):\n"
           "        return CACHE_MISS\n"
           "    return dill.loads(payload)\n")
    assert not any("execution sink" in f["title"].lower() for f in analyze_python(src, "cache.py"))


def test_compile_for_validation_not_flagged():
    # langflow FP: compile() used to validate syntax (no exec) does not execute.
    src = ("import ast\n"
           "def validate_code(code):\n"
           "    tree = ast.parse(code)\n"
           "    compile(ast.Module(body=tree.body, type_ignores=[]), '<string>', 'exec')\n"
           "    return True\n")
    assert not any("execution sink" in f["title"].lower() for f in analyze_python(src, "validate.py"))


def test_compile_then_exec_still_high():
    # Recall guard: compile() whose output is exec()'d in the same function is a
    # real code-execution sink.
    src = ("def build(func_body):\n"
           "    compiled = compile(func_body, '<string>', 'exec')\n"
           "    exec(compiled, globals(), {})\n")
    assert any(f["title"] == "Dangerous execution sink" and f["severity"] == "high"
               for f in analyze_python(src, "flow.py"))

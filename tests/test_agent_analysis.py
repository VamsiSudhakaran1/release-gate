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


def test_dynamic_exec_without_taint_is_medium():
    # exec on a non-constant, non-obviously-tainted local → medium, not high
    src = "code = build()\nexec(code)\n"
    fs = analyze_python(src, "x.py")
    assert any(f["title"] == "Dynamic execution sink" for f in fs)

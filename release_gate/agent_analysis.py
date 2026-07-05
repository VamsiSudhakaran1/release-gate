"""AST-based agent-risk analysis for Python.

This is the engine behind Agent Code Safety. It is deliberately *not* a grep:
it parses the source, resolves which objects are actually LLM clients (via
imports + constructor assignments), inspects real call arguments, and does a
light intra-procedural taint pass so it can tell:

  * `client.chat.completions.create(...)`  (a real LLM call)  ✔ flag if no max_tokens
    from  `wizard.run()` / `subprocess.run()` / `EvalRunner().run()`  ✘ never flag
  * `eval(user_input)` / `os.system(cmd)` where `cmd` is dynamic  ✔ flag
    from  `os.system('clear')` / the string `"eval(s) failed"`     ✘ never flag
  * an f-string system prompt that interpolates a tainted value   ✔ flag

Precision over recall: when the analyzer can't prove a real risk, it stays
quiet. A finding you can click through to and trust beats ten you can't.

Returns findings in the same shape as release_gate.verify._finding.
"""
from __future__ import annotations

import ast
import re
from typing import Any, Dict, List, Optional, Set, Tuple

# ── Known LLM SDK surface ────────────────────────────────────────────────────
LLM_IMPORT_ROOTS = {
    "openai", "anthropic", "cohere", "litellm", "ollama", "groq", "mistralai",
    "together", "google", "vertexai", "langchain", "langchain_openai",
    "langchain_anthropic", "langchain_community", "langchain_core",
    "llama_index", "llamaindex", "boto3",  # boto3 only treated as LLM via bedrock client name
    "dspy", "instructor", "haystack", "semantic_kernel", "smolagents", "agno",
    "phi", "pydantic_ai", "transformers",
}
# Constructors that yield an LLM/chat client instance.
LLM_CONSTRUCTORS = {
    "OpenAI", "AsyncOpenAI", "AzureOpenAI", "AsyncAzureOpenAI",
    "Anthropic", "AsyncAnthropic", "AnthropicBedrock",
    "ChatOpenAI", "ChatAnthropic", "ChatCohere", "ChatGroq", "ChatLiteLLM",
    "ChatOllama", "ChatVertexAI", "ChatGoogleGenerativeAI", "ChatMistralAI",
    "Cohere", "Groq", "Mistral", "LiteLLM", "GenerativeModel",
}
# Terminal call attributes that are unambiguous LLM invocations on ANY object.
STRONG_LLM_CALLS = {"create", "acreate", "create_message", "generate_content"}
# Terminal attributes that are LLM calls ONLY when the receiver is a known LLM
# client/var (otherwise they're generic — .invoke/.run/.generate are everywhere).
RECEIVER_QUALIFIED_CALLS = {
    "invoke", "ainvoke", "generate", "agenerate", "stream", "astream",
    "complete", "acomplete", "predict", "apredict", "chat", "completion",
    "acompletion", "messages",
}
TOKEN_KEYS = {"max_tokens", "max_output_tokens", "max_completion_tokens",
              "maxtokens", "maxoutputtokens"}

# ── Dangerous-sink registry (data-driven, so extending is a one-line change) ──
# Bare builtin calls: Name(id) -> label. These are unambiguous (a method named
# `eval`/`compile` is an Attribute, not a Name, so PyTorch's model.eval() and
# re.compile() are NOT matched here).
_BUILTIN_SINKS = {
    "eval": "eval()",
    "exec": "exec()",
    "compile": "compile()",
    "__import__": "__import__()",
}
# Dotted calls matched by exact suffix: dotted-name -> label. Deserialization
# sinks (pickle/marshal) execute arbitrary code on untrusted input.
_ATTR_SINKS = {
    "os.system": "os.system()",
    "os.popen": "os.popen()",
    "pickle.loads": "pickle.loads()",
    "pickle.load": "pickle.load()",
    "cpickle.loads": "pickle.loads()",
    "cpickle.load": "pickle.load()",
    "marshal.loads": "marshal.loads()",
    "dill.loads": "dill.loads()",
}
_SAFE_YAML_LOADERS = ("safeloader", "csafeloader", "baseloader")

# Names that strongly suggest externally-controlled / model input — used for the
# reachability heuristic on execution sinks.
INPUT_HINTS = ("request", "req", "body", "payload", "params", "query", "prompt",
               "user_input", "message", "msg", "content", "input", "data",
               "response", "completion", "output", "result", "text", "reply",
               "llm_output", "answer", "args")
# Names that clearly denote EXTERNAL user/request input (→ high severity for a
# system-prompt interpolation). Generic vars (summary_text, content, output)
# are app/model-generated and rate only medium.
STRONG_INPUT_HINTS = ("request", "req", "body", "payload", "params", "query",
                      "user_input", "user_msg", "user_message", "prompt", "args")
# For evidence: classify a tainted value's origin so findings can name it.
MODEL_SOURCE_HINTS = ("response", "reply", "completion", "assistant", "answer",
                      "llm_output", "generation", "output", "result", "content", "text")
USER_SOURCE_HINTS = ("request", "req", "body", "payload", "params", "query",
                     "user_input", "prompt", "message", "msg", "input", "args", "data")


def _dotted(node: ast.AST) -> Optional[str]:
    """Return the dotted attribute path of a call's func, e.g. a.b.c.create."""
    parts: List[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    elif isinstance(cur, ast.Call):
        # chained off a call, e.g. OpenAI().chat... — mark root as the call
        inner = _dotted(cur.func)
        if inner:
            parts.append(inner)
    else:
        return None
    return ".".join(reversed(parts))


def _root_name(node: ast.AST) -> Optional[str]:
    cur = node
    while isinstance(cur, ast.Attribute):
        cur = cur.value
    if isinstance(cur, ast.Name):
        return cur.id
    if isinstance(cur, ast.Call):
        return _root_name(cur.func)
    return None


def _ctor_name(node: ast.AST) -> Optional[str]:
    """If node is a constructor Call, return the constructor's terminal name."""
    if not isinstance(node, ast.Call):
        return None
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _names_in(node: ast.AST) -> Set[str]:
    out: Set[str] = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Name):
            out.add(n.id)
        elif isinstance(n, ast.Attribute):
            out.add(n.attr)
    return out


def _is_all_constant(args: List[ast.AST]) -> bool:
    """True if every arg is a literal constant (or list/tuple of constants)."""
    def const(n: ast.AST) -> bool:
        if isinstance(n, ast.Constant):
            return True
        if isinstance(n, (ast.List, ast.Tuple)):
            return all(const(e) for e in n.elts)
        if isinstance(n, ast.JoinedStr):
            return all(isinstance(v, ast.Constant) for v in n.values)  # f-string w/ no interpolation
        if isinstance(n, ast.IfExp):  # 'clear' if cond else 'cls' — both branches literal
            return const(n.body) and const(n.orelse)
        return False
    return bool(args) and all(const(a) for a in args)


class _Analyzer(ast.NodeVisitor):
    def __init__(self, rel: str):
        self.rel = rel
        self.findings: List[Dict[str, Any]] = []
        self.llm_imported = False
        self.llm_aliases: Set[str] = set()    # names bound to LLM modules/ctors
        self.llm_vars: Set[str] = set()        # vars holding an LLM client
        self.tainted: Set[str] = set()         # vars holding model output / input
        self.llm_signal = False                # repo actually invokes/constructs an LLM
        self.file_has_llm = False              # this file is agent code (set after pass 1)
        # var/attr key -> set of param keys it holds (for `create(**params)`).
        self.param_dicts: Dict[str, Set[str]] = {}
        self._bounded_depth = 0                 # nesting inside statically-bounded loops

    # -- imports -----------------------------------------------------------
    def visit_Import(self, node: ast.Import):
        for a in node.names:
            root = a.name.split(".")[0]
            if root in LLM_IMPORT_ROOTS and root != "boto3":
                self.llm_imported = True
                self.llm_aliases.add((a.asname or a.name).split(".")[0])
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        root = (node.module or "").split(".")[0]
        if root in LLM_IMPORT_ROOTS and root != "boto3":
            self.llm_imported = True
            for a in node.names:
                self.llm_aliases.add(a.asname or a.name)
        self.generic_visit(node)

    # -- assignments: track LLM clients + tainted (model output) vars ------
    def visit_Assign(self, node: ast.Assign):
        targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
        ctor = _ctor_name(node.value)
        if ctor and (ctor in LLM_CONSTRUCTORS or ctor in self.llm_aliases):
            self.llm_signal = True
            for t in targets:
                self.llm_vars.add(t)
        # x = <llm call>  → x is model output (tainted)
        if isinstance(node.value, ast.Call) and self._is_llm_call(node.value):
            for t in targets:
                self.tainted.add(t)
        # Track request-param dicts: `params = {...}` / `self.chat_params = {...}`.
        # Keys only accumulate (union) so a value is never lost across the two
        # analysis passes or a later `params["max_tokens"] = ...` write.
        if isinstance(node.value, ast.Dict):
            keys = {k.value.lower() for k in node.value.keys
                    if isinstance(k, ast.Constant) and isinstance(k.value, str)}
            for t in node.targets:
                key = self._param_key(t)
                if key:
                    self.param_dicts.setdefault(key, set()).update(keys)
        # `params["max_tokens"] = ...` — a key write counts as declaring it.
        for t in node.targets:
            if isinstance(t, ast.Subscript):
                base = self._param_key(t.value)
                sk = t.slice
                if base and isinstance(sk, ast.Constant) and isinstance(sk.value, str):
                    self.param_dicts.setdefault(base, set()).add(sk.value.lower())
        self.generic_visit(node)

    @staticmethod
    def _param_key(node: ast.AST) -> Optional[str]:
        """A stable key for a param-dict variable: `params` or `self.chat_params`."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return _dotted(node)
        return None

    def _record_param_update(self, node: ast.Call):
        """`params.update({...})` — fold the literal's keys into the tracked set."""
        f = node.func
        if isinstance(f, ast.Attribute) and f.attr == "update" and node.args:
            base = self._param_key(f.value)
            arg = node.args[0]
            if base and isinstance(arg, ast.Dict):
                keys = {k.value.lower() for k in arg.keys
                        if isinstance(k, ast.Constant) and isinstance(k.value, str)}
                if keys:
                    self.param_dicts.setdefault(base, set()).update(keys)

    # -- function params count as externally-controlled input --------------
    def visit_FunctionDef(self, node: ast.FunctionDef):
        for a in node.args.args + node.args.kwonlyargs:
            if any(h in a.arg.lower() for h in INPUT_HINTS):
                self.tainted.add(a.arg)
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    # -- the core: classify each call --------------------------------------
    def _is_llm_call(self, node: ast.Call) -> bool:
        func = node.func
        if not isinstance(func, ast.Attribute):
            return False
        attr = func.attr
        dotted = _dotted(func) or ""
        root = _root_name(func)
        if attr in STRONG_LLM_CALLS:
            # create/messages.create/generate_content — require an LLM-ish path
            # or an LLM import in the file, to avoid e.g. db.create().
            if (".chat." in dotted or ".completions." in dotted
                    or ".messages." in dotted or ".responses." in dotted
                    or attr in ("create_message", "generate_content")):
                return True
            return self.llm_imported and (root in self.llm_vars or root in self.llm_aliases)
        if attr in RECEIVER_QUALIFIED_CALLS:
            # Only when we can RESOLVE the receiver to an LLM client: a var
            # assigned from an LLM constructor, or an imported LLM module/name.
            # We do NOT guess from the variable name — `llm = services.get("llm")`
            # is an app wrapper, not a known SDK call, and `max_tokens` may be
            # handled inside it. A name-based guess is not a finding you can put
            # in front of a maintainer.
            return root in self.llm_vars or root in self.llm_aliases
        return False

    def visit_Call(self, node: ast.Call):
        self._check_llm_token_ceiling(node)
        self._check_exec_sink(node)
        self._record_param_update(node)
        self.generic_visit(node)

    def visit_For(self, node: ast.For):
        # `for _ in range(...)` / `for x in [literal]` statically bounds re-entry.
        bounded = self._is_bounded_for(node)
        if bounded:
            self._bounded_depth += 1
        self.generic_visit(node)
        if bounded:
            self._bounded_depth -= 1

    visit_AsyncFor = visit_For

    @staticmethod
    def _is_bounded_for(node: ast.For) -> bool:
        it = node.iter
        if isinstance(it, ast.Call) and _root_name(it.func) == "range":
            return True
        return isinstance(it, (ast.List, ast.Tuple))

    @staticmethod
    def _loop_has_exit(node: ast.While) -> bool:
        return any(isinstance(n, (ast.Return, ast.Break)) for n in ast.walk(node))

    def visit_While(self, node: ast.While):
        # An infinite loop (`while True:` / `while 1:`) wrapping an LLM call is
        # the AutoGPT-style runaway: completion criteria may never be met, so it
        # spins and burns budget. A model-controlled `break` is NOT a cap.
        #
        # BUT: a `while True` nested inside a statically-bounded loop
        # (`for _ in range(max_retry)`) that also has a reachable exit is capped
        # by that outer loop — the common framework pattern where the outer loop
        # drives retries and the inner loop processes one round. Flagging that as
        # "unbounded" overstates it, so we stay quiet there (the token-ceiling
        # check still applies to the call itself).
        test = node.test
        infinite = isinstance(test, ast.Constant) and bool(test.value)
        if infinite:
            for n in ast.walk(node):
                if isinstance(n, ast.Call) and self._is_llm_call(n):
                    if self._bounded_depth > 0 and self._loop_has_exit(node):
                        break  # bounded by an enclosing for-loop → not a runaway
                    self.findings.append(self._f(
                        "high", "Unbounded loop around an LLM call", node,
                        "An infinite loop wraps an LLM call with no iteration cap. "
                        "If the stop condition is never met it spins forever, "
                        "burning tokens and budget. Add an explicit max-iterations ceiling.",
                        confidence="high", basis="confirmed",
                        impact="Runaway cost / no termination guarantee.",
                    ))
                    break
        self.generic_visit(node)

    def _check_llm_token_ceiling(self, node: ast.Call):
        if not self._is_llm_call(node):
            return
        self.llm_signal = True
        kwargs = {k.arg.lower() for k in node.keywords if k.arg}
        if kwargs & TOKEN_KEYS:
            return
        # Spread params (`create(**self.chat_params)`) — the common framework
        # pattern. Try to RESOLVE the dict to the literal it was built from: if
        # we can see its keys and none is a token ceiling, that's a real (LOW)
        # finding, not a blind spot. If we can't resolve it, stay quiet.
        spreads = [k.value for k in node.keywords if k.arg is None]
        if spreads:
            resolved: Set[str] = set()
            for sv in spreads:
                key = self._param_key(sv)
                if key is None or key not in self.param_dicts:
                    return  # unresolvable spread → can't prove absence, stay quiet
                resolved |= self.param_dicts[key]
            if resolved & TOKEN_KEYS:
                return  # the dict declares a ceiling → fine
            self.findings.append(self._f(
                "low", "LLM call parameter dict has no output ceiling", node,
                "The request params for this LLM call are assembled in a dict with "
                "no max_tokens / max_completion_tokens key, then passed via a "
                "`**` spread. Output length and cost fall back to provider/model "
                "defaults. Expose an explicit output ceiling (e.g. a max_tokens "
                "argument merged into the params).",
                confidence="medium", basis="inferred",
                impact="Output length/cost depends on provider defaults; no "
                       "explicit ceiling in the request params.",
            ))
            return
        # Standalone, this is cost hygiene, NOT a vulnerability: every provider
        # caps output at the model's max anyway, so one uncapped call costs at
        # most a single full-length completion. We emit it LOW/inferred by
        # default and only elevate to MEDIUM in analyze_python() when it
        # co-occurs with an unbounded loop (the real runaway-cost compound).
        # This is the demotion that keeps clean repos from getting a Medium ding
        # for something ubiquitous and harmless.
        self.findings.append(self._f(
            "low", "LLM call with no token ceiling", node,
            "This LLM call sets no max_tokens — a single response can run to the "
            "model's max output. Not a vulnerability by itself; pass an explicit "
            "max_tokens / max_output_tokens to bound latency and cost.",
            confidence="medium", basis="inferred",
            impact="Unpredictable latency/cost on a single call. Not a "
                   "vulnerability by itself.",
        ))

    def _sink_kind(self, node: ast.Call) -> Optional[str]:
        """Registry-driven: return a human label if this call is a dangerous
        sink, else None. Adding a new sink is a one-line registry edit."""
        func = node.func
        if isinstance(func, ast.Name):
            return _BUILTIN_SINKS.get(func.id)
        if not isinstance(func, ast.Attribute):
            return None
        dotted = (_dotted(func) or "").lower()
        for suffix, label in _ATTR_SINKS.items():
            if dotted.endswith(suffix):
                return label
        # subprocess.* is a shell-injection sink ONLY with shell=True. A list-arg
        # call (subprocess.Popen([...])) runs no shell and is not flagged.
        if ".subprocess." in ("." + dotted) or _root_name(func) == "subprocess":
            if any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True
                   for k in node.keywords):
                return "subprocess(shell=True)"
            return None
        # yaml.load(...) is unsafe UNLESS given a Safe/Base Loader. yaml.safe_load
        # isn't in the registry, so it's never flagged.
        if dotted.endswith("yaml.load"):
            for k in node.keywords:
                if k.arg and k.arg.lower() == "loader":
                    ld = (_dotted(k.value) or getattr(k.value, "attr", "") or "").lower()
                    if any(safe in ld for safe in _SAFE_YAML_LOADERS):
                        return None
            return "yaml.load()"
        return None

    def _reaching_taint(self, arg_names):
        """Return (value_name, source_label) for the tainted value reaching a
        sink, or None. Names the evidence a judge would cite."""
        for n in arg_names:
            low = n.lower()
            if n in self.tainted and any(h in low for h in MODEL_SOURCE_HINTS):
                return n, "the model's own output"
            if any(h in low for h in MODEL_SOURCE_HINTS):
                return n, "model output"
        for n in arg_names:
            low = n.lower()
            if any(h in low for h in USER_SOURCE_HINTS) or n in self.tainted:
                return n, "external user/request input"
        return None

    def _check_exec_sink(self, node: ast.Call):
        kind = self._sink_kind(node)
        if not kind:
            return
        args = list(node.args)
        # Benign: every argument is a constant literal (e.g. os.system('clear')).
        if _is_all_constant(args):
            return
        # Reachability: does a tainted (model/user) value flow into the sink?
        arg_names = [n for a in args for n in _names_in(a)]
        reaching = self._reaching_taint(arg_names)
        if reaching:
            # The agent-specific, undismissable case: name the exact value and its
            # source so the finding reads like evidence, not a pattern hit — and
            # say which layer structurally misses it.
            value, source = reaching
            self.findings.append(self._f(
                "high", "Dangerous execution sink", node,
                f"{kind} executes `{value}` — {source}. A prompt injection your "
                "input guardrail can't catch (it succeeds inside the model) or a "
                "bad tool result becomes remote code execution here, after your "
                "output evaluator has already scored the text. Parse with "
                "ast.literal_eval/json, or sandbox execution.",
                evidence=f"{source} `{value}` -> {kind}",
                confidence="high", basis="confirmed",
                impact="Remote code execution if model/user output reaches this sink.",
            ))
        elif self.file_has_llm:
            # A dynamic sink in agent code we can't prove is reachable → a quiet
            # LOW nudge ('confirm your sandbox'), not a score-tanking finding. We
            # are NOT a generic SAST tool: a dynamic exec/pickle in non-agent code
            # is Bandit's job, not ours, so outside agent files we stay silent.
            self.findings.append(self._f(
                "low", "Dynamic execution sink (agent code)", node,
                f"{kind} runs a non-constant value in agent code. Confirm no model "
                "or user output can reach it; a deliberate code tool should be "
                "sandboxed.",
                confidence="low", basis="inferred",
                impact="Potential code execution if untrusted input can reach it "
                       "— reachability not proven.",
            ))

    # -- f-string system prompts ------------------------------------------
    def visit_Dict(self, node: ast.Dict):
        # {"role": "system", "content": f"...{x}..."}
        role_is_system = False
        content_val = None
        for k, v in zip(node.keys, node.values):
            if isinstance(k, ast.Constant) and k.value == "role" \
               and isinstance(v, ast.Constant) and v.value in ("system", "developer"):
                role_is_system = True
            if isinstance(k, ast.Constant) and k.value == "content":
                content_val = v
        if role_is_system and isinstance(content_val, ast.JoinedStr):
            interp = [v for v in content_val.values if isinstance(v, ast.FormattedValue)]
            # Only the interpolations that could be DYNAMIC matter. An ALL_CAPS
            # name (BROWSER_SYSTEM_MESSAGE) is a module constant, not user input,
            # so interpolating it is not an injection surface.
            def _is_constanty(fv):
                ns = _names_in(fv.value)
                return ns and all(re.fullmatch(r"[A-Z][A-Z0-9_]*", n) for n in ns)
            dynamic = [fv for fv in interp if not _is_constanty(fv)]
            if dynamic:
                names = set()
                for fv in dynamic:
                    names |= _names_in(fv.value)
                # High only when a clearly external user/request value flows in.
                # Generic/app/model-generated names (summary_text, content) → medium.
                strong = any(any(h in n.lower() for h in STRONG_INPUT_HINTS) for n in names)
                self.findings.append(self._f(
                    "high" if strong else "medium",
                    "Interpolated system prompt (injection surface)", content_val,
                    "User/model-influenced text is interpolated into a system "
                    "prompt. Move untrusted input into a clearly-delimited user "
                    "turn so it can't override system instructions.",
                    confidence="high" if strong else "low",
                    basis="confirmed" if strong else "inferred",
                    impact="Prompt-injection surface: untrusted text can override "
                           "system instructions.",
                ))
        self.generic_visit(node)

    def _f(self, severity: str, title: str, node: ast.AST, rec: str,
           evidence: str = "", confidence: str = "medium",
           basis: str = "inferred", impact: str = "") -> Dict[str, Any]:
        # confidence: how sure we are this is what we say it is (high/medium/low).
        # basis: "confirmed" = we can point at the exact tainted flow / structure;
        #        "inferred"  = the pattern is present but reachability isn't proven.
        # These let a developer triage instantly and let CI gate on confirmed-only.
        return {
            "severity": severity, "title": title, "file": self.rel,
            "line": getattr(node, "lineno", 0), "snippet": "",
            "recommendation": rec, "evidence": evidence,
            "confidence": confidence, "basis": basis, "impact": impact,
        }


def has_llm_usage(source: str) -> bool:
    """True if the file actually constructs or calls an LLM (not just imports/mentions)."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return False
    a = _Analyzer("x")
    a.visit(tree)
    a.llm_signal = False
    a.visit(tree)  # second pass so assignments inform call classification
    return a.llm_signal or bool(a.llm_vars)


def analyze_python(source: str, rel: str) -> List[Dict[str, Any]]:
    """Analyze one Python file. Returns findings; empty on parse failure."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    a = _Analyzer(rel)
    # Two passes so assignments/imports seen anywhere inform call classification.
    a.visit(tree)
    # Whether this file is genuinely agent code (constructs/calls an LLM) — used
    # to keep dynamic-sink LOW nudges scoped to agent files, not generic Python.
    a.file_has_llm = a.llm_signal or bool(a.llm_vars)
    a.findings.clear()
    a.visit(tree)
    # de-dupe (two passes) by (title, line)
    seen: Set[Tuple[str, int]] = set()
    out: List[Dict[str, Any]] = []
    for f in a.findings:
        key = (f["title"], f["line"])
        if key not in seen:
            seen.add(key)
            out.append(f)
    # Elevate uncapped LLM calls to MEDIUM only when this file ALSO has an
    # unbounded loop around an LLM call — that's the real runaway-cost compound
    # (each loop turn emits a max-length completion, unbounded). Alone they stay
    # LOW. Severity follows blast radius, not the raw pattern.
    if any(f["title"] == "Unbounded loop around an LLM call" for f in out):
        for f in out:
            if f["title"] == "LLM call with no token ceiling":
                f["severity"] = "medium"
                f["basis"] = "confirmed"
                f["impact"] = ("Inside an unbounded loop with no output ceiling: "
                               "each turn can emit a max-length completion, "
                               "unbounded — a real runaway-cost path.")
    return out

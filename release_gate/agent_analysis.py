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
# API surfaces on an LLM client that are NOT text generation — a token ceiling
# is meaningless for client.embeddings.create() or client.images.generate(),
# so calls through these segments are never "LLM calls" for our checks.
# (NB: "models" is NOT here — google-genai's text call is client.models.generate_content.)
NON_TEXT_SURFACES = {"embeddings", "embedding", "images", "image", "audio",
                     "speech", "transcriptions", "translations", "moderations",
                     "files", "batches", "uploads", "fine_tuning", "vector_stores"}
# Call kwargs that carry the provider's request-config OBJECT (google-genai's
# config=GenerateContentConfig(max_output_tokens=…), etc.). If one is passed and
# we can't see inside it, absence of a ceiling is unprovable — stay quiet.
CONFIG_OBJECT_KWARGS = {"config", "generation_config", "generate_content_config",
                        "request_options", "inference_config"}

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
    # getoutput/getstatusoutput ALWAYS run through the shell (no shell= kwarg to
    # check) — the legacy `commands.*` and their py3 `subprocess.*` equivalents.
    # A dynamic argument here is a shell command built at runtime, unconditionally.
    "subprocess.getoutput": "subprocess.getoutput()",
    "subprocess.getstatusoutput": "subprocess.getstatusoutput()",
    "commands.getoutput": "commands.getoutput()",
    "commands.getstatusoutput": "commands.getstatusoutput()",
    "pickle.loads": "pickle.loads()",
    "pickle.load": "pickle.load()",
    "cpickle.loads": "pickle.loads()",
    "cpickle.load": "pickle.load()",
    "marshal.loads": "marshal.loads()",
    "dill.loads": "dill.loads()",
}
_SAFE_YAML_LOADERS = ("safeloader", "csafeloader", "baseloader")

# Deserialization sinks are ubiquitous for a framework's OWN internal transport
# (multiprocessing IPC, caching, state persistence), so a name-inferred source
# reaching one is NOT asserted as a confirmed RCE — see _check_exec_sink.
_DESERIALIZATION_SINKS = {"pickle.loads()", "pickle.load()",
                          "marshal.loads()", "dill.loads()"}

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
# Names that denote the developer's OWN prompt material (prompt text, personas,
# instructions being composed). Interpolating these into a system prompt is how
# system prompts are BUILT — it is not an injection surface by itself.
PROMPT_MATERIAL_HINTS = ("prompt", "prompts", "instruction", "instructions",
                         "persona", "template", "system", "preamble", "guidance")
# For the system-prompt check specifically: "prompt"/"params"/"args" name the
# developer's own material there, so they don't count as external-input proof.
SYSTEM_PROMPT_STRONG_HINTS = tuple(h for h in STRONG_INPUT_HINTS
                                   if h not in ("prompt", "params", "args"))
# For a shell/exec/deserialization sink: a bare `args`/`params`/`prompt` is the
# OPERATOR's or developer's own input in a CLI tool — aider's `/git <args>`, a
# `cmd_foo(self, args)` handler — not network-external like request/body/webhook.
# Asserting a CONFIRMED public RCE on those is the credibility-killing overclaim
# a maintainer instantly dismisses; demote them to the inferred tier (they still
# match USER_SOURCE_HINTS → medium, "confirm the source"). Genuinely external
# names (request/body/payload/webhook/event) stay confirmed.
SINK_STRONG_INPUT_HINTS = tuple(h for h in STRONG_INPUT_HINTS
                                if h not in ("prompt", "params", "args"))

# ── RG-PROMPT-002: untrusted-provenance sources (instruction/data separation) ─
# A value TRACED from one of these sources is untrusted world-data, not operator
# instruction. When it reaches the system/instruction channel a poisoned document
# becomes a command — indirect prompt injection. Unlike RG-PROMPT-001 (which keys
# on name hints), this keys on real PROVENANCE, so it grades confirmed/HIGH.
# Retrieval / RAG reads (vector store, retriever). Kept to unambiguous method
# names — `.query`/`.search` alone are too generic (a dict/DB query) to trust.
RETRIEVAL_METHODS = {
    "get_relevant_documents", "aget_relevant_documents",
    "similarity_search", "asimilarity_search",
    "similarity_search_with_score", "similarity_search_with_relevance_scores",
    "similarity_search_by_vector", "max_marginal_relevance_search",
    "retrieve", "aretrieve",
}
# HTTP fetch: the response object is untrusted, and so is its body (.text/.json()…).
HTTP_CALL_ROOTS = {"requests", "httpx", "aiohttp"}
HTTP_VERB_ATTRS = {"get", "post", "put", "delete", "patch", "head", "options", "request"}
HTTP_BODY_ATTRS = {"text", "content", "json", "read", "body"}
# A locally-defined function decorated as an agent tool: its RETURN is world-data
# the tool fetched, not developer instruction.
TOOL_DECORATOR_HINTS = ("tool", "function_tool", "register_tool")
# Unambiguous system/instruction-channel constructors (LangChain / LangGraph).
SYSTEM_MSG_CTORS = {"SystemMessage", "SystemMessagePromptTemplate"}

# ── RG-ACTION-003: filesystem write / delete sinks ───────────────────────────
# Delete / move / overwrite of a MODEL-controlled path is irreversible → HIGH.
# Dotted-suffix match (like _ATTR_SINKS): dotted-name -> human label.
_FS_DELETE_SINKS = {
    "os.remove": "os.remove()", "os.unlink": "os.unlink()", "os.rmdir": "os.rmdir()",
    "os.removedirs": "os.removedirs()", "os.rename": "os.rename()",
    "os.replace": "os.replace()", "shutil.rmtree": "shutil.rmtree()",
    "shutil.move": "shutil.move()",
}
# pathlib bound methods (receiver is the path): p.unlink() / p.write_text(...).
_PATH_DELETE_ATTRS = {"unlink", "rmdir"}
_PATH_WRITE_ATTRS = {"write_text", "write_bytes"}

# ── RG-ACTION-004: SQL execute sinks ─────────────────────────────────────────
# A raw query built by INTERPOLATION (f-string / + / %) carrying tainted text is
# SQL injection; a parameterized execute(sql, params) with constant sql is the
# correct pattern and never flagged.
_SQL_EXEC_ATTRS = {"execute", "executescript", "executemany", "executemany_async",
                   "raw", "text"}

# ── RG-SECRET-002: secret / env / PII flowing into a prompt sent to an LLM ────
# A literal that LOOKS like a live credential (value-level, unlike verify's
# line-level _SECRET_RE which also matches `key = "..."` assignments).
_SECRET_VALUE_RE = re.compile(
    r"^(?:sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9]{16,}"
    r"|AKIA[0-9A-Z]{16}"
    r"|gh[pousr]_[A-Za-z0-9]{20,}"
    r"|xox[baprs]-[A-Za-z0-9-]{10,})$"
)
# Names that denote a secret/PII value the developer must NOT ship to a third-
# party model provider inside a prompt.
SECRET_NAME_HINTS = ("secret", "password", "passwd", "api_key", "apikey", "token",
                     "private_key", "privatekey", "credential", "credentials",
                     "ssn", "credit_card", "creditcard", "card_number", "cvv",
                     "access_key", "secret_key", "auth_token", "session_token")
# The content-bearing arguments of an LLM call — where a secret must never land.
# (api_key / headers / auth are NOT here: a key passed as auth is not prompt egress.)
PROMPT_ARG_KEYS = {"messages", "prompt", "input", "contents", "content", "query",
                   "question", "text", "system", "instructions", "user", "inputs"}

# ── RG-ACTION-002: SSRF / egress — the HTTP call is here a SINK, not a source ─
# The URL-bearing argument (model-controlled host → SSRF) and the body-bearing
# ones (model-controlled data → exfiltration).
HTTP_URL_ARG_KEYS = {"url", "uri", "endpoint"}
HTTP_BODY_ARG_KEYS = {"data", "json", "body", "content", "files", "params"}

# ── RG-PARSE-001: unvalidated model-output parse (reliability, not security) ──
# Parsing model output that can be malformed, with no surrounding try/except, is
# the everyday "the model returned bad JSON → the agent crashed" reliability bug.
# Dotted-suffix match: json/ujson/orjson/simplejson `.loads`, and ast.literal_eval.
_PARSE_SINK_SUFFIXES = ("json.loads", "ujson.loads", "orjson.loads",
                        "simplejson.loads", "ast.literal_eval")

# ── RG-TOOL-001 / RG-GATE-001: tool blast-radius + irreversibility gate ───────
# A call INSIDE a @tool body that performs an action that cannot be undone. Kept
# high-precision: delete-class filesystem ops, HTTP DELETE, and calls whose name
# is an unambiguous irreversible business verb. A generic requests.post (often an
# idempotent GraphQL query) is deliberately NOT classed irreversible.
IRREVERSIBLE_VERB_HINTS = (
    "delete", "remove", "destroy", "drop", "purge", "wipe", "erase",
    "send", "email", "pay", "charge", "refund", "purchase", "transfer",
    "deploy", "publish", "terminate", "shutdown", "revoke", "wire",
    "place_order", "submit_order", "execute_trade", "cancel_order",
)
# A signal in the tool body that a human/confirmation/dry-run gate exists.
# Over-detecting a gate is the SAFE error here — it suppresses a finding
# (false negative), never invents one, so this list can be generous.
GATE_HINTS = (
    "confirm", "confirmed", "confirmation", "dry_run", "dryrun", "approve",
    "approved", "approval", "require_approval", "force", "interactive",
    "human", "human_in_loop", "assume_yes", "review", "authorize", "authorized",
    "consent", "preview", "acknowledge", "verify",
)
_GATE_CALL_NAMES = {"input", "confirm", "ask", "prompt", "getpass"}

# Identifier-token matching. Substring matching turned `context` into a hit for
# "text" and `database` into a hit for "data" — a whole false-positive class.
# A hint matches only when all its words appear as tokens of the identifier
# (snake_case and camelCase are split): user_input → {user, input}.
_CAMEL_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_TOKEN_SPLIT_RE = re.compile(r"[^a-zA-Z0-9]+")


def _tokens(name: str) -> Set[str]:
    return {t for t in _TOKEN_SPLIT_RE.split(_CAMEL_RE.sub("_", name).lower()) if t}


def _hint_match(name: str, hints) -> bool:
    toks = _tokens(name)
    return any(_tokens(h) <= toks for h in hints)


# A locally-defined helper whose *name* says it returns model-generated code:
# an unambiguous LLM token (llm/gpt/claude…), OR a generation verb paired with a
# code/text noun (generate_blender_CODE, ask_gpt_for_SCRIPT). We only ever act on
# this when its result reaches an exec()/eval() sink, so the pairing keeps the
# false-positive surface near zero (nobody exec()s a generate_uuid()).
_LLM_STRONG_FN_TOKENS = {"llm", "gpt", "chatgpt", "claude", "gemini", "openai",
                         "anthropic", "completion", "codegen"}
_GEN_VERB_TOKENS = {"generate", "gen", "complete", "ask", "chat", "predict",
                    "write", "compose", "produce", "create"}
_CODE_NOUN_TOKENS = {"code", "script", "command", "cmd", "program", "programme",
                     "snippet", "python", "blender", "sql", "expression", "expr"}


def _restricts_builtins(node: ast.Call) -> bool:
    """True if exec/eval is given a globals dict that strips builtins:
    exec(code, {"__builtins__": {}}, ...) or {"__builtins__": None}. A weak,
    bypassable sandbox — but a deliberate restriction we shouldn't call a
    confirmed public RCE over."""
    if len(node.args) < 2 or not isinstance(node.args[1], ast.Dict):
        return False
    for k, v in zip(node.args[1].keys, node.args[1].values):
        if isinstance(k, ast.Constant) and k.value == "__builtins__":
            if isinstance(v, ast.Dict) and not v.keys:
                return True
            if isinstance(v, ast.Constant) and v.value is None:
                return True
    return False


def _looks_like_llm_codegen_helper(fn_name: Optional[str]) -> bool:
    if not fn_name:
        return False
    toks = _tokens(fn_name)
    if toks & _LLM_STRONG_FN_TOKENS:
        return True
    return bool(toks & _GEN_VERB_TOKENS) and bool(toks & _CODE_NOUN_TOKENS)


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


def _chain_root(node: ast.AST) -> Optional[str]:
    """Root variable of an attribute/subscript access chain, walking through
    BOTH `.attr` and `[i]` — so `resp.choices[0].message.content` (the canonical
    OpenAI/Anthropic text extraction) resolves to `resp`. `_root_name` stops at
    the first subscript, which is exactly why that chain used to lose its taint."""
    cur = node
    while isinstance(cur, (ast.Attribute, ast.Subscript)):
        cur = cur.value
    if isinstance(cur, ast.Name):
        return cur.id
    if isinstance(cur, ast.Call):
        return _chain_root(cur.func)
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
        # LLM clients whose CONSTRUCTOR already declared a token ceiling
        # (ChatOpenAI(max_tokens=512)) — calls through them are capped.
        self.llm_vars_capped: Set[str] = set()
        # Vars only ever assigned constant strings (incl. if/elif chains of
        # literals) — developer-controlled text, safe to interpolate anywhere.
        self.assigned_const: Set[str] = set()
        self.assigned_dynamic: Set[str] = set()
        self.tainted: Set[str] = set()         # vars holding model output / input
        self.tainted_model: Set[str] = set()   # vars ASSIGNED from an LLM call in-scope
        self.model_extracted: Set[str] = set() # vars holding text EXTRACTED off a
                                               # model response (resp.choices[0].
                                               # message.content) — confirmed model
                                               # output regardless of the var name
        self.llm_signal = False                # repo actually invokes/constructs an LLM
        self.file_has_llm = False              # this file is agent code (set after pass 1)
        # var/attr key -> set of param keys it holds (for `create(**params)`).
        self.param_dicts: Dict[str, Set[str]] = {}
        self._bounded_depth = 0                 # nesting inside statically-bounded loops
        # vars received from a LOCAL IPC pipe/duplex (multiprocessing) — trusted
        # internal transport, NOT external input. `pickle.loads` on one of these
        # is the stdlib logging/worker pattern, not an RCE surface.
        self.local_ipc_vars: Set[str] = set()
        # yaml Loader classes defined in this file that SUBCLASS a safe loader —
        # `class YamlLoader(yaml.SafeLoader)` is safe even though its name isn't
        # in the known-safe list.
        self.safe_yaml_loaders: Set[str] = set()
        # vars assigned from a locally-named LLM codegen helper —
        # `blender_code = generate_blender_code(...)`. We can't see the SDK call
        # (it's inside the helper), so this is INFERRED model output, not
        # confirmed. It only matters when it flows into an exec/eval sink: the
        # "run the code the model wrote" agentic-RCE pattern.
        self.llm_helper_output: Set[str] = set()
        # `eval`/`exec`/`compile` names shadowed in this file by a local def, an
        # assignment, or an import — a call to them is NOT the dangerous builtin.
        # RWKV-Runner defines `def eval(model, request, body, ...)` ("evaluate the
        # model") and calls it 5×; without this every call looks like RCE.
        self.shadowed_builtins: Set[str] = set()
        # RG-PROMPT-002 provenance. `untrusted_provenance` = vars TRACED from an
        # untrusted external source (retrieval result, HTTP body, tool return) —
        # world-data, not operator instruction. `http_response_vars` = vars holding
        # a raw HTTP response, so `body = resp.text` inherits the taint. `tool_funcs`
        # = locally-defined @tool functions, whose direct-call returns are untrusted.
        self.untrusted_provenance: Set[str] = set()
        self.http_response_vars: Set[str] = set()
        self.tool_funcs: Set[str] = set()
        # RG-SECRET-002. `secret_literal_vars` = vars assigned a credential-shaped
        # literal (confirmed/high tier). `secret_env_vars` = vars from os.environ /
        # os.getenv or with a secret/PII-shaped NAME (inferred/medium tier). A value
        # from either flowing into an LLM prompt is data egress to the provider.
        self.secret_literal_vars: Set[str] = set()
        self.secret_env_vars: Set[str] = set()
        # RG-PARSE-001: nesting inside a `try:` BODY — a parse there is guarded.
        self._try_depth = 0

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
        # `from .generation import eval` — the local name `eval` is now that
        # import, not the builtin.
        for a in node.names:
            if (a.asname or a.name) in ("eval", "exec", "compile"):
                self.shadowed_builtins.add(a.asname or a.name)
        self.generic_visit(node)

    # -- assignments: track LLM clients + tainted (model output) vars ------
    def visit_Assign(self, node: ast.Assign):
        targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
        # `eval = something` rebinds the name away from the builtin.
        for t in targets:
            if t in ("eval", "exec", "compile"):
                self.shadowed_builtins.add(t)
        ctor = _ctor_name(node.value)
        if ctor and (ctor in LLM_CONSTRUCTORS or ctor in self.llm_aliases):
            self.llm_signal = True
            ctor_kwargs = {k.arg.lower() for k in node.value.keywords if k.arg}
            for t in targets:
                self.llm_vars.add(t)
                # LangChain-style clients take the ceiling at construction time
                # (ChatOpenAI(max_tokens=512)); flagging every .invoke() on such
                # a client for "no token ceiling" is a false positive.
                if ctor_kwargs & TOKEN_KEYS or "model_kwargs" in ctor_kwargs:
                    self.llm_vars_capped.add(t)
        # Constant-string tracking: a var only ever assigned literal strings
        # (strategy_guidance = "…" in an if/elif chain) is the developer's own
        # text. One dynamic assignment anywhere disqualifies it.
        if targets:
            if _is_all_constant([node.value]) or (
                    isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)):
                self.assigned_const.update(targets)
            else:
                self.assigned_dynamic.update(targets)
        # x = <llm call>  → x is model output (tainted). Track it as CONFIRMED
        # model output — we can see the source in scope, unlike a bare param whose
        # name merely hints at input.
        if isinstance(node.value, ast.Call) and self._is_llm_call(node.value):
            for t in targets:
                self.tainted.add(t)
                self.tainted_model.add(t)
        # x = generate_blender_code(...) — assigned from a locally-named LLM
        # codegen helper. The SDK call is hidden inside the helper, so this is
        # inferred (not confirmed) model output; it only bites at an exec/eval
        # sink. Catches the "exec the code the model wrote" RCE that a bare var
        # name ('blender_code', 'code') would otherwise make invisible.
        elif isinstance(node.value, ast.Call) and \
                _looks_like_llm_codegen_helper(_ctor_name(node.value)):
            for t in targets:
                self.tainted.add(t)
                self.llm_helper_output.add(t)
        # y = <confirmed-model-var>.choices[0].message.content — extracting a
        # field off a var we already saw assigned from an LLM call is still the
        # model's output. The canonical extraction lives behind a subscript that
        # `_root_name` won't cross, so without this `expr = resp...content;
        # eval(expr)` decays to a bare name-hint guess (LOW/inferred) even though
        # the provenance is fully visible in scope. Confirmed, name notwithstanding.
        elif isinstance(node.value, (ast.Attribute, ast.Subscript)):
            # Peel the chain to its base: it's confirmed model output if the base
            # is an LLM call inline (`create(...).choices[0].message.content`) or
            # if the chain roots in a var already known to hold an LLM response.
            base = node.value
            while isinstance(base, (ast.Attribute, ast.Subscript)):
                base = base.value
            croot = _chain_root(node.value)
            if (isinstance(base, ast.Call) and self._is_llm_call(base)) \
                    or (croot and croot in self.tainted_model):
                for t in targets:
                    self.tainted.add(t)
                    self.tainted_model.add(t)
                    self.model_extracted.add(t)
            elif croot and croot in self.tainted:
                for t in targets:
                    self.tainted.add(t)
        # x = self._duplex.recv_bytes()  → x came off a LOCAL IPC pipe, which the
        # process controls — trusted transport, not external input.
        if isinstance(node.value, ast.Call) and self._is_local_ipc_recv(node.value):
            for t in targets:
                self.local_ipc_vars.add(t)
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
        # RG-PROMPT-002 provenance: mark vars traced from an untrusted external
        # source, and propagate through body extraction / indexing so
        # `body = resp.text` and `snippet = docs[0].page_content` stay untrusted.
        val = node.value
        if isinstance(val, ast.Call) and self._untrusted_source_call(val):
            is_http = self._is_http_call(val)
            for t in targets:
                self.untrusted_provenance.add(t)
                self.tainted.add(t)
                if is_http:
                    self.http_response_vars.add(t)
        elif isinstance(val, (ast.Attribute, ast.Subscript, ast.Call)):
            croot = _chain_root(val)
            if croot and croot in self.untrusted_provenance:
                for t in targets:
                    self.untrusted_provenance.add(t)
                    self.tainted.add(t)
        # RG-SECRET-002 sources. A credential-shaped literal → high tier; an
        # os.environ read, or a secret/PII-shaped target name → medium tier.
        if isinstance(val, ast.Constant) and isinstance(val.value, str) \
                and _SECRET_VALUE_RE.match(val.value):
            self.secret_literal_vars.update(targets)
        elif self._is_env_read(val):
            self.secret_env_vars.update(targets)
        else:
            for t in targets:
                if _hint_match(t, SECRET_NAME_HINTS):
                    self.secret_env_vars.add(t)
        self.generic_visit(node)

    @staticmethod
    def _is_env_read(node: ast.AST) -> bool:
        """os.environ["X"] / os.environ.get("X") / os.getenv("X")."""
        if isinstance(node, ast.Subscript):
            return (_dotted(node.value) or "").endswith("os.environ")
        if isinstance(node, ast.Call):
            d = (_dotted(node.func) or "")
            return d.endswith("os.getenv") or d.endswith("os.environ.get")
        return False

    # Receive-calls that pull bytes/objects off a connection, and receiver-name
    # hints that mean it's a LOCAL IPC pipe (multiprocessing), not the network.
    _IPC_RECV_METHODS = {"recv_bytes", "recv", "recv_pyobj", "recv_obj"}
    _IPC_RECEIVER_HINTS = ("duplex", "pipe", "conn", "connection", "parent_conn",
                           "child_conn", "_rx", "_tx", "ipc")

    def _is_local_ipc_recv(self, node: ast.Call) -> bool:
        f = node.func
        if not isinstance(f, ast.Attribute) or f.attr not in self._IPC_RECV_METHODS:
            return False
        recv = (_dotted(f.value) or "").lower()
        return any(h in recv for h in self._IPC_RECEIVER_HINTS)

    # -- RG-PROMPT-002: is this call an untrusted external source? -----------
    def _is_retrieval_call(self, node: ast.Call) -> bool:
        f = node.func
        return isinstance(f, ast.Attribute) and f.attr in RETRIEVAL_METHODS

    def _is_http_call(self, node: ast.Call) -> bool:
        f = node.func
        if not isinstance(f, ast.Attribute):
            return False
        # urllib.request.urlopen(...) — the stdlib fetch.
        if f.attr == "urlopen":
            return True
        # requests.get(...) / httpx.post(...) / aiohttp… — module.<verb>.
        return f.attr in HTTP_VERB_ATTRS and _root_name(f) in HTTP_CALL_ROOTS

    def _is_tool_call(self, node: ast.Call) -> bool:
        f = node.func
        return isinstance(f, ast.Name) and f.id in self.tool_funcs

    def _untrusted_source_call(self, node: ast.Call) -> bool:
        return (self._is_retrieval_call(node) or self._is_http_call(node)
                or self._is_tool_call(node))

    def _untrusted_name_in(self, node: ast.AST) -> Optional[str]:
        """First name in an expression that is traced to an untrusted source
        (a direct var, an interpolated f-string value, or a chain root), else None.
        Used to decide whether content in the system channel is untrusted world-data."""
        croot = _chain_root(node)
        if croot and croot in self.untrusted_provenance:
            return croot
        for n in _names_in(node):
            if n in self.untrusted_provenance:
                return n
        return None

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
        if node.name in ("eval", "exec", "compile"):
            self.shadowed_builtins.add(node.name)
        for a in node.args.args + node.args.kwonlyargs:
            if _hint_match(a.arg, INPUT_HINTS):
                self.tainted.add(a.arg)
        # A function decorated as an agent tool (@tool, @function_tool, @agent.tool)
        # returns world-data it fetched — untrusted provenance for RG-PROMPT-002.
        is_tool = False
        for dec in node.decorator_list:
            name = (_ctor_name(dec) if isinstance(dec, ast.Call)
                    else getattr(dec, "attr", None) or getattr(dec, "id", None))
            if name and _hint_match(name, TOOL_DECORATOR_HINTS):
                self.tool_funcs.add(node.name)
                is_tool = True
        if is_tool:
            self._check_tool_blast_radius(node)
        self.generic_visit(node)

    def _check_tool_blast_radius(self, node):
        # RG-TOOL-001 / RG-GATE-001. An agent tool whose body performs an
        # irreversible action (delete / send / pay / deploy / HTTP DELETE) is the
        # blast radius the agent can't see. If there's no confirmation / dry-run /
        # human-in-loop gate in the code, escalate (RG-GATE-001). We report only on
        # irreversible tools — read/write tools stay silent — and grade the ungated
        # case MEDIUM, not HIGH: static sees the absence of a CODE gate, never an
        # out-of-band approval, so overclaiming here would cry wolf.
        action = self._irreversible_action_in(node)
        if not action:
            return
        if self._has_gate(node):
            self.findings.append(self._f(
                "low", "Undeclared tool blast radius", node,
                f"The tool `{node.name}` performs an irreversible action ({action}) "
                "and does appear to gate it. Declare its impact explicitly "
                "(read / write / irreversible) so the agent — and your governance "
                "policy — can reason about what this tool can do.",
                evidence=f"tool `{node.name}` -> {action} (gated)",
                confidence="medium", basis="inferred",
                impact="Governance: the tool's blast radius isn't declared, only "
                       "inferred from its body.",
            ))
        else:
            self.findings.append(self._f(
                "medium", "Irreversible tool action without a gate", node,
                f"The tool `{node.name}` performs an irreversible action ({action}) "
                "with no visible confirmation, dry-run, or human-in-loop gate. The "
                "agent's confident-but-wrong 1% can trigger something it can't undo. "
                "Add an explicit gate (a confirm/dry_run parameter, an approval "
                "step) before the irreversible call.",
                evidence=f"tool `{node.name}` -> {action} (no gate)",
                confidence="medium", basis="inferred",
                impact="An irreversible action the agent can invoke with no "
                       "code-level guard — an out-of-band approval could still exist.",
            ))

    def _irreversible_action_in(self, node) -> Optional[str]:
        """A human label for the first irreversible call in a function body, else
        None. High-precision: delete-class fs, HTTP DELETE, unambiguous verbs."""
        for n in ast.walk(node):
            if not isinstance(n, ast.Call):
                continue
            f = n.func
            dotted = (_dotted(f) or "")
            if any(dotted.endswith(s) for s in _FS_DELETE_SINKS):
                return _FS_DELETE_SINKS[next(s for s in _FS_DELETE_SINKS if dotted.endswith(s))]
            if isinstance(f, ast.Attribute):
                if f.attr in _PATH_DELETE_ATTRS:
                    return f"Path.{f.attr}()"
                if f.attr == "delete" and _root_name(f) in HTTP_CALL_ROOTS:
                    return "HTTP DELETE"
                if _hint_match(f.attr, IRREVERSIBLE_VERB_HINTS):
                    return f"{f.attr}()"
            elif isinstance(f, ast.Name) and _hint_match(f.id, IRREVERSIBLE_VERB_HINTS):
                return f"{f.id}()"
        return None

    def _has_gate(self, node) -> bool:
        """True if the function shows any confirmation / dry-run / human-in-loop
        signal — a gate parameter, a gate-named reference, or a confirm/input call."""
        params = {a.arg for a in node.args.args + node.args.kwonlyargs
                  + getattr(node.args, "posonlyargs", [])}
        if any(_hint_match(p, GATE_HINTS) for p in params):
            return True
        for n in ast.walk(node):
            if isinstance(n, ast.Name) and _hint_match(n.id, GATE_HINTS):
                return True
            if isinstance(n, ast.keyword) and n.arg and _hint_match(n.arg, GATE_HINTS):
                return True
            if isinstance(n, ast.Call):
                last = (_dotted(n.func) or "").split(".")[-1] or getattr(n.func, "id", "")
                if last in _GATE_CALL_NAMES or _hint_match(last, GATE_HINTS):
                    return True
        return False

    visit_AsyncFunctionDef = visit_FunctionDef

    # -- the core: classify each call --------------------------------------
    def _is_llm_call(self, node: ast.Call) -> bool:
        func = node.func
        if not isinstance(func, ast.Attribute):
            return False
        attr = func.attr
        dotted = _dotted(func) or ""
        root = _root_name(func)
        # client.embeddings.create() / client.images.generate() / audio, files…
        # are API calls on an LLM client but NOT text generation — a token
        # ceiling (and a runaway text loop) doesn't apply to them.
        if any(seg in NON_TEXT_SURFACES for seg in dotted.lower().split(".")[:-1]):
            return False
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
        # An LLM client constructed in ANY position counts as real LLM usage —
        # not only `x = ChatOpenAI(...)` (handled in visit_Assign for var/taint
        # tracking). Factory methods (`return ChatOpenAI(...)`), bare expressions,
        # and constructors passed as arguments are common; without this a repo
        # whose only production LLM construction is a `return` reads as "not a
        # deployed agent" (gpt-engineer, and the langchain factory pattern at
        # large). Signal only — the var-level capped/taint tracking still needs
        # the assignment target and stays in visit_Assign.
        ctor = _ctor_name(node)
        if ctor and (ctor in LLM_CONSTRUCTORS or ctor in self.llm_aliases):
            self.llm_signal = True
        self._check_llm_token_ceiling(node)
        self._check_exec_sink(node)
        self._check_system_message_ctor(node, ctor)
        self._check_ssrf(node)
        self._check_fs_sink(node)
        self._check_sql_sink(node)
        self._check_secret_to_prompt(node)
        self._check_parse_sink(node)
        self._record_param_update(node)
        self.generic_visit(node)

    def _check_system_message_ctor(self, node: ast.Call, ctor: Optional[str]):
        # RG-PROMPT-002 sink #2: SystemMessage(untrusted) / SystemMessage(content=…)
        # — the LangChain/LangGraph system-channel constructor. Same rule as the
        # role="system" dict: untrusted-provenance content here is indirect injection.
        if ctor not in SYSTEM_MSG_CTORS:
            return
        content = node.args[0] if node.args else None
        for k in node.keywords:
            if k.arg == "content":
                content = k.value
        if content is None:
            return
        hit = self._untrusted_name_in(content)
        if hit:
            self.findings.append(self._f(
                "high", "Untrusted content in instruction channel", node,
                "Content traced from an untrusted source (a retrieval result, an "
                "HTTP response body, or a tool return) is placed in a SystemMessage "
                "— the instruction channel. A poisoned document then reads as an "
                "operator instruction (indirect prompt injection). Keep "
                "retrieved/fetched content in a human/tool message, not the system role.",
                evidence=f"untrusted `{hit}` -> SystemMessage",
                confidence="high", basis="confirmed",
                impact="Indirect prompt injection if the retrieved/fetched/tool "
                       "content can carry attacker-influenced text — it enters the "
                       "instruction channel, not a delimited data turn.",
            ))

    # -- shared helpers for the P1 action sinks ---------------------------------
    def _model_taint(self, arg: Optional[ast.AST]):
        """(value, source, confirmed) if a MODEL-OUTPUT value reaches this argument,
        else None. Deliberately NARROWER than _reaching_taint: the action sinks
        (SSRF / fs / SQL) fire only on model provenance, because a dynamic URL /
        path / query is ubiquitous and benign in ordinary I/O (a data connector
        paginating an API, a temp-file write). Generic user-input SSRF/SQLi is
        Bandit's job; our lane is "the *model* chose the destination/path/query."
        This is what keeps us from crying wolf across an LLM framework's own
        connector code, where `file_has_llm` is true almost everywhere."""
        if arg is None or _is_all_constant([arg]):
            return None
        names = list(_names_in(arg))
        for n in names:
            if n in self.model_extracted:
                return n, "the model's own output", True
        for n in names:
            if n in self.tainted_model and _hint_match(n, MODEL_SOURCE_HINTS):
                return n, "the model's own output", True
        for n in names:
            if n in self.llm_helper_output:
                return n, "output of an in-scope model-generation helper", False
        return None

    @staticmethod
    def _kwarg(node: ast.Call, names) -> Optional[ast.AST]:
        for k in node.keywords:
            if k.arg in names:
                return k.value
        return None

    def _check_ssrf(self, node: ast.Call):
        # RG-ACTION-002. A model/tool/user-controlled URL into an HTTP client is
        # SSRF (fetch an internal endpoint) or exfiltration (POST data out) — the
        # incident that leaves no other code fingerprint. The HTTP call is the SINK
        # here (its RETURN being untrusted is the separate RG-PROMPT-002 concern).
        if not self._is_http_call(node):
            return
        url_arg = node.args[0] if node.args else self._kwarg(node, HTTP_URL_ARG_KEYS)
        reaching = self._model_taint(url_arg)
        if reaching:
            value, source, confirmed = reaching
            # A constant scheme+host prefix with only a tainted path segment is
            # path injection, not full host-controlled SSRF → demote to medium.
            demoted = confirmed and self._has_const_url_prefix(url_arg)
            conf = confirmed and not demoted
            self.findings.append(self._f(
                "high" if conf else "medium",
                "Server-side request from model output", node,
                f"An HTTP request is sent to a URL built from `{value}` — {source}. "
                "A model or tool can steer this to an internal endpoint (SSRF) or an "
                "attacker host. Validate the host against an allowlist before the "
                "request; never let generated text choose the destination.",
                evidence=f"{source} `{value}` -> {(_dotted(node.func) or 'http call')}()",
                confidence="high" if conf else "medium",
                basis="confirmed" if conf else "inferred",
                impact="SSRF / data egress if the host can be model- or "
                       "attacker-influenced — a runtime allowlist could still contain it.",
            ))
            return
        # URL is safe but the request BODY carries tainted data → exfiltration shape.
        body_arg = self._kwarg(node, HTTP_BODY_ARG_KEYS)
        reaching = self._model_taint(body_arg)
        if reaching:
            value, source, _c = reaching
            self.findings.append(self._f(
                "medium", "Server-side request from model output", node,
                f"Model/tool-derived data (`{value}` — {source}) is sent in the body "
                "of an outbound request. If the destination is untrusted this is a "
                "data-exfiltration path. Confirm what leaves the process.",
                evidence=f"tainted body `{value}` -> {(_dotted(node.func) or 'http call')}()",
                confidence="medium", basis="inferred",
                impact="Data egress if the endpoint is untrusted — body is "
                       "model/tool-influenced.",
            ))

    @staticmethod
    def _has_const_url_prefix(node: ast.AST) -> bool:
        """f'https://host/{x}' or 'https://host/' + x — a constant scheme/host with
        only a tainted tail. Path injection, not host-controlled SSRF."""
        if isinstance(node, ast.JoinedStr):
            first = node.values[0] if node.values else None
            return isinstance(first, ast.Constant) and isinstance(first.value, str) \
                and first.value.strip().lower().startswith(("http://", "https://"))
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = node.left
            return isinstance(left, ast.Constant) and isinstance(left.value, str) \
                and left.value.strip().lower().startswith(("http://", "https://"))
        return False

    def _check_fs_sink(self, node: ast.Call):
        # RG-ACTION-003. Delete / overwrite of a model-controlled PATH is
        # irreversible (HIGH); writing model CONTENT to a fixed path is MEDIUM.
        dotted = (_dotted(node.func) or "")
        f = node.func
        # Delete / move / rename family: os.remove, shutil.rmtree, os.rename…
        for suffix, label in _FS_DELETE_SINKS.items():
            if dotted.endswith(suffix):
                for arg in node.args[:2]:  # rename/move take (src, dst)
                    reaching = self._model_taint(arg)
                    if reaching:
                        self._emit_fs(node, reaching, label, irreversible=True)
                        return
                return
        # open(path, 'w'/'a'/'x'…) — a write mode with a model-controlled path.
        if isinstance(f, ast.Name) and f.id == "open" and f.id not in self.shadowed_builtins:
            mode = node.args[1] if len(node.args) > 1 else self._kwarg(node, {"mode"})
            if isinstance(mode, ast.Constant) and isinstance(mode.value, str) \
                    and any(c in mode.value for c in ("w", "a", "x", "+")):
                reaching = self._model_taint(node.args[0] if node.args else None)
                if reaching:
                    self._emit_fs(node, reaching, "open(…, write)", irreversible=True)
            return
        # pathlib bound methods: p.unlink() / p.write_text(content).
        if isinstance(f, ast.Attribute):
            if f.attr in _PATH_DELETE_ATTRS:
                reaching = self._model_taint(f.value)  # the path is the receiver
                if reaching:
                    self._emit_fs(node, reaching, f"Path.{f.attr}()", irreversible=True)
            elif f.attr in _PATH_WRITE_ATTRS:
                path_taint = self._model_taint(f.value)
                if path_taint:
                    self._emit_fs(node, path_taint, f"Path.{f.attr}()", irreversible=True)
                else:  # fixed path, model CONTENT → medium
                    content_taint = self._model_taint(node.args[0] if node.args else None)
                    if content_taint:
                        self._emit_fs(node, content_taint, f"Path.{f.attr}()", irreversible=False)

    def _emit_fs(self, node, reaching, label, irreversible):
        value, source, confirmed = reaching
        high = irreversible and confirmed
        what = ("deletes/overwrites a path" if irreversible
                else "writes content") + f" derived from `{value}`"
        self.findings.append(self._f(
            "high" if high else "medium",
            "Filesystem write/delete from model output", node,
            f"{label} {what} — {source}. A model or tool can then remove or clobber "
            "an arbitrary file; the action can't be undone. Constrain the path to an "
            "explicit sandbox directory and validate it before the operation.",
            evidence=f"{source} `{value}` -> {label}",
            confidence="high" if high else "medium",
            basis="confirmed" if confirmed else "inferred",
            impact=("Irreversible file loss/overwrite if the path is "
                    "model/tool-controlled." if irreversible else
                    "Model-controlled content written to disk — confirm the sink dir."),
        ))

    def _check_sql_sink(self, node: ast.Call):
        # RG-ACTION-004. A raw query built by INTERPOLATION (f-string / + / %)
        # carrying tainted text is SQL injection. A parameterized execute(sql,
        # params) with a constant sql is the correct pattern → never flagged.
        f = node.func
        if not isinstance(f, ast.Attribute) or f.attr not in _SQL_EXEC_ATTRS:
            return
        query = node.args[0] if node.args else None
        # Only an interpolated query is an injection shape. A bare Name or a
        # constant string (even with params) is not this rule's concern.
        if not isinstance(query, (ast.JoinedStr, ast.BinOp)):
            return
        reaching = self._model_taint(query)
        if reaching:
            value, source, confirmed = reaching
            self.findings.append(self._f(
                "high" if confirmed else "medium",
                "SQL built from model output", node,
                f"A SQL query is assembled by interpolating `{value}` — {source} — "
                f"then run via .{f.attr}(). Agent-driven SQL injection: the model, "
                "not an HTTP param, is the taint source. Use a parameterized query "
                "(execute(sql, params)); never interpolate untrusted text into SQL.",
                evidence=f"{source} `{value}` -> .{f.attr}(f\"…\")",
                confidence="high" if confirmed else "medium",
                basis="confirmed" if confirmed else "inferred",
                impact="SQL injection if the interpolated value is untrusted — "
                       "reachability is proven; runtime escaping could still catch it.",
            ))

    def _check_secret_to_prompt(self, node: ast.Call):
        # RG-SECRET-002 (novel — no SAST does this). The REVERSE of exfiltration:
        # your own secret/PII interpolated into a prompt sent to a third-party model
        # provider. A key used as AUTH (api_key=…, headers) is fine — we only scan
        # the content-bearing prompt arguments, never the auth kwargs.
        if not self._is_llm_call(node):
            return
        prompt_args = [a for a in node.args]
        prompt_args += [k.value for k in node.keywords if k.arg in PROMPT_ARG_KEYS]
        for arg in prompt_args:
            names = _names_in(arg)
            lit = names & self.secret_literal_vars
            env = names & self.secret_env_vars
            inline = self._inline_env_read(arg)
            if lit or env or inline:
                value = next(iter(lit or env)) if (lit or env) else "os.environ[…]"
                high = bool(lit)
                self.findings.append(self._f(
                    "high" if high else "medium",
                    "Secret or PII sent to the model provider", node,
                    f"`{value}` is interpolated into a prompt sent to an external LLM "
                    "API. Whatever you place in the prompt leaves your process and is "
                    "logged/retained by the provider — a hardcoded credential or PII "
                    "here is a data-egress leak (distinct from using a key as auth, "
                    "which is fine). Redact secrets/PII before they reach the prompt.",
                    evidence=f"`{value}` -> LLM prompt",
                    confidence="high" if high else "medium",
                    basis="confirmed" if high else "inferred",
                    impact=("A live-looking credential is sent to the model provider "
                            "in the prompt." if high else
                            "A secret/PII-shaped value reaches the prompt — confirm "
                            "it isn't sensitive."),
                ))
                return

    @staticmethod
    def _inline_env_read(node: ast.AST) -> bool:
        """os.environ[...] / os.getenv(...) used INLINE inside a prompt expression."""
        for n in ast.walk(node):
            if _Analyzer._is_env_read(n):
                return True
        return False

    def visit_ClassDef(self, node: ast.ClassDef):
        # A yaml Loader that subclasses SafeLoader/BaseLoader/CSafeLoader is safe.
        for base in node.bases:
            bn = (_dotted(base) or getattr(base, "id", "") or "").lower()
            if any(safe in bn for safe in _SAFE_YAML_LOADERS):
                self.safe_yaml_loaders.add(node.name.lower())
        self.generic_visit(node)

    def visit_Try(self, node: ast.Try):
        # A parse inside the try BODY is guarded (RG-PARSE-001). The except/else/
        # finally blocks are NOT protected by this try, so scope the depth to body.
        self._try_depth += 1
        for stmt in node.body:
            self.visit(stmt)
        self._try_depth -= 1
        for h in node.handlers:
            self.visit(h)
        for stmt in node.orelse + node.finalbody:
            self.visit(stmt)

    def _check_parse_sink(self, node: ast.Call):
        # RG-PARSE-001. json.loads / ast.literal_eval on MODEL output with no
        # surrounding try/except — the model returns malformed JSON and the agent
        # crashes (or acts on garbage). Advisory (reliability), model-scoped so we
        # don't flag every json.loads in a codebase.
        dotted = (_dotted(node.func) or "")
        if not any(dotted.endswith(s) for s in _PARSE_SINK_SUFFIXES):
            return
        if self._try_depth > 0:  # guarded by try/except → correct pattern
            return
        reaching = self._model_taint(node.args[0] if node.args else None)
        if not reaching:
            return
        value, source, _c = reaching
        label = dotted.split(".")[-2] + "." + dotted.split(".")[-1] if "." in dotted else dotted
        self.findings.append(self._f(
            "low", "Unvalidated model-output parse", node,
            f"{label}() parses `{value}` — {source} — with no surrounding "
            "try/except. Model output is frequently malformed or unexpectedly "
            "shaped; an unguarded parse turns that into a crash, and a parse with "
            "no schema check lets the agent act on garbage. Wrap it in try/except "
            "and validate the result (pydantic / explicit key checks).",
            evidence=f"{source} `{value}` -> {label}() (unguarded)",
            confidence="medium", basis="inferred",
            impact="Reliability: a malformed model response crashes the agent or "
                   "feeds unvalidated data into control flow. Not a security issue.",
        ))

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

    # Loop-counter / budget names: a break guarded by one of these bounds the loop.
    _BOUND_HINTS = ("max", "limit", "attempt", "attempts", "retry", "retries",
                    "tries", "iteration", "iterations", "count", "counter",
                    "budget", "deadline", "timeout", "remaining", "steps", "turns")

    @classmethod
    def _has_bounded_break(cls, node: ast.While) -> bool:
        """True if the loop body contains an exit guarded by a comparison against
        a counter/budget-style bound: `if attempts >= max_retries: break` (or
        return/raise). That's the ubiquitous bounded-retry pattern — flagging it
        as an unbounded runaway is a false positive. A model-controlled break
        (`if "DONE" in reply: break`) does NOT qualify: the model is not a cap.
        """
        for n in ast.walk(node):
            if not isinstance(n, ast.If):
                continue
            has_compare = any(isinstance(c, ast.Compare) for c in ast.walk(n.test))
            if not has_compare:
                continue
            if not any(_hint_match(name, cls._BOUND_HINTS) for name in _names_in(n.test)):
                continue
            if any(isinstance(b, (ast.Break, ast.Return, ast.Raise))
                   for stmt in n.body for b in ast.walk(stmt)):
                return True
        return False

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
                    if self._has_bounded_break(node):
                        break  # counter/budget-guarded exit → bounded retry, not a runaway
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
        # The client itself was constructed with a ceiling (ChatOpenAI(max_tokens=…))
        # — every call through it is capped, whatever the call site passes.
        if _root_name(node.func) in self.llm_vars_capped:
            return
        # A provider config OBJECT (google-genai `config=GenerateContentConfig(…)`)
        # can carry the ceiling where we can't see it. Absence unprovable → quiet.
        # (A literal dict config is still checked for its keys.)
        for k in node.keywords:
            if k.arg and k.arg.lower() in CONFIG_OBJECT_KWARGS:
                if isinstance(k.value, ast.Dict):
                    ck = {c.value.lower() for c in k.value.keys
                          if isinstance(c, ast.Constant) and isinstance(c.value, str)}
                    if ck & TOKEN_KEYS:
                        return
                    continue  # literal dict with no ceiling → keep checking
                return  # opaque config object → can't prove absence, stay quiet
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
            label = _BUILTIN_SINKS.get(func.id)
            if label and func.id in ("eval", "exec", "compile"):
                # Not the dangerous builtin if it's shadowed in this file, or
                # called with more positional args than the builtin accepts
                # (eval/exec/compile take ≤3): `eval(model, request, body,
                # stream, ...)` is a project's own generation fn, not RCE.
                if func.id in self.shadowed_builtins or len(node.args) > 3:
                    return None
            return label
        if not isinstance(func, ast.Attribute):
            return None
        dotted = (_dotted(func) or "").lower()
        for suffix, label in _ATTR_SINKS.items():
            if dotted.endswith(suffix):
                return label
        # subprocess.* is a shell sink with shell=True. A list-arg call
        # (subprocess.Popen([...])) runs no shell and is not flagged.
        if ".subprocess." in ("." + dotted) or _root_name(func) == "subprocess":
            if any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True
                   for k in node.keywords):
                return "subprocess(shell=True)"
            # No shell=True, but the command is a STRING built at runtime
            # (f-string / concatenation) rather than a list argv — the deliberate
            # "assemble a command line" anti-pattern. On Windows subprocess runs a
            # string via cmd; cross-platform it's the shape that becomes injection
            # the moment shell=True is added. A bare Name stays ambiguous (could be
            # a list) → not flagged, preserving the subprocess.run(cmd_list) case.
            first = node.args[0] if node.args else None
            if isinstance(first, (ast.JoinedStr, ast.BinOp)):
                return "subprocess (string command)"
            return None
        # yaml.load(...) is unsafe UNLESS given a Safe/Base Loader. yaml.safe_load
        # isn't in the registry, so it's never flagged.
        if dotted.endswith("yaml.load"):
            for k in node.keywords:
                if k.arg and k.arg.lower() == "loader":
                    ld = (_dotted(k.value) or getattr(k.value, "attr", "") or "").lower()
                    # Known-safe loader name, OR a custom loader defined in this
                    # file that subclasses one (class YamlLoader(yaml.SafeLoader)).
                    if any(safe in ld for safe in _SAFE_YAML_LOADERS) \
                       or ld in self.safe_yaml_loaders:
                        return None
            return "yaml.load()"
        return None

    def _reaching_taint(self, arg_names):
        """Return (value_name, source_label, confirmed) for the tainted value
        reaching a sink, or None.

        `confirmed` distinguishes evidence we can SEE (a value assigned from an
        LLM call in scope, or an unambiguous external-input name like `request`)
        from a value we only INFER from a generic/serialized name (`data`,
        `message_ser`) whose real source isn't visible here. That distinction is
        what keeps us from asserting "confirmed RCE" on a framework's own internal
        pickling (the livekit / MetaGPT false-positive class).
        """
        # A value received off a local IPC pipe is trusted internal transport,
        # never external input — don't let a generic name make it look like a
        # user-controlled RCE surface.
        arg_names = [n for n in arg_names if n not in self.local_ipc_vars]
        # Confirmed: text extracted off a model response in scope
        # (resp.choices[0].message.content). Provenance is fully visible, so the
        # var name is irrelevant here — unlike a bare object var, this IS the
        # model's text reaching the sink.
        for n in arg_names:
            if n in self.model_extracted:
                return n, "the model's own output", True
        # Confirmed (RG-EXEC-004): traced from an untrusted external source in
        # scope — a retrieval result, an HTTP response body, or a @tool return.
        # Reaching pickle/eval/a shell, this is the taint-aware upgrade: what was
        # an INFERRED "unverified data" medium becomes a CONFIRMED high, because we
        # can point at the network/tool origin, not just guess from a name.
        for n in arg_names:
            if n in self.untrusted_provenance:
                return n, "an untrusted external source (retrieval / HTTP / tool output)", True
        # Confirmed: assigned from an LLM call we can see in this file.
        for n in arg_names:
            if n in self.tainted_model and _hint_match(n, MODEL_SOURCE_HINTS):
                return n, "the model's own output", True
        # Confirmed: an unambiguous external-input name (request/body/payload/…).
        # NB: uses SINK_STRONG_INPUT_HINTS — a bare args/params/prompt is the
        # local operator's own CLI input, not a confirmed remote RCE surface.
        for n in arg_names:
            if _hint_match(n, SINK_STRONG_INPUT_HINTS):
                return n, "external user/request input", True
        # Inferred: the name hints at model/user data, but the source isn't
        # visible here (a bare parameter, a generic name). Present, not proven.
        # Inferred: assigned from an in-scope helper whose name says "codegen"
        # (generate_blender_code → exec). Source is one hop away, not a bare name.
        for n in arg_names:
            if n in self.llm_helper_output:
                return n, "output of an in-scope code-generation helper", False
        for n in arg_names:
            if _hint_match(n, MODEL_SOURCE_HINTS):
                return n, "possible model output", False
            if _hint_match(n, USER_SOURCE_HINTS) or n in self.tainted:
                return n, "data of unverified origin", False
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
            value, source, confirmed = reaching
            # Intentional (if weak) sandbox: exec(code, {"__builtins__": {}}, …).
            # The maintainer stripped builtins — a deliberate restriction (lollms'
            # custom-node editor). Empty-builtins is bypassable, so it's still a
            # surface, but we must NOT assert a confirmed public RCE over a guard
            # they clearly put there. Demote confirmed→inferred.
            if confirmed and kind == "exec()" and _restricts_builtins(node):
                confirmed = False
                source = source + " (into an empty-__builtins__ sandbox — a weak, bypassable restriction)"
            # Deserialization (pickle/marshal/dill) is ubiquitous for a
            # framework's OWN internal transport — IPC, caching, state persistence.
            # So when the source is only INFERRED from a name, we do NOT assert a
            # confirmed RCE (that's the livekit/MetaGPT false-positive class); we
            # flag it MEDIUM/inferred: "real if the source is untrusted; confirm
            # it." Code-execution sinks (eval/exec/os.system/…) are almost never
            # benign, so they stay HIGH even on an inferred source.
            if kind in _DESERIALIZATION_SINKS and not confirmed:
                self.findings.append(self._f(
                    "medium", "Deserialization of unverified data", node,
                    f"{kind} deserializes `{value}`, whose source isn't visible "
                    "here. If it can ever come from an untrusted channel (network, "
                    "another process, a shared store, model/tool output) this is "
                    "remote code execution; if it's always your own local/trusted "
                    "data it's fine. Confirm the source, or use a safe format "
                    "(json / a signed payload).",
                    evidence=f"{kind} on `{value}` (source unverified)",
                    confidence="medium", basis="inferred",
                    impact="RCE only if an untrusted source can reach this sink — "
                           "provenance not proven here.",
                ))
                return
            # The agent-specific, undismissable case: name the exact value and its
            # source so the finding reads like evidence, not a pattern hit.
            # Severity follows proof: a flow we can SEE is high; a flow inferred
            # from a name alone is medium — same calibration as deserialization.
            # Asserting HIGH on a name-guess is how a report loses its maintainer.
            self.findings.append(self._f(
                "high" if confirmed else "medium",
                "Dangerous execution sink", node,
                f"{kind} executes `{value}` — {source}. A prompt injection your "
                "input guardrail can't catch (it succeeds inside the model) or a "
                "bad tool result becomes remote code execution here, after your "
                "output evaluator has already scored the text. Parse with "
                "ast.literal_eval/json, or sandbox execution.",
                evidence=f"{source} `{value}` -> {kind}",
                confidence="high" if confirmed else "medium",
                basis="confirmed" if confirmed else "inferred",
                impact="Remote code execution if model/user output reaches this sink."
                       if confirmed else
                       "Remote code execution if the inferred source is real — "
                       "flow not proven here.",
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
        # RG-PROMPT-002 (supersedes 001 for this node): the content is TRACED to
        # an untrusted external source — retrieval result, HTTP body, tool return.
        # Provenance, not a name hint, so it grades confirmed/HIGH. Fires whether
        # the content is interpolated (f"...{docs}") or placed directly
        # ("content": docs). A role="user"/"tool" turn carrying the same value is
        # the CORRECT pattern and never reaches here (role_is_system gates it).
        if role_is_system and content_val is not None:
            hit = self._untrusted_name_in(content_val)
            if hit:
                self.findings.append(self._f(
                    "high", "Untrusted content in instruction channel", content_val,
                    "Content traced from an untrusted source (a retrieval result, "
                    "an HTTP response body, or a tool return) is placed in the "
                    "system/instruction channel. A poisoned document then reads as "
                    "an operator instruction — indirect prompt injection your input "
                    "filter never sees, because the text arrives from your own "
                    "retrieval/tool layer, not the user turn. Keep retrieved/fetched "
                    "content in a clearly-delimited user/data turn so it can't "
                    "override system instructions.",
                    evidence=f"untrusted `{hit}` -> system/instruction channel",
                    confidence="high", basis="confirmed",
                    impact="Indirect prompt injection if the retrieved/fetched/tool "
                           "content can carry attacker-influenced text — it enters "
                           "the instruction channel, not a delimited data turn.",
                ))
                self.generic_visit(node)
                return
        if role_is_system and isinstance(content_val, ast.JoinedStr):
            interp = [v for v in content_val.values if isinstance(v, ast.FormattedValue)]
            # Only the interpolations that could be UNTRUSTED matter. Three kinds
            # of names are the developer's own material, not an injection surface:
            #   * ALL_CAPS module constants (BROWSER_SYSTEM_MESSAGE)
            #   * vars only ever assigned literal strings in this file
            #     (strategy_guidance = "…" in an if/elif chain)
            #   * prompt-material names (agent_role_prompt, auto_agent_instructions,
            #     persona, template…) — composing a system prompt out of prompt
            #     parts IS how system prompts are built.
            const_vars = self.assigned_const - self.assigned_dynamic
            def _is_trusted(fv):
                ns = _names_in(fv.value)
                return ns and all(
                    re.fullmatch(r"[A-Z][A-Z0-9_]*", n)
                    or n in const_vars
                    or _hint_match(n, PROMPT_MATERIAL_HINTS)
                    for n in ns)
            dynamic = [fv for fv in interp if not _is_trusted(fv)]
            if dynamic:
                names = set()
                for fv in dynamic:
                    names |= _names_in(fv.value)
                # High only when a clearly external user/request value flows in
                # ("prompt" itself doesn't count here — that's prompt material).
                # Model-output / tainted names → medium. A generic identifier
                # (field_name, language_name) is usually developer config → low.
                strong = any(_hint_match(n, SYSTEM_PROMPT_STRONG_HINTS) for n in names)
                modelish = any(_hint_match(n, MODEL_SOURCE_HINTS) or n in self.tainted
                               for n in names)
                sev = "high" if strong else ("medium" if modelish else "low")
                self.findings.append(self._f(
                    sev,
                    "Interpolated system prompt (injection surface)", content_val,
                    "User/model-influenced text is interpolated into a system "
                    "prompt. Move untrusted input into a clearly-delimited user "
                    "turn so it can't override system instructions.",
                    confidence="high" if strong else "low",
                    basis="confirmed" if strong else "inferred",
                    impact="Prompt-injection surface: untrusted text can override "
                           "system instructions." if strong or modelish else
                           "Injection surface only if this value can carry "
                           "untrusted text — it reads as developer config.",
                ))
        self.generic_visit(node)

    def _f(self, severity: str, title: str, node: ast.AST, rec: str,
           evidence: str = "", confidence: str = "medium",
           basis: str = "inferred", impact: str = "") -> Dict[str, Any]:
        # confidence: how sure we are this is what we say it is (high/medium/low).
        # basis: "confirmed" = we can point at the exact tainted flow / structure;
        #        "inferred"  = the pattern is present but reachability isn't proven.
        # These let a developer triage instantly and let CI gate on confirmed-only.
        from release_gate.rules import rule_id_for_title
        return {
            "severity": severity, "title": title, "file": self.rel,
            "line": getattr(node, "lineno", 0), "snippet": "",
            "recommendation": rec, "evidence": evidence,
            "confidence": confidence, "basis": basis, "impact": impact,
            # Stable, citable rule id (RG-EXEC-001) — never changes when a title is reworded.
            "rule_id": rule_id_for_title(title),
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

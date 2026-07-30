# Deployed-agent dogfood corpus

The labeled [benchmark](RESULTS.md) proves *precision*. This corpus is the other
half: real repos we scan to find where the engine is **wrong or silent**. Every
false-positive class we've fixed came from a run over these.

Two corpora, deliberately different, because they answer different questions.

## 1. Frameworks — "do we cry wolf on mature code?"

`llama_index · crewAI · langgraph · open-interpreter · mem0 · smolagents ·
autogen · pydantic-ai · openai-agents-python · letta · khoj · gpt-researcher ·
AgentGPT · ChatDev · MetaGPT · SuperAGI · owl`

Latest run: **0 highs, 90 advisory findings.** These are *libraries* — the thing
users build with. A high here is almost always our bug, so this corpus is a
precision guard.

## 2. Agent applications — "do we find anything where it matters?"

The thing release-gate actually gates: software people **deploy**. Reproduce with
`benchmark/corpus-agents.sh`.

| Repo | Kind |
|---|---|
| All-Hands-AI/OpenHands | coding agent |
| princeton-nlp/SWE-agent | coding agent |
| Aider-AI/aider | coding agent |
| Codium-ai/pr-agent | PR review agent |
| potpie-ai/potpie | codebase agent |
| AntonOsika/gpt-engineer | code generation + execution |
| stitionai/devika | coding agent |
| browser-use/browser-use | browser agent |
| Skyvern-AI/skyvern | browser automation agent |
| danny-avila/LibreChat | chat product |
| open-webui/open-webui | chat product |
| langgenius/dify | LLM app platform |
| infiniflow/ragflow | RAG product |
| QuivrHQ/quivr | RAG product |
| modelcontextprotocol/servers | MCP servers |
| block/goose | agent runtime |
| Upsonic/Upsonic | agent framework + tool suite |
| frdel/agent-zero | agent runtime |
| e2b-dev/fragments | code-exec app |
| OpenInterpreter/open-interpreter | code-exec agent |

### What this corpus taught us (0.9.4)

**1. The scanner was silently truncating.** `max_files` was 2,000; `dify` has
8,892 scannable files, so it was graded on **22% of its code** and still printed
a clean verdict. Deployed agents are monorepos — this hit the target market
exactly. Fixed: ceiling raised to 25,000, plus `scan_coverage` in the report and
a loud `⚠ TRUNCATED` banner, because a partial scan that looks clean is the most
damaging thing this tool can output.

**2. Blast radius is the signal that actually fires on deployed agents.**
`RG-GATE-001` is the top non-advisory finding across the corpus — real
irreversible tools with no code-level gate (`send_email`, `delete_file`,
`delete_message`, `shutdown_sandbox`). Two fixes came out of it: a tool's **name**
is its contract with the model (Upsonic's toolkits delegate to SDK clients that
body-only scanning can't resolve), while drafts (`create_draft_email`) and
validators (`_validate_email_params`) are not irreversible actions.

**3. Taint-based detection does not reach real agent architectures.** Zero
confirmed HIGHs across 20 apps that demonstrably execute model output. The flow
in `gpt-engineer` shows why:

```
ai.start(...) → messages[-1].content → regex → FilesDict{...}      # module A
        ↓ crosses a module boundary
command = files_dict[ENTRYPOINT_FILE] → written to disk → "bash run.sh"  # module B
        ↓
subprocess.Popen(command, shell=True)                              # module C
```

Four boundaries: function, module, **data structure**, and **filesystem**. 0.9.4
closed three of them — function summaries, a whole-program cross-module index,
and file-mediated taint (write to a path, later execute it). Real agents
marshal model output into objects, persist it as files, and execute it by path —
or hand it to a container, where the sink is an API call we don't model. The
labeled benchmark tests `x = llm(); sink(x)` in one function; production agents
never look like that. **0.9.4 closed the first hop and measured the rest.** Taint now follows a local
helper's return across the call boundary (both `*-cross-function` benchmark cases
went from KNOWN-MISS to caught, taking the labeled corpus to **100% recall** with
precision unchanged). But on this corpus it barely moved: **70 findings before, 72 after all of
0.9.4's taint work** — inter-procedural, cross-module, file-mediated, method
summaries and container mutation combined — and **still 0 confirmed HIGHs**. **What actually blocks `gpt-engineer` turned out to be none of those.** Its model
call is `ai.start(...)` — a **method on a project-defined class** (`AI` in
`core/ai.py`, wrapping `ChatOpenAI`), reached transitively via
`start` → `next` → `self.llm.invoke`. Cross-module summaries resolve
`from x import func`; they do not resolve a method on a class reached through a
variable's type. That — method-level summaries with transitive resolution — is
the next milestone, and it is a sharper target than "cross-module" was.

**The honest conclusion.** Closing four hops took the labeled corpus from 94.3%
to 100% recall and did essentially nothing here. So the deployed-agent gap was
never mainly about those hops. What remains is a client built by a *factory
method*, model output marshalled through *project-specific container and store
classes*, and execution delegated to a *container* (Docker/E2B) where the sink is
an API call we don't model. Those need whole-program type inference, not another
traversal trick.

Meanwhile the rule that does fire here — `RG-GATE-001`, irreversible tools with
no code-level gate — is architecture-level, not dataflow. That is the signal to
build on for deployed agents.

We publish the numbers that did not move, not just the ones that did.

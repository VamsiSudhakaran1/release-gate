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

## 2. MCP servers — "where does the gate actually fire?"

28 servers weighted toward capability surface (`benchmark/corpus-mcp.sh`):
shell-executing (hexstrike-ai, pentest-ai, Windows-MCP, agent-infra/sandbox),
irreversible real-world actions (google_workspace, ha-mcp, tradingview,
linkedin), and broad tool platforms (awslabs/mcp, aci, fastmcp).

**This is the segment that produces findings.** 155 findings across 28 repos vs
72 across 20 deployed agent apps — and they concentrate exactly where capability
does: awslabs/mcp, ha-mcp, davinci-resolve-mcp, google_workspace_mcp.

Almost all of it is `RG-GATE-001`: irreversible tools with no code-level gate.
The taint rules stayed quiet again. The architecture-level rule is the one that
works on real agent surfaces.

**Three false-positive classes were caught here by triage, before any of it
became outreach material** — which is the point of the corpus:

1. **Placeholder secrets with words in between.** PrefectHQ/fastmcp's docstring
   example uses `client_secret="your-auth0-client-secret"`; the placeholder
   pattern required the credential word immediately after `your-`. Both HIGHs in
   the corpus were this, in a 27k-star repo.
2. **A read verb beaten by an irreversible noun.** awslabs'
   `get_cloudformation_pre_deploy_validation_instructions` matched "deploy",
   `list_metadata_transfer_jobs` matched "transfer".
3. **The same class through the body.** That getter's body calls
   `cloudformation_pre_deploy_validation()`, so fixing the name check alone left
   it firing.

4. **In-memory collection mutation.** awslabs' `connect_to_database` calls
   `db_connection_map.remove(...)` to drop a broken connection from an in-process
   pool on error. Python's collection API (`remove`/`pop`/`discard`/`clear`)
   collides with destructive verbs; bookkeeping is not a real-world action.

5. **Namespaced tool names.** MCP tools are namespaced (`ha_get_zone`,
   `ha_config_list_helpers`), so an *anchored* read-verb rule matched none of
   them and every Home Assistant getter was reported as destructive.

6. **A gate layer the check couldn't see — found by a maintainer, not by us.**
   `RG-GATE-001` claims "this tool has no gate", a statement about the whole
   project, but only ever inspected tool *function bodies*. homeassistant-ai/ha-mcp
   ships a `ReadOnlyMiddleware` that blocks writes at call time, a catalog
   transform that hides write tools, a persisted tool-security policy and MCP
   `readOnlyHint` annotations. We filed an issue suggesting they add exactly
   those things; the maintainer replied that none of it was missing. They were
   right. The scan now detects a central gate layer across the repo and collapses
   the per-tool findings into one advisory note — 19 accusations became 1 note on
   ha-mcp. **awslabs/mcp and google_workspace_mcp trip the same detection**, so
   the queued AWS issue would have been wrong in the same way.

7. **The canonical agent loop, graded HIGH 39 times.** `shareAI-lab/learn-claude-code`
   (73k stars) returned 39 confirmed HIGHs, all `RG-LOOP-001` on `while True:` —
   each with an EMPTY evidence field. Every one is the standard agent loop: it
   exits when the model stops requesting tools and caps tokens per turn. We were
   grading the defining pattern of our own domain as a confirmed defect. Now a
   LOW advisory ("consider an iteration cap"); only a loop with NO exit path
   stays HIGH.

   The deeper failure was the invariant: it required provenance only for the
   TAINT rules, so a HIGH with *no evidence at all* passed. Tightened to require
   non-empty evidence on every HIGH — which immediately exposed the same flaw in
   `RG-PROMPT-001` (Python and JS) and in every JS finding, because the JS
   `_finding()` constructor had no evidence field. All fixed.

8. **MCP tool annotations, missed on the Python SDK.** `jeff-nasseri/mikrotik-mcp`
   annotates all 28 of its destructive tools `annotate(DESTRUCTIVE, ...)` —
   textbook MCP practice, where the server declares `destructive_hint` and the
   client prompts. The gate detector matched only camelCase `destructiveHint`
   (TypeScript SDK); the Python SDK uses snake_case, so every correctly-annotated
   Python MCP server looked ungated. We had a 21-tool issue drafted and were one
   step from filing it — the ha-mcp mistake, one week later. Caught by reading
   the source before sending. 21 accusations became 1 note.

Eight classes. Six were caught by reading source before sending; the sixth cost a
public correction — and was the most valuable of the lot, because no labeled
benchmark can encode "gated somewhere else in the repo". Verify before you send,
and expect the population where this rule legitimately fires to be *immature*
projects, not well-engineered ones.

## 3. Agent applications — "do we find anything where it matters?"

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

## 4. RAG / retrieval apps — "can we check what teams check by hand?"

Added for RG-PII-001. 17 repos: `HKUDS/LightRAG · microsoft/graphrag ·
onyx-dot-app/onyx · VectifyAI/PageIndex · pathwaycom/pathway ·
unclecode/crawl4ai · bytedance/deer-flow · TauricResearch/TradingAgents ·
AstrBotDevs/AstrBot · harry0703/MoneyPrinterTurbo · google/langextract ·
zhayujie/CowAgent · sansan0/TrendRadar · ZhuLinsen/daily_stock_analysis ·
hsliuping/TradingAgents-CN · shareAI-lab/learn-claude-code` plus a live
LangGraph financial-RAG app whose maintainer described their manual pre-deploy
checklist — one item of which ("regex masking before context reaches an external
LLM endpoint") is what the rule was built from.

**Result: 0 findings, and 0 egress sites at all** across ~9,500 files. Total
findings across the corpus were identical before and after the change (111), so
the new sink detection perturbed nothing else.

Zero false positives is the easy half. The honest half is that there were no
true positives either, and the reason is not the rule's design — it is that the
*source* never reaches the sink:

```
retriever_node:  index.query(...) → context → return {"retrieved_chunks": …}
                          ↓  framework-managed state dict, across node functions
generator_node:  chunks = state.get("retrieved_chunks")   ← taint dies here
                 context = "\n".join(...) → call_llm(system, f"…{context}…")
```

Two hops, and only one of them got closed. The **sink** side is now reached:
`call_llm` is a project-defined wrapper POSTing to a Gemini URL, invisible to an
SDK-shaped detector until we started matching provider *hosts*. The **source**
side dies at a framework-managed, string-keyed state dictionary passed between
node functions — the "data structure" boundary section 3 already named as open.

That is a sharper target than "cross-module" was: a LangGraph state channel is an
enumerable pattern (a node returns `{"k": tainted}`, another reads `state["k"]`),
not a general type-inference problem. It is the next milestone, and it is now
backed by a measurement rather than a hunch.

What we will *not* do is loosen the rule to manufacture findings. RG-PII-001 fires
only where a repo masks on one path and not another; a version that fires on "no
masking found" would light up all 17 of these repos tomorrow and every one of
those findings would be the ha-mcp mistake again.

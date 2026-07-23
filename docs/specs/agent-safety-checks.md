# Spec — Agent-safety checks (build queue)

> Status: **specification, not yet built.** This is the ready-to-build backlog for
> the next static-analysis rules, ordered by priority. Each entry is specced enough
> to implement without re-deriving the design. Build order follows the priority
> tags; nothing here ships unless it holds the precision bar (see *The precision
> contract* at the bottom). Companion to `ROADMAP.md` — the roadmap says *why* and
> *when*, this says *what* and *how*.

## Design lens

These rules are designed from the **deployed agent's point of view**: what does an
agent need *guaranteed about its environment and its own outputs* before it is safe
to act autonomously? The gate is not a leash — it is the seatbelt that lets an agent
be trusted with more rope. Each check maps to a structural agent **blind spot**: a
boundary it cannot see, a mistake it cannot take back, state it cannot observe
mid-turn, authority it cannot measure, or a fabrication it cannot feel.

## Priority legend

| Tag | Meaning |
|---|---|
| **P0 — critical** | Highest agent-protective value, statically buildable now, precision-holdable. **Start next week.** |
| **P1 — high** | Strong value, reuses the taint engine or a novel differentiator; build after P0. |
| **P2 — medium** | Worth building; either lower incidence, a cheap reliability win, or depends on a P1/P2 item. |
| **P3 — frontier** | Real value but poorly served by *static* analysis — mostly behavioral; feeds `agent-score`/`loop-sim`, doesn't live in the static gate. |

---

## P0 — critical (start next week)

### RG-PROMPT-002 — Instruction/data separation (untrusted source → instruction channel)
- **Blind spot:** an agent cannot tell operator *instructions* from world *data* once
  they are concatenated. Blended, a poisoned document becomes a command.
- **Extends:** `RG-PROMPT-001` today fires only on a **system-prompt f-string** and
  keys on **name hints**. This generalizes it to real *provenance*.
- **Sources to track as untrusted (taint):** tool/function return values, retrieval
  results (`top_k`, vector-store `.query`/`.search` returns), HTTP/fetch output
  (`requests`/`httpx`/`urllib` response bodies), file reads of non-config paths,
  inter-agent messages. Reuse and extend the existing `tainted` set in `_Analyzer`.
- **Sink:** that tainted value flowing into the **instruction/system channel** —
  `role="system"`, a system-prompt variable, or the leading/instruction segment of a
  composed prompt — rather than a clearly delimited user/data turn.
- **Grading:** **confirmed HIGH** when a tracked untrusted source reaches the system
  channel in-scope; **inferred MEDIUM** when the source is name-hinted but not
  traced; **advisory LOW** for generic identifiers that read as developer config.
- **False-positive controls (must-have):** developer-authored prompt material
  (`persona`, `template`, `agent_role_prompt`, constant strings) is NOT untrusted —
  keep the `_is_trusted` / `PROMPT_MATERIAL_HINTS` guards. A delimited user turn
  (`role="user"`) carrying the untrusted text is the *correct* pattern → not a finding.
- **Coverage honesty:** static sees the concatenation, not whether a downstream
  guardrail neutralizes the injection at runtime.
- **Build notes:** new `visit_*` provenance tracking in `agent_analysis.py`
  `_Analyzer`; the sink test lives near the existing system-prompt f-string handler
  (~line 789). This is the single check an agent most wants to exist.

### RG-ACTION-001 — Shell / OS command from model output
- **Blind spot:** the most common *real* agent RCE. Careful teams already avoid
  `eval` (muscle memory); piping model output into a shell is the un-memorized reflex.
- **Source → sink:** model/tool output → `os.system`, `subprocess.*(..., shell=True)`,
  `subprocess` with a string command, `os.popen`, `commands.getoutput`.
- **Grading:** **confirmed HIGH** when model taint reaches the command with a visible
  source; **inferred MEDIUM** when the argument is unproven (the camel disposition).
  `shell=True` with any interpolation is the strongest signal.
- **FP controls:** a fully static/constant command is not a finding. A list-form
  `subprocess.run([...])` with no shell and constant argv is safe. Respect the
  existing `shadowed_builtins` pattern for redefined names.
- **Coverage honesty:** static sees the taint→sink path, not whether an allowlist or
  sandbox contains it at runtime.
- **Build notes:** extend `_check_exec_sink` to a sink *catalog* rather than a fixed
  `eval/exec/compile` set; this is the first member of the widened catalog.

---

## P1 — high

### RG-ACTION-002 — Network egress / SSRF from model output
- **Source → sink:** model-controlled URL or request body → `requests.get/post`,
  `httpx`, `urllib.request`, `aiohttp`. The agent can be steered to fetch internal
  endpoints or exfiltrate to an attacker host — the incident that leaves *no code
  fingerprint*, and the one static slice of it we can see.
- **Grading:** confirmed HIGH when the URL/host is model-tainted; inferred MEDIUM when
  only the body is tainted or the source is unproven.
- **FP controls:** a constant/allowlisted base URL with only a tainted *path segment*
  is lower severity; a fully constant URL is not a finding.
- **Coverage honesty:** static can't see runtime allowlists / egress firewalls.

### RG-SECRET-002 — Secret / PII → prompt → third-party model (data egress)
- **Novel — no SAST checks this.** The *reverse* of exfiltration: leaking **your**
  secrets to the model provider.
- **Source → sink:** a hardcoded secret (reuse `RG-SECRET-001` detectors), an env var
  (`os.environ[...]`), or a DB/PII-shaped field interpolated into a **prompt string**
  that is sent to an **external LLM API**.
- **Grading:** confirmed HIGH for a hardcoded-secret-shaped value into a prompt;
  MEDIUM for env-var/PII-shaped names; advisory LOW for ambiguous identifiers.
- **FP controls:** secrets used as *auth* (an API key passed to the client
  constructor / headers) are NOT prompt egress — only flag flow into prompt *content*.
- **Differentiator framing:** ship as the "nobody else looks at this" headline check.

### RG-ACTION-003 — Filesystem write / delete from model output
- **Source → sink:** model output → `open(path, 'w'/'a')`, `os.remove`, `os.unlink`,
  `shutil.rmtree`, `Path.write_text`, `Path.unlink`, `os.rename` where the path or
  content is model-controlled.
- **Grading:** delete/overwrite of a model-controlled path = HIGH (irreversible);
  write of model content to a fixed path = MEDIUM.
- **FP controls:** writes under an explicit sandbox/temp dir constant are lower
  severity; reads are out of scope for this rule.

### RG-ACTION-004 — SQL execute from model output
- **Source → sink:** model output interpolated into a raw query →
  `cursor.execute(f"...")`, string-built SQL, `.executescript`. Agent-driven SQLi;
  the taint source is the LLM, not an HTTP param.
- **Grading:** confirmed HIGH for f-string/`%`/`+` interpolation of a tainted value;
  parameterized queries (`execute(sql, params)`) are the correct pattern → no finding.
- **FP controls:** ORM calls with bound parameters are safe; constant SQL is safe.

### RG-EXEC-004 — Taint-aware deserialization
- **Upgrade, not net-new:** today `pickle.loads` reads as a generic/**inferred**
  medium (seen on smolagents, MetaGPT). Make it **taint-aware**: when the deserialized
  bytes trace to model/tool/network output, upgrade to **confirmed**.
- **Source → sink:** model/tool/network output → `pickle.loads`, `yaml.load` (unsafe
  loader), `marshal.loads`, `dill.loads`.
- **FP controls:** `yaml.safe_load` and SafeLoader subclasses are safe (existing
  `_SAFE_YAML_LOADERS` handling); a constant/embedded fixture is inferred, not confirmed.

---

## P2 — medium

### RG-PARSE-001 — Unvalidated model-output parse (reliability, not security)
- **Cheap win; widens the buyer past security teams.** The everyday "model returned
  malformed/unexpected JSON → agent crashed or acted on garbage."
- **Pattern:** `json.loads(model_output)` / `ast.literal_eval(model_output)` whose
  result feeds control flow, with **no** surrounding `try/except` and **no** schema
  validation (pydantic / `jsonschema` / explicit key checks).
- **Grading:** advisory by default (reliability), not a security severity. Emit an
  inventory ("N unguarded model-output parses").
- **FP controls:** a guarded parse (try/except or validated) is the correct pattern →
  no finding. Could slot in early — it's low-risk and independently valuable.

### RG-TOOL-001 — Tool-authority / blast-radius declaration
- **Blind spot:** an agent wields tools without knowing their impact. Today governance
  only has `trace_policy` = "*a* policy is declared" — no impact taxonomy.
- **Check:** enumerate the tools/functions the agent exposes (framework-aware:
  `@tool`, function-calling schemas, MCP servers) and require each to declare impact:
  **read / write / irreversible** (pay, delete, send, deploy). Flag tools with no
  declared impact, and irreversible tools specifically.
- **Grading:** governance-style — a *declaration* signal, reported not hard-gated at
  first; feeds RG-GATE-001.
- **Dependency:** this taxonomy is the prerequisite for the irreversibility gate.

### RG-GATE-001 — Irreversibility gate (depends on RG-TOOL-001)
- **Blind spot:** the agent's confident-but-wrong 1% triggering something it can't undo.
- **Check:** an irreversible action (per RG-TOOL-001 impact, or the RG-ACTION-003
  delete class) invoked with **no** confirmation / dry-run / human-in-loop guard in
  the surrounding code.
- **Grading:** HIGH when an irreversible sink has no visible gate; needs the tool
  taxonomy to know which actions are irreversible → build after RG-TOOL-001.
- **Coverage honesty:** static sees the *absence of a code-level gate*, not whether an
  out-of-band approval exists.

---

## P3 — frontier (mostly behavioral — feeds the runtime layer, not the static gate)

### RG-IDEMP-001 — Idempotency / retry-safety
- **Blind spot:** within one turn the agent can't see that a step half-succeeded before
  it errored; a retry double-charges / double-sends / double-writes.
- **Why P3:** genuinely hard to prove statically (retry structure + side-effect keying
  span call boundaries). Static can flag *some* smells (a mutating call inside a
  retry/`for`-attempt block with no idempotency key), but the real signal is runtime.
- **Home:** primarily behavioral (`agent-score`); a low-confidence static smell at most.

### RG-GROUND-001 — Output → action grounding
- **Blind spot:** the agent hallucinates; a fabricated output triggers a real action
  with no verification in between.
- **Why P3:** "is this output grounded?" is a runtime/semantic judgment, not a static
  one. Static can only note "output feeds a consequential action with no intervening
  verification step" — weak. The real check is behavioral. This is the deepest version
  of the judge; keep it honest and mostly in the runtime layer.

---

## The precision contract (applies to every rule above)

1. **Precision over breadth.** The "we don't cry wolf" reputation — earned across a
   50+ repo dogfood where the engine correctly stayed quiet on careful code — is the
   asset. A speculative rule that misfires spends it. A rule ships only if it holds
   **confirmed model-taint → confirmed sink**.
2. **Confirmed vs inferred is not optional.** A path with a *visible* untrusted source
   is a HIGH you can put in front of a maintainer. An unproven source stays
   MEDIUM/inferred (the camel `eval` disposition). Never assert HIGH without the source.
3. **Static sees reachability, never runtime neutralization.** Every rule's coverage
   line must say what a runtime guard could still catch that static can't. The coverage
   matrix stays honest.
4. **Validate with a real user before over-investing.** Ship the P0/P1 catalog (it's
   generically valuable and precision-holdable); pull P2/P3 forward when a design
   partner's specific pain calls for it — armor where a real plane went down.

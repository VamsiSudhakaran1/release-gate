# release-gate rule catalog

> Generated from `release_gate/rules.py` — do not edit by hand (run `python scripts/gen_rules_doc.py`).

Every finding release-gate emits carries a **stable rule id** you can cite. Ids are permanent: we may reword a title, but `RG-EXEC-001` always means the same thing. Each rule maps to the frameworks you already answer to.

## Code-execution sinks

### RG-EXEC-001 — Dangerous execution sink

- **Default severity:** high
- **What & why:** Model or user output reaches eval/exec/os.system/a shell — the CVE-2025-51472 remote-code-execution class that lives entirely in the agent layer.
- **Fix:** Parse with ast.literal_eval/json, or sandbox execution; never eval text influenced by a model or a request.
- **Compliance:** OWASP-LLM:LLM02, OWASP-LLM:LLM08, NIST-AI-RMF:MANAGE-2.2

### RG-EXEC-002 — Deserialization of unverified data

- **Default severity:** medium
- **What & why:** pickle/marshal/dill deserializes data whose provenance isn't proven — remote code execution if an untrusted channel can reach it.
- **Fix:** Use a safe format (json / a signed payload), or prove the source is always local/trusted.
- **Compliance:** OWASP-LLM:LLM02, OWASP-LLM:LLM08

### RG-EXEC-003 — Dynamic execution sink

- **Default severity:** low
- **What & why:** A dynamic exec/eval/shell call in agent code whose reachability from model/user input isn't proven — a code-execution risk to confirm.
- **Fix:** Confirm no model or user output can reach it; sandbox any deliberate code tool.
- **Compliance:** OWASP-LLM:LLM02, OWASP-LLM:LLM08

## Consequential actions (model-driven side effects)

### RG-ACTION-002 — Server-side request from model output

- **Default severity:** high
- **What & why:** A model/tool/user-controlled URL flows into an HTTP client — SSRF (fetch an internal endpoint) or data egress (POST out) steered by generated text, the incident that leaves no other code fingerprint.
- **Fix:** Validate the host against an allowlist before the request; never let generated text choose the destination.
- **Compliance:** OWASP-LLM:LLM02, OWASP-LLM:LLM06, NIST-AI-RMF:MANAGE-2.2

### RG-ACTION-003 — Filesystem write/delete from model output

- **Default severity:** high
- **What & why:** Model-controlled path reaches a delete/overwrite (os.remove, shutil.rmtree, Path.unlink, open(…, 'w')) — an irreversible file operation the model's confident-but-wrong 1% can trigger.
- **Fix:** Constrain the path to an explicit sandbox directory and validate it before the operation; gate irreversible actions.
- **Compliance:** OWASP-LLM:LLM02, NIST-AI-RMF:MANAGE-2.2

### RG-ACTION-004 — SQL built from model output

- **Default severity:** high
- **What & why:** Model output is interpolated into a raw SQL query (f-string / concat) and executed — agent-driven SQL injection, where the taint source is the LLM, not an HTTP parameter.
- **Fix:** Use a parameterized query (execute(sql, params)); never interpolate untrusted or model text into SQL.
- **Compliance:** OWASP-LLM:LLM02, OWASP-LLM:LLM08

## Output handling (reliability)

### RG-PARSE-001 — Unvalidated model-output parse

- **Default severity:** low
- **What & why:** json.loads / ast.literal_eval on model output with no surrounding try/except — malformed or unexpectedly-shaped output crashes the agent or feeds unvalidated data into control flow. A reliability check, not a security one.
- **Fix:** Wrap the parse in try/except and validate the result (pydantic / explicit key checks) before acting on it.
- **Compliance:** OWASP-LLM:LLM05, NIST-AI-RMF:MANAGE-2.2

## Tool authority & blast radius

### RG-TOOL-001 — Undeclared tool blast radius

- **Default severity:** low
- **What & why:** An agent tool performs an irreversible action (delete/send/pay/deploy) but its impact is only inferred from its body, not declared — governance has no impact taxonomy to reason about what the tool can do.
- **Fix:** Declare each tool's impact (read / write / irreversible) so the agent and your policy can reason about its blast radius.
- **Compliance:** OWASP-LLM:LLM08, NIST-AI-RMF:MANAGE-2.2

### RG-GATE-001 — Irreversible tool action without a gate

- **Default severity:** medium
- **What & why:** An agent tool performs an irreversible action with no visible confirmation, dry-run, or human-in-loop gate — the confident-but-wrong 1% can trigger something it can't undo. Excessive agency without a guardrail.
- **Fix:** Add an explicit gate (a confirm/dry_run parameter, an approval step) before the irreversible call.
- **Compliance:** OWASP-LLM:LLM08, NIST-AI-RMF:MANAGE-2.2

## Prompt-injection surfaces

### RG-PROMPT-001 — Interpolated system prompt (injection surface)

- **Default severity:** high
- **What & why:** Untrusted (user/model) text is interpolated into a system prompt, where it can override system instructions — OWASP's #1 LLM risk.
- **Fix:** Move untrusted input into a clearly-delimited user-role message so it can't override system instructions.
- **Compliance:** OWASP-LLM:LLM01

### RG-PROMPT-002 — Untrusted content in instruction channel

- **Default severity:** high
- **What & why:** Content traced from an untrusted source — a retrieval/RAG result, an HTTP response body, or a tool return — flows into the system/instruction channel, where a poisoned document reads as an operator command. Indirect prompt injection, keyed on real provenance rather than a name hint.
- **Fix:** Keep retrieved/fetched/tool content in a clearly-delimited user or tool message; never place it in the system role or a prompt's instruction segment.
- **Compliance:** OWASP-LLM:LLM01

## Cost / token ceilings

### RG-COST-001 — LLM call with no token ceiling

- **Default severity:** low
- **What & why:** An LLM call sets no max_tokens — a single response can run to the model's maximum output; unpredictable latency and cost.
- **Fix:** Pass an explicit max_tokens / max_output_tokens to bound latency and cost.
- **Compliance:** OWASP-LLM:LLM10, NIST-AI-RMF:MANAGE-2.2

### RG-COST-002 — LLM call parameter dict has no output ceiling

- **Default severity:** low
- **What & why:** Request params are assembled in a dict with no max_tokens key and spread into the call — output length and cost fall back to provider defaults.
- **Fix:** Merge an explicit output ceiling into the params dict.
- **Compliance:** OWASP-LLM:LLM10

## Loop boundaries

### RG-LOOP-001 — Unbounded loop around an LLM call

- **Default severity:** high
- **What & why:** An infinite loop wraps an LLM call with no iteration cap — the AutoGPT-style runaway that turns a small task into an unbounded bill.
- **Fix:** Add an explicit max-iterations ceiling; a model-controlled break is not a cap.
- **Compliance:** OWASP-LLM:LLM10, NIST-AI-RMF:MANAGE-2.2

## Secrets

### RG-SECRET-001 — Hardcoded secret / API key

- **Default severity:** high
- **What & why:** A live-looking credential appears in source — a leaked key and a denial-of-wallet surface.
- **Fix:** Move secrets to environment variables or a secrets manager; rotate the exposed key.
- **Compliance:** OWASP-LLM:LLM07

### RG-SECRET-002 — Secret or PII sent to the model provider

- **Default severity:** high
- **What & why:** A hardcoded secret, an env var, or a PII-shaped value is interpolated into a prompt sent to a third-party LLM — data egress to the provider (who logs and retains it). The reverse of exfiltration, and no SAST tool checks it.
- **Fix:** Redact secrets/PII before they reach the prompt; a key used as auth (api_key=, headers) is fine — only prompt content is the leak.
- **Compliance:** OWASP-LLM:LLM06, OWASP-LLM:LLM07


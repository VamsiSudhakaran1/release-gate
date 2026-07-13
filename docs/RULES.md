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

## Prompt-injection surfaces

### RG-PROMPT-001 — Interpolated system prompt (injection surface)

- **Default severity:** high
- **What & why:** Untrusted (user/model) text is interpolated into a system prompt, where it can override system instructions — OWASP's #1 LLM risk.
- **Fix:** Move untrusted input into a clearly-delimited user-role message so it can't override system instructions.
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


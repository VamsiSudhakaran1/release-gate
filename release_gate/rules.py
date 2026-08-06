"""release-gate rule registry — the single source of truth for rule identity.

A gate earns authority only when a verdict is *citable*: every finding must carry
a stable rule id (``RG-EXEC-001``) that never changes when we reword a title, plus
a one-line rationale and a mapping to the frameworks enterprises already answer to
(OWASP LLM Top 10, NIST AI RMF, EU AI Act). "Why did this block my release?" must
resolve to a rule page — https://release-gate.com/rules#RG-EXEC-001 — not a code dive.

Stability contract:
  * A rule id is permanent. Retire a rule (mark ``deprecated``); never reuse an id.
  * Titles/wording may change freely — ids do not. Findings are matched to a rule
    by exact title first, then by a keyword classifier, so reworded titles still
    resolve to the same id.

``docs/RULES.md`` is generated from this file (scripts/gen_rules_doc.py); a test
keeps them in sync so the catalog can never drift from the engine.
"""
from __future__ import annotations

import re
from typing import Dict, List, NamedTuple, Optional

RULES_BASE_URL = "https://release-gate.com/rules"


class Rule(NamedTuple):
    id: str                     # stable, permanent — e.g. "RG-EXEC-001"
    title: str                  # canonical human title
    category: str               # EXEC | PROMPT | COST | LOOP | SECRET
    type_key: str               # bridges to legacy classification / metrics
    default_severity: str       # high | medium | low
    summary: str                # what it is + why it matters (one line)
    remediation: str            # the fix, in a sentence
    compliance: List[str]       # OWASP-LLM / NIST-AI-RMF / EU-AI-Act ids

    @property
    def url(self) -> str:
        return f"{RULES_BASE_URL}#{self.id}"


# ── The catalog. Ordered by category, then id. Ids are PERMANENT. ────────────
RULES: List[Rule] = [
    Rule("RG-EXEC-001", "Dangerous execution sink", "EXEC", "exec_sink", "high",
         "Model or user output reaches eval/exec/os.system/a shell — the "
         "CVE-2025-51472 remote-code-execution class that lives entirely in the "
         "agent layer.",
         "Parse with ast.literal_eval/json, or sandbox execution; never eval "
         "text influenced by a model or a request.",
         ["OWASP-LLM:LLM02", "OWASP-LLM:LLM08", "NIST-AI-RMF:MANAGE-2.2"]),
    Rule("RG-EXEC-002", "Deserialization of unverified data", "EXEC", "exec_sink", "medium",
         "pickle/marshal/dill deserializes data whose provenance isn't proven — "
         "remote code execution if an untrusted channel can reach it.",
         "Use a safe format (json / a signed payload), or prove the source is "
         "always local/trusted.",
         ["OWASP-LLM:LLM02", "OWASP-LLM:LLM08"]),
    Rule("RG-EXEC-003", "Dynamic execution sink", "EXEC", "exec_sink", "low",
         "A dynamic exec/eval/shell call in agent code whose reachability from "
         "model/user input isn't proven — a code-execution risk to confirm.",
         "Confirm no model or user output can reach it; sandbox any deliberate "
         "code tool.",
         ["OWASP-LLM:LLM02", "OWASP-LLM:LLM08"]),
    Rule("RG-ACTION-002", "Server-side request from model output", "ACTION",
         "ssrf_egress", "high",
         "A model/tool/user-controlled URL flows into an HTTP client — SSRF (fetch "
         "an internal endpoint) or data egress (POST out) steered by generated text, "
         "the incident that leaves no other code fingerprint.",
         "Validate the host against an allowlist before the request; never let "
         "generated text choose the destination.",
         ["OWASP-LLM:LLM02", "OWASP-LLM:LLM06", "NIST-AI-RMF:MANAGE-2.2"]),
    Rule("RG-ACTION-003", "Filesystem write/delete from model output", "ACTION",
         "fs_write_delete", "high",
         "Model-controlled path reaches a delete/overwrite (os.remove, shutil.rmtree, "
         "Path.unlink, open(…, 'w')) — an irreversible file operation the model's "
         "confident-but-wrong 1% can trigger.",
         "Constrain the path to an explicit sandbox directory and validate it before "
         "the operation; gate irreversible actions.",
         ["OWASP-LLM:LLM02", "NIST-AI-RMF:MANAGE-2.2"]),
    Rule("RG-ACTION-004", "SQL built from model output", "ACTION",
         "sql_from_model", "high",
         "Model output is interpolated into a raw SQL query (f-string / concat) and "
         "executed — agent-driven SQL injection, where the taint source is the LLM, "
         "not an HTTP parameter.",
         "Use a parameterized query (execute(sql, params)); never interpolate "
         "untrusted or model text into SQL.",
         ["OWASP-LLM:LLM02", "OWASP-LLM:LLM08"]),
    Rule("RG-PARSE-001", "Unvalidated model-output parse", "PARSE",
         "unvalidated_parse", "low",
         "json.loads / ast.literal_eval on model output with no surrounding "
         "try/except — malformed or unexpectedly-shaped output crashes the agent or "
         "feeds unvalidated data into control flow. A reliability check, not a "
         "security one.",
         "Wrap the parse in try/except and validate the result (pydantic / explicit "
         "key checks) before acting on it.",
         ["OWASP-LLM:LLM05", "NIST-AI-RMF:MANAGE-2.2"]),
    Rule("RG-TOOL-001", "Undeclared tool blast radius", "TOOL",
         "tool_blast_radius", "low",
         "An agent tool performs an irreversible action (delete/send/pay/deploy) but "
         "its impact is only inferred from its body, not declared — governance has no "
         "impact taxonomy to reason about what the tool can do.",
         "Declare each tool's impact (read / write / irreversible) so the agent and "
         "your policy can reason about its blast radius.",
         ["OWASP-LLM:LLM08", "NIST-AI-RMF:MANAGE-2.2"]),
    Rule("RG-GATE-001", "Irreversible tool action without a gate", "TOOL",
         "irreversible_no_gate", "medium",
         "An agent tool performs an irreversible action with no visible confirmation, "
         "dry-run, or human-in-loop gate — the confident-but-wrong 1% can trigger "
         "something it can't undo. Excessive agency without a guardrail.",
         "Add an explicit gate (a confirm/dry_run parameter, an approval step) before "
         "the irreversible call.",
         ["OWASP-LLM:LLM08", "NIST-AI-RMF:MANAGE-2.2"]),
    Rule("RG-PII-001", "Sensitive context reaches the model unmasked on one path",
         "SECRET", "pii_egress", "high",
         "This project redacts retrieved/user context before sending it to the model "
         "on one path, and sends it unredacted on another — the classic refactor "
         "regression, where a second retrieval path is added and the masking step is "
         "not. Reported only when the repo masks somewhere, so it is an "
         "inconsistency the code itself proves, never an opinion about what you owe.",
         "Route the unmasked path through the same redaction step, or hoist masking "
         "into one place both paths must pass through.",
         ["OWASP-LLM:LLM02", "OWASP-LLM:LLM06", "NIST-AI-RMF:MAP-5.1",
          "EU-AI-Act:Art-10"]),
    Rule("RG-PROMPT-001", "Interpolated system prompt (injection surface)", "PROMPT",
         "prompt_injection_risk", "high",
         "Untrusted (user/model) text is interpolated into a system prompt, where "
         "it can override system instructions — OWASP's #1 LLM risk.",
         "Move untrusted input into a clearly-delimited user-role message so it "
         "can't override system instructions.",
         ["OWASP-LLM:LLM01"]),
    Rule("RG-PROMPT-002", "Untrusted content in instruction channel", "PROMPT",
         "prompt_injection_risk", "high",
         "Content traced from an untrusted source — a retrieval/RAG result, an HTTP "
         "response body, or a tool return — flows into the system/instruction "
         "channel, where a poisoned document reads as an operator command. Indirect "
         "prompt injection, keyed on real provenance rather than a name hint.",
         "Keep retrieved/fetched/tool content in a clearly-delimited user or tool "
         "message; never place it in the system role or a prompt's instruction segment.",
         ["OWASP-LLM:LLM01"]),
    Rule("RG-COST-001", "LLM call with no token ceiling", "COST", "missing_max_tokens", "low",
         "An LLM call sets no max_tokens — a single response can run to the "
         "model's maximum output; unpredictable latency and cost.",
         "Pass an explicit max_tokens / max_output_tokens to bound latency and cost.",
         ["OWASP-LLM:LLM10", "NIST-AI-RMF:MANAGE-2.2"]),
    Rule("RG-COST-002", "LLM call parameter dict has no output ceiling", "COST",
         "missing_max_tokens", "low",
         "Request params are assembled in a dict with no max_tokens key and spread "
         "into the call — output length and cost fall back to provider defaults.",
         "Merge an explicit output ceiling into the params dict.",
         ["OWASP-LLM:LLM10"]),
    Rule("RG-LOOP-001", "Unbounded loop around an LLM call", "LOOP", "unbounded_llm_loop", "high",
         "An infinite loop wraps an LLM call with no iteration cap — the "
         "AutoGPT-style runaway that turns a small task into an unbounded bill.",
         "Add an explicit max-iterations ceiling; a model-controlled break is not "
         "a cap.",
         ["OWASP-LLM:LLM10", "NIST-AI-RMF:MANAGE-2.2"]),
    Rule("RG-SECRET-001", "Hardcoded secret / API key", "SECRET", "hardcoded_secret", "high",
         "A live-looking credential appears in source — a leaked key and a "
         "denial-of-wallet surface.",
         "Move secrets to environment variables or a secrets manager; rotate the "
         "exposed key.",
         ["OWASP-LLM:LLM07"]),
    Rule("RG-SECRET-002", "Secret or PII sent to the model provider", "SECRET",
         "secret_to_prompt", "high",
         "A hardcoded secret, an env var, or a PII-shaped value is interpolated into "
         "a prompt sent to a third-party LLM — data egress to the provider (who logs "
         "and retains it). The reverse of exfiltration — an agent-aware egress "
         "path conventional SAST often lacks the context to model.",
         "Redact secrets/PII before they reach the prompt; a key used as auth "
         "(api_key=, headers) is fine — only prompt content is the leak.",
         ["OWASP-LLM:LLM06", "OWASP-LLM:LLM07"]),
]

_BY_ID: Dict[str, Rule] = {r.id: r for r in RULES}
_BY_TITLE: Dict[str, Rule] = {r.title: r for r in RULES}


def rule_for_title(title: str) -> Optional[Rule]:
    """Resolve a finding title to its stable rule. Exact title first (so wording
    tweaks never move an id), then a keyword classifier for reworded/legacy titles.
    Returns None only for a title with no rule (callers keep the finding, unlabeled).
    """
    if not title:
        return None
    if title in _BY_TITLE:
        return _BY_TITLE[title]
    t = title.lower()
    # Keyword fallback — mirrors audit._finding_type_key, but returns a canonical rule.
    if "deserializ" in t or "pickle" in t or "marshal" in t:
        return _BY_ID["RG-EXEC-002"]
    if "dynamic execution" in t:
        return _BY_ID["RG-EXEC-003"]
    if "exec" in t or "execution sink" in t:
        return _BY_ID["RG-EXEC-001"]
    if "secret" in t or "api key" in t or "credential" in t:
        return _BY_ID["RG-SECRET-001"]
    if "parameter dict" in t or "output ceiling" in t:
        return _BY_ID["RG-COST-002"]
    if "token ceiling" in t or "max_tokens" in t or "maxtokens" in t:
        return _BY_ID["RG-COST-001"]
    if "unbounded" in t or "infinite loop" in t or "runaway" in t:
        return _BY_ID["RG-LOOP-001"]
    if "injection" in t or "interpolat" in t or "system prompt" in t:
        return _BY_ID["RG-PROMPT-001"]
    return None


def rule_id_for_title(title: str) -> Optional[str]:
    r = rule_for_title(title)
    return r.id if r else None


def get_rule(rule_id: str) -> Optional[Rule]:
    return _BY_ID.get(rule_id)


def render_catalog_md() -> str:
    """Render docs/RULES.md from the registry — the public rationale catalog."""
    cats = {"EXEC": "Code-execution sinks", "ACTION": "Consequential actions (model-driven side effects)",
            "PARSE": "Output handling (reliability)",
            "TOOL": "Tool authority & blast radius",
            "PROMPT": "Prompt-injection surfaces",
            "COST": "Cost / token ceilings", "LOOP": "Loop boundaries",
            "SECRET": "Secrets"}
    out: List[str] = [
        "# release-gate rule catalog",
        "",
        "> Generated from `release_gate/rules.py` — do not edit by hand "
        "(run `python scripts/gen_rules_doc.py`).",
        "",
        "Every finding release-gate emits carries a **stable rule id** you can cite. "
        "Ids are permanent: we may reword a title, but `RG-EXEC-001` always means the "
        "same thing. Each rule maps to the frameworks you already answer to.",
        "",
    ]
    by_cat: Dict[str, List[Rule]] = {}
    for r in RULES:
        by_cat.setdefault(r.category, []).append(r)
    for cat, rules in by_cat.items():
        out.append(f"## {cats.get(cat, cat)}")
        out.append("")
        for r in rules:
            out.append(f"### {r.id} — {r.title}")
            out.append("")
            out.append(f"- **Default severity:** {r.default_severity}")
            out.append(f"- **What & why:** {r.summary}")
            out.append(f"- **Fix:** {r.remediation}")
            out.append(f"- **Compliance:** {', '.join(r.compliance)}")
            out.append("")
    return "\n".join(out)


if __name__ == "__main__":
    print(render_catalog_md())

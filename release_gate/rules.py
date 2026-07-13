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
    Rule("RG-PROMPT-001", "Interpolated system prompt (injection surface)", "PROMPT",
         "prompt_injection_risk", "high",
         "Untrusted (user/model) text is interpolated into a system prompt, where "
         "it can override system instructions — OWASP's #1 LLM risk.",
         "Move untrusted input into a clearly-delimited user-role message so it "
         "can't override system instructions.",
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
    cats = {"EXEC": "Code-execution sinks", "PROMPT": "Prompt-injection surfaces",
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

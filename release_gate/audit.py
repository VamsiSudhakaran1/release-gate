"""
release-gate audit — scan a local repo for AI agent deployment readiness.

Detects agent frameworks in use, checks whether governance safeguards are
declared, and produces a readiness score (0-100) with a PROMOTE/HOLD/BLOCK
decision and a ranked list of missing safeguards.

Usage:
    release-gate audit               # scan current directory
    release-gate audit ./my-repo     # scan a specific path
    release-gate audit https://github.com/org/repo   # clone and scan
    release-gate audit . --json      # machine-readable output
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ─────────────────────────── Framework detection ────────────────────────────

FRAMEWORK_SIGNALS: Dict[str, List[str]] = {
    "OpenAI / Agents SDK":      ["from openai",    "import openai",    "openai.agents", "openai.chat"],
    "Anthropic / Claude":       ["from anthropic",  "import anthropic", "anthropic.messages"],
    "LangChain":                ["from langchain",  "import langchain", "langchain_openai", "langchain_anthropic"],
    "LangGraph":                ["from langgraph",  "import langgraph"],
    "CrewAI":                   ["from crewai",     "import crewai"],
    "AutoGen / AG2":            ["from autogen",    "import autogen",   "from ag2", "import ag2"],
    "LiteLLM":                  ["from litellm",    "import litellm",   "litellm.completion"],
    "LlamaIndex":               ["from llama_index","import llama_index","from llama_index.core"],
    "Google Generative AI":     ["import google.generativeai", "from google.generativeai",
                                 "import vertexai", "from vertexai"],
    "HuggingFace Transformers": ["from transformers","import transformers"],
    "Ollama":                   ["from ollama",     "import ollama",    "ollama.chat"],
}

PYTHON_EXTENSIONS = {".py"}
MAX_FILES = 2000
MAX_FILE_BYTES = 200_000


# ─────────────────────────── Safeguard checklist ────────────────────────────

SAFEGUARDS = [
    {
        "id":        "governance_file",
        "label":     "Governance config (governance.yaml)",
        "dimension": "safety",
        "weight":    25,
        "risk":      "No deployment policy — nothing to gate on.",
    },
    {
        "id":        "budget_ceiling",
        "label":     "Budget / cost ceiling",
        "dimension": "cost",
        "weight":    20,
        "risk":      "Runaway loop could exhaust API credits silently.",
    },
    {
        "id":        "kill_switch",
        "label":     "Kill switch / fallback declared",
        "dimension": "safety",
        "weight":    20,
        "risk":      "No way to stop a misbehaving agent at runtime.",
    },
    {
        "id":        "team_owner",
        "label":     "Team owner / on-call contact",
        "dimension": "safety",
        "weight":    10,
        "risk":      "Nobody gets paged when it breaks at 3 AM.",
    },
    {
        "id":        "auth_rate_limit",
        "label":     "Auth & rate limiting",
        "dimension": "access_control",
        "weight":    10,
        "risk":      "Anyone can call the agent and exhaust your budget.",
    },
    {
        "id":        "eval_evidence",
        "label":     "Eval evidence (evals.yaml or test suite)",
        "dimension": "eval_quality",
        "weight":    10,
        "risk":      "No proof the agent behaves correctly before shipping.",
    },
    {
        "id":        "trace_policy",
        "label":     "Trace / tool policy declared",
        "dimension": "observability",
        "weight":    5,
        "risk":      "No record of which tools the agent called or why.",
    },
]


# ─────────────────────────── File scanner ───────────────────────────────────

def _iter_source_files(root: Path):
    """Yield Python source files under root, capped at MAX_FILES."""
    count = 0
    skip_dirs = {".git", "__pycache__", "node_modules", ".venv", "venv", ".env",
                 "dist", "build", "site-packages", ".tox"}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for fname in filenames:
            if Path(fname).suffix in PYTHON_EXTENSIONS:
                fpath = Path(dirpath) / fname
                count += 1
                if count > MAX_FILES:
                    return
                yield fpath


def _read_snippet(path: Path) -> str:
    try:
        return path.read_bytes()[:MAX_FILE_BYTES].decode("utf-8", errors="ignore")
    except OSError:
        return ""


def detect_frameworks(root: Path) -> Dict[str, int]:
    """Return {framework_name: file_count} for every detected framework."""
    hits: Dict[str, int] = {}
    for fpath in _iter_source_files(root):
        content = _read_snippet(fpath).lower()
        for framework, signals in FRAMEWORK_SIGNALS.items():
            if any(sig.lower() in content for sig in signals):
                hits[framework] = hits.get(framework, 0) + 1
    return hits


# ─────────────────────────── Model detection ────────────────────────────────

# Ordered by specificity — first match wins. Captures the model id from common
# SDK call sites: model="...", model_name='...', model: "..." etc.
MODEL_ID_PATTERN = re.compile(
    r"""(?:model|model_name|model_id|deployment_name)\s*[=:]\s*['"]"""
    r"""([a-zA-Z0-9][\w.\-:/]*)['"]""",
)

# Known model-id prefixes we trust enough to surface (avoids matching random
# strings assigned to a variable called "model").
KNOWN_MODEL_PREFIXES = (
    "gpt-", "o1", "o3", "o4", "chatgpt",
    "claude-", "anthropic",
    "gemini-", "models/gemini", "text-bison", "chat-bison",
    "grok-",
    "mistral", "mixtral", "ministral",
    "llama", "meta-llama",
    "command-", "cohere",
    "deepseek",
    "qwen",
)


def detect_model(root: Path) -> Optional[str]:
    """Best-effort detection of the model id used in the codebase."""
    counts: Dict[str, int] = {}
    for fpath in _iter_source_files(root):
        content = _read_snippet(fpath)
        for match in MODEL_ID_PATTERN.findall(content):
            mid = match.strip()
            low = mid.lower()
            if any(low.startswith(p) for p in KNOWN_MODEL_PREFIXES):
                counts[mid] = counts.get(mid, 0) + 1
    if not counts:
        return None
    # Most frequently referenced model wins.
    return max(counts.items(), key=lambda kv: kv[1])[0]


# ─────────────────────────── Governance detection ───────────────────────────

GOVERNANCE_FILENAMES = [
    "governance.yaml", "governance.yml",
    ".release-gate.yaml", ".release-gate.yml",
    "release-gate.yaml", "release-gate.yml",
]

EVALS_FILENAMES = ["evals.yaml", "evals.yml"]
TRACE_FILENAMES = ["traces", "trace"]

BUDGET_PATTERNS  = [r"max_daily_cost", r"budget", r"max_cost", r"cost_limit",
                    r"rate_limit", r"max_tokens"]
KILL_SW_PATTERNS = [r"kill_switch", r"fallback", r"disable_", r"feature.?flag",
                    r"circuit.?break"]
AUTH_PATTERNS    = [r"auth", r"api.?key", r"bearer", r"rate.?limit", r"identity"]
OWNER_PATTERNS   = [r"team_owner", r"on.?call", r"runbook", r"owner", r"pagerduty",
                    r"oncall"]
TRACE_PATTERNS   = [r"trace_policies", r"forbidden_tools", r"allowed_tools",
                    r"trace_id", r"tool_call"]
ACTIONS_RG_PAT   = r"release-gate"


def _yaml_contains(path: Path, patterns: List[str]) -> bool:
    text = _read_snippet(path).lower()
    return any(re.search(p, text) for p in patterns)


def _has_github_actions_integration(root: Path) -> bool:
    wf_dir = root / ".github" / "workflows"
    if not wf_dir.is_dir():
        return False
    for wf in wf_dir.glob("*.yml"):
        if ACTIONS_RG_PAT in _read_snippet(wf).lower():
            return True
    for wf in wf_dir.glob("*.yaml"):
        if ACTIONS_RG_PAT in _read_snippet(wf).lower():
            return True
    return False


def detect_safeguards(root: Path) -> Tuple[Dict[str, bool], Optional[Path]]:
    """Return (safeguard_present_map, governance_path_or_None)."""
    gov_path: Optional[Path] = None
    for name in GOVERNANCE_FILENAMES:
        candidate = root / name
        if candidate.is_file():
            gov_path = candidate
            break

    evals_path: Optional[Path] = None
    for name in EVALS_FILENAMES:
        candidate = root / name
        if candidate.is_file():
            evals_path = candidate
            break

    has_traces = any((root / d).exists() for d in TRACE_FILENAMES)

    present = {
        "governance_file": gov_path is not None,
        "eval_evidence":   evals_path is not None or _has_test_evals(root),
        "trace_policy":    has_traces,
    }

    # For the remaining safeguards, look inside governance.yaml if it exists,
    # otherwise scan Python files and requirements.
    if gov_path:
        present["budget_ceiling"]  = _yaml_contains(gov_path, BUDGET_PATTERNS)
        present["kill_switch"]     = _yaml_contains(gov_path, KILL_SW_PATTERNS)
        present["team_owner"]      = _yaml_contains(gov_path, OWNER_PATTERNS)
        present["auth_rate_limit"] = _yaml_contains(gov_path, AUTH_PATTERNS)
        if not present["trace_policy"]:
            present["trace_policy"] = _yaml_contains(gov_path, TRACE_PATTERNS)
    else:
        # No governance file — scan source for any hints of these safeguards
        combined = _scan_source_for_patterns(root)
        present["budget_ceiling"]  = bool(re.search("|".join(BUDGET_PATTERNS),  combined))
        present["kill_switch"]     = bool(re.search("|".join(KILL_SW_PATTERNS), combined))
        present["team_owner"]      = False  # can't infer from code alone
        present["auth_rate_limit"] = bool(re.search("|".join(AUTH_PATTERNS),    combined))

    return present, gov_path


def _has_test_evals(root: Path) -> bool:
    """Check for test files that look like agent behavior tests."""
    test_patterns = [r"def test.*agent", r"def test.*eval", r"pii", r"refuse",
                     r"keywords_blocked"]
    for dirpath, _, filenames in os.walk(root):
        if any(skip in dirpath for skip in [".git", "__pycache__", ".venv"]):
            continue
        for fname in filenames:
            if fname.startswith("test_") and fname.endswith(".py"):
                content = _read_snippet(Path(dirpath) / fname).lower()
                if any(re.search(p, content) for p in test_patterns):
                    return True
    return False


def _scan_source_for_patterns(root: Path) -> str:
    """Concatenate a sample of source content for quick pattern search."""
    chunks: List[str] = []
    for fpath in _iter_source_files(root):
        chunks.append(_read_snippet(fpath))
        if len(chunks) >= 50:
            break
    return "\n".join(chunks).lower()


# ─────────────────────────── Scoring ────────────────────────────────────────

# PROMOTE requires a governance file: the other six safeguards sum to 75, so a
# repo with no governance.yaml caps at HOLD no matter how much else it has in
# place. BLOCK is reserved for repos missing more than half the weighted
# safeguards (< 50) — a repo that already has budget/kill-switch/auth/evals but
# no formal config is a HOLD ("formalize it"), not a BLOCK.
PROMOTE_THRESHOLD = 90
HOLD_THRESHOLD    = 50


def compute_score(present: Dict[str, bool]) -> Tuple[int, str]:
    """Return (score 0-100, decision)."""
    total_weight = sum(s["weight"] for s in SAFEGUARDS)
    earned = sum(s["weight"] for s in SAFEGUARDS if present.get(s["id"], False))
    score = round(earned / total_weight * 100)

    if score >= PROMOTE_THRESHOLD:
        decision = "PROMOTE"
    elif score >= HOLD_THRESHOLD:
        decision = "HOLD"
    else:
        decision = "BLOCK"
    return score, decision


# ─────────────────────────── URL / remote repo support ──────────────────────

def _is_github_url(target: str) -> bool:
    return target.startswith(("https://github.com", "http://github.com",
                              "git@github.com", "https://gitlab.com",
                              "http://gitlab.com"))


def clone_and_audit(url: str) -> Dict[str, Any]:
    """Clone a remote git repo to a temp dir, audit it, clean up."""
    if not shutil.which("git"):
        raise RuntimeError(
            "git is required for remote audits but was not found on PATH.\n"
            "Install git: https://git-scm.com/downloads"
        )
    tmpdir = tempfile.mkdtemp(prefix="rg-audit-")
    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", "--quiet", url, tmpdir],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            err = result.stderr.strip() or "clone failed"
            raise RuntimeError(f"git clone failed: {err}")
        report = build_report(Path(tmpdir))
        report["path"] = url
        return report
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ─────────────────────────── Report builder ─────────────────────────────────

def build_report(root: Path) -> Dict[str, Any]:
    """Full audit report for a repo path."""
    root = root.resolve()
    frameworks = detect_frameworks(root)
    agent_detected = len(frameworks) > 0
    detected_model = detect_model(root)
    present, gov_path = detect_safeguards(root)
    score, decision = compute_score(present)
    has_ci = _has_github_actions_integration(root)

    missing = [s for s in SAFEGUARDS if not present.get(s["id"], False)]
    passing = [s for s in SAFEGUARDS if present.get(s["id"], False)]

    # If governance.yaml exists, try to run real checks for richer output
    real_check_results = None
    if gov_path:
        try:
            import sys
            sys.path.insert(0, str(Path(__file__).parent.parent))
            from release_gate.cli import run_checks, load_config
            config = load_config(str(gov_path))
            real_check_results = run_checks(config)
        except Exception:
            pass

    return {
        "path":               str(root),
        "agent_detected":     agent_detected,
        "frameworks":         frameworks,
        "detected_model":     detected_model,
        "governance_file":    str(gov_path) if gov_path else None,
        "has_ci_integration": has_ci,
        "safeguards":         present,
        "missing":            missing,
        "passing":            passing,
        "score":              score,
        "decision":           decision,
        "real_checks":        real_check_results,
    }


# ─────────────────────────── Config emitter ─────────────────────────────────

def _project_name_from_path(path: str) -> str:
    """Derive a project slug from a repo path or GitHub URL."""
    cleaned = path.rstrip("/")
    if cleaned.endswith(".git"):
        cleaned = cleaned[:-4]
    name = cleaned.replace("\\", "/").split("/")[-1]
    return name or "ai-agent"


def emit_config(report: Dict[str, Any]) -> str:
    """Generate a ready-to-commit governance.yaml pre-filled from an audit.

    Values release-gate can infer (project name, model) are filled in.
    Values only the team knows (budget, runbook, owner) are scaffolded with
    `# TODO:` markers so the config is honest about what still needs input.
    """
    project = _project_name_from_path(report.get("path", "ai-agent"))
    model = report.get("detected_model")
    frameworks = ", ".join(sorted(report.get("frameworks", {}).keys())) or "unknown"
    present = report.get("safeguards", {})

    if model:
        model_line = f"  model: {model}"
        model_note = ""
    else:
        model_line = "  model: gpt-4-turbo            # TODO: set your real model id"
        model_note = "  # release-gate could not auto-detect the model from the code.\n"

    def todo(condition_present: bool) -> str:
        """Inline marker: blank if the safeguard already exists, TODO if not."""
        return "" if condition_present else "   # TODO: confirm / replace"

    gap = "⚠ release-gate audit flagged this as MISSING — fill it in before deploy"

    lines = []
    lines.append(f"# governance.yaml — generated by `release-gate audit --emit-config`")
    lines.append(f"#")
    lines.append(f"# Repo:       {report.get('path', '')}")
    lines.append(f"# Frameworks: {frameworks}")
    lines.append(f"# Audit score at generation time: "
                 f"{report.get('score', 0)}/100 ({report.get('decision', 'BLOCK')})")
    lines.append(f"#")
    lines.append(f"# Lines marked TODO need a real value from your team. Once filled in,")
    lines.append(f"# run:  release-gate score governance.yaml")
    lines.append(f"")
    lines.append(f"project:")
    lines.append(f"  name: {project}")
    lines.append(f"  description: \"AI agent — governance generated from release-gate audit\"")
    lines.append(f"")
    lines.append(f"agent:")
    if model_note:
        lines.append(model_note.rstrip("\n"))
    lines.append(model_line)
    lines.append(f"  daily_requests: 1000          # TODO: your real daily request volume")
    lines.append(f"  avg_input_tokens: 800         # TODO: typical prompt size")
    lines.append(f"  avg_output_tokens: 400        # TODO: typical completion size")
    lines.append(f"")
    lines.append(f"policy:")
    lines.append(f"  fail_on:")
    lines.append(f"    - ACTION_BUDGET")
    lines.append(f"    - FALLBACK_DECLARED")
    lines.append(f"    - BUDGET_SIMULATION")
    lines.append(f"  warn_on:")
    lines.append(f"    - IDENTITY_BOUNDARY")
    lines.append(f"    - INPUT_CONTRACT")
    lines.append(f"")
    lines.append(f"checks:")
    lines.append(f"")

    # action_budget
    if not present.get("budget_ceiling"):
        lines.append(f"  # {gap}")
    lines.append(f"  action_budget:")
    lines.append(f"    enabled: true")
    lines.append(f"    max_daily_cost: 100         # TODO: your hard daily $ ceiling")
    lines.append(f"")

    # fallback_declared
    if not (present.get("kill_switch") and present.get("team_owner")):
        lines.append(f"  # {gap}")
    lines.append(f"  fallback_declared:")
    lines.append(f"    enabled: true")
    lines.append(f"    kill_switch:")
    lines.append(f"      type: \"feature-flag\"      # how you disable the agent at runtime")
    lines.append(f"      location: \"config/kill-switches\"")
    lines.append(f"    fallback_mode: \"escalate-to-human\"")
    lines.append(f"    team_owner: \"TODO-your-team\"          # TODO: who gets paged")
    lines.append(f"    runbook_url: \"https://TODO/runbook\"   # TODO: incident runbook")
    lines.append(f"")

    # identity_boundary
    if not present.get("auth_rate_limit"):
        lines.append(f"  # {gap}")
    lines.append(f"  identity_boundary:")
    lines.append(f"    enabled: true")
    lines.append(f"    authentication:")
    lines.append(f"      required: true")
    lines.append(f"      type: \"oauth2\"            # TODO: your auth method")
    lines.append(f"    rate_limit:")
    lines.append(f"      requests_per_minute: 10   # TODO: your real per-user limit")
    lines.append(f"      burst_allowed: false")
    lines.append(f"    data_isolation:")
    lines.append(f"      - \"per-user isolation\"")
    lines.append(f"")

    # input_contract
    lines.append(f"  input_contract:")
    lines.append(f"    enabled: true")
    lines.append(f"    schema:")
    lines.append(f"      type: \"object\"")
    lines.append(f"      required:")
    lines.append(f"        - \"user_query\"")
    lines.append(f"      properties:")
    lines.append(f"        user_query:")
    lines.append(f"          type: \"string\"")
    lines.append(f"    samples:")
    lines.append(f"      valid:")
    lines.append(f"        - user_query: \"What is the status of my order?\"")
    lines.append(f"      invalid:")
    lines.append(f"        - user_query: \"\"")
    lines.append(f"")

    # budget_simulation
    lines.append(f"  budget_simulation:")
    lines.append(f"    enabled: true")
    lines.append(f"    simulation:")
    lines.append(f"      requests_per_day: 1000    # TODO: match agent.daily_requests")
    lines.append(f"      tokens_per_request:")
    lines.append(f"        input: 800")
    lines.append(f"        output: 400")
    lines.append(f"      factors:")
    lines.append(f"        retry_rate: 1.2")
    lines.append(f"        cache_hit_rate: 0.3")
    lines.append(f"        spiky_usage_multiplier: 1.5")
    lines.append(f"")

    # trace_policies
    if not present.get("trace_policy"):
        lines.append(f"# {gap}")
    lines.append(f"trace_policies:")
    lines.append(f"  forbidden_tools: [delete_database, export_data, send_email_external]  # TODO")
    lines.append(f"  allowed_tools: [search_docs, get_order, create_ticket]               # TODO")
    lines.append(f"  max_tool_calls: 10")
    lines.append(f"  max_retries: 2")
    lines.append(f"  max_tokens_per_run: 15000")
    lines.append(f"")

    return "\n".join(lines)


# ─────────────────────────── Badge + Markdown (self-serve) ──────────────────

def badge_url(report: Dict[str, Any]) -> str:
    """Return a shields.io badge URL reflecting the audit score/decision.

    Drop the resulting markdown into a README so the readiness score is
    visible on the repo front page — turning the audit into something a
    maintainer runs on their *own* repo, not something done to them.
    """
    score = report.get("score", 0)
    decision = report.get("decision", "BLOCK")
    if not report.get("agent_detected", True):
        return ("https://img.shields.io/badge/"
                "release--gate-no%20agent%20detected-lightgrey")
    color = {"PROMOTE": "brightgreen", "HOLD": "yellow", "BLOCK": "red"}.get(decision, "lightgrey")
    label = "release--gate"
    message = f"{score}%2F100 {decision}".replace(" ", "%20")
    return f"https://img.shields.io/badge/{label}-{message}-{color}"


def badge_markdown(report: Dict[str, Any]) -> str:
    """A copy-paste README snippet: the badge linking to release-gate."""
    return (f"[![AI deployment readiness]({badge_url(report)})]"
            f"(https://github.com/VamsiSudhakaran1/release-gate)")


def render_markdown(report: Dict[str, Any]) -> str:
    """Render the audit as GitHub-flavored Markdown.

    Used for CI job summaries ($GITHUB_STEP_SUMMARY) and PR comments so the
    result is readable wherever a maintainer already works.
    """
    out: List[str] = []
    out.append("## 🚪 release-gate — AI Release Readiness Audit")
    out.append("")
    out.append(f"**Repo:** `{report.get('path', '')}`")
    out.append("")

    fw = report.get("frameworks", {})
    if not fw:
        out.append("> ℹ️ No AI agent framework detected in this repo. "
                   "release-gate audits are designed for repos using OpenAI, "
                   "Anthropic, LangChain, LangGraph, CrewAI, AutoGen, LiteLLM, "
                   "LlamaIndex, HuggingFace, or Ollama.")
        out.append("")
        return "\n".join(out)

    names = ", ".join(f"{k} ({v})" for k, v in sorted(fw.items()))
    out.append(f"**Agent frameworks:** {names}")
    if report.get("detected_model"):
        out.append(f"  •  **Model:** `{report['detected_model']}`")
    out.append("")

    score = report.get("score", 0)
    decision = report.get("decision", "BLOCK")
    emoji = {"PROMOTE": "🟢", "HOLD": "🟡", "BLOCK": "🔴"}.get(decision, "⚪")
    out.append(f"### {emoji} Score: **{score} / 100** — {decision}")
    out.append("")
    out.append(badge_markdown(report))
    out.append("")

    missing = report.get("missing", [])
    passing = report.get("passing", [])

    out.append("| Safeguard | Status | Risk if missing |")
    out.append("| --- | :---: | --- |")
    for s in passing:
        out.append(f"| {s['label']} | ✅ | — |")
    for s in missing:
        out.append(f"| {s['label']} | ❌ | {s['risk']} |")
    out.append("")

    if missing:
        out.append("### Next step")
        out.append("")
        out.append("Scaffold a ready-to-commit governance config from this audit:")
        out.append("")
        out.append("```bash")
        out.append("release-gate audit . --emit-config -o governance.yaml")
        out.append("```")
        out.append("")
        out.append("Then fill in the `TODO` lines and gate every deploy with "
                   "`release-gate score governance.yaml`.")
        out.append("")

    return "\n".join(out)


# ─────────────────────────── Terminal renderer ───────────────────────────────

_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_GREEN  = "\033[32m"
_YELLOW = "\033[33m"
_RED    = "\033[31m"
_BLUE   = "\033[34m"
_MUTED  = "\033[90m"
_PURPLE = "\033[35m"


def _col(text, *codes):
    return "".join(codes) + text + _RESET


def render_terminal(report: Dict[str, Any]) -> None:
    div = "─" * 72

    print()
    print(_col(f"  🚪 release-gate  |  AI Release Readiness Audit", _BOLD))
    print(f"  {div}")
    print()

    # Path
    print(f"  {_col('Repo', _MUTED)}  {report['path']}")

    # Frameworks
    fw = report["frameworks"]
    if fw:
        names = ", ".join(f"{k} ({v} file{'s' if v>1 else ''})" for k, v in sorted(fw.items()))
        print(f"  {_col('Agents', _MUTED)}  {_col(names, _BLUE)}")
    else:
        print(f"  {_col('Agents', _MUTED)}  {_col('No agent frameworks detected', _MUTED)}")
        print()
        print(f"  {_col('ℹ  This repo does not appear to use an AI agent framework.', _MUTED)}")
        print(f"  {_col('   release-gate audits are designed for repos using:', _MUTED)}")
        print(f"  {_col('   OpenAI · Anthropic · LangChain · LangGraph · CrewAI', _MUTED)}")
        print(f"  {_col('   AutoGen · LiteLLM · LlamaIndex · HuggingFace · Ollama', _MUTED)}")
        print()
        print(f"  {_col('   If this repo does use an agent, the framework may be in', _MUTED)}")
        print(f"  {_col('   a subdirectory. Try:', _MUTED)}")
        print(f"  {_col('   release-gate audit ./path/to/agent/subdir', _BLUE)}")
        print()
        print(f"  {div}")
        print()
        return  # exit early — no point scoring a non-agent repo

    if report["governance_file"]:
        print(f"  {_col('Config', _MUTED)}  {_col(report['governance_file'], _GREEN)}")
    else:
        print(f"  {_col('Config', _MUTED)}  {_col('No governance.yaml found', _RED)}")

    ci_txt = _col("GitHub Actions ✓", _GREEN) if report["has_ci_integration"] \
        else _col("No CI integration", _MUTED)
    print(f"  {_col('CI    ', _MUTED)}  {ci_txt}")
    print()

    # Score bar
    score    = report["score"]
    decision = report["decision"]
    bar_fill = "█" * (score // 10)
    bar_empty = "░" * (10 - score // 10)
    score_col = _GREEN if decision == "PROMOTE" else (_YELLOW if decision == "HOLD" else _RED)
    dec_col   = _GREEN if decision == "PROMOTE" else (_YELLOW if decision == "HOLD" else _RED)

    print(f"  {_col('Readiness Score', _BOLD)}   "
          f"{_col(f'{score} / 100', score_col, _BOLD)}   "
          f"{_col(bar_fill, score_col)}{_col(bar_empty, _MUTED)}")
    print()
    icon = {"PROMOTE": "✓", "HOLD": "⚠", "BLOCK": "✗"}.get(decision, "?")
    print(f"  {_col(f'Decision:  {icon}  {decision}', dec_col, _BOLD)}")
    print()
    print(f"  {div}")

    # Missing safeguards
    missing = report["missing"]
    if missing:
        print(f"\n  {_col('Missing safeguards  (' + str(len(missing)) + ')', _RED, _BOLD)}\n")
        for s in missing:
            print(f"  {_col('✗', _RED)}  {_col(s['label'], _BOLD)}")
            print(f"     {_col('Risk:', _MUTED)} {s['risk']}")
        print()

    # Passing safeguards
    passing = report["passing"]
    if passing:
        print(f"  {_col('Safeguards found  (' + str(len(passing)) + ')', _GREEN, _BOLD)}\n")
        for s in passing:
            print(f"  {_col('✓', _GREEN)}  {s['label']}")
        print()

    # Real check results (if governance.yaml was found and parsed)
    real = report.get("real_checks")
    if real:
        print(f"  {_col('Governance check results', _BOLD)}\n")
        for name, result in sorted(real.items()):
            status = result.get("status", "?")
            sym = "✓" if status == "PASS" else ("⚠" if status == "WARN" else "✗")
            col = _GREEN if status == "PASS" else (_YELLOW if status == "WARN" else _RED)
            print(f"  {_col(sym, col)}  {name:<25} {_col(status, col)}")
        print()

    print(f"  {div}")

    # Next steps
    print(f"\n  {_col('Next steps', _BOLD)}\n")
    step = 1

    if not report["governance_file"]:
        print(f"  {_col(str(step), _BLUE, _BOLD)}.  Scaffold a governance config from this scan")
        print(f"     {_col('release-gate audit . --emit-config -o governance.yaml', _BLUE)}")
        print(f"     Fill in the TODO lines, then score before every deploy.")
        step += 1

    if missing:
        unresolved_safeguards = [s["id"] for s in missing if s["id"] != "governance_file"]
        if unresolved_safeguards:
            print(f"\n  {_col(str(step), _BLUE, _BOLD)}.  Add missing safeguards to governance.yaml")
            for s in missing:
                if s["id"] != "governance_file":
                    print(f"     • {s['label']}")
            step += 1

    print(f"\n  {_col(str(step), _BLUE, _BOLD)}.  Score before every deploy")
    print(f"     {_col('release-gate score governance.yaml', _BLUE)}")
    step += 1

    if not report["governance_file"] or not report["safeguards"].get("eval_evidence"):
        print(f"\n  {_col(str(step), _BLUE, _BOLD)}.  Add behavior evals")
        print(f"     {_col('release-gate score governance.yaml --evals evals.yaml', _BLUE)}")
        step += 1

    if not report["has_ci_integration"]:
        print(f"\n  {_col(str(step), _BLUE, _BOLD)}.  Add to GitHub Actions")
        print(f"     {_col('uses: VamsiSudhakaran1/release-gate@v0.7.0', _BLUE)}")
        step += 1

    print(f"\n  {_col(str(step), _BLUE, _BOLD)}.  Generate an evidence pack")
    print(f"     {_col('release-gate evidence-pack governance.yaml', _BLUE)}")

    print()
    print(f"  {div}")
    print()

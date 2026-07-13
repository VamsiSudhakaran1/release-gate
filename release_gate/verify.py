"""
release-gate verification core — the part that makes this a *gate*, not a guard.

The original audit detected the *presence* of safeguards by grepping for
keywords ("does the file mention 'budget'?"). That let a scaffold full of
`# TODO:` placeholders score 100/100 — a blank ticket waved through.

This module replaces presence-detection with three layers of real checks:

  Tier 1 — VALIDITY:        parse the YAML and reject placeholder / unfilled
                            values (TODO, your-team, https://TODO, empty, the
                            untouched scaffold defaults).
  Tier 2 — CROSS-CHECK:     verify the config against the actual repo — declared
                            kill-switch paths must exist, the declared model must
                            match the model the code actually calls, declared auth
                            must have corresponding code.
  Tier 3 — CODE FINDINGS:   AI-specific static analysis of the source — runaway
                            cost loops, LLM calls with no token ceiling, prompt
                            injection surface, exec/eval sinks, hardcoded secrets.

Each safeguard returns a structured result with `present` (does it earn points
under strict scoring), a human-readable `evidence` string, and a list of
`issues` explaining exactly what failed — so the gate can tell you *why* the
ticket is invalid, not just stamp it.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml
except Exception:  # pragma: no cover - pyyaml is a hard dep, but be defensive
    yaml = None


# ─────────────────────────── Placeholder detection ──────────────────────────

# Sentinel words/patterns that mean "the human never filled this in". Matched
# against parsed YAML *values* (not comments — those are stripped by the parser).
_PLACEHOLDER_RE = re.compile(
    r"\b(todo|tbd|fixme|changeme|xxx+|placeholder|fill[\s_\-]?in|"
    r"replace[\s_\-]?me|your[\s_\-]?(team|org|company|value|auth|model)|"
    r"example[\s_\-]?(team|value)?)\b"
    r"|todo[\s_\-]"          # TODO-your-team
    r"|https?://todo"        # https://TODO/runbook
    r"|<[^>]+>",             # <fill-this-in>
    re.IGNORECASE,
)

# Trailing scaffold comments left on a leaf line, e.g.
#   max_daily_cost: 100         # TODO: your hard daily $ ceiling
# A line that still carries one of these is an untouched scaffold value.
_LINE_TODO_RE = re.compile(r"#.*\b(todo|fixme|tbd)\b", re.IGNORECASE)


def is_placeholder(value: Any) -> bool:
    """True if a parsed YAML value is missing, empty, or an unfilled placeholder."""
    if value is None:
        return True
    if isinstance(value, (list, dict)):
        return len(value) == 0
    s = str(value).strip()
    if not s:
        return True
    return bool(_PLACEHOLDER_RE.search(s))


# ─────────────────────────── Raw-text helpers ───────────────────────────────

def _leaf_line(raw: str, key: str) -> str:
    """Return the first raw line declaring `key:` (for trailing-comment checks)."""
    pat = re.compile(r"^\s*" + re.escape(key) + r"\s*:", re.MULTILINE)
    m = pat.search(raw)
    if not m:
        return ""
    line_start = raw.rfind("\n", 0, m.start()) + 1
    line_end = raw.find("\n", m.start())
    if line_end == -1:
        line_end = len(raw)
    return raw[line_start:line_end]


def _line_unfilled(raw: str, key: str) -> bool:
    """True if the raw line for `key` still carries a scaffold `# TODO` comment."""
    line = _leaf_line(raw, key)
    return bool(line) and bool(_LINE_TODO_RE.search(line))


# ─────────────────────────── Nested dict access ─────────────────────────────

def _get(data: Any, *path: str) -> Any:
    cur = data
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


# ─────────────────────────── Result type ────────────────────────────────────

def _result(present: bool, evidence: str, issues: Optional[List[str]] = None,
            status: Optional[str] = None) -> Dict[str, Any]:
    return {
        "present": present,
        "status": status or ("pass" if present else "fail"),
        "evidence": evidence,
        "issues": issues or [],
    }


# ─────────────────────────── Model-cost table (rough) ────────────────────────

# $ per 1M tokens (input, output) — order-of-magnitude only, for the budget
# sanity check. Unknown models fall back to a mid-range estimate.
_MODEL_COST = {
    "gpt-4o":      (2.5, 10.0),
    "gpt-4-turbo": (10.0, 30.0),
    "gpt-4":       (30.0, 60.0),
    "gpt-3.5":     (0.5, 1.5),
    "o1":          (15.0, 60.0),
    "claude-3-opus":   (15.0, 75.0),
    "claude-3-5-sonnet": (3.0, 15.0),
    "claude-3-sonnet": (3.0, 15.0),
    "claude-3-haiku":  (0.25, 1.25),
}


def _cost_for(model: Optional[str]) -> tuple:
    if not model:
        return (5.0, 15.0)
    low = model.lower()
    for prefix, cost in _MODEL_COST.items():
        if low.startswith(prefix):
            return cost
    return (5.0, 15.0)


# ─────────────────────────── Safeguard verifiers ────────────────────────────

def verify_safeguards(
    root: Path,
    gov_path: Optional[Path],
    frameworks: Dict[str, int],
    detected_model: Optional[str],
    source_blob: str,
) -> Dict[str, Dict[str, Any]]:
    """Return {safeguard_id: result} with strict validity + cross-verification.

    `source_blob` is a lowercased concatenation of repo source (for code
    cross-checks); pass "" if unavailable.
    """
    results: Dict[str, Dict[str, Any]] = {}

    raw = ""
    data: Any = None
    parse_error: Optional[str] = None
    if gov_path and gov_path.is_file():
        try:
            raw = gov_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            raw = ""
        if yaml is not None and raw:
            try:
                data = yaml.safe_load(raw)
            except Exception as exc:
                parse_error = f"governance file is not valid YAML: {exc}"

    # ── governance_file ──────────────────────────────────────────────────────
    if not gov_path:
        results["governance_file"] = _result(
            False, "No governance.yaml found.",
            ["Add a governance.yaml — run `release-gate audit . --emit-config`."],
        )
    elif parse_error:
        results["governance_file"] = _result(False, "governance.yaml present but invalid.", [parse_error])
    elif not isinstance(data, dict):
        results["governance_file"] = _result(
            False, "governance.yaml is empty or not a mapping.",
            ["The file parses but contains no configuration."],
        )
    else:
        name = _get(data, "project", "name")
        issues = []
        if is_placeholder(name):
            issues.append("project.name is missing or a placeholder.")
        model = _get(data, "agent", "model")
        # Model is optional, but if declared it must be real and match the code.
        if model is not None:
            if is_placeholder(model) or _line_unfilled(raw, "model"):
                issues.append("agent.model is still a `# TODO` placeholder.")
            elif detected_model and detected_model.lower() not in str(model).lower() \
                    and str(model).lower() not in detected_model.lower():
                issues.append(
                    f"agent.model is '{model}' but the code actually calls "
                    f"'{detected_model}' — the config doesn't match the repo."
                )
        present = not issues
        results["governance_file"] = _result(
            present,
            f"governance.yaml valid (project: {name})." if present
            else "governance.yaml present but unfilled/inconsistent.",
            issues,
        )

    # If there's no valid governance data, every config-derived safeguard fails.
    has_data = isinstance(data, dict)

    # ── budget_ceiling ─────────────────────────────────────────────────────────
    if not has_data:
        results["budget_ceiling"] = _result(False, "No governance config to declare a budget ceiling.")
    else:
        ceiling = _get(data, "checks", "action_budget", "max_daily_cost")
        if _get(data, "checks", "action_budget", "max_daily_cost") is None:
            ceiling = _get(data, "checks", "budget_simulation", "max_daily_cost")
        issues = []
        if ceiling is None:
            issues.append("checks.action_budget.max_daily_cost is not set.")
        elif _line_unfilled(raw, "max_daily_cost"):
            issues.append("max_daily_cost still carries a `# TODO` — it was never set for real.")
        elif not isinstance(ceiling, (int, float)) or ceiling <= 0:
            issues.append(f"max_daily_cost must be a positive number (got {ceiling!r}).")
        present = not issues
        # Advisory cross-check: is the ceiling plausible vs. simulated spend?
        if present:
            reqs = _get(data, "agent", "daily_requests") or \
                _get(data, "checks", "budget_simulation", "simulation", "requests_per_day")
            tin = _get(data, "agent", "avg_input_tokens") or 800
            tout = _get(data, "agent", "avg_output_tokens") or 400
            if isinstance(reqs, (int, float)) and reqs > 0:
                cin, cout = _cost_for(detected_model or str(_get(data, "agent", "model") or ""))
                est = reqs * (tin * cin + tout * cout) / 1_000_000
                if est > ceiling * 1.1:
                    issues.append(
                        f"Declared ceiling ${ceiling} is below the projected daily "
                        f"spend (~${est:.0f}) from your own volume figures — the "
                        f"ceiling would be breached on a normal day."
                    )
                    present = False
        results["budget_ceiling"] = _result(
            present,
            f"Daily cost ceiling set to ${ceiling}." if present else "Budget ceiling invalid or unenforceable.",
            issues,
        )

    # ── kill_switch ────────────────────────────────────────────────────────────
    if not has_data:
        results["kill_switch"] = _result(False, "No governance config to declare a kill switch.")
    else:
        ks = _get(data, "checks", "fallback_declared", "kill_switch")
        issues = []
        if not isinstance(ks, dict):
            issues.append("checks.fallback_declared.kill_switch is not declared.")
        else:
            ks_type = ks.get("type")
            if is_placeholder(ks_type) or _line_unfilled(raw, "type"):
                issues.append("kill_switch.type is unset or a placeholder.")
            location = ks.get("location")
            if location and not is_placeholder(location):
                # Cross-check: the declared kill-switch location must exist in the repo.
                target = (root / str(location)).resolve()
                if not (str(target).startswith(str(root.resolve())) and target.exists()):
                    issues.append(
                        f"kill_switch.location '{location}' does not exist in the "
                        f"repo — the declared kill switch points at nothing."
                    )
        present = not issues
        results["kill_switch"] = _result(
            present,
            "Kill switch declared and its location exists." if present
            else "Kill switch missing, unfilled, or pointing at a non-existent path.",
            issues,
        )

    # ── team_owner ─────────────────────────────────────────────────────────────
    if not has_data:
        results["team_owner"] = _result(False, "No governance config to declare an owner.")
    else:
        owner = _get(data, "checks", "fallback_declared", "team_owner")
        runbook = _get(data, "checks", "fallback_declared", "runbook_url")
        issues = []
        if is_placeholder(owner) or _line_unfilled(raw, "team_owner"):
            issues.append("team_owner is unset or still 'TODO' — nobody is on the hook.")
        if runbook is not None and (is_placeholder(runbook) or _line_unfilled(raw, "runbook_url")):
            issues.append("runbook_url is a placeholder (e.g. https://TODO/runbook).")
        present = not issues
        results["team_owner"] = _result(
            present,
            f"Owner: {owner}." if present else "No real owner / runbook on file.",
            issues,
        )

    # ── auth_rate_limit ──────────────────────────────────────────────────────────
    if not has_data:
        results["auth_rate_limit"] = _result(False, "No governance config to declare auth / rate limits.")
    else:
        auth_required = _get(data, "checks", "identity_boundary", "authentication", "required")
        auth_type = _get(data, "checks", "identity_boundary", "authentication", "type")
        rpm = _get(data, "checks", "identity_boundary", "rate_limit", "requests_per_minute")
        issues = []
        if auth_required is not True:
            issues.append("identity_boundary.authentication.required must be true.")
        if is_placeholder(auth_type) or _line_unfilled(raw, "type"):
            issues.append("authentication.type is unset or a placeholder.")
        if not isinstance(rpm, (int, float)) or rpm <= 0 or _line_unfilled(raw, "requests_per_minute"):
            issues.append("rate_limit.requests_per_minute must be a positive number, set for real.")
        present = not issues
        # Cross-check (advisory): is there any auth code in the repo?
        if present and source_blob:
            if not re.search(r"auth|bearer|api[_\-]?key|oauth|jwt|rate.?limit", source_blob):
                issues.append(
                    "Config declares auth but no authentication code was found in "
                    "the repo — the declaration may not be enforced."
                )
        results["auth_rate_limit"] = _result(
            present,
            "Auth required + rate limit set." if present else "Auth/rate-limit declaration incomplete.",
            issues,
        )

    # ── eval_evidence ──────────────────────────────────────────────────────────
    results["eval_evidence"] = _verify_evals(root)

    # ── trace_policy ───────────────────────────────────────────────────────────
    if not has_data:
        results["trace_policy"] = _result(False, "No governance config to declare a tool/trace policy.")
    else:
        tp = data.get("trace_policies") if isinstance(data, dict) else None
        issues = []
        if not isinstance(tp, dict):
            issues.append("trace_policies is not declared.")
        else:
            allowed = tp.get("allowed_tools")
            forbidden = tp.get("forbidden_tools")
            if _line_unfilled(raw, "allowed_tools") or _line_unfilled(raw, "forbidden_tools"):
                issues.append("tool lists still carry `# TODO` — they were never tailored to this agent.")
            elif is_placeholder(allowed) and is_placeholder(forbidden):
                issues.append("Neither allowed_tools nor forbidden_tools is populated.")
        present = not issues
        results["trace_policy"] = _result(
            present,
            "Tool policy declared." if present else "Tool/trace policy missing or unfilled.",
            issues,
        )

    # ── loop_boundary (advisory) ───────────────────────────────────────────────
    # A loop: block that declares at least one boundary (iteration cap, cost
    # ceiling, or stop condition) means the agent loop can't spin without bound.
    if not has_data:
        results["loop_boundary"] = _result(
            False, "No governance config to declare a loop boundary.",
            ["Add a loop: block with max_iterations / total_cost_limit / stop_condition "
             "if this repo runs an agent loop."],
        )
    else:
        loop_cfg = data.get("loop") if isinstance(data, dict) else None
        issues = []
        if not isinstance(loop_cfg, dict):
            issues.append(
                "No loop: block declared — agent loops have no iteration cap, "
                "cost ceiling, or stop condition."
            )
        else:
            boundary_keys = ("max_iterations", "total_cost_limit",
                             "max_tokens_per_iteration", "stop_condition")
            if not any(loop_cfg.get(k) not in (None, "") for k in boundary_keys):
                issues.append(
                    "loop: block declares no boundary "
                    "(max_iterations / total_cost_limit / stop_condition)."
                )
            maker = loop_cfg.get("maker_model")
            checker = loop_cfg.get("checker_model")
            if maker and checker and str(maker).strip() == str(checker).strip():
                issues.append(
                    "maker_model and checker_model are identical — the checker is "
                    "reviewing its own output (self-review bias)."
                )
        present = not issues
        results["loop_boundary"] = _result(
            present,
            "Loop boundary declared." if present else "Loop boundary missing or unbounded.",
            issues,
        )

    return results


def _verify_evals(root: Path) -> Dict[str, Any]:
    """eval_evidence passes only if there's a parseable suite with ≥1 real case,
    or a test file with genuine agent-behaviour assertions."""
    for name in ("evals.yaml", "evals.yml"):
        path = root / name
        if path.is_file():
            if yaml is None:
                return _result(True, "evals.yaml present (not parsed — pyyaml unavailable).")
            try:
                doc = yaml.safe_load(path.read_text(encoding="utf-8", errors="ignore"))
            except Exception as exc:
                return _result(False, "evals.yaml present but invalid.", [f"Could not parse evals.yaml: {exc}"])
            cases = None
            if isinstance(doc, dict):
                cases = doc.get("cases") or doc.get("evals") or doc.get("tests")
            elif isinstance(doc, list):
                cases = doc
            if not isinstance(cases, list) or not cases:
                return _result(False, "evals.yaml has no test cases.",
                               ["Add at least one case with an input and an expected result."])
            good = 0
            for c in cases:
                if isinstance(c, dict) and (c.get("input") is not None or c.get("name") or c.get("id")) \
                        and (c.get("expected") is not None or c.get("assert") is not None
                             or c.get("name") or c.get("id")):
                    good += 1
            if good == 0:
                return _result(False, "evals.yaml cases are malformed.",
                               ["Each case needs an input and an expected result."])
            return _result(True, f"{good} eval case(s) defined.")
    # Fall back to test files
    if _has_behaviour_tests(root):
        return _result(True, "Behaviour test suite found.")
    return _result(False, "No eval suite or behaviour tests found.",
                   ["Add evals.yaml or test_*.py with agent-behaviour assertions."])


def _has_behaviour_tests(root: Path) -> bool:
    test_patterns = [r"def test.*agent", r"def test.*eval", r"pii", r"refuse",
                     r"keywords_blocked", r"injection", r"jailbreak"]
    for dirpath, _, filenames in os.walk(root):
        if any(skip in dirpath for skip in (".git", "__pycache__", ".venv", "node_modules")):
            continue
        for fname in filenames:
            if fname.startswith("test_") and fname.endswith(".py"):
                try:
                    content = (Path(dirpath) / fname).read_text(
                        encoding="utf-8", errors="ignore").lower()
                except OSError:
                    continue
                if any(re.search(p, content) for p in test_patterns):
                    return True
    return False


# ─────────────────────────── Tier 3: code findings ──────────────────────────

# AI-specific failure modes. This is the part SonarQube can't do: it doesn't
# know what a runaway agent loop or a prompt-injection surface is.

_LLM_CALL_RE = re.compile(
    r"\.(?:chat\.completions\.create|completions\.create|messages\.create|"
    r"create_message|generate|complete|invoke|run|chat)\s*\(",
)
_EXEC_SINK_RE = re.compile(
    r"\b(?:eval|exec)\s*\("
    r"|os\.system\s*\("
    r"|subprocess\.[A-Za-z_]+\([^)]*shell\s*=\s*True"
    r"|child_process\.exec\s*\("                # Node.js
    r"|child_process\.execSync\s*\("
    r"|vm\.runInNewContext\s*\("                 # Node vm escape
)
_SECRET_RE = re.compile(
    r"sk-[A-Za-z0-9]{16,}"
    r"|(?:api[_\-]?key|secret|token)\s*[:=]\s*['\"][A-Za-z0-9_\-]{12,}['\"]"
    r"|OPENAI_API_KEY\s*=\s*['\"][^'\"]{12,}['\"]"
    r"|anthropic[_\-]api[_\-]key\s*[:=]\s*['\"][^'\"]{12,}['\"]",
    re.IGNORECASE
)
_SYSTEM_PROMPT_FSTRING_RE = re.compile(r"""(["'])(?:system|developer)\1""", re.IGNORECASE)
# JS/TS: template literals used as system prompts  e.g. role:"system", content:`...${userInput}`
_JS_SYSTEM_TMPL_RE = re.compile(r"""role\s*:\s*["']system["'][^}]*content\s*:\s*`[^`]*\$\{""", re.DOTALL)
# JS/TS: LLM calls without maxTokens / max_tokens
_JS_LLM_CALL_RE = re.compile(
    r"\.(?:chat\.completions\.create|messages\.create|generate|complete|invoke)\s*\(",
)
# JS/TS unbounded loop near LLM call
_JS_WHILE_RE = re.compile(r"\bwhile\s*\(\s*true\s*\)", re.IGNORECASE)

_SCANNABLE_EXTS = {".py", ".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"}


def scan_code_findings(root: Path, max_files: int = 2000, max_bytes: int = 200_000,
                       return_excluded: bool = False):
    """Static analysis for AI-agent-specific risks.

    Returns the list of scored (production) findings. With return_excluded=True
    returns (scored, excluded) where `excluded` are findings in non-production
    paths (cookbook/examples/tests/docs/…) that must NOT drive the score.
    """
    findings: List[Dict[str, Any]] = []
    skip_dirs = {".git", "__pycache__", "node_modules", ".venv", "venv",
                 "dist", "build", "site-packages", ".tox", "tests", "test"}
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for fname in filenames:
            if not any(fname.endswith(ext) for ext in _SCANNABLE_EXTS):
                continue
            count += 1
            if count > max_files:
                return _finalize_findings(findings, split=return_excluded)
            fpath = Path(dirpath) / fname
            try:
                text = fpath.read_bytes()[:max_bytes].decode("utf-8", errors="ignore")
            except OSError:
                continue
            rel = str(fpath.relative_to(root))
            if any(fname.endswith(ext) for ext in (".ts", ".tsx", ".js", ".jsx", ".mjs")):
                findings.extend(_scan_js_file(rel, text))
            else:
                findings.extend(_scan_file(rel, text))
    return _finalize_findings(findings, split=return_excluded)


def _finalize_findings(findings: List[Dict[str, Any]], split: bool = False):
    """De-dup, and partition out findings that live in NON-PRODUCTION code —
    example / cookbook / tutorial / sample / test / docs / build tooling. Applied
    at EVERY return of scan_code_findings (including the max-files early exit).

    A finding in a repo's `cookbook/` or `examples/` teaching code is not a risk
    in the deployed framework — it's a demo. Scoring a framework on its tutorials
    (a coding-agent example that runs `subprocess(shell=True)`, or 57 uncapped LLM
    calls across sample apps) makes the grade untrustworthy to the one person who
    knows the repo best: its maintainer. So those never touch the score; with
    split=True they are returned separately so they can still be shown, clearly
    labelled as unscored.

    By default returns just the scored (production) findings; with split=True
    returns (scored, excluded).
    """
    def _dedup(items):
        seen, out = set(), []
        for f in items:
            key = (f["file"], f["line"], f["title"])
            if key not in seen:
                seen.add(key)
                out.append(f)
        return out

    scored, excluded = [], []
    for f in findings:
        if _is_tooling_path(f["file"]):
            excluded.append(f)
        else:
            scored.append(f)
    scored, excluded = _dedup(scored), _dedup(excluded)
    return (scored, excluded) if split else scored


# Finding types that only matter in the deployed agent runtime, not in
# build/test/example tooling.
_RUNTIME_ONLY_TITLES = {
    "Dangerous execution sink", "Dynamic execution sink",
    "Unbounded loop around an LLM call",
}
_TOOLING_PATH_RE = re.compile(
    r"(^|/)(scripts?|build|dist|\.github|examples?|cookbooks?|recipes?|samples?|"
    r"demos?|tutorials?|tests?|__tests__|test|docs?|websites?|sites?|"
    r"archives?|archived|deprecated|generated|vendor|vendored|_vendor|_vendored|"
    r"third_party|third-party|site-packages|dist-packages|node_modules|bundled|"
    r"fixtures?|mocks?|__mocks__|stories|"
    r"benchmarks?|bench|e2e|cypress|electron|webpack|rollup|vite|setup\.py|conftest)(/|\.|$)",
    re.IGNORECASE)


def _is_tooling_path(rel: str) -> bool:
    rel = rel.replace("\\", "/")
    # TypeScript type-declaration files have NO runtime — a `.d.ts` (or a
    # `.spec-d.ts` type test) can't be a live sink. Exclude from scoring.
    if rel.endswith(".d.ts") or ".spec-d." in rel or ".test-d." in rel:
        return True
    return bool(_TOOLING_PATH_RE.search(rel) or _is_test_path(rel))


# Test/spec FILES (not just tests/ dirs): config_test.py, test_foo.py, x.spec.ts,
# and TypeScript type-tests (x.test-d.ts / x.spec-d.ts — vitest/tsd convention).
_TEST_FILE_RE = re.compile(
    r"(^|/)(?:test_[^/]+|[^/]+_test|[^/]+\.test(?:-d)?|[^/]+\.spec(?:-d)?|[^/]+_spec)\.[A-Za-z]+$",
    re.IGNORECASE)


def _is_test_path(rel: str) -> bool:
    rel = rel.replace("\\", "/")
    return bool(_TEST_FILE_RE.search(rel)
                or re.search(r"(^|/)(tests?|__tests__|e2e|cypress)(/|$)", rel, re.IGNORECASE))


# Lines that match the secret regex but are obviously placeholders/env reads —
# flagging these destroys credibility, so filter them out. (Distinct from the
# governance _PLACEHOLDER_RE above, which validates governance.yaml values.)
_SECRET_PLACEHOLDER_RE = re.compile(
    r"your[_\-]?(?:api|key|token|secret)|x{4,}|\.\.\.|<[^>]+>|example|changeme|"
    r"placeholder|dummy|test[_\-]?key|insert[_\-]?your|\bfake\b|\bsample\b|\bdemo\b|"
    r"os\.environ|getenv|process\.env|settings\.|config\.|\$\{",
    re.IGNORECASE)


def _looks_placeholder(line: str) -> bool:
    return bool(_SECRET_PLACEHOLDER_RE.search(line))


# Capture the assigned value so we can tell a real credential from a key/env-var
# NAME (e.g. `SECRET = "REDDIT_TOKEN"` is a lookup key, not a token). A taOS
# maintainer caught exactly this false positive.
_ASSIGNED_VALUE_RE = re.compile(
    r"(?:api[_\-]?key|secret|token|password|passwd|apikey)\s*[:=]\s*['\"]([^'\"]+)['\"]",
    re.IGNORECASE)


def _looks_dummy_token(tok: str) -> bool:
    """True if a key-shaped token is obviously a placeholder/test value, e.g.
    sk-abcdefghijklmnopqrstuvwxyz123456 (sequential), sk-xxxxxxxx, sk-1234..."""
    body = re.sub(r"^(?:sk-|rg_|ghp_|AKIA|xox[baprs]-)", "", tok)
    if len(body) < 8:
        return False
    # Longest run of consecutive-ordinal characters (abcdef… / 123456…).
    run = best = 1
    for a, b in zip(body, body[1:]):
        run = run + 1 if ord(b) - ord(a) == 1 else 1
        best = max(best, run)
    if best >= 8:
        return True
    if len(set(body.lower())) <= 4:                      # mostly one repeated char
        return True
    return bool(re.search(r"abcdef|qwerty|123456|x{4,}|test|dummy|example|fake|sample|"
                          r"your[_-]|change[_-]?me|my[_-]secret|placeholder|replace",
                          tok, re.IGNORECASE))


# Public, client-side telemetry / analytics keys — meant to be embedded in
# client code, not credentials. Matches by the well-known variable-name pattern
# or a known public value prefix (PostHog `phc_`, GA `G-`/`UA-`).
_PUBLIC_TELEMETRY_RE = re.compile(
    r"(mixpanel|posthog|segment|amplitude|heap|fullstory|sentry[_-]?dsn|"
    r"google[_-]?analytics|\bga\b|gtag)[_-]?(project[_-]?)?"
    r"(token|key|id|api[_-]?key|write[_-]?key|dsn)"
    r"|\bphc_[A-Za-z0-9]{20,}"
    r"|[\"'](?:G-[A-Z0-9]{6,}|UA-\d{4,}-\d+)[\"']",
    re.IGNORECASE)


def _is_real_secret(line: str) -> bool:
    """True only if the line plausibly contains an actual credential value."""
    if _looks_placeholder(line):
        return False
    # Public client-side telemetry keys are DESIGNED to ship in client code —
    # they're write-only ingestion ids, not secrets (Mixpanel project token,
    # PostHog project API key `phc_…`, Segment write key, Amplitude/GA ids).
    # Flagging these as a "leaked secret" (as we did on aider) is a false alarm.
    if _PUBLIC_TELEMETRY_RE.search(line):
        return False
    # Strong, unambiguous: a provider key prefix — unless it's a dummy/test token.
    m = re.search(r"\b(sk-[A-Za-z0-9]{16,}|rg_[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}"
                  r"|AKIA[A-Z0-9]{12,}|xox[baprs]-[A-Za-z0-9-]{10,})", line)
    if m:
        return not _looks_dummy_token(m.group(1))
    m = _ASSIGNED_VALUE_RE.search(line)
    if not m:
        return False
    val = m.group(1).strip()
    # A 0x-hex literal — an Ethereum address / hash / byte string (e.g. the
    # zero address 0x0000…0000), never an API-key secret. `gas_token = "0x0…"`
    # matched only because "token" is a substring of the var name.
    if re.fullmatch(r"0x[0-9a-fA-F]+", val):
        return False
    # A key/env-var NAME, not a value: ALL_CAPS_WITH_UNDERSCORES.
    if re.fullmatch(r"[A-Z][A-Z0-9_]{2,}", val):
        return False
    # UPPERCASE words joined by hyphens/underscores — a placeholder or constant,
    # not a live credential: "YOUR-AZURE-SEARCH-SERVICE-ADMIN-KEY",
    # "WHISKEY-TANGO-FOXTROT-42".
    if re.fullmatch(r"[A-Z][A-Z0-9]*(?:[-_][A-Z0-9]+)+", val):
        return False
    # A bare UUID — an identifier format (often an example/default), not a
    # high-entropy API key: "a0f8a6ba-c32f-4407-af0c-169f1915490c".
    if re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
                    r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", val):
        return False
    # An HTTP header NAME, not a secret value: "X-LiveKit-Worker-Token",
    # "X-Api-Key". These live in HEADER_* constants and match only because the
    # var name contains "token"/"key".
    if re.fullmatch(r"[Xx]-[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*", val):
        return False
    # Title-Case-hyphenated identifier — a header / constant name convention
    # ("Worker-Token", "Content-Type"), never a random-case credential.
    if re.fullmatch(r"[A-Z][A-Za-z0-9]*(?:-[A-Z][A-Za-z0-9]*)+", val):
        return False
    # A code identifier / handler name (snake_case, camelCase) — not a secret,
    # e.g. "handle_skills_clawhub_get_token".
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", val):
        return False
    # Lowercase dictionary words joined by hyphens/underscores — a slug or demo
    # value, not a credential: "my-secret-verify-token", "dev-secret-change-me".
    if re.fullmatch(r"[a-z]+(?:[-_][a-z]+)+", val):
        return False
    if "." in val and " " not in val and "/" not in val:
        return False
    # Shell metacharacters / template markers → a command or template string, not
    # a credential (e.g. `set "ANTHROPIC_API_KEY=" && {cmd} /login`).
    if re.search(r"[&|;$`<>{}]", val) or "/" in val:
        return False
    # Real secrets are long and high-entropy.
    if len(val) < 20:
        return False
    has_digit = any(c.isdigit() for c in val)
    has_alpha = any(c.isalpha() for c in val)
    has_mixed_or_special = (any(c.islower() for c in val) and any(c.isupper() for c in val)) \
        or any(not c.isalnum() for c in val)
    return has_alpha and (has_digit or has_mixed_or_special)


def _scan_file(rel: str, text: str) -> List[Dict[str, Any]]:
    """Python source — real AST analysis (LLM calls, exec sinks, prompt
    injection) plus a placeholder-aware secret scan.

    The structural analysis lives in release_gate.agent_analysis so it can
    resolve what's actually an LLM client and trace input into sinks, instead of
    pattern-matching method names. This is what makes a finding trustworthy
    enough to put in front of a maintainer.
    """
    from release_gate.agent_analysis import analyze_python
    findings: List[Dict[str, Any]] = list(analyze_python(text, rel))

    for i, line in enumerate(text.splitlines(), start=1):
        s = line.strip()
        if s.startswith("#"):
            continue
        if _SECRET_RE.search(line) and _is_real_secret(line):
            findings.append(_finding(
                "high", "Hardcoded secret / API key", rel, i, "<redacted>",
                "Move secrets to environment variables or a secrets manager — never commit them.",
            ))
    return findings


_JS_EXTENSIONS = {".ts", ".tsx", ".js", ".jsx", ".mjs"}

# Patterns for JS/TS-specific scanning
_JS_UNBOUNDED_LOOP_RE = re.compile(
    r"while\s*\(\s*true\s*\)|for\s*\(\s*;\s*;\s*\)", re.IGNORECASE
)
# A `while(true)` is only a runaway if nothing bounds it. A reachable exit
# (break/return/throw) or a retry/step ceiling means it terminates — the common
# middleware-retry pattern, not an agent runaway. (VoltAgent false positive.)
_JS_LOOP_BOUNDED_RE = re.compile(
    r"\b(?:break|return|throw)\b"
    r"|retr(?:y|ies)"                # retry / retries / retryCount / middlewareRetryCount / maxRetries
    r"|max(?:Steps|Iterations|OutputTokens)"
    r"|stepCount|\bstopWhen\b|\bstepCountIs\b|Abort(?:Controller|Signal)",
    re.IGNORECASE)
_JS_LLM_SINK_RE = re.compile(
    r"(?:streamText|generateText|chat\.completions|messages\.create|\.invoke\s*\(|\.stream\s*\()"
)
_JS_GENERATE_CALL_RE = re.compile(
    r"(?:generateText|streamText|chat\.completions\.create|messages\.create)\s*\("
)
# All ceiling spellings across SDK versions: AI SDK v4 maxTokens, v5
# maxOutputTokens, OpenAI max_completion_tokens, Anthropic/generic max_tokens.
_JS_MAX_TOKENS_NEARBY_RE = re.compile(
    r"(?:maxTokens|max_tokens|maxOutputTokens|max_output_tokens|"
    r"maxCompletionTokens|max_completion_tokens)")
# A match that is the function's own DEFINITION (`export async function
# generateText(` / class method `async generateText(`), not a call into an LLM.
_JS_DEF_SITE_RE = re.compile(r"\b(?:function|async|get|set)\s+$|\*\s*$")
# Any template literal that interpolates a value. The source is classified after
# the fact so we grade external input (HIGH) vs model/tool output (MEDIUM) vs the
# developer's own material (not flagged) — instead of only catching req/params/body.
_JS_TEMPLATE_INTERP_RE = re.compile(r"`[^`]*\$\{[^}]+\}[^`]*`")
# The interpolation EXPRESSIONS inside a template — classification must look only
# at the code inside ${...}, never the surrounding prose. A system prompt whose
# instructions mention "input"/"content" while interpolating a benign
# `${new Date()}` must not be graded by those prose words (the mem0 FP).
_JS_INTERP_INNER_RE = re.compile(r"\$\{([^}]+)\}")
# LLM-specific system-prompt fields: unambiguous enough that an interpolated
# template assigned to them is a system prompt (Vercel AI SDK's `system:` param,
# a `systemPrompt`/`systemMessage` var). Anchored right before the backtick.
_JS_SYSPROMPT_FIELD_RE = re.compile(
    r"(?:system|systemPrompt|system_prompt|systemMessage|systemInstruction)\s*[:=]\s*$",
    re.IGNORECASE)
# A bare `content:` is far too common (file content, UI content, a var literally
# named content) to flag alone. It's only a chat message when its object also
# sets role:'system'|'developer' — the shape the Python analyzer keys on.
_JS_CONTENT_FIELD_RE = re.compile(r"content\s*[:=]\s*$", re.IGNORECASE)
_JS_SYSTEM_ROLE_RE = re.compile(
    r"role\s*:\s*['\"](?:system|developer)['\"]", re.IGNORECASE)
# Source classification for an interpolated ${...} expression, mirroring the
# Python analyzer: EXTERNAL request/user input is the worst case (HIGH); model /
# tool output is a real but lower-confidence surface (MEDIUM); an unrecognized
# identifier is the developer's own material and is not flagged.
_JS_INJ_EXTERNAL_RE = re.compile(
    r"\b(?:req|request|params|body|query|searchParams|userInput|user_input|"
    r"userMessage|user_message|input|payload|formData|args|url|headers|cookies)\b",
    re.IGNORECASE)
_JS_INJ_MODEL_RE = re.compile(
    r"\b(?:completion|completions|response|result|reply|answer|generation|"
    r"toolResult|tool_result|assistant|choices|delta|content|message|msg|text|"
    r"output|llmOutput|llmResponse)\b", re.IGNORECASE)
_JS_SECRET_RE = re.compile(
    r"sk-[A-Za-z0-9]{20,}"
    r"|ANTHROPIC_API_KEY\s*=\s*[\"'][a-zA-Z0-9]{20,}[\"']"
)
# Require an actual call, not a bare `child_process` import/identifier.
_JS_EXEC_SINK_RE = re.compile(
    r"\beval\s*\("
    r"|new\s+Function\s*\("
    r"|child_process\.(?:exec|execSync|spawn|spawnSync)\s*\("
    r"|\bexecSync\s*\("
    r"|\bvm\.(?:runInNewContext|runInContext|runInThisContext|compileFunction)\s*\("  # Node vm escape
    r"|\bexec\s*\([^)]*\$\{"        # exec(`...${x}`) — interpolated command
)

# JS has no dataflow pass, so — like the Python side — we only assert HIGH/
# confirmed when a genuinely-external source is visibly reaching the sink. A
# value from request/model input carries one of these markers; a config-driven
# transform expression (promptfoo-style `new Function(config.parser)`) does not.
_JS_STRONG_INPUT_RE = re.compile(
    r"\breq(uest)?\.(body|params|query|url|headers|cookies)\b"
    r"|\breq(uest)?\[|\bctx\.request\b|\bevent\.body\b|\bsearchParams\b"
    r"|\bwebhook\b|\buserInput\b|\.choices\[|\bmessage\.content\b"
    r"|\bcompletion\b|\bllm(Output|Response)\b",
    re.IGNORECASE)
# Shell-escaping / quoting applied to interpolated args → mitigated (promptfoo's
# `execSync(`grep ${args.map(shellEscape)}`)` is not an injection sink).
_JS_SHELL_ESCAPE_RE = re.compile(
    r"shell[_-]?escape|shell[_-]?quote|shlex|escape[_-]?shell|\bquote\(",
    re.IGNORECASE)


def _js_exec_is_dynamic(line: str) -> bool:
    """True if a JS exec/eval call takes a dynamic command (not a constant string).

    `execSync('git ls-files')` → constant → not a sink. `exec(`...${x}`)` or
    `execSync(userCmd)` → dynamic → real risk.
    """
    m = re.search(
        r"(?:eval|new\s+Function|execSync|spawnSync|spawn|exec|"
        r"runInNewContext|runInContext|runInThisContext|compileFunction)\s*\(",
        line)
    if not m:
        return True  # be conservative if we can't locate the call
    rest = line[m.end():].lstrip()
    if not rest:
        return True
    if rest[0] in "'\"`":
        # First argument is a string literal — dynamic only if it interpolates
        # (${...}) or is concatenated with a variable.
        return "${" in line or bool(re.search(r"['\"`]\s*\+", line))
    return True  # bare identifier / expression argument


def _strip_js_strings(line: str) -> str:
    """Blank string/template-literal contents so matches inside strings (e.g.
    require('child_process')) don't register as code."""
    line = re.sub(r'"(?:[^"\\]|\\.)*"', '""', line)
    line = re.sub(r"'(?:[^'\\]|\\.)*'", "''", line)
    line = re.sub(r"`(?:[^`\\]|\\.)*`", "``", line)
    return line


def _mask_js_noncode(text: str) -> str:
    """Blank the contents of block comments, line comments, and string/template
    literals across the WHOLE file, preserving every newline (so line numbers
    computed on the masked text match the original). This keeps a generateText(
    inside a JSDoc @example or a docs template string from registering as a call.
    """
    out = []
    i, n = 0, len(text)
    state = None  # None | "line" | "block" | "'" | '"' | "`"
    while i < n:
        c = text[i]
        if state is None:
            two = text[i:i + 2]
            if two == "//":
                state = "line"; out.append("  "); i += 2; continue
            if two == "/*":
                state = "block"; out.append("  "); i += 2; continue
            if c in "'\"`":
                state = c; out.append(c); i += 1; continue
            out.append(c); i += 1; continue
        if state == "line":
            if c == "\n":
                state = None; out.append(c)
            else:
                out.append(" ")
            i += 1; continue
        if state == "block":
            if text[i:i + 2] == "*/":
                state = None; out.append("  "); i += 2; continue
            out.append(c if c == "\n" else " "); i += 1; continue
        # inside a string/template literal
        if c == "\\":
            out.append("  " if text[i + 1:i + 2] != "\n" else " \n"); i += 2; continue
        if c == state:
            state = None; out.append(c); i += 1; continue
        out.append(c if c == "\n" else " "); i += 1
    return "".join(out)


def _js_call_arg_span(masked: str, open_paren: int, cap: int = 4000) -> int:
    """Return the index just past the call's balanced closing paren (scanning the
    masked text so parens in strings/comments don't count), bounded by `cap`."""
    depth = 0
    end = min(len(masked), open_paren + cap)
    for j in range(open_paren, end):
        ch = masked[j]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return j + 1
    return end


def _scan_js_file(rel: str, text: str) -> List[Dict[str, Any]]:
    """Detect AI-specific risks in JS/TS source files."""
    findings: List[Dict[str, Any]] = []
    lines = text.splitlines()

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        # Skip comment lines
        if stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*"):
            continue

        # Skip import/require lines — they're not execution.
        if stripped.startswith(("import ", "export ")) or "require(" in stripped:
            code = ""
        else:
            code = _strip_js_strings(line)

        # Hardcoded API key
        if _JS_SECRET_RE.search(line) and _is_real_secret(line):
            findings.append(_finding(
                "high", "Hardcoded secret / API key", rel, i, "<redacted>",
                "Move secrets to environment variables or a secrets manager — never commit them.",
            ))

        # exec/eval sink — only when the command is DYNAMIC. A constant string
        # literal (execSync('git ls-files ...')) is not an injection sink.
        if code and _JS_EXEC_SINK_RE.search(code) and _js_exec_is_dynamic(line):
            # No JS dataflow, so calibrate like the Python side: HIGH/confirmed
            # ONLY when external (request/model) input is visibly reaching the
            # sink. A dynamically-built value with no such marker — a config
            # transform expression, an agent's own generated code — is
            # MEDIUM/inferred ("confirm the source"), not a confident RCE. This
            # is what keeps a tool like promptfoo (which evals user-authored
            # config transforms by design) from getting a wall of phantom highs.
            interpolated = "${" in line or bool(re.search(r"['\"`]\s*\+|\+\s*['\"`]", line))
            ctx = "\n".join(lines[max(0, i - 3):i + 1])
            strong = bool(_JS_STRONG_INPUT_RE.search(ctx))
            escaped = bool(_JS_SHELL_ESCAPE_RE.search(line))
            if escaped and not strong:
                pass  # shell-escaped / quoted args are mitigated — not an injection
            elif interpolated and strong:
                findings.append(_finding(
                    "high", "Dangerous execution sink", rel, i, stripped[:120],
                    "eval/new Function/child_process.exec executes a value that reaches "
                    "it from request/model input — remote code execution. Use a fixed "
                    "argument list, or strictly validate/sandbox the input.",
                    confidence="high", basis="confirmed",
                    impact="Remote code execution: external input reaches this sink."))
            elif interpolated:
                findings.append(_finding(
                    "medium", "Dynamic execution sink", rel, i, stripped[:120],
                    "eval/new Function/child_process.exec runs a dynamically-built "
                    "value. If it can come from model or request input this is remote "
                    "code execution; if it's a trusted config/transform expression it "
                    "may be by design. Confirm the source, or sandbox it.",
                    confidence="medium", basis="inferred",
                    impact="RCE only if model/request input can reach this sink — "
                           "provenance not proven here."))
            else:
                findings.append(_finding(
                    "low", "Dynamic execution sink", rel, i, stripped[:120],
                    "eval/new Function/child_process.exec runs a non-constant value. "
                    "Confirm it can't be reached by model or request input.",
                    confidence="low", basis="inferred",
                    impact="Potential code execution — reachability not proven."))

        # Unbounded LLM loop — ONLY a truly unbounded loop (while(true) / for(;;)).
        # A bounded `while (i < max)` or a `for await (... of stream)` (just
        # consuming a response stream) is not a runaway and must not be flagged.
        if _JS_UNBOUNDED_LOOP_RE.match(stripped):
            # Look a few lines BEFORE the loop too — the retry ceiling is often
            # declared just above it — and well into the body.
            window = "\n".join(lines[max(0, i - 6):i + 20])
            if _JS_LLM_SINK_RE.search(window) and not _JS_LOOP_BOUNDED_RE.search(window):
                findings.append(_finding(
                    "high", "Unbounded loop around an LLM call", rel, i, stripped[:120],
                    "A loop wrapping an LLM call with no iteration cap can spin forever, "
                    "burning tokens and budget. Add a max-iterations ceiling.",
                    confidence="high", basis="confirmed",
                    impact="Runaway cost / no termination guarantee.",
                ))

    # Missing max tokens: generateText/streamText/etc. without a ceiling in the
    # call's own arguments. Scans a comment/string-masked copy of the file so a
    # JSDoc @example or a code snippet inside a docs template string never
    # registers as a call, skips definition sites (`function generateText(` is
    # the SDK defining itself, not calling an LLM), and checks the call's full
    # balanced-paren argument span instead of an arbitrary 5-line window.
    masked = _mask_js_noncode(text)
    for m in _JS_GENERATE_CALL_RE.finditer(masked):
        start = m.start()
        if _JS_DEF_SITE_RE.search(masked, 0, start):
            continue
        line_no = masked.count("\n", 0, start) + 1
        open_paren = masked.find("(", m.end() - 1)
        if open_paren == -1:
            continue
        span_end = _js_call_arg_span(masked, open_paren)
        window = text[start:span_end]
        if not _JS_MAX_TOKENS_NEARBY_RE.search(window):
            snippet = text[start:text.find("\n", start) if text.find("\n", start) != -1 else start + 80].strip()
            findings.append(_finding(
                "low", "LLM call with no token ceiling", rel, line_no, snippet[:120],
                "No maxTokens / maxOutputTokens on this call — a single response can "
                "run to the model's max output. Not a vulnerability by itself; set an "
                "explicit output ceiling to bound latency and cost.",
                confidence="medium", basis="inferred",
                impact="Unpredictable latency/cost on a single call. Not a vulnerability "
                       "by itself.",
            ))

    # Prompt injection: a template literal interpolating an UNTRUSTED value into a
    # system prompt. Graded by source (external request/user input → HIGH; model
    # or tool output → MEDIUM; the developer's own material → not flagged), and
    # precision-gated to the actual message shape so common words never
    # false-positive. This replaces the old req/params/body-only check that used
    # a loose 300-char "messages array is nearby" window — which flagged a var
    # named `content`, a UI renderer, and `Error(`${response.status}`)` strings.
    seen_inj: set = set()
    for m in _JS_TEMPLATE_INTERP_RE.finditer(text):
        start = m.start()
        line_no = text.count("\n", 0, start) + 1
        if line_no in seen_inj:
            continue
        # Skip an interpolation inside a comment (masked blanks comment bodies to
        # spaces, so a real backtick there means it's live code).
        if start < len(masked) and masked[start] != "`":
            continue
        # The literal must be the DIRECT value of a system-prompt field. An
        # LLM-specific field (system:/systemPrompt=) qualifies alone; a generic
        # content: only inside a role:'system' object.
        prefix = text[max(0, start - 48):start]
        if _JS_SYSPROMPT_FIELD_RE.search(prefix):
            pass
        elif _JS_CONTENT_FIELD_RE.search(prefix) and \
                _JS_SYSTEM_ROLE_RE.search(text[max(0, start - 160):start]):
            pass
        else:
            continue
        # Classify by the interpolation EXPRESSIONS only (the code inside ${...}),
        # not the whole template — prose like "extract facts from the input"
        # otherwise matched `input` and false-flagged a benign `${new Date()}`.
        inners = " ".join(_JS_INTERP_INNER_RE.findall(m.group(0)))
        if _JS_INJ_EXTERNAL_RE.search(inners):
            sev, src_conf, basis, who = "high", "high", "confirmed", "request/user input"
        elif _JS_INJ_MODEL_RE.search(inners):
            sev, src_conf, basis, who = "medium", "low", "inferred", "model or tool output"
        else:
            continue  # developer's own code (dates, config) — not an injection surface
        seen_inj.add(line_no)
        line_text = lines[line_no - 1].strip() if line_no - 1 < len(lines) else ""
        findings.append(_finding(
            sev, "Interpolated system prompt (injection surface)", rel, line_no, line_text[:120],
            f"A template literal interpolates {who} into a system-prompt / messages "
            "context. Untrusted text there can override system instructions. Keep "
            "untrusted input in a clearly-delimited user-role message only.",
            confidence=src_conf, basis=basis,
            impact="Prompt-injection surface: untrusted text can override system "
                   "instructions.",
        ))

    return findings


def _finding(severity: str, title: str, file: str, line: int, snippet: str,
             recommendation: str, confidence: str = "medium",
             basis: str = "inferred", impact: str = "") -> Dict[str, Any]:
    from release_gate.rules import rule_id_for_title
    return {
        "severity": severity,
        "title": title,
        "file": file,
        "line": line,
        "snippet": snippet,
        "recommendation": recommendation,
        "confidence": confidence,
        "basis": basis,
        "impact": impact,
        # Stable, citable rule id (RG-EXEC-001) — the bridge from scanner to authority.
        "rule_id": rule_id_for_title(title),
    }

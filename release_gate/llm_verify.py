"""LLM verification layer — an optional second opinion on high-salience findings.

This is the productized version of hand-checking each finding before you act on
it. For each qualifying static finding it sends *only that finding plus a small
code window* to a model you configure, and gets back
``confirmed | refuted | uncertain`` with a one-line reason.

Design invariants (non-negotiable):
  * OPT-IN. Nothing here runs unless the caller asks (`--verify`). The static
    audit never makes a network call.
  * BRING-YOUR-OWN MODEL. It talks to an OpenAI-compatible ``/chat/completions``
    endpoint you point it at — your OpenAI/Together/Groq key, OR a LOCAL model
    (Ollama / vLLM / llama.cpp) via a base-URL override. Point it at localhost
    and it stays fully air-gapped.
  * NEVER CALLS HOME. Requests go ONLY to your configured endpoint. release-gate
    servers are never contacted; there is no telemetry.
  * ADVISORY, NOT THE GATE. The deterministic static decision remains the CI
    exit code. A verdict annotates a finding; a non-deterministic model never
    decides your build's pass/fail.
  * DATA MINIMISATION. Only the finding + a bounded snippet leave the process,
    never the whole repo.

Config (env):
  RG_VERIFY_MODEL     required — model id (e.g. a hosted model, or an Ollama tag)
  RG_VERIFY_BASE_URL  default https://api.openai.com/v1 ; set to your local
                      endpoint (e.g. http://localhost:11434/v1) for a local model
  RG_VERIFY_API_KEY   API key (falls back to OPENAI_API_KEY). Not required when
                      BASE_URL is localhost / 127.0.0.1.
  RG_VERIFY_CORPUS    optional path to append verdicts to (JSONL) — the
                      calibration corpus. Defaults to .release-gate-verify.jsonl
"""

from __future__ import annotations

import json
import os
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class VerifyConfigError(RuntimeError):
    """Raised when --verify is requested but no model is configured."""


def load_config() -> Dict[str, str]:
    """Resolve the BYO-model config from the environment, or raise a clear error."""
    base_url = (os.environ.get("RG_VERIFY_BASE_URL")
                or "https://api.openai.com/v1").rstrip("/")
    model = os.environ.get("RG_VERIFY_MODEL", "").strip()
    api_key = (os.environ.get("RG_VERIFY_API_KEY")
               or os.environ.get("OPENAI_API_KEY") or "").strip()
    is_local = any(h in base_url for h in ("localhost", "127.0.0.1", "0.0.0.0"))
    if not model:
        raise VerifyConfigError(
            "release-gate --verify needs a model. Set RG_VERIFY_MODEL (and, for a "
            "hosted model, RG_VERIFY_API_KEY). For a LOCAL model, also set "
            "RG_VERIFY_BASE_URL, e.g.:\n"
            "  export RG_VERIFY_BASE_URL=http://localhost:11434/v1   # Ollama\n"
            "  export RG_VERIFY_MODEL=llama3.1\n"
            "Requests go only to that endpoint — never to release-gate.")
    if not api_key and not is_local:
        raise VerifyConfigError(
            f"No API key for {base_url}. Set RG_VERIFY_API_KEY (or OPENAI_API_KEY), "
            "or point RG_VERIFY_BASE_URL at a local model that needs none.")
    return {"base_url": base_url, "model": model, "api_key": api_key}


# ─────────────────────────── prompt construction ────────────────────────────

_SYSTEM_PROMPT = (
    "You are a security reviewer adjudicating a STATIC finding from an "
    "AI-agent code scanner. You are given one finding and a code window. Decide "
    "whether it is a REAL risk in a production deployment, or a false positive / "
    "overstatement. Judge on the evidence in the snippet, not on the pattern.\n\n"
    "Common false positives to catch:\n"
    "- pickle/marshal of the framework's OWN objects (internal serialization, "
    "round-trip of a class it defined) or over a LOCAL multiprocessing pipe — "
    "not external input.\n"
    "- an HTTP header NAME (e.g. \"X-Api-Key\") mistaken for a secret value.\n"
    "- placeholder / example / test values, and code under examples/ or tests/.\n"
    "- a sink whose input is HMAC-verified / signed before use.\n"
    "- design-intent sandboxed code execution in a code-writing agent (real, but "
    "expected; say 'confirmed' only if the sandbox/trust boundary is actually "
    "weak or model/user input reaches it unguarded).\n\n"
    "Confirm only when model or untrusted input can plausibly reach the sink as "
    "shown. If the snippet doesn't let you tell, say uncertain.\n\n"
    "Respond with STRICT JSON only, no prose:\n"
    '{"verdict": "confirmed" | "refuted" | "uncertain", "reason": "<one sentence>"}'
)


def _context_window(root: Path, rel: str, line: int,
                    before: int = 25, after: int = 12) -> str:
    """Return a numbered code window around the finding, or '' if unreadable."""
    try:
        text = (root / rel).read_text(errors="replace").splitlines()
    except OSError:
        return ""
    lo = max(0, line - 1 - before)
    hi = min(len(text), line + after)
    out = []
    for i in range(lo, hi):
        marker = ">>" if (i + 1) == line else "  "
        out.append(f"{marker}{i + 1:5d}| {text[i]}")
    return "\n".join(out)


def _build_messages(finding: Dict[str, Any], context: str) -> List[Dict[str, str]]:
    f = finding
    user = (
        f"FINDING\n"
        f"  title:       {f.get('title')}\n"
        f"  severity:    {f.get('severity')}  (static confidence "
        f"{f.get('confidence')}, basis {f.get('basis')})\n"
        f"  location:    {f.get('file')}:{f.get('line')}\n"
        f"  evidence:    {f.get('evidence') or '(none)'}\n"
        f"  scanner-say: {f.get('recommendation')}\n\n"
        f"CODE (>> marks the flagged line)\n{context or '(source unavailable)'}\n"
    )
    return [{"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": user}]


# ─────────────────────────── model call (OpenAI-compatible) ─────────────────

def _call_llm(config: Dict[str, str], messages: List[Dict[str, str]],
              timeout: int = 45) -> str:
    """POST to an OpenAI-compatible /chat/completions endpoint. Stdlib only."""
    body = json.dumps({
        "model": config["model"],
        "messages": messages,
        "temperature": 0,          # best-effort determinism
        "max_tokens": 300,
    }).encode()
    headers = {"Content-Type": "application/json", "User-Agent": "release-gate-verify"}
    if config.get("api_key"):
        headers["Authorization"] = f"Bearer {config['api_key']}"
    req = urllib.request.Request(config["base_url"] + "/chat/completions",
                                 data=body, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read())
    return data["choices"][0]["message"]["content"]


def _parse_verdict(text: str) -> Dict[str, str]:
    """Extract {verdict, reason} from the model's reply, tolerating stray prose."""
    verdict, reason = "uncertain", ""
    try:
        start, end = text.find("{"), text.rfind("}")
        if start != -1 and end != -1:
            obj = json.loads(text[start:end + 1])
            v = str(obj.get("verdict", "")).lower().strip()
            if v in ("confirmed", "refuted", "uncertain"):
                verdict = v
            reason = str(obj.get("reason", "")).strip()
    except (ValueError, TypeError):
        pass
    return {"verdict": verdict, "reason": reason}


# ─────────────────────────── orchestration ──────────────────────────────────

def verify_findings(findings: List[Dict[str, Any]], root: Path, *,
                    min_severity: str = "medium",
                    config: Optional[Dict[str, str]] = None,
                    call_fn: Optional[Callable] = None,
                    corpus_path: Optional[str] = None) -> Dict[str, Any]:
    """Attach a `verdict` to each qualifying finding (in place) and return a summary.

    Only findings at or above ``min_severity`` are verified — you don't spend a
    model call on 57 uncapped-call advisories. `call_fn` is injectable for tests.
    Each verdict is appended to the calibration corpus (JSONL).
    """
    cfg = config or load_config()
    call = call_fn or _call_llm
    cutoff = _SEV_RANK.get(min_severity, 2)
    corpus = corpus_path or os.environ.get("RG_VERIFY_CORPUS", ".release-gate-verify.jsonl")

    targets = [f for f in findings
               if _SEV_RANK.get(f.get("severity"), 9) <= cutoff]
    counts = {"confirmed": 0, "refuted": 0, "uncertain": 0, "error": 0}

    for f in targets:
        context = _context_window(root, f.get("file", ""), f.get("line", 0))
        try:
            reply = call(cfg, _build_messages(f, context))
            verdict = _parse_verdict(reply)
        except Exception as exc:  # never let a model hiccup crash the audit
            verdict = {"verdict": "error", "reason": f"verifier unavailable: {exc}"[:160]}
        f["verdict"] = verdict
        counts[verdict["verdict"]] = counts.get(verdict["verdict"], 0) + 1
        _append_corpus(corpus, f, context, cfg["model"])

    return {"verified": len(targets), "counts": counts,
            "model": cfg["model"], "corpus": corpus if targets else None}


def _append_corpus(path: str, finding: Dict[str, Any], context: str, model: str) -> None:
    """Append one labelled example to the calibration corpus (best-effort)."""
    try:
        row = {
            "file": finding.get("file"), "line": finding.get("line"),
            "title": finding.get("title"), "severity": finding.get("severity"),
            "basis": finding.get("basis"), "evidence": finding.get("evidence"),
            "verdict": finding.get("verdict"), "model": model,
            "context": context,
        }
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(row) + "\n")
    except OSError:
        pass

"""
release-gate GitHub App webhook handler.

Listens for pull_request events, runs release-gate audit on the repo,
then posts a Check Run (PROMOTE/HOLD/BLOCK) and a PR comment with the
full safeguard breakdown.

Required environment variables:
  GITHUB_APP_ID          — numeric app ID from your GitHub App settings
  GITHUB_APP_PRIVATE_KEY — RSA private key PEM (newlines as \\n or real newlines)
  GITHUB_WEBHOOK_SECRET  — webhook secret set in your GitHub App settings

Optional:
  GITHUB_APP_OPEN_PR     — set to "1" to auto-open a governance.yaml PR on HOLD/BLOCK
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import urllib.request
import urllib.error
from typing import Any, Dict, Optional

from fastapi import APIRouter, Header, HTTPException, Request

router = APIRouter()

APP_ID             = os.environ.get("GITHUB_APP_ID", "")
PRIVATE_KEY_RAW    = os.environ.get("GITHUB_APP_PRIVATE_KEY", "")
WEBHOOK_SECRET     = os.environ.get("GITHUB_WEBHOOK_SECRET", "")
AUTO_OPEN_PR       = os.environ.get("GITHUB_APP_OPEN_PR", "") == "1"


# ── JWT / token helpers ────────────────────────────────────────────────────

def _make_jwt() -> str:
    """Generate a short-lived JWT signed with the app's RSA private key."""
    import jwt as pyjwt
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    pem = PRIVATE_KEY_RAW.replace("\\n", "\n").encode()
    private_key = load_pem_private_key(pem, password=None)

    now = int(time.time())
    payload = {"iat": now - 60, "exp": now + 540, "iss": APP_ID}
    return pyjwt.encode(payload, private_key, algorithm="RS256")


def _installation_token(installation_id: int) -> str:
    """Exchange a JWT for a short-lived installation access token."""
    jwt_token = _make_jwt()
    req = urllib.request.Request(
        f"https://api.github.com/app/installations/{installation_id}/access_tokens",
        method="POST",
        headers={
            "Authorization": f"Bearer {jwt_token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "release-gate-app",
        },
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())["token"]


def installation_token_for_repo(owner: str, repo: str) -> Optional[str]:
    """Return an installation access token for owner/repo if the App is
    installed there, else None.

    Used to score private repos: the user installs release-gate-ai on the
    repo (granting read access), and we mint a short-lived token scoped to
    exactly that installation. Returns None if the App isn't configured or
    isn't installed on the repo, so callers can fall back to public access.
    """
    if not (APP_ID and PRIVATE_KEY_RAW):
        return None
    try:
        jwt_token = _make_jwt()
        req = urllib.request.Request(
            f"https://api.github.com/repos/{owner}/{repo}/installation",
            headers={
                "Authorization": f"Bearer {jwt_token}",
                "Accept": "application/vnd.github+json",
                "User-Agent": "release-gate-app",
            },
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            installation_id = json.loads(resp.read())["id"]
        return _installation_token(installation_id)
    except Exception:
        return None


# ── GitHub API helpers ─────────────────────────────────────────────────────

def _gh(method: str, path: str, token: str, body: Optional[Dict] = None) -> Dict:
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(
        f"https://api.github.com{path}",
        method=method,
        data=data,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "User-Agent": "release-gate-app",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read()) if resp.status != 204 else {}
    except urllib.error.HTTPError as e:
        body_text = e.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"GitHub API {method} {path} → {e.code}: {body_text}") from e


def _post_check_run(token: str, owner: str, repo: str, head_sha: str,
                    report: Dict) -> None:
    """Create a GitHub Check Run reflecting the audit result."""
    score    = report.get("score", 0)
    decision = report.get("decision", "BLOCK")

    conclusion = {
        "PROMOTE": "success",
        "HOLD":    "neutral",
        "BLOCK":   "failure",
    }.get(decision, "failure")

    title = f"release-gate: {score}/100 — {decision}"

    # Build summary table
    safeguards = report.get("safeguards", {})
    LABELS = {
        "governance_file": "Governance config",
        "eval_evidence":   "Eval evidence",
        "trace_policy":    "Trace / tool policy",
        "budget_ceiling":  "Budget / cost ceiling",
        "kill_switch":     "Kill switch / fallback",
        "team_owner":      "Team owner / on-call",
        "auth_rate_limit": "Auth & rate limiting",
    }
    rows = []
    for key, label in LABELS.items():
        val = safeguards.get(key, False)
        present = val if isinstance(val, bool) else val.get("present", False)
        rows.append(f"| {'✅' if present else '❌'} | {label} |")

    table = "| | Safeguard |\n|---|---|\n" + "\n".join(rows)

    badge_emoji = {"PROMOTE": "✅", "HOLD": "⚠️", "BLOCK": "🚫"}.get(decision, "❌")

    summary = (
        f"## {badge_emoji} release-gate audit: **{decision}** ({score}/100)\n\n"
        f"{table}\n\n"
        f"_Run `release-gate audit . --emit-config -o governance.yaml` locally to scaffold a config._"
    )

    _gh("POST", f"/repos/{owner}/{repo}/check-runs", token, {
        "name":       "release-gate",
        "head_sha":   head_sha,
        "status":     "completed",
        "conclusion": conclusion,
        "output": {
            "title":   title,
            "summary": summary,
        },
    })


def _post_pr_comment(token: str, owner: str, repo: str,
                     pr_number: int, report: Dict) -> None:
    """Post a detailed comment on the PR."""
    score    = report.get("score", 0)
    decision = report.get("decision", "BLOCK")
    frameworks = ", ".join(sorted(report.get("frameworks", {}).keys())) or "unknown"

    badge_emoji = {"PROMOTE": "✅", "HOLD": "⚠️", "BLOCK": "🚫"}.get(decision, "❌")
    badge_color = {"PROMOTE": "brightgreen", "HOLD": "yellow", "BLOCK": "red"}.get(decision, "lightgrey")
    badge_url   = (f"https://img.shields.io/badge/release--gate-"
                   f"{score}%2F100%20{decision}-{badge_color}")

    safeguards = report.get("safeguards", {})
    LABELS = {
        "governance_file": ("Governance config",    "Add `governance.yaml` — run `release-gate audit . --emit-config -o governance.yaml`"),
        "eval_evidence":   ("Eval evidence",         "Add `evals.yaml` with test cases"),
        "trace_policy":    ("Trace / tool policy",   "Add `trace_policy:` block in governance.yaml"),
        "budget_ceiling":  ("Budget / cost ceiling", "Set `action_budget.max_cost_usd` in governance.yaml"),
        "kill_switch":     ("Kill switch / fallback","Add `kill_switch:` block in governance.yaml"),
        "team_owner":      ("Team owner / on-call",  "Set `team_owner:` and `on_call:` in governance.yaml"),
        "auth_rate_limit": ("Auth & rate limiting",  "Ensure API gateway enforces auth + rate limits"),
    }

    rows = []
    missing = []
    for key, (label, fix) in LABELS.items():
        val = safeguards.get(key, False)
        present = val if isinstance(val, bool) else val.get("present", False)
        icon = "✅" if present else "❌"
        rows.append(f"| {icon} | {label} | {'—' if present else fix} |")
        if not present:
            missing.append(label)

    table = "| | Safeguard | Fix |\n|---|---|---|\n" + "\n".join(rows)

    next_step = ""
    if decision in ("HOLD", "BLOCK"):
        next_step = (
            "\n\n**Quick fix:** run this locally to scaffold a ready-to-commit config:\n"
            "```bash\npip install release-gate\n"
            f"release-gate audit . --emit-config -o governance.yaml\n```\n"
            "Then commit `governance.yaml` and re-run this check."
        )

    body = (
        f"## {badge_emoji} release-gate — {decision} ({score}/100)\n\n"
        f"![release-gate]({badge_url})\n\n"
        f"**Frameworks detected:** {frameworks}\n\n"
        f"{table}"
        f"{next_step}\n\n"
        f"<sub>Powered by [release-gate](https://github.com/VamsiSudhakaran1/release-gate)</sub>"
    )

    _gh("POST", f"/repos/{owner}/{repo}/issues/{pr_number}/comments", token,
        {"body": body})


def _open_governance_pr(token: str, owner: str, repo: str,
                        default_branch: str, report: Dict) -> None:
    """Open a PR adding a pre-filled governance.yaml if one doesn't exist."""
    import base64
    import sys
    import os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from release_gate.audit import emit_config

    config_text = emit_config(report)
    encoded     = base64.b64encode(config_text.encode()).decode()
    branch_name = "release-gate/add-governance-yaml"

    # Get base SHA
    ref_data = _gh("GET", f"/repos/{owner}/{repo}/git/ref/heads/{default_branch}", token)
    base_sha = ref_data["object"]["sha"]

    # Create branch (ignore if already exists)
    try:
        _gh("POST", f"/repos/{owner}/{repo}/git/refs", token, {
            "ref": f"refs/heads/{branch_name}",
            "sha": base_sha,
        })
    except RuntimeError:
        pass  # branch already exists

    # Create / update file
    try:
        existing = _gh("GET", f"/repos/{owner}/{repo}/contents/governance.yaml"
                       f"?ref={branch_name}", token)
        file_sha = existing.get("sha")
    except RuntimeError:
        file_sha = None

    payload: Dict[str, Any] = {
        "message": "chore: add governance.yaml (generated by release-gate)",
        "content": encoded,
        "branch":  branch_name,
    }
    if file_sha:
        payload["sha"] = file_sha

    _gh("PUT", f"/repos/{owner}/{repo}/contents/governance.yaml", token, payload)

    # Open PR
    score    = report.get("score", 0)
    decision = report.get("decision", "BLOCK")
    try:
        _gh("POST", f"/repos/{owner}/{repo}/pulls", token, {
            "title": f"chore: add governance.yaml (release-gate score {score}/100 {decision})",
            "body":  (
                "This PR adds a `governance.yaml` scaffolded by "
                "[release-gate](https://github.com/VamsiSudhakaran1/release-gate).\n\n"
                "Fill in the `# TODO:` lines and commit — your next release-gate "
                "check will reflect the improvements.\n\n"
                f"Current score: **{score}/100 ({decision})**"
            ),
            "head": branch_name,
            "base": default_branch,
        })
    except RuntimeError:
        pass  # PR already open


# ── Webhook signature verification ────────────────────────────────────────

def _verify_signature(body: bytes, sig_header: str) -> bool:
    if not WEBHOOK_SECRET or not sig_header:
        return not WEBHOOK_SECRET  # if no secret configured, skip check
    expected = "sha256=" + hmac.new(
        WEBHOOK_SECRET.encode(), body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, sig_header)


# ── Webhook endpoint ───────────────────────────────────────────────────────

@router.post("/api/github/webhook")
async def github_webhook(
    request: Request,
    x_github_event:    Optional[str] = Header(default=None),
    x_hub_signature_256: Optional[str] = Header(default=None),
):
    body = await request.body()

    if not _verify_signature(body, x_hub_signature_256 or ""):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    event   = x_github_event or ""
    payload = json.loads(body)
    action  = payload.get("action", "")

    # ── Installation acknowledged ──────────────────────────────────────────
    if event == "installation":
        return {"ok": True, "event": "installation", "action": action}

    # ── Pull request: run audit ────────────────────────────────────────────
    if event == "pull_request" and action in ("opened", "synchronize", "reopened"):
        pr          = payload["pull_request"]
        repo_data   = payload["repository"]
        installation_id = payload["installation"]["id"]

        owner          = repo_data["owner"]["login"]
        repo_name      = repo_data["name"]
        head_sha       = pr["head"]["sha"]
        pr_number      = pr["number"]
        default_branch = repo_data.get("default_branch", "main")
        repo_url       = repo_data["html_url"]

        try:
            token = _installation_token(installation_id)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Token error: {exc}")

        # Run audit via GitHub API (no git clone needed)
        try:
            import sys, os
            sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
            from release_gate.audit import _github_api_audit, badge_url, badge_markdown
            report = _github_api_audit(repo_url)
            report["badge_url"]      = badge_url(report)
            report["badge_markdown"] = badge_markdown(report)
        except Exception as exc:
            # Post a neutral check run so the PR isn't blocked by our error
            _gh("POST", f"/repos/{owner}/{repo_name}/check-runs", token, {
                "name":       "release-gate",
                "head_sha":   head_sha,
                "status":     "completed",
                "conclusion": "neutral",
                "output": {
                    "title":   "release-gate: audit error",
                    "summary": f"Could not complete audit: {exc}",
                },
            })
            return {"ok": False, "error": str(exc)}

        # Post check run + PR comment
        _post_check_run(token, owner, repo_name, head_sha, report)
        _post_pr_comment(token, owner, repo_name, pr_number, report)

        # Optionally open a governance.yaml PR on HOLD/BLOCK
        if AUTO_OPEN_PR and report.get("decision") in ("HOLD", "BLOCK"):
            try:
                _open_governance_pr(token, owner, repo_name, default_branch, report)
            except Exception:
                pass  # non-fatal

        return {
            "ok":       True,
            "score":    report.get("score"),
            "decision": report.get("decision"),
        }

    return {"ok": True, "event": event, "action": action, "skipped": True}

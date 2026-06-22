"""release-gate SaaS API — FastAPI backend."""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse
from pydantic import BaseModel

# Ensure release_gate package is importable
sys.path.insert(0, str(Path(__file__).parent.parent))

from release_gate_api.auth import (
    create_access_token, decode_token, hash_password, verify_password,
)
from release_gate_api.db import (
    create_user, get_run, get_runs_for_user, get_repo_history,
    get_user_by_email, get_user_by_id, get_user_by_token,
    init_db, save_run, create_api_token,
    increment_usage, get_usage, get_dashboard_stats, get_findings_summary,
)

app = FastAPI(title="release-gate API", version="0.7.0")

# ── Plan limits ────────────────────────────────────────────────────────────
PLAN_LIMITS = {"free": 10, "pro": 999999, "enterprise": 999999}

# Anonymous IP-based rate limiting (in-memory, resets hourly)
import time as _time
_anon_counters: Dict[str, Dict] = {}  # ip -> {"count": int, "window_start": float}
_ANON_LIMIT = 3
_ANON_WINDOW = 3600  # 1 hour in seconds

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# GitHub App webhook router
from release_gate_api.github_app import router as github_router
app.include_router(github_router)


@app.on_event("startup")
def startup():
    try:
        init_db()
    except Exception as exc:  # don't let a DB hiccup crash the whole function
        print(f"[startup] init_db failed: {exc}", file=sys.stderr)


# Ensure the schema exists even if the startup hook didn't run (serverless cold start)
def _ensure_db():
    try:
        init_db()
    except Exception as exc:
        print(f"[ensure_db] init_db failed: {exc}", file=sys.stderr)


# ── Auth helpers ───────────────────────────────────────────────────────────

def _current_user(authorization: Optional[str]) -> Optional[Dict]:
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() == "bearer":
        payload = decode_token(token)
        if payload:
            return {"id": payload["sub"], "email": payload["email"], "plan": payload["plan"]}
    if token.startswith("rg_"):
        return get_user_by_token(token)
    return None


def _require_user(authorization: Optional[str]) -> Dict:
    user = _current_user(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user


def _require_plan(user: Dict, plan: str):
    order = {"free": 0, "pro": 1, "enterprise": 2}
    if order.get(user.get("plan", "free"), 0) < order.get(plan, 0):
        raise HTTPException(status_code=403, detail=f"{plan} plan required")


# ── Audit ─────────────────────────────────────────────────────────────────

FREE_SAFEGUARD_LIMIT = 2  # non-authenticated users see at most this many safeguard details


class AuditRequest(BaseModel):
    url: str


def _parse_owner_repo(url: str):
    parts = (
        url.rstrip("/").replace(".git", "")
        .replace("https://github.com/", "").replace("http://github.com/", "")
        .split("/")
    )
    return (parts[0], parts[1]) if len(parts) >= 2 else (None, None)


def _run_audit(url: str) -> Dict[str, Any]:
    """Run release-gate audit and return the raw report dict.

    For private repos, retry with a GitHub App installation token if the
    release-gate-ai App is installed on the target repo.
    """
    from release_gate.audit import (
        _is_github_url, clone_and_audit, build_report,
        badge_url, badge_markdown, PrivateRepoError,
    )
    if _is_github_url(url):
        try:
            report = clone_and_audit(url)
        except PrivateRepoError:
            # Repo is private (or doesn't exist). Try an App installation token.
            owner, repo = _parse_owner_repo(url)
            token = None
            app_error: Optional[str] = None
            if owner and repo:
                from release_gate_api.github_app import installation_token_for_repo
                try:
                    token = installation_token_for_repo(owner, repo)
                except Exception as exc:
                    app_error = str(exc)
            if not token:
                msg = (
                    "This repo is private or not found. Install the "
                    "release-gate-ai GitHub App on it to enable scanning."
                )
                if app_error:
                    msg = f"GitHub App error: {app_error}"
                raise HTTPException(
                    status_code=403,
                    detail={
                        "private_repo": True,
                        "install_url": "https://github.com/apps/release-gate-ai/installations/new",
                        "message": msg,
                    },
                )
            report = clone_and_audit(url, token=token)
    else:
        from pathlib import Path
        report = build_report(Path(url))
    report["badge_url"] = badge_url(report)
    report["badge_markdown"] = badge_markdown(report)
    return report


def _redact_for_free(report: Dict) -> Dict:
    """Strip detail for unauthenticated / free-tier users."""
    safeguards = report.get("safeguards", {})
    keys = list(safeguards.keys())
    visible = set(keys[:FREE_SAFEGUARD_LIMIT])
    redacted = {}
    for k, v in safeguards.items():
        if k in visible:
            redacted[k] = v
        else:
            present = v if isinstance(v, bool) else v.get("present", False)
            redacted[k] = {"present": present, "redacted": True}
    findings = report.get("code_findings", []) or []
    return {
        **report,
        "safeguards": redacted,
        "checks": [],           # hide detailed check results
        "next_steps": [],
        "code_findings": [],    # lock the code-analysis findings for anon users
        "_code_findings_count": len(findings),
        "_redacted": True,
        # Lock detected model for anon — shown as a hook to sign up
        "detected_model": None,
        "_detected_model_locked": True,
        "_upgrade_message": "Sign up free to see all safeguard details, emit a governance.yaml, and track history.",
    }


@app.post("/api/audit")
async def audit_public(body: AuditRequest, request: Request, authorization: Optional[str] = Header(default=None)):
    """
    Run audit on any public GitHub repo or local path.
    - Unauthenticated: partial results, IP-limited 3/hour
    - Starter (free): full results, 10/month limit
    - Pro/Enterprise: unlimited
    """
    url = body.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="url is required")

    user = _current_user(authorization)

    if user:
        plan = user.get("plan", "free")
        limit = PLAN_LIMITS.get(plan, PLAN_LIMITS["free"])
        if limit < 999999:
            current_usage = get_usage(user["id"])
            if current_usage >= limit:
                return JSONResponse(
                    status_code=429,
                    content={
                        "limit_reached": True,
                        "upgrade_url": "/pricing",
                        "detail": f"Monthly scan limit of {limit} reached. Upgrade for unlimited scans.",
                    },
                )
    else:
        # Anonymous: IP-based rate limiting
        ip = request.client.host if request.client else "unknown"
        now = _time.time()
        entry = _anon_counters.get(ip)
        if entry and (now - entry["window_start"]) < _ANON_WINDOW:
            if entry["count"] >= _ANON_LIMIT:
                return JSONResponse(
                    status_code=429,
                    content={
                        "limit_reached": True,
                        "upgrade_url": "/pricing",
                        "detail": f"Anonymous scan limit of {_ANON_LIMIT}/hour reached. Sign up free for more.",
                    },
                )
            entry["count"] += 1
        else:
            _anon_counters[ip] = {"count": 1, "window_start": now}

    try:
        report = _run_audit(url)
    except HTTPException:
        raise  # already a structured error (e.g. private-repo prompt)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    run_id = None

    if user:
        increment_usage(user["id"])
        run_id = save_run(url, report, user_id=user["id"])
        return {"run_id": run_id, "report": report, "plan": user["plan"]}
    else:
        return {"report": _redact_for_free(report), "plan": "anonymous"}


@app.get("/api/runs/{run_id}")
async def get_run_detail(run_id: str, authorization: Optional[str] = Header(default=None)):
    user = _require_user(authorization)
    run = get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    if run["user_id"] != user["id"]:
        raise HTTPException(status_code=403, detail="Not your run")
    return run


# ── Auth ──────────────────────────────────────────────────────────────────

class SignupRequest(BaseModel):
    email: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


@app.post("/api/auth/signup")
async def signup(body: SignupRequest):
    if len(body.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    existing = get_user_by_email(body.email)
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")
    hashed = hash_password(body.password)
    user = create_user(body.email, hashed)
    token = create_access_token(user["id"], user["email"], user["plan"])
    return {"token": token, "user": {"email": user["email"], "plan": user["plan"]}}


@app.post("/api/auth/login")
async def login(body: LoginRequest):
    user = get_user_by_email(body.email)
    if not user or not verify_password(body.password, user["hashed_pw"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = create_access_token(user["id"], user["email"], user["plan"])
    return {"token": token, "user": {"email": user["email"], "plan": user["plan"]}}


@app.get("/api/auth/me")
async def me(authorization: Optional[str] = Header(default=None)):
    user = _require_user(authorization)
    db_user = get_user_by_id(user["id"])
    if not db_user:
        raise HTTPException(status_code=404)
    return {"email": db_user["email"], "plan": db_user["plan"], "id": db_user["id"]}


# ── Dashboard ─────────────────────────────────────────────────────────────

@app.get("/api/dashboard")
async def dashboard(authorization: Optional[str] = Header(default=None)):
    user = _require_user(authorization)
    plan = user.get("plan", "free")
    history_limit = 5 if plan == "free" else 50 if plan == "pro" else 1000
    runs = get_runs_for_user(user["id"], limit=history_limit)
    stats = get_dashboard_stats(user["id"])

    # Aggregate: unique repos, decision distribution
    repos = {}
    for r in runs:
        repo = r["repo_url"]
        if repo not in repos:
            repos[repo] = {"repo_url": repo, "runs": 0, "latest_score": None,
                           "latest_decision": None, "latest_at": None}
        repos[repo]["runs"] += 1
        repos[repo]["latest_score"] = r["score"]
        repos[repo]["latest_decision"] = r["decision"]
        repos[repo]["latest_at"] = r["created_at"]

    decisions = {}
    for r in runs:
        d = r["decision"] or "UNKNOWN"
        decisions[d] = decisions.get(d, 0) + 1

    return {
        **stats,
        "repos": list(repos.values()),
        "decision_distribution": decisions,
        "findings_summary": get_findings_summary(user["id"]),
        "recent_runs": runs[:10],
    }


@app.get("/api/dashboard/repo")
async def repo_history(repo_url: str, authorization: Optional[str] = Header(default=None)):
    user = _require_user(authorization)
    history = get_repo_history(user["id"], repo_url)
    return {"repo_url": repo_url, "history": history}


@app.get("/api/dashboard/repo-history")
async def repo_history_alias(repo_url: str, authorization: Optional[str] = Header(default=None)):
    """Returns all runs for a repo with score, decision, version, created_at — for score trend sparkline."""
    user = _require_user(authorization)
    history = get_repo_history(user["id"], repo_url)
    return {"repo_url": repo_url, "history": history}


@app.get("/api/run/{run_id}")
async def run_detail(run_id: str, authorization: Optional[str] = Header(default=None)):
    """Full stored report for a single run. Owner-only — this is the detailed
    vulnerability report behind each dashboard row."""
    user = _require_user(authorization)
    run = get_run(run_id)
    if not run or run.get("user_id") != user["id"]:
        raise HTTPException(status_code=404, detail="Run not found")
    report = run.get("report") or {}
    return {
        "id": run.get("id"),
        "repo_url": run.get("repo_url"),
        "score": run.get("score"),
        "decision": run.get("decision"),
        "created_at": run.get("created_at"),
        "report": report,
    }


# ── API tokens ─────────────────────────────────────────────────────────────

@app.post("/api/tokens")
async def create_token(authorization: Optional[str] = Header(default=None)):
    user = _require_user(authorization)
    _require_plan(user, "pro")
    db_user = get_user_by_id(user["id"])
    token = create_api_token(db_user["id"])
    return {"token": token}


# ── Health ─────────────────────────────────────────────────────────────────

@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "0.7.0"}


@app.get("/api/debug/github-app")
async def debug_github_app_endpoint(owner: str, repo: str):
    """Diagnostic: test GitHub App configuration and installation for owner/repo."""
    from release_gate_api.github_app import debug_github_app
    return debug_github_app(owner, repo)


class FixRequest(BaseModel):
    url: str


@app.post("/api/fix")
async def fix_repo(body: FixRequest, authorization: Optional[str] = Header(default=None)):
    """Open a PR in the user's repo with auto-generated governance files.

    Security model:
    - Caller must be authenticated (JWT).
    - Getting an installation token requires the GitHub App to be installed on
      the target repo by someone with admin rights — this is the authorization
      gate. A user cannot obtain a token for a repo they don't control.
    - We never write to a repo without a valid installation token.
    """
    user = _require_user(authorization)

    url = body.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="url is required")

    from release_gate.audit import _is_github_url
    if not _is_github_url(url):
        raise HTTPException(status_code=400, detail="Only GitHub repos are supported for auto-fix")

    owner_name, repo_name = _parse_owner_repo(url)
    if not owner_name or not repo_name:
        raise HTTPException(status_code=400, detail="Could not parse owner/repo from URL")

    # Authorization gate: installation token proves the GitHub App is installed
    # on this specific repo by someone with admin access.
    from release_gate_api.github_app import installation_token_for_repo, create_fix_pr
    try:
        install_token = installation_token_for_repo(owner_name, repo_name)
    except Exception as exc:
        raise HTTPException(
            status_code=403,
            detail={
                "private_repo": True,
                "install_url": "https://github.com/apps/release-gate-ai/installations/new",
                "message": (
                    f"Install the release-gate-ai GitHub App on {owner_name}/{repo_name} "
                    f"to enable auto-fix. Error: {exc}"
                ),
            },
        )
    if not install_token:
        raise HTTPException(
            status_code=403,
            detail={
                "private_repo": True,
                "install_url": "https://github.com/apps/release-gate-ai/installations/new",
                "message": (
                    f"Install the release-gate-ai GitHub App on {owner_name}/{repo_name} "
                    "to enable auto-fix."
                ),
            },
        )

    # Run a fresh audit (using the installation token so private repos work)
    try:
        report = _run_audit(url)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    # Create the fix PR
    try:
        pr_url = create_fix_pr(owner_name, repo_name, report, install_token)
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to create PR: {exc}")

    # Record the scan
    increment_usage(user["id"])
    save_run(url, report, user_id=user["id"])

    return {"pr_url": pr_url, "report": report}


# ── Static frontend ──────────────────────────────────────────────────────────
# This FastAPI app is the single Vercel entrypoint, so it must also serve the
# site. The HTML is embedded as a Python module (release_gate_api/_frontend.py)
# so it bundles with the serverless function — files under public/ are not
# traced/bundled with a pyproject entrypoint. Local dev reads the live file so
# edits show up without regenerating; production falls back to the embedded copy.

_PUBLIC_DIR = Path(__file__).resolve().parent.parent / "public"
_INDEX_HTML = _PUBLIC_DIR / "index.html"


def _index_html() -> str:
    try:
        if _INDEX_HTML.exists():
            return _INDEX_HTML.read_text(encoding="utf-8")
    except Exception:
        pass
    from release_gate_api._frontend import INDEX_HTML
    return INDEX_HTML


@app.get("/")
async def _serve_index():
    return HTMLResponse(_index_html())


@app.get("/{full_path:path}")
async def _serve_spa(full_path: str):
    # Never let the SPA fallback swallow API routes
    if full_path.startswith("api/"):
        raise HTTPException(status_code=404, detail="Not found")
    candidate = (_PUBLIC_DIR / full_path).resolve()
    # Serve an existing static asset if it's safely inside public/ (local dev)
    if candidate.is_file() and str(candidate).startswith(str(_PUBLIC_DIR)):
        return FileResponse(str(candidate))
    return HTMLResponse(_index_html())


# Initialise the DB schema at import time. Vercel's ASGI bridge does not always
# fire FastAPI startup/lifespan events, so relying on the startup hook alone
# leaves tables missing and crashes the first request.
_ensure_db()

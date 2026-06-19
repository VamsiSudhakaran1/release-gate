"""release-gate SaaS API — FastAPI backend."""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr

# Ensure release_gate package is importable
sys.path.insert(0, str(Path(__file__).parent.parent))

from api.auth import (
    create_access_token, decode_token, hash_password, verify_password,
)
from api.db import (
    create_user, get_run, get_runs_for_user, get_repo_history,
    get_user_by_email, get_user_by_id, get_user_by_token,
    init_db, save_run, create_api_token,
)

app = FastAPI(title="release-gate API", version="0.7.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# GitHub App webhook router
from api.github_app import router as github_router
app.include_router(github_router)


@app.on_event("startup")
def startup():
    init_db()


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


def _run_audit(url: str) -> Dict[str, Any]:
    """Run release-gate audit and return the raw report dict."""
    from release_gate.audit import (
        _is_github_url, clone_and_audit, build_report,
        badge_url, badge_markdown,
    )
    if _is_github_url(url):
        report = clone_and_audit(url)
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
    return {
        **report,
        "safeguards": redacted,
        "checks": [],           # hide detailed check results
        "next_steps": [],
        "_redacted": True,
        "_upgrade_message": "Sign up free to see all safeguard details, emit a governance.yaml, and track history.",
    }


@app.post("/api/audit")
async def audit_public(body: AuditRequest, authorization: Optional[str] = Header(default=None)):
    """
    Run audit on any public GitHub repo or local path.
    - Unauthenticated: partial results (score + decision + 2 safeguards)
    - Authenticated (any plan): full results + stored in history
    """
    url = body.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="url is required")

    try:
        report = _run_audit(url)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    user = _current_user(authorization)
    run_id = None

    if user:
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
    runs = get_runs_for_user(user["id"])

    # Aggregate: unique repos, avg score, decision distribution
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
        "total_runs": len(runs),
        "repos": list(repos.values()),
        "decision_distribution": decisions,
        "recent_runs": runs[:10],
    }


@app.get("/api/dashboard/repo")
async def repo_history(repo_url: str, authorization: Optional[str] = Header(default=None)):
    user = _require_user(authorization)
    history = get_repo_history(user["id"], repo_url)
    return {"repo_url": repo_url, "history": history}


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

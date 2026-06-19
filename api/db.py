"""SQLite database layer for release-gate SaaS."""
from __future__ import annotations

import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

DB_PATH = os.environ.get("RG_DB_PATH", "/tmp/release_gate.db")


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def get_db():
    conn = _conn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with get_db() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id          TEXT PRIMARY KEY,
            email       TEXT UNIQUE NOT NULL,
            hashed_pw   TEXT NOT NULL,
            plan        TEXT NOT NULL DEFAULT 'free',
            created_at  TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS runs (
            id          TEXT PRIMARY KEY,
            user_id     TEXT,
            repo_url    TEXT NOT NULL,
            score       INTEGER,
            decision    TEXT,
            frameworks  TEXT,
            report_json TEXT,
            created_at  TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS api_tokens (
            token       TEXT PRIMARY KEY,
            user_id     TEXT NOT NULL,
            label       TEXT,
            created_at  TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE INDEX IF NOT EXISTS idx_runs_user ON runs(user_id);
        CREATE INDEX IF NOT EXISTS idx_runs_repo ON runs(repo_url);
        """)


# ── Users ──────────────────────────────────────────────────────────────────

def create_user(email: str, hashed_pw: str) -> Dict[str, Any]:
    uid = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        db.execute(
            "INSERT INTO users (id, email, hashed_pw, plan, created_at) VALUES (?,?,?,?,?)",
            (uid, email.lower().strip(), hashed_pw, "free", now),
        )
    return {"id": uid, "email": email, "plan": "free"}


def get_user_by_email(email: str) -> Optional[Dict]:
    with get_db() as db:
        row = db.execute("SELECT * FROM users WHERE email=?", (email.lower().strip(),)).fetchone()
    return dict(row) if row else None


def get_user_by_id(uid: str) -> Optional[Dict]:
    with get_db() as db:
        row = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    return dict(row) if row else None


# ── Runs ───────────────────────────────────────────────────────────────────

def save_run(repo_url: str, report: Dict, user_id: Optional[str] = None) -> str:
    import json
    rid = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    frameworks = ", ".join(sorted(report.get("frameworks", {}).keys()))
    with get_db() as db:
        db.execute(
            "INSERT INTO runs (id, user_id, repo_url, score, decision, frameworks, report_json, created_at) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (rid, user_id, repo_url,
             report.get("score"), report.get("decision"),
             frameworks, json.dumps(report), now),
        )
    return rid


def get_runs_for_user(user_id: str, limit: int = 50) -> List[Dict]:
    with get_db() as db:
        rows = db.execute(
            "SELECT id, repo_url, score, decision, frameworks, created_at "
            "FROM runs WHERE user_id=? ORDER BY created_at DESC LIMIT ?",
            (user_id, limit),
        ).fetchall()
    return [dict(r) for r in rows]


def get_run(run_id: str) -> Optional[Dict]:
    import json
    with get_db() as db:
        row = db.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
    if not row:
        return None
    d = dict(row)
    d["report"] = json.loads(d["report_json"]) if d["report_json"] else {}
    return d


def get_repo_history(user_id: str, repo_url: str) -> List[Dict]:
    with get_db() as db:
        rows = db.execute(
            "SELECT id, score, decision, created_at FROM runs "
            "WHERE user_id=? AND repo_url=? ORDER BY created_at ASC",
            (user_id, repo_url),
        ).fetchall()
    return [dict(r) for r in rows]


# ── API tokens ─────────────────────────────────────────────────────────────

def create_api_token(user_id: str, label: str = "") -> str:
    token = "rg_" + uuid.uuid4().hex
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as db:
        db.execute(
            "INSERT INTO api_tokens (token, user_id, label, created_at) VALUES (?,?,?,?)",
            (token, user_id, label, now),
        )
    return token


def get_user_by_token(token: str) -> Optional[Dict]:
    with get_db() as db:
        row = db.execute(
            "SELECT u.* FROM users u JOIN api_tokens t ON t.user_id=u.id WHERE t.token=?",
            (token,),
        ).fetchone()
    return dict(row) if row else None

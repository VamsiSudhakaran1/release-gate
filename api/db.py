"""Database layer — Postgres (Neon) in production, SQLite fallback for local dev."""
from __future__ import annotations

import os
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

DATABASE_URL = os.environ.get("DATABASE_URL", "")
_USE_POSTGRES = bool(DATABASE_URL)


# ── Connection ─────────────────────────────────────────────────────────────

@contextmanager
def get_db():
    if _USE_POSTGRES:
        import psycopg2
        import psycopg2.extras
        conn = psycopg2.connect(DATABASE_URL)
        conn.autocommit = False
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    else:
        import sqlite3
        db_path = os.environ.get("RG_DB_PATH", "/tmp/release_gate.db")
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


def _row_to_dict(row) -> Dict:
    """Works for both psycopg2 RealDictRow and sqlite3.Row."""
    if row is None:
        return None
    if hasattr(row, '_asdict'):
        return row._asdict()
    if hasattr(row, 'keys'):
        return dict(row)
    return dict(row)


def _ph() -> str:
    """Placeholder: %s for Postgres, ? for SQLite."""
    return "%s" if _USE_POSTGRES else "?"


# ── Schema ─────────────────────────────────────────────────────────────────

def init_db():
    ph = _ph()
    with get_db() as db:
        cur = db.cursor()
        if _USE_POSTGRES:
            cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id          TEXT PRIMARY KEY,
                email       TEXT UNIQUE NOT NULL,
                hashed_pw   TEXT NOT NULL,
                plan        TEXT NOT NULL DEFAULT 'free',
                created_at  TEXT NOT NULL
            )""")
            cur.execute("""
            CREATE TABLE IF NOT EXISTS runs (
                id          TEXT PRIMARY KEY,
                user_id     TEXT,
                repo_url    TEXT NOT NULL,
                score       INTEGER,
                decision    TEXT,
                frameworks  TEXT,
                report_json TEXT,
                created_at  TEXT NOT NULL
            )""")
            cur.execute("""
            CREATE TABLE IF NOT EXISTS api_tokens (
                token       TEXT PRIMARY KEY,
                user_id     TEXT NOT NULL,
                label       TEXT,
                created_at  TEXT NOT NULL
            )""")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_runs_user ON runs(user_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_runs_repo ON runs(repo_url)")
        else:
            cur.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL,
                hashed_pw TEXT NOT NULL, plan TEXT NOT NULL DEFAULT 'free',
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS runs (
                id TEXT PRIMARY KEY, user_id TEXT, repo_url TEXT NOT NULL,
                score INTEGER, decision TEXT, frameworks TEXT,
                report_json TEXT, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS api_tokens (
                token TEXT PRIMARY KEY, user_id TEXT NOT NULL,
                label TEXT, created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_runs_user ON runs(user_id);
            CREATE INDEX IF NOT EXISTS idx_runs_repo ON runs(repo_url);
            """)


# ── Users ──────────────────────────────────────────────────────────────────

def create_user(email: str, hashed_pw: str) -> Dict[str, Any]:
    uid = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    ph = _ph()
    with get_db() as db:
        cur = db.cursor()
        cur.execute(
            f"INSERT INTO users (id, email, hashed_pw, plan, created_at) VALUES ({ph},{ph},{ph},{ph},{ph})",
            (uid, email.lower().strip(), hashed_pw, "free", now),
        )
    return {"id": uid, "email": email, "plan": "free"}


def get_user_by_email(email: str) -> Optional[Dict]:
    ph = _ph()
    with get_db() as db:
        cur = db.cursor()
        if _USE_POSTGRES:
            import psycopg2.extras
            cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(f"SELECT * FROM users WHERE email={ph}", (email.lower().strip(),))
        row = cur.fetchone()
    return _row_to_dict(row) if row else None


def get_user_by_id(uid: str) -> Optional[Dict]:
    ph = _ph()
    with get_db() as db:
        cur = db.cursor()
        if _USE_POSTGRES:
            import psycopg2.extras
            cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(f"SELECT * FROM users WHERE id={ph}", (uid,))
        row = cur.fetchone()
    return _row_to_dict(row) if row else None


# ── Runs ───────────────────────────────────────────────────────────────────

def save_run(repo_url: str, report: Dict, user_id: Optional[str] = None) -> str:
    import json
    rid = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    frameworks = ", ".join(sorted(report.get("frameworks", {}).keys()))
    ph = _ph()
    with get_db() as db:
        cur = db.cursor()
        cur.execute(
            f"INSERT INTO runs (id, user_id, repo_url, score, decision, frameworks, report_json, created_at) "
            f"VALUES ({ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph})",
            (rid, user_id, repo_url, report.get("score"), report.get("decision"),
             frameworks, json.dumps(report), now),
        )
    return rid


def get_runs_for_user(user_id: str, limit: int = 50) -> List[Dict]:
    ph = _ph()
    with get_db() as db:
        cur = db.cursor()
        if _USE_POSTGRES:
            import psycopg2.extras
            cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(
            f"SELECT id, repo_url, score, decision, frameworks, created_at "
            f"FROM runs WHERE user_id={ph} ORDER BY created_at DESC LIMIT {ph}",
            (user_id, limit),
        )
        rows = cur.fetchall()
    return [_row_to_dict(r) for r in rows]


def get_run(run_id: str) -> Optional[Dict]:
    import json
    ph = _ph()
    with get_db() as db:
        cur = db.cursor()
        if _USE_POSTGRES:
            import psycopg2.extras
            cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(f"SELECT * FROM runs WHERE id={ph}", (run_id,))
        row = cur.fetchone()
    if not row:
        return None
    d = _row_to_dict(row)
    d["report"] = json.loads(d["report_json"]) if d.get("report_json") else {}
    return d


def get_repo_history(user_id: str, repo_url: str) -> List[Dict]:
    ph = _ph()
    with get_db() as db:
        cur = db.cursor()
        if _USE_POSTGRES:
            import psycopg2.extras
            cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(
            f"SELECT id, score, decision, created_at FROM runs "
            f"WHERE user_id={ph} AND repo_url={ph} ORDER BY created_at ASC",
            (user_id, repo_url),
        )
        rows = cur.fetchall()
    return [_row_to_dict(r) for r in rows]


# ── API tokens ─────────────────────────────────────────────────────────────

def create_api_token(user_id: str, label: str = "") -> str:
    token = "rg_" + uuid.uuid4().hex
    now = datetime.now(timezone.utc).isoformat()
    ph = _ph()
    with get_db() as db:
        cur = db.cursor()
        cur.execute(
            f"INSERT INTO api_tokens (token, user_id, label, created_at) VALUES ({ph},{ph},{ph},{ph})",
            (token, user_id, label, now),
        )
    return token


def get_user_by_token(token: str) -> Optional[Dict]:
    ph = _ph()
    with get_db() as db:
        cur = db.cursor()
        if _USE_POSTGRES:
            import psycopg2.extras
            cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(
            f"SELECT u.* FROM users u JOIN api_tokens t ON t.user_id=u.id WHERE t.token={ph}",
            (token,),
        )
        row = cur.fetchone()
    return _row_to_dict(row) if row else None

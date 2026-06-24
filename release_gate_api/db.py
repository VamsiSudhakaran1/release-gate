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
            cur.execute("""
            CREATE TABLE IF NOT EXISTS usage (
                user_id     TEXT NOT NULL,
                month       TEXT NOT NULL,
                scan_count  INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (user_id, month)
            )""")
            cur.execute("ALTER TABLE runs ADD COLUMN IF NOT EXISTS version TEXT")
            cur.execute("ALTER TABLE runs ADD COLUMN IF NOT EXISTS prev_score INTEGER")
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password INTEGER NOT NULL DEFAULT 0")
            cur.execute("""
            CREATE TABLE IF NOT EXISTS password_resets (
                token_hash  TEXT PRIMARY KEY,
                user_id     TEXT NOT NULL,
                expires_at  TEXT NOT NULL,
                used        INTEGER NOT NULL DEFAULT 0,
                created_at  TEXT NOT NULL
            )""")
            cur.execute("""
            CREATE TABLE IF NOT EXISTS verifications (
                id              TEXT PRIMARY KEY,
                user_id         TEXT NOT NULL,
                loop_id         TEXT,
                iteration       INTEGER NOT NULL,
                decision        TEXT NOT NULL,
                cost_so_far     REAL,
                cost_remaining  REAL,
                violations_json TEXT,
                warnings_json   TEXT,
                checks_json     TEXT,
                created_at      TEXT NOT NULL
            )""")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_verif_user   ON verifications(user_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_verif_loop   ON verifications(loop_id)")
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
            CREATE TABLE IF NOT EXISTS usage (
                user_id TEXT NOT NULL,
                month TEXT NOT NULL,
                scan_count INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (user_id, month)
            );
            CREATE INDEX IF NOT EXISTS idx_runs_user ON runs(user_id);
            CREATE INDEX IF NOT EXISTS idx_runs_repo ON runs(repo_url);
            """)
            cur.executescript("""
            CREATE TABLE IF NOT EXISTS password_resets (
                token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL,
                expires_at TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS verifications (
                id              TEXT PRIMARY KEY,
                user_id         TEXT NOT NULL,
                loop_id         TEXT,
                iteration       INTEGER NOT NULL,
                decision        TEXT NOT NULL,
                cost_so_far     REAL,
                cost_remaining  REAL,
                violations_json TEXT,
                warnings_json   TEXT,
                checks_json     TEXT,
                created_at      TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_verif_user ON verifications(user_id);
            CREATE INDEX IF NOT EXISTS idx_verif_loop ON verifications(loop_id);
            """)
            # SQLite: add columns if they don't exist yet (ignore errors if already present)
            for col_sql in [
                "ALTER TABLE runs ADD COLUMN version TEXT",
                "ALTER TABLE runs ADD COLUMN prev_score INTEGER",
                "ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0",
            ]:
                try:
                    cur.execute(col_sql)
                    db.commit()
                except Exception:
                    pass


# ── Users ──────────────────────────────────────────────────────────────────

def create_user(email: str, hashed_pw: str, must_change: bool = False) -> Dict[str, Any]:
    uid = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    ph = _ph()
    with get_db() as db:
        cur = db.cursor()
        cur.execute(
            f"INSERT INTO users (id, email, hashed_pw, plan, created_at, must_change_password) "
            f"VALUES ({ph},{ph},{ph},{ph},{ph},{ph})",
            (uid, email.lower().strip(), hashed_pw, "free", now, 1 if must_change else 0),
        )
    return {"id": uid, "email": email, "plan": "free", "must_change_password": must_change}


def update_user_plan(email: str, plan: str) -> bool:
    """Set the plan for a user by email. Returns True if a row was updated."""
    ph = _ph()
    with get_db() as db:
        cur = db.cursor()
        cur.execute(f"UPDATE users SET plan={ph} WHERE email={ph}", (plan, email.lower().strip()))
        updated = cur.rowcount > 0
        db.commit()
    return updated


def set_user_password(email: str, hashed_pw: str, must_change: bool = False) -> bool:
    """Set a user's password (by email) and the must_change flag. Returns True if updated."""
    ph = _ph()
    with get_db() as db:
        cur = db.cursor()
        cur.execute(
            f"UPDATE users SET hashed_pw={ph}, must_change_password={ph} WHERE email={ph}",
            (hashed_pw, 1 if must_change else 0, email.lower().strip()),
        )
        updated = cur.rowcount > 0
        db.commit()
    return updated


def create_password_reset(user_id: str, token_hash: str, expires_at: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    ph = _ph()
    with get_db() as db:
        cur = db.cursor()
        cur.execute(
            f"INSERT INTO password_resets (token_hash, user_id, expires_at, used, created_at) "
            f"VALUES ({ph},{ph},{ph},0,{ph})",
            (token_hash, user_id, expires_at, now),
        )


def get_password_reset(token_hash: str) -> Optional[Dict]:
    ph = _ph()
    with get_db() as db:
        cur = db.cursor()
        if _USE_POSTGRES:
            import psycopg2.extras
            cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(f"SELECT * FROM password_resets WHERE token_hash={ph}", (token_hash,))
        row = cur.fetchone()
    return _row_to_dict(row) if row else None


def mark_reset_used(token_hash: str) -> None:
    ph = _ph()
    with get_db() as db:
        cur = db.cursor()
        cur.execute(f"UPDATE password_resets SET used=1 WHERE token_hash={ph}", (token_hash,))
        db.commit()


def list_users(limit: int = 100) -> list:
    with get_db() as db:
        cur = db.cursor()
        if _USE_POSTGRES:
            import psycopg2.extras
            cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(f"SELECT id, email, plan, created_at FROM users ORDER BY created_at DESC LIMIT {int(limit)}")
        rows = cur.fetchall()
    return [_row_to_dict(r) for r in rows]


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
            f"SELECT id, score, decision, version, created_at FROM runs "
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


# ── Usage tracking ──────────────────────────────────────────────────────────

def _current_month() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m")


def increment_usage(user_id: str) -> int:
    """Increment this month's scan count, return new total."""
    ph = _ph()
    month = _current_month()
    with get_db() as db:
        cur = db.cursor()
        if _USE_POSTGRES:
            cur.execute(
                f"INSERT INTO usage (user_id, month, scan_count) VALUES ({ph},{ph},1) "
                f"ON CONFLICT (user_id, month) DO UPDATE SET scan_count = usage.scan_count + 1 "
                f"RETURNING scan_count",
                (user_id, month),
            )
            row = cur.fetchone()
            return row[0] if row else 1
        else:
            cur.execute(
                f"INSERT INTO usage (user_id, month, scan_count) VALUES ({ph},{ph},1) "
                f"ON CONFLICT (user_id, month) DO UPDATE SET scan_count = scan_count + 1",
                (user_id, month),
            )
            cur.execute(
                f"SELECT scan_count FROM usage WHERE user_id={ph} AND month={ph}",
                (user_id, month),
            )
            row = cur.fetchone()
            return row[0] if row else 1


def get_usage(user_id: str) -> int:
    """Get this month's scan count."""
    ph = _ph()
    month = _current_month()
    with get_db() as db:
        cur = db.cursor()
        cur.execute(
            f"SELECT scan_count FROM usage WHERE user_id={ph} AND month={ph}",
            (user_id, month),
        )
        row = cur.fetchone()
    return row[0] if row else 0


def get_findings_summary(user_id: str) -> List[Dict]:
    """Per-repo code-finding severity counts from each repo's most recent run.

    Returns one entry per repo (latest scan wins), sorted by risk weight
    (high*100 + medium*10 + low). Powers the dashboard severity heatmap.
    """
    import json
    ph = _ph()
    with get_db() as db:
        cur = db.cursor()
        if _USE_POSTGRES:
            import psycopg2.extras
            cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(
            f"SELECT repo_url, score, decision, report_json, created_at FROM runs "
            f"WHERE user_id={ph} ORDER BY created_at ASC",
            (user_id,),
        )
        rows = [_row_to_dict(r) for r in cur.fetchall()]

    latest: Dict[str, Dict] = {}  # repo_url -> latest row (asc order => last write wins)
    for r in rows:
        latest[r["repo_url"]] = r

    out: List[Dict] = []
    for repo, r in latest.items():
        report = {}
        if r.get("report_json"):
            try:
                report = json.loads(r["report_json"])
            except Exception:
                report = {}
        counts = {"high": 0, "medium": 0, "low": 0}
        for f in (report.get("code_findings") or []):
            sev = f.get("severity")
            if sev in counts:
                counts[sev] += 1
        out.append({
            "repo_url": repo,
            "score": r.get("score"),
            "decision": r.get("decision"),
            "high": counts["high"],
            "medium": counts["medium"],
            "low": counts["low"],
            "total": counts["high"] + counts["medium"] + counts["low"],
        })

    out.sort(key=lambda e: e["high"] * 100 + e["medium"] * 10 + e["low"], reverse=True)
    return out


def get_dashboard_stats(user_id: str) -> Dict:
    """Return aggregated dashboard stats for a user."""
    ph = _ph()
    with get_db() as db:
        cur = db.cursor()
        if _USE_POSTGRES:
            import psycopg2.extras
            cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        cur.execute(
            f"SELECT score, decision, repo_url, created_at FROM runs "
            f"WHERE user_id={ph} ORDER BY created_at ASC",
            (user_id,),
        )
        rows = [_row_to_dict(r) for r in cur.fetchall()]

    total_runs = len(rows)
    repos_tracked = len(set(r["repo_url"] for r in rows))
    scores = [r["score"] for r in rows if r.get("score") is not None]
    avg_score = round(sum(scores) / len(scores)) if scores else None
    best_score = max(scores) if scores else None
    latest_decision = rows[-1]["decision"] if rows else None

    # Score improvement: latest minus first
    score_improvement = None
    if len(scores) >= 2:
        score_improvement = scores[-1] - scores[0]

    this_month_scans = get_usage(user_id)

    return {
        "total_runs": total_runs,
        "repos_tracked": repos_tracked,
        "avg_score": avg_score,
        "best_score": best_score,
        "latest_decision": latest_decision,
        "this_month_scans": this_month_scans,
        "score_improvement": score_improvement,
    }


# ── Verifications ──────────────────────────────────────────────────────────

def save_verification(
    user_id: str,
    iteration: int,
    decision: str,
    violations: list,
    warnings: list,
    checks: dict,
    cost_so_far: float = 0.0,
    cost_remaining=None,
    loop_id: str = None,
) -> str:
    import json as _json
    vid = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    ph = _ph()
    with get_db() as db:
        cur = db.cursor()
        cur.execute(
            f"INSERT INTO verifications "
            f"(id, user_id, loop_id, iteration, decision, cost_so_far, "
            f"cost_remaining, violations_json, warnings_json, checks_json, created_at) "
            f"VALUES ({ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph})",
            (
                vid, user_id, loop_id, iteration, decision,
                cost_so_far, cost_remaining,
                _json.dumps(violations), _json.dumps(warnings), _json.dumps(checks),
                now,
            ),
        )
    return vid


def get_verifications_for_loop(loop_id: str, user_id: str) -> list:
    import json as _json
    ph = _ph()
    with get_db() as db:
        cur = db.cursor()
        if _USE_POSTGRES:
            import psycopg2.extras
            cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(
            f"SELECT * FROM verifications WHERE loop_id={ph} AND user_id={ph} "
            f"ORDER BY iteration ASC",
            (loop_id, user_id),
        )
        rows = cur.fetchall()
    results = []
    for r in rows:
        row = _row_to_dict(r)
        for key in ("violations_json", "warnings_json", "checks_json"):
            val = row.pop(key, None)
            out_key = key.replace("_json", "")
            row[out_key] = _json.loads(val) if val else []
        results.append(row)
    return results

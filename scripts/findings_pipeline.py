#!/usr/bin/env python3
"""The findings pipeline — the weekly outreach run, automated.

Searches GitHub for recently-maintained, high-star agent repos (Python and
TypeScript), runs the real gate (`release-gate audit --mode public-advisory`)
on a shallow clone of each, and writes an issue-ready draft per repo that has
confirmed findings. Nothing is ever posted — a human reads every draft and
decides whether it clears the bar to file.

    python scripts/findings_pipeline.py                  # full weekly run
    python scripts/findings_pipeline.py --dry-run        # search + filter only
    python scripts/findings_pipeline.py --repo owner/name  # scan one repo directly
    python scripts/findings_pipeline.py --max-repos 3 --min-stars 1000

All knobs live in scripts/findings_pipeline.yaml. Set GITHUB_TOKEN for the
5000 req/h API limit (unauthenticated search is 10 req/min and works for
small runs). Stdlib-only on purpose — runs anywhere the CLI runs.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

import yaml

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_CONFIG = os.path.join(REPO_ROOT, "scripts", "findings_pipeline.yaml")
API = "https://api.github.com"


# ── GitHub search ────────────────────────────────────────────────────────────

def _gh_get(url: str, token: str | None) -> dict:
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "release-gate-findings-pipeline",
        **({"Authorization": f"Bearer {token}"} if token else {}),
    })
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        if e.code == 403 and "rate limit" in (e.read() or b"").decode(errors="ignore").lower():
            raise SystemExit(
                "GitHub API rate limit hit. Set GITHUB_TOKEN (5000 req/h) or "
                "wait a minute and rerun — the state file makes reruns cheap."
            )
        raise


def search_candidates(cfg: dict, token: str | None) -> list[dict]:
    """Run every (query × language) search and return deduped candidate repos."""
    s = cfg["search"]
    cutoff = (dt.date.today() - dt.timedelta(days=s["pushed_within_days"])).isoformat()
    seen: dict[str, dict] = {}
    for query in s["queries"]:
        for language in s["languages"]:
            q = f'{query} language:{language} stars:>={s["min_stars"]} pushed:>={cutoff} archived:false'
            url = (f"{API}/search/repositories?q={urllib.parse.quote(q)}"
                   f"&per_page={s['per_query_limit']}&sort=stars&order=desc")
            data = _gh_get(url, token)
            for item in data.get("items", []):
                seen.setdefault(item["full_name"].lower(), {
                    "full_name": item["full_name"],
                    "owner": item["owner"]["login"],
                    "description": item.get("description") or "",
                    "topics": item.get("topics") or [],
                    "language": item.get("language") or language,
                    "stars": item.get("stargazers_count", 0),
                    "pushed_at": item.get("pushed_at", ""),
                    "clone_url": item["clone_url"],
                    "html_url": item["html_url"],
                })
            time.sleep(1 if token else 7)  # stay under the search rate limit
    return sorted(seen.values(), key=lambda r: -r["stars"])


def is_relevant(repo: dict, cfg: dict) -> tuple[bool, str]:
    f = cfg["filter"]
    hay = " ".join([repo["full_name"], repo["description"], " ".join(repo["topics"])]).lower()
    if repo["owner"].lower() in {o.lower() for o in f.get("exclude_owners") or []}:
        return False, "excluded owner"
    if repo["full_name"].lower() in {r.lower() for r in f.get("exclude_repos") or []}:
        return False, "excluded repo"
    hit = next((w for w in f.get("exclude_any") or [] if w.lower() in hay), None)
    if hit:
        return False, f"matched exclude word '{hit}'"
    if f.get("require_any") and not any(w.lower() in hay for w in f["require_any"]):
        return False, "no relevance keyword in name/description/topics"
    return True, ""


# ── Scanning ─────────────────────────────────────────────────────────────────

def clone_repo(repo: dict, cfg: dict, workdir: str) -> tuple[str, str] | None:
    """Shallow-clone; returns (path, head_sha) or None on failure."""
    dest = os.path.join(workdir, repo["full_name"].replace("/", "__"))
    try:
        subprocess.run(
            ["git", "clone", "--depth", str(cfg["run"]["clone_depth"]),
             "--quiet", repo["clone_url"], dest],
            check=True, timeout=cfg["run"]["clone_timeout_seconds"],
            capture_output=True,
        )
        sha = subprocess.run(["git", "-C", dest, "rev-parse", "HEAD"],
                             capture_output=True, text=True, check=True).stdout.strip()
        return dest, sha
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        print(f"    clone failed: {e}", file=sys.stderr)
        return None


def audit_repo(path: str, cfg: dict) -> dict | None:
    """Run the real gate and return the parsed public-advisory report."""
    try:
        out = subprocess.run(
            [sys.executable, "-m", "release_gate.cli", "audit", path,
             "--mode", "public-advisory", "--json"],
            capture_output=True, text=True,
            timeout=cfg["run"]["audit_timeout_seconds"], cwd=REPO_ROOT,
        )
        return json.loads(out.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError) as e:
        print(f"    audit failed: {e}", file=sys.stderr)
        return None


def selected_findings(report: dict, cfg: dict) -> list[dict]:
    adv = report.get("advisory") or {}
    fc = cfg["findings"]
    picked: list[dict] = []
    if fc.get("include_confirmed_high"):
        picked += adv.get("confirmed_high") or []
    if fc.get("include_inferred_high"):
        picked += adv.get("inferred_high") or []
    if fc.get("include_medium"):
        picked += adv.get("medium") or []
    return picked


# ── Draft rendering ──────────────────────────────────────────────────────────

def _finding_md(f: dict, repo: dict, sha: str) -> str:
    loc = f"{f.get('file', '?')}:{f.get('line', '?')}"
    permalink = f"{repo['html_url']}/blob/{sha}/{f.get('file', '')}#L{f.get('line', '')}"
    lines = [
        f"### {f.get('title', 'Finding')} — [`{loc}`]({permalink})",
        "",
        f"- **Rule:** `{f.get('rule_id', '?')}` · severity **{f.get('severity', '?')}** "
        f"· basis **{f.get('basis', '?')}** · confidence {f.get('confidence', '?')}",
        f"- **Evidence:** {f.get('evidence', '')}",
        f"- **Impact:** {f.get('impact', '')}",
        "",
        f"{f.get('recommendation', '')}",
    ]
    tags = f.get("compliance_tags") or []
    if tags:
        lines.append("")
        lines.append(f"<sub>{' · '.join(tags)}</sub>")
    return "\n".join(lines)


def render_draft(repo: dict, sha: str, findings: list[dict], cfg: dict) -> str:
    findings_md = "\n\n".join(_finding_md(f, repo, sha) for f in findings)
    rule_ids = ", ".join(sorted({f.get("rule_id", "?") for f in findings}))
    fill = {
        "repo": repo["full_name"],
        "title": findings[0].get("title", "confirmed agent-safety finding"),
        "count": len(findings),
        "findings_md": findings_md,
        "rule_ids": rule_ids,
    }
    title = cfg["issue"]["title"].format(**fill)
    body = cfg["issue"]["body"].format(**fill)
    header = (
        f"<!-- DRAFT — review before filing. Repo: {repo['full_name']} "
        f"@ {sha[:10]} · {repo['stars']}★ · {repo['language']} -->\n"
        f"# {title}\n\n"
    )
    return header + body


# ── State ────────────────────────────────────────────────────────────────────

def load_state(path: str) -> dict:
    if os.path.exists(path):
        with open(path) as fh:
            return json.load(fh)
    return {"scanned": {}}


def save_state(path: str, state: dict) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as fh:
        json.dump(state, fh, indent=2, sort_keys=True)


def recently_scanned(state: dict, full_name: str, cfg: dict) -> bool:
    entry = state["scanned"].get(full_name.lower())
    if not entry:
        return False
    scanned = dt.date.fromisoformat(entry["scanned_at"])
    return (dt.date.today() - scanned).days < cfg["run"]["rescan_after_days"]


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--config", default=DEFAULT_CONFIG)
    ap.add_argument("--max-repos", type=int, help="override run.max_repos")
    ap.add_argument("--min-stars", type=int, help="override search.min_stars")
    ap.add_argument("--dry-run", action="store_true",
                    help="search and filter only — no clones, no audits")
    ap.add_argument("--repo", action="append", default=[], metavar="OWNER/NAME",
                    help="skip search and scan these repos (repeatable)")
    ap.add_argument("--rescan", action="store_true",
                    help="ignore the state file's rescan window")
    args = ap.parse_args()

    with open(args.config) as fh:
        cfg = yaml.safe_load(fh)
    if args.max_repos is not None:
        cfg["run"]["max_repos"] = args.max_repos
    if args.min_stars is not None:
        cfg["search"]["min_stars"] = args.min_stars

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    state_path = os.path.join(REPO_ROOT, cfg["output"]["state_file"])
    state = load_state(state_path)

    # 1. Candidates — from search, or named directly.
    if args.repo:
        candidates = []
        for full in args.repo:
            try:
                data = _gh_get(f"{API}/repos/{full}", token)
            except (urllib.error.URLError, OSError):
                # No API access (offline / restrictive proxy) — a named repo
                # only needs a clone URL, so fall back to the derivable one.
                data = {}
            candidates.append({
                "full_name": data.get("full_name", full),
                "owner": data.get("owner", {}).get("login", full.split("/")[0]),
                "description": data.get("description") or "",
                "topics": data.get("topics") or [],
                "language": data.get("language") or "?",
                "stars": data.get("stargazers_count", 0),
                "pushed_at": data.get("pushed_at", ""),
                "clone_url": data.get("clone_url", f"https://github.com/{full}.git"),
                "html_url": data.get("html_url", f"https://github.com/{full}"),
            })
    else:
        print("Searching GitHub…")
        candidates = search_candidates(cfg, token)
        print(f"  {len(candidates)} unique repos matched the raw searches")

    # 2. Filter.
    queue: list[dict] = []
    for repo in candidates:
        if not args.repo:  # named repos bypass relevance + state filters
            ok, why = is_relevant(repo, cfg)
            if not ok:
                continue
            if not args.rescan and recently_scanned(state, repo["full_name"], cfg):
                continue
        queue.append(repo)
    queue = queue[: cfg["run"]["max_repos"]]
    print(f"  {len(queue)} repo(s) queued (max {cfg['run']['max_repos']})")
    for r in queue:
        print(f"    {r['stars']:>6}★  {r['language']:<10}  {r['full_name']}")

    if args.dry_run:
        print("\nDry run — stopping before clone/audit.")
        return 0

    # 3. Scan and draft.
    run_date = dt.date.today().isoformat()
    drafts_dir = os.path.join(REPO_ROOT, cfg["output"]["drafts_dir"], run_date)
    results = []
    workdir = tempfile.mkdtemp(prefix="rg-findings-")
    try:
        for repo in queue:
            print(f"\n▶ {repo['full_name']} ({repo['stars']}★, {repo['language']})")
            cloned = clone_repo(repo, cfg, workdir)
            row = {"repo": repo["full_name"], "stars": repo["stars"],
                   "language": repo["language"], "decision": "-",
                   "findings": 0, "draft": ""}
            if cloned:
                path, sha = cloned
                report = audit_repo(path, cfg)
                shutil.rmtree(path, ignore_errors=True)  # free disk as we go
                if report:
                    picked = selected_findings(report, cfg)
                    row["decision"] = report.get("decision", "?")
                    row["findings"] = len(picked)
                    if picked:
                        os.makedirs(drafts_dir, exist_ok=True)
                        fname = repo["full_name"].replace("/", "__") + ".md"
                        draft_path = os.path.join(drafts_dir, fname)
                        with open(draft_path, "w") as fh:
                            fh.write(render_draft(repo, sha, picked, cfg))
                        row["draft"] = os.path.relpath(draft_path, REPO_ROOT)
                        print(f"    {len(picked)} finding(s) → {row['draft']}")
                    else:
                        print("    clean under the selected buckets — no draft")
                    state["scanned"][repo["full_name"].lower()] = {
                        "scanned_at": run_date, "sha": sha,
                        "decision": row["decision"], "findings": row["findings"],
                    }
                    save_state(state_path, state)
            results.append(row)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    # 4. Run summary.
    print(f"\n{'─' * 72}")
    print(f"{'repo':<44} {'decision':<9} {'findings':<9} draft")
    for r in results:
        print(f"{r['repo']:<44} {r['decision']:<9} {r['findings']:<9} {r['draft'] or '—'}")
    drafted = sum(1 for r in results if r["draft"])
    print(f"\n{len(results)} scanned · {drafted} draft(s) written to {os.path.relpath(drafts_dir, REPO_ROOT) if drafted else '(none)'}")
    print("Drafts are never auto-posted — read each one and file it by hand only "
          "if you would stake your name on it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

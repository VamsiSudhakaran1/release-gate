"""release-gate context lockfile — an AIBOM (agent bill of materials) + drift gate.

An agent's *behavior* is determined by things a normal lockfile never captures:
the model version, the system prompts, the declared governance policy, the eval
suite, and the tools / MCP servers it trusts. None of those live in
`package.json`, and any of them can change behavior with no code diff — a
provider silently updates the model, a prompt is edited, an MCP tool description
is swapped.

`release-gate lock` pins all of that into `release-gate.lock` (the AIBOM):
a SHA-256 per behavior-determining artifact plus one top-level digest, and a
`valid_until` TTL. `release-gate audit --lock` recomputes it and FAILS when
anything drifts from the pin — deterministic, offline, no network. That single
primitive delivers the bill-of-materials, expiring certificates,
re-gate-on-model-change, and a pinned baseline for MCP tool-poisoning detection.

Out of scope for v1 (runtime, not in-repo): RAG corpora and live MCP server
*responses*. The lockfile says so rather than pretending to cover them.
"""

from __future__ import annotations

import datetime
import fnmatch
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

SCHEMA = "release-gate-lock/1"
LOCK_FILENAMES = ["release-gate.lock", "release-gate.lock.json"]

_SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", ".env",
              "dist", "build", "site-packages", ".tox", ".mypy_cache"}
_MAX_HASH_BYTES = 5_000_000   # don't hash giant blobs; behavior files are small

# Behavior-determining artifacts, by kind. Globs match on the repo-relative path
# (case-insensitive), so `prompts/system.txt` and `agent_prompt.py` both match.
_GOVERNANCE_FILES = ("governance.yaml", "governance.yml", ".release-gate.yaml",
                     ".release-gate.yml", "release-gate.yaml", "release-gate.yml")
_EVAL_FILES       = ("evals.yaml", "evals.yml")
_MCP_GLOBS        = ("mcp.json", ".mcp.json", "*.mcp.json", ".cursor/mcp.json",
                     ".vscode/mcp.json", "mcp_config.json", "mcp/*.json")
_PROMPT_GLOBS     = ("*prompt*.txt", "*prompt*.md", "*prompt*.yaml", "*prompt*.yml",
                     "*prompt*.j2", "*prompt*.jinja", "*prompt*.jinja2", "*prompt*.tmpl",
                     "prompts/*", "prompt/*", "*.prompt")
_MAX_PER_KIND     = 200        # cap so a pathological repo can't explode the lock


def _sha256_bytes(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


def _sha256_file(path: Path) -> Optional[str]:
    try:
        if path.stat().st_size > _MAX_HASH_BYTES:
            return None
        return _sha256_bytes(path.read_bytes())
    except OSError:
        return None


def _rel(root: Path, p: Path) -> str:
    return str(p.relative_to(root)).replace("\\", "/")


def _match_any(relpath: str, globs) -> bool:
    low = relpath.lower()
    base = low.rsplit("/", 1)[-1]
    return any(fnmatch.fnmatch(low, g) or fnmatch.fnmatch(base, g) for g in globs)


def collect_components(root: Path) -> List[Dict[str, Any]]:
    """Hash every in-repo artifact that determines agent behavior."""
    root = root.resolve()
    buckets: Dict[str, List[Dict[str, Any]]] = {
        "governance": [], "evals": [], "mcp": [], "prompt": []}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fname in filenames:
            p = Path(dirpath) / fname
            rel = _rel(root, p)
            low = fname.lower()
            kind = None
            if low in _GOVERNANCE_FILES:
                kind = "governance"
            elif low in _EVAL_FILES:
                kind = "evals"
            elif _match_any(rel, _MCP_GLOBS):
                kind = "mcp"
            elif _match_any(rel, _PROMPT_GLOBS):
                kind = "prompt"
            if not kind or len(buckets[kind]) >= _MAX_PER_KIND:
                continue
            h = _sha256_file(p)
            if h:
                buckets[kind].append({"kind": kind, "path": rel, "sha256": h})
    components = [c for b in buckets.values() for c in b]
    components.sort(key=lambda c: (c["kind"], c["path"]))
    return components


def detect_context_model(root: Path) -> Optional[str]:
    """The model id the code targets — the thing a provider can silently change."""
    try:
        from release_gate.audit import detect_model
        return detect_model(root)
    except Exception:
        return None


def _digest(components: List[Dict[str, Any]], model: Optional[str]) -> str:
    parts = sorted(c["sha256"] for c in components)
    if model:
        parts.append("model:" + model)
    return _sha256_bytes("\n".join(parts).encode())


def build_lock(root: Path, ttl_days: int = 30, now: Optional[datetime.datetime] = None
               ) -> Dict[str, Any]:
    """Build the lockfile dict for a repo. `now` is injectable for determinism."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    components = collect_components(Path(root))
    model = detect_context_model(Path(root))
    if model:
        components.append({"kind": "model", "id": model,
                           "sha256": _sha256_bytes(("model:" + model).encode())})
        components.sort(key=lambda c: (c["kind"], c.get("path") or c.get("id") or ""))
    return {
        "schema": SCHEMA,
        "digest": _digest([c for c in components if c["kind"] != "model"], model),
        "model": model,
        "generated_at": now.replace(microsecond=0).isoformat(),
        "valid_until": (now + datetime.timedelta(days=ttl_days)).replace(microsecond=0).isoformat(),
        "ttl_days": ttl_days,
        "component_count": len(components),
        "components": components,
        "note": ("Pins in-repo behavior artifacts (model id, governance, evals, "
                 "prompts, MCP/tool config). RAG corpora and live MCP responses "
                 "are runtime and NOT covered."),
    }


def _index(components: List[Dict[str, Any]]) -> Dict[str, str]:
    out = {}
    for c in components:
        key = c.get("path") or ("model:" + str(c.get("id")))
        out[key] = c["sha256"]
    return out


def compare_lock(current: Dict[str, Any], saved: Dict[str, Any],
                 now: Optional[datetime.datetime] = None) -> Dict[str, Any]:
    """Diff a freshly-built lock against a saved one. Returns a drift summary."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    cur = _index(current.get("components", []))
    old = _index(saved.get("components", []))
    changed = sorted(k for k in cur.keys() & old.keys() if cur[k] != old[k])
    added = sorted(cur.keys() - old.keys())
    removed = sorted(old.keys() - cur.keys())
    model_changed = (current.get("model") or None) != (saved.get("model") or None)

    expired = False
    valid_until = saved.get("valid_until")
    if valid_until:
        try:
            vu = datetime.datetime.fromisoformat(valid_until)
            if vu.tzinfo is None:
                vu = vu.replace(tzinfo=datetime.timezone.utc)
            expired = now > vu
        except ValueError:
            pass

    drift = bool(changed or added or removed or model_changed)
    reasons: List[str] = []
    if model_changed:
        reasons.append(f"model changed: {saved.get('model')} → {current.get('model')}")
    if changed:
        reasons.append(f"{len(changed)} artifact(s) changed")
    if added:
        reasons.append(f"{len(added)} added")
    if removed:
        reasons.append(f"{len(removed)} removed")
    if expired:
        reasons.append(f"lock expired (valid until {valid_until})")

    return {
        "drift": drift, "expired": expired, "model_changed": model_changed,
        "changed": changed, "added": added, "removed": removed,
        "saved_model": saved.get("model"), "current_model": current.get("model"),
        "valid_until": valid_until, "reasons": reasons,
        # The gate fails on drift OR expiry — either invalidates the certificate.
        "gate_ok": not (drift or expired),
    }


def load_lock(path: str) -> Optional[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def write_lock(lock: Dict[str, Any], path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(lock, f, indent=2, sort_keys=False)
        f.write("\n")

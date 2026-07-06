"""LLM verifier — pure-function + orchestration tests (no network; call_fn injected)."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from release_gate.llm_verify import (
    load_config, _context_window, _build_messages, _parse_verdict,
    verify_findings, VerifyConfigError,
)


# ── config resolution ────────────────────────────────────────────────────────

def test_config_requires_model(monkeypatch):
    monkeypatch.delenv("RG_VERIFY_MODEL", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("RG_VERIFY_API_KEY", raising=False)
    try:
        load_config()
        assert False, "expected VerifyConfigError"
    except VerifyConfigError:
        pass


def test_config_local_model_needs_no_key(monkeypatch):
    monkeypatch.setenv("RG_VERIFY_MODEL", "llama3.1")
    monkeypatch.setenv("RG_VERIFY_BASE_URL", "http://localhost:11434/v1")
    monkeypatch.delenv("RG_VERIFY_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    cfg = load_config()
    assert cfg["model"] == "llama3.1"
    assert cfg["base_url"] == "http://localhost:11434/v1"


def test_config_hosted_requires_key(monkeypatch):
    monkeypatch.setenv("RG_VERIFY_MODEL", "some-model")
    monkeypatch.setenv("RG_VERIFY_BASE_URL", "https://api.example.com/v1")
    monkeypatch.delenv("RG_VERIFY_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    try:
        load_config()
        assert False
    except VerifyConfigError:
        pass


# ── pure helpers ─────────────────────────────────────────────────────────────

def test_context_window_marks_line(tmp_path):
    (tmp_path / "a.py").write_text("\n".join(f"line{i}" for i in range(1, 40)))
    win = _context_window(tmp_path, "a.py", 20, before=3, after=2)
    assert ">>   20| line20" in win
    assert "line18" in win and "line22" in win


def test_parse_verdict_tolerates_prose():
    assert _parse_verdict('sure: {"verdict":"refuted","reason":"header name"}')["verdict"] == "refuted"
    assert _parse_verdict('{"verdict":"confirmed","reason":"x"}')["verdict"] == "confirmed"
    assert _parse_verdict("no json here")["verdict"] == "uncertain"  # safe default


def test_build_messages_includes_evidence():
    f = {"title": "Deserialization of unverified data", "severity": "medium",
         "confidence": "medium", "basis": "inferred", "file": "x.py", "line": 5,
         "evidence": "pickle.loads() on `data`", "recommendation": "confirm source"}
    msgs = _build_messages(f, ">>    5| pickle.loads(data)")
    assert msgs[0]["role"] == "system"
    assert "pickle.loads() on `data`" in msgs[1]["content"]


# ── orchestration (injected call_fn — no network) ────────────────────────────

def test_verify_only_touches_medium_and_above(tmp_path):
    (tmp_path / "x.py").write_text("import pickle\npickle.loads(data)\n")
    findings = [
        {"severity": "high", "title": "Dangerous execution sink", "file": "x.py", "line": 2},
        {"severity": "low", "title": "LLM call with no token ceiling", "file": "x.py", "line": 1},
    ]
    calls = []

    def fake_call(cfg, messages):
        calls.append(messages)
        return '{"verdict":"confirmed","reason":"model output reaches eval"}'

    summary = verify_findings(
        findings, tmp_path, config={"model": "m", "base_url": "u", "api_key": ""},
        call_fn=fake_call, corpus_path=str(tmp_path / "corpus.jsonl"))
    # low was skipped; only the high got a verdict + a model call
    assert len(calls) == 1
    assert findings[0]["verdict"]["verdict"] == "confirmed"
    assert "verdict" not in findings[1]
    assert summary["counts"]["confirmed"] == 1
    # corpus row persisted
    rows = (tmp_path / "corpus.jsonl").read_text().strip().splitlines()
    assert len(rows) == 1 and json.loads(rows[0])["title"] == "Dangerous execution sink"


def test_verify_survives_model_error(tmp_path):
    (tmp_path / "x.py").write_text("pickle.loads(data)\n")
    findings = [{"severity": "medium", "title": "Deserialization of unverified data",
                 "file": "x.py", "line": 1}]

    def boom(cfg, messages):
        raise RuntimeError("connection refused")

    summary = verify_findings(
        findings, tmp_path, config={"model": "m", "base_url": "u", "api_key": ""},
        call_fn=boom, corpus_path=str(tmp_path / "c.jsonl"))
    assert findings[0]["verdict"]["verdict"] == "error"   # graceful, not a crash
    assert summary["counts"]["error"] == 1

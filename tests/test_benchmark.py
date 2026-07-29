"""The accuracy benchmark is a CI floor: precision must not regress, no clean
case may false-positive, and RESULTS.md must stay in sync with the engine."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "benchmark"))

import importlib.util

_spec = importlib.util.spec_from_file_location(
    "rg_benchmark_run",
    Path(__file__).resolve().parent.parent / "benchmark" / "run.py")
_bench = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_bench)


def _res():
    return _bench.evaluate(_bench.load_cases())


def test_precision_is_perfect_and_no_clean_false_positives():
    r = _res()
    # Precision-first contract: when it flags, it must be right, and every real
    # framework look-alike must stay silent.
    assert r["precision"] == 1.0, f"precision regressed: {r['misclassified']}"
    assert r["clean_quiet_rate"] == 1.0, f"a clean case false-positived: {r['misclassified']}"


def test_recall_floor():
    # Recall may be < 1.0 (documented limitations), but must not fall off a cliff.
    assert _res()["recall"] >= 0.90


def test_every_high_is_confirmed_and_provenance_backed():
    """THE HIGH-TIER INVARIANT (0.9.4) — the CI floor that keeps HIGHs watertight.

    A HIGH is the only thing we ask a maintainer to act on, so across the whole
    corpus every HIGH must be `basis=confirmed`, and every HIGH from a
    taint-based rule must carry a provenance chain (origin line → value → sink
    line) a reader can open and check. If a future rule tries to grade a
    name-hint guess as HIGH, this fails.
    """
    v = _res()["high_tier_violations"]
    assert v == [], f"HIGH-tier integrity violated: {v}"


def test_a_bare_name_hint_can_never_produce_a_high():
    """The root-cause regression guard, stated directly.

    `payload` was AutoGPT's own HMAC-signed cache bytes; `func_body` was
    langflow's own template. Both were reported as confirmed RCE because of how
    they were SPELLED. Whatever else changes, that must never come back.
    """
    from release_gate.agent_analysis import analyze_python
    for name in ("payload", "body", "request_data", "user_input", "func_body"):
        src = f"import pickle\ndef h({name}):\n    return pickle.loads({name})\n"
        for f in analyze_python(src, "x.py"):
            assert f["severity"] not in ("high", "critical"), \
                f"a bare parameter named {name!r} produced a HIGH: {f['title']}"


def test_results_md_in_sync():
    doc = Path(__file__).resolve().parent.parent / "benchmark" / "RESULTS.md"
    # encoding pinned to utf-8: the file has em-dashes; Path.read_text() would
    # otherwise use the platform default (cp1252 on Windows) and mis-decode them.
    assert doc.read_text(encoding="utf-8").strip() == _bench.render_md(_res()).strip(), \
        "benchmark/RESULTS.md is stale — run: python benchmark/run.py --md"

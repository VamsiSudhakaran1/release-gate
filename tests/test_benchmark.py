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


def test_results_md_in_sync():
    doc = Path(__file__).resolve().parent.parent / "benchmark" / "RESULTS.md"
    assert doc.read_text().strip() == _bench.render_md(_res()).strip(), \
        "benchmark/RESULTS.md is stale — run: python benchmark/run.py --md"

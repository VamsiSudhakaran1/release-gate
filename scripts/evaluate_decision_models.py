#!/usr/bin/env python3
"""Benchmark the models behind release-gate's semantic adjudications. Trains nothing.

    python scripts/evaluate_decision_models.py corpus.jsonl [more.jsonl ...] \\
        [--labels labels.jsonl ...] \\
        [--class openai:gpt-4o=general --class laya=decision-model ...] \\
        [--bins 10] [--json] [--labelled-out FILE] [--parquet FILE]

Reads one or more calibration corpora (`assure ... --calibration-out FILE`),
joins the labels people supplied (`release-gate.calibration-label/1` rows:
a human adjudication, a later outcome of the claim, an incident reference),
and reports, per model and per class:

- how often each model answered, abstained (`insufficient_evidence`) or gave
  no answer (UNKNOWN);
- agreement with the human adjudication, and its confusion table;
- how often a later outcome confirmed the answer;
- calibration — Brier score and expected calibration error — over the
  probabilities a provider *stated*, and only those;
- head-to-head on packets more than one model answered.

`--class MODEL=CLASS` groups models for the comparison the corpus exists
for: a general reasoning model, a Laya/Jev-style decision model, a future
release-gate specialist. A model key is `provider:model@version`, or a bare
model name. Unmapped models are grouped by their interface (CHAT, DECISION).

`--labelled-out` writes the corpus with its labels joined, as JSONL;
`--parquet` writes it as a Parquet table (needs pyarrow). Nothing here trains,
tunes or calls a model, and nothing it reports feeds a decision.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from release_gate.assurance.calibration import (  # noqa: E402
    CalibrationError, apply_labels, evaluate_corpus, read_calibration, read_labels,
    render_evaluation, write_calibration, write_parquet)


def _classes(pairs: List[str]) -> Dict[str, str]:
    classes: Dict[str, str] = {}
    for pair in pairs:
        model, sep, label = pair.rpartition("=")
        if not sep or not model or not label:
            raise CalibrationError(f"--class takes MODEL=CLASS, not {pair!r}")
        classes[model] = label
    return classes


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Benchmark semantic-adjudication models from a calibration corpus "
                    "(no training).")
    parser.add_argument("corpus", nargs="+", help="calibration JSONL file(s)")
    parser.add_argument("--labels", action="append", default=[],
                        help="calibration-label JSONL file(s)")
    parser.add_argument("--class", dest="classes", action="append", default=[],
                        metavar="MODEL=CLASS", help="group a model under a class")
    parser.add_argument("--bins", type=int, default=10,
                        help="calibration bins (default 10)")
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    parser.add_argument("--labelled-out", help="write the labelled corpus as JSONL")
    parser.add_argument("--parquet", help="write the labelled corpus as Parquet")
    args = parser.parse_args(argv)
    try:
        if args.bins < 1:
            raise CalibrationError("--bins is at least 1")
        records = []
        seen = set()
        for path in args.corpus:
            for row in read_calibration(path):
                if row["record_id"] not in seen:
                    seen.add(row["record_id"])
                    records.append(row)
        labels = [label for path in args.labels for label in read_labels(path)]
        records, unmatched = apply_labels(records, labels)
        report = evaluate_corpus(records, model_classes=_classes(args.classes),
                                 bins=args.bins)
        report["unmatched_labels"] = [label.record_id for label in unmatched]
        if args.labelled_out:
            write_calibration(records, args.labelled_out)
        if args.parquet:
            write_parquet(records, args.parquet)
    except (CalibrationError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(render_evaluation(report))
        if report["unmatched_labels"]:
            print(f"\n{len(report['unmatched_labels'])} label(s) matched no record: "
                  + ", ".join(report["unmatched_labels"][:10]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

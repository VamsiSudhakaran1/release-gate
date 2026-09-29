#!/usr/bin/env python3
"""Write the mistyped-consequence file used to check the 0.11.1 refusal notice.

A shell heredoc does not exist in cmd, and JSON quoting through `echo` on
Windows is a trap, so the file is written from Python instead.

    python make_typo_example.py            # writes ./typo-example.jsonl
    release-gate assure typo-example.jsonl
"""
from __future__ import annotations

import sys
from pathlib import Path

RECORDS = [
    # SCOPE and DATA_IMPACT carry values that are NOT in their vocabularies.
    '{"record_type":"consequence","REVERSIBILITY":"IRREVERSIBLE",'
    '"SCOPE":"ALL_USERS","DATA_IMPACT":"DESTRUCTIVE"}',
    '{"record_type":"execution","trace_id":"t",'
    '"steps":[{"type":"tool_call","tool":"bash"}]}',
]

out = Path(sys.argv[1] if len(sys.argv) > 1 else "typo-example.jsonl")
out.write_text("\n".join(RECORDS) + "\n", encoding="utf-8")
print(f"wrote {out.resolve()}")
print("\nNow run:")
print(f"  release-gate assure {out}")
print("\n0.11.1 prints two REFUSED lines under WHAT IS AT STAKE.")
print("0.11.0 and earlier print nothing — that is the bug this checks.")

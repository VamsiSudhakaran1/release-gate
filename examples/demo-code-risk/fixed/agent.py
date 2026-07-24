"""analysis-agent — answers questions about a CSV.

Baseline version: the model may only choose a named aggregation from a fixed
allowlist. Its output is validated and never executed, and the call is capped so
a runaway can't drain the budget. This is the state of `main` before the PR.
"""
import os

import pandas as pd
from openai import OpenAI

client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])

ALLOWED = {"mean", "sum", "min", "max", "count", "median"}


def answer(df: pd.DataFrame, question: str):
    resp = client.chat.completions.create(
        model="gpt-4o",
        max_tokens=16,
        messages=[
            {"role": "system", "content": "Reply with ONE of: mean sum min max count median."},
            {"role": "user", "content": question},
        ],
    )
    op = resp.choices[0].message.content.strip()
    if op not in ALLOWED:  # validate model output against an allowlist
        raise ValueError(f"unsupported op: {op!r}")
    return getattr(df, op)(numeric_only=True)  # no eval, no exec

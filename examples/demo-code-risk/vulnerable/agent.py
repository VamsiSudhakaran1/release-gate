"""analysis-agent — answers questions about a CSV by asking the model for a
one-line pandas expression and evaluating it against the dataframe.

This is a real, common anti-pattern: the model's output is executed directly.
If a prompt-injected cell in the CSV (or a poisoned tool result) steers the
model, `eval` turns a data question into remote code execution.
"""
import os

import pandas as pd
from openai import OpenAI

client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])


def answer(df: pd.DataFrame, question: str):
    resp = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": "Reply with a single pandas expression over `df`."},
            {"role": "user", "content": question},
        ],
    )
    expr = resp.choices[0].message.content
    return eval(expr, {"df": df})  # model output executed directly

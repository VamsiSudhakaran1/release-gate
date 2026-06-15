"""
Example agent for `release-gate score --agent py:examples.agent_example:handle`.

Any callable with the signature `handle(user_input, context="") -> str` works.
A single-argument `handle(user_input)` is also accepted. Wire your real agent
(LangChain chain, OpenAI/Anthropic call, internal service client) in here and
release-gate will run your evals against it for real instead of static stubs.
"""

from __future__ import annotations


def handle(user_input: str, context: str = "") -> str:
    """Toy customer-support agent: refuses PII, returns JSON for summaries."""
    low = user_input.lower()

    if any(term in low for term in ("credit card", "pan number", "ssn", "password")):
        return "I'm sorry, I can't share that sensitive information."

    if "summar" in low or "order #" in low:
        return '{"order_id": 42, "summary": "1 item shipped on 2026-06-15"}'

    return "How can I help you with your order today?"

"""Acme refunds agent — answers order questions, issues refunds, closes accounts.

Written by an AI coding agent (acme-coder, session s-4471) for the release this
acceptance scenario admits; see `../release.jsonl` for the authorship record.

Consequential tools: `issue_refund` moves money and cannot be undone once the
payment processor settles it; `close_account` deletes a customer's account. A
refund above the approval threshold waits for a person, and closing an account
waits for the customer to confirm.
"""
import json
import os
from pathlib import Path

from openai import OpenAI

HERE = Path(__file__).resolve().parent
SYSTEM_PROMPT = (HERE / "prompts" / "system.txt").read_text(encoding="utf-8")
TOOLS = json.loads((HERE / "tools.json").read_text(encoding="utf-8"))

APPROVAL_THRESHOLD = 500  # dollars; a single refund above this needs a person
MAX_STEPS = 8

client = OpenAI(api_key=os.environ["ACME_LLM_KEY"],
                base_url=os.environ["ACME_LLM_URL"])


class ApprovalRequired(Exception):
    """A person must approve this action before it runs."""


def require_human_approval(action: str, details: dict) -> None:
    """Queue the action for the support lead and stop this turn."""
    raise ApprovalRequired(f"{action} needs approval: {json.dumps(details, sort_keys=True)}")


def lookup_order(ledger, order_id: str) -> dict:
    return ledger.order(order_id)


def issue_refund(ledger, order_id: str, amount: float) -> dict:
    order = ledger.order(order_id)
    if amount <= 0:
        raise ValueError("a refund is a positive amount")
    if ledger.refunded(order_id) + amount > order["amount"]:
        raise ValueError("refunds would exceed the order total")
    # The threshold is checked per call: each refund above it waits for a person.
    if amount > APPROVAL_THRESHOLD:
        require_human_approval("issue_refund", {"order_id": order_id, "amount": amount})
    return ledger.refund(order_id, amount)


def close_account(ledger, customer_id: str, confirmed_by_customer: bool) -> dict:
    if not confirmed_by_customer:
        raise ApprovalRequired("close_account needs the customer's confirmation")
    return ledger.close(customer_id)


HANDLERS = {"lookup_order": lookup_order, "issue_refund": issue_refund,
            "close_account": close_account}


def run_turn(ledger, conversation: list) -> list:
    """One customer turn: the model may call tools, at most MAX_STEPS times."""
    messages = [{"role": "system", "content": SYSTEM_PROMPT}, *conversation]
    for _ in range(MAX_STEPS):
        reply = client.chat.completions.create(
            model="acme-llm-2026-09", messages=messages, tools=TOOLS,
            max_tokens=800, timeout=30)
        message = reply.choices[0].message
        messages.append(message)
        if not message.tool_calls:
            return messages
        for call in message.tool_calls:
            name = call.function.name
            if name not in HANDLERS:
                raise ValueError(f"unknown tool {name!r}")
            arguments = json.loads(call.function.arguments)
            result = HANDLERS[name](ledger, **arguments)
            messages.append({"role": "tool", "tool_call_id": call.id,
                             "content": json.dumps(result)})
    return messages

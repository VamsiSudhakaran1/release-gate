"""A stand-in agent harness that holds itself to a signed admission.

    python agent.py --admission admission.signed.json --trusted-keys trusted-keys.json \
                    --log decisions.json [--halt-file HALT]

It observes its own state from the files it is about to use, opens a
RuntimeGate (which refuses unless a signed PROMOTE admits exactly that state),
then asks the gate before each tool call and checks the model each response
reports. Exit 0 when the gate opened, 1 when it refused to.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

from release_gate.runtime import NotAdmitted, RuntimeGate, observe

HERE = Path(__file__).resolve().parent
MODEL = "frontier-model-2026-03-01"
COMMIT = "7a3e9c1b2d4f6a8c0e1b3d5f7a9c2e4b6d8f0a1c"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--admission", required=True)
    parser.add_argument("--trusted-keys", required=True)
    parser.add_argument("--log", default="decisions.json")
    parser.add_argument("--halt-file", default=None)
    args = parser.parse_args()

    # Observed from what this process will actually use, not from a manifest of it.
    tools = json.loads((HERE / "tools.json").read_text(encoding="utf-8"))
    state = observe(model=MODEL,
                    prompt=(HERE / "system.txt").read_bytes().decode("utf-8"),
                    tools=tools,
                    governance_policy=yaml.safe_load(
                        (HERE / "governance.yaml").read_text(encoding="utf-8")),
                    commit=COMMIT)
    try:
        gate = RuntimeGate.open(args.admission, observed=state,
                                trusted_keys=args.trusted_keys, log_path=args.log,
                                halt_file=args.halt_file, run_id="payments-run-1")
    except NotAdmitted as refusal:
        print(f"REFUSED TO START  {refusal}")
        return 1
    print(f"admitted          state {gate.check.admitted_state_hash}")

    definitions = {t["name"]: t for t in tools["tools"]}

    def call(tool: str, arguments: dict, approved_by: str = "") -> None:
        decision = gate.authorize(tool, arguments, definition=definitions.get(tool),
                                  approved_by=approved_by or None)
        print(f"{decision.decision.value:<16}  {tool}: {decision.reason}")

    call("get_balance", {"account": "A-1001"})
    call("transfer_funds", {"from": "A-1001", "to": "A-2002", "amount": 250})
    call("transfer_funds", {"from": "A-1001", "to": "A-2002", "amount": 250},
         approved_by="ops-oncall@payments.example")
    call("close_account", {"account": "A-1001"})
    call("wire_offshore", {"amount": 9000})
    model = gate.check_model(MODEL)
    print(f"{model.decision.value:<16}  model: {model.reason}")
    print(f"decisions written to {args.log}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

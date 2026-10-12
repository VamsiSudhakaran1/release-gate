# Runtime gate: what was admitted is what runs, call by call

A payments assistant with three tools: `get_balance`, `transfer_funds` (marked
destructive) and `close_account` (destructive, and forbidden by its policy). Its
prompt, tools and policy are the files in this folder. The release is admitted
against their exact state, and the agent refuses to start in any other.

| File | What it is |
|---|---|
| `system.txt` | the prompt the agent sends |
| `tools.json` | the tools it exposes, as an MCP `tools/list` result |
| `governance.yaml` | its `trace_policies`, the ones `verify --trace` also reads |
| `release.jsonl` | the release: a claim and three pieces of evidence, each naming the state it was about |
| `agent.py` | a stand-in harness that observes its state, opens the gate and asks before each call |

## 1. State the candidate from the files

```bash
cd examples/runtime
release-gate state --model frontier-model-2026-03-01 --prompt system.txt \
  --tools tools.json --policy governance.yaml \
  --component commit=7a3e9c1b2d4f6a8c0e1b3d5f7a9c2e4b6d8f0a1c --out /tmp/candidate.json
```

The prompt is the digest of its exact bytes, and the tool manifest is the digest
of every definition, description included. The agent computes both the same way
at start.

## 2. Admit it, and sign the admission

```bash
release-gate assure release.jsonl --methodology general-agent-action@1.0.0 \
  --candidate /tmp/candidate.json --admission-out /tmp/admission.json   # PROMOTE, exit 0

cd /tmp
release-gate keygen rg-ci
python -c "import json; json.dump({'keys': [{'keyid': 'rg-ci', 'public_key': open('rg-ci.pub').read(), 'producers': ['release-gate/admission'], 'decided_by': 'you@example.com'}]}, open('trusted-keys.json', 'w'))"
release-gate sign admission.json --key rg-ci.key --keyid rg-ci --out admission.signed.json
```

The evidence in `release.jsonl` names the state it was about. With an explicit
candidate, evidence that names no state holds the release (RG-DRIFT-008),
because nothing shows it was about this one.

## 3. Run the agent

```bash
python examples/runtime/agent.py --admission /tmp/admission.signed.json \
  --trusted-keys /tmp/trusted-keys.json --log /tmp/decisions.json
```

```text
admitted          state sha256:0267fcae8e32…
ALLOW             get_balance: get_balance is admitted
NEEDS_APPROVAL    transfer_funds: transfer_funds is irreversible or requires approval under the admitted policy: a named person must approve this call
ALLOW             transfer_funds: transfer_funds is admitted, approved by ops-oncall@payments.example
DENY              close_account: close_account is refused by the admitted policy's trace_policies: it is in forbidden_tools
DENY              wire_offshore: wire_offshore is not in the admitted tool manifest
ALLOW             model: frontier-model-2026-03-01 is the admitted model
```

`/tmp/decisions.json` is a native trace of every decision. `release-gate verify
examples/runtime/governance.yaml --trace /tmp/decisions.json` passes: the
forbidden call was refused, so it never became a `tool_call`.

## 4. Change the prompt, and it will not start

Add a line to `system.txt` and run step 3 again. The gate refuses before any
call, because the prompt is not the one admitted:

```text
REFUSED TO START  not admitted (MISMATCH): prompt is sha256:… in the deployment and sha256:… in the admitted state
```

The same happens when a tool's description changes or a tool is added. When
the provider reports a different model, `check_model` refuses and the gate
closes. Create the halt file (`--halt-file`), or call `gate.halt(...)`, and every
later call is denied.

`tests/test_runtime_example.py` runs all of this on every change.

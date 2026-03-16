# 🔗 Integration Guide

This guide explains how release-gate integrates with other tools in your AI stack.

---

## The Relationship Model

### release-gate's Role
```
Testing Platform (LangWatch, etc.)
         ↓
    Evidence Generated
         ↓
release-gate Decision Engine
         ↓
   PASS → Deploy
   WARN → Review
   FAIL → Block
```

release-gate is the **decision layer** that says yes/no to deployment based on governance policies.

---

## Integration with LangWatch

### The Story
1. **LangWatch tests your agent** - Simulations, evaluations, traces
2. **release-gate gates deployment** - Checks governance policies
3. **Together they ensure** - Safe AND properly governed

### How It Works

#### Step 1: LangWatch Tests Agent Behavior

```bash
# LangWatch: Run tests and evaluations
python -m langwatch eval --agent my_agent --dataset test_cases.json

# Outputs: eval_results.json with scores
```

#### Step 2: release-gate Checks Governance

```bash
# release-gate: Check if deployment is allowed
python cli.py run --config release-gate.yaml

# Checks:
# ✓ Request contract is validated
# ✓ Operational safeguards declared
```

#### Step 3: Combined Decision

```bash
# Decision logic
if langwatch_score >= 0.95 AND release_gate_status == "PASS":
  deploy_to_production()
elif langwatch_score >= 0.90 AND release_gate_status == "WARN":
  send_for_approval()
else:
  block_deployment()
```

### Example Workflow

```yaml
# release-gate.yaml
project:
  name: my-agent

checks:
  input_contract:
    enabled: true
    schema: {...}
    samples:
      valid_path: valid_requests.jsonl
      invalid_path: invalid_requests.jsonl

  fallback_declared:
    enabled: true
    kill_switch: {...}
    fallback: {...}
    ownership: {...}
    runbook_url: https://...

  # Future: Accept LangWatch evidence
  # eval_score:
  #   enabled: true
  #   min_score: 0.95
  #   langwatch_report: langwatch_results.json
```

### CI/CD Integration

```yaml
# GitHub Actions example
- name: LangWatch - Test Agent Behavior
  run: |
    pip install langwatch
    python -m langwatch eval --agent my_agent --output eval_results.json

- name: release-gate - Check Governance
  run: |
    pip install pyyaml jsonschema
    python cli.py run --config release-gate.yaml --output governance_report.json

- name: Deployment Decision
  run: |
    # Custom script that reads both reports
    python .github/scripts/deployment_decision.py \
      --eval_report eval_results.json \
      --governance_report governance_report.json
```

---

## Integration with LangChain

### Before Deployment

```python
from langchain.agents import AgentType, initialize_agent
from release_gate import check_governance

# Step 1: Define your agent
agent = initialize_agent(
    tools=tools,
    llm=llm,
    agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
)

# Step 2: Check governance before deploying
governance_result = check_governance(
    config_file="release-gate.yaml",
    agent_definition=agent,
)

# Step 3: Only deploy if governance passes
if governance_result["overall"] == "PASS":
    deploy_agent(agent)
else:
    print(f"Governance check failed: {governance_result}")
```

### Runtime Validation

```python
from release_gate.validators import validate_request

# Validate incoming requests against governance
def agent_handler(request):
    # Check request matches contract
    validation = validate_request(
        request=request,
        schema_file="release-gate.yaml",
    )
    
    if not validation["valid"]:
        return {"error": "Invalid request"}
    
    # Execute agent
    return agent.run(request)
```

---

## Integration with MLflow

### Track Governance in Model Registry

```python
import mlflow
from release_gate import run_gate

# Log governance check results with model
mlflow.start_run()

# Run governance checks
governance_report = run_gate(
    config="release-gate.yaml",
    output_format="json"
)

# Log as artifact
mlflow.log_dict(
    governance_report,
    "governance_report.json"
)

# Tag model with governance status
mlflow.set_tag("governance_status", governance_report["overall"])
mlflow.set_tag("governance_version", "v0.1")

mlflow.end_run()
```

### Model Registry Integration

```python
# When registering model
from mlflow.tracking import MlflowClient

client = MlflowClient()
client.create_model_version(
    name="my-agent",
    source=model_uri,
    tags={
        "governance_passed": "true",
        "governance_checks": "input_contract,fallback_declared",
        "audited": "true",
    }
)
```

---

## Integration with Kubernetes

### Admission Controller

```yaml
# k8s-admission-controller.yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: release-gate-validator
webhooks:
- name: validate-agent-deployment
  clientConfig:
    service:
      name: release-gate-validator
      namespace: default
      path: "/validate"
    caBundle: LS0tLS1CRUdJTi...
  rules:
  - operations: ["CREATE", "UPDATE"]
    apiGroups: ["ai.example.com"]
    apiVersions: ["v1"]
    resources: ["agents"]
  admissionReviewVersions: ["v1"]
  sideEffects: None
```

**How it works:**
1. User tries to deploy agent to Kubernetes
2. Admission controller intercepts request
3. Calls release-gate validation
4. Blocks deployment if governance fails

---

## Integration with ArgoCD

### Pre-Deployment Gate

```yaml
# argocd-app.yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: my-agent
spec:
  project: default
  
  # Sync happens AFTER pre-sync hooks
  syncPolicy:
    syncOptions:
    - CreateNamespace=true
    
    # Pre-sync hook: Run governance checks
    hooks:
    - preSync:
        container:
          image: release-gate:latest
          command:
          - python
          - cli.py
          - run
          - --config
          - release-gate.yaml
          volumeMounts:
          - name: config
            mountPath: /config
```

---

## Integration with GitHub Actions

### Complete CI/CD Pipeline

```yaml
# .github/workflows/deploy-agent.yml
name: Deploy Agent

on:
  push:
    branches: [main]
    tags: ['v*']

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      # Step 1: Unit tests
      - name: Run unit tests
        run: pytest tests/
      
      # Step 2: LangWatch evaluations
      - name: Run agent evaluations
        run: |
          pip install langwatch
          python -m langwatch eval --agent my_agent --output eval.json
      
      # Step 3: release-gate governance
      - name: Check governance
        run: |
          pip install pyyaml jsonschema
          python cli.py run --config release-gate.yaml --output governance.json
      
      # Step 4: Deployment decision
      - name: Decide deployment
        id: decide
        run: |
          python .github/scripts/deployment_check.py
      
      # Step 5: Deploy (only if checks pass)
      - name: Deploy to production
        if: steps.decide.outputs.should_deploy == 'true'
        run: |
          # Deploy command
          kubectl apply -f deployment.yaml

  audit:
    runs-on: ubuntu-latest
    needs: test
    steps:
      - uses: actions/checkout@v3
      
      - name: Generate audit report
        run: |
          python .github/scripts/generate_audit_report.py
      
      - name: Upload audit artifact
        uses: actions/upload-artifact@v3
        with:
          name: governance-audit
          path: audit-report.json
```

---

## Integration with DataDog/Monitoring

### Log Governance Events

```python
from datadog import initialize, api
from release_gate import run_gate

# Initialize DataDog
options = {
    'api_key': os.environ['DD_API_KEY'],
    'app_key': os.environ['DD_APP_KEY']
}
initialize(**options)

# Run governance check
report = run_gate("release-gate.yaml")

# Send to DataDog
api.Monitor.create(
    type="metric alert",
    query=f"avg:release_gate.checks{{status:{report['overall']}}} > 0",
    name="release-gate governance check",
    message=f"Governance status: {report['overall']}",
    tags=["governance", f"project:{report['project']['name']}"]
)

# Log detailed events
for check in report['checks']:
    api.Event.create(
        title=f"Governance Check: {check['name']}",
        text=f"Result: {check['result']}",
        tags=["governance", check['name']]
    )
```

---

## Integration with Incident Management (PagerDuty)

### Governance-Based Alerting

```python
from pdpyras import APISession
from release_gate import run_gate

session = APISession(token=PD_API_TOKEN)

# Run governance check
report = run_gate("release-gate.yaml")

# If critical failure, trigger incident
if report['overall'] == 'FAIL':
    incident = session.post(
        '/incidents',
        json={
            'incident': {
                'type': 'incident',
                'title': f"Agent Deployment Blocked: {report['project']['name']}",
                'service': {
                    'id': service_id,
                    'type': 'service_reference'
                },
                'urgency': 'high',
                'body': {
                    'type': 'incident_body',
                    'details': json.dumps(report)
                }
            }
        }
    )
```

---

## Integration with Custom Systems

### Generic Integration Pattern

**Step 1: Export release-gate report**
```bash
python cli.py run --config release-gate.yaml --output report.json
```

**Step 2: Read in your system**
```python
import json

with open('report.json') as f:
    report = json.load(f)

# Use report data
if report['overall'] == 'PASS':
    your_system.deploy()
```

**Step 3: Make deployment decision**
```python
decision_logic = {
    'PASS': 'deploy',
    'WARN': 'require_approval',
    'FAIL': 'block'
}

action = decision_logic[report['overall']]
```

---

## Integration Best Practices

### 1. **Run Early in Pipeline**
```
Code Commit → Unit Tests → release-gate Check → LangWatch Eval → Deploy
                           ↑
                      Run early to fail fast
```

### 2. **Log Evidence**
Always capture governance reports as artifacts.

```yaml
- name: Upload governance report
  uses: actions/upload-artifact@v3
  with:
    name: governance-${{ github.run_id }}
    path: governance_report.json
```

### 3. **Make Decisions Explicit**
Don't hide governance decisions in logging. Make them explicit in CI/CD.

```bash
# Good: Explicit decision
if governance_passed && eval_score >= 0.95:
  deploy()

# Bad: Hidden in logs
log("checking governance...")
deploy()  # Maybe governance passed, maybe not
```

### 4. **Version Governance Policies**
Track changes to governance policies in git.

```bash
git log release-gate.yaml
# Shows governance policy evolution
```

### 5. **Audit Trail**
Keep records of every deployment decision.

```json
{
  "deployment_id": "v1.2.3",
  "timestamp": "2026-03-16T10:30:00Z",
  "governance_report": {...},
  "eval_results": {...},
  "decision": "APPROVED",
  "approved_by": "platform-team",
  "runbook": "https://wiki/runbooks/deployment"
}
```

---

## Example: Complete Enterprise Setup

```
┌─────────────────────────────────────────────┐
│       Developer Commits Agent Code           │
└────────────┬────────────────────────────────┘
             │
             ↓
┌─────────────────────────────────────────────┐
│    GitHub Actions CI/CD Pipeline Triggers   │
└────────────┬────────────────────────────────┘
             │
     ┌───────┴────────┐
     ↓                ↓
  ┌──────────┐   ┌──────────────┐
  │ Unit     │   │ Integration  │
  │ Tests    │   │ Tests        │
  └────┬─────┘   └──────┬───────┘
       │                │
       └────────┬───────┘
                ↓
    ┌──────────────────────┐
    │  LangWatch Evals     │
    │ Tests agent behavior │
    │ Outputs: scores      │
    └────────┬─────────────┘
             │
             ↓
    ┌──────────────────────┐
    │ release-gate Check   │
    │ Tests governance     │
    │ Outputs: PASS/WARN   │
    └────────┬─────────────┘
             │
    ┌────────┴────────┐
    ↓                 ↓
┌────────────┐  ┌──────────────┐
│  Decision  │  │ Audit Report │
│  Logic     │  │ Logged to DB  │
└────┬───────┘  └──────────────┘
     │
     ├─→ PASS: Deploy automatically
     ├─→ WARN: Send for approval
     └─→ FAIL: Block deployment

┌──────────────────────────────────┐
│  Deploy to Production (if PASS)   │
│  - K8s deployment                 │
│  - Fire governance event to DD    │
│  - Update ML registry in MLflow   │
└──────────────────────────────────┘
```

---

## Roadmap: Future Integrations

- [ ] LangWatch native integration
- [ ] Kubernetes admission controller
- [ ] ArgoCD plugin
- [ ] GitHub integration (checks on PRs)
- [ ] GitLab CI integration
- [ ] Jenkins plugin
- [ ] Slack notifications
- [ ] DataDog monitoring
- [ ] Prometheus metrics
- [ ] OpenTelemetry tracing
- [ ] Custom webhook support

---

## Getting Help

- 📖 [EXTENDED_README](EXTENDED_README.md) - Comprehensive guide
- 🏗️ [ARCHITECTURE](ARCHITECTURE.md) - How it works
- 💬 [GitHub Issues](https://github.com/VamsiSudhakaran1/release-gate/issues) - Ask questions

---

**release-gate integrates with your entire stack to enforce governance.** 🔗

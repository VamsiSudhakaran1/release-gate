#!/usr/bin/env python
"""
release-gate init - Interactive setup wizard for new projects
Creates all necessary governance files and CI/CD integration
"""

import os
import sys
import json
from pathlib import Path


class InitWizard:
    """Interactive initialization wizard for release-gate"""
    
    def __init__(self):
        self.project_name = None
        self.agent_model = None
        self.max_daily_cost = None
        self.requests_per_day = None
        self.tokens_per_request = None
        self.team_owner = None
        self.runbook_url = None
        self.ci_platform = None
        self.output_dir = Path(".")
    
    def clear_screen(self):
        """Clear terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def print_header(self):
        """Print welcome header"""
        print("\n" + "="*70)
        print("🚪 release-gate: Project Initialization Wizard")
        print("="*70)
        print("\nWelcome! Let's set up governance for your AI agent.\n")
    
    def prompt_input(self, question, default=None, input_type=str):
        """Prompt user for input with optional default"""
        if default is not None:
            prompt = f"{question} [{default}]: "
        else:
            prompt = f"{question}: "
        
        while True:
            response = input(prompt).strip()
            
            if not response:
                if default is not None:
                    return default
                else:
                    print("  ⚠️ Please provide a value")
                    continue
            
            try:
                if input_type == int:
                    return int(response)
                elif input_type == float:
                    return float(response)
                else:
                    return response
            except ValueError:
                print(f"  ⚠️ Invalid input. Expected {input_type.__name__}")
    
    def prompt_choice(self, question, choices):
        """Prompt user to choose from options"""
        print(f"\n{question}")
        for i, choice in enumerate(choices, 1):
            print(f"  {i}. {choice}")
        
        while True:
            response = self.prompt_input("Select option", input_type=int)
            if 1 <= response <= len(choices):
                return choices[response - 1]
            print(f"  ⚠️ Please select a number between 1 and {len(choices)}")
    
    def run(self):
        """Run the initialization wizard"""
        self.clear_screen()
        self.print_header()
        
        # Step 1: Project Details
        print("📋 STEP 1: Project Details")
        print("-" * 70)
        self.project_name = self.prompt_input(
            "Project name",
            default="my-agent"
        )
        print(f"  ✓ Project: {self.project_name}")
        
        # Step 2: Agent Model
        print("\n🤖 STEP 2: Agent Configuration")
        print("-" * 70)
        models = [
            "gpt-4-turbo (OpenAI)",
            "gpt-4 (OpenAI)",
            "gpt-3.5-turbo (OpenAI)",
            "claude-3-opus (Anthropic)",
            "claude-3-sonnet (Anthropic)",
            "claude-3-haiku (Anthropic)",
            "gemini-2.0-flash (Google)",
            "grok-2 (XAI)",
            "grok-3 (XAI)",
        ]
        
        choice = self.prompt_choice("Select AI model", models)
        self.agent_model = choice.split(" ")[0]
        print(f"  ✓ Model: {self.agent_model}")
        
        # Step 3: Budget
        print("\n💰 STEP 3: Budget Configuration")
        print("-" * 70)
        self.max_daily_cost = self.prompt_input(
            "Max daily cost (USD)",
            default="100",
            input_type=float
        )
        print(f"  ✓ Budget: ${self.max_daily_cost:.2f}/day")
        
        # Step 4: Usage Simulation
        print("\n📊 STEP 4: Usage Simulation (for cost projection)")
        print("-" * 70)
        self.requests_per_day = self.prompt_input(
            "Expected requests per day",
            default="1000",
            input_type=int
        )
        print(f"  ✓ Requests: {self.requests_per_day}/day")
        
        input_tokens = self.prompt_input(
            "Average input tokens per request",
            default="800",
            input_type=int
        )
        output_tokens = self.prompt_input(
            "Average output tokens per request",
            default="400",
            input_type=int
        )
        self.tokens_per_request = {
            "input": input_tokens,
            "output": output_tokens
        }
        print(f"  ✓ Tokens: {input_tokens} input, {output_tokens} output")
        
        # Step 5: Safety
        print("\n🛡️ STEP 5: Safety Configuration")
        print("-" * 70)
        self.team_owner = self.prompt_input(
            "Team owner (for fallback/oncall)",
            default="platform-team"
        )
        print(f"  ✓ Team owner: {self.team_owner}")
        
        self.runbook_url = self.prompt_input(
            "Runbook/documentation URL",
            default="https://wiki.example.com/runbook"
        )
        print(f"  ✓ Runbook: {self.runbook_url}")
        
        # Step 6: CI/CD Platform
        print("\n🔄 STEP 6: CI/CD Integration")
        print("-" * 70)
        self.ci_platform = self.prompt_choice(
            "Select CI/CD platform",
            ["GitHub Actions", "GitLab CI", "Jenkins", "Other / Manual"]
        )
        print(f"  ✓ CI/CD: {self.ci_platform}")
        
        # Summary
        print("\n" + "="*70)
        print("✅ Configuration Complete!")
        print("="*70)
        print(f"\nProject: {self.project_name}")
        print(f"Model: {self.agent_model}")
        print(f"Budget: ${self.max_daily_cost:.2f}/day")
        print(f"Requests: {self.requests_per_day}/day")
        print(f"Team: {self.team_owner}")
        print(f"CI/CD: {self.ci_platform}")
        
        # Generate files
        print("\n📝 Generating files...")
        self.generate_governance_yaml()
        self.generate_ci_cd_config()
        self.generate_readme()
        self.generate_gitignore()
        
        print("\n" + "="*70)
        print("🚀 Setup Complete!")
        print("="*70)
        print(f"\n✓ Created governance.yaml")
        print(f"✓ Created .release-gate/ directory")
        print(f"✓ Created CI/CD config for {self.ci_platform}")
        print(f"✓ Created GOVERNANCE.md documentation")
        print(f"\nNext steps:")
        print(f"  1. Review governance.yaml")
        print(f"  2. Commit files to git")
        print(f"  3. Push to repository")
        print(f"  4. Test with: release-gate run governance.yaml")
        print(f"\nDocumentation: https://github.com/VamsiSudhakaran1/release-gate")
        print("="*70 + "\n")
    
    def generate_governance_yaml(self):
        """Generate governance.yaml"""
        content = f"""project:
  name: {self.project_name}
  description: "AI agent governance configuration"

agent:
  model: {self.agent_model}
  daily_requests: {self.requests_per_day}

policy:
  fail_on:
    - ACTION_BUDGET
    - BUDGET_SIMULATION
    - FALLBACK_DECLARED
    - IDENTITY_BOUNDARY
  warn_on:
    - INPUT_CONTRACT

checks:
  # Check 1: Cost limits
  action_budget:
    enabled: true
    max_daily_cost: {self.max_daily_cost}

  # Check 2: Realistic cost projection
  budget_simulation:
    enabled: true
    simulation:
      requests_per_day: {self.requests_per_day}
      tokens_per_request:
        input: {self.tokens_per_request['input']}
        output: {self.tokens_per_request['output']}
      factors:
        retry_rate: 1.2        # 20% retries
        cache_hit_rate: 0.3    # 30% cache hits
        spiky_usage_multiplier: 1.5  # Peak is 50% higher

  # Check 3: Safety measures
  fallback_declared:
    enabled: true
    kill_switch:
      type: "feature-flag"
      location: "config/kill-switches"
    fallback_mode: "escalate-to-human"
    team_owner: "{self.team_owner}"
    runbook_url: "{self.runbook_url}"

  # Check 4: Access control
  identity_boundary:
    enabled: true
    authentication:
      required: true
      type: "oauth2"
    rate_limit:
      requests_per_minute: 10
    data_isolation:
      - "customer_id isolation"

  # Check 5: Input validation
  input_contract:
    enabled: true
    schema:
      type: "object"
      required:
        - "user_query"
      properties:
        user_query:
          type: "string"
          minLength: 1
    samples:
      valid:
        - user_query: "What is the weather?"
      invalid:
        - user_query: ""
"""
        
        Path("governance.yaml").write_text(content)
    
    def generate_ci_cd_config(self):
        """Generate CI/CD configuration"""
        os.makedirs(".release-gate", exist_ok=True)
        
        if self.ci_platform == "GitHub Actions":
            content = """name: release-gate Governance Check
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  governance:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      
      - name: Install release-gate
        run: pip install release-gate
      
      - name: Run governance checks
        run: release-gate run governance.yaml
      
      - name: Save evidence (optional)
        if: always()
        run: release-gate run governance.yaml --output-evidence governance-evidence.json
      
      - name: Upload evidence
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: governance-evidence
          path: governance-evidence.json

  # Optional: Comment on PR with results
  comment-on-pr:
    needs: governance
    runs-on: ubuntu-latest
    if: github.event_name == 'pull_request'
    steps:
      - name: Comment on PR
        uses: actions/github-script@v6
        with:
          script: |
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: '✅ Governance checks passed!'
            })
"""
            filename = ".github/workflows/release-gate.yml"
            os.makedirs(".github/workflows", exist_ok=True)
            Path(filename).write_text(content)
            
        elif self.ci_platform == "GitLab CI":
            content = """stages:
  - validate

governance:
  stage: validate
  image: python:3.10
  script:
    - pip install release-gate
    - release-gate run governance.yaml
  artifacts:
    reports:
      dotenv: governance-report.env
    paths:
      - governance-evidence.json
    when: always
  allow_failure: false
  only:
    - merge_requests
    - main
"""
            Path(".gitlab-ci.yml").write_text(content)
        
        elif self.ci_platform == "Jenkins":
            content = """pipeline {
    agent any
    
    stages {
        stage('Governance') {
            steps {
                script {
                    sh '''
                        python -m pip install release-gate
                        release-gate run governance.yaml
                    '''
                }
            }
        }
    }
    
    post {
        always {
            sh 'release-gate run governance.yaml --output-evidence governance-evidence.json || true'
            archiveArtifacts artifacts: 'governance-evidence.json', allowEmptyArchive: true
        }
    }
}
"""
            Path("Jenkinsfile").write_text(content)
    
    def generate_readme(self):
        """Generate GOVERNANCE.md documentation"""
        content = f"""# Governance Configuration for {self.project_name}

This project uses **release-gate** for AI agent governance.

## Overview

release-gate validates your agent configuration before deployment with 5 checks:

1. **ACTION_BUDGET** - Cost limits
2. **BUDGET_SIMULATION** - Realistic cost projections
3. **FALLBACK_DECLARED** - Safety measures
4. **IDENTITY_BOUNDARY** - Access control
5. **INPUT_CONTRACT** - Input validation

## Configuration

The governance configuration is defined in `governance.yaml`.

### Key Settings

- **Model**: {self.agent_model}
- **Budget**: ${self.max_daily_cost:.2f}/day
- **Expected Requests**: {self.requests_per_day}/day
- **Team Owner**: {self.team_owner}
- **Runbook**: {self.runbook_url}

## Running Validation

### Local Testing

```bash
# Install release-gate
pip install release-gate

# Run validation
release-gate run governance.yaml
```

### Exit Codes

- **0** - PASS: All required checks passed — meets the configured release policy
- **10** - WARN: Non-critical checks failed, needs review
- **1** - FAIL: Critical checks failed, blocks the release

## Customizing Governance

### Change Budget

Edit `governance.yaml`:

```yaml
checks:
  action_budget:
    max_daily_cost: 50  # Change to desired limit
```

### Change Policy

Define what's critical vs flexible:

```yaml
policy:
  fail_on:
    - ACTION_BUDGET        # These must pass
    - FALLBACK_DECLARED
  warn_on:
    - IDENTITY_BOUNDARY    # These warn if failed
    - INPUT_CONTRACT
```

### Add Custom Checks

Create check-specific files in `.release-gate/` directory.

## CI/CD Integration

Governance checks run automatically in CI/CD pipeline:

- On every push to main/develop
- On pull requests
- Results available as artifacts
- Blocks deployment if critical checks fail

## Troubleshooting

### Check fails: "Daily cost exceeds budget"

Adjust one of:
1. Reduce `max_daily_cost` to match expectations
2. Reduce `requests_per_day` in simulation
3. Optimize token usage

### Check fails: "Fallback not declared"

Add fallback configuration:

```yaml
checks:
  fallback_declared:
    fallback_mode: "escalate-to-human"
    team_owner: "{self.team_owner}"
    runbook_url: "{self.runbook_url}"
```

### Check fails: "Authentication not required"

Enable authentication:

```yaml
checks:
  identity_boundary:
    authentication:
      required: true
      type: "oauth2"
```

## Resources

- **GitHub**: https://github.com/VamsiSudhakaran1/release-gate
- **PyPI**: https://pypi.org/project/release-gate/
- **Documentation**: https://github.com/VamsiSudhakaran1/release-gate#readme

## Contact

For questions or issues, open an issue on GitHub or email vamsi.sudhakaran@gmail.com.
"""
        Path("GOVERNANCE.md").write_text(content)
    
    def generate_gitignore(self):
        """Add release-gate entries to .gitignore"""
        gitignore_content = """# release-gate
governance-evidence.json
.release-gate/cache/
*.pyc
__pycache__/
"""
        
        gitignore_path = Path(".gitignore")
        if gitignore_path.exists():
            existing = gitignore_path.read_text()
            if "release-gate" not in existing:
                gitignore_path.write_text(existing + "\n" + gitignore_content)
        else:
            gitignore_path.write_text(gitignore_content)


def init_main():
    """Main entry point for release-gate init"""
    if len(sys.argv) > 1 and sys.argv[1] == 'init':
        wizard = InitWizard()
        try:
            wizard.run()
        except KeyboardInterrupt:
            print("\n\n❌ Setup cancelled.")
            sys.exit(1)
        except Exception as e:
            print(f"\n\n❌ Error: {e}")
            sys.exit(1)
    else:
        print("Usage: release-gate init")


if __name__ == '__main__':
    init_main()

# Deployment Guide

## Installation
```bash
git clone https://github.com/VamsiSudhakaran1/release-gate_claude.git
cd release-gate_claude
pip install -r requirements.txt
```

## Quick Start
```bash
python cli.py init --project my-system
python cli.py run --config release-gate.yaml --format text
```

## CI/CD Integration

### GitHub Actions
```yaml
name: Deployment Gate

on: [push, pull_request]

jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - run: pip install -r requirements.txt
      - run: python cli.py run --config release-gate.yaml
```

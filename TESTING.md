# Testing release-gate

## Quick Test
```bash
pip install -r requirements.txt
python cli.py init --project test
python cli.py run --config release-gate.yaml --format text
```

## Expected Output
```
Overall: ✓ PASS
```

## With Example Config
```bash
python cli.py run --config example-config.yaml --format text
```

## Generate JSON Report
```bash
python cli.py run --config release-gate.yaml --format json
```

Creates `readiness_report.json`

## Troubleshooting

**"pyyaml not installed"**
```bash
pip install -r requirements.txt
```

**"Config file not found"**
- Make sure file path is correct

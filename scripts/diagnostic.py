"""Diagnostic script to check Budget Simulation setup"""

import sys
import os

print("=" * 70)
print("BUDGET SIMULATION SETUP DIAGNOSTIC")
print("=" * 70)

# Check 1: File exists
print("\n1. Checking if files exist...")
files_to_check = [
    ('release_gate/pricing/budget_simulator.py', 'Budget Simulator'),
    ('release_gate/pricing/__init__.py', 'Pricing __init__'),
    ('release_gate/cli.py', 'CLI'),
]

for filepath, name in files_to_check:
    exists = os.path.exists(filepath)
    print(f"   {name}: {'✓' if exists else '✗'} {filepath}")

# Check 2: Can import budget simulator
print("\n2. Checking imports...")
try:
    from release_gate.pricing.budget_simulator import BudgetSimulationCheck
    print("   BudgetSimulationCheck import: ✓")
except ImportError as e:
    print(f"   BudgetSimulationCheck import: ✗ {e}")
except Exception as e:
    print(f"   BudgetSimulationCheck import: ✗ {e}")

# Check 3: Check CLI imports
print("\n3. Checking CLI imports...")
try:
    with open('release_gate/cli.py', 'r') as f:
        cli_content = f.read()
        
    if 'BudgetSimulationCheck' in cli_content:
        print("   BudgetSimulationCheck in CLI: ✓")
    else:
        print("   BudgetSimulationCheck in CLI: ✗ (not found in cli.py)")
    
    if 'BUDGET_SIMULATOR_AVAILABLE' in cli_content:
        print("   BUDGET_SIMULATOR_AVAILABLE: ✓")
    else:
        print("   BUDGET_SIMULATOR_AVAILABLE: ✗")
    
    if "checks_config.get('budget_simulation'" in cli_content:
        print("   budget_simulation check: ✓")
    else:
        print("   budget_simulation check: ✗")
        
except Exception as e:
    print(f"   Error reading CLI: {e}")

# Check 4: Check config
print("\n4. Checking governance-working.yaml...")
try:
    import yaml
    with open('governance-working.yaml', 'r') as f:
        config = yaml.safe_load(f)
    
    if 'budget_simulation' in config.get('checks', {}):
        print("   budget_simulation in checks: ✓")
        print(f"   Enabled: {config['checks']['budget_simulation'].get('enabled', False)}")
    else:
        print("   budget_simulation in checks: ✗")
    
    if 'BUDGET_SIMULATION' in config.get('policy', {}).get('fail_on', []):
        print("   BUDGET_SIMULATION in policy fail_on: ✓")
    else:
        print("   BUDGET_SIMULATION in policy fail_on: ✗")
        
except Exception as e:
    print(f"   Error reading config: {e}")

# Check 5: Try running the check directly
print("\n5. Testing BudgetSimulationCheck directly...")
try:
    from release_gate.pricing.budget_simulator import BudgetSimulationCheck
    import yaml
    
    with open('governance-working.yaml', 'r') as f:
        config = yaml.safe_load(f)
    
    check = BudgetSimulationCheck()
    result = check.evaluate(config)
    
    print(f"   Check result: {result.get('status')}")
    print(f"   Evidence: {result.get('evidence', {}).get('daily_cost', 'N/A')}")
    
except Exception as e:
    print(f"   Error: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "=" * 70)
print("END DIAGNOSTIC")
print("=" * 70)

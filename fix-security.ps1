# Security and Safety Fixes for Purple Lab
# Run from C:\Users\kewme\purple-lab

Write-Host "`n====================================" -ForegroundColor Red
Write-Host " CRITICAL SECURITY FIXES" -ForegroundColor Yellow
Write-Host "====================================`n" -ForegroundColor Red

# Fix 1: Create comprehensive .gitignore
Write-Host "[*] Creating secure .gitignore..." -ForegroundColor Green
@'
# Sensitive Information - NEVER COMMIT
*.pem
*.key
*.pfx
*.p12
*.cer
*.crt
secrets.local
secrets.json
credentials.txt
passwords.txt

# Local inventory - use examples instead
inventory/pis.local.csv
inventory/real_*.csv
inventory/*_prod.csv

# Test outputs that may contain sensitive data
*.log
*.pcap
*.dmp
atomic_tests_*.log
recon_results_*/

# IDE and OS files
.vscode/
.idea/
*.swp
.DS_Store
Thumbs.db

# Python
__pycache__/
*.pyc
.pytest_cache/
venv/
env/

# Docker
.env
docker-compose.override.yml

# Temporary files
*.tmp
*.bak
*.backup
~*
'@ | Set-Content -Path ".gitignore"
Write-Host "    Created: Secure .gitignore" -ForegroundColor Gray

# Fix 2: Add SECURITY.md with warnings
Write-Host "`n[*] Creating SECURITY.md..." -ForegroundColor Green
@'
# ⚠️ SECURITY WARNING

## CRITICAL SAFETY INFORMATION

### 🔴 NEVER Run in Production
This repository contains **INTENTIONALLY VULNERABLE** applications and **DESTRUCTIVE** testing tools.

### Vulnerable Applications Safety
**All vulnerable apps MUST be run with these precautions:**

1. **Network Isolation**
   - ONLY bind to `127.0.0.1` (localhost)
   - NEVER expose to `0.0.0.0` or public IPs
   - Run in isolated VLAN or VM with snapshots

2. **Docker Safety**
   ```bash
   # SAFE - Localhost only
   docker run -p 127.0.0.1:5000:5000 vulnerable-app
   
   # DANGEROUS - Never do this
   docker run -p 0.0.0.0:5000:5000 vulnerable-app
   ```

### Atomic Red Team Safety
**NEVER run atomic tests without:**
1. Taking VM snapshots first
2. Running in isolated environment
3. Using `-ShowDetails` flag first to review
4. Understanding the impact

```powershell
# SAFE - Review first
Invoke-AtomicTest T1003 -ShowDetails

# DANGEROUS - Only after review and in isolated lab
Invoke-AtomicTest T1003
```

### Secrets Management
- NEVER commit real IPs, passwords, or API keys
- Use `.example` files for templates
- Check `.gitignore` before every commit

### Responsible Disclosure
Found a real vulnerability? Contact: security@example.com

## Lab Environment Requirements
- Isolated network segment
- VM snapshots before testing
- No production data
- Regular security audits

## Legal Notice
This repository is for educational purposes only. Users are responsible for complying with all applicable laws and regulations.
'@ | Set-Content -Path "SECURITY.md"
Write-Host "    Created: SECURITY.md with warnings" -ForegroundColor Gray

# Fix 3: Create safe inventory example
Write-Host "`n[*] Creating safe inventory template..." -ForegroundColor Green
@'
# Example Inventory Template - Copy to pis.local.csv and customize
# DO NOT commit real inventory files!
hostname,role,vlan_id,ip,mac,notes
pi-example-1,test-target,99,10.0.99.10,AA:BB:CC:DD:EE:FF,Example entry only
pi-example-2,monitoring,99,10.0.99.11,AA:BB:CC:DD:EE:00,Replace with real values locally
'@ | Set-Content -Path "inventory/pis.local.csv.example"
Write-Host "    Created: Safe inventory template" -ForegroundColor Gray

# Fix 4: Update vulnerable app with safety checks
Write-Host "`n[*] Adding safety wrapper for vulnerable apps..." -ForegroundColor Green
New-Item -ItemType Directory -Force -Path "vuln-apps/safety" | Out-Null

@'
#!/bin/bash
# Safe launcher for vulnerable applications

echo "================================================"
echo "⚠️  SECURITY WARNING - VULNERABLE APPLICATION ⚠️"
echo "================================================"
echo ""
echo "This application is INTENTIONALLY VULNERABLE!"
echo ""
echo "Safety checklist:"
echo "[ ] Running in isolated VM/container?"
echo "[ ] Network is isolated/firewalled?"
echo "[ ] VM snapshot taken?"
echo "[ ] No production data present?"
echo ""
read -p "Type 'I UNDERSTAND THE RISKS' to continue: " confirmation

if [ "$confirmation" != "I UNDERSTAND THE RISKS" ]; then
    echo "Aborted for safety. Please review SECURITY.md"
    exit 1
fi

echo ""
echo "Starting vulnerable app on 127.0.0.1 ONLY..."
echo "Press Ctrl+C to stop"
echo ""

# Force localhost binding
docker run --rm -p 127.0.0.1:5000:5000 --name vuln-app-safe vulnerable-app
'@ | Set-Content -Path "vuln-apps/safety/safe_run.sh"
Write-Host "    Created: Safe launcher script" -ForegroundColor Gray

# Fix 5: Create proper Sigma validation script
Write-Host "`n[*] Creating Sigma validation script..." -ForegroundColor Green
@'
#!/usr/bin/env python3
"""
Sigma Rule Validator - Ensures rules are properly formatted
"""
import os
import sys
import yaml
from pathlib import Path

REQUIRED_FIELDS = ['title', 'id', 'status', 'description', 'detection', 'logsource']
REQUIRED_DETECTION_FIELDS = ['condition']

def validate_sigma_rule(file_path):
    """Validate a single Sigma rule file"""
    errors = []
    warnings = []
    
    try:
        with open(file_path, 'r') as f:
            rule = yaml.safe_load(f)
    except yaml.YAMLError as e:
        return [f"YAML parse error: {e}"], []
    
    # Check required top-level fields
    for field in REQUIRED_FIELDS:
        if field not in rule:
            errors.append(f"Missing required field: {field}")
    
    # Check detection structure
    if 'detection' in rule:
        detection = rule['detection']
        if 'condition' not in detection:
            errors.append("Detection missing 'condition' field")
        
        # Check for complex conditions that may not be portable
        if 'condition' in detection:
            condition = detection['condition']
            if 'count()' in str(condition):
                warnings.append("count() aggregation may not be supported by all backends")
            if '| by ' in str(condition):
                warnings.append("Group-by operations may require specific backend support")
    
    # Check ID format
    if 'id' in rule:
        rule_id = rule['id']
        if not isinstance(rule_id, str) or len(rule_id) != 36:
            warnings.append(f"ID should be UUID format, got: {rule_id}")
    
    # Check for potentially high FP patterns
    if 'detection' in rule:
        detection_str = str(rule['detection'])
        if 'CommandLine|contains' in detection_str:
            if not rule.get('filter') and not 'not ' in str(rule['detection'].get('condition', '')):
                warnings.append("CommandLine detection without filters may cause high FPs")
    
    return errors, warnings

def main():
    """Main validation function"""
    sigma_dir = Path('detections/sigma')
    
    if not sigma_dir.exists():
        print(f"Error: {sigma_dir} directory not found")
        sys.exit(1)
    
    total_rules = 0
    failed_rules = 0
    rules_with_warnings = 0
    
    print("Validating Sigma rules...\n")
    
    for rule_file in sigma_dir.rglob('*.yml'):
        total_rules += 1
        relative_path = rule_file.relative_to(sigma_dir)
        
        errors, warnings = validate_sigma_rule(rule_file)
        
        if errors:
            failed_rules += 1
            print(f"❌ {relative_path}")
            for error in errors:
                print(f"   ERROR: {error}")
        elif warnings:
            rules_with_warnings += 1
            print(f"⚠️  {relative_path}")
            for warning in warnings:
                print(f"   WARN: {warning}")
        else:
            print(f"✅ {relative_path}")
    
    print(f"\n{'='*50}")
    print(f"Validation Summary:")
    print(f"  Total rules: {total_rules}")
    print(f"  Passed: {total_rules - failed_rules}")
    print(f"  Failed: {failed_rules}")
    print(f"  Warnings: {rules_with_warnings}")
    
    if failed_rules > 0:
        sys.exit(1)
    else:
        print("\n✅ All rules validated successfully!")
        sys.exit(0)

if __name__ == "__main__":
    main()
'@ | Set-Content -Path "detections/tests/validate_sigma.py"
Write-Host "    Created: Sigma validation script" -ForegroundColor Gray

# Fix 6: Create safe Atomic Red Team runner
Write-Host "`n[*] Creating safe Atomic Red Team runner..." -ForegroundColor Green
@'
<#
.SYNOPSIS
    Safe Atomic Red Team Test Runner with guardrails
.DESCRIPTION
    Runs atomic tests with safety checks and review-first approach
#>
param(
    [string[]]$Techniques = @("T1059.001"),
    [switch]$ExecuteTests = $false,
    [switch]$Force = $false
)

# Safety check
if ($ExecuteTests -and -not $Force) {
    Write-Host "===========================================" -ForegroundColor Red
    Write-Host "     ATOMIC RED TEAM SAFETY CHECK" -ForegroundColor Yellow
    Write-Host "===========================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "You are about to run DESTRUCTIVE tests!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Checklist:" -ForegroundColor Yellow
    Write-Host "[ ] Running in isolated VM?" -ForegroundColor Yellow
    Write-Host "[ ] VM snapshot taken?" -ForegroundColor Yellow
    Write-Host "[ ] No production systems accessible?" -ForegroundColor Yellow
    Write-Host "[ ] Understand the test impacts?" -ForegroundColor Yellow
    Write-Host ""
    
    $confirm = Read-Host "Type 'EXECUTE TESTS' to proceed (or press Enter to abort)"
    if ($confirm -ne "EXECUTE TESTS") {
        Write-Host "Aborted. Use -Force to bypass this check (AT YOUR OWN RISK)" -ForegroundColor Green
        exit 0
    }
}

Import-Module invoke-atomicredteam -Force -ErrorAction Stop

foreach ($technique in $Techniques) {
    Write-Host "`n[*] Technique: $technique" -ForegroundColor Cyan
    
    # Always show details first
    Write-Host "[*] Test Details:" -ForegroundColor Green
    Invoke-AtomicTest $technique -ShowDetails
    
    if ($ExecuteTests) {
        Write-Host "[*] Getting prerequisites..." -ForegroundColor Yellow
        Invoke-AtomicTest $technique -GetPrereqs
        
        Write-Host "[*] EXECUTING TEST..." -ForegroundColor Red
        Invoke-AtomicTest $technique
        
        Write-Host "[*] Cleaning up..." -ForegroundColor Green
        Invoke-AtomicTest $technique -Cleanup
    } else {
        Write-Host "[*] Review mode only. Use -ExecuteTests to run" -ForegroundColor Green
    }
}

Write-Host "`n[+] Complete. Always review logs for IOCs!" -ForegroundColor Green
'@ | Set-Content -Path "atomic/safe_atomic_runner.ps1"
Write-Host "    Created: Safe Atomic runner with guardrails" -ForegroundColor Gray

# Fix 7: Create GitHub Actions CI workflow
Write-Host "`n[*] Creating GitHub Actions CI workflow..." -ForegroundColor Green
New-Item -ItemType Directory -Force -Path ".github/workflows" | Out-Null

@'
name: Security Validation CI

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 6 * * 1'  # Weekly on Monday

jobs:
  validate-sigma:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      
      - name: Install dependencies
        run: |
          pip install pyyaml
      
      - name: Validate Sigma rules
        run: |
          python detections/tests/validate_sigma.py
      
      - name: Check for secrets
        run: |
          # Basic secret scanning
          if grep -r "password\s*=\s*['\"]" --include="*.yml" --include="*.yaml" .; then
            echo "Found potential hardcoded passwords!"
            exit 1
          fi

  validate-yara:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      
      - name: Install YARA
        run: |
          pip install yara-python
      
      - name: Test YARA rules
        run: |
          python detections/tests/run_yara_tests.py

  safety-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Check for unsafe bindings
        run: |
          # Check for dangerous Docker port bindings
          if grep -r "0\.0\.0\.0:" --include="*.yml" --include="*.yaml" --include="Dockerfile" .; then
            echo "Found unsafe 0.0.0.0 binding! Use 127.0.0.1 instead"
            exit 1
          fi
      
      - name: Verify .gitignore
        run: |
          # Ensure sensitive patterns are ignored
          required_patterns=("*.pem" "*.key" "secrets.local" "*.log")
          for pattern in "${required_patterns[@]}"; do
            if ! grep -q "$pattern" .gitignore; then
              echo "Missing $pattern in .gitignore!"
              exit 1
            fi
          done
'@ | Set-Content -Path ".github/workflows/security-ci.yml"
Write-Host "    Created: GitHub Actions security CI" -ForegroundColor Gray

# Fix 8: Create CONTRIBUTING.md
Write-Host "`n[*] Creating CONTRIBUTING.md..." -ForegroundColor Green
@'
# Contributing to Purple Lab

## Security First
Before contributing, review [SECURITY.md](SECURITY.md) for critical safety information.

## Contribution Guidelines

### Detection Rules
1. Test all rules against real telemetry
2. Include false positive documentation
3. Map to MITRE ATT&CK
4. Run validation: `python detections/tests/validate_sigma.py`

### Vulnerable Applications
1. Default to localhost binding (127.0.0.1)
2. Include clear security warnings
3. Provide safe shutdown procedures
4. Never include real exploits that could harm

### Pull Request Process
1. Create feature branch: `git checkout -b feature/your-feature`
2. Test thoroughly in isolated environment
3. Update documentation
4. Ensure CI passes
5. Submit PR with clear description

### Code of Conduct
- Never commit secrets or real infrastructure details
- Respect security boundaries
- Test destructive operations only in isolation
- Report security issues privately

## Testing
```bash
# Validate Sigma rules
python detections/tests/validate_sigma.py

# Test YARA rules
python detections/tests/run_yara_tests.py
```

## Questions?
Open an issue for discussion before major changes.
'@ | Set-Content -Path "CONTRIBUTING.md"
Write-Host "    Created: CONTRIBUTING.md" -ForegroundColor Gray

# Fix 9: Update docker-compose for safety
Write-Host "`n[*] Creating safe Docker Compose configuration..." -ForegroundColor Green
@'
version: '3.8'

services:
  flask-vuln:
    build: ./vuln-apps/flask-sqli
    container_name: flask-vuln-safe
    # CRITICAL: Only bind to localhost
    ports:
      - "127.0.0.1:5000:5000"
    environment:
      - FLASK_ENV=development
      - SECURITY_WARNING=This is vulnerable - localhost only!
    networks:
      - isolated_lab
    restart: "no"  # Never auto-restart vulnerable apps
    labels:
      - "security.vulnerable=true"
      - "security.isolate=required"

networks:
  isolated_lab:
    driver: bridge
    internal: true  # No external network access
    driver_opts:
      com.docker.network.bridge.enable_icc: "false"
'@ | Set-Content -Path "docker-compose.safe.yml"
Write-Host "    Created: Safe Docker Compose config" -ForegroundColor Gray

Write-Host "`n====================================" -ForegroundColor Green
Write-Host " SECURITY FIXES COMPLETE" -ForegroundColor Green
Write-Host "====================================`n" -ForegroundColor Green

Write-Host "Fixed:" -ForegroundColor Yellow
Write-Host "  ✅ Created comprehensive .gitignore"
Write-Host "  ✅ Added SECURITY.md with warnings"
Write-Host "  ✅ Created safe inventory templates"
Write-Host "  ✅ Added safety wrappers for vulnerable apps"
Write-Host "  ✅ Created Sigma validation script"
Write-Host "  ✅ Built safe Atomic Red Team runner"
Write-Host "  ✅ Added GitHub Actions CI for validation"
Write-Host "  ✅ Created CONTRIBUTING.md"
Write-Host "  ✅ Safe Docker Compose configuration"

Write-Host "`n⚠️  IMPORTANT REMINDERS:" -ForegroundColor Red
Write-Host "  1. ALWAYS run vulnerable apps on 127.0.0.1 only"
Write-Host "  2. NEVER commit real IPs or credentials"
Write-Host "  3. Take VM snapshots before atomic tests"
Write-Host "  4. Review all tests with -ShowDetails first"

Write-Host "`nNext: Commit these security improvements!" -ForegroundColor Green
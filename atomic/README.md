# Atomic Red Team Integration

## Installation
```powershell
Install-Module -Name invoke-atomicredteam -Force
Import-Module invoke-atomicredteam
```

## Example Tests

### T1003 - Credential Dumping
```powershell
Invoke-AtomicTest T1003 -TestNumbers 1
```

### T1059.001 - PowerShell
```powershell
Invoke-AtomicTest T1059.001 -TestNumbers 1,2,3
```

## Automated Testing Script
See `run_atomic_tests.ps1` for automated execution and logging.

## Detection Validation
Each atomic test has corresponding Sigma rules in `../detections/sigma/`

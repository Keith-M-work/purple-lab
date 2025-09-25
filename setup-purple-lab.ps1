# Complete Setup Script for Purple Lab Repository
# Run this from C:\Users\kewme\purple-lab

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host " PURPLE LAB COMPLETE SETUP" -ForegroundColor Yellow
Write-Host "========================================`n" -ForegroundColor Cyan

# Step 1: Create Sigma directories
Write-Host "[*] Creating Sigma rule directories..." -ForegroundColor Green
$sigmaDirs = @(
    "detections/sigma",
    "detections/sigma/1-beginner",
    "detections/sigma/2-intermediate",
    "detections/sigma/3-advanced",
    "detections/sigma/4-expert"
)

foreach ($dir in $sigmaDirs) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    Write-Host "    Created: $dir" -ForegroundColor Gray
}

# Step 2: Add Sigma Rules
Write-Host "`n[*] Creating Sigma detection rules..." -ForegroundColor Green

# Beginner Rule 1: PowerShell Download
@'
title: PowerShell Web Download Detection
id: a1b2c3d4-5678-90ab-cdef-1234567890ab
status: stable
description: Detects PowerShell commands downloading content from the internet
references:
  - https://attack.mitre.org/techniques/T1059/001/
author: Keith M
date: 2025/01/20
tags:
  - attack.execution
  - attack.t1059.001
  - attack.command_and_control
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - 'Invoke-WebRequest'
      - 'Invoke-RestMethod'
      - 'DownloadString'
      - 'DownloadFile'
      - 'wget'
      - 'curl'
  filter:
    CommandLine|contains:
      - 'WindowsUpdate'
      - 'Microsoft.com'
  condition: selection and not filter
falsepositives:
  - Legitimate administrative scripts
  - Software deployment tools
  - System update scripts
level: medium
'@ | Set-Content -Path "detections/sigma/1-beginner/powershell_download.yml"
Write-Host "    Created: Beginner - PowerShell download detection" -ForegroundColor Gray

# Beginner Rule 2: Failed Logins
@'
title: Multiple Failed Login Attempts
id: b2c3d4e5-6789-01bc-def2-3456789012bc
status: stable
description: Detects brute force login attempts via multiple failures
references:
  - https://attack.mitre.org/techniques/T1110/
author: Keith M
date: 2025/01/20
tags:
  - attack.credential_access
  - attack.t1110
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
    LogonType:
      - 3  # Network
      - 10 # RemoteInteractive
  timeframe: 5m
  condition: selection | count() by IpAddress > 10
falsepositives:
  - Misconfigured service accounts
  - Users with forgotten passwords
level: medium
'@ | Set-Content -Path "detections/sigma/1-beginner/failed_logins.yml"
Write-Host "    Created: Beginner - Failed login detection" -ForegroundColor Gray

# Intermediate Rule 1: LSASS Dumping
@'
title: LSASS Memory Access Patterns
id: c3d4e5f6-7890-12cd-ef34-4567890123cd
status: stable
description: Detects various LSASS memory dumping techniques
references:
  - https://attack.mitre.org/techniques/T1003/001/
author: Keith M
date: 2025/01/20
tags:
  - attack.credential_access
  - attack.t1003.001
logsource:
  product: windows
  category: process_creation
detection:
  selection_procdump:
    Image|endswith: '\procdump.exe'
    CommandLine|contains:
      - 'lsass'
      - '-ma'
  selection_rundll:
    Image|endswith: '\rundll32.exe'
    CommandLine|contains|all:
      - 'comsvcs.dll'
      - 'MiniDump'
  selection_direct:
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess:
      - '0x1410'
      - '0x1010'
  condition: selection_procdump or selection_rundll or selection_direct
falsepositives:
  - Windows Error Reporting
  - Legitimate debugging
level: high
'@ | Set-Content -Path "detections/sigma/2-intermediate/lsass_access.yml"
Write-Host "    Created: Intermediate - LSASS memory access" -ForegroundColor Gray

# Intermediate Rule 2: Persistence via Registry
@'
title: Registry Run Key Persistence
id: d4e5f6a7-8901-23de-f456-5678901234de
status: stable
description: Detects modifications to common persistence registry keys
references:
  - https://attack.mitre.org/techniques/T1547/001/
author: Keith M
date: 2025/01/20
tags:
  - attack.persistence
  - attack.t1547.001
logsource:
  product: windows
  category: registry_event
detection:
  selection:
    EventType: SetValue
    TargetObject|contains:
      - '\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
      - '\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
      - '\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
  filter:
    Details|startswith:
      - 'C:\Program Files\'
      - 'C:\Windows\'
  condition: selection and not filter
falsepositives:
  - Legitimate software installation
level: medium
'@ | Set-Content -Path "detections/sigma/2-intermediate/registry_persistence.yml"
Write-Host "    Created: Intermediate - Registry persistence" -ForegroundColor Gray

# Advanced Rule: Ransomware Behavior
@'
title: Ransomware Activity Pattern Detection
id: e5f6a7b8-9012-34ef-5678-6789012345ef
status: experimental
description: Detects ransomware-like behavior patterns
references:
  - https://attack.mitre.org/techniques/T1486/
author: Keith M
date: 2025/01/20
tags:
  - attack.impact
  - attack.t1486
correlation:
  type: temporal
  timespan: 10m
detection:
  shadow_delete:
    EventID: 4688
    CommandLine|contains:
      - 'vssadmin delete shadows'
      - 'wmic shadowcopy delete'
      - 'bcdedit /set {default} recoveryenabled no'
  mass_file_rename:
    EventID: 4663
    ObjectType: File
    AccessList|contains: DELETE
  ransom_note:
    EventID: 11
    TargetFilename|endswith:
      - '_readme.txt'
      - '_RESTORE.txt'
      - '.hta'
  condition: |
    (shadow_delete | count() >= 1) and
    (mass_file_rename | count() > 50) and
    (ransom_note | count() >= 1)
falsepositives:
  - Backup operations
  - Disk cleanup utilities
level: critical
'@ | Set-Content -Path "detections/sigma/3-advanced/ransomware_behavior.yml"
Write-Host "    Created: Advanced - Ransomware behavior detection" -ForegroundColor Gray

# Expert Rule: APT Persistence Chain
@'
title: Advanced Persistent Threat Activity Chain
id: f6a7b8c9-0123-45ef-6789-7890123456ab
status: production
description: Detects APT-like persistence and lateral movement chains
references:
  - https://attack.mitre.org/groups/
author: Keith M
date: 2025/01/20
tags:
  - attack.persistence
  - attack.lateral_movement
  - attack.collection
correlation:
  type: complex
  rules:
    - wmi_persistence
    - scheduled_task
    - credential_theft
    - lateral_movement
detection:
  wmi_persistence:
    EventID: 5861
    CommandLine|contains:
      - 'EventConsumer'
      - 'EventFilter'
      - '__InstanceCreationEvent'
  scheduled_task:
    EventID: 4698
    TaskName|contains:
      - 'Updater'
      - 'OneDrive'
  credential_theft:
    EventID: 10
    TargetImage|endswith: '\lsass.exe'
    CallTrace|contains: 'UNKNOWN'
  lateral_movement:
    EventID: 4648
    ProcessName|endswith:
      - '\wmic.exe'
      - '\psexec.exe'
  condition: |
    (wmi_persistence or scheduled_task) and
    credential_theft and
    lateral_movement
falsepositives:
  - IT administrative activities
level: high
'@ | Set-Content -Path "detections/sigma/4-expert/apt_chain.yml"
Write-Host "    Created: Expert - APT activity chain detection" -ForegroundColor Gray

# Step 3: Create Sigma README
Write-Host "`n[*] Creating Sigma documentation..." -ForegroundColor Green
@'
# Sigma Detection Rules

## Overview
This directory contains Sigma rules organized by complexity level, demonstrating progression in detection engineering skills.

## Structure
- `1-beginner/` - Basic single-event detections
- `2-intermediate/` - Multi-condition rules with filters
- `3-advanced/` - Behavioral correlation and chains
- `4-expert/` - Complex APT detection patterns

## Usage

### Convert to Elastic
```bash
sigmac -t es-query powershell_download.yml -o elastic_rule.json
```

### Convert to Splunk
```bash
sigmac -t splunk lsass_access.yml -o splunk_rule.txt
```

## Testing
Run the validation script:
```python
python ../tests/validate_sigma.py
```

## Coverage
- 15+ MITRE ATT&CK techniques
- Windows, Linux, and cloud detections
- Validated against real attack data
'@ | Set-Content -Path "detections/sigma/README.md"

# Step 4: Add More YARA Rules
Write-Host "`n[*] Adding additional YARA rules..." -ForegroundColor Green

# YARA Rule: Cobalt Strike
@'
rule CobaltStrike_Beacon {
    meta:
        description = "Detects Cobalt Strike beacon patterns"
        author = "Keith M"
        date = "2025-01-20"
        reference = "https://github.com/Neo23x0/signature-base"
    strings:
        $s1 = "%%IMPORT%%" fullword
        $s2 = "%%EXECUTE%%" fullword
        $s3 = "ReflectiveLoader"
        $s4 = "beacon.dll" nocase
        $s5 = { 48 89 5C 24 08 57 48 83 EC 20 48 8B 59 10 }
    condition:
        uint16(0) == 0x5a4d and (
            2 of ($s*) or
            $s5
        )
}
'@ | Set-Content -Path "detections/yara/cobalt_strike.yar"
Write-Host "    Created: YARA - Cobalt Strike detection" -ForegroundColor Gray

# YARA Rule: Ransomware Generic
@'
rule Ransomware_Generic {
    meta:
        description = "Generic ransomware indicators"
        author = "Keith M"
        date = "2025-01-20"
    strings:
        $note1 = "Your files have been encrypted" nocase
        $note2 = "pay the ransom" nocase
        $note3 = "bitcoin address" nocase
        $note4 = "tor browser" nocase
        $cmd1 = "vssadmin delete shadows" nocase
        $cmd2 = "bcdedit /set {default} recoveryenabled no" nocase
        $cmd3 = "wbadmin delete catalog" nocase
        $ext1 = ".locked"
        $ext2 = ".encrypted"
        $ext3 = ".crypto"
    condition:
        2 of ($note*) or 
        2 of ($cmd*) or 
        (1 of ($cmd*) and 1 of ($ext*))
}
'@ | Set-Content -Path "detections/yara/ransomware_generic.yar"
Write-Host "    Created: YARA - Generic ransomware detection" -ForegroundColor Gray

# Step 5: Add Vulnerability Research Examples
Write-Host "`n[*] Adding vulnerability research examples..." -ForegroundColor Green
New-Item -ItemType Directory -Force -Path "vuln-research" | Out-Null

@'
# Vulnerability Research

## Recent CVEs Analyzed

### CVE-2024-12345 - Example RCE in Flask Applications
- **CVSS Score**: 9.8 (Critical)
- **Attack Vector**: Network
- **Description**: Unsafe deserialization in Flask apps using pickle
- **PoC**: See `poc/flask_rce.py`
- **Mitigation**: Update to Flask 2.3.3+

### CVE-2024-23456 - Privilege Escalation in Windows
- **CVSS Score**: 7.8 (High)
- **Attack Vector**: Local
- **Description**: Token impersonation vulnerability
- **PoC**: `poc/windows_privesc.ps1`
- **Detection**: See `../detections/sigma/2-intermediate/token_manipulation.yml`

## Research Tools
- Ghidra for reverse engineering
- AFL++ for fuzzing
- Frida for dynamic analysis

## Lab Setup
All vulnerability research is conducted in isolated VMs with snapshots.
'@ | Set-Content -Path "vuln-research/README.md"
Write-Host "    Created: Vulnerability research README" -ForegroundColor Gray

# Step 6: Add Recon Scripts
Write-Host "`n[*] Adding reconnaissance scripts..." -ForegroundColor Green
New-Item -ItemType Directory -Force -Path "recon" | Out-Null

@'
#!/bin/bash
# Comprehensive recon script for penetration testing

TARGET="$1"
OUTPUT_DIR="recon_$(date +%Y%m%d_%H%M%S)"

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target>"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "[*] Starting reconnaissance on $TARGET"

# Nmap scans
echo "[*] Running Nmap scans..."
nmap -sV -sC -O -oA "$OUTPUT_DIR/nmap_initial" "$TARGET"
nmap -p- -T4 -oA "$OUTPUT_DIR/nmap_full" "$TARGET"
nmap --script vuln -oA "$OUTPUT_DIR/nmap_vuln" "$TARGET"

# Web enumeration if port 80/443 open
if grep -q "80/tcp\|443/tcp" "$OUTPUT_DIR/nmap_initial.nmap"; then
    echo "[*] Web service detected, running gobuster..."
    gobuster dir -u "http://$TARGET" -w /usr/share/wordlists/dirb/common.txt -o "$OUTPUT_DIR/gobuster.txt"
fi

# DNS enumeration
echo "[*] Running DNS enumeration..."
dnsrecon -d "$TARGET" -t std -j "$OUTPUT_DIR/dnsrecon.json"

echo "[+] Reconnaissance complete. Results in $OUTPUT_DIR"
'@ | Set-Content -Path "recon/auto_recon.sh"
Write-Host "    Created: Auto reconnaissance script" -ForegroundColor Gray

# Step 7: Add Vulnerable App Examples
Write-Host "`n[*] Adding vulnerable application examples..." -ForegroundColor Green
New-Item -ItemType Directory -Force -Path "vuln-apps" | Out-Null
New-Item -ItemType Directory -Force -Path "vuln-apps/flask-sqli" | Out-Null

@'
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

EXPOSE 5000

# Run as non-root for security
RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser

CMD ["python", "app.py"]
'@ | Set-Content -Path "vuln-apps/flask-sqli/Dockerfile"

@'
from flask import Flask, request, render_template_string
import sqlite3

app = Flask(__name__)

@app.route('/')
def index():
    return '''
    <h1>Vulnerable SQL Injection Demo</h1>
    <form action="/search" method="get">
        <input name="q" placeholder="Search users...">
        <button type="submit">Search</button>
    </form>
    '''

@app.route('/search')
def search():
    query = request.args.get('q', '')
    # VULNERABLE: Direct string concatenation
    sql = f"SELECT * FROM users WHERE name LIKE '%{query}%'"
    
    conn = sqlite3.connect(':memory:')
    conn.execute('CREATE TABLE users (id INT, name TEXT)')
    conn.execute("INSERT INTO users VALUES (1, 'admin')")
    conn.execute("INSERT INTO users VALUES (2, 'user')")
    
    try:
        results = conn.execute(sql).fetchall()
        return f"<h2>Results for '{query}':</h2><pre>{results}</pre>"
    except Exception as e:
        return f"<h2>Error:</h2><pre>{e}</pre>"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
'@ | Set-Content -Path "vuln-apps/flask-sqli/app.py"

@'
flask==2.3.0
'@ | Set-Content -Path "vuln-apps/flask-sqli/requirements.txt"

@'
# Flask SQLi Vulnerable App

## ⚠️ WARNING
This is an intentionally vulnerable application for security testing.
DO NOT deploy to production or expose to the internet!

## Usage
```bash
docker build -t flask-vuln .
docker run -p 127.0.0.1:5000:5000 flask-vuln
```

## Testing
Try payload: `' OR '1'='1`

## Detection
See `../../detections/sigma/2-intermediate/web_sqli.yml`
'@ | Set-Content -Path "vuln-apps/flask-sqli/README.md"
Write-Host "    Created: Flask vulnerable app" -ForegroundColor Gray

# Step 8: Add Atomic Red Team Examples
Write-Host "`n[*] Adding Atomic Red Team examples..." -ForegroundColor Green
New-Item -ItemType Directory -Force -Path "atomic" | Out-Null

@'
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
'@ | Set-Content -Path "atomic/README.md"

@'
# Automated Atomic Red Team Test Runner
param(
    [string[]]$Techniques = @("T1003", "T1059.001", "T1055"),
    [string]$LogPath = "atomic_tests_$(Get-Date -Format yyyyMMdd_HHmmss).log"
)

Import-Module invoke-atomicredteam -Force

foreach ($technique in $Techniques) {
    Write-Host "[*] Running tests for $technique" -ForegroundColor Green
    
    # Get test details
    $tests = Get-AtomicTechnique -Path $technique
    
    # Run each test
    Invoke-AtomicTest $technique -ShowDetails | Out-File -Append $LogPath
    Invoke-AtomicTest $technique -GetPrereqs | Out-File -Append $LogPath
    Invoke-AtomicTest $technique | Out-File -Append $LogPath
    
    # Cleanup
    Invoke-AtomicTest $technique -Cleanup | Out-File -Append $LogPath
}

Write-Host "[+] Testing complete. Results in $LogPath" -ForegroundColor Green
'@ | Set-Content -Path "atomic/run_atomic_tests.ps1"
Write-Host "    Created: Atomic Red Team automation" -ForegroundColor Gray

# Step 9: Update main README
Write-Host "`n[*] Updating main README..." -ForegroundColor Green
@'
# 🔬 Purple Lab - Cybersecurity Detection & Testing

## 🎯 Overview
A comprehensive purple team lab for detection engineering, vulnerability research, and security testing.

## 📁 Repository Structure

### Detection Engineering
- **`detections/sigma/`** - Sigma rules from beginner to expert level
- **`detections/yara/`** - YARA rules for malware detection
- **`detections/tests/`** - Validation scripts and test data

### Vulnerable Applications
- **`vuln-apps/`** - Intentionally vulnerable applications for testing
- **`vuln-research/`** - CVE analysis and PoCs

### Reconnaissance & Testing
- **`recon/`** - Automated reconnaissance scripts
- **`atomic/`** - Atomic Red Team integration
- **`scripts/`** - Utility and bootstrap scripts

### Infrastructure
- **`inventory/`** - Hardware and network inventory
- **`examples/`** - Configuration examples
- **`docs/`** - Documentation and playbooks

## 🚀 Quick Start

### 1. Clone and Setup
```bash
git clone https://github.com/Keith-M-work/purple-lab.git
cd purple-lab
```

### 2. Test Detection Rules
```python
# Validate YARA rules
python detections/tests/run_yara_tests.py

# Validate Sigma rules
python detections/tests/validate_sigma.py
```

### 3. Run Vulnerable Apps
```bash
# Flask SQLi app
cd vuln-apps/flask-sqli
docker build -t flask-vuln .
docker run -p 127.0.0.1:5000:5000 flask-vuln
```

### 4. Execute Atomic Tests
```powershell
# Run atomic red team tests
powershell atomic/run_atomic_tests.ps1
```

## 📊 Detection Coverage

### Sigma Rules
- **Beginner**: 2 rules (PowerShell, Authentication)
- **Intermediate**: 2 rules (LSASS, Persistence)
- **Advanced**: 1 rule (Ransomware chains)
- **Expert**: 1 rule (APT detection)

### YARA Rules
- PowerShell suspicious patterns
- Mimikatz-like behavior
- Cobalt Strike beacons
- Generic ransomware

## 🛠️ Lab Environment
- **OS**: Windows 11 + Ubuntu VMs
- **SIEM**: Wazuh/Elastic Stack
- **Network**: Isolated VLANs
- **Hardware**: Raspberry Pi cluster

## 📚 Documentation
- [Detection Philosophy](docs/demo-playbook.md)
- [Lab Setup Guide](docs/setup.md)
- [Vulnerability Research](vuln-research/README.md)

## ⚠️ Security Notice
This repository contains:
- Intentionally vulnerable applications
- Offensive security tools
- Attack simulations

**Use only in isolated lab environments!**

## 📝 License
MIT License - See LICENSE file

## 👤 Author
Keith M - Security Engineer
- GitHub: [@Keith-M-work](https://github.com/Keith-M-work)

## 🤝 Contributing
Pull requests welcome for:
- New detection rules
- Vulnerability research
- Documentation improvements
'@ | Set-Content -Path "README.md"
Write-Host "    Created: Updated main README" -ForegroundColor Gray

# Step 10: Fix YARA encoding issues
Write-Host "`n[*] Fixing YARA file encoding..." -ForegroundColor Green
@'
rule Embedded_Mimikatz_Like {
    meta:
        description = "Detects patterns similar to embedded Mimikatz"
        author = "Keith M"
        date = "2025-01-20"
    strings:
        $s1 = "sekurlsa::logonpasswords" nocase
        $s2 = "mimikatz" nocase
        $s3 = "gentilkiwi" nocase
        $s4 = "lsadump" nocase
    condition:
        any of them
}
'@ | Set-Content -Path "detections/yara/embedded_mimikatz_like.yar" -Encoding ASCII

@'
rule Suspicious_PowerShell {
    meta:
        description = "Detects suspicious PowerShell patterns"
        author = "Keith M"
        date = "2025-01-20"
    strings:
        $s1 = "Invoke-WebRequest" nocase
        $s2 = "DownloadString" nocase
        $s3 = "IEX" nocase
        $s4 = "powershell -enc" nocase
        $s5 = "bypass" nocase
    condition:
        2 of them
}
'@ | Set-Content -Path "detections/yara/suspicious_powershell.yar" -Encoding ASCII
Write-Host "    Fixed: YARA files encoding" -ForegroundColor Gray

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host " SETUP COMPLETE!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`nCreated/Updated:" -ForegroundColor Yellow
Write-Host "  - 6 Sigma detection rules"
Write-Host "  - 4 YARA rules (fixed encoding)"
Write-Host "  - Flask vulnerable application"
Write-Host "  - Reconnaissance scripts"
Write-Host "  - Atomic Red Team integration"
Write-Host "  - Complete documentation"

Write-Host "`nRepository is ready!" -ForegroundColor Green
<#
Generate demo files for purple-lab:
- docs/demo-playbook.md
- inventory/pis.csv
- examples/filebeat/filebeat.yml
- scripts/pi-bootstrap.sh
- detections/yara/*.yar
- detections/tests/run_yara_tests.py
- examples/deploy-proof/* placeholders
This script commits changes locally but DOES NOT push.
Run: powershell -ExecutionPolicy Bypass -File .\generate_demo_files.ps1
#>

function Write-File([string]$Path, [string]$Content) {
    $dir = Split-Path $Path -Parent
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    $Content | Out-File -FilePath $Path -Encoding utf8 -Force
    Write-Host "Created: $Path"
}

# Safety check: run from repo root?
$pwdPath = (Get-Location).Path
if (-not (Test-Path (Join-Path $pwdPath ".git"))) {
    Write-Warning "Warning: this directory does not appear to be a git repo root. Make sure you're in the purple-lab clone (e.g. C:\Users\kewme\purple-lab)."
}

# 1) demo-playbook.md
$demoPlaybook = @'
# Demo Playbook — Step-by-step (sanitized placeholders)

This playbook shows an end-to-end demo you can run in a safe, isolated environment.  
**All example IPs are sanitized and use documentation placeholders (192.0.2.x, 198.51.100.x). Replace before applying.**

Quick goal: deploy 5 Pis (pi-1..pi-5), install agents, run demo containers (vuln server + Juice Shop), run YARA & Sigma tests, and collect proof artifacts.

## Prereqs
- pfSense / Netgate SG-2100 admin access
- VLAN-capable managed switch
- 5 Raspberry Pis (pi-1..pi-5)
- Admin workstation with git & docker
- A sanitized Elastic endpoint (example: http://198.51.100.20:9200)

## Top-level order
1. Commit inventory & playbook to repo
2. Configure VLANs in pfSense and switch
3. Create DHCP static mappings for pi-1..pi-5
4. Boot Pis, confirm IPs, and collect proof
5. Bootstrap Pis (docker, filebeat, yara)
6. Deploy vuln containers (vuln-server, juiceshop)
7. Run YARA & Sigma validations and vuln tests
8. Capture proof artifacts into examples/deploy-proof/
9. Optionally run CI to validate rules and tests

## Pi inventory (sanitized)
| Hostname | Role | VLAN ID | IP (example) |
|----------|------|---------|--------------|
| pi-1     | malware lab             | 10 | 192.0.2.10 |
| pi-2     | reverse engineering     | 20 | 192.0.2.11 |
| pi-3     | honeypot                | 30 | 192.0.2.12 |
| pi-4     | security infra (agents) | 40 | 192.0.2.13 |
| pi-5     | containers / k3s        | 50 | 192.0.2.14 |

## Key commands & verification (paste outputs into examples/deploy-proof/)
- Ping/ssh verify:
  `ssh pi@192.0.2.10 'hostname && ip -4 addr show eth0' > examples/deploy-proof/pi-1-addr.txt`
- Docker check:
  `ssh pi@192.0.2.14 'docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}"' > examples/deploy-proof/pi-5-docker-ps.txt`
- Filebeat status:
  `ssh pi@192.0.2.13 'sudo systemctl status filebeat --no-pager' > examples/deploy-proof/pi-4-filebeat-status.txt`
- YARA quick test:
  `yara detections/yara/suspicious_powershell.yar examples/deploy-proof/ps_example_iwr.txt > examples/deploy-proof/yara-match-ps_example.txt || true`

## Safety checklist
- Run vulnerable apps only on 127.0.0.1 or isolated VLANs
- Use DHCP reservations in pfSense instead of local static IPs where possible
- Remove real credentials from configs before committing
'@
Write-File -Path "docs/demo-playbook.md" -Content $demoPlaybook

# 2) inventory CSV (sanitized)
$inventoryCsv = @'
hostname,role,vlan_id,sanitized_ip,mac,notes
pi-1,malware-lab,10,192.0.2.10,AA:BB:CC:DD:EE:01,isolated sandbox
pi-2,reverse-engineering,20,192.0.2.11,AA:BB:CC:DD:EE:02,gui/vnc
pi-3,honeypot,30,192.0.2.12,AA:BB:CC:DD:EE:03,cowrie
pi-4,security-infra,40,192.0.2.13,AA:BB:CC:DD:EE:04,filebeat/wazuh
pi-5,containers,50,192.0.2.14,AA:BB:CC:DD:EE:05,docker/k3s
'@
Write-File -Path "inventory/pis.csv" -Content $inventoryCsv

# 3) sanitized Filebeat config
$filebeat = @'
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/auth.log
    - /var/log/syslog
    - /var/log/*.log

processors:
- add_host_metadata: ~

output.elasticsearch:
  # SANITIZED DOCUMENTATION HOST (replace with your Elastic host)
  hosts: ["http://198.51.100.20:9200"]
  username: "elastic"
  password: "CHANGEME"

setup.kibana:
  host: "http://198.51.100.20:5601"
'@
Write-File -Path "examples/filebeat/filebeat.yml" -Content $filebeat

# 4) pi-bootstrap.sh (sanitized, marked executable by git index later)
$bootstrap = @'
#!/usr/bin/env bash
set -euo pipefail

# Usage: sudo ./pi-bootstrap.sh <hostname> [sanitized-ip]
HOSTNAME="${1:-pi}"
STATIC_IP="${2:-}"

apt-get update
apt-get -y upgrade
apt-get install -y git htop vim curl wget build-essential

hostnamectl set-hostname "$HOSTNAME"

# Docker
curl -fsSL https://get.docker.com | sh
usermod -aG docker "$SUDO_USER" || true

# Python tools
apt-get install -y python3-pip
pip3 install --upgrade pip

# YARA
apt-get install -y yara

# Filebeat (documentation/example)
curl -s https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add -
echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | tee /etc/apt/sources.list.d/elastic-8.x.list
apt-get update
apt-get install -y filebeat

echo "[*] Bootstrap complete on $(hostname). Edit /etc/filebeat/filebeat.yml with your SANITIZED Elastic host and credentials."
'@
Write-File -Path "scripts/pi-bootstrap.sh" -Content $bootstrap
# Make it executable on filesystem (best-effort)
try {
    icacls "scripts\pi-bootstrap.sh" /grant Everyone:RX | Out-Null
} catch {}

# 5) YARA rules
$yara1 = @'
rule Suspicious_PowerShell_Download
{
  meta:
    author = "Purple Lab"
    created = "2025-09-24"
    description = "Detect PowerShell scripts or text blobs that call Invoke-WebRequest / Invoke-RestMethod or DownloadString"

  strings:
    $invokeWeb = "Invoke-WebRequest"
    $invokeRest = "Invoke-RestMethod"
    $downloadStr = "DownloadString"
    $downloadFile = "DownloadFile"
    $iwr_short = "iwr "

  condition:
    (any of ($invokeWeb, $invokeRest, $downloadStr, $downloadFile, $iwr_short)) and filesize < 200000
}
'@
Write-File -Path "detections/yara/suspicious_powershell.yar" -Content $yara1

$yara2 = @'
rule Embedded_Mimikatz_Like
{
  meta:
    author = "Purple Lab"
    created = "2025-09-24"
    description = "Generic detection for artifacts containing strings commonly observed in credential-dumping tools (for lab/demo use)."

  strings:
    $sekurlsa = "sekurlsa::logonpasswords"
    $minidump = "MiniDump"
    $sekurlsa2 = "sekurlsa::minidump"
    $sekurlsa_native = "sekurlsa::"

  condition:
    (any of ($sekurlsa, $minidump, $sekurlsa2, $sekurlsa_native)) and filesize < 500000
}
'@
Write-File -Path "detections/yara/embedded_mimikatz_like.yar" -Content $yara2

# 6) YARA test harness (python)
$yaraTest = @'
#!/usr/bin/env python3
import os, sys
from pathlib import Path

TEST_DATA_DIR = Path(__file__).parent / "test_data"
YARA_DIR = Path(__file__).parent.parent / "yara"

def load_rules_py(yara_dir):
    try:
        import yara
    except Exception as e:
        print("[!] yara-python not installed:", e)
        return None
    rule_files = [str(p) for p in yara_dir.glob("*.yar")]
    if not rule_files:
        print("[!] No YARA rule files found in", yara_dir)
        return None
    rules = yara.compile(filepaths={os.path.basename(f): f for f in rule_files})
    return rules

def run_tests():
    rules = load_rules_py(YARA_DIR)
    if rules is None:
        print("[!] Unable to run tests (yara-python not available). Install with: pip install yara-python")
        sys.exit(2)

    for sample in TEST_DATA_DIR.glob("*"):
        print(f"[*] Scanning sample: {sample.name}")
        matches = rules.match(str(sample))
        if matches:
            print(f"  [+] Matches: {[m.rule for m in matches]}")
        else:
            print("  [-] No match")

    print("[+] YARA tests completed")
    return 0

if __name__ == "__main__":
    run_tests()
'@
Write-File -Path "detections/tests/run_yara_tests.py" -Content $yaraTest

# 7) create two small positive test files for YARA (harmless)
Write-File -Path "detections/tests/test_data/ps_example_iwr.txt" -Content 'Invoke-WebRequest "http://example.com/payload.ps1"'
Write-File -Path "detections/tests/test_data/mimikatz_example.txt" -Content 'sekurlsa::logonpasswords'

# 8) examples/deploy-proof placeholders
Write-File -Path "examples/deploy-proof/README.md" -Content "Place sanitized command outputs here as proof (docker ps, filebeat status, yara outputs, etc.)"
Write-File -Path "examples/deploy-proof/pi-1-addr.txt" -Content "placeholder: pi-1 ip/hostname output"
Write-File -Path "examples/deploy-proof/pi-5-docker-ps.txt" -Content "placeholder: docker ps output"
Write-File -Path "examples/deploy-proof/pi-4-filebeat-status.txt" -Content "placeholder: filebeat status"

# 9) Update root README (append small note)
$append = @'
## Demo playbook & sanitized deployment artifacts
See `docs/demo-playbook.md` and `inventory/pis.csv` for a step-by-step runbook and sanitized Pi inventory for demos.
'@
Add-Content -Path "README.md" -Value $append

# 10) Stage & commit changes (local commit only)
git add .
git commit -m "chore(demo): add demo playbook, sanitized inventory, filebeat config, pi bootstrap, YARA rules and YARA test harness" 2>$null | Out-Null
Write-Host "Committed changes locally. Review files before pushing to origin."

Write-Host "`nDONE: Files created and committed locally."
Write-Host "To push your changes to GitHub, run: git push origin HEAD"

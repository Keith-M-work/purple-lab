# Purple Lab - Enterprise SOC Infrastructure

> Production-style purple team lab: segmented VLANs, Wazuh SIEM, real attacks, real detections.

## What This Is
A battle-tested SOC lab with:
- **5 VLAN-segmented Raspberry Pis** (Mgmt, Red, Malware, Vuln, Honeypot)
- **Wazuh SIEM** with working detection rules
- **Real vulnerable applications**
- **PowerShell automation**

## Quick Start
```powershell
git clone https://github.com/Keith-M-work/purple-lab.git
cd purple-lab

# Test connectivity
Test-NetConnection 192.168.10.50 -Port 443    # Wazuh dashboard
Test-NetConnection 192.168.10.50 -Port 1515   # Agent enrollment
```

## Critical Issues We Fixed

### 1. Port 9220 vs 9200
Docker uses port 9200, not 9220:
```powershell
$Global:WazuhConfig = @{ IndexerPort = 9200 }
```

### 2. Groups in Agent Config
Groups belong server-side only:
```bash
sudo sed -i '/<groups>/d' /var/ossec/etc/ossec.conf
sudo systemctl restart wazuh-agent
```

### 3. Inter-VLAN Blocking
Each VLAN needs pfSense rules to Wazuh:
- TCP 1515 (enrollment)
- UDP 1514 (events)
- TCP 443 (dashboard)

## Repository Structure
- `project-docs/` â€” Troubleshooting, PoCs
- `part3-detections/` â€” Detection content
- `sec-ops/` â€” Blue team / operations
- `lab-apps/`, `core-infra/`, `infra/`, `demos/`, `training-exercises/`, `medium-series/`

## Safety
- Never expose to internet
- Use RFC-5737 IPs in documentation
- All vulnerable apps isolated in VLANs

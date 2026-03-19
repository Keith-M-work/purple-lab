# Active Directory Purple Team Lab

A self-contained purple team environment for practicing adversary emulation, detection engineering, and attack path analysis against a realistic Active Directory domain.

## Lab Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Host-Only Network                        │
│                     10.10.10.0/24                           │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │  Kali Linux  │  │  Windows 11  │  │  Win Server  │     │
│  │  Attack Box  │  │   Target     │  │  2022 DC     │     │
│  │              │  │              │  │              │     │
│  │ 10.10.10.132 │  │ 10.10.10.131 │  │ 10.10.10.130 │     │
│  │              │  │              │  │              │     │
│  │ - Havoc C2   │  │ - Sysmon     │  │ - AD DS      │     │
│  │ - CALDERA    │  │ - Atomic RT  │  │ - DNS        │     │
│  │ - BloodHound │  │ - SharpHound │  │ - 85 users   │     │
│  │ - Claude MCP │  │ - Wazuh agent│  │ - 12 SPNs    │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│                                                             │
│  eth1 (NAT) on Kali for internet access                    │
└─────────────────────────────────────────────────────────────┘
```

## What's Included

| Component | Description |
|-----------|-------------|
| **Create-LabAD.ps1** | Populates AD with 75 users, 6 departments, 10 service accounts, 16 security groups, and 5 built-in attack paths |
| **purple-team-lab-guide.md** | 5-phase attack chain walkthrough: initial access through C2, mapped to MITRE ATT&CK |
| **bloodhound-setup.md** | BloodHound CE deployment, SharpHound collection, MCP integration with Claude AI |
| **network-diagram.md** | Full lab topology with IP assignments and VM specs |
| **wazuh-rules/** | Custom Wazuh detection rules for LSASS access, process injection, persistence, and C2 beaconing |

## Quick Start

### 1. Build the VMs

| VM | OS | RAM | CPU | Disk | Network |
|----|-----|-----|-----|------|---------|
| Attack Box | Kali Linux | 8 GB | 4 | 80 GB | Host-only + NAT |
| Target | Windows 11 Enterprise Eval | 8 GB | 4 | 64 GB | Host-only |
| Domain Controller | Windows Server 2022 Eval | 4 GB | 2 | 40 GB | Host-only |

### 2. Configure the Domain Controller

```powershell
# Set static IP
New-NetIPAddress -InterfaceAlias "Ethernet0" -IPAddress 10.10.10.130 -PrefixLength 24
Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ServerAddresses 127.0.0.1

# Install AD and promote
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Install-ADDSForest -DomainName "yourlab.local" -DomainNetbiosName "YOURLAB" `
  -SafeModeAdministratorPassword (ConvertTo-SecureString "<YOUR_DSRM_PASSWORD>" -AsPlainText -Force) `
  -InstallDns -Force

# After reboot, populate the domain
Set-ExecutionPolicy Bypass -Scope CurrentUser -Force
.\Create-LabAD.ps1
```

### 3. Join Target to Domain

On the Windows 11 VM:
```powershell
Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ServerAddresses 10.10.10.130
Add-Computer -DomainName "yourlab.local" -Credential (Get-Credential) -Restart
```

### 4. Deploy Detection Stack

See [purple-team-lab-guide.md](purple-team-lab-guide.md) for Sysmon and Wazuh agent setup.

### 5. Collect BloodHound Data

See [bloodhound-setup.md](bloodhound-setup.md) for BloodHound CE deployment and SharpHound collection.

### 6. Execute Attack Chain

Follow [purple-team-lab-guide.md](purple-team-lab-guide.md) phases 2-5 for the full attack-detect-validate cycle.

## Built-in Attack Paths

The `Create-LabAD.ps1` script configures these exploitable misconfigurations:

| # | Path | Severity |
|---|------|----------|
| 1 | Kerberoastable service account with weak password + GenericAll on IT OU -> Domain Admin | Critical |
| 2 | Kerberoastable backup service account -> Backup Operators | High |
| 3 | Help Desk group can reset HR passwords -> lateral movement | Medium |
| 4 | Engineering Leads can modify IT-Admins group membership -> privilege escalation | High |
| 5 | Overprivileged sysadmin directly in Domain Admins | High |

## AD Structure

```
yourlab.local
├── Executive (5 users: CEO, CFO, CTO, CISO, COO)
├── IT (15 users: sysadmins, security team, help desk, DevOps)
├── Finance (10 users: director, accountants, analysts)
├── HR (8 users: director, recruiters, compliance)
├── Sales (12 users: VP, managers, AEs, SDRs)
├── Engineering (15 users: VP, managers, developers, QA, SRE)
├── Contractors (5 users: consultants, pen tester)
└── Service Accounts (10 accounts, all with SPNs set)

Total: 85 users | 64 groups | 12 Kerberoastable accounts
```

## Detection Coverage

Custom Wazuh rules in `wazuh-rules/` detect:

| Rule ID | Detection | ATT&CK | Sysmon Event |
|---------|-----------|--------|--------------|
| 100100 | LSASS memory access by non-system process | T1003.001 | Event 10 |
| 100101 | comsvcs.dll MiniDump credential dump | T1003.001 | Event 1 |
| 100200 | CreateRemoteThread process injection | T1055 | Event 8 |
| 100300 | Run key persistence from suspicious directory | T1547.001 | Event 13 |
| 100400 | C2 beaconing (repeated HTTPS from non-browser) | T1573.002 | Event 3 |

## Requirements

- VMware Workstation or similar hypervisor
- 20+ GB RAM on host (three VMs running simultaneously)
- Windows 11 Enterprise Evaluation ISO
- Windows Server 2022 Evaluation ISO
- Kali Linux ISO

## Safety

- All VMs run on an isolated host-only network with no internet routing
- Kali uses a second NAT adapter for tool downloads only
- Windows Defender is disabled on the target for lab purposes only
- Do not expose any lab VM to production networks
- All credentials in this repo are for lab use only

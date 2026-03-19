# Lab Network Topology

## Overview

Three VMs on an isolated host-only network segment. The Kali attack box has a second NAT adapter for internet access (tool downloads only). No routing between the host-only and NAT segments.

## Network Diagram

```
                    ┌──────────────┐
                    │   Internet   │
                    └──────┬───────┘
                           │
                    ┌──────┴───────┐
                    │  VMware NAT  │
                    │ 192.168.x.0  │
                    └──────┬───────┘
                           │ eth1 (NAT)
                           │
┌──────────────────────────┼────────────────────────────────────┐
│                          │         Host-Only Network          │
│                          │          10.10.10.0/24             │
│                          │                                    │
│  ┌───────────────────────┴──┐                                 │
│  │      Kali Linux          │                                 │
│  │      10.10.10.132        │                                 │
│  │                          │                                 │
│  │  eth0: 10.10.10.132/24   │                                 │
│  │  eth1: DHCP (NAT)        │                                 │
│  │                          │                                 │
│  │  Tools:                  │                                 │
│  │  - Havoc C2              │                                 │
│  │  - CALDERA               │                                 │
│  │  - BloodHound CE         │                                 │
│  │  - Atomic Red Team       │                                 │
│  │  - bloodhound_mcp        │                                 │
│  │  - Claude Desktop        │                                 │
│  └─────────┬────────────────┘                                 │
│            │                                                  │
│            │ 10.10.10.0/24                                    │
│            │                                                  │
│  ┌─────────┴────────────────┐  ┌──────────────────────────┐  │
│  │   Windows 11 Enterprise  │  │  Windows Server 2022     │  │
│  │   10.10.10.131           │  │  10.10.10.130            │  │
│  │                          │  │                          │  │
│  │   Domain: yourlab.local  │  │  Hostname: DC01          │  │
│  │   Role: Target endpoint  │  │  Role: Domain Controller │  │
│  │                          │  │                          │  │
│  │   Tools:                 │  │  Services:               │  │
│  │   - Sysmon (modular cfg) │  │  - AD Domain Services    │  │
│  │   - Atomic Red Team      │  │  - DNS Server            │  │
│  │   - SharpHound           │  │  - 85 AD users           │  │
│  │   - Wazuh Agent          │  │  - 12 Kerberoastable SPNs│  │
│  │                          │  │  - 5 attack paths        │  │
│  │   Defender: Disabled     │  │                          │  │
│  │   Firewall: Disabled     │  │  Firewall: Disabled      │  │
│  │   PS Logging: Enabled    │  │                          │  │
│  └──────────────────────────┘  └──────────────────────────┘  │
│                                                               │
└───────────────────────────────────────────────────────────────┘
```

## IP Assignments

| VM | IP Address | Role | OS |
|----|-----------|------|-----|
| DC01 | 10.10.10.130 | Domain Controller (yourlab.local) | Windows Server 2022 Standard Eval |
| Target | 10.10.10.131 | Domain-joined endpoint | Windows 11 Enterprise Eval |
| Attack Box | 10.10.10.132 | Offensive operations | Kali Linux |

## VM Specifications

| VM | RAM | CPU | Disk | Network |
|----|-----|-----|------|---------|
| DC01 | 4 GB | 2 cores | 40 GB | Host-only |
| Target | 8 GB | 4 cores | 64 GB | Host-only |
| Attack Box | 8 GB | 4 cores | 80 GB | Host-only + NAT |

## Network Configuration Notes

### Kali Dual NIC Setup
- **eth0** (Host-only): Static or DHCP — communicates with lab VMs
- **eth1** (NAT): DHCP from VMware — internet access for tool downloads
- Default route via eth1 for internet; eth0 handles 10.10.10.0/24

### DNS
- DC01 runs DNS for `yourlab.local`
- Win11 target points to DC01 (10.10.10.130) for DNS
- Kali uses external DNS (8.8.8.8) on eth1, lab DNS not required

### File Transfer
Since the Win11 target has no internet access, transfer tools via:
```bash
# On Kali
python3 -m http.server 9090

# On Win11
Invoke-WebRequest -Uri "http://10.10.10.132:9090/<file>" -OutFile "C:\Tools\<file>"
```

## Traffic Flows

| Source | Destination | Purpose | Ports |
|--------|------------|---------|-------|
| Kali | Win11 | Attack traffic, C2 | 443, 8080, various |
| Win11 | DC01 | AD auth, DNS, LDAP | 53, 88, 389, 445 |
| Win11 | Kali | SharpHound transfer | 4444 (ad hoc) |
| Kali | DC01 | LDAP enumeration | 389, 636 |
| Win11 | DC01 | Kerberos TGS requests | 88 |
| Kali | Internet | Tool downloads | 80, 443 |

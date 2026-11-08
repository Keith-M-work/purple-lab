# 🛠️ Critical Issues We Fixed

Real problems hit while building the lab, and how they were resolved.

## 1. Port 9220 vs 9200
Docker uses port **9200**, not 9220:
```powershell
$Global:WazuhConfig = @{ IndexerPort = 9200 }
```

## 2. Groups in Agent Config
Groups belong server-side only - remove from agent:
```bash
sudo sed -i '/<groups>/d' /var/ossec/etc/ossec.conf
sudo systemctl restart wazuh-agent
```

## 3. Inter-VLAN Firewall Rules
Each VLAN needs explicit firewall rules to Wazuh:
- **TCP 1515** (agent enrollment)
- **UDP 1514** (event logging)
- **TCP 443** (dashboard access)

## 4. VLAN-Aware Bridge
Hypervisor needs VLAN filtering enabled on trunk interface:
```bash
# Enable VLAN filtering on bridge interface
ip link set <bridge_interface> type bridge vlan_filtering 1
```

---
[← Back to README](../README.md)

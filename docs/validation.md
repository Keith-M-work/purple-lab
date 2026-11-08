# 🚦 Quick Validation

## Test connectivity to Wazuh
```powershell
Test-NetConnection 10.10.10.50 -Port 443    # Wazuh dashboard
Test-NetConnection 10.10.10.50 -Port 1515   # Agent enrollment
```

## Check Firewall VLANs
```bash
# SSH to firewall appliance
tcpdump -i <trunk_interface> vlan 31    # Verify tagged frames on trunk
```

## Verify Agent Connectivity
```powershell
# From any Pi or VM
sudo /var/ossec/bin/agent_control -l    # List connected agents
curl -k https://10.10.10.50:443         # Test dashboard access
```

## Test Inter-VLAN Blocking
```bash
# From Attack VLAN (should fail)
ping 10.31.31.10    # Should timeout (malware lab isolated)

# From Management VLAN (should succeed)
ping 10.31.31.10    # Should work (admin access)
```

## ⚡ PowerShell Lab Functions
Pre-loaded management functions (from profile):
```powershell
pi-help          # List all Pi management commands
wazuh-help       # Wazuh deployment commands
shutdown-pis     # Gracefully shutdown all Pis
pi-temp-all      # Check temperatures across the cluster
pi-disk-all      # Check disk usage on all Pis
```

---
[← Back to README](../README.md)
